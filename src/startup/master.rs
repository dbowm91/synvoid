use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::block_store::BlockStore;
use crate::config::ConfigManager;
use crate::config::MainConfig;
use crate::master::handle_worker_connection;
use crate::mime;
use crate::overseer::{OverseerConfig, OverseerProcess};
use crate::platform::fs::PlatformPaths;
use crate::process::{IpcEndpoint, ProcessEvent, ProcessManager, ProcessManagerConfig};
use crate::waf::RuleFeedManagerForWaf;

use super::bootstrap::init_logging;
use super::daemon::setup_signal_handlers;
use super::{MasterState, MasterStateTrackers};

use crate::common::setup_panic_handler;

pub fn run_master_mode(config_path: Option<PathBuf>, log_level: Option<String>) {
    let master_panic_log = format!(
        "{}/synvoid-master-panic.log",
        std::env::temp_dir().display()
    );
    setup_panic_handler("MASTER", Some(&master_panic_log));

    let config_dir = config_path.unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    let mut config_manager = ConfigManager::new(config_dir.clone());

    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main.toml: {}, using defaults", e);
    }

    let main_config = config_manager.main.clone();

    if main_config.mimes.enabled {
        if let Some(ref mimes_file) = main_config.mimes.file {
            match mime::init_mimes_from_file(mimes_file) {
                Ok(()) => {
                    tracing::info!("Loaded MIME types from {}", mimes_file);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load MIME types from {}: {}, using defaults",
                        mimes_file,
                        e
                    );
                }
            }
        }
    }

    let worker_threads = main_config.tokio.worker_threads;
    tracing::info!(
        "Starting synvoid Master Process with {} worker threads",
        worker_threads
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        rt.block_on(run_master(config_manager, main_config, log_level.clone()))
    }));

    match result {
        Ok(Ok(())) => {
            tracing::info!("synvoid master process exited cleanly");
        }
        Ok(Err(e)) => {
            tracing::error!("synvoid master process error: {}", e);
            std::process::exit(1);
        }
        Err(panic_info) => {
            tracing::error!("synvoid master process panicked: {:?}", panic_info);
            std::process::exit(1);
        }
    }
}

pub fn run_overseer_mode(
    config_path: Option<PathBuf>,
    foreground: bool,
    test_mode: Option<&[String]>,
    pid_manager: &crate::process::PidFileManager,
) {
    let overseer_panic_log = format!(
        "{}/synvoid-overseer-panic.log",
        std::env::temp_dir().display()
    );
    setup_panic_handler("OVERSEER", Some(&overseer_panic_log));

    let config_dir = config_path.unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    let mut config_manager = ConfigManager::new(config_dir.clone());

    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main.toml: {}, using defaults", e);
    }

    let main_config = config_manager.main.clone();

    // Load MIME types from file if enabled
    if main_config.mimes.enabled {
        if let Some(ref mimes_file) = main_config.mimes.file {
            match mime::init_mimes_from_file(mimes_file) {
                Ok(()) => {
                    tracing::info!("Loaded MIME types from {}", mimes_file);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load MIME types from {}: {}, using defaults",
                        mimes_file,
                        e
                    );
                }
            }
        }
    }

    // PID file already written by acquire_pid_file

    // Daemonize unless foreground flag is set or test mode is enabled
    let should_daemonize = !foreground && test_mode.is_none();

    if should_daemonize {
        super::daemon::daemonize(pid_manager);
    }

    tracing::info!("Starting synvoid Overseer Process");

    // Create OverseerConfig from main config
    let overseer_config = OverseerConfig {
        config_path: Some(config_dir.clone()),
        auto_restart: main_config.overseer.auto_restart,
        restart_delay_secs: main_config.overseer.restart_delay_secs,
        max_restart_attempts: main_config.overseer.max_restart_attempts,
        health_check_interval_secs: main_config.overseer.health_check_interval_secs,
        stable_uptime_secs: main_config.overseer.stable_uptime_secs,
        upgrade_validation_timeout_secs: main_config.overseer.upgrade_validation_timeout_secs,
        upgrade_drain_timeout_secs: main_config.overseer.upgrade_drain_timeout_secs,
        upgrade_health_check_retries: main_config.overseer.upgrade_health_check_retries,
        upgrade_health_check_interval_secs: main_config.overseer.upgrade_health_check_interval_secs,
        ipc_read_timeout_ms: main_config.overseer.ipc_read_timeout_ms,
        ipc_write_timeout_ms: main_config.overseer.ipc_write_timeout_ms,
        master_startup_timeout_secs: main_config.overseer.master_startup_timeout_secs,
        drain_check_interval_ms: main_config.overseer.drain_check_interval_ms,
    };

    // Determine runtime directory for status file
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run"))
        .join("synvoid");

    // Ensure runtime directory exists
    if let Err(e) = std::fs::create_dir_all(&runtime_dir) {
        tracing::warn!(
            "Failed to create runtime directory {}: {}",
            runtime_dir.display(),
            e
        );
    }

    // Run the overseer (which spawns Master, which spawns Workers)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        rt.block_on(async {
            let mut overseer = OverseerProcess::new(overseer_config, runtime_dir)?;
            overseer.run().await
        })
    }));

    match result {
        Ok(Ok(())) => {
            tracing::info!("synvoid overseer process exited cleanly");
        }
        Ok(Err(e)) => {
            tracing::error!("synvoid overseer process error: {}", e);
            std::process::exit(1);
        }
        Err(panic_info) => {
            tracing::error!("synvoid overseer process panicked: {:?}", panic_info);
            std::process::exit(1);
        }
    }
}

async fn run_master(
    mut config_manager: ConfigManager,
    main_config: MainConfig,
    log_level_override: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize post-quantum cryptography for TLS
    // This enables X25519MLKEM768 hybrid key exchange for all TLS connections
    #[cfg(feature = "post-quantum")]
    {
        use rustls_post_quantum::provider;
        if let Err(e) = provider().install_default() {
            tracing::warn!(
                "Failed to install post-quantum TLS provider: {:?}. Using default.",
                e
            );
        } else {
            tracing::info!("Post-quantum TLS (X25519MLKEM768) enabled");

            // Verify PQ is actually available by checking supported key exchange groups
            use rustls::crypto::CryptoProvider;
            let provider = CryptoProvider::get_default();
            if let Some(p) = provider {
                let group_count = p.kx_groups.len();
                tracing::info!(
                    "TLS crypto provider has {} key exchange groups available",
                    group_count
                );
                // Log first few groups to confirm PQ is included
                let sample_groups: Vec<_> = p
                    .kx_groups
                    .iter()
                    .take(5)
                    .map(|g| format!("{:?}", g))
                    .collect();
                tracing::debug!("Sample kx_groups: {:?}", sample_groups);
            }
        }
    }
    #[cfg(not(feature = "post-quantum"))]
    {
        tracing::info!("TLS using classical cryptography (post-quantum feature not enabled)");
    }

    let log_level_for_process = log_level_override.clone();
    init_logging(&main_config.logging, log_level_override);

    tracing::info!("Starting synvoid - Multi-Process WAF");
    tracing::info!(
        "Main HTTP entry: http://{}:{}",
        main_config.server.host,
        main_config.server.port
    );

    let site_results = config_manager.discover_sites();
    let loaded_count = site_results.iter().filter(|r| r.1.is_ok()).count();
    let failed_count = site_results.iter().filter(|r| r.1.is_err()).count();

    tracing::info!("Loaded {} site(s), {} failed", loaded_count, failed_count);

    for (site_id, result) in &site_results {
        if let Err(e) = result {
            tracing::warn!("Site '{}' error: {}", site_id, e);
        }
    }

    let config_path_for_process = config_manager
        .sites_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| config_manager.sites_dir.clone());

    let shared_config = Arc::new(RwLock::new(config_manager));

    // ============================================================================================
    // CRITICAL ARCHITECTURAL REQUIREMENT: Master process must NEVER run UnifiedServer inline.
    //
    // The Master process must ONLY:
    // - Run the admin panel API
    // - Orchestrate threat intelligence (aggregate threats from workers, coordinate mesh sharing)
    // - Manage worker processes (spawn, monitor, restart)
    // - Handle IPC communications
    //
    // The Master MUST NOT:
    // - Run UnifiedServer inline for request handling
    // - Accept HTTP/TCP/UDP/QUIC/WebSocket requests directly
    // - Handle any external network traffic for proxying
    //
    // This separation is CRITICAL for security:
    // - Process isolation: If a CVE exists in the request handling code (UnifiedServer),
    //   the Master process is protected as it's in a separate process
    // - Least privilege: Master handles sensitive operations (config, workers, intelligence)
    //   while Workers handle untrusted input (client requests)
    // - Crash isolation: Worker crashes don't affect Master or admin panel
    //
    // All request handling MUST occur in UnifiedServerWorker processes which are spawned
    // and managed by the ProcessManager. The Workers also handle mesh connections
    // (WAF-WAF, WAF-User VPN, WAF-Server VPN) directly without IPC overhead.
    // ============================================================================================

    // NOTE: We do NOT create UnifiedServer inline here. Trackers for admin panel
    // will be obtained from Workers via IPC or created separately if needed.
    // The Master ONLY orchestrates - it does not handle requests.

    // Create BlockStore for persistent blocklist management in Master
    let data_dir = main_config.persistence.data_dir.as_ref().map(PathBuf::from);
    let master_block_store = Arc::new(BlockStore::new(
        true, // enabled
        data_dir,
        main_config.blocklist_limits.clone(),
    ));

    // Clone for ProcessManager before moving into MasterState
    let master_block_store_for_pm = master_block_store.clone();

    // Initialize rule feed manager if enabled
    let rule_feed_config = main_config.rule_feed.clone();
    let rule_feed_manager = if rule_feed_config.enabled {
        let manager = RuleFeedManagerForWaf::new(rule_feed_config)
            .map_err(|e| format!("Rule feed initialization failed: {}", e))?;
        let manager_clone = manager.clone();
        manager_clone.start_background_fetching();
        Some(manager)
    } else {
        None
    };

    #[cfg(feature = "mesh")]
    let master_state = MasterState::new(
        shared_config.clone(),
        MasterStateTrackers {
            probe_tracker: None,
            suspicious_word_tracker: None,
            upstream_error_tracker: None,
            threat_level_manager: None,
            rule_feed_manager: rule_feed_manager.clone(),
            yara_rules: None,
        },
        master_block_store,
        None,
    );

    #[cfg(not(feature = "mesh"))]
    let master_state = MasterState::new(
        shared_config.clone(),
        MasterStateTrackers {
            probe_tracker: None,
            suspicious_word_tracker: None,
            upstream_error_tracker: None,
            threat_level_manager: None,
            rule_feed_manager: rule_feed_manager.clone(),
        },
        master_block_store,
    );

    let paths = PlatformPaths::new();
    let master_socket_path = paths.master_socket_path();

    #[cfg(unix)]
    if master_socket_path.exists() {
        std::fs::remove_file(&master_socket_path)?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let pipe_name: Vec<u16> = std::ffi::OsStr::new("\\\\.\\pipe\\synvoid-master")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Try to clean up any existing pipe
        // SAFETY: CreateNamedPipeW returns a new handle which we immediately close.
        // This attempts to clean up a stale pipe from a previous crashed process.
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(
                windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                    pipe_name.as_ptr(),
                    windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                    windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                        | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                        | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                    1,
                    65536,
                    65536,
                    0,
                    std::ptr::null_mut(),
                ),
            );
        }
    }

    let ipc_session_key = if let Ok(key_file) = std::env::var("SYNVOID_IPC_KEY_FILE") {
        // Master passed IPC key via temp file (preferred over env var for security)
        match std::fs::read_to_string(&key_file) {
            Ok(key_hex) => {
                let key_hex = key_hex.trim();
                if key_hex.len() == 64 {
                    let mut key = [0u8; 32];
                    let mut valid = true;
                    for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
                        if chunk.len() != 2 {
                            valid = false;
                            break;
                        }
                        let Ok(s) = std::str::from_utf8(chunk) else {
                            valid = false;
                            break;
                        };
                        match u8::from_str_radix(s, 16) {
                            Ok(b) => key[i] = b,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if valid {
                        // Clean up the temp file after reading
                        let _ = std::fs::remove_file(&key_file);
                        Some(key)
                    } else {
                        tracing::error!("IPC key file {} contains invalid hex", key_file);
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Invalid IPC session key in file",
                        )));
                    }
                } else {
                    tracing::error!(
                        "IPC key file {} has wrong length: expected 64 hex chars, got {}",
                        key_file,
                        key_hex.len()
                    );
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid IPC session key length in file",
                    )));
                }
            }
            Err(e) => {
                tracing::error!("Failed to read IPC key file {}: {}", key_file, e);
                return Err(Box::new(e));
            }
        }
    } else if let Some(ref env_var) = main_config.security.ipc_session_key_env {
        match std::env::var(env_var) {
            Ok(key_hex) => {
                if key_hex.len() == 64 {
                    let mut key = [0u8; 32];
                    let mut valid = true;
                    for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
                        if chunk.len() != 2 {
                            valid = false;
                            break;
                        }
                        let Ok(s) = std::str::from_utf8(chunk) else {
                            valid = false;
                            break;
                        };
                        match u8::from_str_radix(s, 16) {
                            Ok(b) => key[i] = b,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if valid {
                        Some(key)
                    } else {
                        tracing::error!("IPC session key from env {} contains invalid hex characters. Generate with: xxd -l 32 -p /dev/urandom", env_var);
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Invalid IPC session key: must be valid hexadecimal",
                        )));
                    }
                } else {
                    tracing::error!("IPC session key from env {} is not 64 hex chars. Generate with: xxd -l 32 -p /dev/urandom", env_var);
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid IPC session key: must be 64 hex characters",
                    )));
                }
            }
            Err(_) => {
                tracing::error!("IPC session key env var {} is not set but ipc_enforce_signing is enabled. Set with: export {}='$(xxd -l 32 -p /dev/urandom)'", env_var, env_var);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "IPC session key environment variable not set",
                )));
            }
        }
    } else {
        None
    };

    let process_config = ProcessManagerConfig {
        min_workers: main_config.defaults.worker_pool.workers,
        max_workers: 16,
        unified_server_workers: main_config.process_manager.unified_server_workers,
        max_restart_attempts: 5,
        restart_cooldown_secs: 60,
        restart_backoff_max_secs: 300,
        heartbeat_timeout_secs: 30,
        graceful_shutdown_timeout_secs: 30,
        worker_port_base: main_config.defaults.worker_pool.worker_port_base,
        config_path: config_path_for_process,
        master_socket_path: master_socket_path.clone(),
        control_api_addr: main_config.supervisor.control_api_addr.clone(),
        log_level: log_level_for_process,
        pre_spawn_workers: main_config.defaults.worker_pool.workers,
        warm_workers_target: main_config.defaults.worker_pool.workers,
        health_check_interval_secs: 5,
        ipc_session_key,
        ipc_enforce_signing: main_config.security.ipc_enforce_signing,
        allow_insecure_ipc_key: main_config.security.allow_insecure_ipc_key,
        ipc_rate_limit: Default::default(),
    };

    let (process_manager, mut event_rx) =
        ProcessManager::new(process_config, Some(master_block_store_for_pm));
    let process_manager = Arc::new(process_manager);

    // Initialize threat feed client if enabled
    #[cfg(feature = "mesh")]
    {
        let threat_feed_config = crate::waf::threat_intel::feed_client::ThreatFeedConfig {
            enabled: true, // TODO: Make configurable
            ..Default::default()
        };
        let threat_feed_client =
            crate::waf::threat_intel::feed_client::ThreatFeedClient::new(threat_feed_config, None);

        {
            let pm = process_manager.clone();
            threat_feed_client.set_on_update_callback(move |_timestamp, indicators| {
                let pm_clone = pm.clone();
                let ipc_indicators: Vec<crate::process::ipc::ThreatIndicatorData> = indicators
                    .into_iter()
                    .map(|i| crate::process::ipc::ThreatIndicatorData {
                        threat_type: match i.threat_type {
                            crate::mesh::protocol::ThreatType::IpBlock => {
                                crate::process::ipc::ThreatIndicatorType::IpBlock
                            }
                            crate::mesh::protocol::ThreatType::RateLimitViolation => {
                                crate::process::ipc::ThreatIndicatorType::RateLimitViolation
                            }
                            crate::mesh::protocol::ThreatType::SuspiciousActivity => {
                                crate::process::ipc::ThreatIndicatorType::SuspiciousActivity
                            }
                            _ => crate::process::ipc::ThreatIndicatorType::IpBlock,
                        },
                        indicator_value: i.indicator_value,
                        severity: match i.severity {
                            crate::mesh::protocol::ThreatSeverity::Low => {
                                crate::process::ipc::ThreatSeverityLevel::Low
                            }
                            crate::mesh::protocol::ThreatSeverity::Medium => {
                                crate::process::ipc::ThreatSeverityLevel::Medium
                            }
                            crate::mesh::protocol::ThreatSeverity::High => {
                                crate::process::ipc::ThreatSeverityLevel::High
                            }
                            crate::mesh::protocol::ThreatSeverity::Critical => {
                                crate::process::ipc::ThreatSeverityLevel::Critical
                            }
                            _ => crate::process::ipc::ThreatSeverityLevel::Medium,
                        },
                        reason: i.reason,
                        ttl_seconds: i.ttl_seconds,
                        source_node_id: i.source_node_id,
                        timestamp: i.timestamp,
                        site_scope: i.site_scope,
                        rate_limit_requests: i.rate_limit_requests,
                        rate_limit_window_secs: i.rate_limit_window_secs,
                        suspicious_pattern: i.suspicious_pattern,
                    })
                    .collect();

                tokio::spawn(async move {
                    pm_clone
                        .broadcast_threat_feed_update(ipc_indicators, 1)
                        .await;
                });
            });
        }
        threat_feed_client.start_background_fetching();
    }

    // Set up rule feed broadcast callback if enabled
    if let Some(ref manager) = rule_feed_manager {
        let pm = process_manager.clone();
        manager.set_on_apply_callback(move |version, patterns| {
            let pm_clone = pm.clone();
            tokio::spawn(async move {
                pm_clone
                    .broadcast_rule_patterns_update(version, patterns)
                    .await;
            });
        });
    }

    #[cfg(unix)]
    {
        let ipc_endpoint = IpcEndpoint::master();
        let ipc_listener = ipc_endpoint.bind().await?;
        tracing::info!("Master IPC socket listening at {:?}", master_socket_path);

        let pm_clone = process_manager.clone();
        tokio::spawn(async move {
            loop {
                match ipc_listener.accept().await {
                    Ok(ipc) => {
                        let pm = pm_clone.clone();

                        tokio::spawn(async move {
                            handle_worker_connection(ipc, pm).await;
                        });
                    }
                    Err(e) => {
                        tracing::debug!("IPC accept error: {}", e);
                    }
                }
            }
        });
    }

    #[cfg(windows)]
    {
        tracing::info!("Master IPC listening on Windows named pipe: \\\\.\\pipe\\synvoid-master");

        let pm_clone = process_manager.clone();
        let master_path = master_socket_path.clone();

        tokio::spawn(async move {
            windows_ipc_accept_loop(pm_clone, master_path).await;
        });

        let config_clone = config_manager.clone();
        let command_signer = process_manager
            .get_ipc_session_key()
            .map(|key| Arc::new(crate::process::IpcSigner::new(&key)));
        tokio::spawn(async move {
            windows_command_pipe_listener(config_clone, command_signer).await;
        });
    }

    for _ in 0..main_config.defaults.worker_pool.workers {
        process_manager.spawn_worker()?;
    }

    process_manager.ensure_warm_workers();

    if main_config
        .static_config
        .as_ref()
        .and_then(|c| c.enabled)
        .unwrap_or(true)
    {
        if let Err(e) = process_manager.spawn_static_worker() {
            tracing::warn!("Failed to spawn static worker: {}", e);
        }
    }

    setup_signal_handlers(master_state.clone(), process_manager.clone());

    let pm_health = process_manager.clone();
    let handle = tokio::spawn(async move {
        crate::process::start_health_monitor(pm_health, 5).await;
    });
    process_manager.set_health_monitor_handle(handle).await;

    let pm_persist = process_manager.clone();
    let persist_interval_secs = main_config.blocklist_limits.persist_interval_secs;
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(persist_interval_secs));
        loop {
            interval.tick().await;
            pm_persist.trigger_blocklist_persist();
            tracing::debug!("Blocklist persisted to disk");
        }
    });

    tracing::info!(
        "Starting admin server on port {} (owned by: MASTER process)",
        main_config.admin.port
    );
    let admin_state = master_state.clone();
    tokio::spawn(async move {
        #[cfg(feature = "mesh")]
        crate::admin::start_admin_server(
            admin_state.config,
            admin_state.probe_tracker,
            admin_state.suspicious_word_tracker,
            admin_state.upstream_error_tracker,
            admin_state.threat_level_manager,
            admin_state.rule_feed_manager,
            admin_state.yara_rules,
            admin_state.mesh_transport,
            #[cfg(feature = "icmp-filter")]
            None,
            None,
            None,
        )
        .await;

        #[cfg(not(feature = "mesh"))]
        crate::admin::start_admin_server(
            admin_state.config,
            admin_state.probe_tracker,
            admin_state.suspicious_word_tracker,
            admin_state.upstream_error_tracker,
            admin_state.threat_level_manager,
            admin_state.rule_feed_manager,
            #[cfg(feature = "icmp-filter")]
            None,
            None,
            None,
        )
        .await;
    });

    let unified_worker_count = process_manager.get_config().unified_server_workers.max(1);
    tracing::info!(
        "Spawning {} unified server worker(s) (each worker owns: HTTP/HTTPS/HTTP3 listeners)...",
        unified_worker_count
    );
    if let Err(e) = process_manager.spawn_unified_server_workers(unified_worker_count) {
        tracing::error!("Failed to spawn unified server workers: {}", e);
        std::process::exit(1);
    }

    let mut shutdown_rx = master_state.subscribe_shutdown();

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    ProcessEvent::WorkerStarted(id, pid, port) => {
                        tracing::info!("Worker {} started (PID: {}, port: {})", id, pid, port);
                    }
                    ProcessEvent::WorkerReady(id) => {
                        tracing::info!("Worker {} ready", id);
                    }
                    ProcessEvent::WorkerStopped(id) => {
                        tracing::warn!("Worker {} stopped", id);
                    }
                    ProcessEvent::WorkerFailed(id, error) => {
                        tracing::error!("Worker {} failed: {}", id, error);
                    }
                    ProcessEvent::WorkerRestarted(id, attempt) => {
                        tracing::info!("Worker {} restarted (attempt {})", id, attempt);
                    }
                    ProcessEvent::UnifiedServerWorkerStarted(id, pid) => {
                        tracing::info!("UnifiedServerWorker {} started (PID: {})", id, pid);
                    }
                    ProcessEvent::UnifiedServerWorkerReady(id) => {
                        tracing::info!("UnifiedServerWorker {} ready", id);
                    }
                    ProcessEvent::UnifiedServerWorkerStopped(id) => {
                        tracing::warn!("UnifiedServerWorker {} stopped", id);
                    }
                    ProcessEvent::UnifiedServerWorkerFailed(id, error) => {
                        tracing::error!("UnifiedServerWorker {} failed: {}", id, error);
                    }
                    ProcessEvent::ShutdownInitiated => {
                        tracing::info!("Shutdown initiated by process manager");
                    }
                    ProcessEvent::ShutdownComplete => {
                        tracing::info!("Process manager shutdown complete");
                        break;
                    }
                }
            }

            _ = shutdown_rx.recv() => {
                tracing::info!("Shutdown signal received");
                break;
            }
        }
    }

    tracing::info!("Initiating graceful shutdown...");
    process_manager.graceful_shutdown().await;

    if master_socket_path.exists() {
        std::fs::remove_file(&master_socket_path)?;
    }

    tracing::info!("synvoid shutdown complete");
    Ok(())
}

#[cfg(windows)]
async fn windows_ipc_accept_loop(process_manager: Arc<ProcessManager>, _pipe_name: PathBuf) {
    let listener = crate::process::ipc::WindowsIpcListener::new("synvoid-master");

    loop {
        match listener.accept() {
            Ok(stream) => {
                let pm = process_manager.clone();
                tokio::spawn(async move {
                    let ipc = IpcStream::new(stream);
                    handle_worker_connection(ipc, pm).await;
                });
            }
            Err(e) => {
                tracing::warn!("Named pipe accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(windows)]
async fn windows_command_pipe_listener(
    config_manager: Arc<RwLock<ConfigManager>>,
    signer: Option<Arc<crate::process::IpcSigner>>,
) {
    let listener = crate::process::ipc::WindowsIpcListener::new("synvoid-commands");

    loop {
        match listener.accept() {
            Ok(stream) => {
                let signer = signer.clone();
                tokio::spawn(async move {
                    handle_command_connection(stream, config_manager.clone(), signer).await;
                });
            }
            Err(e) => {
                tracing::warn!("Command pipe accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Handle an incoming command on the Windows named command pipe.
///
/// Privileged commands (Stop, ReloadConfig) require HMAC-signed IPC messages.
/// Read-only commands (Status, HealthCheck) are accepted unsigned but this
/// should be migrated to require signing in a future release.
///
/// TODO(security): Full signed IPC migration — accept ONLY signed messages
/// when a signing key is configured, removing the unsigned fallback entirely.
#[cfg(windows)]
async fn handle_command_connection(
    stream: std::fs::File,
    config_manager: Arc<RwLock<ConfigManager>>,
    signer: Option<Arc<crate::process::IpcSigner>>,
) {
    use crate::process::ipc_signed::SignedIpcMessage;
    use std::io::{Read, Write};

    let mut stream = stream;

    let mut length_buf = [0u8; 4];
    match stream.read_exact(&mut length_buf) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to read command length: {}", e);
            return;
        }
    }

    let len = u32::from_be_bytes(length_buf) as usize;
    if len > 1024 * 1024 {
        let _ = stream.write_all(&0u32.to_be_bytes());
        return;
    }

    let mut msg_buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut msg_buf) {
        tracing::warn!("Failed to read command: {}", e);
        return;
    }

    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&length_buf);
    frame.extend_from_slice(&msg_buf);

    let (command, authenticated) = if let Some(ref s) = signer {
        match SignedIpcMessage::deserialize_signed::<crate::process::MasterCommand>(&frame, s) {
            Ok(cmd) => (cmd, true),
            Err(_) => {
                match crate::serialization::deserialize::<crate::process::MasterCommand>(&msg_buf) {
                    Ok(c) => (c, false),
                    Err(_) => {
                        match serde_json::from_slice::<crate::process::MasterCommand>(&msg_buf) {
                            Ok(c) => (c, false),
                            Err(e) => {
                                tracing::warn!("Failed to parse command: {}", e);
                                let _ = crate::process::write_message_sync(
                                    &mut stream,
                                    &crate::process::CommandResponse::Error(
                                        "Failed to parse command".to_string(),
                                    ),
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }
    } else {
        match crate::serialization::deserialize::<crate::process::MasterCommand>(&msg_buf) {
            Ok(c) => (c, false),
            Err(_) => match serde_json::from_slice::<crate::process::MasterCommand>(&msg_buf) {
                Ok(c) => (c, false),
                Err(e) => {
                    tracing::warn!("Failed to parse command: {}", e);
                    let _ = crate::process::write_message_sync(
                        &mut stream,
                        &crate::process::CommandResponse::Error(
                            "Failed to parse command".to_string(),
                        ),
                    );
                    return;
                }
            },
        }
    };

    match &command {
        crate::process::MasterCommand::Stop { .. }
        | crate::process::MasterCommand::ReloadConfig => {
            if !authenticated {
                tracing::error!(
                    "SECURITY: Rejected unauthenticated privileged command ({:?}) \
                     on command pipe. Configure SYNVOID_IPC_KEY or SYNVOID_IPC_KEY_FILE \
                     for signed IPC.",
                    command
                );
                let _ = crate::process::write_message_sync(
                    &mut stream,
                    &crate::process::CommandResponse::Error(
                        "Authentication required: configure IPC signing key".to_string(),
                    ),
                );
                return;
            }
        }
        crate::process::MasterCommand::Status | crate::process::MasterCommand::HealthCheck => {
            // SECURITY NOTE: Status and HealthCheck are non-mutating read-only
            // operations and may remain unsigned. Future releases should require
            // signing for all commands when a signing key is configured.
            if !authenticated {
                tracing::debug!("Unsigned read-only command ({:?}) on command pipe", command);
            }
        }
        _ => {
            if !authenticated {
                tracing::warn!("Rejected unauthenticated unknown command on command pipe");
                let _ = crate::process::write_message_sync(
                    &mut stream,
                    &crate::process::CommandResponse::Error("Authentication required".to_string()),
                );
                return;
            }
        }
    }

    match command {
        crate::process::MasterCommand::Stop { graceful } => {
            tracing::info!("CLI: Stop command received (graceful: {})", graceful);
            let _ = crate::process::write_message_sync(
                &mut stream,
                &crate::process::CommandResponse::Ok("true".to_string()),
            );
        }
        crate::process::MasterCommand::ReloadConfig => {
            tracing::info!("CLI: ReloadConfig command received");
            {
                let config = config_manager.read();
                let mimes_config = &config.main.mimes;
                if mimes_config.enabled {
                    if let Some(ref mimes_file) = mimes_config.file {
                        match crate::mime::reload_mimes_from_file(mimes_file) {
                            Ok(()) => {
                                tracing::info!("MIME types reloaded from {}", mimes_file);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to reload MIME types from {}: {}",
                                    mimes_file,
                                    e
                                );
                            }
                        }
                    }
                }
            }
            {
                let mut config = config_manager.write();
                config.reload_all();
            }
            let _ = crate::process::write_message_sync(
                &mut stream,
                &crate::process::CommandResponse::Ok("true".to_string()),
            );
        }
        crate::process::MasterCommand::Status => {
            let status = crate::process::MasterStatus {
                master_pid: std::process::id(),
                started_at: 0,
                uptime_secs: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
                workers: vec![],
                stats: crate::process::StatusStats::default(),
                threat_summary: crate::process::ThreatSummary::default(),
            };
            let _ = crate::process::write_message_sync(
                &mut stream,
                &crate::process::CommandResponse::Status(status),
            );
        }
        crate::process::MasterCommand::HealthCheck => {
            let _ = crate::process::write_message_sync(
                &mut stream,
                &crate::process::CommandResponse::Ok("true".to_string()),
            );
        }
        _ => {}
    }
}

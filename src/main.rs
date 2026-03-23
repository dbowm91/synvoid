use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::{broadcast, RwLock};

use maluwaf::block_store::BlockStore;
use maluwaf::config::logging::LoggingConfig;
use maluwaf::config::ConfigManager;
use maluwaf::config::MainConfig;
use maluwaf::log_controller;
use maluwaf::master::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash, handle_status,
    handle_stop, handle_worker_connection,
};
use maluwaf::mime;
use maluwaf::overseer::{OverseerConfig, OverseerProcess};
use maluwaf::platform::fs::PlatformPaths;
use maluwaf::process::{
    IpcEndpoint, PidFileManager, ProcessEvent, ProcessManager, ProcessManagerConfig,
};
use maluwaf::waf::{
    ProbeTracker, RuleFeedManagerForWaf, SuspiciousWordTracker, ThreatLevelManager,
    UpstreamErrorTracker,
};
use maluwaf::worker::{
    run_static_worker, run_unified_server_worker, run_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler, StaticWorkerArgs, UnifiedServerWorkerArgs, WorkerArgs,
};

#[derive(Parser, Debug)]
#[command(name = "maluwaf")]
#[command(about = "Multi-Process Web Application Firewall")]
#[command(version)]
struct Args {
    #[arg(long, help = "Run as worker process")]
    worker: bool,

    #[arg(long, value_name = "ID", help = "Worker ID (worker mode only)")]
    worker_id: Option<usize>,

    #[arg(long, value_name = "PORT", help = "Worker port (worker mode only)")]
    port: Option<u16>,

    #[arg(long, value_name = "PATH", help = "Config directory path")]
    config_path: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Master socket path (worker mode only)"
    )]
    master_socket: Option<PathBuf>,

    #[arg(long, help = "Run as static file worker process")]
    static_worker: bool,

    #[arg(long, value_name = "ID", help = "Static worker ID")]
    static_worker_id: Option<usize>,

    #[arg(
        long,
        help = "Run as unified server worker process (handles HTTP/HTTPS/HTTP3)"
    )]
    unified_server_worker: bool,

    #[arg(long, value_name = "ID", help = "Unified server worker ID")]
    unified_worker_id: Option<usize>,

    #[arg(
        long,
        value_name = "COUNT",
        help = "Number of tokio worker threads (for worker processes)"
    )]
    worker_threads: Option<usize>,

    // Internal: Used by Overseer to spawn Master process. Not for direct user invocation.
    // The default behavior (no flags) runs the Overseer which spawns Master.
    #[arg(long, hide = true)]
    master: bool,

    #[arg(short, long, help = "Run in foreground (don't daemonize)")]
    foreground: bool,

    #[arg(long, help = "Validate config files and exit")]
    configtest: bool,

    #[arg(long, help = "Show status of running instance")]
    status: bool,

    #[arg(long, help = "Stop running instance")]
    stop: bool,

    #[arg(long, help = "Restart instance (stop + start)")]
    restart: bool,

    #[arg(long, help = "Reload configuration and propagate to workers")]
    rehash: bool,

    #[arg(
        long,
        help = "Generate a new admin token and save it to config/main.toml"
    )]
    generatenewtoken: bool,

    #[arg(
        long,
        help = "Generate and print an admin token (does not save to config)"
    )]
    generatetoken: bool,

    #[arg(
        long,
        value_name = "MODE",
        help = "Test mode: challenge-off, ratelimit-off, attack-off, bot-off, flood-off, all-off"
    )]
    test: Option<Vec<String>>,

    #[arg(
        long,
        value_name = "PATTERN",
        help = "Check if a regex pattern is safe (ReDoS check)"
    )]
    checkregex: Option<String>,

    #[arg(
        long,
        help = "Required when using --test all-off to confirm intentional testing"
    )]
    force: bool,

    #[arg(
        short,
        long,
        value_name = "LEVEL",
        help = "Log level: trace, debug, info, warn, error (overrides config)"
    )]
    log_level: Option<String>,

    #[arg(long, help = "Export OpenAPI spec as JSON and exit")]
    export_openapi: bool,
}

#[derive(Clone)]
struct MasterState {
    config: Arc<RwLock<ConfigManager>>,
    shutdown_tx: broadcast::Sender<()>,
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
    rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    block_store: Arc<BlockStore>,
    mesh_transport: Option<Arc<maluwaf::mesh::transport::MeshTransport>>,
}

#[derive(Clone)]
struct MasterStateTrackers {
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
    rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
}

impl MasterState {
    fn new(
        config: Arc<RwLock<ConfigManager>>,
        trackers: MasterStateTrackers,
        block_store: Arc<BlockStore>,
        mesh_transport: Option<Arc<maluwaf::mesh::transport::MeshTransport>>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            shutdown_tx,
            probe_tracker: trackers.probe_tracker,
            suspicious_word_tracker: trackers.suspicious_word_tracker,
            upstream_error_tracker: trackers.upstream_error_tracker,
            threat_level_manager: trackers.threat_level_manager,
            rule_feed_manager: trackers.rule_feed_manager,
            block_store,
            mesh_transport,
        }
    }

    fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

use maluwaf::common::setup_panic_handler;

fn setup_signal_handlers(master_state: MasterState, process_manager: Arc<ProcessManager>) {
    let state = master_state.clone();
    let pm = process_manager.clone();

    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                state.shutdown().await;
                pm.graceful_shutdown().await;
            }
            Err(e) => {
                tracing::error!("Error in signal handler: {}", e);
            }
        }
    });

    // Unix-specific signal handler for graceful shutdown.
    //
    // Signal handling notes:
    // - This handles SIGTERM (not SIGINT/Ctrl+C which is handled separately above)
    // - On Unix, SIGTERM is the standard signal for graceful shutdown request
    // - On Windows, we rely solely on Ctrl+C (handled by ctrl_c() above)
    // - The SIGTERM handler triggers the same graceful shutdown flow as Ctrl+C
    #[cfg(unix)]
    {
        let state = master_state.clone();
        let pm = process_manager.clone();

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut sigterm =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("Failed to install SIGTERM handler: {}", e);
                            return;
                        }
                    };

                sigterm.recv().await;
            }

            #[cfg(windows)]
            {
                use tokio::signal::ctrl_c;
                ctrl_c().await.ok();
            }

            tracing::info!("Received shutdown signal, initiating graceful shutdown...");
            state.shutdown().await;
            pm.graceful_shutdown().await;
        });
    }
}

fn init_logging(config: &LoggingConfig, log_level_override: Option<String>) {
    let level = log_level_override.unwrap_or_else(|| config.level.clone());
    log_controller::init_logging_with_dynamic_level(&level);
}

fn init_logging_simple() {
    log_controller::init_logging_with_dynamic_level("info");
}

fn print_test_mode_warning(test_flags: &[String]) {
    let mut disabled = Vec::new();

    for flag in test_flags {
        match flag.as_str() {
            "challenge-off" | "challenge_off" => disabled.push("challenge"),
            "ratelimit-off" | "ratelimit_off" => disabled.push("ratelimit"),
            "attack-off" | "attack_off" => disabled.push("attack"),
            "bot-off" | "bot_off" => disabled.push("bot"),
            "flood-off" | "flood_off" => disabled.push("flood"),
            "all-off" | "all_off" => {
                disabled.clear();
                disabled.push("ALL");
                break;
            }
            _ => {}
        }
    }

    if disabled.is_empty() {
        disabled.push("ALL");
    }

    let is_all_disabled = disabled.iter().any(|s| s.to_lowercase() == "all");
    let disabled_str = if is_all_disabled {
        "ALL".to_string()
    } else {
        disabled.join(", ")
    };

    eprintln!();
    eprintln!("WARNING: TEST MODE ENABLED");
    eprintln!("  Protections DISABLED: {}", disabled_str);
    eprintln!("  This mode is intended for throughput/capacity testing only.");
    eprintln!("  DO NOT use in production.");
    eprintln!();
}

fn main() {
    let args = Args::parse();

    // Handle CLI commands that don't require starting the server
    if args.configtest {
        if let Err(e) = handle_configtest(&args.config_path) {
            eprintln!("Config test failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.export_openapi {
        use maluwaf::admin::openapi::ApiDoc;
        let spec: utoipa::openapi::OpenApi = ApiDoc.into();
        println!(
            "{}",
            serde_json::to_string_pretty(&spec).unwrap_or_default()
        );
        std::process::exit(0);
    }

    if args.generatetoken {
        handle_generatetoken();
        std::process::exit(0);
    }

    if let Some(pattern) = args.checkregex {
        use maluwaf::utils::check_regex_complexity;
        let result = check_regex_complexity(&pattern);
        if result.safe {
            println!("✓ Pattern is safe: {}", pattern);
        } else {
            println!("✗ Pattern is UNSAFE: {}", pattern);
            println!(
                "  Reason: {}",
                result.reason.as_deref().unwrap_or("unknown")
            );
        }
        std::process::exit(if result.safe { 0 } else { 1 });
    }

    if args.generatenewtoken {
        handle_generatenewtoken(&args.config_path);
        std::process::exit(0);
    }

    if args.status {
        if let Err(e) = handle_status() {
            eprintln!("Status check failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.stop {
        if let Err(e) = handle_stop() {
            eprintln!("Stop failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.rehash {
        if let Err(e) = handle_rehash() {
            eprintln!("Reload failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.restart {
        if let Err(e) = handle_stop() {
            eprintln!("Warning: Restart may fail - could not stop existing instance: {}", e);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Check for test mode flags and print warning
    if let Some(ref test_flags) = args.test {
        if !args.force {
            eprintln!("ERROR: --test requires --force flag");
            eprintln!(
                "This mode disables security protections and should only be used for testing."
            );
            eprintln!("If you're sure you want to proceed, add --force");
            std::process::exit(1);
        }
        print_test_mode_warning(test_flags);
    }

    // Check if already running (atomic check-and-write to avoid TOCTOU race)
    let mut pid_manager = PidFileManager::new();
    let current_pid = std::process::id();
    let version = env!("CARGO_PKG_VERSION");

    match pid_manager.try_acquire(current_pid, version) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "RustWAF is already running (PID: {:?})",
                pid_manager.get_pid()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "Error acquiring PID file: {}. RustWAF may already be running.",
                e
            );
            std::process::exit(1);
        }
    }

    // Validate mutual exclusivity of worker modes
    let worker_mode_count = [
        args.worker,
        args.static_worker,
        args.unified_server_worker,
        args.master,
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    if worker_mode_count > 1 {
        eprintln!("Error: Only one worker mode (--worker, --static-worker, --unified-server-worker, --master) can be specified");
        std::process::exit(1);
    }

    // Check for worker mode
    if args.worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let paths = PlatformPaths::new();
        let worker_args = WorkerArgs {
            worker_id: args.worker_id.unwrap_or(0),
            port: args.port.unwrap_or(9000),
            config_path: args.config_path.unwrap_or_else(|| PathBuf::from("config")),
            master_socket: args
                .master_socket
                .unwrap_or_else(|| paths.master_socket_path()),
            test_mode: args.test,
            log_level: args.log_level,
            upgrade_mode: false,
            reuse_port: false,
            ipc_key: None,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_worker(worker_args)) {
            tracing::error!("Worker error: {}", e);
            std::process::exit(1);
        }
    } else if args.static_worker {
        setup_worker_panic_handler();
        init_logging_simple();

        let paths = PlatformPaths::new();
        let static_worker_args = StaticWorkerArgs {
            worker_id: args.static_worker_id.unwrap_or(0),
            config_path: args.config_path.unwrap_or_else(|| PathBuf::from("config")),
            master_socket: args
                .master_socket
                .unwrap_or_else(|| paths.master_socket_path()),
            static_worker_socket: paths.static_worker_socket_path(),
            log_level: args.log_level,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_static_worker(static_worker_args)) {
            tracing::error!("Static worker error: {}", e);
            std::process::exit(1);
        }
    // ============================================================================================
    // IMPORTANT: UnifiedServerWorker MUST run as a separate process from the master.
    //
    // Architectural requirements for running as separate process:
    // - Improved robustness: Isolates master from crashes/vulnerabilities in the worker
    // - Rolling updates: Allows graceful draining and restart without affecting master
    // - Process isolation: Prevents worker issues from bringing down the entire system
    //
    // DO NOT run UnifiedServer in-process within the master - this violates the
    // overseer -> master -> worker separation model required for production deployments.
    // ============================================================================================
    } else if args.unified_server_worker {
        setup_unified_server_panic_handler();
        init_logging_simple();

        let worker_threads = args.worker_threads.unwrap_or(2);
        let paths = PlatformPaths::new();

        let unified_worker_args = UnifiedServerWorkerArgs {
            worker_id: args.unified_worker_id.unwrap_or(0),
            config_path: args.config_path.unwrap_or_else(|| PathBuf::from("config")),
            master_socket: args
                .master_socket
                .unwrap_or_else(|| paths.master_socket_path()),
            log_level: args.log_level,
            upgrade_mode: false,
            reuse_port: false,
            worker_threads,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        if let Err(e) = rt.block_on(run_unified_server_worker(unified_worker_args)) {
            tracing::error!("Unified server worker error: {}", e);
            std::process::exit(1);
        }
    // ============================================================================================
    // INTERNAL: Master mode is invoked by the Overseer process.
    // This is NOT for direct user invocation - use the default mode instead.
    // ============================================================================================
    } else if args.master {
        let master_panic_log = format!(
            "{}/maluwaf-master-panic.log",
            std::env::temp_dir().display()
        );
        setup_panic_handler("MASTER", Some(&master_panic_log));

        let config_dir = args.config_path.unwrap_or_else(|| PathBuf::from("config"));
        let main_config_path = config_dir.join("main.toml");

        let mut config_manager = ConfigManager::new(config_dir.clone());

        if let Err(e) = config_manager.load_main(&main_config_path) {
            eprintln!("Failed to load main.toml: {}, using defaults", e);
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
            "Starting RustWAF Master Process with {} worker threads",
            worker_threads
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            rt.block_on(run_master(
                config_manager,
                main_config,
                args.log_level.clone(),
            ))
        }));

        match result {
            Ok(Ok(())) => {
                tracing::info!("RustWAF master process exited cleanly");
            }
            Ok(Err(e)) => {
                tracing::error!("RustWAF master process error: {}", e);
                eprintln!("Error: {}", e);
                eprintln!("Master process exiting due to error");
                std::process::exit(1);
            }
            Err(panic_info) => {
                tracing::error!("RustWAF master process panicked: {:?}", panic_info);
                eprintln!("Master process panic: {:?}", panic_info);
                eprintln!("Master process exiting due to panic");
                std::process::exit(1);
            }
        }
    } else {
        // Default: Run as Overseer (parent of Master and Workers)
        // This is the only supported mode for production deployments.
        //
        // Process hierarchy:
        //   Overseer (this process) -> Master -> Workers
        //
        // The Overseer is responsible for:
        //   - Spawning and monitoring the Master process
        //   - Health checking and automatic restart
        //   - Managing upgrades and rollbacks
        //   - Daemonization (unless --foreground is set)

        let overseer_panic_log = format!(
            "{}/maluwaf-overseer-panic.log",
            std::env::temp_dir().display()
        );
        setup_panic_handler("OVERSEER", Some(&overseer_panic_log));

        let config_dir = args.config_path.unwrap_or_else(|| PathBuf::from("config"));
        let main_config_path = config_dir.join("main.toml");

        let mut config_manager = ConfigManager::new(config_dir.clone());

        if let Err(e) = config_manager.load_main(&main_config_path) {
            eprintln!("Failed to load main.toml: {}, using defaults", e);
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

        // PID file already written by try_acquire above

        // Daemonize unless foreground flag is set or test mode is enabled
        let should_daemonize = !args.foreground && args.test.is_none();

        if should_daemonize {
            #[cfg(unix)]
            {
                let current_dir =
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));

                let result = {
                    // SAFETY: daemon.start() must be called before any threads exist.
                    // This runs during early initialization before Tokio runtime starts.
                    unsafe {
                        daemonize2::Daemonize::new()
                            .working_directory(current_dir)
                            .umask(0o077)
                            .pid_file(pid_manager.pid_file_path())
                            .start()
                    }
                };
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to daemonize: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("Warning: Daemonization is not supported on this platform, running in foreground");
            }
        }

        tracing::info!("Starting RustWAF Overseer Process");

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
            upgrade_health_check_interval_secs: main_config
                .overseer
                .upgrade_health_check_interval_secs,
            ipc_read_timeout_ms: main_config.overseer.ipc_read_timeout_ms,
            ipc_write_timeout_ms: main_config.overseer.ipc_write_timeout_ms,
            master_startup_timeout_secs: main_config.overseer.master_startup_timeout_secs,
        };

        // Run the overseer (which spawns Master, which spawns Workers)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            rt.block_on(async {
                let mut overseer = OverseerProcess::new(overseer_config)?;
                overseer.run().await
            })
        }));

        match result {
            Ok(Ok(())) => {
                tracing::info!("RustWAF overseer process exited cleanly");
            }
            Ok(Err(e)) => {
                tracing::error!("RustWAF overseer process error: {}", e);
                eprintln!("Error: {}", e);

                eprintln!("Overseer process exiting due to error");
                std::process::exit(1);
            }
            Err(panic_info) => {
                tracing::error!("RustWAF overseer process panicked: {:?}", panic_info);
                eprintln!("Overseer process panic: {:?}", panic_info);
                eprintln!("Overseer process exiting due to panic");
                std::process::exit(1);
            }
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

    tracing::info!("Starting RustWAF - Multi-Process WAF");
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
        let manager = RuleFeedManagerForWaf::new(rule_feed_config);
        let manager_clone = manager.clone();
        manager_clone.start_background_fetching();
        Some(manager)
    } else {
        None
    };

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
        None,
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
        let pipe_name: Vec<u16> = std::ffi::OsStr::new("\\\\.\\pipe\\maluwaf-master")
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

    let ipc_session_key = if let Some(ref env_var) = main_config.security.ipc_session_key_env {
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
        max_restart_attempts: 5,
        restart_cooldown_secs: 60,
        restart_backoff_max_secs: 300,
        heartbeat_timeout_secs: 30,
        graceful_shutdown_timeout_secs: 30,
        worker_port_base: main_config.defaults.worker_pool.worker_port_base,
        config_path: config_path_for_process,
        master_socket_path: master_socket_path.clone(),
        log_level: log_level_for_process,
        pre_spawn_workers: main_config.defaults.worker_pool.workers,
        warm_workers_target: main_config.defaults.worker_pool.workers,
        health_check_interval_secs: 5,
        ipc_session_key,
        ipc_enforce_signing: main_config.security.ipc_enforce_signing,
        ipc_rate_limit: Default::default(),
    };

    let (process_manager, mut event_rx) =
        ProcessManager::new(process_config, Some(master_block_store_for_pm));
    let process_manager = Arc::new(process_manager);

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
        tracing::info!("Master IPC listening on Windows named pipe: \\\\.\\pipe\\maluwaf-master");

        // On Windows, need to do IPC different
        // The workers will connect via named pipes
        // This spawns a background task that handles Windows pipe connections
        let pm_clone = process_manager.clone();
        let master_path = master_socket_path.clone();

        tokio::spawn(async move {
            windows_ipc_accept_loop(pm_clone, master_path).await;
        });

        // Also start command pipe listener for CLI commands
        let config_clone = config_manager.clone();
        tokio::spawn(async move {
            windows_command_pipe_listener(config_clone).await;
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
    tokio::spawn(async move {
        maluwaf::process::start_health_monitor(pm_health, 5).await;
    });

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

    tracing::info!("Starting admin server...");
    let admin_state = master_state.clone();
    tokio::spawn(async move {
        maluwaf::admin::start_admin_server(
            admin_state.config,
            admin_state.probe_tracker,
            admin_state.suspicious_word_tracker,
            admin_state.upstream_error_tracker,
            admin_state.threat_level_manager,
            admin_state.rule_feed_manager,
            admin_state.mesh_transport,
            #[cfg(feature = "icmp-filter")]
            None,
            None,
        )
        .await;
    });

    tracing::info!("Spawning unified server worker...");
    if let Err(e) = process_manager.spawn_unified_server_worker() {
        tracing::error!("Failed to spawn unified server worker: {}", e);
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

    tracing::info!("RustWAF shutdown complete");
    Ok(())
}

#[cfg(windows)]
async fn windows_ipc_accept_loop(process_manager: Arc<ProcessManager>, pipe_name: PathBuf) {
    use std::os::windows::ffi::OsStrExt;

    let pipe_name_str = format!("\\\\.\\pipe\\maluwaf-master");
    let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(&pipe_name_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
        // Create a new pipe instance for each connection
        // SAFETY: CreateNamedPipeW called with valid pipe name; we check for zero handle.
        let pipe_handle = unsafe {
            windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                pipe_name_wide.as_ptr(),
                windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            )
        };

        if pipe_handle == 0 {
            tracing::error!(
                "Failed to create named pipe: {:?}",
                std::io::Error::last_os_error()
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // Wait for client connection
        // SAFETY: ConnectNamedPipe called with valid pipe handle; we check return value.
        let connected = unsafe {
            windows_sys::Win32::System::Pipes::ConnectNamedPipe(pipe_handle, std::ptr::null_mut())
        };

        if connected == 0 {
            // SAFETY: GetLastError reads thread-local errno; always safe.
            let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                tracing::warn!("ConnectNamedPipe failed with error: {}", error);
                // SAFETY: CloseHandle called on valid handle we own from failed ConnectNamedPipe.
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(pipe_handle);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        }

        // Convert raw handle to File
        // SAFETY: from_raw_handle takes ownership of pipe_handle; we validated it's non-zero above.
        let stream = unsafe {
            std::fs::File::from_raw_handle(pipe_handle as std::os::windows::io::RawHandle)
        };

        let pm = process_manager.clone();
        tokio::spawn(async move {
            let ipc = IpcStream::new(stream);
            handle_worker_connection(ipc, pm).await;
        });
    }
}

#[cfg(windows)]
async fn windows_command_pipe_listener(config_manager: Arc<RwLock<ConfigManager>>) {
    use std::os::windows::ffi::OsStrExt;

    let pipe_name_str = "\\\\.\\pipe\\maluwaf-commands";
    let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(pipe_name_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
        // Create a new pipe instance for each connection
        // SAFETY: CreateNamedPipeW called with valid pipe name; we check for zero handle.
        let pipe_handle = unsafe {
            windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                pipe_name_wide.as_ptr(),
                windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            )
        };

        if pipe_handle == 0 {
            tracing::error!(
                "Failed to create command pipe: {:?}",
                std::io::Error::last_os_error()
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // Wait for client connection
        // SAFETY: ConnectNamedPipe called with valid pipe handle; we check return value.
        let connected = unsafe {
            windows_sys::Win32::System::Pipes::ConnectNamedPipe(pipe_handle, std::ptr::null_mut())
        };

        if connected == 0 {
            // SAFETY: GetLastError reads thread-local errno; always safe.
            let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                tracing::warn!("ConnectNamedPipe failed with error: {}", error);
                // SAFETY: CloseHandle called on valid handle we own from failed ConnectNamedPipe.
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(pipe_handle);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        }

        // Convert raw handle to File and handle command
        // SAFETY: from_raw_handle takes ownership of pipe_handle; we validated it's non-zero above.
        let stream = unsafe {
            std::fs::File::from_raw_handle(pipe_handle as std::os::windows::io::RawHandle)
        };
        tokio::spawn(async move {
            handle_command_connection(stream, config_manager.clone()).await;
        });
    }
}

#[cfg(windows)]
async fn handle_command_connection(
    stream: std::fs::File,
    config_manager: Arc<RwLock<ConfigManager>>,
) {
    use std::io::{Read, Write};

    let mut stream = stream;

    // Read command
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

    let mut json_buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut json_buf) {
        tracing::warn!("Failed to read command: {}", e);
        return;
    }

    let command: crate::process::MasterCommand = match serde_json::from_slice(&json_buf) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to parse command: {}", e);
            let _ = stream.write_all(&0u32.to_be_bytes());
            return;
        }
    };

    // Handle command and send response
    let response = match command {
        crate::process::MasterCommand::Stop { graceful } => {
            tracing::info!("CLI: Stop command received (graceful: {})", graceful);
            // Trigger shutdown
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"true");
            return;
        }
        crate::process::MasterCommand::ReloadConfig => {
            tracing::info!("CLI: ReloadConfig command received");
            // Reload config and mimes
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
            // Reload site configs
            {
                let mut config = config_manager.write();
                config.reload_all();
            }
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"true");
            return;
        }
        crate::process::MasterCommand::Status => {
            // Return status
            let status = crate::process::MasterStatus {
                master_pid: std::process::id(),
                started_at: 0,
                uptime_secs: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
                workers: vec![],
                stats: crate::process::StatusStats::default(),
                threat_summary: crate::process::ThreatSummary::default(),
            };
            let json = serde_json::to_string(&crate::process::CommandResponse::Status(status))
                .unwrap_or_default();
            let len = json.len() as u32;
            let _ = stream.write_all(&len.to_be_bytes());
            let _ = stream.write_all(json.as_bytes());
            return;
        }
        crate::process::MasterCommand::HealthCheck => {
            let _ = stream.write_all(&4u32.to_be_bytes());
            let _ = stream.write_all(b"true");
            return;
        }
    };
}

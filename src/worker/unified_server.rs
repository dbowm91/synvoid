use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as TokioMutex, RwLock};
use tokio::task::JoinHandle;

use super::connect::connect_to_master_async;
use super::context::RequestServices;
use super::drain_state::WorkerDrainState;
use super::metrics::WorkerMetrics;
use crate::app_server::{GranianConfig, GranianSupervisor};
use crate::common::setup_panic_handler;
use crate::config::ConfigManager;
#[cfg(feature = "mesh")]
use crate::mesh::backend::create_record_store;
#[cfg(feature = "mesh")]
use crate::mesh::config::ThreatIntelligenceConfig;
#[cfg(feature = "mesh")]
use crate::mesh::threat_intel::ThreatIntelligenceManager;
#[cfg(feature = "mesh")]
use crate::mesh::topology::MeshTopology;
#[cfg(feature = "mesh")]
use crate::mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use crate::mesh::yara_rules::YaraRulesManager;
use crate::platform::fs::PlatformPaths;
use crate::plugin::get_global_plugin_manager;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::{check_ports_available, current_timestamp, Message, WorkerId};
use crate::server::UnifiedServer;
use crate::upload::UploadValidator;
use crate::{DrainFlag, RunningFlag};

#[derive(Clone)]
pub struct UnifiedServerWorkerArgs {
    pub worker_id: usize,
    pub config_path: PathBuf,
    pub master_socket: PathBuf,
    pub log_level: Option<String>,
    pub upgrade_mode: bool,
    pub reuse_port: bool,
    pub worker_threads: usize,
    pub cpu_affinity: Option<usize>,
    pub total_workers: usize,
}

pub fn setup_unified_server_panic_handler() {
    let paths = PlatformPaths::new();
    let panic_path = paths
        .unified_worker_socket_path(0)
        .to_string_lossy()
        .replace(".sock", "-panic.log");
    setup_panic_handler("UNIFIED SERVER WORKER", Some(&panic_path));
}

async fn setup_worker_ipc(
    master_socket: &std::path::Path,
    worker_id: &WorkerId,
) -> Result<Arc<TokioMutex<AsyncIpcStream>>, Box<dyn std::error::Error + Send + Sync>> {
    // Read IPC session key from environment (passed via temp file by master)
    let signer = if let Ok(key_file) = std::env::var("SYNVOID_IPC_KEY_FILE") {
        crate::process::ipc_signed::read_ipc_key_file(&key_file)
    } else if let Ok(key_hex) = std::env::var("SYNVOID_IPC_KEY") {
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
                Some(std::sync::Arc::new(crate::process::IpcSigner::new(&key)))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut stream = if let Some(signer) = signer {
        crate::process::connect_to_master_signed(signer).await?
    } else {
        connect_to_master_async(
            master_socket,
            5,
            std::time::Duration::from_secs(2),
            "Unified server worker",
        )
        .await?
    };

    stream
        .send(&Message::UnifiedServerWorkerStarted {
            id: *worker_id,
            pid: std::process::id(),
            timestamp: current_timestamp(),
        })
        .await?;

    Ok(Arc::new(TokioMutex::new(stream)))
}

async fn setup_config(config_path: &std::path::Path) -> Arc<RwLock<ConfigManager>> {
    let mut config_manager = ConfigManager::new(config_path.to_path_buf());
    let main_config_path = config_path.join("main.toml");

    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main config: {}, using defaults", e);
    }

    config_manager.discover_sites();

    Arc::new(RwLock::new(config_manager))
}

async fn extract_bandwidth_config(
    config: &Arc<RwLock<ConfigManager>>,
) -> (
    Option<String>,
    u32,
    bool,
    crate::metrics::bandwidth::MonthlyResetConfig,
) {
    let config_guard = config.read().await;
    let bandwidth = &config_guard.main.traffic_shaping.bandwidth;
    let reset_cfg_external = bandwidth.monthly_reset.clone();
    let reset_cfg_internal: crate::metrics::bandwidth::MonthlyResetConfig =
        serde_json::from_str(&serde_json::to_string(&reset_cfg_external).unwrap())
            .unwrap();
    (
        bandwidth.data_dir.clone(),
        bandwidth.retention_days,
        bandwidth.mesh_excluded_from_total,
        reset_cfg_internal,
    )
}

#[derive(Clone)]
struct UnifiedServerWorkerState {
    worker_id: WorkerId,
    metrics: Arc<WorkerMetrics>,
    start_time: Instant,
    ipc: Arc<TokioMutex<AsyncIpcStream>>,
    running: RunningFlag,
    master_dead: RunningFlag,
    app_servers: Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>,
    draining: DrainFlag,
    drain_id: Arc<std::sync::atomic::AtomicU64>,
    stopped_accepting: DrainFlag,
    drain_state: Arc<WorkerDrainState>,
    stop_accepting_tx: Arc<TokioMutex<Option<tokio::sync::broadcast::Sender<()>>>>,
    unified_server: Arc<crate::server::UnifiedServer>,
    task_handles: Arc<TokioMutex<Vec<JoinHandle<()>>>>,
    request_services: Arc<RequestServices>,
}

pub async fn run_unified_server_worker(
    args: UnifiedServerWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let worker_id_raw = args.worker_id;
    crate::process::set_current_worker_id(worker_id_raw);

    let worker_id = WorkerId(worker_id_raw);

    // Apply CPU affinity if specified
    if let Some(core) = args.cpu_affinity {
        #[cfg(target_os = "linux")]
        {
            use nix::sched::{sched_setaffinity, CpuSet};
            use nix::unistd::Pid;

            let mut cpuset = CpuSet::new();
            if let Err(e) = cpuset.set(core) {
                tracing::warn!("Failed to set CPU core {} in CpuSet: {}", core, e);
            } else {
                let pid = Pid::from_raw(0); // Current process
                if let Err(e) = sched_setaffinity(pid, &cpuset) {
                    tracing::warn!("Failed to set CPU affinity to core {}: {}", core, e);
                } else {
                    tracing::info!(
                        "Unified Server Worker {} pinned to CPU core {}",
                        worker_id,
                        core
                    );
                }
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            tracing::info!("CPU affinity pinning requested for core {}, but not supported on this Unix platform", core);
        }
        #[cfg(not(unix))]
        {
            tracing::warn!("CPU affinity pinning is not supported on this platform");
        }
    }

    if let Some(ref level) = args.log_level {
        crate::log_controller::init_logging_with_dynamic_level(level);
    }

    // Start background heartbeat task for shared connection table
    if let Some(table) = crate::upstream::shared_state::SharedConnectionTable::get_global() {
        tokio::spawn(async move {
            loop {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                table.record_heartbeat(worker_id_raw, now);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    // Start system health monitor
    crate::metrics::health::SystemHealthMonitor::start();

    tracing::info!(
        "Unified Server Worker {} starting, config: {:?}, master socket: {:?}",
        worker_id,
        args.config_path,
        args.master_socket
    );

    let ipc = setup_worker_ipc(&args.master_socket, &worker_id).await?;

    let shared_config = setup_config(&args.config_path).await;

    {
        let config_guard = shared_config.read().await;
        let main_config = &config_guard.main;

        let mut ports_to_check = Vec::new();
        let mut port_labels = std::collections::HashMap::new();

        ports_to_check.push(main_config.server.port);
        port_labels.insert(main_config.server.port, "HTTP");

        if main_config.tls.enabled {
            ports_to_check.push(main_config.tls.port);
            port_labels.insert(main_config.tls.port, "TLS");
        }

        if main_config.http3.enabled {
            ports_to_check.push(main_config.http3.port);
            port_labels.insert(main_config.http3.port, "HTTP3");
        }

        if main_config.admin.enabled {
            ports_to_check.push(main_config.admin.port);
            port_labels.insert(main_config.admin.port, "Admin");
        }

        #[cfg(feature = "mesh")]
        if let Some(ref mesh_config) = main_config.mesh {
            if mesh_config.enabled {
                ports_to_check.push(mesh_config.port);
                port_labels.insert(mesh_config.port, "Mesh");
            }
        }

        if let Err(e) = check_ports_available(&ports_to_check) {
            let error_msg = e.to_string();
            let unavailable: Vec<u16> = error_msg
                .split(['[', ']', ' '])
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            let conflicts: Vec<String> = unavailable
                .iter()
                .map(|port| {
                    port_labels
                        .get(port)
                        .map(|label| format!("{} (port {})", label, port))
                        .unwrap_or_else(|| format!("port {}", port))
                })
                .collect();

            if conflicts.is_empty() {
                tracing::error!("Port conflict detected: {}", e);
            } else {
                tracing::error!(
                    "Port conflicts detected between services: {}. Other services may be affected.",
                    conflicts.join(", ")
                );
            }
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                if conflicts.is_empty() {
                    format!("Port conflict: {}", e)
                } else {
                    conflicts.join(", ")
                },
            )));
        }
    }

    {
        let config = shared_config.read().await;
        let passthrough_sites: Vec<_> = config
            .sites
            .iter()
            .filter(|(_, site)| site.proxy.tls_passthrough == Some(true))
            .map(|(id, _)| id.clone())
            .collect();
        let passthrough_with_waf: Vec<_> = config
            .sites
            .iter()
            .filter(|(_, site)| {
                site.proxy.tls_passthrough == Some(true)
                    && site.proxy.tls_passthrough_enforce_waf == Some(true)
            })
            .map(|(id, _)| id.clone())
            .collect();
        if !passthrough_sites.is_empty() {
            if !passthrough_with_waf.is_empty() {
                tracing::info!(
                    "TLS passthrough with WAF enforcement enabled for sites: {:?}. WAF will inspect L7 traffic.",
                    passthrough_with_waf
                );
            }
            let bypass_sites: Vec<_> = passthrough_sites
                .iter()
                .filter(|s| !passthrough_with_waf.contains(s))
                .cloned()
                .collect();
            if !bypass_sites.is_empty() {
                tracing::error!(
                    "TLS passthrough is enabled for sites: {:?}. WAF inspection is BYPASSED for these sites - L7 attacks will not be blocked. Set tls_passthrough_enforce_waf = true to enable WAF inspection for passthrough traffic.",
                    bypass_sites
                );
                crate::metrics::record_tls_passthrough_waf_bypassed();
            }
            let rate_limited_sites: Vec<_> = bypass_sites
                .iter()
                .filter(|s| {
                    let site_config = config.sites.get(*s);
                    let rl = site_config.map(|s| &s.ratelimit);
                    rl.is_none()
                })
                .cloned()
                .collect();
            if !rate_limited_sites.is_empty() {
                tracing::error!(
                    "TLS passthrough sites {:?} do not have rate limiting configured. Rate limiting is required for passthrough sites to prevent abuse.",
                    rate_limited_sites
                );
            }
        }
    }

    let (
        bandwidth_data_dir,
        bandwidth_retention_days,
        bandwidth_mesh_excluded,
        bandwidth_reset_config,
    ) = extract_bandwidth_config(&shared_config).await;

    // Initialize global bandwidth tracker with config values
    crate::metrics::bandwidth::init_global_bandwidth_tracker(
        bandwidth_retention_days,
        bandwidth_mesh_excluded,
    );

    // Configure persistence and reset settings
    crate::metrics::bandwidth::configure_global_bandwidth_tracker(
        bandwidth_data_dir.as_deref(),
        bandwidth_reset_config,
    );

    let drain_state = Arc::new(WorkerDrainState::new());
    let metrics =
        WorkerMetrics::shared_with_bandwidth(bandwidth_retention_days, bandwidth_mesh_excluded);
    let ipc_for_server = ipc.clone();
    let worker_id_for_server = worker_id;

    // App servers (Granian supervisors) - initialized before UnifiedServer
    let app_servers = Arc::new(RwLock::new(HashMap::new()));
    let app_servers_init = app_servers.clone();

    // Initialize serverless manager if configured
    let serverless_manager = {
        let config = shared_config.read().await;
        let serverless_config = &config.main.serverless;
        if serverless_config.enabled {
            let runtime = get_global_plugin_manager().get_wasm_manager();
            let manager = Arc::new(
                crate::serverless::manager::ServerlessManager::new().with_runtime(runtime),
            );
            if let Err(e) = manager.initialize(serverless_config.clone()) {
                tracing::warn!("Failed to initialize serverless manager: {}", e);
                None
            } else {
                tracing::info!(
                    "Serverless manager initialized with {} functions",
                    serverless_config.functions.len()
                );
                Some(manager)
            }
        } else {
            None
        }
    };

    let unified_server = UnifiedServer::new(
        shared_config.clone(),
        None,
        app_servers.clone(),
        args.total_workers,
    )
    .await?
    .with_drain_state(drain_state.clone())
        .with_metrics(metrics.clone())
        .with_ipc(ipc_for_server, worker_id_for_server)
        .with_serverless_manager(serverless_manager.unwrap_or_else(|| {
            let runtime = get_global_plugin_manager().get_wasm_manager();
            Arc::new(crate::serverless::manager::ServerlessManager::new().with_runtime(runtime))
        }));

    // Wrap in Arc immediately for easier sharing
    let unified_server: Arc<UnifiedServer> = Arc::new(unified_server);

    // Setup ACME if enabled (this spawns the renewal task)
    #[cfg(feature = "dns")]
    {
        if let Some(acme_manager) = unified_server.setup_acme() {
            tracing::info!("ACME manager started for worker {}", worker_id);

            // Wire AcmeDnsChallenge to DNS server for DNS-01 support
            if let Some(dns_server) = unified_server.get_dns_server() {
                if let Some(dns_challenges) = acme_manager.get_dns_challenges() {
                    let _server = (*dns_server)
                        .clone()
                        .with_acme_dns_challenges(dns_challenges);
                    tracing::info!("ACME DNS-01 challenges wired to DNS server");
                }
            }
        }
    }

    // Initialize Granian supervisors for AppServer backends
    let app_servers_for_init = app_servers_init.clone();
    let worker_id_for_app = worker_id;
    let config_for_app = shared_config.clone();
    tokio::spawn(async move {
        let config = config_for_app.read().await;

        for (site_id, site_config) in config.sites.iter() {
            let app_config = site_config.app_server_config();
            if !app_config.is_valid() {
                continue;
            }

            let app_config_internal: crate::app_server::AppServerConfig =
                serde_json::from_str(&serde_json::to_string(&app_config).unwrap())
                    .unwrap();
            let mut granian_config = GranianConfig::from(&app_config_internal);
            granian_config = granian_config.with_site_info(site_id, worker_id_for_app.as_usize());

            tracing::info!(
                "Initializing granian for site {} on unified server worker with socket: {}",
                site_id,
                granian_config.resolve_socket_path().display()
            );

            let supervisor = Arc::new(GranianSupervisor::new(granian_config));

            if let Err(e) = supervisor.start().await {
                tracing::error!("Failed to start granian for site {}: {}", site_id, e);
                continue;
            }

            app_servers_for_init
                .write()
                .await
                .insert(site_id.clone(), supervisor.clone());
            crate::app_server::register_granian_supervisor(site_id, supervisor);
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Start background tasks for WAF components (ASN cleanup, etc.)
    unified_server.get_waf().start_background_tasks();

    // Initialize UploadValidator
    {
        let upload_config = {
            let config = shared_config.read().await;
            let defaults = &config.main.defaults.upload;
            crate::upload::UploadConfig {
                enabled: defaults.enabled,
                max_size: defaults.max_size.clone(),
                memory_threshold: defaults.memory_threshold.clone(),
                scan_with_yara: defaults.scan_with_yara,
                sandbox_enabled: defaults.sandbox_enabled,
                sandbox_dir: defaults.sandbox_dir.clone(),
                quarantine_dir: defaults.quarantine_dir.clone(),
                yara_rules_dir: defaults.yara_rules_dir.clone(),
                yara_timeout_ms: defaults.yara_timeout_ms,
                verify_signature: true,
                signature_strict_mode: false,
                rate_limit_enabled: true,
                max_uploads_per_minute: 30,
                max_uploads_per_hour: 200,
                max_bytes_per_minute: "100MB".to_string(),
                burst_allowance: 5,
                allowed_types: crate::upload::AllowedTypesConfig {
                    mode: crate::upload::AllowedTypesMode::Allowlist,
                    mime_types: defaults.allowed_types.mime_types.clone(),
                },
                paths: Vec::new(),
                reject_mime_mismatch: false,
            }
        };

        match UploadValidator::new(upload_config) {
            Ok(validator) => {
                let validator = Arc::new(validator);
                crate::waf::set_upload_validator(validator);
                tracing::info!("UploadValidator initialized");
            }
            Err(e) => {
                tracing::warn!("Failed to initialize UploadValidator: {}", e);
            }
        }
    }

    // Initialize Port Honeypot
    let honeypot_port_config = {
        let config = shared_config.read().await;
        config.main.honeypot_port.clone()
    };

    let port_honeypot_runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>> =
        if honeypot_port_config.enabled {
            let port_honeypot_config = crate::honeypot_port::PortHoneypotConfig {
                enabled: honeypot_port_config.enabled,
                min_port: honeypot_port_config
                    .ports
                    .iter()
                    .copied()
                    .min()
                    .unwrap_or(10000),
                max_port: honeypot_port_config
                    .ports
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(60000),
                num_honeypot_ports: honeypot_port_config.ports.len(),
                site_scope: honeypot_port_config.site_scope.clone(),
                ..Default::default()
            };

            match crate::honeypot_port::PortHoneypotRunner::new(port_honeypot_config) {
                Ok(runner) => {
                    tracing::info!("Port honeypot runner initialized");
                    Some(runner)
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize port honeypot runner: {}", e);
                    None
                }
            }
        } else {
            tracing::info!("Port honeypot is disabled");
            None
        };

    // Spawn port honeypot background task
    if let Some(ref runner) = port_honeypot_runner {
        let runner_clone = runner.clone();
        tokio::spawn(async move {
            runner_clone.run().await;
        });
    }

    // ============================================================================================
    // Mesh and Threat Intelligence Initialization
    //
    // The UnifiedServer Worker handles all mesh connections (WAF-WAF, WAF-User VPN, WAF-Server VPN).
    // This ensures:
    // - Direct proxying without IPC overhead for mesh traffic
    // - Process isolation: mesh-related vulnerabilities don't affect Master
    // - Single mesh identity per WAF deployment (shared across Workers via Master config)
    // ============================================================================================
    #[cfg(feature = "mesh")]
    let mesh_config_external = {
        let config = shared_config.read().await;
        config.main.tunnel.mesh.clone()
    };
    
    #[cfg(feature = "mesh")]
    let mesh_config: Option<crate::mesh::config::MeshConfig> = mesh_config_external.map(|c| {
        serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap()
    });

    #[cfg(feature = "mesh")]
    let (_mesh_transport_manager, _threat_intel_manager, _mesh_signer) = if let Some(
        ref mesh_config,
    ) = mesh_config
    {
        // Phase 3: Mesh Control Plane is relegated to the Supervisor process.
        // Workers act as dumb data-planes and receive intelligence via IPC.
        if true {
            tracing::info!("Mesh control plane is disabled in worker process");
            let threat_persistence_path = args
                .config_path
                .parent()
                .map(|p| p.join("threat_intel.json"));
            let dummy_threat = if let Some(ref path) = threat_persistence_path {
                Arc::new(ThreatIntelligenceManager::new_for_standalone(
                    crate::mesh::threat_intel::ThreatIntelligenceConfig::default().to_internal(),
                    Arc::new(crate::block_store::BlockStore::new(
                        true,
                        None,
                        crate::config::DenyListLimitsConfig::default(),
                    )),
                    "dummy".to_string(),
                    crate::mesh::config::MeshNodeRole::EDGE,
                    None,
                    path.clone(),
                ))
            } else {
                Arc::new(ThreatIntelligenceManager::new(
                    crate::mesh::threat_intel::ThreatIntelligenceConfig::default().to_internal(),
                    Arc::new(crate::block_store::BlockStore::new(
                        true,
                        None,
                        crate::config::DenyListLimitsConfig::default(),
                    )),
                    "dummy".to_string(),
                    crate::mesh::config::MeshNodeRole::EDGE,
                    None,
                ))
            };
            dummy_threat.start_background_tasks();
            crate::waf::set_threat_intel(dummy_threat.clone());
            (
                None::<Arc<MeshTransportManager>>,
                Some(dummy_threat),
                None::<Arc<crate::mesh::protocol::MeshMessageSigner>>,
            )
        } else {
            tracing::info!("Initializing mesh transport in UnifiedServer Worker...");

            let node_id = mesh_config.node_id();

            // Create mesh config as Arc
            let mesh_config_arc = Arc::new(mesh_config.clone());

            // Create mesh topology first
            let topology = Arc::new(MeshTopology::new(mesh_config_arc.clone()));
            topology.start_background_tasks();

            // Create DHT routing manager if enabled
            let routing_manager = if mesh_config
                .dht
                .as_ref()
                .map(|d| d.routing_enabled)
                .unwrap_or(false)
            {
                let manager = Arc::new(crate::mesh::dht::routing::DhtRoutingManager::new(
                    mesh_config_arc.clone(),
                ));
                let manager_clone = manager.clone();
                manager.start_background_tasks();
                tokio::spawn(async move {
                    manager_clone.init().await;
                });
                Some(manager)
            } else {
                None
            };

            // Create verification pool for PQC offloading
            let verification_pool =
                Arc::new(crate::mesh::crypto_verification::CryptoVerificationPool::default());

            // Create DHT record store if DHT is enabled
            let record_store = create_record_store(
                mesh_config,
                routing_manager,
                Some(verification_pool.clone()),
            );

            // Create mesh transport manager with config, topology, and record_store
            let transport_manager = Arc::new(MeshTransportManager::new(
                mesh_config_arc.clone(),
                topology.clone(),
                record_store.clone(),
            ));

            // Create backend pool and proxy for RaftAwareClient
            let proxy = Arc::new(crate::mesh::proxy::MeshProxy::new(
                mesh_config_arc.clone(),
                topology.clone(),
                None,
            ));
            let backend_pool = Arc::new(crate::mesh::backend::MeshBackendPool::new(
                proxy.clone(),
                topology.clone(),
            ));

            // Create signer for threat messages (HMAC)
            // Use global_node_key if available, otherwise generate from node_id
            let signer_key = if let Some(ref key) = mesh_config.global_node_key {
                let mut key_bytes = [0u8; 32];
                let key_str = key.as_bytes();
                let len = key_str.len().min(32);
                key_bytes[..len].copy_from_slice(&key_str[..len]);
                key_bytes
            } else {
                // Derive a cryptographically secure key from node_id using HKDF
                use hkdf::Hkdf;
                use sha2::Sha256;
                let ikm = node_id.as_bytes();
                let hk = Hkdf::<Sha256>::new(None, ikm);
                let mut okm = [0u8; 32];
                hk.expand(b"synvoid-mesh-signer", &mut okm)
                    .expect("HKDF expand failed");
                okm
            };

            // Create ThreatIntelligenceManager for this worker
            // Get BlockStore from UnifiedServer if available
            let Some(block_store) = unified_server.get_block_store() else {
                tracing::warn!("BlockStore not initialized, skipping threat intelligence setup");
                return Ok(());
            };

            let mesh_threat_intel = mesh_config.threat_intel.clone();

            let threat_config = ThreatIntelligenceConfig {
                enabled: mesh_threat_intel.enabled,
                push_enabled: mesh_threat_intel.push_enabled,
                sync_enabled: mesh_threat_intel.sync_enabled,
                sync_interval_secs: mesh_threat_intel.sync_interval_secs,
                threat_sync_interval_secs: mesh_threat_intel.threat_sync_interval_secs,
                push_severity_threshold: mesh_threat_intel.push_severity_threshold,
                min_ttl_seconds: mesh_threat_intel.min_ttl_seconds,
                max_indicators_per_message: mesh_threat_intel.max_indicators_per_message,
                hub_only_mode: mesh_threat_intel.hub_only_mode,
                reputation_config: mesh_threat_intel.reputation_config.clone(),
                fanout_factor: mesh_threat_intel.fanout_factor,
                re_announce_interval_secs: mesh_threat_intel.re_announce_interval_secs,
                trusted_signers: mesh_threat_intel.trusted_signers.clone(),
                behavioral_enabled: mesh_threat_intel.behavioral_enabled,
                min_samples_for_fingerprint: mesh_threat_intel.min_samples_for_fingerprint,
                fingerprint_ttl_secs: mesh_threat_intel.fingerprint_ttl_secs,
                high_severity_threshold: mesh_threat_intel.high_severity_threshold,
            };

            // Create signer for threat intel
            let signer_for_threat = crate::mesh::protocol::MeshMessageSigner::new(signer_key)
                .with_verification_pool(verification_pool.clone());

            // Create signer for returning (we need to create another one since we can't clone)
            let signer_key_clone = signer_key;

            let threat_intel = Arc::new(ThreatIntelligenceManager::from_external_config(
                threat_config.clone(),
                block_store.clone(),
                node_id.clone(),
                mesh_config.role,
                Some(Arc::new(signer_for_threat)),
            ));

            // Initialize mesh transports (WireGuard/QUIC)
            // This connects to other WAF nodes in the mesh
            // Pass threat_intel so transport can update global nodes in threat intel
            let signer_for_mesh = crate::mesh::protocol::MeshMessageSigner::new(signer_key_clone)
                .with_verification_pool(verification_pool.clone());
            #[cfg(feature = "dns")]
            {
                // Get DNS config for mesh registry
                // SECURITY: Only global nodes perform DNS verification - edge nodes are untrusted
                let dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>> = {
                    let config = shared_config.read().await;
                    let dns_cfg = config.main.dns.clone();

                    if !dns_cfg.enabled {
                        if mesh_config.role.is_global() {
                            tracing::warn!(
                                "Global node has dns.enabled = false — global nodes are required \
                                 to serve DNS. DNS-dependent mesh features (verification, \
                                 zone signing) will be unavailable."
                            );
                        }
                        None
                    } else if !mesh_config.role.is_global() {
                        // Edge nodes do NOT get a resolver - they cannot perform verification
                        // Only global nodes (which are trusted) perform DNS verification
                        tracing::debug!("Edge node - DNS resolver not created (verification only on global nodes)");

                        // Create minimal registry for edge nodes (no resolver)
                        let registry_config = crate::dns::MeshDnsRegistryConfig {
                            verification_timeout_secs: dns_cfg.mesh.verification_timeout_secs,
                            verification_retry_interval_secs: dns_cfg
                                .mesh
                                .verification_retry_interval_secs,
                            require_cert_chain_verification: dns_cfg
                                .mesh
                                .require_cert_chain_verification,
                            ..Default::default()
                        };

                        let registry = crate::dns::MeshDnsRegistry::with_config(
                            mesh_config.node_id(),
                            false, // not global
                            registry_config,
                        );
                        Some(Arc::new(registry))
                    } else {
                        // Global node - create resolver for verification
                        let upstream_servers: Vec<std::net::IpAddr> = dns_cfg
                            .mesh
                            .upstream_dns_servers
                            .iter()
                            .filter_map(|s| s.parse().ok())
                            .collect();

                        if upstream_servers.is_empty() {
                            tracing::warn!("No valid upstream DNS servers configured, DNS verification will not work");
                            None
                        } else {
                            // Create resolver with configured upstream servers
                            match crate::dns::HickoryResolver::with_upstream_servers(
                                &upstream_servers,
                            ) {
                                Ok(resolver) => {
                                    tracing::info!("Global node DNS resolver initialized with upstream servers: {:?}", upstream_servers);

                                    // Create mesh DNS registry with resolver - only global nodes verify
                                    let registry_config = crate::dns::MeshDnsRegistryConfig {
                                        verification_timeout_secs: dns_cfg
                                            .mesh
                                            .verification_timeout_secs,
                                        verification_retry_interval_secs: dns_cfg
                                            .mesh
                                            .verification_retry_interval_secs,
                                        require_cert_chain_verification: dns_cfg
                                            .mesh
                                            .require_cert_chain_verification,
                                        ..Default::default()
                                    };

                                    let registry = crate::dns::MeshDnsRegistry::with_config(
                                        mesh_config.node_id(),
                                        true, // is global - performs verification
                                        registry_config,
                                    )
                                    .with_dns_resolver(resolver);

                                    // Start the verification loop for global nodes
                                    let registry_clone = registry.clone();
                                    tokio::spawn(async move {
                                        registry_clone.start_verification_loop().await;
                                    });

                                    Some(Arc::new(registry))
                                }
                                Err(e) => {
                                    tracing::error!("Failed to create DNS resolver: {}", e);
                                    None
                                }
                            }
                        }
                    }
                };

                if let Err(e) = crate::mesh::backend::initialize_mesh_transports(
                    mesh_config,
                    transport_manager.clone(),
                    backend_pool.clone(),
                    Some(threat_intel.clone()),
                    Some(Arc::new(signer_for_mesh)),
                    None::<Arc<dyn crate::dns::resolver::DnsResolver>>,
                    dns_registry,
                )
                .await
                {
                    tracing::warn!("Mesh transport initialization failed: {}", e);
                }
            }
            #[cfg(not(feature = "dns"))]
            {
                if mesh_config.role.is_global() {
                    tracing::warn!(
                        "Global node compiled without dns feature — DNS serving is unavailable. \
                         Global nodes are required to serve DNS."
                    );
                }
                if let Err(e) = crate::mesh::backend::initialize_mesh_transports(
                    &mesh_config,
                    transport_manager.clone(),
                    backend_pool,
                    Some(threat_intel.clone()),
                    Some(Arc::new(signer_for_mesh)),
                )
                .await
                {
                    tracing::warn!("Mesh transport initialization failed: {}", e);
                }
            }

            // Wire mesh_sender for threat intel and YARA rules mesh broadcast
            let mesh_broadcast_tx_for_yara = {
                let (mesh_broadcast_tx, mut mesh_broadcast_rx) =
                    tokio::sync::mpsc::channel::<crate::mesh::protocol::MeshMessage>(128);

                // Set sender on threat_intel before start_background_tasks()
                threat_intel.set_mesh_sender(mesh_broadcast_tx.clone());

                // Spawn forwarder task that receives mesh messages and broadcasts to peers
                if let Some(quic_transport) = transport_manager.get_quic_transport() {
                    let mesh_transport = quic_transport.get_inner();
                    let broadcast_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
                    tokio::spawn(async move {
                        while let Some(msg) = mesh_broadcast_rx.recv().await {
                            let transport = mesh_transport.clone();
                            let permit = broadcast_semaphore.clone().acquire_owned().await.ok();
                            tokio::spawn(async move {
                                transport
                                    .broadcast_to_all_peers(
                                        msg,
                                        Some(crate::mesh::config::MeshNodeRole::GLOBAL),
                                    )
                                    .await;
                                drop(permit);
                            });
                        }
                    });
                }

                mesh_broadcast_tx
            };

            // Announce key exchange endpoint if global node with key exchange enabled
            if mesh_config.role.is_global()
                && mesh_config.global_node.key_exchange_enabled
                && mesh_config.origin_signing_key.is_some()
            {
                // Update key exchange endpoint announcement
                transport_manager.update_key_exchange_endpoint().await;
            }

            // Announce edge node key if edge with key exchange auth enabled
            if mesh_config.role == crate::mesh::config::MeshNodeRole::EDGE
                && mesh_config.global_node.key_exchange_enabled
                && mesh_config.global_node.key_exchange_require_edge_auth
            {
                if let Some(ref global_node_key) = mesh_config.global_node_key {
                    // Announce edge's public key to DHT for global nodes to verify tokens
                    transport_manager.announce_edge_key(&mesh_config.node_id(), global_node_key);
                }
            }

            // Announce node capabilities to DHT for discovery
            {
                let capabilities = crate::mesh::protocol::MeshCapabilities::from_config(
                    mesh_config,
                    mesh_config.role,
                );
                if !capabilities.supported_services.is_empty() {
                    transport_manager.announce_capabilities(
                        &mesh_config.node_id(),
                        &capabilities.supported_services,
                    );
                }
            }

            // Start background tasks for threat intel (periodic sync, cleanup)
            threat_intel.start_background_tasks();

            // Set threat_intel in thread-local so it can be accessed by blocking code
            crate::waf::set_threat_intel(threat_intel.clone());

            // Initialize YARA rules manager
            {
                let main_config = {
                    let config = shared_config.read().await;
                    config.main.clone()
                };

                if mesh_config.yara_rules.enabled || main_config.yara_feed.enabled {
                    let feed_mgr: Option<Arc<crate::upload::yara_rule_feed::YaraRuleFeedManager>> =
                        if main_config.yara_feed.enabled {
                            Some(crate::upload::YaraRuleFeedManager::new(
                                main_config.yara_feed.clone(),
                            ))
                        } else {
                            None
                        };

                    // Use config_dir as data directory for YARA submissions
                    let yara_data_dir = args.config_path.parent().map(|p| p.to_path_buf());

                    let signer_for_yara: Option<Arc<crate::mesh::protocol::MeshMessageSigner>> =
                        Some(Arc::new(crate::mesh::protocol::MeshMessageSigner::new(
                            signer_key,
                        )));

                    let yara_rules = Arc::new(YaraRulesManager::new(
                        mesh_config.yara_rules.clone().into(),
                        node_id.clone(),
                        mesh_config.role,
                        signer_for_yara,
                        feed_mgr,
                        yara_data_dir,
                    ));

                    // Wire mesh sender for YARA rules mesh broadcast
                    yara_rules.set_mesh_sender(mesh_broadcast_tx_for_yara.clone());

                    // Wire record store for YARA rules DHT distribution
                    if let Some(record_store) = transport_manager.get_record_store() {
                        yara_rules.set_record_store(record_store.clone());
                        crate::mesh::set_global_record_store(record_store);
                    }

                    // Get elevated threat level for feed polling interval
                    let is_elevated: Arc<parking_lot::RwLock<bool>> =
                        Arc::new(parking_lot::RwLock::new(false));

                    // Start background fetching for feed if enabled
                    if yara_rules.has_feed_manager() {
                        let fm = yara_rules
                            .get_feed_manager()
                            .expect("guarded by has_feed_manager check");
                        let elevated_clone = is_elevated.clone();
                        fm.start_background_fetching(elevated_clone);

                        // Try to apply rules from feed on startup
                        if let Err(e) = yara_rules.apply_rules_from_feed() {
                            tracing::debug!("No feed rules to apply on startup: {}", e);
                        }
                    }

                    // Set in thread-local
                    crate::waf::set_yara_rules(yara_rules.clone());

                    // Start periodic YARA sync task
                    if mesh_config.yara_rules.sync_interval_secs > 0 {
                        let sync_manager = yara_rules.clone();
                        let sync_interval = std::time::Duration::from_secs(
                            mesh_config.yara_rules.sync_interval_secs,
                        );
                        tokio::spawn(async move {
                            let mut ticker = tokio::time::interval(sync_interval);
                            loop {
                                ticker.tick().await;
                                let _ = sync_manager.sync_from_dht();
                                sync_manager.record_sync();
                            }
                        });
                        tracing::info!(
                            "YARA DHT sync task started (interval: {}s)",
                            mesh_config.yara_rules.sync_interval_secs
                        );
                    }

                    // Start periodic YARA re-announce task for global nodes
                    if mesh_config.yara_rules.re_announce_interval_secs > 0
                        && mesh_config.role.is_global()
                    {
                        let rules_manager = yara_rules.clone();
                        let re_announce_interval = std::time::Duration::from_secs(
                            mesh_config.yara_rules.re_announce_interval_secs,
                        );
                        tokio::spawn(async move {
                            let mut ticker = tokio::time::interval(re_announce_interval);
                            loop {
                                ticker.tick().await;
                                rules_manager.publish_rules_to_dht();
                            }
                        });
                        tracing::info!(
                            "YARA re-announce task started (interval: {}s)",
                            mesh_config.yara_rules.re_announce_interval_secs
                        );
                    }

                    tracing::info!("YARA rules manager initialized");
                }
            }

            tracing::info!("Mesh and threat intelligence initialized in UnifiedServer Worker");

            // Key exchange endpoints are served by the main HTTP/HTTPS server
            // For global nodes with key exchange enabled
            let is_global = mesh_config_arc.role.is_global();
            if is_global
                && mesh_config_arc.global_node.key_exchange_enabled
                && mesh_config_arc.origin_signing_key.is_some()
            {
                tracing::info!("Key exchange endpoints enabled on global node at /key-request-origin, /key-confirm, /health");
            } else if is_global && !mesh_config_arc.global_node.key_exchange_enabled {
                tracing::info!(
                    "Key exchange server disabled on global node (key_exchange_enabled=false)"
                );
            }

            // Note: threat_intel is set on WafCore after creation in unified_server initialization
            // The proxy/handler code accesses threat_intel through self.waf.threat_intel

            (
                Some(transport_manager),
                Some(threat_intel),
                Some(Arc::new(crate::mesh::protocol::MeshMessageSigner::new(
                    signer_key_clone,
                ))),
            )
        }
    } else {
        let threat_persistence_path = args
            .config_path
            .parent()
            .map(|p| p.join("threat_intel.json"));
        let dummy_threat = if let Some(ref path) = threat_persistence_path {
            Arc::new(ThreatIntelligenceManager::new_for_standalone(
                crate::mesh::threat_intel::ThreatIntelligenceConfig::default().to_internal(),
                Arc::new(crate::block_store::BlockStore::new(
                    true,
                    None,
                    crate::config::DenyListLimitsConfig::default(),
                )),
                "dummy".to_string(),
                crate::mesh::config::MeshNodeRole::EDGE,
                None,
                path.clone(),
            ))
        } else {
            Arc::new(ThreatIntelligenceManager::new(
                crate::mesh::threat_intel::ThreatIntelligenceConfig::default().to_internal(),
                Arc::new(crate::block_store::BlockStore::new(
                    true,
                    None,
                    crate::config::DenyListLimitsConfig::default(),
                )),
                "dummy".to_string(),
                crate::mesh::config::MeshNodeRole::EDGE,
                None,
            ))
        };
        dummy_threat.start_background_tasks();
        crate::waf::set_threat_intel(dummy_threat.clone());
        (
            None::<Arc<MeshTransportManager>>,
            Some(dummy_threat),
            None::<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        )
    };

    // Wire serverless manager to record store and routing manager if mesh is enabled
    #[cfg(feature = "mesh")]
    if let Some(sm) = unified_server.get_serverless_manager() {
        #[cfg(feature = "mesh")]
        if let Some(ref tm) = _mesh_transport_manager {
            #[cfg(feature = "mesh")]
            if let Some(rs) = tm.get_record_store() {
                sm.set_record_store(rs);
                tracing::info!("Serverless manager wired to DHT record store");
            }
            #[cfg(feature = "mesh")]
            if let Some(quic) = tm.get_quic_transport() {
                sm.set_transport(quic.get_inner());
                tracing::info!("Serverless manager wired to mesh transport");
            }
            #[cfg(feature = "mesh")]
            if let Some(quic) = tm.get_quic_transport() {
                let inner = quic.get_inner();
                inner.set_serverless_manager(sm.clone());
                tracing::info!("Mesh transport wired to serverless manager for origin mode");
            }
        }
    }

    // Wire up port honeypot threat publishing to mesh network (or standalone)
    #[cfg(feature = "mesh")]
    if let Some(ref runner) = port_honeypot_runner {
        #[cfg(feature = "mesh")]
        if let Some(ref threat_intel) = _threat_intel_manager {
            runner.start_mesh_threat_publishing(threat_intel.clone(), 30);
            #[cfg(feature = "mesh")]
            if _mesh_transport_manager.is_some() {
                tracing::info!("Port honeypot threat publishing wired to mesh network");
            } else {
                tracing::info!("Port honeypot threat publishing in standalone mode");
            }
        }
    }

    // Register this worker with Master for threat intelligence coordination
    // The Master orchestrates what intelligence is shared globally
    // Note: UnifiedServerWorkerReady is sent after full state construction (see below)

    // Request blocklist from Master on startup
    let Some(block_store) = unified_server.get_block_store() else {
        tracing::warn!("BlockStore not initialized, skipping blocklist request");
        return Ok(());
    };
    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&Message::BlocklistRequest {
                worker_id: worker_id.as_usize(),
                from_version: 0,
            })
            .await?;

        // Wait for response with timeout
        let timeout = Duration::from_secs(5);
        let start = Instant::now();
        while start.elapsed() < timeout {
            match ipc_guard.recv_with_timeout::<Message>(100).await {
                Ok(Some(Message::BlocklistResponse { blocks, .. })) => {
                    tracing::info!(
                        "Received blocklist from Master with {} entries",
                        blocks.len()
                    );
                    for block in blocks {
                        if let Ok(ip) = block.ip.parse() {
                            let _ = block_store.block_ip(
                                ip,
                                &block.reason,
                                block.ban_expire_seconds,
                                &block.site_scope,
                            );
                        }
                    }
                    break;
                }
                Ok(Some(msg)) => {
                    // Other messages - could queue them for later processing
                    tracing::debug!("Received non-blocklist message during startup: {:?}", msg);
                }
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(_) => break,
            }
        }
    }

    let metrics = WorkerMetrics::shared();
    let running = RunningFlag::new();

    let draining = DrainFlag::new();
    let drain_id = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stopped_accepting = DrainFlag::new();

    // Get stop_accepting_sender - unified_server is already Arc
    let stop_accepting_sender = unified_server.get_stop_accepting_sender();
    let stop_accepting_tx = Arc::new(TokioMutex::new(Some(stop_accepting_sender)));

    let request_services = {
        #[cfg(feature = "mesh")]
        {
            let threat_intel = _threat_intel_manager.clone();
            let yara_rules = if let Some(yr) = crate::waf::get_yara_rules() {
                Some(yr)
            } else {
                None
            };
            RequestServices::new(threat_intel, None, yara_rules, None, None)
        }
        #[cfg(not(feature = "mesh"))]
        {
            RequestServices::new(None, None, None)
        }
    };

    let request_services = Arc::new(request_services);

    unified_server
        .get_waf()
        .set_request_services(request_services.clone());

    let state = UnifiedServerWorkerState {
        worker_id,
        metrics: metrics.clone(),
        start_time: Instant::now(),
        ipc: ipc.clone(),
        running: running.clone(),
        master_dead: RunningFlag::new(),
        app_servers: app_servers.clone(),
        draining: draining.clone(),
        drain_id: drain_id.clone(),
        stopped_accepting: stopped_accepting.clone(),
        drain_state: drain_state.clone(),
        stop_accepting_tx: stop_accepting_tx.clone(),
        unified_server: unified_server.clone(),
        task_handles: Arc::new(TokioMutex::new(Vec::new())),
        request_services: request_services.clone(),
    };

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
    }

    tracing::info!("Unified Server Worker {} ready", worker_id);

    let worker_exit_code: Arc<std::sync::atomic::AtomicI32> =
        Arc::new(std::sync::atomic::AtomicI32::new(0));

    let heartbeat_state = state.clone();
    let task_handles = state.task_handles.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            if !heartbeat_state.running.is_running() {
                break;
            }

            let uptime = heartbeat_state.start_time.elapsed().as_secs();
            let payload = heartbeat_state.metrics.to_payload(uptime);
            let timestamp = current_timestamp();
            let worker_id = heartbeat_state.worker_id;

            let app_health: Vec<(String, bool)> = {
                let app_servers = heartbeat_state.app_servers.read().await;
                app_servers
                    .iter()
                    .map(|(site_id, supervisor)| (site_id.clone(), supervisor.is_healthy()))
                    .collect()
            };

            let mut ipc = heartbeat_state.ipc.lock().await;
            let _ = ipc
                .send(&Message::UnifiedServerWorkerHeartbeat {
                    id: worker_id,
                    timestamp,
                    metrics: payload,
                })
                .await;

            for (site_id, healthy) in app_health {
                let _ = ipc
                    .send(&Message::AppServerHealth {
                        id: worker_id,
                        site_id,
                        healthy,
                        timestamp,
                    })
                    .await;
            }
        }
    });
    task_handles.lock().await.push(heartbeat_handle);

    let task_handles = state.task_handles.clone();
    let bandwidth_persist_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;
            crate::metrics::bandwidth::persist_global_bandwidth_tracker();
        }
    });
    task_handles.lock().await.push(bandwidth_persist_handle);

    let ipc_state = state.clone();
    let ipc_exit_code = worker_exit_code.clone();
    let ipc_handle = tokio::spawn(async move {
        loop {
            if !ipc_state.running.is_running() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;

            let message = {
                let mut ipc = ipc_state.ipc.lock().await;
                match ipc.recv_with_timeout::<Message>(50).await {
                    Ok(Some(msg)) => Some(msg),
                    Ok(None) => None,
                    Err(_) => {
                        tracing::warn!("Unified server worker lost connection to master");
                        ipc_state.master_dead.stop();
                        break;
                    }
                }
            };

            match message {
                Some(Message::MasterShutdown {
                    graceful,
                    timeout_secs,
                }) => {
                    tracing::info!(
                        "Unified Server Worker {} received shutdown signal (graceful: {}, timeout: {}s)",
                        ipc_state.worker_id,
                        graceful,
                        timeout_secs
                    );

                    tracing::info!(
                        "Stopping app servers for unified server worker {}",
                        ipc_state.worker_id
                    );
                    let app_servers = ipc_state.app_servers.read().await;
                    for (site_id, supervisor) in app_servers.iter() {
                        tracing::info!("Stopping granian for site {}", site_id);
                        supervisor.stop().await;
                    }
                    drop(app_servers);

                    ipc_state.running.stop();

                    tracing::info!("Persisting bandwidth data on shutdown...");
                    crate::metrics::bandwidth::persist_global_bandwidth_tracker();

                    tracing::info!("Aborting spawned tasks...");
                    let handles = ipc_state.task_handles.lock().await;
                    for handle in handles.iter() {
                        handle.abort();
                    }
                    drop(handles);

                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc
                        .send(&Message::UnifiedServerWorkerShutdownComplete {
                            id: ipc_state.worker_id,
                        })
                        .await;
                    break;
                }
                Some(Message::MasterConfigReload { config_path }) => {
                    tracing::info!(
                        "Unified Server Worker {} received config reload: {}",
                        ipc_state.worker_id,
                        config_path
                    );

                    if cfg!(feature = "mesh") {
                        tracing::error!(
                            "Config hot-reload is not supported when mesh feature is enabled. \
                            Mesh, YARA rules, threat intel, and honeypot changes require full worker restart. \
                            Please restart the worker to apply mesh-related configuration changes."
                        );
                        let mut ipc = ipc_state.ipc.lock().await;
                        let _ = ipc.send(&Message::WorkerError {
                            id: ipc_state.worker_id,
                            error: "Config hot-reload not supported with mesh feature enabled".to_string(),
                            severity: crate::process::ErrorSeverity::Warning,
                            error_code: crate::process::ErrorCode::ConfigLoadFailed,
                        }).await;
                        continue;
                    }

                    let config_dir = std::path::Path::new(&config_path);
                    let mut cm = ConfigManager::new(config_dir.to_path_buf());
                    let main_path = config_dir.join("main.toml");
                    if cm.load_main(&main_path).is_ok() {
                        cm.discover_sites();
                        *shared_config.write().await = cm;

                        tracing::info!(
                            "Unified Server Worker {} config reloaded.",
                            ipc_state.worker_id
                        );
                    } else {
                        tracing::warn!(
                            "Unified Server Worker {} failed to reload config from {}",
                            ipc_state.worker_id,
                            config_path
                        );
                    }
                }
                Some(Message::MasterHealthCheck { timestamp }) => {
                    let mut ipc = ipc_state.ipc.lock().await;
                    if ipc
                        .send(&Message::HealthCheckAck { timestamp })
                        .await
                        .is_err()
                    {
                        tracing::warn!("Failed to send health check ack to master");
                    }
                }
                Some(Message::MasterCertReload) => {
                    tracing::info!(
                        "Unified Server Worker {} received cert reload",
                        ipc_state.worker_id
                    );
                    if let Some(cert_resolver) = ipc_state.unified_server.get_cert_resolver() {
                        if let Err(e) = cert_resolver.load_certificates() {
                            tracing::error!(
                                "Failed to reload certificates in worker {}: {}",
                                ipc_state.worker_id,
                                e
                            );
                        } else {
                            tracing::info!(
                                "Certificates reloaded successfully in worker {}",
                                ipc_state.worker_id
                            );
                        }
                    } else {
                        tracing::warn!(
                            "No cert_resolver in worker {}, cannot reload certificates",
                            ipc_state.worker_id
                        );
                    }
                }
                Some(Message::BlocklistUpdate { blocks, version: _ }) => {
                    tracing::debug!(
                        "Received blocklist update with {} entries from Master",
                        blocks.len()
                    );
                    if let Some(block_store) = ipc_state.unified_server.get_block_store() {
                        for block in blocks {
                            if let Ok(ip) = block.ip.parse() {
                                let _ = block_store.block_ip(
                                    ip,
                                    &block.reason,
                                    block.ban_expire_seconds,
                                    &block.site_scope,
                                );
                            }
                        }
                    }
                }
                Some(Message::RulePatternsUpdate { version, patterns }) => {
                    tracing::info!(
                        "Received rule patterns update v{} from Master ({} categories)",
                        version,
                        patterns.len()
                    );

                    // Update the global pattern store
                    for pattern_data in patterns {
                        crate::waf::rule_feed::update_patterns_for_category(
                            &pattern_data.category,
                            pattern_data.patterns,
                        );
                    }

                    // Reload attack detector with new patterns
                    if let Err(e) = ipc_state.unified_server.reload_attack_detector() {
                        tracing::error!(
                            "Failed to reload attack detector with new patterns: {}",
                            e
                        );
                    } else {
                        tracing::info!(
                            "Successfully reloaded attack detector with new rule patterns"
                        );
                    }
                }
                #[cfg(feature = "mesh")]
                Some(Message::ThreatFeedUpdate {
                    indicators,
                    version: _,
                    timestamp: _,
                }) => {
                    tracing::debug!(
                        "Received threat feed update with {} indicators from Master",
                        indicators.len()
                    );
                    if let Some(threat_intel) = &ipc_state.request_services.threat_intel {
                        for indicator_data in &indicators {
                            let threat_type = match indicator_data.threat_type {
                                crate::process::ipc::ThreatIndicatorType::IpBlock => {
                                    crate::mesh::protocol::ThreatType::IpBlock
                                }
                                crate::process::ipc::ThreatIndicatorType::RateLimitViolation => {
                                    crate::mesh::protocol::ThreatType::RateLimitViolation
                                }
                                crate::process::ipc::ThreatIndicatorType::SuspiciousActivity => {
                                    crate::mesh::protocol::ThreatType::SuspiciousActivity
                                }
                            };
                            let severity = match indicator_data.severity {
                                crate::process::ipc::ThreatSeverityLevel::Low => {
                                    crate::mesh::protocol::ThreatSeverity::Low
                                }
                                crate::process::ipc::ThreatSeverityLevel::Medium => {
                                    crate::mesh::protocol::ThreatSeverity::Medium
                                }
                                crate::process::ipc::ThreatSeverityLevel::High => {
                                    crate::mesh::protocol::ThreatSeverity::High
                                }
                                crate::process::ipc::ThreatSeverityLevel::Critical => {
                                    crate::mesh::protocol::ThreatSeverity::Critical
                                }
                            };
                            let indicator = crate::mesh::protocol::ThreatIndicator {
                                threat_type,
                                indicator_value: indicator_data.indicator_value.clone(),
                                severity,
                                reason: indicator_data.reason.clone(),
                                ttl_seconds: indicator_data.ttl_seconds,
                                source_node_id: indicator_data.source_node_id.clone(),
                                timestamp: indicator_data.timestamp,
                                site_scope: indicator_data.site_scope.clone(),
                                rate_limit_requests: indicator_data.rate_limit_requests,
                                rate_limit_window_secs: indicator_data.rate_limit_window_secs,
                                suspicious_pattern: indicator_data.suspicious_pattern.clone(),
                                signature: Vec::new(),
                                signer_public_key: None,
                            };
                            threat_intel.add_feed_indicator(indicator);
                        }
                        tracing::info!(
                            "Applied {} threat feed indicators from Master",
                            indicators.len()
                        );
                    } else {
                        tracing::warn!("No threat intel manager available to apply feed update");
                    }
                }
                Some(Message::UnifiedServerWorkerDrain {
                    timeout_secs,
                    drain_id: request_drain_id,
                }) => {
                    tracing::info!(
                        "Unified Server Worker {} received drain signal (timeout: {}s, drain_id: {})",
                        ipc_state.worker_id,
                        timeout_secs,
                        request_drain_id
                    );

                    if ipc_state.draining.is_draining() {
                        let current_drain_id =
                            ipc_state.drain_id.load(std::sync::atomic::Ordering::SeqCst);
                        if current_drain_id > 0 && current_drain_id != request_drain_id {
                            tracing::warn!(
                                "Already draining with id {}, ignoring request for id {}",
                                current_drain_id,
                                request_drain_id
                            );
                            continue;
                        }
                    }

                    ipc_state
                        .drain_id
                        .store(request_drain_id, std::sync::atomic::Ordering::SeqCst);
                    ipc_state.draining.start_drain();

                    ipc_state.drain_state.start_drain(request_drain_id).await;

                    let tx_guard = ipc_state.stop_accepting_tx.lock().await;
                    if let Some(tx) = tx_guard.as_ref() {
                        let _ = tx.send(());
                    }
                    ipc_state.stopped_accepting.start_drain();

                    tracing::info!(
                        "Unified Server Worker {} stopping accepting new connections",
                        ipc_state.worker_id
                    );

                    let _remaining = wait_for_drain(
                        &ipc_state.drain_state,
                        timeout_secs,
                        &ipc_state.worker_id,
                        "drain request",
                    )
                    .await;

                    tracing::info!(
                        "Unified Server Worker {} stopping Granian supervisors",
                        ipc_state.worker_id
                    );
                    let app_servers = ipc_state.app_servers.read().await;
                    for (site_id, supervisor) in app_servers.iter() {
                        tracing::info!("Stopping granian for site {}", site_id);
                        supervisor.stop().await;
                    }
                    drop(app_servers);

                    let remaining = ipc_state.drain_state.get_active_connections();
                    let current_drain_id =
                        ipc_state.drain_id.load(std::sync::atomic::Ordering::SeqCst);
                    tracing::info!(
                        "Unified Server Worker {} drain complete, {} remaining connections",
                        ipc_state.worker_id,
                        remaining
                    );

                    ipc_state.draining.end_drain();
                    ipc_state
                        .drain_id
                        .store(0, std::sync::atomic::Ordering::SeqCst);
                    ipc_state.stopped_accepting.end_drain();

                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc
                        .send(&Message::UnifiedServerWorkerDrained {
                            id: ipc_state.worker_id,
                            remaining_connections: remaining,
                            drain_id: current_drain_id,
                        })
                        .await;
                }
                Some(Message::UnifiedServerWorkerResize { worker_threads }) => {
                    tracing::info!(
                        "Unified Server Worker {} received threadpool resize request to {} threads",
                        ipc_state.worker_id,
                        worker_threads
                    );

                    ipc_state.draining.start_drain();

                    let tx_guard = ipc_state.stop_accepting_tx.lock().await;
                    if let Some(tx) = tx_guard.as_ref() {
                        let _ = tx.send(());
                    }
                    ipc_state.stopped_accepting.start_drain();

                    tracing::info!(
                        "Unified Server Worker {} stopping accepting new connections for resize",
                        ipc_state.worker_id
                    );

                    let _remaining = wait_for_drain(
                        &ipc_state.drain_state,
                        30,
                        &ipc_state.worker_id,
                        "resize request",
                    )
                    .await;

                    tracing::info!(
                        "Unified Server Worker {} exiting for threadpool resize to {} threads",
                        ipc_state.worker_id,
                        worker_threads
                    );

                    ipc_state.running.stop();

                    let mut ipc = ipc_state.ipc.lock().await;
                    let _ = ipc
                        .send(&Message::UnifiedServerWorkerResizeAck {
                            id: ipc_state.worker_id,
                            worker_threads,
                        })
                        .await;

                    ipc_exit_code.store(100, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                Some(_) | None => {}
            }
        }
    });

    let task_handles = state.task_handles.clone();
    task_handles.lock().await.push(ipc_handle);

    let server_state = state.clone();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = unified_server.run().await {
            tracing::error!("Unified server error: {}", e);
            server_state.running.stop();
        }
    });

    let master_dead_flag = state.master_dead.clone();

    let _ = server_handle.await;

    running.stop();

    if !master_dead_flag.is_running() {
        tracing::error!(
            "Unified Server Worker {} exiting because master died",
            worker_id
        );
        worker_exit_code.store(1, std::sync::atomic::Ordering::Relaxed);
    }

    let exit_code = worker_exit_code.load(std::sync::atomic::Ordering::Relaxed);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    tracing::info!("Unified Server Worker {} shutting down", worker_id);
    Ok(())
}

async fn wait_for_drain(
    drain_state: &WorkerDrainState,
    timeout_secs: u64,
    worker_id: &WorkerId,
    reason: &str,
) -> u64 {
    let start = Instant::now();
    let drain_timeout = Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_millis(100);

    loop {
        if start.elapsed() >= drain_timeout {
            tracing::warn!(
                "Unified Server Worker {} drain timeout reached for {}",
                worker_id,
                reason
            );
            break;
        }

        let active = drain_state.get_active_connections();
        if active == 0 {
            tracing::info!(
                "Unified Server Worker {} all connections drained for {}",
                worker_id,
                reason
            );
            break;
        }

        tracing::debug!(
            "Unified Server Worker {} waiting for {} connections to drain for {}",
            worker_id,
            active,
            reason
        );

        tokio::time::sleep(poll_interval).await;
    }

    drain_state.get_active_connections()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wait_for_drain_immediate() {
        let drain_state = WorkerDrainState::new();
        assert_eq!(drain_state.get_active_connections(), 0);

        let worker_id = WorkerId(1);
        let remaining = wait_for_drain(&drain_state, 10, &worker_id, "test").await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn test_wait_for_drain_with_connections() {
        let drain_state = WorkerDrainState::new();
        drain_state.increment_active();
        drain_state.increment_active();
        drain_state.increment_active();
        drain_state.increment_active();
        drain_state.increment_active();
        assert_eq!(drain_state.get_active_connections(), 5);

        let worker_id = WorkerId(1);
        let remaining = wait_for_drain(&drain_state, 1, &worker_id, "test").await;
        assert_eq!(remaining, 5);
    }

    #[test]
    fn test_unified_server_worker_args_clone() {
        let args = UnifiedServerWorkerArgs {
            worker_id: 2,
            config_path: PathBuf::from("/custom/config"),
            master_socket: PathBuf::from("/var/run/master.sock"),
            log_level: Some("debug".to_string()),
            upgrade_mode: true,
            reuse_port: false,
            worker_threads: 8,
        };

        let cloned = args.clone();

        assert_eq!(cloned.worker_id, args.worker_id);
        assert_eq!(cloned.config_path, args.config_path);
        assert_eq!(cloned.master_socket, args.master_socket);
        assert_eq!(cloned.log_level, args.log_level);
        assert_eq!(cloned.upgrade_mode, args.upgrade_mode);
        assert_eq!(cloned.reuse_port, args.reuse_port);
        assert_eq!(cloned.worker_threads, args.worker_threads);
    }

    #[test]
    fn test_unified_server_worker_args_with_log_level() {
        let args = UnifiedServerWorkerArgs {
            worker_id: 3,
            config_path: PathBuf::from("config"),
            master_socket: PathBuf::from("/tmp/master.sock"),
            log_level: Some("trace".to_string()),
            upgrade_mode: false,
            reuse_port: true,
            worker_threads: 2,
        };

        assert!(args.log_level.is_some());
        assert_eq!(args.log_level.unwrap(), "trace");
    }

    #[test]
    fn test_unified_server_worker_args_thread_values() {
        let single_thread = UnifiedServerWorkerArgs {
            worker_id: 1,
            config_path: PathBuf::from("config"),
            master_socket: PathBuf::from("/tmp/master.sock"),
            log_level: None,
            upgrade_mode: false,
            reuse_port: true,
            worker_threads: 1,
        };

        let multi_thread = UnifiedServerWorkerArgs {
            worker_id: 2,
            config_path: PathBuf::from("config"),
            master_socket: PathBuf::from("/tmp/master.sock"),
            log_level: None,
            upgrade_mode: false,
            reuse_port: true,
            worker_threads: 16,
        };

        assert_eq!(single_thread.worker_threads, 1);
        assert_eq!(multi_thread.worker_threads, 16);
    }
}

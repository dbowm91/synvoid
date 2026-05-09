use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, RwLock};

use crate::block_store::BlockStore;
use crate::config::{ConfigManager, MainConfig};
use crate::process::{
    IpcEndpoint, IpcListener, IpcStream, Message, MasterCommand,
    PidFileManager, ProcessManager, ProcessManagerConfig, ProcessEvent
};
use crate::waf::RuleFeedManagerForWaf;
use crate::RunningFlag;

use super::state::{SupervisorState, SupervisorStateTrackers};

pub struct SupervisorProcess {
    state: SupervisorState,
    process_manager: Arc<ProcessManager>,
    event_rx: mpsc::Receiver<ProcessEvent>,
    running: RunningFlag,
    ipc_listener: Option<IpcListener>,
}

impl SupervisorProcess {
    pub async fn new(
        state: SupervisorState,
        pm_config: ProcessManagerConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (process_manager, event_rx) = ProcessManager::new(pm_config, Some(state.block_store.clone()));
        
        // Initialize IPC listener (consolidated master + command socket)
        let endpoint = IpcEndpoint::master();
        let ipc_listener = endpoint.bind().await?;

        Ok(Self {
            state,
            process_manager: Arc::new(process_manager),
            event_rx,
            running: RunningFlag::new(),
            ipc_listener: Some(ipc_listener),
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Supervisor process started");

        // Spawn initial unified workers (data plane)
        let config = self.process_manager.get_config();
        tracing::info!("Spawning {} unified server workers", config.unified_server_workers);
        if let Err(e) = self.process_manager.spawn_unified_server_workers(config.unified_server_workers) {
            tracing::error!("Failed to spawn unified server workers: {}", e);
        }

        // Start IPC accept loop
        if let Some(listener) = self.ipc_listener.take() {
            let pm = self.process_manager.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok(ipc) => {
                            let pm_clone = pm.clone();
                            let state_clone = state.clone();
                            tokio::spawn(async move {
                                Self::handle_connection(ipc, pm_clone, state_clone).await;
                            });
                        }
                        Err(e) => {
                            tracing::debug!("Supervisor IPC accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        // Start gRPC control server
        let grpc_addr = self.state.config.read().await.main.supervisor.control_api_addr.parse();
        if let Ok(addr) = grpc_addr {
            let pm = self.process_manager.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = super::api::start_grpc_server(addr, pm, state).await {
                    tracing::error!("Failed to start gRPC control server: {}", e);
                }
            });
        } else {
            tracing::error!("Invalid gRPC control API address configured");
        }

        let mut shutdown_rx = self.state.subscribe_shutdown();

        // Main event loop
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if !self.running.is_running() {
                        break;
                    }
                    self.process_manager.reap_zombies().await;
                    self.process_manager.check_workers_health().await;
                }
                event = self.event_rx.recv() => {
                    if let Some(evt) = event {
                        self.handle_process_event(evt).await;
                    } else {
                        break;
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Supervisor received shutdown signal");
                    break;
                }
            }
        }

        tracing::info!("Supervisor shutting down...");
        self.process_manager.graceful_shutdown().await;

        Ok(())
    }

    async fn handle_connection(mut ipc: crate::process::ipc_transport::IpcStream, pm: Arc<ProcessManager>, state: SupervisorState) {
        // The supervisor socket handles both Worker Messages and Admin Commands.
        // On Unix, we try to deserialize as Message first, then as MasterCommand.
        
        // Use a small timeout for the initial message to distinguish between
        // a slow worker and a CLI command.
        match ipc.recv_with_timeout::<Message>(1000).await {
            Ok(Some(msg)) => {
                crate::master::handle_worker_connection_single(ipc, pm, msg).await;
            }
            _ => {
                // If not a worker message, try as a MasterCommand
                // We need a separate handler for this since handle_worker_connection
                // is specialized for Message.
                Self::handle_admin_command(ipc, pm, state).await;
            }
        }
    }

    async fn handle_admin_command(mut ipc: crate::process::ipc_transport::IpcStream, pm: Arc<ProcessManager>, state: SupervisorState) {
        // Implement command handling similar to src/startup/master.rs:handle_command_connection
        // but adapted for IpcStream.
        
        // For now, we'll delegate to a new command handler.
        if let Err(e) = crate::supervisor::commands::handle_supervisor_command(&mut ipc, pm, state).await {
            tracing::debug!("Admin command error: {}", e);
        }
    }

    async fn handle_process_event(&mut self, event: ProcessEvent) {
        tracing::debug!("Supervisor received event: {:?}", event);
    }
}

pub fn run_supervisor_mode(
    config_path: Option<PathBuf>,
    foreground: bool,
    test_mode: Option<&[String]>,
    pid_manager: &PidFileManager,
) {
    let supervisor_panic_log = format!(
        "{}/synvoid-supervisor-panic.log",
        std::env::temp_dir().display()
    );
    crate::common::setup_panic_handler("SUPERVISOR", Some(&supervisor_panic_log));

    let config_dir = config_path.unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    let mut config_manager = ConfigManager::new(config_dir.clone());
    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::warn!("Failed to load main.toml: {}, using defaults", e);
    }
    
    let main_config = config_manager.main.clone();

    // Initialize core subsystems (ported from Master)
    let data_dir = main_config.persistence.data_dir.as_ref().map(PathBuf::from);
    let block_store = Arc::new(BlockStore::new(
        true,
        data_dir,
        main_config.blocklist_limits.clone(),
    ));

    let rule_feed_config = main_config.rule_feed.clone();
    let rule_feed_manager = if rule_feed_config.enabled {
        match RuleFeedManagerForWaf::new(rule_feed_config) {
            Ok(manager) => {
                manager.start_background_fetching();
                Some(manager)
            }
            Err(e) => {
                tracing::error!("Rule feed initialization failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    let shared_config = Arc::new(RwLock::new(config_manager));
    
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    #[cfg(feature = "mesh")]
    let mesh_cp = {
        let block_store_clone = block_store.clone();
        let main_config_clone = main_config.clone();
        rt.block_on(async move {
            crate::supervisor::mesh::init_mesh_control_plane(&main_config_clone, block_store_clone).await
        })
    };

    let trackers = SupervisorStateTrackers {
        rule_feed_manager,
        #[cfg(feature = "mesh")]
        threat_intel_manager: mesh_cp.as_ref().map(|cp| cp.threat_intel.clone()),
        #[cfg(feature = "mesh")]
        yara_rules: mesh_cp.as_ref().and_then(|cp| cp.yara_rules.clone()),
        #[cfg(feature = "mesh")]
        mesh_transport_manager: mesh_cp.as_ref().map(|cp| cp.transport_manager.clone()),
        ..SupervisorStateTrackers::default()
    };

    let state = SupervisorState::new(shared_config, trackers, block_store);

    // Determine runtime directory for status file
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run"))
        .join("synvoid");

    if let Err(e) = std::fs::create_dir_all(&runtime_dir) {
        tracing::warn!("Failed to create runtime directory {}: {}", runtime_dir.display(), e);
    }

    let should_daemonize = !foreground && test_mode.is_none();
    if should_daemonize {
        crate::startup::daemon::daemonize(pid_manager);
    }

    tracing::info!("Starting synvoid Supervisor Process");

    let pm_config = ProcessManagerConfig {
        config_path: config_dir.clone(),
        unified_server_workers: main_config.defaults.worker_pool.workers.max(1),
        master_socket_path: pid_manager.socket_file_path(),
        control_api_addr: main_config.supervisor.control_api_addr.clone(),
        ..ProcessManagerConfig::default()
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let mut supervisor = SupervisorProcess::new(state, pm_config).await.expect("Failed to initialize SupervisorProcess");
            supervisor.run().await
        })
    }));

    match result {
        Ok(Ok(())) => tracing::info!("synvoid supervisor process exited cleanly"),
        Ok(Err(e)) => {
            tracing::error!("synvoid supervisor process error: {}", e);
            std::process::exit(1);
        }
        Err(panic_info) => {
            tracing::error!("synvoid supervisor process panicked: {:?}", panic_info);
            std::process::exit(1);
        }
    }
}

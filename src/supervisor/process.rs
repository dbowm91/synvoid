use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, RwLock};

use crate::platform::fs::PlatformPaths;
use crate::supervisor::drain_manager::{DrainManager, DrainProtocol};
use crate::supervisor::shutdown::{SupervisorDrainReport, SupervisorShutdownCause};
use crate::supervisor::task_registry::{
    SupervisorTaskClass, SupervisorTaskOutcome, SupervisorTaskRegistry,
};
use crate::waf::RuleFeedManagerForWaf;
use crate::RunningFlag;
use synvoid_block_store::BlockStore;
use synvoid_config::ConfigManager;
use synvoid_ipc::{
    IpcEndpoint, IpcListener, Message, PidFileManager, ProcessEvent, ProcessManager,
    ProcessManagerConfig, WorkerId,
};

use super::state::{SupervisorState, SupervisorStateTrackers};

const DRAIN_POLL_INTERVAL_MS: u64 = 100;
#[allow(dead_code)]
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;

/// Supervisor process for managing worker lifecycle.
///
/// # Drain Coordination
///
/// The Supervisor uses [`DrainManager`] for drain-aware worker shutdown, providing
/// per-worker connection tracking during drain (active/idle connections, drain states, etc.).
/// Uses the shared drain manager for drain-aware worker shutdown.
///
/// # Task Lifecycle
///
/// Long-lived supervisor tasks (IPC accept loop, gRPC control server) are registered
/// in [`SupervisorTaskRegistry`] for structured lifecycle management. Critical task
/// failures map to [`SupervisorShutdownCause::TaskFailed`] and trigger supervisor shutdown.
pub struct SupervisorProcess {
    state: SupervisorState,
    process_manager: Arc<ProcessManager>,
    drain_manager: Arc<DrainManager>,
    drain_protocol: Arc<DrainProtocol>,
    event_rx: mpsc::Receiver<ProcessEvent>,
    running: RunningFlag,
    ipc_listener: Option<IpcListener>,
    supervisor_tasks: SupervisorTaskRegistry,
}

impl SupervisorProcess {
    pub async fn new(
        state: SupervisorState,
        pm_config: ProcessManagerConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (process_manager, event_rx) =
            ProcessManager::new(pm_config, Some(state.block_store.clone()));

        let drain_manager = Arc::new(DrainManager::new(DRAIN_POLL_INTERVAL_MS));
        let drain_protocol = Arc::new(DrainProtocol::new(drain_manager.clone()));

        // Initialize IPC listener for worker messages and admin commands.
        let endpoint = IpcEndpoint::supervisor();
        let ipc_listener = endpoint.bind().await?;

        Ok(Self {
            state,
            process_manager: Arc::new(process_manager),
            drain_manager,
            drain_protocol,
            event_rx,
            running: RunningFlag::new(),
            ipc_listener: Some(ipc_listener),
            supervisor_tasks: SupervisorTaskRegistry::new(),
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Supervisor process started");

        let paths = PlatformPaths::new();
        let _ = paths.ensure_all();

        // Initialize Shared Connection Table for distributed load balancing
        let config = self.process_manager.get_config();
        let shm_path = paths.connections_shm_path();

        // Max workers + some headroom, and 2048 possible backend slots
        let max_workers = config.unified_server_workers + 10;
        let max_backends = 2048;

        if let Err(e) = crate::upstream::shared_state::SharedConnectionTable::init_global(
            shm_path,
            max_workers,
            max_backends,
        ) {
            tracing::warn!("Failed to initialize shared connection table: {}", e);
        }

        // Initialize Shared Rate Limit Table
        let ratelimit_shm_path = paths.ratelimit_shm_path();
        if let Err(e) = crate::upstream::shared_state::SharedRateLimitTable::init_global(
            ratelimit_shm_path,
            crate::waf::ratelimit::core::IP_RATE_LIMIT_SLOTS,
        ) {
            tracing::warn!("Failed to initialize shared rate limit table: {}", e);
        }

        // Spawn initial unified workers (data plane)
        tracing::info!(
            "Spawning {} unified server workers",
            config.unified_server_workers
        );
        if let Err(e) = self
            .process_manager
            .spawn_unified_server_workers(config.unified_server_workers)
        {
            tracing::error!("Failed to spawn unified server workers: {}", e);
        }

        // Register IPC accept loop as a managed task
        if let Some(listener) = self.ipc_listener.take() {
            let pm = self.process_manager.clone();
            let state = self.state.clone();
            let handle = tokio::spawn(run_supervisor_ipc_accept_loop(listener, pm, state));
            self.supervisor_tasks.register(
                "supervisor_ipc_accept",
                SupervisorTaskClass::CriticalControlPlane,
                handle,
            );
            tracing::info!("Registered IPC accept loop as critical control-plane task");
        }

        // Register gRPC control server as a managed task
        let grpc_addr = self
            .state
            .config
            .read()
            .await
            .main
            .supervisor
            .control_api_addr
            .parse();
        let control_api_tls = self
            .state
            .config
            .read()
            .await
            .main
            .supervisor
            .control_api_tls
            .clone()
            .map(crate::tls::config::InternalTlsConfig::from);
        if let Ok(addr) = grpc_addr {
            let pm = self.process_manager.clone();
            let state = self.state.clone();
            let handle = tokio::spawn(run_supervisor_control_api_task(
                addr,
                pm,
                state,
                control_api_tls,
            ));
            self.supervisor_tasks.register(
                "supervisor_grpc_control_api",
                SupervisorTaskClass::CriticalControlPlane,
                handle,
            );
            tracing::info!("Registered gRPC control API as critical control-plane task");
        } else {
            tracing::error!("Invalid gRPC control API address configured");
        }

        let mut shutdown_rx = self.state.subscribe_shutdown();
        let mut shutdown_cause = SupervisorShutdownCause::Requested;

        // Main event loop
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if !self.running.is_running() {
                        shutdown_cause = SupervisorShutdownCause::Requested;
                        break;
                    }
                    self.process_manager.reap_zombies().await;
                    self.process_manager.check_workers_health().await;

                    // Check for finished supervisor tasks
                    let finished = self.supervisor_tasks.join_finished().await;
                    for (task_id, outcome) in finished {
                        match outcome {
                            SupervisorTaskOutcome::Failed(reason) => {
                                tracing::error!(
                                    "Supervisor task failed: {:?} — triggering shutdown",
                                    reason
                                );
                                shutdown_cause = SupervisorShutdownCause::TaskFailed {
                                    task: "supervisor_task",
                                    reason,
                                };
                                break;
                            }
                            SupervisorTaskOutcome::Cancelled => {
                                tracing::warn!("Supervisor task was cancelled");
                            }
                            SupervisorTaskOutcome::Completed => {
                                tracing::debug!("Supervisor task completed normally");
                            }
                        }
                    }
                    if matches!(shutdown_cause, SupervisorShutdownCause::TaskFailed { .. }) {
                        break;
                    }
                }
                event = self.event_rx.recv() => {
                    if let Some(evt) = event {
                        self.handle_process_event(evt).await;
                    } else {
                        shutdown_cause = SupervisorShutdownCause::ProcessManagerFailed(
                            "event channel closed".to_string(),
                        );
                        break;
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Supervisor received shutdown signal");
                    shutdown_cause = SupervisorShutdownCause::Requested;
                    break;
                }
            }
        }

        tracing::info!("Supervisor shutting down (cause: {})", shutdown_cause);

        // Shutdown order: stop control-plane tasks first, then drain workers
        let task_report = self
            .supervisor_tasks
            .shutdown_and_join(Duration::from_secs(10))
            .await;
        tracing::info!(
            "Supervisor task shutdown report: completed={}, failed={}, aborted={}, timed_out={}",
            task_report.completed,
            task_report.failed,
            task_report.aborted,
            task_report.timed_out
        );

        let drain_report = self.drain_aware_shutdown().await;
        tracing::info!(
            "Drain report: id={}, workers={}, drained={}, timed_out={}, errored={}, forced={}",
            drain_report.drain_id,
            drain_report.worker_count,
            drain_report.drained,
            drain_report.timed_out,
            drain_report.errored,
            drain_report.forced_shutdown
        );

        if shutdown_cause.is_fatal() {
            tracing::error!("Supervisor exiting with fatal cause: {}", shutdown_cause);
        }

        Ok(())
    }

    async fn drain_aware_shutdown(&self) -> SupervisorDrainReport {
        tracing::info!("Starting drain-aware shutdown");

        let timeout_secs = self
            .process_manager
            .get_config()
            .graceful_shutdown_timeout_secs;
        let drain_id = self.drain_manager.start_drain(timeout_secs);

        let worker_ids: Vec<WorkerId> = {
            let unified_workers = self.process_manager.get_all_unified_server_worker_ids();
            unified_workers
        };

        for worker_id in &worker_ids {
            self.drain_manager.register_worker(*worker_id, 0, 0);
        }

        tracing::info!(
            "Initiating drain {} for {} unified server workers",
            drain_id,
            worker_ids.len()
        );

        let mut drained = 0usize;
        let mut timed_out = 0usize;
        let mut errored = 0usize;

        for worker_id in &worker_ids {
            if let Some(ipc) = self
                .process_manager
                .get_unified_server_worker_ipc(*worker_id)
            {
                let mut ipc = ipc.lock().await;
                match self
                    .drain_protocol
                    .drain_worker_with_confirmation(
                        &mut ipc,
                        worker_id,
                        timeout_secs,
                        DRAIN_POLL_INTERVAL_MS,
                    )
                    .await
                {
                    Ok(true) => {
                        tracing::info!("Worker {} drained successfully", worker_id);
                        drained += 1;
                    }
                    Ok(false) => {
                        tracing::warn!("Worker {} drain timeout, forcing shutdown", worker_id);
                        timed_out += 1;
                    }
                    Err(e) => {
                        tracing::error!("Worker {} drain error: {}", worker_id, e);
                        errored += 1;
                    }
                }
            }
        }

        let drain_complete = self.drain_manager.wait_for_drain(timeout_secs).await;

        if drain_complete {
            tracing::info!("All workers drained successfully, proceeding with shutdown");
        } else {
            tracing::warn!("Drain timeout reached, proceeding with shutdown anyway");
        }

        let status = self.drain_manager.get_drain_status();
        tracing::info!(
            "Drain status: id={}, active={}, idle={}, complete={}",
            status.drain_id,
            status.active_connections,
            status.idle_connections,
            status.drain_complete
        );

        self.process_manager.shutdown_workers().await;
        self.drain_manager.clear();

        tracing::info!("Drain-aware shutdown complete");

        SupervisorDrainReport {
            drain_id,
            worker_count: worker_ids.len(),
            drained,
            timed_out,
            errored,
            forced_shutdown: !drain_complete,
        }
    }

    async fn handle_connection(
        mut ipc: crate::process::ipc_transport::IpcStream,
        pm: Arc<ProcessManager>,
        state: SupervisorState,
    ) {
        // The supervisor socket handles both Worker Messages and Admin Commands.
        // On Unix, we try to deserialize as Message first, then as supervisor command.

        // Use a small timeout for the initial message to distinguish between
        // a slow worker and a CLI command.
        match ipc.recv_with_timeout::<Message>(1000).await {
            Ok(Some(msg)) => {
                crate::supervisor::commands::handle_worker_connection_single(ipc, pm, state, msg)
                    .await;
            }
            _ => {
                // If not a worker message, try as a supervisor command.
                // We need a separate handler for this since handle_worker_connection
                // is specialized for Message.
                Self::handle_admin_command(ipc, pm, state).await;
            }
        }
    }

    async fn handle_admin_command(
        mut ipc: crate::process::ipc_transport::IpcStream,
        pm: Arc<ProcessManager>,
        state: SupervisorState,
    ) {
        // Delegate to supervisor command handler.
        if let Err(e) =
            crate::supervisor::commands::handle_supervisor_command(&mut ipc, pm, state).await
        {
            tracing::debug!("Admin command error: {}", e);
        }
    }

    async fn handle_process_event(&mut self, event: ProcessEvent) {
        tracing::debug!("Supervisor received event: {:?}", event);
    }
}

/// Long-lived IPC accept loop for supervisor connections.
///
/// Registered as a critical control-plane task in `SupervisorTaskRegistry`.
/// Per-connection spawns are short-lived and do not require registry ownership.
async fn run_supervisor_ipc_accept_loop(
    listener: IpcListener,
    pm: Arc<ProcessManager>,
    state: SupervisorState,
) -> SupervisorTaskOutcome {
    loop {
        match listener.accept().await {
            Ok(ipc) => {
                let pm_clone = pm.clone();
                let state_clone = state.clone();
                // reason: Per-connection IPC handler — short-lived, not a background task
                tokio::spawn(async move {
                    SupervisorProcess::handle_connection(ipc, pm_clone, state_clone).await;
                });
            }
            Err(e) => {
                tracing::debug!("Supervisor IPC accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Long-lived gRPC control API server task.
///
/// Registered as a critical control-plane task in `SupervisorTaskRegistry`.
async fn run_supervisor_control_api_task(
    addr: std::net::SocketAddr,
    pm: Arc<ProcessManager>,
    state: SupervisorState,
    tls: Option<crate::tls::config::InternalTlsConfig>,
) -> SupervisorTaskOutcome {
    match super::api::start_grpc_server(addr, pm, state, tls).await {
        Ok(()) => SupervisorTaskOutcome::Completed,
        Err(e) => SupervisorTaskOutcome::Failed(e.to_string()),
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

    // Initialize core subsystems (ported from Supervisor)
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

    let trackers = SupervisorStateTrackers {
        rule_feed_manager,
        ..SupervisorStateTrackers::default()
    };

    let state = SupervisorState::new(shared_config, trackers, block_store);

    // Determine runtime directory for status file
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run"))
        .join("synvoid");

    if let Err(e) = std::fs::create_dir_all(&runtime_dir) {
        tracing::warn!(
            "Failed to create runtime directory {}: {}",
            runtime_dir.display(),
            e
        );
    }

    let should_daemonize = !foreground && test_mode.is_none();
    if should_daemonize {
        crate::startup::daemon::daemonize(pid_manager);
    }

    tracing::info!("Starting synvoid Supervisor Process");

    let pm_config = ProcessManagerConfig {
        config_path: config_dir.clone(),
        unified_server_workers: main_config.defaults.worker_pool.workers.max(1),
        supervisor_socket_path: pid_manager.socket_file_path(),
        control_api_addr: main_config.supervisor.control_api_addr.clone(),
        control_api_tls: main_config
            .supervisor
            .control_api_tls
            .clone()
            .map(Into::into),
        ..ProcessManagerConfig::default()
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let mut supervisor = SupervisorProcess::new(state, pm_config)
                .await
                .expect("Failed to initialize SupervisorProcess");
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

// Submodule: UnifiedServerWorker bootstrap and lifecycle.
//
// Architecture:
//   - [`state`]    : Worker args, state struct, panic handler, IPC setup,
//                    CPU affinity, config setup, bandwidth, port checks,
//                    drain wait.
//   - [`init_runtime`]: re-exports for the runtime helpers from `state`.
//   - [`init_config`] : re-exports for the config helpers from `state`.
//   - [`init_apps`]   : Granian supervisors, serverless manager, ACME wiring.
//   - [`init_waf`]    : WAF background tasks, UploadValidator, port honeypot.
//   - [`init_mesh`]   : Mesh + Threat Intel + YARA rules initialization.
//   - [`lifecycle`]   : Heartbeat task, IPC message loop, server run task.

pub mod init_apps;
pub mod init_config;
pub mod init_mesh;
pub mod init_runtime;
pub mod init_waf;
pub mod lifecycle;
pub mod passthrough_validation;
pub mod services;
pub mod state;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex as TokioMutex;
use tokio::sync::RwLock;

use super::drain_state::WorkerDrainState;
use super::metrics::WorkerMetrics;
use crate::server::UnifiedServer;
use crate::{DrainFlag, RunningFlag};
use synvoid_ipc::WorkerId;

pub use state::{
    setup_unified_server_panic_handler, UnifiedServerWorkerArgs, UnifiedServerWorkerState,
};

pub async fn run_unified_server_worker(
    args: UnifiedServerWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ---- Phase 0: identity ----
    let worker_id_raw = args.worker_id;
    crate::process::set_current_worker_id(worker_id_raw);
    let worker_id = WorkerId(worker_id_raw);

    // ---- Phase 1: runtime ----
    state::apply_cpu_affinity(args.cpu_affinity, worker_id);

    if let Some(ref level) = args.log_level {
        crate::log_controller::init_logging_with_dynamic_level(level);
    }

    state::start_shared_connection_heartbeat(worker_id_raw);
    crate::metrics::health::SystemHealthMonitor::start();

    tracing::info!(
        "Unified Server Worker {} starting, config: {:?}, supervisor socket: {:?}",
        worker_id,
        args.config_path,
        args.supervisor_socket
    );

    let ipc = state::setup_worker_ipc(&args.supervisor_socket, &worker_id).await?;
    let shared_config = state::setup_config(&args.config_path).await;

    // ---- Phase 2: pre-bind port check ----
    state::validate_ports_or_skip_for_shared_port(&args, &shared_config).await?;

    // ---- Phase 3: TLS passthrough validation ----
    passthrough_validation::validate_tls_passthrough_waf_policy(&shared_config)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    // ---- Phase 4: bandwidth config ----
    let (
        bandwidth_data_dir,
        bandwidth_retention_days,
        bandwidth_mesh_excluded,
        bandwidth_reset_config,
    ) = state::extract_bandwidth_config(&shared_config).await;
    crate::metrics::bandwidth::init_global_bandwidth_tracker(
        bandwidth_retention_days,
        bandwidth_mesh_excluded,
    );
    crate::metrics::bandwidth::configure_global_bandwidth_tracker(
        bandwidth_data_dir.as_deref(),
        bandwidth_reset_config,
    );

    // ---- Phase 5: serverless + unified server ----
    let drain_state = Arc::new(WorkerDrainState::new());
    let metrics =
        WorkerMetrics::shared_with_bandwidth(bandwidth_retention_days, bandwidth_mesh_excluded);
    let ipc_for_server = ipc.clone();
    let worker_id_for_server = worker_id;

    let app_servers = Arc::new(RwLock::new(HashMap::new()));
    let serverless_manager = init_apps::init_serverless_manager(&shared_config)
        .await
        .unwrap_or_else(init_apps::build_default_serverless_manager);

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
    .with_serverless_manager(serverless_manager.clone());
    let unified_server: Arc<UnifiedServer> = Arc::new(unified_server);

    // ---- Phase 6: ACME + Granian ----
    init_apps::setup_acme(&unified_server, worker_id);
    init_apps::spawn_granian_supervisors(worker_id, shared_config.clone(), app_servers.clone());
    init_apps::wait_after_granian_spawn().await;

    // ---- Phase 7: WAF ----
    init_waf::start_waf_background_tasks(&unified_server);
    init_waf::init_upload_validator(&shared_config).await;
    let port_honeypot_runner = init_waf::build_port_honeypot(&shared_config).await;
    init_waf::spawn_port_honeypot(port_honeypot_runner.clone());

    // ---- Phase 8: mesh + threat intel ----
    let mesh_init =
        init_mesh::init_mesh_and_threat_intel(&shared_config, &args.config_path, &unified_server)
            .await;

    // ---- Phase 9: cross-wire serverless + port-honeypot to mesh ----
    // Now handled by DataPlaneServicesBuilder below.

    // ---- Phase 10: request blocklist from supervisor ----
    lifecycle::request_initial_blocklist(&ipc, worker_id, &unified_server).await;

    // ---- Phase 11: build DataPlaneServices + Ready ----
    let metrics = WorkerMetrics::shared();
    let _running = RunningFlag::new();
    let draining = DrainFlag::new();
    let drain_id = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stopped_accepting = DrainFlag::new();
    let stop_accepting_sender = unified_server.get_stop_accepting_sender();
    let stop_accepting_tx = Arc::new(TokioMutex::new(Some(stop_accepting_sender)));

    let mut builder = services::DataPlaneServicesBuilder::new(serverless_manager)
        .with_port_honeypot(port_honeypot_runner);

    #[cfg(feature = "mesh")]
    {
        use synvoid_mesh::dht::advisory_source::{AdvisoryRecordSource, RecordStoreAdvisorySource};
        let yara_rules = crate::waf::get_yara_rules();
        let record_store = mesh_init
            .transport_manager
            .as_ref()
            .and_then(|tm| tm.get_record_store());
        let advisory_source = record_store.as_ref().map(|store| {
            Arc::new(RecordStoreAdvisorySource::new(store.clone())) as Arc<dyn AdvisoryRecordSource>
        });

        // Iteration 28: Canonical reader from Supervisor-exported snapshot.
        //
        // Canonical trust state (Raft consensus, EdgeReplicaManager) is
        // owned by the Supervisor process. Workers receive a bounded
        // CanonicalTrustSnapshot via IPC. The snapshot itself implements
        // CanonicalTrustReader and can be used directly.
        let canonical_reader: Option<Arc<dyn synvoid_mesh::canonical::CanonicalTrustReader>> =
            mesh_init.canonical_snapshot.map(|snapshot| {
                tracing::info!(
                    "Constructing canonical trust reader from Supervisor snapshot (generated_at={}, {} global nodes, {} org keys, {} revoked, {} intel)",
                    snapshot.generated_at_unix,
                    snapshot.authorized_global_nodes.len(),
                    snapshot.org_key_entries.len(),
                    snapshot.revoked_node_ids.len(),
                    snapshot.threat_intel_ids.len(),
                );
                Arc::new(snapshot) as Arc<dyn synvoid_mesh::canonical::CanonicalTrustReader>
            });
        builder = builder
            .with_mesh_transport(mesh_init.transport_manager)
            .with_threat_intel(mesh_init.threat_intel)
            .with_yara_rules(yara_rules)
            .with_record_store(record_store)
            .with_threat_intel_policy(
                services::DataPlaneServicesBuilder::build_threat_intel_policy_context(
                    canonical_reader,
                    advisory_source,
                ),
            );
    }
    #[cfg(not(feature = "mesh"))]
    {
        let _ = mesh_init;
    }

    let data_plane = builder.build();

    #[cfg(feature = "mesh")]
    {
        data_plane.apply_threat_intel_policy_context();
        services::cross_wire_mesh_services(&unified_server, &data_plane);
    }

    unified_server
        .get_waf()
        .set_request_services(data_plane.request_services.clone());

    let data_plane = std::sync::Arc::new(data_plane);

    let state = UnifiedServerWorkerState {
        worker_id,
        metrics: metrics.clone(),
        start_time: std::time::Instant::now(),
        ipc: ipc.clone(),
        running: _running.clone(),
        master_dead: RunningFlag::new(),
        app_servers: app_servers.clone(),
        draining: draining.clone(),
        drain_id: drain_id.clone(),
        stopped_accepting: stopped_accepting.clone(),
        drain_state: drain_state.clone(),
        stop_accepting_tx: stop_accepting_tx.clone(),
        unified_server: unified_server.clone(),
        task_handles: Arc::new(TokioMutex::new(Vec::new())),
        request_services: data_plane.request_services.clone(),
        data_plane,
        #[cfg(feature = "mesh")]
        canonical_snapshot: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        task_registry: Arc::new(TokioMutex::new(
            crate::worker::task_registry::WorkerTaskRegistry::new(),
        )),
    };

    {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
    }
    tracing::info!("Unified Server Worker {} ready", worker_id);

    // ---- Phase 12: subscribe to exit notifications BEFORE spawning tasks ----
    let mut exit_rx = {
        let registry = state.task_registry.lock().await;
        registry.subscribe_exits()
    };

    // ---- Phase 13: spawn lifecycle tasks via registry ----
    let mut lifecycle_rx = {
        let mut registry = state.task_registry.lock().await;
        lifecycle::spawn_heartbeat_task(state.clone(), &mut registry);
        lifecycle::spawn_bandwidth_persist_task(&mut registry);
        let (_ipc_id, lifecycle_rx) =
            lifecycle::spawn_ipc_loop(state.clone(), shared_config.clone(), &mut registry);
        lifecycle_rx
    };

    // ---- Phase 14: register server run task under registry ownership ----
    {
        let mut registry = state.task_registry.lock().await;
        let server_clone = unified_server.clone();
        registry.spawn_critical_result("server_run", async move {
            server_clone.run().await.map_err(|e| {
                tracing::error!("Unified server error: {}", e);
                e.to_string()
            })
        });
    }

    // Get the shared shutdown flag for fatality classification.
    let shutdown_flag = {
        let registry = state.task_registry.lock().await;
        registry.shutdown_started_flag()
    };

    // ---- Phase 15: supervision loop ----
    //
    // Select over both lifecycle events from the IPC task and task exits
    // from the registry. Lifecycle events arrive before the IPC critical task
    // returns, ensuring `begin_shutdown()` is called before task return.
    //
    // Returns a `SupervisionOutcome` that preserves direct shutdown causes
    // without converting them to fake lifecycle events.
    let outcome: crate::worker::task_registry::SupervisionOutcome = loop {
        tokio::select! {
            // Lifecycle events from IPC task (MasterShutdown, WorkerResize, SupervisorDisconnected).
            request = lifecycle_rx.recv() => {
                match request {
                    Some(req) => {
                        tracing::debug!(
                            "Received lifecycle event from IPC: {:?}",
                            req.event
                        );
                        break crate::worker::task_registry::SupervisionOutcome::Lifecycle {
                            event: req.event,
                            accepted: req.accepted,
                        };
                    }
                    None => {
                        // Lifecycle channel closed — IPC task exited without sending an event.
                        let shutdown_started = shutdown_flag.load(std::sync::atomic::Ordering::Acquire);
                        if let Some(cause) = crate::worker::task_registry::map_lifecycle_channel_closed(shutdown_started) {
                            tracing::error!(
                                "Lifecycle channel closed while worker active — {}",
                                cause
                            );
                            state.running.stop();
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(cause);
                        }
                        // Shutdown already in progress: channel closure is expected.
                        // Wait for the IPC task exit to arrive via exit_rx.
                        tracing::debug!("Lifecycle channel closed during shutdown — expected");
                    }
                }
            }
            // Task exits from the registry.
            exit = exit_rx.recv() => {
                match exit {
                    Ok(exit) => {
                        let shutdown_started = shutdown_flag.load(std::sync::atomic::Ordering::Acquire);
                        if crate::worker::task_registry::is_fatal_exit(&exit, shutdown_started) {
                            tracing::error!(
                                "Critical task '{}' ({}) exited unexpectedly: {} (class={:?})",
                                exit.name,
                                exit.id.0,
                                exit.reason,
                                exit.class,
                            );
                            state.running.stop();
                            let cause = crate::worker::task_registry::map_task_exit_to_shutdown_cause(exit);
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(cause);
                        } else {
                            tracing::debug!(
                                "Non-fatal task exit: '{}' ({}) reason={} expected={}",
                                exit.name,
                                exit.id.0,
                                exit.reason,
                                exit.expected_during_shutdown,
                            );
                        }
                    }
                    Err(recv_error) => {
                        let shutdown_started = shutdown_flag.load(std::sync::atomic::Ordering::Acquire);
                        if let Some(cause) = crate::worker::task_registry::map_exit_recv_error_to_shutdown_cause(
                            recv_error,
                            shutdown_started,
                        ) {
                            state.running.stop();
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(cause);
                        }
                        // RecvError::Closed during shutdown is expected — continue waiting.
                        tracing::debug!("Exit channel closed during shutdown — expected");
                    }
                }
            }
        }
    };

    // ---- Phase 16: composition-root shutdown procedure ----
    //
    // The supervision loop has exited with a SupervisionOutcome.
    // Map the outcome to the correct WorkerShutdownCause and execute
    // the ordered shutdown sequence.

    // Extract the shutdown cause and lifecycle acknowledgement from the outcome.
    let (shutdown_cause, lifecycle_ack, graceful, drain_timeout) = match outcome {
        crate::worker::task_registry::SupervisionOutcome::Lifecycle { event, accepted } => {
            let (graceful, drain_timeout) = match &event {
                lifecycle::WorkerLifecycleEvent::MasterShutdown { graceful, timeout } => {
                    (*graceful, *timeout)
                }
                lifecycle::WorkerLifecycleEvent::WorkerResize { .. } => {
                    (true, std::time::Duration::from_secs(30))
                }
                lifecycle::WorkerLifecycleEvent::SupervisorDisconnected => {
                    (false, std::time::Duration::ZERO)
                }
            };
            let cause = match &event {
                lifecycle::WorkerLifecycleEvent::MasterShutdown { .. } => {
                    crate::worker::task_registry::WorkerShutdownCause::SupervisorShutdown
                }
                lifecycle::WorkerLifecycleEvent::WorkerResize { worker_threads } => {
                    crate::worker::task_registry::WorkerShutdownCause::WorkerResize {
                        worker_threads: *worker_threads,
                    }
                }
                lifecycle::WorkerLifecycleEvent::SupervisorDisconnected => {
                    crate::worker::task_registry::WorkerShutdownCause::SupervisorDisconnected
                }
            };
            (cause, Some(accepted), graceful, drain_timeout)
        }
        crate::worker::task_registry::SupervisionOutcome::DirectCause(cause) => {
            let graceful = !matches!(
                cause,
                crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly
                    | crate::worker::task_registry::WorkerShutdownCause::CriticalTaskExit(_)
                    | crate::worker::task_registry::WorkerShutdownCause::RegistryExitChannelClosed
                    | crate::worker::task_registry::WorkerShutdownCause::SupervisorDisconnected
            );
            let drain_timeout = if graceful {
                std::time::Duration::from_secs(30)
            } else {
                std::time::Duration::ZERO
            };
            (cause, None, graceful, drain_timeout)
        }
    };

    // Step 1: Record coordinated shutdown intent before any teardown.
    {
        let registry = state.task_registry.lock().await;
        registry.begin_shutdown();
    }

    // Step 1a: Acknowledge the lifecycle event so the IPC task can return.
    // This must happen after begin_shutdown() so the IPC task's exit is
    // classified as CleanCompletion, not UnexpectedCompletion.
    if let Some(ack_tx) = lifecycle_ack {
        let _ = ack_tx.send(());
    }

    // Step 2: Stop accepting new connections.
    let tx_guard = state.stop_accepting_tx.lock().await;
    if let Some(tx) = tx_guard.as_ref() {
        let _ = tx.send(());
    }
    drop(tx_guard);
    state.stopped_accepting.start_drain();

    // Step 3: Graceful drain (if requested and nonzero timeout).
    if graceful && !drain_timeout.is_zero() {
        tracing::info!(
            "Unified Server Worker {} waiting for connection drain (timeout: {:?})",
            worker_id,
            drain_timeout
        );
        let _remaining = crate::worker::unified_server::state::wait_for_drain(
            &state.drain_state,
            drain_timeout.as_secs() as u64,
            &worker_id,
            "graceful shutdown",
        )
        .await;
    }

    // Step 4: Stop app servers (Granian supervisors).
    tracing::info!(
        "Stopping app servers for unified server worker {}",
        worker_id
    );
    let app_servers = state.app_servers.read().await;
    for (site_id, supervisor) in app_servers.iter() {
        tracing::info!("Stopping granian for site {}", site_id);
        supervisor.stop().await;
    }
    drop(app_servers);

    // Step 5: Clear running flag.
    state.running.stop();

    // Step 6: Broadcast registry cancellation to all tasks.
    {
        let registry = state.task_registry.lock().await;
        registry.broadcast_shutdown();
    }

    // Step 7: Bandwidth persist — single owner is the background task.
    // The bandwidth_persist task does its own final flush after the
    // shutdown signal. No explicit persist call here to avoid double-flush.

    // Step 8: Await registry tasks with bounded timeouts.
    {
        let mut registry = state.task_registry.lock().await;
        let exits = registry
            .shutdown_and_join(
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(3),
            )
            .await;
        if !exits.is_empty() {
            tracing::warn!(
                "Task registry shutdown: {} tasks with non-clean exits",
                exits.len()
            );
            for exit in &exits {
                tracing::warn!("  - '{}' ({}): {}", exit.name, exit.id.0, exit.reason);
            }
        }
    }

    // Step 9: Abort and await any remaining non-migrated task handles.
    // No legacy handle should remain in the vector after shutdown.
    {
        let mut handles = state.task_handles.lock().await;
        let handles_to_await: Vec<_> = std::mem::take(&mut *handles);
        drop(handles);
        for handle in handles_to_await {
            handle.abort();
            let _ = handle.await;
        }
    }

    // Step 10: Send supervisor acknowledgement (last IPC operation).
    // Routing is explicit by cause:
    //   SupervisorShutdown   -> ShutdownComplete
    //   WorkerResize         -> ResizeAck
    //   CriticalTaskExit     -> WorkerError
    //   ServerExitedUnexpectedly -> WorkerError
    //   SupervisorDisconnected   -> no-op (channel unavailable)
    //   RegistryExitChannelClosed -> WorkerError
    //   other (ExternalStop, etc.) -> no-op
    match &shutdown_cause {
        crate::worker::task_registry::WorkerShutdownCause::SupervisorShutdown => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(
                    &crate::process::Message::UnifiedServerWorkerShutdownComplete { id: worker_id },
                )
                .await;
        }
        crate::worker::task_registry::WorkerShutdownCause::WorkerResize { worker_threads } => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::UnifiedServerWorkerResizeAck {
                    id: worker_id,
                    worker_threads: *worker_threads as u32,
                })
                .await;
        }
        crate::worker::task_registry::WorkerShutdownCause::CriticalTaskExit(exit) => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!("Critical task '{}' exited: {}", exit.name, exit.reason),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::WorkerPanic,
                })
                .await;
        }
        crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: "Server runtime exited unexpectedly".to_string(),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::Unknown,
                })
                .await;
        }
        crate::worker::task_registry::WorkerShutdownCause::RegistryExitChannelClosed => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: "Registry exit channel closed — lifecycle infrastructure failure"
                        .to_string(),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::Unknown,
                })
                .await;
        }
        // SupervisorDisconnected, ExternalStop, RunningFlagCleared, ServerStoppedForShutdown
        // -> no supervisor notification needed.
        _ => {}
    }

    // Step 11: Derive exit code from the authoritative shutdown cause.
    let exit_code = shutdown_cause.exit_code();

    tracing::info!(
        "Unified Server Worker {} shutting down (cause: {}, exit_code: {})",
        worker_id,
        shutdown_cause,
        exit_code
    );

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

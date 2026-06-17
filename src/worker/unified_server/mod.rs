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
            )
            .with_dns_shutdown_tx(mesh_init.dns_shutdown_tx)
            .with_yara_broadcast_shutdown_tx(mesh_init.yara_broadcast_shutdown_tx);
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

    // ---- Phase 11.5: derive mesh supervision policy from config ----
    #[cfg(feature = "mesh")]
    let mesh_policy = {
        let config_guard = shared_config.read().await;
        let mesh_enabled = config_guard
            .main
            .tunnel
            .mesh
            .as_ref()
            .map(|m| m.enabled)
            .unwrap_or(false);
        let supervision_config = config_guard
            .main
            .tunnel
            .mesh
            .as_ref()
            .map(|m| m.supervision.clone())
            .unwrap_or_default();
        crate::worker::mesh_supervision::build_mesh_supervision_policy(
            mesh_enabled,
            &supervision_config,
        )
        .unwrap_or_else(crate::worker::mesh_supervision::MeshSupervisionPolicy::required)
    };

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
        #[cfg(feature = "mesh")]
        mesh_status: std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::worker::mesh_supervision::WorkerMeshStatus::default(),
        )),
        #[cfg(feature = "mesh")]
        mesh_policy,
        task_registry: Arc::new(TokioMutex::new(
            crate::worker::task_registry::WorkerTaskRegistry::new(),
        )),
    };

    // ---- Phase 11.5: send ready message ----
    // Required mesh defers ready until mesh startup completes.
    // Optional/disabled mesh sends ready immediately.
    #[cfg(feature = "mesh")]
    let ready_deferred =
        state.mesh_policy.required && state.data_plane.mesh_transport_manager.is_some();
    #[cfg(not(feature = "mesh"))]
    let ready_deferred = false;

    if !ready_deferred {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
        tracing::info!("Unified Server Worker {} ready", worker_id);
    } else {
        tracing::info!(
            "Unified Server Worker {} deferring ready until mesh startup completes",
            worker_id
        );
    }

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

    // ---- Phase 14.5: mesh supervision pipeline ----
    //
    // Required mesh: observer + coordinator as critical tasks, startup awaited inline,
    //   ready sent after startup success.
    // Optional mesh: observer + coordinator as critical tasks, startup as background,
    //   ready already sent.
    // Disabled mesh: no pipeline at all.
    //
    // `mesh_decision_rx_opt` is always created (but `None` without mesh feature)
    // so the select loop can unconditionally poll it.
    #[cfg(feature = "mesh")]
    let mut mesh_decision_rx_opt: Option<
        tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
    > = {
        let mesh_status = state.mesh_status.clone();

        // Check if mesh transport exists.
        let has_mesh_transport = state
            .data_plane
            .mesh_transport_manager
            .as_ref()
            .and_then(|tm| tm.get_quic_transport())
            .is_some();

        if !has_mesh_transport {
            // Mesh disabled — no pipeline, no tasks, no channels.
            tracing::info!("Mesh disabled — no supervision pipeline created");
            None
        } else {
            // Mesh enabled (required or optional) — create pipeline.
            let mesh_transport: std::sync::Arc<synvoid_mesh::MeshTransport> = state
                .data_plane
                .mesh_transport_manager
                .as_ref()
                .and_then(|tm| tm.get_quic_transport())
                .expect("mesh transport verified above")
                .get_inner();

            let (event_tx, coordinator, decision_rx) =
                crate::worker::mesh_supervision::create_supervision_pipeline(
                    mesh_status.clone(),
                    state.mesh_policy.clone(),
                );

            // Register coordinator as critical supervision infrastructure.
            {
                let shutdown_rx = state.task_registry.lock().await.child_token();
                let mut registry = state.task_registry.lock().await;
                let mut coord = coordinator;
                registry.spawn_critical("mesh_supervision_coordinator", async move {
                    coord.run(shutdown_rx).await;
                });
                tracing::info!("Mesh supervision coordinator started (critical)");
            }

            // Subscribe to mesh exit events and register observer as critical.
            {
                let exits = mesh_transport.subscribe_exits();
                let shutdown_rx = state.task_registry.lock().await.child_token();
                let status = mesh_status.clone();
                let mut registry = state.task_registry.lock().await;
                registry.spawn_critical(
                    "mesh_exit_observer",
                    crate::worker::mesh_supervision::run_mesh_exit_observer(
                        exits,
                        status,
                        event_tx.clone(),
                        shutdown_rx,
                    ),
                );
                tracing::info!("Mesh exit observer started (critical)");
            }

            // Start mesh transport — gated behind dns feature.
            #[cfg(feature = "dns")]
            if state.mesh_policy.required {
                // Required mesh: await startup inline before ready.
                let event_tx_for_start = event_tx.clone();
                match crate::worker::mesh_supervision::start_mesh_generation(
                    &mesh_transport,
                    &mesh_status,
                    0,
                )
                .await
                {
                    Ok(()) => {
                        let _ = event_tx_for_start
                            .send(crate::worker::mesh_supervision::MeshSupervisionEvent::Started)
                            .await;
                        // Send ready after successful required mesh startup.
                        if ready_deferred {
                            let mut ipc_guard = state.ipc.lock().await;
                            ipc_guard
                                .send(&crate::process::Message::UnifiedServerWorkerReady {
                                    id: worker_id,
                                })
                                .await?;
                            tracing::info!(
                                "Unified Server Worker {} ready (mesh started)",
                                worker_id
                            );
                        }
                    }
                    Err(cause) => {
                        let _ = event_tx_for_start
                            .send(
                                crate::worker::mesh_supervision::MeshSupervisionEvent::StartupFailed(
                                    cause.exit_reason(),
                                ),
                            )
                            .await;
                        // Required mesh startup failed — ready was never sent,
                        // worker will shut down via supervision decision.
                    }
                }
            } else {
                // Optional mesh: start as background task.
                let event_tx_for_start = event_tx.clone();
                let mut registry = state.task_registry.lock().await;
                registry.spawn_critical("mesh_startup", async move {
                    let result = mesh_transport
                        .start_with_policy(synvoid_mesh::lifecycle::MeshStartupPolicy::default())
                        .await;
                    match result {
                        Ok(report) => {
                            tracing::info!(?report, "Mesh transport started");
                            let _ = event_tx_for_start
                                .send(crate::worker::mesh_supervision::MeshSupervisionEvent::Started)
                                .await;
                        }
                        Err(e) => {
                            tracing::error!("Mesh startup failed: {}", e);
                            let _ = event_tx_for_start
                                .send(
                                    crate::worker::mesh_supervision::MeshSupervisionEvent::StartupFailed(
                                        e.to_string(),
                                    ),
                                )
                                .await;
                        }
                    }
                });
            }
            #[cfg(not(feature = "dns"))]
            {
                let _ = mesh_transport;
                tracing::warn!("Mesh transport start requires dns feature");
            }

            Some(decision_rx)
        }
    };
    #[cfg(not(feature = "mesh"))]
    let mut mesh_decision_rx_opt: Option<
        tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
    > = None;

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
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(cause);
                        }
                        // RecvError::Closed during shutdown is expected — continue waiting.
                        tracing::debug!("Exit channel closed during shutdown — expected");
                    }
                }
            }
            // Mesh supervision decisions. Inlined async block avoids
            // moving a captured future across loop iterations.
            mesh_decision = async {
                match &mut mesh_decision_rx_opt {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match mesh_decision {
                    Some(crate::worker::mesh_supervision::MeshSupervisorDecision::ShutdownWorker(cause)) => {
                        tracing::error!(
                            "Mesh supervision shutting down worker: {} ({})",
                            cause.task_name(),
                            cause.exit_reason()
                        );
                        break crate::worker::task_registry::SupervisionOutcome::DirectCause(
                            crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause)
                        );
                    }
                    Some(crate::worker::mesh_supervision::MeshSupervisorDecision::RestartMesh) => {
                        tracing::error!("BUG: RestartMesh decision received but restart is not implemented");
                        #[cfg(feature = "mesh")]
                        {
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(
                                crate::worker::task_registry::WorkerShutdownCause::MeshRestartExhausted {
                                    attempts: 0,
                                    last_error: "restart not implemented".to_string(),
                                }
                            );
                        }
                        #[cfg(not(feature = "mesh"))]
                        {
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(
                                crate::worker::task_registry::WorkerShutdownCause::ServerStoppedForShutdown,
                            );
                        }
                    }
                    Some(crate::worker::mesh_supervision::MeshSupervisorDecision::MarkDegraded(reason)) => {
                        tracing::warn!(reason = %reason, "mesh degraded");
                    }
                    Some(crate::worker::mesh_supervision::MeshSupervisorDecision::NoAction) => {}
                    None => {
                        // Mesh decision channel closed — observer exited.
                        tracing::debug!("Mesh supervision decision channel closed");
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
    let (mut shutdown_cause, lifecycle_ack, graceful, drain_timeout) = match outcome {
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
                crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly(_)
                    | crate::worker::task_registry::WorkerShutdownCause::CriticalTaskExit(_)
                    | crate::worker::task_registry::WorkerShutdownCause::RegistryExitChannelClosed
                    | crate::worker::task_registry::WorkerShutdownCause::SupervisorDisconnected
                    | crate::worker::task_registry::WorkerShutdownCause::MeshStartupFailed(_)
                    | crate::worker::task_registry::WorkerShutdownCause::MeshShutdownIncomplete(_)
                    | crate::worker::task_registry::WorkerShutdownCause::MeshServiceExit(_)
                    | crate::worker::task_registry::WorkerShutdownCause::MeshRestartExhausted { .. }
            );
            let drain_timeout = if graceful {
                std::time::Duration::from_secs(30)
            } else {
                std::time::Duration::ZERO
            };
            (cause, None, graceful, drain_timeout)
        }
    };

    // Step 1: Record coordinated shutdown intent before any teardown,
    // and acknowledge the lifecycle event so the IPC task can return.
    lifecycle::begin_coordinated_shutdown(&state.task_registry, lifecycle_ack).await;

    // Step 1.2: Signal mesh background tasks (DNS verification loops,
    // YARA broadcast) to shut down early so they drain during the
    // connection-drain window rather than running until process exit.
    #[cfg(feature = "mesh")]
    state.data_plane.shutdown_mesh_background_tasks();

    // Step 1.5: Establish real shutdown deadline (Phase 19).
    // All subsequent timeout calculations derive from this deadline,
    // not from worker uptime.
    let shutdown_started_at = std::time::Instant::now();
    let shutdown_deadline = shutdown_started_at + drain_timeout;
    let remaining_budget = || -> std::time::Duration {
        shutdown_deadline.saturating_duration_since(std::time::Instant::now())
    };

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

    // Step 4.5: Shutdown mesh transport (if running).
    // Record final mesh status and use real shutdown budget (Phases 19-22).
    #[cfg(feature = "dns")]
    {
        // Phase 22: Mark mesh as stopping before shutdown
        {
            let mut mesh_status = state.mesh_status.write().await;
            mesh_status.transition_stopping();
        }
        if let Some(tm) = state.data_plane.mesh_transport_manager.as_ref() {
            if let Some(quic) = tm.get_quic_transport() {
                let transport = quic.get_inner();
                if synvoid_mesh::ManagedMeshService::is_running(&transport) {
                    let remaining = remaining_budget();
                    let report = transport.shutdown_with_timeout(remaining).await;
                    let disposition =
                        crate::worker::mesh_supervision::classify_mesh_shutdown_report(&report);
                    match disposition {
                        crate::worker::mesh_supervision::MeshShutdownDisposition::Clean => {
                            tracing::info!("Mesh shutdown completed cleanly");
                            let mut mesh_status = state.mesh_status.write().await;
                            mesh_status.transition_stopped();
                        }
                        crate::worker::mesh_supervision::MeshShutdownDisposition::ForcedButComplete => {
                            tracing::warn!("Mesh shutdown forced but complete");
                            let mut mesh_status = state.mesh_status.write().await;
                            mesh_status.transition_stopped();
                        }
                        crate::worker::mesh_supervision::MeshShutdownDisposition::Incomplete(
                            cause,
                        ) => {
                            let reason = cause.exit_reason();
                            tracing::error!("Mesh shutdown incomplete: {}", reason);
                            let mut mesh_status = state.mesh_status.write().await;
                            mesh_status.transition_failed(reason);
                            // Phase 20: Accumulate incomplete mesh shutdown into final cause.
                            shutdown_cause = crate::worker::mesh_supervision::merge_worker_shutdown_cause(
                                shutdown_cause,
                                crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),
                            );
                        }
                    }
                } else {
                    let mut mesh_status = state.mesh_status.write().await;
                    mesh_status.transition_stopped();
                }
            }
        }
    }

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
        crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly(ref exit) => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!(
                        "Server task '{}' exited unexpectedly: {}",
                        exit.name, exit.reason
                    ),
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
        #[cfg(feature = "mesh")]
        crate::worker::task_registry::WorkerShutdownCause::MeshStartupFailed(ref reason) => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!("Mesh startup failed: {}", reason),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::Unknown,
                })
                .await;
        }
        #[cfg(feature = "mesh")]
        crate::worker::task_registry::WorkerShutdownCause::MeshShutdownIncomplete(ref reason) => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!("Mesh shutdown incomplete: {}", reason),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::Unknown,
                })
                .await;
        }
        #[cfg(feature = "mesh")]
        crate::worker::task_registry::WorkerShutdownCause::MeshServiceExit(ref exit) => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!("Mesh service '{}' exited: {}", exit.name, exit.reason),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::Unknown,
                })
                .await;
        }
        #[cfg(feature = "mesh")]
        crate::worker::task_registry::WorkerShutdownCause::MeshRestartExhausted {
            attempts,
            ref last_error,
        } => {
            let mut ipc_guard = state.ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!(
                        "Mesh restart exhausted after {} attempts: {}",
                        attempts, last_error
                    ),
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

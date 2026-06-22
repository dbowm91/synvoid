// Worker startup plan.
//
// Owns phases from worker identity through data-plane/service readiness
// preparation and mesh supervision pipeline setup. Extracted from
// run_unified_server_worker() in Iteration 93.
//
// This module MUST NOT contain `shutdown_and_join` or
// `begin_coordinated_shutdown` — those belong to shutdown_executor.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex as TokioMutex;
use tokio::sync::RwLock;

use super::init_mesh::MeshInit;
use super::passthrough_validation;
use super::services::DataPlaneServicesBuilder;
use super::state::{self, UnifiedServerWorkerArgs, UnifiedServerWorkerState};
use super::{MeshGenerationSupport, SupportStopContext};
use crate::server::UnifiedServer;
use crate::worker::drain_state::WorkerDrainState;
use crate::worker::metrics::WorkerMetrics;
use crate::{DrainFlag, RunningFlag};
use synvoid_config::ConfigManager;
use synvoid_ipc::WorkerId;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type SharedConfig = Arc<RwLock<ConfigManager>>;
type SharedUnifiedServer = Arc<UnifiedServer>;
type SharedTaskRegistry = Arc<TokioMutex<crate::worker::task_registry::WorkerTaskRegistry>>;

/// Readiness plan for the worker.
///
/// Encodes worker ready signaling rules without changing behavior.
/// This type is documentation plus control-flow clarity.
pub enum WorkerReadinessPlan {
    /// Ready immediately after baseline startup (disabled/optional mesh).
    SendImmediately,
    /// Ready only after mesh transport startup and support-task registration
    /// succeed (required mesh).
    DeferUntilRequiredMeshReady,
    /// Ready was already sent (required mesh startup succeeded).
    AlreadySent,
}

/// Mesh-specific startup state produced by the startup plan.
pub struct MeshStartupState {
    /// Mesh supervision policy (required/optional).
    pub policy: crate::worker::mesh_supervision::MeshSupervisionPolicy,
    /// Mesh supervision decision receiver (created during pipeline setup).
    pub decision_rx:
        tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
    /// Mesh failure from startup, converted to WorkerShutdownCause
    /// (if required mesh failed during startup).
    pub startup_failure: Option<crate::worker::task_registry::WorkerShutdownCause>,
    /// Active mesh support bundle (populated after mesh startup succeeds).
    pub active_mesh_support: Option<MeshGenerationSupport>,
}

/// All artifacts produced by the worker startup plan.
///
/// Contains everything needed by the supervision loop and shutdown executor.
pub struct WorkerStartupArtifacts {
    pub worker_id: WorkerId,
    pub args: UnifiedServerWorkerArgs,
    pub shared_config: SharedConfig,
    pub ipc: Arc<TokioMutex<synvoid_ipc::AsyncIpcStream>>,
    pub unified_server: SharedUnifiedServer,
    pub state: UnifiedServerWorkerState,
    pub readiness: WorkerReadinessPlan,
    pub lifecycle_rx: tokio::sync::mpsc::Receiver<super::lifecycle::LifecycleRequest>,
    pub exit_rx: tokio::sync::broadcast::Receiver<crate::worker::task_registry::NamedTaskExit>,
    #[cfg(feature = "mesh")]
    pub mesh_startup: Option<MeshStartupState>,
    pub legacy_handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Build the worker startup artifacts.
///
/// Executes phases 0 through 14.5 (identity through mesh supervision
/// pipeline setup). Returns all artifacts needed for supervision and
/// shutdown.
pub async fn build_worker_startup(
    args: UnifiedServerWorkerArgs,
) -> Result<WorkerStartupArtifacts, BoxError> {
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
        .map_err(|e| -> BoxError { e.into() })?;

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
    let serverless_manager = super::init_apps::init_serverless_manager(&shared_config)
        .await
        .unwrap_or_else(super::init_apps::build_default_serverless_manager);

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
    let unified_server: SharedUnifiedServer = Arc::new(unified_server);

    // ---- Phase 6: ACME + Granian ----
    super::init_apps::setup_acme(&unified_server, worker_id);
    super::init_apps::spawn_granian_supervisors(
        worker_id,
        shared_config.clone(),
        app_servers.clone(),
    );
    super::init_apps::wait_after_granian_spawn().await;

    // ---- Phase 7: WAF ----
    super::init_waf::start_waf_background_tasks(&unified_server);
    super::init_waf::init_upload_validator(&shared_config).await;
    let port_honeypot_runner = super::init_waf::build_port_honeypot(&shared_config).await;
    super::init_waf::spawn_port_honeypot(port_honeypot_runner.clone());

    // ---- Phase 8: mesh + threat intel ----
    let mesh_init = super::init_mesh::init_mesh_and_threat_intel(
        &shared_config,
        &args.config_path,
        &unified_server,
    )
    .await;

    // ---- Phase 8.5: validate support components against enabled state ----
    #[cfg(all(feature = "mesh", feature = "dns"))]
    {
        let config_guard = shared_config.read().await;
        let mesh_enabled = config_guard
            .main
            .tunnel
            .mesh
            .as_ref()
            .map(|m| m.enabled)
            .unwrap_or(false);
        if !mesh_enabled {
            debug_assert!(
                mesh_init.dns_verification_registries.is_empty(),
                "disabled mesh must have empty dns_verification_registries"
            );
            debug_assert!(
                mesh_init.yara_broadcast.is_none(),
                "disabled mesh must have no yara_broadcast"
            );
            debug_assert!(
                mesh_init.transport_manager.is_none(),
                "disabled mesh must have no transport_manager"
            );
        }
    }

    // ---- Phase 8.7: validate mesh runtime inputs before consumption ----
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
        let policy = crate::worker::mesh_supervision::build_mesh_supervision_policy(
            mesh_enabled,
            &supervision_config,
        )
        .map_err(|e| -> BoxError { e.into() })?;
        super::init_mesh::validate_mesh_runtime_inputs(&mesh_init, policy.as_ref())
            .map_err(|e| -> BoxError { e.to_string().into() })?;
        policy
    };

    // ---- Phase 9: cross-wire serverless + port-honeypot to mesh ----
    // Now handled by DataPlaneServicesBuilder below.

    // ---- Phase 10: request blocklist from supervisor ----
    super::lifecycle::request_initial_blocklist(&ipc, worker_id, &unified_server).await;

    // ---- Phase 11: build DataPlaneServices + Ready ----
    let metrics = WorkerMetrics::shared();
    let _running = RunningFlag::new();
    let draining = DrainFlag::new();
    let drain_id = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stopped_accepting = DrainFlag::new();
    let stop_accepting_sender = unified_server.get_stop_accepting_sender();
    let stop_accepting_tx = Arc::new(TokioMutex::new(Some(stop_accepting_sender)));

    let mut builder =
        DataPlaneServicesBuilder::new(serverless_manager).with_port_honeypot(port_honeypot_runner);

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
            .with_threat_intel_policy(DataPlaneServicesBuilder::build_threat_intel_policy_context(
                canonical_reader,
                advisory_source,
            ));
    }
    #[cfg(not(feature = "mesh"))]
    {
        let _ = mesh_init;
    }

    // ---- Phase 11.5: extract mesh support tasks ----
    #[cfg(feature = "mesh")]
    let support_tasks = super::MeshSupportTasks {
        #[cfg(all(feature = "mesh", feature = "dns"))]
        dns_verification_registries: mesh_init.dns_verification_registries,
        #[cfg(all(feature = "mesh", feature = "dns"))]
        yara_broadcast: mesh_init.yara_broadcast,
    };
    #[cfg(not(feature = "mesh"))]
    let support_tasks = super::MeshSupportTasks::empty();

    #[cfg(feature = "mesh")]
    let mut support_tasks = Some(support_tasks);

    let data_plane = builder.build();

    #[cfg(feature = "mesh")]
    {
        data_plane.apply_threat_intel_policy_context();
        super::services::cross_wire_mesh_services(&unified_server, &data_plane);
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
    #[cfg(feature = "mesh")]
    let ready_deferred = state.mesh_policy.as_ref().is_some_and(|p| p.required)
        && state.data_plane.mesh_transport_manager.is_some();
    #[cfg(not(feature = "mesh"))]
    let ready_deferred = false;

    let readiness = if ready_deferred {
        tracing::info!(
            "Unified Server Worker {} deferring ready until mesh startup completes",
            worker_id
        );
        WorkerReadinessPlan::DeferUntilRequiredMeshReady
    } else {
        let mut ipc_guard = ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
        tracing::info!("Unified Server Worker {} ready", worker_id);
        WorkerReadinessPlan::SendImmediately
    };

    // ---- Phase 12: subscribe to exit notifications BEFORE spawning tasks ----
    let mut exit_rx = {
        let registry = state.task_registry.lock().await;
        registry.subscribe_exits()
    };

    // ---- Phase 13: spawn lifecycle tasks via registry ----
    let mut lifecycle_rx = {
        let mut registry = state.task_registry.lock().await;
        super::lifecycle::spawn_heartbeat_task(state.clone(), &mut registry);
        super::lifecycle::spawn_bandwidth_persist_task(&mut registry);
        let (_ipc_id, lifecycle_rx) =
            super::lifecycle::spawn_ipc_loop(state.clone(), shared_config.clone(), &mut registry);
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

    // ---- Phase 14.5: mesh supervision pipeline ----
    #[cfg(feature = "mesh")]
    let mesh_startup = {
        let mesh_status = state.mesh_status.clone();

        let has_mesh_transport = state
            .data_plane
            .mesh_transport_manager
            .as_ref()
            .and_then(|tm| tm.get_quic_transport())
            .is_some();

        let mut required_mesh_startup_failure: Option<
            crate::worker::task_registry::WorkerShutdownCause,
        > = None;

        let (optional_startup_tx, mut optional_startup_rx): (
            tokio::sync::oneshot::Sender<Result<Option<MeshGenerationSupport>, String>>,
            tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, String>>,
        ) = tokio::sync::oneshot::channel();

        if !has_mesh_transport {
            tracing::info!("Mesh disabled — no supervision pipeline created");
            None
        } else {
            let mesh_transport: std::sync::Arc<synvoid_mesh::MeshTransport> = state
                .data_plane
                .mesh_transport_manager
                .as_ref()
                .and_then(|tm| tm.get_quic_transport())
                .expect("mesh transport verified above")
                .get_inner();

            let (event_tx, coordinator, mut decision_rx) =
                crate::worker::mesh_supervision::create_supervision_pipeline(
                    mesh_status.clone(),
                    state
                        .mesh_policy
                        .clone()
                        .expect("mesh policy present when transport exists"),
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

            // Start mesh transport — gated behind mesh feature.
            #[cfg(feature = "mesh")]
            let mut mesh_generation_counter: u64 = 0;
            #[cfg(feature = "mesh")]
            let mut active_mesh_support: Option<MeshGenerationSupport> = None;

            #[cfg(feature = "mesh")]
            if state.mesh_policy.as_ref().is_some_and(|p| p.required) {
                // Required mesh: await startup inline before ready.
                {
                    let mut s = mesh_status.write().await;
                    s.transition_starting();
                }
                match crate::worker::mesh_supervision::start_mesh_generation(&mesh_transport, 0)
                    .await
                {
                    Ok(()) => {
                        mesh_generation_counter += 1;
                        if let Some(support) = support_tasks.take() {
                            match super::register_mesh_generation_support(
                                &state,
                                support,
                                mesh_generation_counter,
                            )
                            .await
                            {
                                Ok(bundle) => {
                                    {
                                        let mut s = mesh_status.write().await;
                                        s.transition_running();
                                    }
                                    active_mesh_support = Some(bundle);
                                    if let WorkerReadinessPlan::DeferUntilRequiredMeshReady =
                                        &readiness
                                    {
                                        let mut ipc_guard = state.ipc.lock().await;
                                        ipc_guard
                                            .send(
                                                &crate::process::Message::UnifiedServerWorkerReady {
                                                    id: worker_id,
                                                },
                                            )
                                            .await?;
                                        tracing::info!(
                                            "Unified Server Worker {} ready (mesh started)",
                                            worker_id
                                        );
                                    }
                                }
                                Err(cause) => {
                                    tracing::error!("Failed to register mesh support: {}", cause);
                                    required_mesh_startup_failure = Some(
                                        crate::worker::mesh_supervision::mesh_failure_to_worker_cause(
                                            crate::worker::mesh_supervision::MeshFailureCause::StartupFailed(
                                                format!("support registration failed: {}", cause),
                                            ),
                                        ),
                                    );
                                    {
                                        let mut s = mesh_status.write().await;
                                        s.transition_failed(format!(
                                            "support registration failed: {}",
                                            cause
                                        ));
                                    }
                                }
                            }
                        } else {
                            {
                                let mut s = mesh_status.write().await;
                                s.transition_running();
                            }
                            if let WorkerReadinessPlan::DeferUntilRequiredMeshReady = &readiness {
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
                    }
                    Err(cause) => {
                        {
                            let mut s = mesh_status.write().await;
                            s.transition_failed(format!("startup failed: {}", cause.exit_reason()));
                        }
                        tracing::error!("Required mesh startup failed: {}", cause.exit_reason());
                        required_mesh_startup_failure = Some(
                            crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),
                        );
                    }
                }
            } else {
                // Optional mesh: start as one-shot background task.
                {
                    let mut s = mesh_status.write().await;
                    s.transition_starting();
                }
                let event_tx_for_start = event_tx.clone();
                let startup_complete_tx = optional_startup_tx;
                let state_for_startup = state.clone();

                let (helper_tx, helper_rx) = tokio::sync::oneshot::channel();
                let support_for_helper = support_tasks.take();
                let mut registry = state.task_registry.lock().await;
                registry.spawn_one_shot("mesh_support_registration", async move {
                    let result = if let Some(support) = support_for_helper {
                        super::register_mesh_generation_support(&state_for_startup, support, 1)
                            .await
                            .map(Some)
                    } else {
                        Ok(None)
                    };
                    let _ = helper_tx.send(result);
                });

                registry.spawn_one_shot("mesh_startup", async move {
                    let result = mesh_transport
                        .start_with_policy(synvoid_mesh::lifecycle::MeshStartupPolicy::default())
                        .await;
                    match result {
                        Ok(report) => {
                            tracing::info!(?report, "Mesh transport started");
                            let bundle = match helper_rx.await {
                                Ok(Ok(b)) => b,
                                Ok(Err(e)) => {
                                    tracing::error!(
                                        "Optional mesh support registration failed: {}",
                                        e
                                    );
                                    None
                                }
                                Err(_) => {
                                    tracing::error!("Helper task dropped without sending result");
                                    None
                                }
                            };
                            let _ = startup_complete_tx.send(Ok(bundle));
                            let _ = event_tx_for_start
                                .send(crate::worker::mesh_supervision::MeshSupervisionEvent::Started)
                                .await;
                        }
                        Err(e) => {
                            tracing::error!("Mesh startup failed: {}", e);
                            let _ = startup_complete_tx.send(Err(e.to_string()));
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

            // Select to receive optional startup result before returning.
            let mut pending_optional_failure = false;
            loop {
                #[cfg(feature = "mesh")]
                let mut mesh_decision_future = async { decision_rx.recv().await };
                #[cfg(not(feature = "mesh"))]
                let mesh_decision_future: std::future::Pending<Option<()>> = std::future::pending();

                tokio::select! {
                    optional_result = &mut optional_startup_rx => {
                        match optional_result {
                            Ok(Ok(bundle)) => {
                                if pending_optional_failure {
                                    #[cfg(all(feature = "mesh", feature = "dns"))]
                                    if let Some(support) = bundle {
                                        tracing::warn!(
                                            "Optional mesh startup completed but degradation pending — stopping support bundle"
                                        );
                                        let stop_report = super::stop_mesh_generation_support(
                                            &state.task_registry,
                                            support,
                                            std::time::Duration::from_secs(5),
                                            SupportStopContext::OptionalMeshDegraded,
                                        )
                                        .await;
                                        if !stop_report.clean() {
                                            tracing::warn!(
                                                context = ?SupportStopContext::OptionalMeshDegraded,
                                                generation = stop_report.generation,
                                                not_found = stop_report.not_found,
                                                "support bundle required forced cleanup during degradation"
                                            );
                                        }
                                    }
                                    {
                                        let mut s = mesh_status.write().await;
                                        s.transition_degraded("degradation arrived during startup".to_string());
                                    }
                                } else {
                                    {
                                        let mut s = mesh_status.write().await;
                                        s.transition_running();
                                    }
                                    active_mesh_support = bundle;
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::error!("Optional mesh startup failed: {}", e);
                                {
                                    let mut s = mesh_status.write().await;
                                    s.transition_failed(format!("startup failed: {}", e));
                                }
                            }
                            Err(_) => {
                                tracing::error!("Optional startup channel closed unexpectedly");
                            }
                        }
                        break;
                    }
                    mesh_decision = mesh_decision_future => {
                        match mesh_decision {
                            Some(crate::worker::mesh_supervision::MeshSupervisorDecision::MarkDegraded(reason)) => {
                                tracing::warn!(reason = %reason, "mesh degraded during optional startup");
                                pending_optional_failure = true;
                            }
                            Some(crate::worker::mesh_supervision::MeshSupervisorDecision::ShutdownWorker(cause)) => {
                                tracing::error!(
                                    "Mesh supervision shutting down worker during startup: {}",
                                    cause.exit_reason()
                                );
                                required_mesh_startup_failure = Some(
                                    crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),
                                );
                                break;
                            }
                            Some(crate::worker::mesh_supervision::MeshSupervisorDecision::RestartMesh) => {
                                tracing::error!("Invariant violation: RestartMesh during startup");
                                required_mesh_startup_failure = Some(
                                    crate::worker::mesh_supervision::mesh_failure_to_worker_cause(
                                        crate::worker::mesh_supervision::MeshFailureCause::MeshConfigurationInvariant(
                                            "RestartMesh during startup".to_string(),
                                        ),
                                    ),
                                );
                                break;
                            }
                            Some(crate::worker::mesh_supervision::MeshSupervisorDecision::NoAction) => {}
                            None => {}
                        }
                    }
                }
            }

            Some(MeshStartupState {
                policy: state.mesh_policy.clone().expect("mesh policy present"),
                decision_rx,
                startup_failure: required_mesh_startup_failure,
                active_mesh_support,
            })
        }
    };
    #[cfg(not(feature = "mesh"))]
    let mesh_startup: Option<MeshStartupState> = None;

    Ok(WorkerStartupArtifacts {
        worker_id,
        args,
        shared_config,
        ipc,
        unified_server,
        state,
        readiness,
        lifecycle_rx,
        exit_rx,
        #[cfg(feature = "mesh")]
        mesh_startup,
        legacy_handles: Vec::new(),
    })
}

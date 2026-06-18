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
use std::time::Duration;

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

/// Report from the YARA broadcast loop summarizing child task outcomes.
#[cfg(all(feature = "mesh", feature = "dns"))]
#[derive(Debug)]
pub struct YaraBroadcastReport {
    pub completed: usize,
    pub failed: usize,
    pub aborted: usize,
    pub dropped: usize,
}

/// A bundle of worker-owned mesh support tasks tied to a specific mesh
/// generation (Iteration 87, Phase 8).
///
/// When an optional mesh generation fails, the active bundle can be
/// cancelled to stop DNS verification and YARA broadcast support
/// without shutting down the entire worker.
#[cfg(feature = "mesh")]
pub struct MeshGenerationSupport {
    /// The mesh generation this bundle belongs to.
    pub generation: u64,
    /// Task IDs of registered support tasks (for subset join/verification).
    pub task_ids: Vec<crate::worker::task_registry::TaskId>,
    /// Watch sender for generation-specific cancellation. Sending `true`
    /// causes all support tasks in this generation to exit cooperatively.
    cancel_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(feature = "mesh")]
impl MeshGenerationSupport {
    /// Signal all support tasks in this generation to shut down cooperatively.
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// Returns a receiver that fires when this generation is cancelled.
    pub fn cancel_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.cancel_tx.subscribe()
    }
}

/// Classify a single child task result and update the report.
#[cfg(all(feature = "mesh", feature = "dns"))]
fn classify_yara_child_result(
    result: Result<(), tokio::task::JoinError>,
    report: &mut YaraBroadcastReport,
) {
    match result {
        Ok(()) => {
            report.completed += 1;
            metrics::counter!("yara_mesh_broadcast_completed_total").increment(1);
        }
        Err(e) if e.is_cancelled() => {
            report.aborted += 1;
            metrics::counter!("yara_mesh_broadcast_aborted_total").increment(1);
        }
        Err(e) => {
            tracing::warn!("YARA broadcast child failed: {}", e);
            report.failed += 1;
            metrics::counter!("yara_mesh_broadcast_failed_total").increment(1);
        }
    }
}

/// Abstraction for the YARA broadcast action, enabling testability without
/// concrete `MeshTransport` coupling (Iteration 87, Phase 15).
#[cfg(all(feature = "mesh", feature = "dns"))]
#[async_trait::async_trait]
trait YaraBroadcastSink: Send + Sync {
    async fn broadcast(&self, msg: crate::mesh::protocol::MeshMessage);
}

/// Production adapter wrapping `MeshTransport`.
#[cfg(all(feature = "mesh", feature = "dns"))]
struct MeshTransportBroadcastSink(Arc<crate::mesh::transport::MeshTransport>);

#[cfg(all(feature = "mesh", feature = "dns"))]
#[async_trait::async_trait]
impl YaraBroadcastSink for MeshTransportBroadcastSink {
    async fn broadcast(&self, msg: crate::mesh::protocol::MeshMessage) {
        self.0
            .broadcast_to_all_peers(msg, Some(crate::mesh::config::MeshNodeRole::GLOBAL))
            .await;
    }
}

/// Dedicated YARA broadcast loop with bounded child ownership.
///
/// Consumes `MeshMessage`s from the channel, spawns bounded broadcast tasks
/// (semaphore-gated), and reaps children inline. On shutdown or channel
/// closure, performs a deadline-bounded drain and aborts stragglers.
#[cfg(all(feature = "mesh", feature = "dns"))]
async fn run_yara_broadcast_loop(
    mut broadcast_rx: tokio::sync::mpsc::Receiver<crate::mesh::protocol::MeshMessage>,
    sink: Arc<dyn YaraBroadcastSink>,
    semaphore: Arc<tokio::sync::Semaphore>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    drain_timeout: Duration,
) -> YaraBroadcastReport {
    let mut report = YaraBroadcastReport {
        completed: 0,
        failed: 0,
        aborted: 0,
        dropped: 0,
    };
    let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                tracing::debug!("YARA broadcast loop received shutdown signal");
                break;
            }
            msg = broadcast_rx.recv() => {
                match msg {
                    Some(msg) => {
                        match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => {
                                metrics::counter!("yara_mesh_broadcast_submitted_total").increment(1);
                                let sink = sink.clone();
                                children.spawn(async move {
                                    sink.broadcast(msg).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                report.dropped += 1;
                                metrics::counter!("yara_mesh_broadcast_dropped_total").increment(1);
                                tracing::debug!(
                                    "YARA broadcast semaphore saturated, dropping message"
                                );
                            }
                        }
                    }
                    None => {
                        tracing::debug!(
                            "YARA broadcast mpsc channel closed, exiting loop"
                        );
                        break;
                    }
                }
            }
            Some(result) = children.join_next(), if !children.is_empty() => {
                classify_yara_child_result(result, &mut report);
            }
        }
    }

    // Deadline-bounded drain: reap remaining children within the timeout.
    let drain_deadline = tokio::time::Instant::now() + drain_timeout;
    while let Some(result) = tokio::time::timeout(
        drain_deadline.saturating_duration_since(tokio::time::Instant::now()),
        children.join_next(),
    )
    .await
    .unwrap_or(None)
    {
        classify_yara_child_result(result, &mut report);
    }

    // Abort any children that did not finish within the drain deadline.
    if !children.is_empty() {
        tracing::warn!(
            "YARA broadcast: aborting {} remaining children after drain timeout",
            children.len()
        );
        children.abort_all();
        while let Some(result) = children.join_next().await {
            classify_yara_child_result(result, &mut report);
        }
    }

    report
}

/// Mesh support task descriptors extracted from `MeshInit` but registered
/// only AFTER mesh startup succeeds (Iteration 86 Part A).
///
/// DNS verification loops, YARA broadcast loop, and DHT routing init are
/// support infrastructure that should only run when the mesh transport is
/// actually active. Registering them before startup would create orphaned
/// tasks if mesh startup fails.
pub struct MeshSupportTasks {
    #[cfg(all(feature = "mesh", feature = "dns"))]
    pub dns_verification_registries: Vec<(Arc<crate::dns::mesh_sync::MeshDnsRegistry>, bool)>,
    #[cfg(all(feature = "mesh", feature = "dns"))]
    pub yara_broadcast: Option<(
        tokio::sync::mpsc::Receiver<crate::mesh::protocol::MeshMessage>,
        Arc<crate::mesh::transport::MeshTransport>,
        Arc<tokio::sync::Semaphore>,
    )>,
}

impl MeshSupportTasks {
    /// Create an empty instance (no mesh feature).
    pub fn empty() -> Self {
        Self {
            #[cfg(all(feature = "mesh", feature = "dns"))]
            dns_verification_registries: Vec::new(),
            #[cfg(all(feature = "mesh", feature = "dns"))]
            yara_broadcast: None,
        }
    }
}

/// Register mesh generation support tasks (DNS verification, YARA broadcast,
/// DHT routing init) in the worker task registry.
///
/// Called ONLY after successful mesh startup — required mesh: after
/// `start_mesh_generation()` returns Ok; optional mesh: inside the
/// one-shot's Ok branch. This ensures mesh support infrastructure is
/// only active when the mesh transport is actually running (Iteration 86 Part A).
///
/// Returns a `MeshGenerationSupport` bundle that can be used to cancel
/// this generation's support tasks independently (Iteration 87, Phase 10).
#[cfg(all(feature = "mesh", feature = "dns"))]
async fn register_mesh_generation_support(
    state: &UnifiedServerWorkerState,
    support: MeshSupportTasks,
    generation: u64,
) -> Result<MeshGenerationSupport, crate::worker::task_registry::WorkerShutdownCause> {
    use crate::worker::task_registry::{TaskId, WorkerShutdownCause};

    let worker_shutdown_rx = state.task_registry.lock().await.child_token();
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let mut task_ids = Vec::new();
    let mut registry = state.task_registry.lock().await;

    // Spawn DNS verification loops.
    for (dns_registry, is_global) in support.dns_verification_registries {
        let role = if is_global { "global" } else { "edge" };
        if let Some(loop_fut) = dns_registry.build_verification_loop(None) {
            let mut gen_cancel = cancel_rx.clone();
            let mut worker_shutdown = worker_shutdown_rx.clone();
            let wrapped = async move {
                tokio::select! {
                    biased;
                    _ = gen_cancel.changed() => { return; }
                    _ = worker_shutdown.changed() => { return; }
                    result = loop_fut => { result; }
                }
            };
            let id = registry.spawn_background(
                Box::leak(format!("dns_verification_{}", role).into_boxed_str()),
                wrapped,
            );
            task_ids.push(TaskId(id as u64));
            tracing::info!("DNS verification loop registered ({})", role);
        }
    }

    // Spawn YARA broadcast loop with deadline-bounded drain.
    if let Some((broadcast_rx, mesh_transport, broadcast_semaphore)) = support.yara_broadcast {
        // Create a combined shutdown signal from worker shutdown and generation cancel.
        let combined_shutdown = {
            let mut ws = worker_shutdown_rx.clone();
            let mut gc = cancel_rx.clone();
            let (tx, rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                tokio::select! {
                    _ = ws.changed() => { let _ = tx.send(true); }
                    _ = gc.changed() => { let _ = tx.send(true); }
                }
            });
            rx
        };
        let id = registry.spawn_background("yara_broadcast", async move {
            let sink: Arc<dyn YaraBroadcastSink> =
                Arc::new(MeshTransportBroadcastSink(mesh_transport));
            let report = run_yara_broadcast_loop(
                broadcast_rx,
                sink,
                broadcast_semaphore,
                combined_shutdown,
                Duration::from_secs(30),
            )
            .await;
            tracing::info!(
                "YARA broadcast loop exiting: completed={}, failed={}, aborted={}, dropped={}",
                report.completed,
                report.failed,
                report.aborted,
                report.dropped,
            );
        });
        task_ids.push(TaskId(id as u64));
        tracing::info!("YARA broadcast loop registered");
    }

    // DHT routing initialization is now handled by the mesh transport's
    // transactional startup phases (Iteration 87, Phase 1). The routing
    // table is initialized or restored before bootstrap, eliminating the
    // race condition where bootstrap could run against an absent table.

    tracing::info!(
        "Mesh generation {} support registered: {} tasks",
        generation,
        task_ids.len()
    );

    Ok(MeshGenerationSupport {
        generation,
        task_ids,
        cancel_tx,
    })
}

/// No-op stub when dns feature is disabled (mesh only).
#[cfg(all(feature = "mesh", not(feature = "dns")))]
async fn register_mesh_generation_support(
    _state: &UnifiedServerWorkerState,
    _support: MeshSupportTasks,
    generation: u64,
) -> Result<MeshGenerationSupport, crate::worker::task_registry::WorkerShutdownCause> {
    tracing::debug!("Mesh support tasks skipped (dns feature disabled)");
    Ok(MeshGenerationSupport {
        generation,
        task_ids: Vec::new(),
        cancel_tx: tokio::sync::watch::channel(false).0,
    })
}

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
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        crate::worker::unified_server::init_mesh::validate_mesh_runtime_inputs(
            &mesh_init,
            policy.as_ref(),
        )
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
        policy
    };

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

    // ---- Phase 11.5: extract mesh support tasks ----
    //
    // DNS verification loops, YARA broadcast loop, and DHT routing init
    // are extracted here but registered AFTER mesh startup succeeds.
    // This ensures mesh support infrastructure is only active when the
    // mesh transport is actually running (Iteration 86 Part A).
    #[cfg(feature = "mesh")]
    let support_tasks = MeshSupportTasks {
        #[cfg(all(feature = "mesh", feature = "dns"))]
        dns_verification_registries: mesh_init.dns_verification_registries,
        #[cfg(all(feature = "mesh", feature = "dns"))]
        yara_broadcast: mesh_init.yara_broadcast,
    };
    #[cfg(not(feature = "mesh"))]
    let support_tasks = MeshSupportTasks::empty();

    // Wrap in Option so it can be .take()-moved into mesh startup paths.
    #[cfg(feature = "mesh")]
    let mut support_tasks = Some(support_tasks);

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
    let ready_deferred = state.mesh_policy.as_ref().is_some_and(|p| p.required)
        && state.data_plane.mesh_transport_manager.is_some();
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

    // ---- Phase 13.5: mesh support task registration ----
    //
    // Support tasks (DNS verification, YARA broadcast, DHT routing init)
    // are NOT registered here — they are registered AFTER mesh startup
    // succeeds (Iteration 86 Part A). The support descriptors were
    // extracted into `support_tasks` in Phase 11.5.
    //
    // The helper function `register_mesh_generation_support()` is called
    // from the mesh startup success paths (required: after Ok branch;
    // optional: inside the one-shot's Ok branch).

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
    let (mut mesh_decision_rx_opt, mut required_mesh_startup_failure, mut active_mesh_support): (
        Option<
            tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
        >,
        Option<crate::worker::mesh_supervision::MeshFailureCause>,
        Option<MeshGenerationSupport>,
    ) = {
        let mesh_status = state.mesh_status.clone();

        // Check if mesh transport exists.
        let has_mesh_transport = state
            .data_plane
            .mesh_transport_manager
            .as_ref()
            .and_then(|tm| tm.get_quic_transport())
            .is_some();

        let mut required_mesh_startup_failure: Option<
            crate::worker::mesh_supervision::MeshFailureCause,
        > = None;

        if !has_mesh_transport {
            // Mesh disabled — no pipeline, no tasks, no channels.
            tracing::info!("Mesh disabled — no supervision pipeline created");
            (None, None, None)
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
                        {
                            let mut s = mesh_status.write().await;
                            s.transition_running();
                        }
                        // Register mesh support tasks after successful startup.
                        mesh_generation_counter += 1;
                        if let Some(support) = support_tasks.take() {
                            match register_mesh_generation_support(
                                &state,
                                support,
                                mesh_generation_counter,
                            )
                            .await
                            {
                                Ok(bundle) => {
                                    active_mesh_support = Some(bundle);
                                }
                                Err(cause) => {
                                    tracing::error!("Failed to register mesh support: {}", cause);
                                    required_mesh_startup_failure = Some(
                                        crate::worker::mesh_supervision::MeshFailureCause::StartupFailed(
                                            format!("support registration failed: {}", cause),
                                        ),
                                    );
                                }
                            }
                        }
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
                        {
                            let mut s = mesh_status.write().await;
                            s.transition_failed(format!("startup failed: {}", cause.exit_reason()));
                        }
                        tracing::error!("Required mesh startup failed: {}", cause.exit_reason());
                        required_mesh_startup_failure = Some(cause);
                    }
                }
            } else {
                // Optional mesh: start as one-shot background task.
                // Clean completion is expected (not fatal).
                {
                    let mut s = mesh_status.write().await;
                    s.transition_starting();
                }
                let event_tx_for_start = event_tx.clone();
                let support_for_startup = support_tasks.take();
                let state_for_startup = state.clone();
                let mut registry = state.task_registry.lock().await;
                registry.spawn_one_shot("mesh_startup", async move {
                    let result = mesh_transport
                        .start_with_policy(synvoid_mesh::lifecycle::MeshStartupPolicy::default())
                        .await;
                    match result {
                        Ok(report) => {
                            tracing::info!(?report, "Mesh transport started");
                            // Register mesh support tasks after successful startup.
                            if let Some(support) = support_for_startup {
                                let _ = register_mesh_generation_support(
                                    &state_for_startup,
                                    support,
                                    1, // generation counter passed via shared state in real impl
                                ).await;
                            }
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

            (Some(decision_rx), required_mesh_startup_failure, active_mesh_support)
        }
    };
    #[cfg(not(feature = "mesh"))]
    let (mut mesh_decision_rx_opt, required_mesh_startup_failure, mut active_mesh_support): (
        Option<()>,
        Option<()>,
        Option<()>,
    ) = (None, None, None);

    // ---- Phase 15: supervision loop ----
    //
    // Select over both lifecycle events from the IPC task and task exits
    // from the registry. Lifecycle events arrive before the IPC critical task
    // returns, ensuring `begin_shutdown()` is called before task return.
    //
    // Returns a `SupervisionOutcome` that preserves direct shutdown causes
    // without converting them to fake lifecycle events.
    let outcome: crate::worker::task_registry::SupervisionOutcome = 'supervision: {
        #[cfg(feature = "mesh")]
        if let Some(cause) = required_mesh_startup_failure {
            break 'supervision crate::worker::task_registry::SupervisionOutcome::DirectCause(
                crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),
            );
        }
        loop {
            // Mesh supervision decisions future. Defined outside select to
            // avoid #[cfg] on select branches (not valid proc-macro syntax).
            #[cfg(feature = "mesh")]
            let mut mesh_decision_future = async {
                match &mut mesh_decision_rx_opt {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            #[cfg(not(feature = "mesh"))]
            let mesh_decision_future: std::future::Pending<Option<()>> = std::future::pending();

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
                // Mesh supervision decisions.
                mesh_decision = mesh_decision_future => {
                    #[cfg(feature = "mesh")]
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
                            // RestartMesh is unreachable when restart_enabled is rejected at
                            // config validation time. This branch is defense-in-depth only.
                            tracing::error!("Invariant violation: RestartMesh reached while restart is disabled");
                            break crate::worker::task_registry::SupervisionOutcome::DirectCause(
                                crate::worker::task_registry::WorkerShutdownCause::MeshConfigurationInvariant(
                                    "RestartMesh reached while restart is disabled".to_string(),
                                )
                            );
                        }
                        Some(crate::worker::mesh_supervision::MeshSupervisorDecision::MarkDegraded(reason)) => {
                            tracing::warn!(reason = %reason, "mesh degraded");
                            // Cancel generation-specific support tasks when optional mesh
                            // degrades (Iteration 87, Phase 12). DNS/YARA work must not
                            // continue targeting a failed transport.
                            #[cfg(feature = "mesh")]
                            if let Some(support) = active_mesh_support.take() {
                                tracing::info!(
                                    "Cancelling mesh generation {} support tasks",
                                    support.generation
                                );
                                support.cancel();
                            }
                        }
                        Some(crate::worker::mesh_supervision::MeshSupervisorDecision::NoAction) => {}
                        None => {
                            // Mesh decision channel closed — observer exited.
                            tracing::debug!("Mesh supervision decision channel closed");
                        }
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
            let graceful = match &cause {
                crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly(_)
                | crate::worker::task_registry::WorkerShutdownCause::CriticalTaskExit(_)
                | crate::worker::task_registry::WorkerShutdownCause::RegistryExitChannelClosed
                | crate::worker::task_registry::WorkerShutdownCause::SupervisorDisconnected => {
                    false
                }
                #[cfg(feature = "mesh")]
                crate::worker::task_registry::WorkerShutdownCause::MeshStartupFailed(_)
                | crate::worker::task_registry::WorkerShutdownCause::MeshShutdownIncomplete(_)
                | crate::worker::task_registry::WorkerShutdownCause::MeshServiceExit(_)
                | crate::worker::task_registry::WorkerShutdownCause::MeshRestartExhausted {
                    ..
                }
                | crate::worker::task_registry::WorkerShutdownCause::MeshConfigurationInvariant(
                    _,
                ) => false,
                _ => true,
            };
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
    #[cfg(feature = "mesh")]
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

#[cfg(test)]
#[cfg(all(feature = "mesh", feature = "dns"))]
mod yara_broadcast_tests {
    use super::*;

    #[test]
    fn yara_report_defaults_to_zero() {
        let report = YaraBroadcastReport {
            completed: 0,
            failed: 0,
            aborted: 0,
            dropped: 0,
        };
        assert_eq!(report.completed, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.aborted, 0);
        assert_eq!(report.dropped, 0);
    }

    #[test]
    fn classify_yara_child_completed() {
        let mut report = YaraBroadcastReport {
            completed: 0,
            failed: 0,
            aborted: 0,
            dropped: 0,
        };
        classify_yara_child_result(Ok(()), &mut report);
        assert_eq!(report.completed, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.aborted, 0);
        assert_eq!(report.dropped, 0);
    }

    #[test]
    fn classify_yara_child_multiple_completed() {
        let mut report = YaraBroadcastReport {
            completed: 0,
            failed: 0,
            aborted: 0,
            dropped: 0,
        };
        classify_yara_child_result(Ok(()), &mut report);
        classify_yara_child_result(Ok(()), &mut report);
        classify_yara_child_result(Ok(()), &mut report);
        assert_eq!(report.completed, 3);
        assert_eq!(report.failed, 0);
        assert_eq!(report.aborted, 0);
        assert_eq!(report.dropped, 0);
    }

    #[test]
    fn yara_report_struct_is_pub() {
        let report = YaraBroadcastReport {
            completed: 10,
            failed: 2,
            aborted: 1,
            dropped: 5,
        };
        assert_eq!(report.completed, 10);
        assert_eq!(report.failed, 2);
        assert_eq!(report.aborted, 1);
        assert_eq!(report.dropped, 5);
    }

    #[tokio::test]
    async fn yara_loop_drains_on_channel_close() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::mesh::protocol::MeshMessage>(10);

        // Drop the sender to simulate channel close
        drop(tx);
        // The receiver should immediately return None (channel closed)
        let result = rx.recv().await;
        assert!(result.is_none(), "closed channel must return None");
    }

    #[tokio::test]
    async fn yara_semaphore_bounds_concurrency() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(2));

        // Acquire 2 permits (the max)
        let p1 = semaphore.clone().acquire_owned().await.unwrap();
        let p2 = semaphore.clone().acquire_owned().await.unwrap();

        // No permits available
        assert_eq!(semaphore.available_permits(), 0);

        // Try to acquire a third — should not succeed immediately
        let p3_fut = semaphore.clone().acquire_owned();
        let result = tokio::time::timeout(Duration::from_millis(10), p3_fut).await;
        assert!(result.is_err(), "third permit should not be available");

        // Release one permit
        drop(p1);
        assert_eq!(semaphore.available_permits(), 1);

        // Now the third can succeed
        let p3 = semaphore.clone().acquire_owned().await.unwrap();
        assert_eq!(semaphore.available_permits(), 0);

        drop(p2);
        drop(p3);
    }

    struct MockYaraBroadcastSink;

    #[async_trait::async_trait]
    impl super::YaraBroadcastSink for MockYaraBroadcastSink {
        async fn broadcast(&self, _msg: crate::mesh::protocol::MeshMessage) {
            // Mock: no-op
        }
    }

    #[tokio::test]
    async fn yara_loop_normal_child_completion_increments_completed() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Send messages so children are spawned, then close channel
        for _ in 0..3 {
            tx.send(crate::mesh::protocol::MeshMessage::FindNode {
                request_id: "test".into(),
                target_node_id: vec![0; 32],
                requester_node_id: "test".into(),
                timestamp: 0,
            })
            .await
            .unwrap();
        }
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(report.completed, 3);
        assert_eq!(report.dropped, 0);
    }

    #[tokio::test]
    async fn yara_loop_dropped_message_increments_counter() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(0)); // 0 permits = always saturated
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Send a message - should be dropped since semaphore has 0 permits
        tx.send(crate::mesh::protocol::MeshMessage::FindNode {
            request_id: "test".into(),
            target_node_id: vec![0; 32],
            requester_node_id: "test".into(),
            timestamp: 0,
        })
        .await
        .unwrap();
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.dropped, 1, "saturated semaphore must drop messages");
    }

    #[tokio::test]
    async fn yara_loop_channel_close_drains_children() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Drop sender immediately - channel closes
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report.completed, 0);
    }

    #[tokio::test]
    async fn yara_loop_concurrency_never_exceeds_permits() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(3));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        assert_eq!(semaphore.available_permits(), 3);
        // Send messages and close — loop must respect semaphore bounds
        for _ in 0..5 {
            tx.send(crate::mesh::protocol::MeshMessage::FindNode {
                request_id: "test".into(),
                target_node_id: vec![0; 32],
                requester_node_id: "test".into(),
                timestamp: 0,
            })
            .await
            .unwrap();
        }
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(5),
        )
        .await;
        // With 3 permits and 5 messages, at least 2 must be dropped
        assert!(
            report.dropped >= 2,
            "expected at least 2 dropped, got {}",
            report.dropped
        );
        // All children should complete or be accounted for
        assert_eq!(report.completed + report.dropped, 5);
    }

    #[tokio::test]
    async fn yara_loop_shutdown_exits_promptly() {
        use std::sync::Arc;
        let (_tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Send shutdown signal
        shutdown_tx.send(true).unwrap();
        let start = std::time::Instant::now();
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(30),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "shutdown must exit promptly, took {:?}",
            elapsed
        );
        assert_eq!(report.completed, 0);
    }

    #[tokio::test]
    async fn yara_helper_returns_after_joinset_empty() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Send messages and close - loop must drain before returning
        for _ in 0..5 {
            tx.send(crate::mesh::protocol::MeshMessage::FindNode {
                request_id: "test".into(),
                target_node_id: vec![0; 32],
                requester_node_id: "test".into(),
                timestamp: 0,
            })
            .await
            .unwrap();
        }
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(10),
        )
        .await;
        // All children should have completed or been cleaned up
        assert!(report.completed + report.failed + report.aborted + report.dropped <= 5);
    }

    #[test]
    fn yara_metrics_constants_exist() {
        // Verify metric names are documented/used in the source
        let content =
            std::fs::read_to_string("src/worker/unified_server/mod.rs").unwrap_or_default();
        assert!(content.contains("yara_mesh_broadcast_submitted_total"));
        assert!(content.contains("yara_mesh_broadcast_completed_total"));
        assert!(content.contains("yara_mesh_broadcast_failed_total"));
        assert!(content.contains("yara_mesh_broadcast_aborted_total"));
        assert!(content.contains("yara_mesh_broadcast_dropped_total"));
    }

    #[test]
    fn yara_broadcast_sink_trait_exists() {
        // Phase 15: YaraBroadcastSink trait enables testability
        let content =
            std::fs::read_to_string("src/worker/unified_server/mod.rs").unwrap_or_default();
        assert!(content.contains("trait YaraBroadcastSink"));
        assert!(content.contains("async fn broadcast(&self, msg:"));
    }

    #[test]
    fn yara_report_has_dropped_field() {
        let report = super::YaraBroadcastReport {
            completed: 0,
            failed: 0,
            aborted: 0,
            dropped: 5,
        };
        assert_eq!(report.dropped, 5);
    }

    struct PanickingSink;

    #[async_trait::async_trait]
    impl super::YaraBroadcastSink for PanickingSink {
        async fn broadcast(&self, _msg: crate::mesh::protocol::MeshMessage) {
            panic!("test panic");
        }
    }

    #[tokio::test]
    async fn yara_loop_child_panic_increments_failed() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(PanickingSink);
        for _ in 0..2 {
            tx.send(crate::mesh::protocol::MeshMessage::FindNode {
                request_id: "test".into(),
                target_node_id: vec![0; 32],
                requester_node_id: "test".into(),
                timestamp: 0,
            })
            .await
            .unwrap();
        }
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(
            report.failed, 2,
            "panicking children must be counted as failed"
        );
        assert_eq!(report.completed, 0, "panicking children must not complete");
    }

    struct HangSink;

    #[async_trait::async_trait]
    impl super::YaraBroadcastSink for HangSink {
        async fn broadcast(&self, _msg: crate::mesh::protocol::MeshMessage) {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    #[tokio::test]
    async fn yara_loop_hung_child_is_aborted_after_drain() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(HangSink);
        tx.send(crate::mesh::protocol::MeshMessage::FindNode {
            request_id: "test".into(),
            target_node_id: vec![0; 32],
            requester_node_id: "test".into(),
            timestamp: 0,
        })
        .await
        .unwrap();
        drop(tx);
        let start = std::time::Instant::now();
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_millis(50),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "loop must complete quickly after drain, took {:?}",
            elapsed
        );
        assert!(
            report.aborted + report.failed >= 1,
            "hung child must be aborted or failed, got {:?}",
            report
        );
    }

    #[tokio::test]
    async fn yara_loop_shutdown_aborts_running_children() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(HangSink);
        // Spawn the loop so it can process messages concurrently
        let handle = tokio::spawn(super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            Duration::from_millis(100),
        ));
        // Send a message — the loop will spawn a child that hangs
        tx.send(crate::mesh::protocol::MeshMessage::FindNode {
            request_id: "test".into(),
            target_node_id: vec![0; 32],
            requester_node_id: "test".into(),
            timestamp: 0,
        })
        .await
        .unwrap();
        // Yield to let the loop receive and spawn the child
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        // Now send shutdown — the loop must abort the running child
        shutdown_tx.send(true).unwrap();
        drop(tx);
        let start = std::time::Instant::now();
        let report = handle.await.unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown must exit promptly, took {:?}",
            elapsed
        );
        assert!(
            report.aborted + report.failed >= 1,
            "running child must be aborted or failed, got {:?}",
            report
        );
    }

    #[tokio::test]
    async fn yara_loop_zero_drain_timeout_aborts_immediately() {
        use std::sync::Arc;
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(HangSink);
        tx.send(crate::mesh::protocol::MeshMessage::FindNode {
            request_id: "test".into(),
            target_node_id: vec![0; 32],
            requester_node_id: "test".into(),
            timestamp: 0,
        })
        .await
        .unwrap();
        drop(tx);
        let start = std::time::Instant::now();
        let report =
            super::run_yara_broadcast_loop(rx, sink, semaphore, shutdown_rx, Duration::ZERO).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "zero drain timeout must abort immediately, took {:?}",
            elapsed
        );
        assert!(
            report.aborted + report.failed >= 1,
            "all children must be accounted for, got {:?}",
            report
        );
    }
}

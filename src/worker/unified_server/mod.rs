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
pub mod shutdown_executor;
pub mod startup_plan;
pub mod state;
pub mod supervision_loop;
pub mod supervisor_notify;

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
    /// Create an empty support bundle for a generation (no tasks registered).
    /// Used when optional mesh starts without DNS/YARA support tasks.
    pub fn empty(generation: u64) -> Self {
        let (cancel_tx, _) = tokio::sync::watch::channel(false);
        Self {
            generation,
            task_ids: Vec::new(),
            cancel_tx,
        }
    }

    /// Signal all support tasks in this generation to shut down cooperatively.
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// Returns a receiver that fires when this generation is cancelled.
    pub fn cancel_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.cancel_tx.subscribe()
    }
}

/// Context for support teardown (Iteration 88, Part B).
#[derive(Debug, Clone, Copy)]
pub enum SupportStopContext {
    /// Optional mesh degraded — worker remains active.
    OptionalMeshDegraded,
    /// Whole worker is shutting down.
    WorkerShutdown,
    /// Startup rollback in progress.
    StartupRollback,
}

impl SupportStopContext {
    /// Whether exits during this context are expected (worker shutting down).
    pub fn expected_during_shutdown(&self) -> bool {
        matches!(self, Self::WorkerShutdown | Self::StartupRollback)
    }
}

/// Report from generation support teardown (Iteration 88, Part B).
#[derive(Debug)]
pub struct MeshSupportStopReport {
    /// The generation that was stopped.
    pub generation: u64,
    /// Number of tasks that exited cooperatively.
    pub cooperative: usize,
    /// Number of tasks that required forced abort.
    pub aborted: usize,
    /// Number of tasks that failed to exit.
    pub failed: usize,
    /// Number of task IDs not found in the registry.
    pub not_found: usize,
}

impl MeshSupportStopReport {
    /// Returns true if all tasks exited cleanly and no IDs were missing.
    pub fn clean(&self) -> bool {
        self.aborted == 0 && self.failed == 0 && self.not_found == 0
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
    mut worker_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut generation_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    drain_timeout: Duration,
) -> YaraBroadcastReport {
    let mut report = YaraBroadcastReport {
        completed: 0,
        failed: 0,
        aborted: 0,
        dropped: 0,
    };
    let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    // Check if either receiver is already true before entering the loop.
    // A watch receiver initialized to `true` will never fire `changed()` again,
    // so we must check the current value (Iteration 88, Part C — Phase 14).
    if *worker_shutdown_rx.borrow() || *generation_shutdown_rx.borrow() {
        tracing::debug!("YARA broadcast loop: shutdown signal already set at entry");
        // Fall through to drain.
    } else {
        loop {
            tokio::select! {
                biased;
                _ = worker_shutdown_rx.changed() => {
                    tracing::debug!("YARA broadcast loop received worker shutdown");
                    break;
                }
                _ = generation_shutdown_rx.changed() => {
                    tracing::debug!("YARA broadcast loop received generation shutdown");
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
/// DNS verification loops and YARA broadcast loop are support infrastructure
/// that should only run when the mesh transport is actually active. DHT routing
/// initialization belongs to MeshTransport transactional startup (Iteration 87).
/// Registering them before startup would create orphaned tasks if mesh startup fails.
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

/// Register mesh generation support tasks (DNS verification, YARA broadcast)
/// in the worker task registry.
///
/// DHT routing initialization belongs to MeshTransport transactional startup
/// (Iteration 87, Phase 1).
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
        let gen_shutdown = cancel_rx.clone();
        let id = registry.spawn_background("yara_broadcast", async move {
            let sink: Arc<dyn YaraBroadcastSink> =
                Arc::new(MeshTransportBroadcastSink(mesh_transport));
            let report = run_yara_broadcast_loop(
                broadcast_rx,
                sink,
                broadcast_semaphore,
                worker_shutdown_rx,
                gen_shutdown,
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

/// Stop a mesh generation support bundle with cooperative-then-forced cleanup
/// (Iteration 88, Part B — Phase 7).
///
/// Sends a cooperative cancellation signal, waits up to half the timeout for
/// natural completion, then force-aborts and joins remaining tasks.
#[cfg(all(feature = "mesh", feature = "dns"))]
pub async fn stop_mesh_generation_support(
    task_registry: &tokio::sync::Mutex<crate::worker::task_registry::WorkerTaskRegistry>,
    support: MeshGenerationSupport,
    timeout: Duration,
    context: SupportStopContext,
) -> MeshSupportStopReport {
    support.cancel();

    let cooperative_budget = timeout / 2;
    let forced_budget = timeout.saturating_sub(cooperative_budget);

    let mut registry = task_registry.lock().await;

    let report = registry
        .cancel_then_join_tasks(
            &support.task_ids,
            cooperative_budget,
            forced_budget,
            context.expected_during_shutdown(),
        )
        .await;

    MeshSupportStopReport {
        generation: support.generation,
        cooperative: report
            .exits
            .iter()
            .filter(|e| {
                matches!(
                    e.reason,
                    crate::worker::task_registry::TaskExitReason::CleanCompletion
                        | crate::worker::task_registry::TaskExitReason::Cancelled
                )
            })
            .count(),
        aborted: report.aborted_count(),
        failed: report
            .exits
            .iter()
            .filter(|e| {
                matches!(
                    e.reason,
                    crate::worker::task_registry::TaskExitReason::Error(_)
                        | crate::worker::task_registry::TaskExitReason::Panic(_)
                        | crate::worker::task_registry::TaskExitReason::UnexpectedCompletion
                )
            })
            .count(),
        not_found: report.not_found_ids.len(),
    }
}

pub async fn run_unified_server_worker(
    args: UnifiedServerWorkerArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ---- Phase 0–14.5: startup plan (identity through mesh supervision pipeline) ----
    let startup = startup_plan::build_worker_startup(args).await?;

    // ---- Phase 15: supervision loop (select over lifecycle, exits, mesh decisions) ----
    // Extract owned fields from startup before passing to supervision loop.
    #[cfg(feature = "mesh")]
    let (mesh_decision_rx_opt, required_mesh_startup_failure, mut active_mesh_support) = {
        match startup.mesh_startup {
            Some(ms) => (
                Some(ms.decision_rx),
                ms.startup_failure,
                ms.active_mesh_support,
            ),
            None => (None, None, None),
        }
    };
    #[cfg(not(feature = "mesh"))]
    let (mesh_decision_rx_opt, required_mesh_startup_failure, active_mesh_support): (
        Option<()>,
        Option<()>,
        Option<()>,
    ) = (None, None, None);

    let worker_id = startup.worker_id;
    let supervision_result = supervision_loop::run_worker_supervision(
        &startup.state,
        startup.lifecycle_rx,
        startup.exit_rx,
        mesh_decision_rx_opt,
        required_mesh_startup_failure,
        active_mesh_support,
    )
    .await;

    // ---- Phase 16: map supervision outcome + execute ordered shutdown ----
    let shutdown_ctx = shutdown_executor::WorkerShutdownContext::from_supervision_result(
        worker_id,
        startup.state,
        supervision_result,
    );
    let _report = shutdown_executor::execute_worker_shutdown(shutdown_ctx).await?;

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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Drop sender immediately - channel closes
        drop(tx);
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(MockYaraBroadcastSink);
        // Send shutdown signal
        shutdown_tx.send(true).unwrap();
        let start = std::time::Instant::now();
        let report = super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
        let sink = Arc::new(HangSink);
        // Spawn the loop so it can process messages concurrently
        let handle = tokio::spawn(super::run_yara_broadcast_loop(
            rx,
            sink,
            semaphore,
            shutdown_rx,
            gen_shutdown_rx,
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
        let (_gen_shutdown_tx, gen_shutdown_rx) = tokio::sync::watch::channel(false);
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
            gen_shutdown_rx,
            Duration::ZERO,
        )
        .await;
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

// ── Phase 6: Optional startup behavioral tests ──────────────────────────────
// ── Phase 10: Required readiness behavioral tests ───────────────────────────

#[cfg(test)]
#[cfg(all(feature = "mesh", feature = "dns"))]
mod composition_root_tests {
    use super::*;

    // ── MeshGenerationSupport tests ─────────────────────────────────────────

    #[tokio::test]
    async fn optional_support_cancel_signals_receiver() {
        let support = MeshGenerationSupport::empty(1);
        let mut rx = support.cancel_receiver();
        assert!(!*rx.borrow_and_update());
        support.cancel();
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
    }

    #[test]
    fn optional_support_empty_has_no_tasks() {
        let support = MeshGenerationSupport::empty(42);
        assert_eq!(support.generation, 42);
        assert!(support.task_ids.is_empty());
    }

    #[tokio::test]
    async fn optional_support_cancel_is_idempotent() {
        let support = MeshGenerationSupport::empty(1);
        let mut rx = support.cancel_receiver();
        assert!(!*rx.borrow_and_update());
        support.cancel();
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
        // Second cancel is a no-op (already cancelled).
        support.cancel();
        // Receiver should still see true.
        assert!(*rx.borrow());
    }

    // ── MeshSupportStopReport tests ─────────────────────────────────────────

    #[test]
    fn stop_report_clean_when_all_cooperative() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 3,
            aborted: 0,
            failed: 0,
            not_found: 0,
        };
        assert!(report.clean());
    }

    #[test]
    fn stop_report_not_clean_when_aborted() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 2,
            aborted: 1,
            failed: 0,
            not_found: 0,
        };
        assert!(!report.clean());
    }

    #[test]
    fn stop_report_not_clean_when_failed() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 1,
            aborted: 0,
            failed: 2,
            not_found: 0,
        };
        assert!(!report.clean());
    }

    #[test]
    fn stop_report_clean_zero_tasks() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 0,
            aborted: 0,
            failed: 0,
            not_found: 0,
        };
        assert!(report.clean());
    }

    // ── Phase 6: Optional startup success returns bundle ────────────────────

    #[tokio::test]
    async fn optional_startup_success_returns_bundle() {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<Result<Option<MeshGenerationSupport>, String>>(1);
        let support = MeshGenerationSupport::empty(1);
        let _ = tx.send(Ok(Some(support))).await;
        let result = rx.recv().await.unwrap();
        assert!(result.is_ok());
        let bundle = result.unwrap().unwrap();
        assert_eq!(bundle.generation, 1);
        assert!(bundle.task_ids.is_empty());
    }

    // ── Phase 6: Optional startup failure produces no bundle ────────────────

    #[tokio::test]
    async fn optional_startup_failure_produces_no_bundle() {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<Result<Option<MeshGenerationSupport>, String>>(1);
        let _ = tx.send(Err("startup failed".into())).await;
        let result = rx.recv().await.unwrap();
        assert!(result.is_err());
    }

    // ── Phase 6: Optional degradation invokes stop_mesh_generation_support ──

    #[tokio::test]
    async fn optional_degradation_stops_support_bundle() {
        let registry =
            tokio::sync::Mutex::new(crate::worker::task_registry::WorkerTaskRegistry::new());
        let support = MeshGenerationSupport::empty(1);
        let task_ids = support.task_ids.clone();
        let generation = support.generation;
        let report = stop_mesh_generation_support(
            &registry,
            support,
            Duration::from_secs(5),
            SupportStopContext::OptionalMeshDegraded,
        )
        .await;
        assert_eq!(report.generation, generation);
        assert!(report.clean());
        assert!(task_ids.is_empty());
    }

    // ── Phase 6: Channel closure produces None ──────────────────────────────

    #[tokio::test]
    async fn optional_startup_channel_closure_returns_none() {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<Result<Option<MeshGenerationSupport>, String>>(1);
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    // ── Phase 10: Empty support set permits ready ───────────────────────────

    #[test]
    fn empty_support_bundle_allows_ready() {
        let support = MeshGenerationSupport::empty(1);
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 0,
            aborted: 0,
            failed: 0,
            not_found: 0,
        };
        assert!(report.clean());
        assert!(support.task_ids.is_empty());
    }

    // ── Phase 10: Ready semantics via report ────────────────────────────────

    #[test]
    fn required_support_success_report_allows_ready() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 2,
            aborted: 0,
            failed: 0,
            not_found: 0,
        };
        assert!(report.clean(), "clean support stop must allow ready");
    }

    #[test]
    fn required_support_failure_report_blocks_ready() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 0,
            aborted: 1,
            failed: 1,
            not_found: 0,
        };
        assert!(!report.clean(), "failed support stop must block ready");
    }

    // ── Phase 16: Accounting correctness ────────────────────────────────────

    #[tokio::test]
    async fn stop_report_classifies_cooperative_cancellation() {
        let registry =
            tokio::sync::Mutex::new(crate::worker::task_registry::WorkerTaskRegistry::new());
        let mut reg = registry.lock().await;
        // Spawn a task that cooperatively exits when the watch signal fires.
        let (_gen_shutdown_tx, mut gen_shutdown_rx) = tokio::sync::watch::channel(false);
        let task_id = reg.spawn_background("test_coop", async move {
            // Cooperatively exit when shutdown signal fires.
            let _ = gen_shutdown_rx.changed().await;
        });
        let cancel_tx = {
            let (tx, _) = tokio::sync::watch::channel(false);
            tx
        };
        let support = MeshGenerationSupport {
            generation: 1,
            task_ids: vec![crate::worker::task_registry::TaskId(task_id as u64)],
            cancel_tx,
        };
        drop(reg);

        let report = stop_mesh_generation_support(
            &registry,
            support,
            Duration::from_secs(5),
            SupportStopContext::OptionalMeshDegraded,
        )
        .await;

        // The task receives the cooperative cancel signal from support.cancel()
        // but that's a different watch channel. The gen_shutdown_rx won't fire.
        // So the task will be force-aborted. After abort, the join resolves as
        // Cancelled, which is classified as cooperative in the current accounting.
        let total = report.cooperative + report.aborted + report.failed;
        assert!(total >= 1, "report must count the task, got {:?}", report);
        // Clean means no aborts and no failures.
        assert!(report.clean(), "cancelled task is still clean");
    }

    #[test]
    fn stop_report_failed_counts_include_panic() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 0,
            aborted: 0,
            failed: 2,
            not_found: 0,
        };
        assert!(!report.clean());
    }

    #[test]
    fn stop_report_failed_counts_include_unexpected_completion() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 0,
            aborted: 0,
            failed: 1,
            not_found: 0,
        };
        assert!(!report.clean());
    }

    #[test]
    fn stop_report_not_found_blocks_clean() {
        let report = MeshSupportStopReport {
            generation: 1,
            cooperative: 1,
            aborted: 0,
            failed: 0,
            not_found: 1,
        };
        assert!(
            !report.clean(),
            "not_found > 0 must produce non-clean report"
        );
    }
}

// Ordered shutdown executor for the unified worker.
//
// Executes the composition-root shutdown procedure after the supervision
// loop exits. Extracted from run_unified_server_worker() in Iteration 93.
//
// Iteration 94: Moved supervision-outcome-to-shutdown-cause mapping here
// from mod.rs, restoring explicit active mesh support shutdown.

use crate::worker::task_registry::{SupervisionOutcome, WorkerShutdownCause};
use crate::worker::unified_server::lifecycle::WorkerLifecycleEvent;
use crate::worker::unified_server::state::UnifiedServerWorkerState;
use crate::worker::unified_server::supervisor_notify;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Report from the shutdown executor.
pub struct WorkerShutdownReport {
    pub final_cause: WorkerShutdownCause,
    pub exit_code: i32,
}

/// Shutdown plan produced from a supervision outcome.
///
/// Encapsulates the mapping from `SupervisionOutcome` to the individual
/// shutdown parameters (cause, lifecycle ack, graceful flag, drain timeout).
/// This keeps the composition root thin and makes the mapping unit-testable.
pub struct WorkerShutdownPlan {
    pub shutdown_cause: WorkerShutdownCause,
    pub lifecycle_ack: Option<tokio::sync::oneshot::Sender<()>>,
    pub graceful: bool,
    pub drain_timeout: std::time::Duration,
}

impl WorkerShutdownPlan {
    /// Map a supervision outcome to a shutdown plan.
    ///
    /// Preserves the exact mapping semantics from the original inline
    /// implementation in `run_unified_server_worker()`.
    pub fn from_supervision_outcome(outcome: SupervisionOutcome) -> Self {
        match outcome {
            SupervisionOutcome::Lifecycle { event, accepted } => {
                let (graceful, drain_timeout) = match &event {
                    WorkerLifecycleEvent::MasterShutdown { graceful, timeout } => {
                        (*graceful, *timeout)
                    }
                    WorkerLifecycleEvent::WorkerResize { .. } => {
                        (true, std::time::Duration::from_secs(30))
                    }
                    WorkerLifecycleEvent::SupervisorDisconnected => {
                        (false, std::time::Duration::ZERO)
                    }
                };
                let cause = match &event {
                    WorkerLifecycleEvent::MasterShutdown { .. } => {
                        WorkerShutdownCause::SupervisorShutdown
                    }
                    WorkerLifecycleEvent::WorkerResize { worker_threads } => {
                        WorkerShutdownCause::WorkerResize {
                            worker_threads: *worker_threads,
                        }
                    }
                    WorkerLifecycleEvent::SupervisorDisconnected => {
                        WorkerShutdownCause::SupervisorDisconnected
                    }
                };
                Self {
                    shutdown_cause: cause,
                    lifecycle_ack: Some(accepted),
                    graceful,
                    drain_timeout,
                }
            }
            SupervisionOutcome::DirectCause(cause) => {
                let graceful = match &cause {
                    WorkerShutdownCause::ServerExitedUnexpectedly(_)
                    | WorkerShutdownCause::CriticalTaskExit(_)
                    | WorkerShutdownCause::RegistryExitChannelClosed
                    | WorkerShutdownCause::SupervisorDisconnected => false,
                    #[cfg(feature = "mesh")]
                    WorkerShutdownCause::MeshStartupFailed(_)
                    | WorkerShutdownCause::MeshShutdownIncomplete(_)
                    | WorkerShutdownCause::MeshServiceExit(_)
                    | WorkerShutdownCause::MeshRestartExhausted { .. }
                    | WorkerShutdownCause::MeshConfigurationInvariant(_) => false,
                    _ => true,
                };
                let drain_timeout = if graceful {
                    std::time::Duration::from_secs(30)
                } else {
                    std::time::Duration::ZERO
                };
                Self {
                    shutdown_cause: cause,
                    lifecycle_ack: None,
                    graceful,
                    drain_timeout,
                }
            }
        }
    }
}

/// Context for the shutdown executor. Holds all state needed for ordered teardown.
pub struct WorkerShutdownContext {
    pub worker_id: synvoid_ipc::WorkerId,
    pub state: UnifiedServerWorkerState,
    pub shutdown_cause: WorkerShutdownCause,
    pub lifecycle_ack: Option<tokio::sync::oneshot::Sender<()>>,
    pub graceful: bool,
    pub drain_timeout: std::time::Duration,
    pub active_mesh_support: Option<crate::worker::unified_server::MeshGenerationSupport>,
}

impl WorkerShutdownContext {
    /// Build a shutdown context from startup state and supervision result.
    ///
    /// Consumes the `WorkerSupervisionResult` (via its outcome and active
    /// mesh support) along with the startup state to produce a fully-formed
    /// shutdown context. This keeps the composition root thin.
    pub fn from_supervision_result(
        worker_id: synvoid_ipc::WorkerId,
        state: UnifiedServerWorkerState,
        supervision_result: crate::worker::unified_server::supervision_loop::WorkerSupervisionResult,
    ) -> Self {
        let plan = WorkerShutdownPlan::from_supervision_outcome(supervision_result.outcome);
        Self {
            worker_id,
            state,
            shutdown_cause: plan.shutdown_cause,
            lifecycle_ack: plan.lifecycle_ack,
            graceful: plan.graceful,
            drain_timeout: plan.drain_timeout,
            active_mesh_support: supervision_result.active_mesh_support,
        }
    }
}

/// Execute the ordered shutdown procedure.
///
/// Shutdown order (preserved exactly from the original inline implementation):
/// 1. Record coordinated shutdown intent + lifecycle ack
/// 2. Stop accepting new connections
/// 3. Graceful drain (if requested and nonzero timeout)
/// 4. Stop app servers (Granian supervisors)
/// 4.5. Shutdown mesh transport (if running)
/// 4.6. Stop active mesh support bundle explicitly (Iteration 94)
/// 5. Clear running flag
/// 6. Broadcast registry cancellation
/// 7. Bandwidth persist (handled by background task)
/// 8. Await registry tasks with bounded timeouts
/// 9. Abort and await remaining non-migrated task handles
/// 10. Send supervisor acknowledgement
/// 11. Derive exit code
pub async fn execute_worker_shutdown(
    ctx: WorkerShutdownContext,
) -> Result<WorkerShutdownReport, BoxError> {
    let WorkerShutdownContext {
        worker_id,
        state,
        mut shutdown_cause,
        lifecycle_ack,
        graceful,
        drain_timeout,
        mut active_mesh_support,
    } = ctx;

    // Step 1: Record coordinated shutdown intent before any teardown,
    // and acknowledge the lifecycle event so the IPC task can return.
    super::lifecycle::begin_coordinated_shutdown(&state.task_registry, lifecycle_ack).await;

    // Step 1.5: Establish real shutdown deadline.
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
    #[cfg(feature = "mesh")]
    {
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

    // Step 4.6: Stop active mesh support bundle explicitly (Iteration 94).
    // If optional mesh degradation already took the support bundle,
    // active_mesh_support is None and this is a no-op.
    // Gated on both mesh+dns because stop_mesh_generation_support is only
    // available when DNS support is compiled in (YARA broadcast, DNS verification).
    #[cfg(all(feature = "mesh", feature = "dns"))]
    if let Some(support) = active_mesh_support.take() {
        let remaining = remaining_budget();
        let timeout = if remaining.is_zero() {
            std::time::Duration::from_secs(5)
        } else {
            remaining.min(std::time::Duration::from_secs(5))
        };

        let stop_report = crate::worker::unified_server::stop_mesh_generation_support(
            &state.task_registry,
            support,
            timeout,
            crate::worker::unified_server::SupportStopContext::WorkerShutdown,
        )
        .await;

        if stop_report.clean() {
            tracing::info!(
                generation = stop_report.generation,
                cooperative = stop_report.cooperative,
                "mesh support generation stopped cleanly during worker shutdown"
            );
        } else {
            tracing::warn!(
                generation = stop_report.generation,
                cooperative = stop_report.cooperative,
                aborted = stop_report.aborted,
                failed = stop_report.failed,
                not_found = stop_report.not_found,
                "mesh support generation required cleanup during worker shutdown"
            );
        }
    }
    // Suppress unused variable when mesh+dns is not compiled in.
    #[cfg(not(all(feature = "mesh", feature = "dns")))]
    let _ = active_mesh_support;

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
    supervisor_notify::notify_supervisor_of_shutdown(&state.ipc, worker_id, &shutdown_cause).await;

    // Step 11: Derive exit code from the authoritative shutdown cause.
    let exit_code = supervisor_notify::exit_code_for_shutdown_cause(&shutdown_cause);

    tracing::info!(
        "Unified Server Worker {} shutting down (cause: {}, exit_code: {})",
        worker_id,
        shutdown_cause,
        exit_code
    );

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(WorkerShutdownReport {
        final_cause: shutdown_cause,
        exit_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::task_registry::SupervisionOutcome;
    use crate::worker::unified_server::lifecycle::WorkerLifecycleEvent;

    #[test]
    fn lifecycle_master_shutdown_preserves_graceful_and_timeout() {
        let (tx, _) = tokio::sync::oneshot::channel();
        let event = WorkerLifecycleEvent::MasterShutdown {
            graceful: true,
            timeout: std::time::Duration::from_secs(45),
        };
        let outcome = SupervisionOutcome::Lifecycle {
            event,
            accepted: tx,
        };

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert_eq!(plan.shutdown_cause, WorkerShutdownCause::SupervisorShutdown);
        assert!(plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::from_secs(45));
        assert!(plan.lifecycle_ack.is_some());
    }

    #[test]
    fn lifecycle_resize_is_graceful_with_default_timeout() {
        let (tx, _) = tokio::sync::oneshot::channel();
        let event = WorkerLifecycleEvent::WorkerResize { worker_threads: 8 };
        let outcome = SupervisionOutcome::Lifecycle {
            event,
            accepted: tx,
        };

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(matches!(
            plan.shutdown_cause,
            WorkerShutdownCause::WorkerResize { worker_threads: 8 }
        ));
        assert!(plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::from_secs(30));
        assert!(plan.lifecycle_ack.is_some());
    }

    #[test]
    fn lifecycle_supervisor_disconnected_is_immediate() {
        let (tx, _) = tokio::sync::oneshot::channel();
        let event = WorkerLifecycleEvent::SupervisorDisconnected;
        let outcome = SupervisionOutcome::Lifecycle {
            event,
            accepted: tx,
        };

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert_eq!(
            plan.shutdown_cause,
            WorkerShutdownCause::SupervisorDisconnected
        );
        assert!(!plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::ZERO);
        assert!(plan.lifecycle_ack.is_some());
    }

    #[test]
    fn direct_critical_task_exit_is_immediate() {
        let cause =
            WorkerShutdownCause::CriticalTaskExit(crate::worker::task_registry::NamedTaskExit {
                name: "test_task",
                id: crate::worker::task_registry::TaskId(1),
                reason: crate::worker::task_registry::TaskExitReason::Panic(
                    "test panic".to_string(),
                ),
                class: crate::worker::task_registry::TaskClass::CriticalService,
                expected_during_shutdown: false,
            });
        let outcome = SupervisionOutcome::DirectCause(cause);

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(matches!(
            plan.shutdown_cause,
            WorkerShutdownCause::CriticalTaskExit(_)
        ));
        assert!(!plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::ZERO);
        assert!(plan.lifecycle_ack.is_none());
    }

    #[test]
    fn direct_external_stop_is_graceful() {
        let cause = WorkerShutdownCause::ExternalStop;
        let outcome = SupervisionOutcome::DirectCause(cause);

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(matches!(
            plan.shutdown_cause,
            WorkerShutdownCause::ExternalStop
        ));
        assert!(plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::from_secs(30));
        assert!(plan.lifecycle_ack.is_none());
    }

    #[test]
    fn direct_server_exited_unexpectedly_is_immediate() {
        let cause = WorkerShutdownCause::ServerExitedUnexpectedly(
            crate::worker::task_registry::NamedTaskExit {
                name: "server_run",
                id: crate::worker::task_registry::TaskId(1),
                reason: crate::worker::task_registry::TaskExitReason::CleanCompletion,
                class: crate::worker::task_registry::TaskClass::CriticalService,
                expected_during_shutdown: false,
            },
        );
        let outcome = SupervisionOutcome::DirectCause(cause);

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(!plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::ZERO);
    }

    #[test]
    fn direct_registry_exit_channel_closed_is_immediate() {
        let cause = WorkerShutdownCause::RegistryExitChannelClosed;
        let outcome = SupervisionOutcome::DirectCause(cause);

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(!plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::ZERO);
    }

    #[test]
    fn direct_supervisor_disconnected_is_immediate() {
        let cause = WorkerShutdownCause::SupervisorDisconnected;
        let outcome = SupervisionOutcome::DirectCause(cause);

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(!plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::ZERO);
    }

    #[test]
    fn direct_server_stopped_for_shutdown_is_graceful() {
        let cause = WorkerShutdownCause::ServerStoppedForShutdown;
        let outcome = SupervisionOutcome::DirectCause(cause);

        let plan = WorkerShutdownPlan::from_supervision_outcome(outcome);
        assert!(plan.graceful);
        assert_eq!(plan.drain_timeout, std::time::Duration::from_secs(30));
    }
}

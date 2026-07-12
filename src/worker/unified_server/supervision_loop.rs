// Worker supervision loop.
//
// Runs the main select loop over lifecycle events, task exits, and mesh
// supervision decisions. Extracted from run_unified_server_worker() in Iteration 93.
//
// This module must NOT perform ordered teardown — it only selects the
// cause and returns.

#[cfg(all(feature = "mesh", feature = "dns"))]
use std::time::Duration;

use crate::worker::task_registry::SupervisionOutcome;
use crate::worker::task_registry::WorkerShutdownCause;
use crate::worker::unified_server::state::UnifiedServerWorkerState;
#[cfg(feature = "mesh")]
use crate::worker::unified_server::MeshGenerationSupport;
#[cfg(all(feature = "mesh", feature = "dns"))]
use crate::worker::unified_server::SupportStopContext;

#[cfg(feature = "mesh")]
type MeshDecisionReceiver =
    tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>;
#[cfg(not(feature = "mesh"))]
type MeshDecisionReceiver = ();

#[cfg(feature = "mesh")]
type OptionalMeshSupport = Option<MeshGenerationSupport>;
#[cfg(not(feature = "mesh"))]
type OptionalMeshSupport = Option<()>;

/// Result of the supervision loop.
pub struct WorkerSupervisionResult {
    pub outcome: SupervisionOutcome,
    #[cfg(feature = "mesh")]
    pub active_mesh_support: Option<MeshGenerationSupport>,
}

/// Run the supervision loop.
///
/// Selects over lifecycle IPC events, task registry exits, and mesh
/// supervision decisions. Returns a `SupervisionOutcome` that preserves
/// direct shutdown causes without converting them to fake lifecycle events.
///
/// This function does NOT perform ordered teardown — that is the
/// responsibility of `shutdown_executor::execute_worker_shutdown()`.
#[cfg_attr(not(feature = "mesh"), allow(unused_mut, unused_variables))]
#[cfg_attr(all(feature = "mesh", not(feature = "dns")), allow(unused_mut))]
pub async fn run_worker_supervision(
    state: &UnifiedServerWorkerState,
    mut lifecycle_rx: tokio::sync::mpsc::Receiver<
        crate::worker::unified_server::lifecycle::LifecycleRequest,
    >,
    mut exit_rx: tokio::sync::broadcast::Receiver<crate::worker::task_registry::NamedTaskExit>,
    mut mesh_decision_rx_opt: Option<MeshDecisionReceiver>,
    required_mesh_startup_failure: Option<WorkerShutdownCause>,
    mut active_mesh_support: OptionalMeshSupport,
) -> WorkerSupervisionResult {
    let shutdown_flag = {
        let registry = state.task_registry.lock().await;
        registry.shutdown_started_flag()
    };

    let outcome: SupervisionOutcome = {
        #[cfg(feature = "mesh")]
        if let Some(cause) = required_mesh_startup_failure {
            return WorkerSupervisionResult {
                outcome: SupervisionOutcome::DirectCause(cause),
                #[cfg(feature = "mesh")]
                active_mesh_support,
            };
        }
        loop {
            // Mesh supervision decisions future. Defined outside select to
            // avoid #[cfg] on select branches (not valid proc-macro syntax).
            #[cfg(feature = "mesh")]
            let mesh_decision_future = async {
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
                            break SupervisionOutcome::Lifecycle {
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
                                break SupervisionOutcome::DirectCause(cause);
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
                                break SupervisionOutcome::DirectCause(cause);
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
                                break SupervisionOutcome::DirectCause(cause);
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
                            break SupervisionOutcome::DirectCause(
                                crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause)
                            );
                        }
                        Some(crate::worker::mesh_supervision::MeshSupervisorDecision::RestartMesh) => {
                            // RestartMesh is unreachable when restart_enabled is rejected at
                            // config validation time. This branch is defense-in-depth only.
                            tracing::error!("Invariant violation: RestartMesh reached while restart is disabled");
                            break SupervisionOutcome::DirectCause(
                                WorkerShutdownCause::MeshConfigurationInvariant(
                                    "RestartMesh reached while restart is disabled".to_string(),
                                )
                            );
                        }
                        Some(crate::worker::mesh_supervision::MeshSupervisorDecision::MarkDegraded(reason)) => {
                            tracing::warn!(reason = %reason, "mesh degraded");
                            #[cfg(all(feature = "mesh", feature = "dns"))]
                            if let Some(support) = active_mesh_support.take() {
                                let stop_report = crate::worker::unified_server::stop_mesh_generation_support(
                                    &state.task_registry,
                                    support,
                                    Duration::from_secs(5),
                                    SupportStopContext::OptionalMeshDegraded,
                                )
                                .await;
                                if !stop_report.clean() {
                                    tracing::warn!(
                                        context = ?SupportStopContext::OptionalMeshDegraded,
                                        generation = stop_report.generation,
                                        not_found = stop_report.not_found,
                                        "mesh support generation required forced cleanup"
                                    );
                                }
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

    WorkerSupervisionResult {
        outcome,
        #[cfg(feature = "mesh")]
        active_mesh_support,
    }
}

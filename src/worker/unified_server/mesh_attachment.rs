// Worker-side mesh attachment orchestration.
//
// Owns mesh supervision pipeline creation, required/optional startup behavior,
// and support-task registration after mesh transport startup succeeds.
//
// This module does not implement mesh transport internals and does not perform
// ordered worker shutdown.

#[cfg(feature = "mesh")]
use std::sync::Arc;
#[cfg(feature = "mesh")]
use tokio::sync::RwLock;

#[cfg(feature = "mesh")]
use super::startup_plan::{MeshStartupState, WorkerReadinessPlan};
#[cfg(feature = "mesh")]
use super::state::UnifiedServerWorkerState;
#[cfg(feature = "mesh")]
use super::{MeshGenerationSupport, SupportStopContext};
#[cfg(feature = "mesh")]
use synvoid_config::ConfigManager;

#[cfg(feature = "mesh")]
type BoxError = Box<dyn std::error::Error + Send + Sync>;
#[cfg(feature = "mesh")]
type SharedConfig = Arc<RwLock<ConfigManager>>;

#[cfg(feature = "mesh")]
pub struct WorkerMeshAttachmentInput<'a> {
    pub worker_id: synvoid_ipc::WorkerId,
    pub state: &'a UnifiedServerWorkerState,
    pub shared_config: SharedConfig,
    pub has_mesh_transport: bool,
    pub mesh_transport: Option<Arc<synvoid_mesh::MeshTransport>>,
    pub support_tasks: Option<super::MeshSupportTasks>,
    pub readiness: &'a WorkerReadinessPlan,
}

// ── Internal helpers ────────────────────────────────────────────────────────

#[cfg(feature = "mesh")]
struct MeshPipelineRuntime {
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    decision_rx:
        tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
}

#[cfg(feature = "mesh")]
struct RequiredMeshStartInput<'a> {
    worker_id: synvoid_ipc::WorkerId,
    state: &'a UnifiedServerWorkerState,
    readiness: &'a WorkerReadinessPlan,
    mesh_status: Arc<tokio::sync::RwLock<crate::worker::mesh_supervision::WorkerMeshStatus>>,
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    support_tasks: Option<super::MeshSupportTasks>,
}

#[cfg(feature = "mesh")]
struct RequiredMeshStartOutput {
    startup_failure: Option<crate::worker::task_registry::WorkerShutdownCause>,
    active_mesh_support: Option<MeshGenerationSupport>,
}

#[cfg(feature = "mesh")]
struct OptionalMeshStartInput<'a> {
    state: &'a UnifiedServerWorkerState,
    mesh_status: Arc<tokio::sync::RwLock<crate::worker::mesh_supervision::WorkerMeshStatus>>,
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    support_tasks: Option<super::MeshSupportTasks>,
}

#[cfg(feature = "mesh")]
struct OptionalMeshStartOutput {
    startup_failure: Option<crate::worker::task_registry::WorkerShutdownCause>,
    active_mesh_support: Option<MeshGenerationSupport>,
}

// ── Phase 1: Pipeline creation ─────────────────────────────────────────────

#[cfg(feature = "mesh")]
async fn create_mesh_pipeline(
    input: &WorkerMeshAttachmentInput<'_>,
) -> Result<MeshPipelineRuntime, BoxError> {
    let mesh_transport = input
        .mesh_transport
        .clone()
        .expect("mesh transport verified above");

    let mesh_status = input.state.mesh_status.clone();

    let (event_tx, coordinator, decision_rx) =
        crate::worker::mesh_supervision::create_supervision_pipeline(
            mesh_status.clone(),
            input
                .state
                .mesh_policy
                .clone()
                .expect("mesh policy present when transport exists"),
        );

    {
        let shutdown_rx = input.state.task_registry.lock().await.child_token();
        let mut registry = input.state.task_registry.lock().await;
        let mut coord = coordinator;
        registry.spawn_critical("mesh_supervision_coordinator", async move {
            coord.run(shutdown_rx).await;
        });
        tracing::info!("Mesh supervision coordinator started (critical)");
    }

    {
        let exits = mesh_transport.subscribe_exits();
        let shutdown_rx = input.state.task_registry.lock().await.child_token();
        let status = mesh_status.clone();
        let mut registry = input.state.task_registry.lock().await;
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

    Ok(MeshPipelineRuntime {
        mesh_transport,
        event_tx,
        decision_rx,
    })
}

// ── Phase 2: Ready sending helper ──────────────────────────────────────────

#[cfg(feature = "mesh")]
async fn send_ready_if_deferred(
    state: &UnifiedServerWorkerState,
    worker_id: synvoid_ipc::WorkerId,
    readiness: &WorkerReadinessPlan,
) -> Result<(), BoxError> {
    if let WorkerReadinessPlan::DeferUntilRequiredMeshReady = readiness {
        let mut ipc_guard = state.ipc.lock().await;
        ipc_guard
            .send(&crate::process::Message::UnifiedServerWorkerReady { id: worker_id })
            .await?;
        tracing::info!("Unified Server Worker {} ready (mesh started)", worker_id);
    }
    Ok(())
}

// ── Phase 3: Required mesh startup ─────────────────────────────────────────

#[cfg(feature = "mesh")]
async fn start_required_mesh(
    input: RequiredMeshStartInput<'_>,
) -> Result<RequiredMeshStartOutput, BoxError> {
    let mesh_status = input.mesh_status.clone();

    {
        let mut s = mesh_status.write().await;
        s.transition_starting();
    }

    match crate::worker::mesh_supervision::start_mesh_generation(&input.mesh_transport, 0).await {
        Ok(()) => {
            if let Some(support) = input.support_tasks {
                match super::register_mesh_generation_support(input.state, support, 1).await {
                    Ok(bundle) => {
                        {
                            let mut s = mesh_status.write().await;
                            s.transition_running();
                        }
                        send_ready_if_deferred(input.state, input.worker_id, input.readiness)
                            .await?;
                        Ok(RequiredMeshStartOutput {
                            startup_failure: None,
                            active_mesh_support: Some(bundle),
                        })
                    }
                    Err(cause) => {
                        tracing::error!("Failed to register mesh support: {}", cause);
                        let msg = format!("support registration failed: {}", cause);
                        {
                            let mut s = mesh_status.write().await;
                            s.transition_failed(msg.clone());
                        }
                        Ok(RequiredMeshStartOutput {
                            startup_failure: Some(
                                crate::worker::mesh_supervision::mesh_failure_to_worker_cause(
                                    crate::worker::mesh_supervision::MeshFailureCause::StartupFailed(
                                        msg,
                                    ),
                                ),
                            ),
                            active_mesh_support: None,
                        })
                    }
                }
            } else {
                {
                    let mut s = mesh_status.write().await;
                    s.transition_running();
                }
                send_ready_if_deferred(input.state, input.worker_id, input.readiness).await?;
                Ok(RequiredMeshStartOutput {
                    startup_failure: None,
                    active_mesh_support: None,
                })
            }
        }
        Err(cause) => {
            {
                let mut s = mesh_status.write().await;
                s.transition_failed(format!("startup failed: {}", cause.exit_reason()));
            }
            tracing::error!("Required mesh startup failed: {}", cause.exit_reason());
            Ok(RequiredMeshStartOutput {
                startup_failure: Some(
                    crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),
                ),
                active_mesh_support: None,
            })
        }
    }
}

// ── Phase 4: Optional support registration spawning ────────────────────────

#[cfg(feature = "mesh")]
fn spawn_optional_support_registration(
    state: &UnifiedServerWorkerState,
    support_tasks: Option<super::MeshSupportTasks>,
    registry: &mut crate::worker::task_registry::WorkerTaskRegistry,
) -> tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, String>> {
    let (helper_tx, helper_rx) = tokio::sync::oneshot::channel();
    let state_for_startup = state.clone();
    registry.spawn_one_shot("mesh_support_registration", async move {
        let result = if let Some(support) = support_tasks {
            super::register_mesh_generation_support(&state_for_startup, support, 1)
                .await
                .map(Some)
                .map_err(|e| format!("{}", e))
        } else {
            Ok(None)
        };
        let _ = helper_tx.send(result);
    });
    helper_rx
}

// ── Phase 5: Optional mesh startup task spawning ───────────────────────────

#[cfg(feature = "mesh")]
fn spawn_optional_mesh_startup(
    registry: &mut crate::worker::task_registry::WorkerTaskRegistry,
    mesh_transport: Arc<synvoid_mesh::MeshTransport>,
    event_tx: tokio::sync::mpsc::Sender<crate::worker::mesh_supervision::MeshSupervisionEvent>,
    support_rx: tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, String>>,
    startup_complete_tx: tokio::sync::oneshot::Sender<
        Result<Option<MeshGenerationSupport>, String>,
    >,
) {
    registry.spawn_one_shot("mesh_startup", async move {
        let result = mesh_transport
            .start_with_policy(synvoid_mesh::lifecycle::MeshStartupPolicy::default())
            .await;
        match result {
            Ok(report) => {
                tracing::info!(?report, "Mesh transport started");
                let bundle = match support_rx.await {
                    Ok(Ok(b)) => b,
                    Ok(Err(e)) => {
                        tracing::error!("Optional mesh support registration failed: {}", e);
                        None
                    }
                    Err(_) => {
                        tracing::error!("Helper task dropped without sending result");
                        None
                    }
                };
                let _ = startup_complete_tx.send(Ok(bundle));
                let _ = event_tx
                    .send(crate::worker::mesh_supervision::MeshSupervisionEvent::Started)
                    .await;
            }
            Err(e) => {
                tracing::error!("Mesh startup failed: {}", e);
                let _ = startup_complete_tx.send(Err(e.to_string()));
                let _ = event_tx
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

// ── Phase 6: Optional startup race loop ────────────────────────────────────

#[cfg(feature = "mesh")]
async fn await_optional_mesh_startup(
    state: &UnifiedServerWorkerState,
    mesh_status: &Arc<tokio::sync::RwLock<crate::worker::mesh_supervision::WorkerMeshStatus>>,
    mut optional_startup_rx: tokio::sync::oneshot::Receiver<
        Result<Option<MeshGenerationSupport>, String>,
    >,
    mut decision_rx: tokio::sync::mpsc::Receiver<
        crate::worker::mesh_supervision::MeshSupervisorDecision,
    >,
) -> (
    OptionalMeshStartOutput,
    tokio::sync::mpsc::Receiver<crate::worker::mesh_supervision::MeshSupervisorDecision>,
) {
    let mut pending_optional_failure = false;
    let mut active_mesh_support: Option<MeshGenerationSupport> = None;
    let mut startup_failure: Option<crate::worker::task_registry::WorkerShutdownCause> = None;

    loop {
        let mut mesh_decision_future = async { decision_rx.recv().await };

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
                        startup_failure = Some(
                            crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),
                        );
                        break;
                    }
                    Some(crate::worker::mesh_supervision::MeshSupervisorDecision::RestartMesh) => {
                        tracing::error!("Invariant violation: RestartMesh during startup");
                        startup_failure = Some(
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

    (
        OptionalMeshStartOutput {
            startup_failure,
            active_mesh_support,
        },
        decision_rx,
    )
}

// ── Public entry point ─────────────────────────────────────────────────────

#[cfg(feature = "mesh")]
pub async fn attach_mesh(
    input: WorkerMeshAttachmentInput<'_>,
) -> Result<Option<MeshStartupState>, BoxError> {
    if !input.has_mesh_transport {
        tracing::info!("Mesh disabled — no supervision pipeline created");
        return Ok(None);
    }

    let MeshPipelineRuntime {
        mesh_transport,
        event_tx,
        decision_rx,
    } = create_mesh_pipeline(&input).await?;

    let mesh_status = input.state.mesh_status.clone();

    let (startup_failure, active_mesh_support, decision_rx) =
        if input.state.mesh_policy.as_ref().is_some_and(|p| p.required) {
            let output = start_required_mesh(RequiredMeshStartInput {
                worker_id: input.worker_id,
                state: input.state,
                readiness: input.readiness,
                mesh_status: mesh_status.clone(),
                mesh_transport,
                support_tasks: input.support_tasks,
            })
            .await?;
            (
                output.startup_failure,
                output.active_mesh_support,
                decision_rx,
            )
        } else {
            {
                let mut s = mesh_status.write().await;
                s.transition_starting();
            }

            let mut registry = input.state.task_registry.lock().await;
            let support_rx = spawn_optional_support_registration(
                input.state,
                input.support_tasks,
                &mut registry,
            );

            let (startup_complete_tx, startup_complete_rx) = tokio::sync::oneshot::channel();
            spawn_optional_mesh_startup(
                &mut registry,
                mesh_transport,
                event_tx,
                support_rx,
                startup_complete_tx,
            );
            drop(registry);

            let (output, decision_rx) = await_optional_mesh_startup(
                input.state,
                &mesh_status,
                startup_complete_rx,
                decision_rx,
            )
            .await;
            (
                output.startup_failure,
                output.active_mesh_support,
                decision_rx,
            )
        };

    Ok(Some(MeshStartupState {
        policy: input
            .state
            .mesh_policy
            .clone()
            .expect("mesh policy present"),
        decision_rx,
        startup_failure,
        active_mesh_support,
    }))
}

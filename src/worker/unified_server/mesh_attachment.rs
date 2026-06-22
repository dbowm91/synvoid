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

#[cfg(feature = "mesh")]
pub async fn attach_mesh(
    input: WorkerMeshAttachmentInput<'_>,
) -> Result<Option<MeshStartupState>, BoxError> {
    if !input.has_mesh_transport {
        tracing::info!("Mesh disabled — no supervision pipeline created");
        return Ok(None);
    }

    let mesh_transport = input
        .mesh_transport
        .clone()
        .expect("mesh transport verified above");

    let mesh_status = input.state.mesh_status.clone();

    let (event_tx, coordinator, mut decision_rx) =
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

    let mut mesh_generation_counter: u64 = 0;
    let mut active_mesh_support: Option<MeshGenerationSupport> = None;
    let mut required_mesh_startup_failure: Option<
        crate::worker::task_registry::WorkerShutdownCause,
    > = None;

    let (optional_startup_tx, mut optional_startup_rx): (
        tokio::sync::oneshot::Sender<Result<Option<MeshGenerationSupport>, String>>,
        tokio::sync::oneshot::Receiver<Result<Option<MeshGenerationSupport>, String>>,
    ) = tokio::sync::oneshot::channel();

    let mut support_tasks = input.support_tasks;

    if input.state.mesh_policy.as_ref().is_some_and(|p| p.required) {
        {
            let mut s = mesh_status.write().await;
            s.transition_starting();
        }
        match crate::worker::mesh_supervision::start_mesh_generation(&mesh_transport, 0).await {
            Ok(()) => {
                mesh_generation_counter += 1;
                if let Some(support) = support_tasks.take() {
                    match super::register_mesh_generation_support(
                        input.state,
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
                                &input.readiness
                            {
                                let mut ipc_guard = input.state.ipc.lock().await;
                                ipc_guard
                                    .send(&crate::process::Message::UnifiedServerWorkerReady {
                                        id: input.worker_id,
                                    })
                                    .await?;
                                tracing::info!(
                                    "Unified Server Worker {} ready (mesh started)",
                                    input.worker_id
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
                    if let WorkerReadinessPlan::DeferUntilRequiredMeshReady = &input.readiness {
                        let mut ipc_guard = input.state.ipc.lock().await;
                        ipc_guard
                            .send(&crate::process::Message::UnifiedServerWorkerReady {
                                id: input.worker_id,
                            })
                            .await?;
                        tracing::info!(
                            "Unified Server Worker {} ready (mesh started)",
                            input.worker_id
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
                required_mesh_startup_failure =
                    Some(crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause));
            }
        }
    } else {
        {
            let mut s = mesh_status.write().await;
            s.transition_starting();
        }
        let event_tx_for_start = event_tx.clone();
        let startup_complete_tx = optional_startup_tx;
        let state_for_startup = input.state.clone();

        let (helper_tx, helper_rx) = tokio::sync::oneshot::channel();
        let support_for_helper = support_tasks.take();
        let mut registry = input.state.task_registry.lock().await;
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
                            tracing::error!("Optional mesh support registration failed: {}", e);
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

    let mut pending_optional_failure = false;
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
                                    &input.state.task_registry,
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

    Ok(Some(MeshStartupState {
        policy: input
            .state
            .mesh_policy
            .clone()
            .expect("mesh policy present"),
        decision_rx,
        startup_failure: required_mesh_startup_failure,
        active_mesh_support,
    }))
}

// Ordered shutdown executor for the unified worker.
//
// Executes the composition-root shutdown procedure after the supervision
// loop exits. Extracted from run_unified_server_worker() in Iteration 93.

use std::sync::Arc;

use tokio::sync::Mutex as TokioMutex;

use crate::worker::task_registry::WorkerShutdownCause;
use crate::worker::unified_server::state::UnifiedServerWorkerState;
use crate::worker::unified_server::supervisor_notify;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Report from the shutdown executor.
pub struct WorkerShutdownReport {
    pub final_cause: WorkerShutdownCause,
    pub exit_code: i32,
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

/// Execute the ordered shutdown procedure.
///
/// Shutdown order (preserved exactly from the original inline implementation):
/// 1. Record coordinated shutdown intent + lifecycle ack
/// 2. Stop accepting new connections
/// 3. Graceful drain (if requested and nonzero timeout)
/// 4. Stop app servers (Granian supervisors)
/// 4.5. Shutdown mesh transport (if running)
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
        active_mesh_support: _,
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

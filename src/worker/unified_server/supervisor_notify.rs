// Supervisor shutdown notification mapping.
//
// Maps WorkerShutdownCause to supervisor IPC messages and exit codes.
// Extracted from run_unified_server_worker() in Iteration 93.

use synvoid_ipc::WorkerId;

use crate::worker::task_registry::WorkerShutdownCause;

/// Map a `WorkerShutdownCause` to the appropriate supervisor IPC message.
pub async fn notify_supervisor_of_shutdown(
    ipc: &tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>,
    worker_id: WorkerId,
    cause: &WorkerShutdownCause,
) {
    match cause {
        WorkerShutdownCause::SupervisorShutdown => {
            send_to_supervisor(
                ipc,
                crate::process::Message::UnifiedServerWorkerShutdownComplete { id: worker_id },
                "shutdown complete",
            )
            .await;
        }
        WorkerShutdownCause::WorkerResize { worker_threads } => {
            send_to_supervisor(
                ipc,
                crate::process::Message::UnifiedServerWorkerResizeAck {
                    id: worker_id,
                    worker_threads: *worker_threads as u32,
                },
                "resize ack",
            )
            .await;
        }
        WorkerShutdownCause::CriticalTaskExit(exit) => {
            send_worker_error(
                ipc,
                worker_id,
                format!("Critical task '{}' exited: {}", exit.name, exit.reason),
                crate::process::ErrorCode::WorkerPanic,
            )
            .await;
        }
        WorkerShutdownCause::ServerExitedUnexpectedly(ref exit) => {
            send_worker_error(
                ipc,
                worker_id,
                format!(
                    "Server task '{}' exited unexpectedly: {}",
                    exit.name, exit.reason
                ),
                crate::process::ErrorCode::Unknown,
            )
            .await;
        }
        WorkerShutdownCause::RegistryExitChannelClosed => {
            send_worker_error(
                ipc,
                worker_id,
                "Registry exit channel closed — lifecycle infrastructure failure".to_string(),
                crate::process::ErrorCode::Unknown,
            )
            .await;
        }
        #[cfg(feature = "mesh")]
        WorkerShutdownCause::MeshStartupFailed(ref reason) => {
            send_worker_error(
                ipc,
                worker_id,
                format!("Mesh startup failed: {}", reason),
                crate::process::ErrorCode::Unknown,
            )
            .await;
        }
        #[cfg(feature = "mesh")]
        WorkerShutdownCause::MeshShutdownIncomplete(ref reason) => {
            send_worker_error(
                ipc,
                worker_id,
                format!("Mesh shutdown incomplete: {}", reason),
                crate::process::ErrorCode::Unknown,
            )
            .await;
        }
        #[cfg(feature = "mesh")]
        WorkerShutdownCause::MeshServiceExit(ref exit) => {
            send_worker_error(
                ipc,
                worker_id,
                format!("Mesh service '{}' exited: {}", exit.name, exit.reason),
                crate::process::ErrorCode::Unknown,
            )
            .await;
        }
        #[cfg(feature = "mesh")]
        WorkerShutdownCause::MeshRestartExhausted {
            attempts,
            ref last_error,
        } => {
            send_worker_error(
                ipc,
                worker_id,
                format!(
                    "Mesh restart exhausted after {} attempts: {}",
                    attempts, last_error
                ),
                crate::process::ErrorCode::Unknown,
            )
            .await;
        }
        // SupervisorDisconnected, ExternalStop, RunningFlagCleared, ServerStoppedForShutdown
        // -> no supervisor notification needed.
        _ => {}
    }
}

async fn send_to_supervisor(
    ipc: &tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>,
    msg: crate::process::Message,
    context: &str,
) {
    let mut ipc_guard = ipc.lock().await;
    if let Err(e) = ipc_guard.send(&msg).await {
        tracing::warn!(
            context = context,
            error = %e,
            "Failed to send supervisor notification; supervisor may misinterpret shutdown outcome"
        );
    }
}

async fn send_worker_error(
    ipc: &tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>,
    worker_id: WorkerId,
    error: String,
    error_code: crate::process::ErrorCode,
) {
    send_to_supervisor(
        ipc,
        crate::process::Message::WorkerError {
            id: worker_id,
            error,
            severity: crate::process::ErrorSeverity::Critical,
            error_code,
        },
        "worker error report",
    )
    .await;
}

/// Derive the process exit code from the authoritative shutdown cause.
pub fn exit_code_for_shutdown_cause(cause: &WorkerShutdownCause) -> i32 {
    cause.exit_code()
}

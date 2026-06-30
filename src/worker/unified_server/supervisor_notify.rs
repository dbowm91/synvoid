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
            let mut ipc_guard = ipc.lock().await;
            let _ = ipc_guard
                .send(
                    &crate::process::Message::UnifiedServerWorkerShutdownComplete { id: worker_id },
                )
                .await;
        }
        WorkerShutdownCause::WorkerResize { worker_threads } => {
            let mut ipc_guard = ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::UnifiedServerWorkerResizeAck {
                    id: worker_id,
                    worker_threads: *worker_threads as u32,
                })
                .await;
        }
        WorkerShutdownCause::CriticalTaskExit(exit) => {
            let mut ipc_guard = ipc.lock().await;
            let _ = ipc_guard
                .send(&crate::process::Message::WorkerError {
                    id: worker_id,
                    error: format!("Critical task '{}' exited: {}", exit.name, exit.reason),
                    severity: crate::process::ErrorSeverity::Critical,
                    error_code: crate::process::ErrorCode::WorkerPanic,
                })
                .await;
        }
        WorkerShutdownCause::ServerExitedUnexpectedly(ref exit) => {
            let mut ipc_guard = ipc.lock().await;
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
        WorkerShutdownCause::RegistryExitChannelClosed => {
            let mut ipc_guard = ipc.lock().await;
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
        WorkerShutdownCause::MeshStartupFailed(ref reason) => {
            let mut ipc_guard = ipc.lock().await;
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
        WorkerShutdownCause::MeshShutdownIncomplete(ref reason) => {
            let mut ipc_guard = ipc.lock().await;
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
        WorkerShutdownCause::MeshServiceExit(ref exit) => {
            let mut ipc_guard = ipc.lock().await;
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
        WorkerShutdownCause::MeshRestartExhausted {
            attempts,
            ref last_error,
        } => {
            let mut ipc_guard = ipc.lock().await;
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
}

/// Derive the process exit code from the authoritative shutdown cause.
pub fn exit_code_for_shutdown_cause(cause: &WorkerShutdownCause) -> i32 {
    cause.exit_code()
}

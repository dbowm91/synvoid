// Submodule: CPU worker IPC connection handler (sync, cross-platform).

use std::collections::HashSet;
use std::time::Duration;

use crate::process::{IpcStream, Message};

use super::dispatch::process_cpu_task_request_sync;
use super::payload::deadline_timeout_error;
use super::state::StaticWorkerState;

/// Handle a CPU worker IPC connection (cross-platform).
///
/// Uses the sync `IpcStream` abstraction for framed message I/O on both
/// Unix (UnixStream) and Windows (named pipe as File).
pub fn handle_minify_client_connection(mut ipc: IpcStream, state: StaticWorkerState) {
    let mut cancelled_requests = HashSet::new();
    loop {
        match ipc.try_recv() {
            Ok(Some(message)) => {
                if let Message::CpuTaskCancel {
                    request_id,
                    task_kind,
                } = message
                {
                    cancelled_requests.insert((request_id, task_kind));
                    continue;
                }
                if let Some((
                    request_id,
                    task_kind,
                    _priority,
                    policy,
                    deadline_unix_ms,
                    payload_size_limit,
                    output_size_limit,
                    file_payload_path,
                    payload,
                    is_legacy_shape,
                )) = message.into_cpu_task_request_compat()
                {
                    if cancelled_requests.remove(&(request_id, task_kind)) {
                        let response = deadline_timeout_error(
                            request_id,
                            task_kind,
                            "CPU task cancelled by client".to_string(),
                        );
                        let response = Message::adapt_cpu_task_response_compat(
                            response,
                            request_id,
                            task_kind,
                            is_legacy_shape,
                        );
                        if let Err(e) = ipc.send(&response) {
                            tracing::warn!(
                                "Failed to send CPU worker cancellation response for request {}: {}",
                                request_id,
                                e
                            );
                        }
                        continue;
                    }
                    let response = process_cpu_task_request_sync(
                        &state,
                        request_id,
                        task_kind,
                        policy,
                        deadline_unix_ms,
                        payload_size_limit,
                        output_size_limit,
                        file_payload_path,
                        payload,
                    );
                    let response = Message::adapt_cpu_task_response_compat(
                        response,
                        request_id,
                        task_kind,
                        is_legacy_shape,
                    );
                    if let Err(e) = ipc.send(&response) {
                        tracing::warn!(
                            "Failed to send CPU worker response for request {}: {}",
                            request_id,
                            e
                        );
                    }
                }
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }

        if !state.running.is_running() {
            break;
        }
    }
}

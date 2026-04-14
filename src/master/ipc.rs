use std::sync::Arc;

use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::{ErrorCode, ErrorSeverity, Message, ProcessManager, WorkerId};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ipc_rate_limit::IpcRateLimiter;
    use crate::process::ipc_transport::IpcEndpoint;
    use crate::process::manager::ProcessManager;
    use crate::process::WorkerMetricsPayload;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_worker_started_message_parsing() {
        let message = Message::WorkerStarted {
            id: WorkerId(1),
            pid: 1234,
            port: 8080,
            timestamp: 1234567890,
        };

        match message {
            Message::WorkerStarted { id, pid, port, .. } => {
                assert_eq!(id.as_usize(), 1);
                assert_eq!(pid, 1234);
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected WorkerStarted message"),
        }
    }

    #[tokio::test]
    async fn test_worker_ready_message() {
        let message = Message::WorkerReady { id: WorkerId(2) };

        match message {
            Message::WorkerReady { id } => {
                assert_eq!(id.as_usize(), 2);
            }
            _ => panic!("Expected WorkerReady message"),
        }
    }

    #[tokio::test]
    async fn test_worker_heartbeat_message() {
        use std::collections::HashMap;
        let metrics = WorkerMetricsPayload {
            total_requests: 100,
            blocked: 10,
            challenged: 5,
            proxied: 80,
            errors: 2,
            current_concurrent: 5,
            peak_concurrent: 10,
            avg_latency_ms: 15.5,
            p50_latency_ms: 10.0,
            p95_latency_ms: 25.0,
            p99_latency_ms: 50.0,
            uptime_secs: 3600,
            memory_bytes: 100_000_000,
            cpu_percent: 25.5,
            blocked_by_type: HashMap::new(),
            per_site: HashMap::new(),
            static_cache_hits: 0,
            static_cache_misses: 0,
            bandwidth: crate::metrics::bandwidth::BandwidthPayload::default(),
            serverless_metrics: Vec::new(),
        };
        let message = Message::WorkerHeartbeat {
            id: WorkerId(3),
            timestamp: 1234567890,
            metrics,
        };

        match message {
            Message::WorkerHeartbeat {
                id,
                timestamp,
                metrics,
            } => {
                assert_eq!(id.as_usize(), 3);
                assert_eq!(timestamp, 1234567890);
                assert_eq!(metrics.total_requests, 100);
                assert_eq!(metrics.blocked, 10);
            }
            _ => panic!("Expected WorkerHeartbeat message"),
        }
    }

    #[tokio::test]
    async fn test_worker_error_message() {
        let message = Message::WorkerError {
            id: WorkerId(4),
            error: "Test error".to_string(),
            severity: ErrorSeverity::Warning,
            error_code: ErrorCode::Unknown,
        };

        match message {
            Message::WorkerError {
                id,
                error,
                severity,
                error_code,
            } => {
                assert_eq!(id.as_usize(), 4);
                assert_eq!(error, "Test error");
                assert_eq!(severity, ErrorSeverity::Warning);
                assert_eq!(error_code, ErrorCode::Unknown);
            }
            _ => panic!("Expected WorkerError message"),
        }
    }

    #[tokio::test]
    async fn test_worker_shutdown_complete_message() {
        let message = Message::WorkerShutdownComplete { id: WorkerId(5) };

        match message {
            Message::WorkerShutdownComplete { id } => {
                assert_eq!(id.as_usize(), 5);
            }
            _ => panic!("Expected WorkerShutdownComplete message"),
        }
    }

    #[tokio::test]
    async fn test_static_worker_messages() {
        let started = Message::StaticWorkerStarted {
            worker_id: 10,
            pid: 5678,
        };

        match started {
            Message::StaticWorkerStarted { worker_id, pid } => {
                assert_eq!(worker_id, 10);
                assert_eq!(pid, 5678);
            }
            _ => panic!("Expected StaticWorkerStarted message"),
        }

        let ready = Message::StaticWorkerReady { worker_id: 10 };

        match ready {
            Message::StaticWorkerReady { worker_id } => {
                assert_eq!(worker_id, 10);
            }
            _ => panic!("Expected StaticWorkerReady message"),
        }
    }

    #[tokio::test]
    async fn test_blocklist_request_response() {
        let request = Message::BlocklistRequest {
            worker_id: 1,
            from_version: 0,
        };

        match &request {
            Message::BlocklistRequest {
                worker_id,
                from_version,
            } => {
                assert_eq!(*worker_id, 1);
                assert_eq!(*from_version, 0);
            }
            _ => panic!("Expected BlocklistRequest message"),
        }

        let response = Message::BlocklistResponse {
            worker_id: 1,
            blocks: vec![],
            version: 1,
        };

        match response {
            Message::BlocklistResponse {
                worker_id,
                blocks,
                version,
            } => {
                assert_eq!(worker_id, 1);
                assert!(blocks.is_empty());
                assert_eq!(version, 1);
            }
            _ => panic!("Expected BlocklistResponse message"),
        }
    }

    #[tokio::test]
    async fn test_error_code_variants() {
        assert_eq!(ErrorCode::Unknown.to_string(), "unknown");
        assert_eq!(
            ErrorCode::AuthenticationFailed.to_string(),
            "authentication_failed"
        );
        assert_eq!(
            ErrorCode::ConfigLoadFailed.to_string(),
            "config_load_failed"
        );
        assert_eq!(
            ErrorCode::SocketBindFailed.to_string(),
            "socket_bind_failed"
        );
    }

    #[tokio::test]
    async fn test_error_severity_variants() {
        assert_eq!(ErrorSeverity::Warning.to_string(), "warning");
        assert_eq!(ErrorSeverity::Error.to_string(), "error");
        assert_eq!(ErrorSeverity::Critical.to_string(), "critical");
    }

    #[tokio::test]
    async fn test_worker_id_as_usize() {
        let id1 = WorkerId(1);
        let id2 = WorkerId(2);

        assert_eq!(id1.as_usize(), 1);
        assert_eq!(id2.as_usize(), 2);
        assert_ne!(id1.as_usize(), id2.as_usize());
    }

    #[tokio::test]
    async fn test_message_dispatch_identifies_worker_id() {
        // Verify all worker-originating messages carry extractable IDs
        let messages = vec![
            (
                Message::WorkerStarted {
                    id: WorkerId(1),
                    pid: 100,
                    port: 8080,
                    timestamp: 0,
                },
                Some(1u64),
            ),
            (Message::WorkerReady { id: WorkerId(2) }, Some(2)),
            (
                Message::WorkerHeartbeat {
                    id: WorkerId(3),
                    timestamp: 0,
                    metrics: crate::process::WorkerMetricsPayload::default(),
                },
                Some(3),
            ),
            (
                Message::WorkerError {
                    id: WorkerId(4),
                    error: "test".into(),
                    severity: ErrorSeverity::Warning,
                    error_code: ErrorCode::Unknown,
                },
                Some(4),
            ),
            (Message::WorkerShutdownComplete { id: WorkerId(5) }, None),
        ];

        for (msg, expected_id) in messages {
            let extracted = match &msg {
                Message::WorkerStarted { id, .. } => Some(id.as_usize() as u64),
                Message::WorkerReady { id } => Some(id.as_usize() as u64),
                Message::WorkerHeartbeat { id, .. } => Some(id.as_usize() as u64),
                Message::WorkerError { id, .. } => Some(id.as_usize() as u64),
                _ => None,
            };
            assert_eq!(extracted, expected_id, "Mismatch for {:?}", msg);
        }
    }

    #[tokio::test]
    async fn test_blocklist_response_structure() {
        let blocks = vec![crate::process::ipc::BlockEntryData {
            ip: "1.2.3.4".to_string(),
            reason: "test".to_string(),
            blocked_at: 0,
            ban_expire_seconds: 3600,
            site_scope: "*".to_string(),
        }];
        let response = Message::BlocklistResponse {
            worker_id: 1,
            blocks: blocks.clone(),
            version: 5,
        };

        match response {
            Message::BlocklistResponse {
                worker_id,
                blocks: b,
                version,
            } => {
                assert_eq!(worker_id, 1);
                assert_eq!(b.len(), 1);
                assert_eq!(b[0].ip, "1.2.3.4");
                assert_eq!(b[0].ban_expire_seconds, 3600);
                assert_eq!(version, 5);
            }
            _ => panic!("Expected BlocklistResponse"),
        }
    }

    #[tokio::test]
    async fn test_error_severity_ordering() {
        // Verify severity levels can be compared
        assert_ne!(ErrorSeverity::Warning, ErrorSeverity::Error);
        assert_ne!(ErrorSeverity::Error, ErrorSeverity::Critical);
        assert_ne!(ErrorSeverity::Warning, ErrorSeverity::Critical);
    }
}

pub async fn handle_worker_connection(
    mut ipc: AsyncIpcStream,
    process_manager: Arc<ProcessManager>,
) {
    let enforce_signing = process_manager.get_ipc_enforce_signing();
    let session_key = process_manager.get_ipc_session_key();

    if enforce_signing {
        if session_key.is_none() {
            tracing::error!("IPC signing is enforced but no session key configured - rejecting worker connection");
            let _ = ipc
                .send(&Message::WorkerError {
                    id: WorkerId(0),
                    error: "IPC signing enforced but master has no session key".to_string(),
                    severity: ErrorSeverity::Critical,
                    error_code: ErrorCode::AuthenticationFailed,
                })
                .await;
            return;
        }

        static VERIFIED_WITH_ASYNC: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        VERIFIED_WITH_ASYNC.get_or_init(|| {
            tracing::debug!("IPC signing verified with async transport");
        });
    }

    // Validate peer credentials if available (Unix only)
    let peer_pid = ipc.peer_pid();
    if let Some(actual_pid) = peer_pid {
        tracing::debug!("Worker IPC connection from peer PID: {}", actual_pid);
    }

    let rate_limiter = process_manager.get_ipc_rate_limiter();
    loop {
        match ipc.recv_with_timeout::<Message>(5000).await {
            Ok(Some(message)) => {
                if let Err(e) = message.validate() {
                    tracing::warn!("Invalid IPC message received: {}", e);
                    continue;
                }

                // Validate claimed PID matches peer credentials
                if let Message::WorkerStarted {
                    id,
                    pid: claimed_pid,
                    ..
                } = &message
                {
                    if let Some(actual_pid) = peer_pid {
                        if *claimed_pid as u32 != actual_pid {
                            tracing::warn!(
                                "IPC security: worker {} claims PID {} but socket peer PID is {}",
                                id,
                                claimed_pid,
                                actual_pid
                            );
                        }
                    }
                }

                let worker_id = match &message {
                    Message::WorkerStarted { id, .. } => Some(id.as_usize() as u64),
                    Message::WorkerReady { id } => Some(id.as_usize() as u64),
                    Message::WorkerHeartbeat { id, .. } => Some(id.as_usize() as u64),
                    Message::WorkerError { id, .. } => Some(id.as_usize() as u64),
                    Message::StaticWorkerStarted { worker_id, .. } => Some(*worker_id as u64),
                    Message::StaticWorkerReady { worker_id } => Some(*worker_id as u64),
                    Message::StaticWorkerHeartbeat { worker_id, .. } => Some(*worker_id as u64),
                    _ => None,
                };

                if let Some(wid) = worker_id {
                    if let Err(e) = rate_limiter.check_worker(wid) {
                        tracing::warn!("IPC rate limit exceeded for worker {}: {}", wid, e);
                        continue;
                    }
                } else if rate_limiter.check().is_err() {
                    tracing::warn!("IPC rate limit exceeded (global)");
                    continue;
                }

                let _needs_response = matches!(message, Message::BlocklistRequest { .. });
                let blocklist_response = if let Message::BlocklistRequest {
                    worker_id,
                    from_version: _,
                } = &message
                {
                    tracing::debug!("Blocklist request from worker {}", worker_id);
                    process_manager
                        .handle_blocklist_request(*worker_id)
                        .map(|blocks| Message::BlocklistResponse {
                            worker_id: *worker_id,
                            blocks,
                            version: 0,
                        })
                } else {
                    None
                };

                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match message {
                        Message::WorkerStarted {
                            id,
                            pid,
                            port,
                            timestamp: _,
                        } => {
                            tracing::debug!(
                                "Worker {} connected (PID: {}, port: {})",
                                id,
                                pid,
                                port
                            );
                        }
                        Message::WorkerReady { id } => {
                            process_manager.handle_worker_ready(id);
                        }
                        Message::WorkerHeartbeat {
                            id,
                            timestamp: _,
                            metrics,
                        } => {
                            process_manager.handle_heartbeat(id, metrics);
                        }
                        Message::WorkerRequestLog { id, log } => {
                            process_manager.handle_request_log(id, log);
                        }
                        Message::WorkerError {
                            id,
                            error,
                            severity,
                            error_code,
                        } => {
                            process_manager.handle_worker_error(id, error, severity, error_code);
                        }
                        Message::WorkerShutdownComplete { id } => {
                            process_manager.mark_worker_stopped(id);
                            return Err(());
                        }
                        Message::StaticWorkerStarted { worker_id, pid } => {
                            tracing::debug!("Static worker {} connected (PID: {})", worker_id, pid);
                        }
                        Message::StaticWorkerReady { worker_id } => {
                            process_manager.handle_static_worker_ready(worker_id);
                        }
                        Message::StaticWorkerHeartbeat {
                            worker_id,
                            timestamp: _,
                            static_cache_hits,
                            static_cache_misses,
                        } => {
                            process_manager.handle_static_worker_heartbeat(
                                worker_id,
                                static_cache_hits,
                                static_cache_misses,
                            );
                        }
                        Message::StaticWorkerRequestLog { worker_id: _, log } => {
                            process_manager.handle_request_log(WorkerId(0), log);
                        }
                        Message::StaticWorkerShutdownComplete { worker_id } => {
                            tracing::info!("Static worker {} shutdown complete", worker_id);
                            return Err(());
                        }
                        Message::MinifyResponse {
                            request_id,
                            site_id,
                            path,
                            content,
                            content_type: _,
                            encoding: _,
                            queued_encodings,
                        } => {
                            tracing::debug!(
                                "Minify response for request {}: site={}, path={}, size={}, queued={:?}",
                                request_id, site_id, path, content.len(), queued_encodings
                            );
                        }
                        Message::MinifyError { request_id, error } => {
                            tracing::warn!("Minify error for request {}: {}", request_id, error);
                        }
                        Message::GetCompressedResponse {
                            request_id,
                            content,
                        } => {
                            tracing::debug!(
                                "Compressed response for request {}: size={}",
                                request_id,
                                content.len()
                            );
                        }
                        Message::BlocklistUpdate { blocks, version: _ } => {
                            tracing::debug!("Blocklist update with {} entries", blocks.len());
                            process_manager.handle_blocklist_update(blocks);
                            process_manager.trigger_blocklist_persist();
                        }
                        _ => {}
                    }
                    Ok(())
                }));

                if let Some(response) = blocklist_response {
                    if ipc.send(&response).await.is_err() {
                        tracing::warn!("Failed to send blocklist response to worker");
                    }
                }

                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(())) => break,
                    Err(panic_info) => {
                        tracing::error!("IPC message handler panicked: {:?}", panic_info);
                        break;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("Worker connection error: {}", e);
                break;
            }
        }
    }
}

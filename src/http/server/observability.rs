//! Observability concern: request metrics collection and request log rate limiting.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use synvoid_config::MainConfig;
use synvoid_ipc::AsyncIpcStream as IpcStream;
use synvoid_ipc::WorkerId;
use synvoid_metrics::RequestLogPayload;
use synvoid_utils::current_timestamp;

static REQUEST_LOG_RATE_LIMITER: AtomicU32 = AtomicU32::new(0);
static REQUEST_LOG_RATE_LIMITER_RESET: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_request_log_if_enabled(
    ipc: Option<Arc<tokio::sync::Mutex<IpcStream>>>,
    worker_id: Option<WorkerId>,
    main_config: &Arc<MainConfig>,
    client_ip: IpAddr,
    method: &str,
    path: &str,
    status: u16,
    latency_ms: u64,
    site_id: &str,
    user_agent: Option<&str>,
    is_internal: bool,
) {
    let verbose_config = &main_config.logging.verbose_request_logging;
    if !verbose_config.enabled {
        return;
    }

    let should_log = if is_internal {
        verbose_config.log_internal
    } else {
        match status {
            0 => verbose_config.log_dropped,
            1..=399 => verbose_config.log_proxied,
            400..=599 => verbose_config.log_blocked,
            _ => false,
        }
    };

    if !should_log {
        return;
    }

    let max_per_second = verbose_config.max_logs_per_second;
    let now = synvoid_utils::safe_unix_timestamp();

    let last_reset = REQUEST_LOG_RATE_LIMITER_RESET.load(Ordering::Relaxed);
    if now != last_reset {
        // Only one thread should reset the counter per second.
        // compare_exchange ensures only the first caller resets.
        if REQUEST_LOG_RATE_LIMITER_RESET
            .compare_exchange(last_reset, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            REQUEST_LOG_RATE_LIMITER.store(0, Ordering::Relaxed);
        }
    }

    let current_count = REQUEST_LOG_RATE_LIMITER.fetch_add(1, Ordering::Relaxed);
    if current_count >= max_per_second {
        return;
    }

    if let (Some(ref ipc), Some(ref worker_id)) = (ipc, worker_id) {
        let log = RequestLogPayload {
            timestamp: current_timestamp(),
            client_ip: client_ip.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            status,
            response_time_ms: latency_ms as u32,
            site_id: site_id.to_string(),
            user_agent: user_agent.map(|s| s.to_string()),
            bytes_sent: 0,
            bytes_received: 0,
        };
        let ipc = ipc.clone();
        let worker_id = *worker_id;
        tokio::spawn(async move {
            let mut ipc_guard = ipc.lock().await;
            let msg = synvoid_ipc::Message::WorkerRequestLog { id: worker_id, log };
            if let Err(e) = ipc_guard.send(&msg).await {
                tracing::warn!("Failed to send request log: {}", e);
            }
        });
    }
}

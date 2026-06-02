use super::*;
use metrics::counter;
use std::sync::Arc;
use std::time::Instant;

pub(super) enum TrafficControlOutcome {
    Continue {
        conn_guard: Option<ConnectionTokenGuard>,
    },
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

pub(super) async fn maybe_enforce_request_traffic_limits(
    waf: &WafCore,
    client_ip: std::net::IpAddr,
    path: &str,
    start: Instant,
    ipc: &Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> TrafficControlOutcome {
    let connection_token = if let Some(ref conn_limiter) = waf.connection_limiter {
        match conn_limiter.try_acquire("_http_", client_ip).await {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                counter!("synvoid.traffic.connection_limited").increment(1);
                HttpServer::send_request_log_if_enabled(
                    ipc.clone(),
                    worker_id,
                    main_config,
                    client_ip,
                    "UNKNOWN",
                    path,
                    503,
                    start.elapsed().as_millis() as u64,
                    "internal",
                    None,
                    true,
                );
                return TrafficControlOutcome::Respond(
                    crate::http::response_builder::build_response_with_alt_svc(
                        503,
                        "Too Many Connections".to_string(),
                        "application/json",
                        alt_svc,
                        main_config,
                    ),
                );
            }
        }
    } else {
        None
    };

    let conn_guard =
        if let (Some(limiter), Some(token)) = (waf.connection_limiter.clone(), connection_token) {
            Some(ConnectionTokenGuard::new(limiter, token))
        } else {
            None
        };

    if waf.is_over_bandwidth_limit() {
        tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
        counter!("synvoid.bandwidth.limit_exceeded").increment(1);

        let path_owned = path.to_string();
        let start_elapsed = start.elapsed().as_millis() as u64;
        let client_ip_str = client_ip.to_string();

        if let (Some(ref ipc_ref), Some(worker_id_value)) = (ipc, worker_id) {
            let ipc_clone = ipc_ref.clone();
            tokio::spawn(async move {
                let log = crate::metrics::RequestLogPayload {
                    timestamp: current_timestamp(),
                    client_ip: client_ip_str,
                    method: "UNKNOWN".to_string(),
                    path: path_owned,
                    status: 503,
                    response_time_ms: start_elapsed as u32,
                    site_id: "internal".to_string(),
                    user_agent: None,
                    bytes_sent: 0,
                    bytes_received: 0,
                };
                let mut ipc_guard = ipc_clone.lock().await;
                let msg = crate::process::Message::WorkerRequestLog {
                    id: worker_id_value,
                    log,
                };
                if let Err(e) = ipc_guard.send(&msg).await {
                    tracing::warn!("Failed to send request log: {}", e);
                }
            });
        }

        return TrafficControlOutcome::Respond(
            crate::http::response_builder::build_response_with_alt_svc(
                503,
                "Monthly Bandwidth Limit Exceeded".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            ),
        );
    }

    TrafficControlOutcome::Continue { conn_guard }
}

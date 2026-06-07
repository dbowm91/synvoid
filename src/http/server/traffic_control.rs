use super::*;

pub(super) use synvoid_http::TrafficControlOutcome;

#[allow(clippy::too_many_arguments)]
pub(super) async fn maybe_enforce_request_traffic_limits(
    waf: &WafCore,
    client_ip: std::net::IpAddr,
    path: &str,
    start: std::time::Instant,
    ipc: &Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> TrafficControlOutcome {
    synvoid_http::maybe_enforce_request_traffic_limits(
        waf.connection_limiter.clone(),
        client_ip,
        path,
        start,
        waf.is_over_bandwidth_limit(),
        alt_svc,
        main_config,
        |status, latency_ms, site_id, method, path, user_agent, is_internal| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method,
                path,
                status,
                latency_ms,
                site_id,
                user_agent,
                is_internal,
            );
        },
    )
    .await
}

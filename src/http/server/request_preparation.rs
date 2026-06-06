use super::*;

pub(super) use synvoid_http::{
    PreparedRequest, RequestPreflight, RequestPreflightOutcome, RequestPreparationOutcome,
};

pub(super) struct RequestPreparationContext<'a> {
    pub req: hyper::Request<hyper::body::Incoming>,
    pub client_ip: IpAddr,
    pub local_addr: Option<SocketAddr>,
    pub router: &'a Arc<Router>,
    pub waf: &'a Arc<WafCore>,
    pub alt_svc: &'a Option<String>,
    pub main_config: &'a Arc<MainConfig>,
    pub http_config: &'a HttpConfig,
    pub metrics: &'a Option<Arc<WorkerMetrics>>,
    pub http_conn: &'a HttpConnection,
    pub ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    pub worker_id: Option<crate::process::ipc::WorkerId>,
    pub start: std::time::Instant,
    pub upstream_client_registry: &'a Arc<UpstreamClientRegistry>,
    #[cfg(feature = "mesh")]
    pub serverless_manager: &'a Option<Arc<crate::serverless::manager::ServerlessManager>>,
    pub conn_guard: Option<&'a ConnectionTokenGuard>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_request_before_buffered_waf(
    ctx: RequestPreparationContext<'_>,
) -> Result<RequestPreparationOutcome, hyper::Error> {
    let RequestPreparationContext {
        req,
        client_ip,
        local_addr,
        router,
        waf,
        alt_svc,
        main_config,
        http_config,
        metrics,
        http_conn,
        ipc,
        worker_id,
        start,
        upstream_client_registry,
        #[cfg(feature = "mesh")]
        serverless_manager,
        conn_guard,
    } = ctx;

    let waf_ref = waf.as_ref();
    let preflight = match synvoid_http::prepare_request_preflight(
        req,
        client_ip,
        local_addr,
        router,
        waf_ref,
        alt_svc,
        main_config,
        |status, site_id, bypassed, method, path, user_agent| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method,
                path,
                status,
                start.elapsed().as_millis() as u64,
                site_id,
                user_agent,
                bypassed,
            );
        },
        |status, message| {
            waf_ref
                .error_page_manager
                .render_page_with_theme(status, Some(message), None)
        },
        || {
            http_conn.request_drop();
        },
    )
    .await?
    {
        RequestPreflightOutcome::Continue(preflight) => preflight,
        RequestPreflightOutcome::Respond(response) => {
            return Ok(RequestPreparationOutcome::Respond(response));
        }
    };

    let RequestPreflight {
        on_upgrade,
        target,
        parts,
        body,
        method,
        path,
        host,
        user_agent,
        skip_waf,
    } = preflight;

    let site_id = target.site_id.to_string();
    let site_traffic_config = &target.site_config.traffic_shaping.connection;
    let site_max_connections = site_traffic_config.max_connections;
    let site_max_per_ip = site_traffic_config.max_connections_per_ip;
    if site_max_connections.is_some() || site_max_per_ip.is_some() {
        if let Some(ref conn_limiter) = waf.connection_limiter {
            match conn_limiter
                .try_acquire_with_limits(&site_id, client_ip, site_max_connections, site_max_per_ip)
                .await
            {
                Ok(new_token) => {
                    if let Some(ref guard) = conn_guard {
                        guard.release_and_acquire(new_token);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Per-site connection limit exceeded for site {}: {}",
                        site_id,
                        e
                    );
                    counter!("synvoid.traffic.connection_limited").increment(1);
                    send_request_log_if_enabled(
                        ipc.clone(),
                        worker_id,
                        main_config,
                        client_ip,
                        method.as_str(),
                        &path,
                        503,
                        start.elapsed().as_millis() as u64,
                        &site_id,
                        user_agent.as_deref(),
                        true,
                    );
                    return Ok(RequestPreparationOutcome::Respond(
                        crate::http::response_builder::build_response_with_alt_svc(
                            503,
                            "Too Many Connections".to_string(),
                            "application/json",
                            alt_svc,
                            main_config,
                        ),
                    ));
                }
            }
        }
    }

    let query_string = parts.uri.query();
    let body = match maybe_handle_streaming_request_fast_path(
        &target,
        router,
        waf,
        skip_waf,
        &site_id,
        client_ip,
        &method,
        &path,
        query_string,
        &parts,
        user_agent.as_deref(),
        body,
        alt_svc,
        main_config,
        upstream_client_registry,
        #[cfg(feature = "mesh")]
        serverless_manager,
        |status| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                status,
                start.elapsed().as_millis() as u64,
                &site_id,
                user_agent.as_deref(),
                false,
            );
        },
        |decision| async {
            maybe_handle_streaming_waf_decision(
                decision,
                || http_conn.request_drop(),
                |status, message| {
                    waf.error_page_manager.render_page_with_theme(
                        status,
                        Some(message),
                        target
                            .site_config
                            .error_pages
                            .theme
                            .as_ref()
                            .map(|theme_config| {
                                theme_config.to_theme_config(waf.error_page_manager.theme())
                            })
                            .as_ref(),
                    )
                },
                |path, user_agent| Box::pin(waf.stream_tarpit(path, user_agent)),
                http_config,
                user_agent.as_deref(),
                alt_svc,
                main_config,
            )
            .await
        },
    )
    .await?
    {
        StreamingRequestFastPathOutcome::Continue(body) => body,
        StreamingRequestFastPathOutcome::Respond(response) => {
            return Ok(RequestPreparationOutcome::Respond(response));
        }
    };

    let method_for_log = method.clone();
    let path_for_log = path.clone();
    let user_agent_for_log = user_agent.clone();

    synvoid_http::finalize_request_preparation(
        on_upgrade,
        target,
        parts,
        method,
        path,
        user_agent,
        skip_waf,
        body,
        client_ip,
        host,
        waf.as_ref(),
        waf.honeypot_ban_duration_secs,
        main_config,
        http_config,
        metrics,
        alt_svc,
        |status, bypassed| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method_for_log.as_str(),
                &path_for_log,
                status,
                start.elapsed().as_millis() as u64,
                "internal",
                user_agent_for_log.as_deref(),
                bypassed,
            );
        },
    )
    .await
}

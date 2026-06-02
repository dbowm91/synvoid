use super::*;

pub(super) struct PreparedRequest {
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    pub target: crate::router::RouteTarget,
    pub parts: http::request::Parts,
    pub method: http::Method,
    pub path: String,
    pub user_agent: Option<String>,
    pub skip_waf: bool,
    pub full_body_arc: Arc<Bytes>,
    pub request_body_size: u64,
    pub body_slice: Option<Arc<Bytes>>,
}

pub(super) enum RequestPreparationOutcome {
    Continue(PreparedRequest),
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

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

    let mut req = req;
    let is_ws_upgrade = validate_websocket_upgrade(req.headers());
    let on_upgrade = if is_ws_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let (parts, body) = req.into_parts();
    let (method, path, host, user_agent, cookies) = extract_request_metadata(&parts);
    let skip_waf = should_skip_waf_from_trust_cookie(waf, client_ip, cookies.as_deref());
    if skip_waf {
        tracing::debug!(
            "Bypassing WAF check due to valid trust token for {}",
            client_ip
        );
    }

    let early_decision = early_waf_decision(waf, client_ip, &path, cookies.as_deref(), skip_waf);

    match early_decision {
        crate::proxy::WafDecision::Drop => {
            counter!("synvoid.http.early_drop").increment(1);
            http_conn.request_drop();
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                0,
                start.elapsed().as_millis() as u64,
                "unknown",
                user_agent.as_deref(),
                false,
            );
            let resp = Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(&[])).boxed())
                .unwrap_or_else(|_| crate::http::fallback_error_boxed());
            return Ok(RequestPreparationOutcome::Respond(resp));
        }
        crate::proxy::WafDecision::ChallengeWithCookie {
            challenge_type: _,
            html,
            session_cookie_name,
            session_cookie_value,
            session_cookie_max_age,
        } => {
            let cookie = format_secure_http_only_cookie(
                &session_cookie_name,
                &session_cookie_value,
                session_cookie_max_age as u64,
            );
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                200,
                start.elapsed().as_millis() as u64,
                "unknown",
                user_agent.as_deref(),
                false,
            );
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                    alt_svc,
                    main_config,
                ),
            ));
        }
        crate::proxy::WafDecision::Challenge(_type, html) => {
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                200,
                start.elapsed().as_millis() as u64,
                "unknown",
                user_agent.as_deref(),
                false,
            );
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        crate::proxy::WafDecision::Block(status, message) => {
            let body = waf
                .error_page_manager
                .render_page_with_theme(status, Some(&message), None);
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                status,
                start.elapsed().as_millis() as u64,
                "unknown",
                user_agent.as_deref(),
                false,
            );
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    status,
                    body,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        crate::proxy::WafDecision::Pass
        | crate::proxy::WafDecision::Stall
        | crate::proxy::WafDecision::Tarpit(_) => {}
    }

    let route = router.route_with_local_addr(&host, &path, local_addr);
    let target = match route {
        crate::router::RouteResult::Found(target) => target,
        crate::router::RouteResult::NotFound(msg) => {
            tracing::debug!("Route not found: {} for host: {}", msg, host);
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                404,
                start.elapsed().as_millis() as u64,
                &host,
                user_agent.as_deref(),
                false,
            );
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    404,
                    "Not Found".to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        crate::router::RouteResult::Error(msg) => {
            tracing::error!("Router error: {}", msg);
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                500,
                start.elapsed().as_millis() as u64,
                &host,
                user_agent.as_deref(),
                false,
            );
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    500,
                    crate::http::reason_phrase(500).to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            ));
        }
    };

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
                    HttpServer::send_request_log_if_enabled(
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
    let _is_internal_orig = client_ip.is_loopback();
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
            HttpServer::send_request_log_if_enabled(
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
                waf,
                || http_conn.request_drop(),
                http_config,
                &target,
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

    let content_length: Option<usize> = parts
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    let (full_body, request_body_size) = match collect_and_scan_request_body(
        body,
        waf,
        client_ip,
        content_length,
        http_config.max_streaming_body_size,
    )
    .await
    {
        Ok((full_body, request_body_size)) => (full_body, request_body_size),
        Err(BodyPolicyError::BlockedByWaf) => {
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    403,
                    "Request blocked by WAF".to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        Err(BodyPolicyError::BodyTooLarge) => {
            return Ok(RequestPreparationOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    413,
                    "Request body too large".to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            ));
        }
    };
    let full_body_arc = Arc::new(full_body);
    let body_slice = if full_body_arc.is_empty() {
        None
    } else {
        Some(full_body_arc.clone())
    };

    if let Some(ref m) = metrics {
        if let Some(content_length) = parts.headers.get("content-length") {
            if let Ok(len_str) = content_length.to_str() {
                if let Ok(len) = len_str.parse::<u64>() {
                    m.bandwidth.record_ingress(len, BandwidthProtocol::Http);
                    m.bandwidth.record_site_ingress(&host, len);
                }
            }
        }
    }

    if let Some(response) = maybe_handle_challenge_paths(
        &path,
        client_ip,
        waf,
        &parts,
        main_config,
        alt_svc,
        |status, bypassed| {
            HttpServer::send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method.as_str(),
                &path,
                status,
                start.elapsed().as_millis() as u64,
                "internal",
                user_agent.as_deref(),
                bypassed,
            );
        },
    ) {
        return Ok(RequestPreparationOutcome::Respond(response));
    }

    Ok(RequestPreparationOutcome::Continue(PreparedRequest {
        on_upgrade,
        target,
        parts,
        method,
        path,
        user_agent,
        skip_waf,
        full_body_arc,
        request_body_size,
        body_slice,
    }))
}

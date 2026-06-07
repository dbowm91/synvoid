use async_trait::async_trait;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use metrics::counter;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::bandwidth::BandwidthProtocol;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::{RouteResult, RouteTarget, Router};
use synvoid_waf::ConnectionLimiter;

use crate::body_policy::RequestBodyWaf;
use crate::body_policy::{collect_and_scan_request_body, BodyPolicyError};
use crate::challenge_paths::maybe_handle_challenge_paths;
use crate::challenge_paths::ChallengePathWaf;
use crate::request_parse::{
    early_waf_decision, extract_request_metadata, should_skip_waf_from_trust_cookie,
};
use crate::response_builder::build_response_with_alt_svc;
use crate::response_helpers::format_secure_http_only_cookie;
use crate::streaming_request_fast_path::{
    maybe_handle_streaming_request_fast_path, StreamingRequestFastPathOutcome,
};
use crate::streaming_waf_decision::{maybe_handle_streaming_waf_decision, TarpitStream};
use crate::traffic_control::ConnectionTokenGuard;
use crate::validation_helpers::validate_websocket_upgrade;

pub struct RequestPreflight {
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    pub target: RouteTarget,
    pub parts: http::request::Parts,
    pub body: hyper::body::Incoming,
    pub method: http::Method,
    pub path: String,
    pub host: String,
    pub user_agent: Option<String>,
    pub skip_waf: bool,
}

pub enum RequestPreflightOutcome {
    Continue(RequestPreflight),
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_request_preflight<W, LogFn, DropFn>(
    req: hyper::Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    local_addr: Option<SocketAddr>,
    router: &Arc<Router>,
    waf: &W,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    mut on_log: LogFn,
    mut on_drop: DropFn,
) -> Result<RequestPreflightOutcome, hyper::Error>
where
    W: BufferedRequestWaf,
    LogFn: FnMut(u16, &str, bool, &str, &str, Option<&str>),
    DropFn: FnMut(),
{
    let mut req = req;
    let is_ws_upgrade = validate_websocket_upgrade(req.headers());
    let on_upgrade = if is_ws_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let (parts, body) = req.into_parts();
    let (method, path, host, user_agent, cookies) = extract_request_metadata(&parts);
    let cookies_ref = cookies.as_deref();
    let skip_waf = should_skip_waf_from_trust_cookie(waf, client_ip, cookies_ref);
    if skip_waf {
        tracing::debug!(
            "Bypassing WAF check due to valid trust token for {}",
            client_ip
        );
    }

    let early_decision = early_waf_decision(waf, client_ip, &path, cookies_ref, skip_waf);

    match early_decision {
        synvoid_proxy::WafDecision::Drop => {
            counter!("synvoid.http.early_drop").increment(1);
            on_drop();
            on_log(
                0,
                "unknown",
                false,
                method.as_str(),
                &path,
                user_agent.as_deref(),
            );
            let resp = Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(&[])).boxed())
                .unwrap_or_else(|_| crate::response_builder::fallback_error_boxed());
            return Ok(RequestPreflightOutcome::Respond(resp));
        }
        synvoid_proxy::WafDecision::ChallengeWithCookie {
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
            on_log(
                200,
                "unknown",
                false,
                method.as_str(),
                &path,
                user_agent.as_deref(),
            );
            return Ok(RequestPreflightOutcome::Respond(
                crate::response_builder::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                    alt_svc,
                    main_config,
                ),
            ));
        }
        synvoid_proxy::WafDecision::Challenge(_type, html) => {
            on_log(
                200,
                "unknown",
                false,
                method.as_str(),
                &path,
                user_agent.as_deref(),
            );
            return Ok(RequestPreflightOutcome::Respond(
                crate::response_builder::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        synvoid_proxy::WafDecision::Block(status, message) => {
            let body = waf.render_page_with_theme(status, Some(&message), None);
            on_log(
                status,
                "unknown",
                false,
                method.as_str(),
                &path,
                user_agent.as_deref(),
            );
            return Ok(RequestPreflightOutcome::Respond(
                crate::response_builder::build_response_with_alt_svc(
                    status,
                    body,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        synvoid_proxy::WafDecision::Pass
        | synvoid_proxy::WafDecision::Stall
        | synvoid_proxy::WafDecision::Tarpit(_) => {}
    }

    let route = router.route_with_local_addr(&host, &path, local_addr);
    let target = match route {
        RouteResult::Found(target) => target,
        RouteResult::NotFound(msg) => {
            tracing::debug!("Route not found: {} for host: {}", msg, host);
            on_log(
                404,
                &host,
                false,
                method.as_str(),
                &path,
                user_agent.as_deref(),
            );
            return Ok(RequestPreflightOutcome::Respond(
                crate::response_builder::build_response_with_alt_svc(
                    404,
                    "Not Found".to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            ));
        }
        RouteResult::Error(msg) => {
            tracing::error!("Router error: {}", msg);
            on_log(
                500,
                &host,
                false,
                method.as_str(),
                &path,
                user_agent.as_deref(),
            );
            return Ok(RequestPreflightOutcome::Respond(
                crate::response_builder::build_response_with_alt_svc(
                    500,
                    crate::response_builder::reason_phrase(500).to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            ));
        }
    };

    Ok(RequestPreflightOutcome::Continue(RequestPreflight {
        on_upgrade,
        target,
        parts,
        body,
        method,
        path,
        host,
        user_agent,
        skip_waf,
    }))
}

pub struct PreparedRequest {
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    pub target: RouteTarget,
    pub parts: http::request::Parts,
    pub method: http::Method,
    pub path: String,
    pub user_agent: Option<String>,
    pub skip_waf: bool,
    pub full_body_arc: Arc<Bytes>,
    pub request_body_size: u64,
    pub body_slice: Option<Arc<Bytes>>,
}

pub enum RequestPreparationOutcome {
    Continue(PreparedRequest),
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

#[async_trait]
pub trait BufferedRequestWaf:
    crate::EarlyWafHooks + RequestBodyWaf + ChallengePathWaf + Send + Sync
{
    fn error_page_theme(&self) -> &synvoid_config::theme::ThemeConfig;

    fn render_page_with_theme(
        &self,
        status: u16,
        message: Option<&str>,
        override_theme: Option<&synvoid_config::theme::ThemeConfig>,
    ) -> String;

    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>>;

    fn is_over_bandwidth_limit(&self) -> bool;

    fn honeypot_ban_duration_secs(&self) -> u64;

    fn stream_tarpit(&self, path: &str, user_agent: Option<&str>) -> TarpitStream;

    fn generate_tarpit_response(&self, path: &str) -> String;

    async fn check_request_full(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
        ua: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision;
}

#[allow(clippy::too_many_arguments)]
pub async fn finalize_request_preparation<W, LogFn>(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    target: RouteTarget,
    parts: http::request::Parts,
    method: http::Method,
    path: String,
    user_agent: Option<String>,
    skip_waf: bool,
    body: hyper::body::Incoming,
    client_ip: IpAddr,
    host: String,
    waf: &W,
    honeypot_ban_duration_secs: u64,
    main_config: &Arc<MainConfig>,
    http_config: &HttpConfig,
    metrics: &Option<Arc<WorkerMetrics>>,
    alt_svc: &Option<String>,
    mut on_log: LogFn,
) -> Result<RequestPreparationOutcome, hyper::Error>
where
    W: BufferedRequestWaf,
    LogFn: FnMut(u16, bool),
{
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
                build_response_with_alt_svc(
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
                build_response_with_alt_svc(
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
        if let Some(content_length) = content_length {
            let len = content_length as u64;
            m.bandwidth.record_ingress(len, BandwidthProtocol::Http);
            m.bandwidth.record_site_ingress(&host, len);
        }
    }

    if let Some(response) = maybe_handle_challenge_paths(
        &path,
        client_ip,
        waf,
        honeypot_ban_duration_secs,
        &parts,
        main_config,
        alt_svc,
        &mut on_log,
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

#[allow(clippy::too_many_arguments)]
pub async fn prepare_request_after_preflight<W, OnLimitLogFn, FinalLogFn, PassFn, PassFut, DropFn>(
    preflight: RequestPreflight,
    client_ip: IpAddr,
    router: &Arc<Router>,
    waf: &W,
    main_config: &Arc<MainConfig>,
    http_config: &HttpConfig,
    metrics: &Option<Arc<WorkerMetrics>>,
    alt_svc: &Option<String>,
    conn_guard: Option<&ConnectionTokenGuard>,
    start: std::time::Instant,
    mut on_limit_log: OnLimitLogFn,
    on_final_log: FinalLogFn,
    handle_pass: PassFn,
    request_drop: DropFn,
) -> Result<RequestPreparationOutcome, hyper::Error>
where
    W: BufferedRequestWaf,
    OnLimitLogFn: FnMut(u16, u64, &str, &str, &str, Option<&str>, bool),
    FinalLogFn: FnMut(u16, bool),
    PassFn: FnOnce(hyper::body::Incoming) -> PassFut,
    PassFut: Future<Output = Result<StreamingRequestFastPathOutcome, hyper::Error>>,
    DropFn: FnOnce(),
{
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
    let connection_limiter = waf.connection_limiter();
    if let Some(guard) = conn_guard {
        if let Err(e) = guard
            .maybe_enforce_site_connection_limits(
                connection_limiter.as_ref(),
                &site_id,
                client_ip,
                site_max_connections,
                site_max_per_ip,
            )
            .await
        {
            tracing::warn!(
                "Per-site connection limit exceeded for site {}: {}",
                site_id,
                e
            );
            counter!("synvoid.traffic.connection_limited").increment(1);
            on_limit_log(
                503,
                start.elapsed().as_millis() as u64,
                &site_id,
                method.as_str(),
                &path,
                user_agent.as_deref(),
                true,
            );
            return Ok(RequestPreparationOutcome::Respond(
                crate::response_builder::build_response_with_alt_svc(
                    503,
                    "Too Many Connections".to_string(),
                    "application/json",
                    alt_svc,
                    main_config,
                ),
            ));
        }
    }

    let check_request_full = || {
        let site_id = site_id.clone();
        let method = method.clone();
        let path = path.clone();
        let parts = parts.clone();
        let target = target.clone();
        let user_agent = user_agent.clone();
        async move {
            waf.check_request_full(
                Some(site_id.as_str()),
                client_ip,
                method.as_str(),
                &path,
                parts.uri.query(),
                &parts.headers,
                None,
                user_agent.as_deref(),
                None,
                Some(&target.site_config.bot),
            )
            .await
        }
    };

    let render_block_page =
        |status: u16, message: &str| waf.render_page_with_theme(status, Some(message), None);

    let stream_tarpit = |path: &str, user_agent: Option<&str>| waf.stream_tarpit(path, user_agent);

    let body = match maybe_handle_streaming_request_fast_path(
        &target,
        router,
        skip_waf,
        &parts,
        body,
        check_request_full,
        handle_pass,
        |decision| async {
            maybe_handle_streaming_waf_decision(
                decision,
                request_drop,
                render_block_page,
                stream_tarpit,
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

    finalize_request_preparation(
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
        waf,
        waf.honeypot_ban_duration_secs(),
        main_config,
        http_config,
        metrics,
        alt_svc,
        on_final_log,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_request_before_buffered_waf<
    W,
    PreflightLogFn,
    PreflightDropFn,
    OnLimitLogFn,
    FinalLogFn,
    PassFn,
    PassFut,
    DropFn,
>(
    req: hyper::Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    local_addr: Option<SocketAddr>,
    router: &Arc<Router>,
    waf: &W,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    http_config: &HttpConfig,
    metrics: &Option<Arc<WorkerMetrics>>,
    conn_guard: Option<&ConnectionTokenGuard>,
    start: std::time::Instant,
    mut preflight_on_log: PreflightLogFn,
    mut preflight_request_drop: PreflightDropFn,
    on_limit_log: OnLimitLogFn,
    on_final_log: FinalLogFn,
    handle_pass: PassFn,
    request_drop_after_preflight: DropFn,
) -> Result<RequestPreparationOutcome, hyper::Error>
where
    W: BufferedRequestWaf,
    PreflightLogFn: FnMut(u16, &str, bool, &str, &str, Option<&str>),
    PreflightDropFn: FnMut(),
    OnLimitLogFn: FnMut(u16, u64, &str, &str, &str, Option<&str>, bool),
    FinalLogFn: FnMut(u16, bool),
    PassFn: FnOnce(hyper::body::Incoming) -> PassFut,
    PassFut: Future<Output = Result<StreamingRequestFastPathOutcome, hyper::Error>>,
    DropFn: FnOnce(),
{
    let preflight = match prepare_request_preflight(
        req,
        client_ip,
        local_addr,
        router,
        waf,
        alt_svc,
        main_config,
        |status, site_id, bypassed, method, path, user_agent| {
            preflight_on_log(status, site_id, bypassed, method, path, user_agent);
        },
        || {
            preflight_request_drop();
        },
    )
    .await?
    {
        RequestPreflightOutcome::Continue(preflight) => preflight,
        RequestPreflightOutcome::Respond(response) => {
            return Ok(RequestPreparationOutcome::Respond(response));
        }
    };

    let outcome = prepare_request_after_preflight(
        preflight,
        client_ip,
        router,
        waf,
        main_config,
        http_config,
        metrics,
        alt_svc,
        conn_guard,
        start,
        on_limit_log,
        on_final_log,
        handle_pass,
        request_drop_after_preflight,
    )
    .await?;

    Ok(outcome)
}

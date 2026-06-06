use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use metrics::counter;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::bandwidth::BandwidthProtocol;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::{RouteResult, RouteTarget, Router};

use crate::body_policy::{collect_and_scan_request_body, BodyPolicyError, RequestBodyWaf};
use crate::challenge_paths::{maybe_handle_challenge_paths, ChallengePathWaf};
use crate::response_builder::build_response_with_alt_svc;
use crate::response_helpers::format_secure_http_only_cookie;
use crate::request_parse::{early_waf_decision, extract_request_metadata, should_skip_waf_from_trust_cookie};
use crate::validation_helpers::validate_websocket_upgrade;
use crate::request_parse::EarlyWafHooks;

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
pub async fn prepare_request_preflight<W, LogFn, BlockPageFn, DropFn>(
    req: hyper::Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    local_addr: Option<SocketAddr>,
    router: &Arc<Router>,
    waf: &W,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    mut on_log: LogFn,
    render_block_page: BlockPageFn,
    mut on_drop: DropFn,
) -> Result<RequestPreflightOutcome, hyper::Error>
where
    W: EarlyWafHooks,
    LogFn: FnMut(u16, &str, bool, &str, &str, Option<&str>),
    BlockPageFn: Fn(u16, &str) -> String,
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
            let body = render_block_page(status, &message);
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
    W: RequestBodyWaf + ChallengePathWaf,
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
            return Ok(RequestPreparationOutcome::Respond(build_response_with_alt_svc(
                403,
                "Request blocked by WAF".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            )));
        }
        Err(BodyPolicyError::BodyTooLarge) => {
            return Ok(RequestPreparationOutcome::Respond(build_response_with_alt_svc(
                413,
                "Request body too large".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            )));
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

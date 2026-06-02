use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use std::convert::Infallible;
use std::time::Duration;

use crate::config::{HttpConfig, MainConfig};
use std::net::IpAddr;
use std::sync::Arc;

use crate::http::response_helpers::format_secure_http_only_cookie;
use crate::proxy::WafDecision;
use crate::router::{BackendType, RouteTarget};
use crate::waf::WafCore;
use metrics::counter;

pub enum FullWafDecisionOutcome {
    Pass,
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

pub fn should_skip_full_waf(
    skip_waf: bool,
    allow_serverless_waf_off: bool,
    target: &RouteTarget,
) -> bool {
    if skip_waf {
        return true;
    }

    allow_serverless_waf_off
        && matches!(target.backend_type, BackendType::Serverless)
        && target
            .site_config
            .serverless
            .as_ref()
            .is_some_and(|s| s.waf_mode == crate::config::serverless::ServerlessWafMode::Off)
}

pub async fn full_request_waf_decision(
    waf: &Arc<WafCore>,
    target: &RouteTarget,
    skip_waf: bool,
    allow_serverless_waf_off: bool,
    site_id: &str,
    client_ip: IpAddr,
    method_str: &str,
    path: &str,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body_slice_ref: Option<&[u8]>,
    user_agent: Option<&str>,
) -> WafDecision {
    if should_skip_full_waf(skip_waf, allow_serverless_waf_off, target) {
        return WafDecision::Pass;
    }

    waf.check_request_full(
        Some(site_id),
        client_ip,
        method_str,
        path,
        query_string,
        headers,
        body_slice_ref,
        user_agent,
        None,
        Some(&target.site_config.bot),
        None,
    )
    .await
}

pub async fn resolve_full_request_waf_decision(
    decision: WafDecision,
    waf: &Arc<WafCore>,
    client_ip: IpAddr,
    http_config: &HttpConfig,
    target: &RouteTarget,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    mut on_drop: impl FnMut(),
    mut on_log: impl FnMut(u16, u64),
    mut on_blocked: impl FnMut(),
    mut on_blocked_egress: impl FnMut(u64),
    mut on_challenged: impl FnMut(u64),
    mut elapsed_ms: impl FnMut() -> u64,
) -> FullWafDecisionOutcome {
    match decision {
        WafDecision::Drop => {
            counter!("synvoid.http.blackhole_drop").increment(1);
            on_drop();
            on_log(0, elapsed_ms());
            let resp = Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(http_body_util::Full::new(Bytes::from_static(&[])).boxed())
                .unwrap_or_else(|_| crate::http::fallback_error_boxed());
            FullWafDecisionOutcome::Respond(resp)
        }
        WafDecision::Stall => {
            counter!("synvoid.http.stalled").increment(1);
            let current_stalled = crate::metrics::get_active_stalled_requests();
            if current_stalled >= http_config.max_stalled_requests as u64 {
                crate::metrics::record_stall_rejected();
                tracing::warn!(
                    client_ip = %client_ip,
                    current_stalled = current_stalled,
                    max_stalled = http_config.max_stalled_requests,
                    "Stall rejected due to concurrency cap"
                );
                return FullWafDecisionOutcome::Respond(
                    crate::http::response_builder::build_response_with_alt_svc(
                        429,
                        "Too many requests".to_string(),
                        "text/plain",
                        alt_svc,
                        main_config,
                    ),
                );
            }
            crate::metrics::record_stall_start();
            let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
            tokio::select! {
                _ = tokio::time::sleep(stall_timeout) => {
                    crate::metrics::record_stall_end();
                    let latency_ms = stall_timeout.as_millis() as u64;
                    on_log(408, latency_ms);
                    FullWafDecisionOutcome::Respond(crate::http::response_builder::build_response_with_alt_svc(
                        408,
                        "Request timeout".to_string(),
                        "text/plain",
                        alt_svc,
                        main_config,
                    ))
                }
            }
        }
        WafDecision::Block(status, message) => {
            on_blocked();
            let body = waf.error_page_manager.render_page_with_theme(
                status,
                Some(&message),
                target
                    .site_config
                    .error_pages
                    .theme
                    .as_ref()
                    .map(|theme_config| {
                        theme_config.to_theme_config(waf.error_page_manager.theme())
                    })
                    .as_ref(),
            );
            on_blocked_egress(body.len() as u64);
            on_log(status, elapsed_ms());
            FullWafDecisionOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    status,
                    body,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            )
        }
        WafDecision::Challenge(_type, html) => {
            on_challenged(html.len() as u64);
            on_log(200, elapsed_ms());
            FullWafDecisionOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            )
        }
        WafDecision::ChallengeWithCookie {
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
            on_challenged(html.len() as u64);
            on_log(200, elapsed_ms());
            FullWafDecisionOutcome::Respond(
                crate::http::response_builder::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                    alt_svc,
                    main_config,
                ),
            )
        }
        WafDecision::Tarpit(tar_path) => {
            on_blocked();
            let html = waf.generate_tarpit_response(&tar_path);
            on_blocked_egress(html.len() as u64);
            on_log(200, elapsed_ms());
            FullWafDecisionOutcome::Respond(
                crate::http::response_builder::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    alt_svc,
                    main_config,
                ),
            )
        }
        WafDecision::Pass => FullWafDecisionOutcome::Pass,
    }
}

use std::convert::Infallible;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use metrics::counter;

use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::StallPermit;
use synvoid_waf::WafDecision;

use crate::response_builder::{build_response_with_alt_svc, build_response_with_cookie};
use crate::response_helpers::format_secure_http_only_cookie;

pub enum FullWafDecisionOutcome {
    Pass,
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

pub fn should_skip_full_waf(
    skip_waf: bool,
    allow_serverless_waf_off: bool,
    is_serverless_backend: bool,
    serverless_waf_off: bool,
) -> bool {
    skip_waf || (allow_serverless_waf_off && is_serverless_backend && serverless_waf_off)
}

pub async fn full_request_waf_decision<CheckFn, CheckFut>(
    skip_waf: bool,
    allow_serverless_waf_off: bool,
    is_serverless_backend: bool,
    serverless_waf_off: bool,
    check_request_full: CheckFn,
) -> WafDecision
where
    CheckFn: FnOnce() -> CheckFut,
    CheckFut: Future<Output = WafDecision>,
{
    if should_skip_full_waf(
        skip_waf,
        allow_serverless_waf_off,
        is_serverless_backend,
        serverless_waf_off,
    ) {
        return WafDecision::Pass;
    }

    check_request_full().await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_full_request_waf_decision<
    DropFn,
    LogFn,
    BlockedFn,
    BlockedEgressFn,
    ChallengedFn,
    ElapsedFn,
    BlockRenderFn,
    TarpitRenderFn,
>(
    decision: WafDecision,
    client_ip: IpAddr,
    http_config: HttpConfig,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    mut on_drop: DropFn,
    mut on_log: LogFn,
    mut on_blocked: BlockedFn,
    mut on_blocked_egress: BlockedEgressFn,
    mut on_challenged: ChallengedFn,
    mut elapsed_ms: ElapsedFn,
    mut render_block_body: BlockRenderFn,
    mut generate_tarpit_html: TarpitRenderFn,
) -> FullWafDecisionOutcome
where
    DropFn: FnMut(),
    LogFn: FnMut(u16, u64),
    BlockedFn: FnMut(),
    BlockedEgressFn: FnMut(u64),
    ChallengedFn: FnMut(u64),
    ElapsedFn: FnMut() -> u64,
    BlockRenderFn: FnMut(u16, &str) -> String,
    TarpitRenderFn: FnMut(&str) -> String,
{
    match decision {
        WafDecision::Drop => {
            counter!("synvoid.http.blackhole_drop").increment(1);
            on_drop();
            on_log(0, elapsed_ms());
            let resp = Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(http_body_util::Full::new(Bytes::from_static(&[])).boxed())
                .unwrap_or_else(|_| crate::fallback_error_boxed());
            FullWafDecisionOutcome::Respond(resp)
        }
        WafDecision::Stall => {
            counter!("synvoid.http.stalled").increment(1);
            let permit = match StallPermit::try_new(http_config.max_stalled_requests) {
                Some(p) => p,
                None => {
                    tracing::warn!(
                        client_ip = %client_ip,
                        max_stalled = http_config.max_stalled_requests,
                        "Stall rejected due to concurrency cap"
                    );
                    return FullWafDecisionOutcome::Respond(build_response_with_alt_svc(
                        429,
                        "Too many requests".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }
            };
            let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
            tokio::select! {
                _ = tokio::time::sleep(stall_timeout) => {
                    drop(permit);
                    let latency_ms = stall_timeout.as_millis() as u64;
                    on_log(408, latency_ms);
                    FullWafDecisionOutcome::Respond(build_response_with_alt_svc(
                        408,
                        "Request timeout".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ))
                }
            }
        }
        WafDecision::Block(status, message) => {
            on_blocked();
            let body = render_block_body(status, &message);
            on_blocked_egress(body.len() as u64);
            on_log(status, elapsed_ms());
            FullWafDecisionOutcome::Respond(build_response_with_alt_svc(
                status,
                body,
                "text/html",
                &alt_svc,
                &main_config,
            ))
        }
        WafDecision::Challenge(_type, html) => {
            on_challenged(html.len() as u64);
            on_log(200, elapsed_ms());
            FullWafDecisionOutcome::Respond(build_response_with_alt_svc(
                200,
                html,
                "text/html",
                &alt_svc,
                &main_config,
            ))
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
            FullWafDecisionOutcome::Respond(build_response_with_cookie(
                200,
                html,
                "text/html",
                &cookie,
                &alt_svc,
                &main_config,
            ))
        }
        WafDecision::Tarpit(tar_path) => {
            on_blocked();
            let html = generate_tarpit_html(&tar_path);
            on_blocked_egress(html.len() as u64);
            on_log(200, elapsed_ms());
            FullWafDecisionOutcome::Respond(build_response_with_alt_svc(
                200,
                html,
                "text/html",
                &alt_svc,
                &main_config,
            ))
        }
        WafDecision::Pass => FullWafDecisionOutcome::Pass,
    }
}

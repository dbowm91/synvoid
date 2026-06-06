use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use synvoid_config::{serverless::ServerlessWafMode, HttpConfig, MainConfig};
use synvoid_metrics::{
    get_active_stalled_requests, record_stall_end, record_stall_rejected, record_stall_start,
};
use synvoid_proxy::{BackendType, RouteTarget};
use synvoid_waf::WafDecision;

use crate::waf_decision::{
    full_request_waf_decision, resolve_full_request_waf_decision, should_skip_full_waf,
    FullWafDecisionOutcome,
};

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_buffered_request_waf<
    CheckFn,
    CheckFut,
    DropFn,
    LogFn,
    BlockedFn,
    BlockedEgressFn,
    ChallengedFn,
    ElapsedFn,
    BlockRenderFn,
    TarpitRenderFn,
>(
    target: &RouteTarget,
    skip_waf: bool,
    site_id: &str,
    client_ip: std::net::IpAddr,
    method_str: &str,
    path: &str,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body_slice_ref: Option<&[u8]>,
    user_agent: Option<&str>,
    http_config: &HttpConfig,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    check_request_full: CheckFn,
    on_drop: DropFn,
    on_log: LogFn,
    on_blocked: BlockedFn,
    on_blocked_egress: BlockedEgressFn,
    on_challenged: ChallengedFn,
    elapsed_ms: ElapsedFn,
    render_block_body: BlockRenderFn,
    generate_tarpit_html: TarpitRenderFn,
) -> Option<Response<BoxBody<Bytes, Infallible>>>
where
    CheckFn: FnOnce() -> CheckFut,
    CheckFut: Future<Output = WafDecision>,
    DropFn: FnMut(),
    LogFn: FnMut(u16, u64),
    BlockedFn: FnMut(),
    BlockedEgressFn: FnMut(u64),
    ChallengedFn: FnMut(u64),
    ElapsedFn: FnMut() -> u64,
    BlockRenderFn: FnMut(u16, &str) -> String,
    TarpitRenderFn: FnMut(&str) -> String,
{
    let is_serverless_backend = matches!(target.backend_type, BackendType::Serverless);
    let serverless_waf_off = target
        .site_config
        .serverless
        .as_ref()
        .is_some_and(|s| s.waf_mode == ServerlessWafMode::Off);

    if should_skip_full_waf(skip_waf, true, is_serverless_backend, serverless_waf_off)
        && !skip_waf
        && is_serverless_backend
    {
        tracing::debug!(
            "serverless route with waf_mode=off - skipping WAF check for {} {}",
            method_str,
            path
        );
    }

    let waf_decision = full_request_waf_decision(
        skip_waf,
        true,
        is_serverless_backend,
        serverless_waf_off,
        check_request_full,
    )
    .await;

    match resolve_full_request_waf_decision(
        waf_decision,
        client_ip,
        http_config,
        alt_svc,
        main_config,
        on_drop,
        on_log,
        on_blocked,
        on_blocked_egress,
        on_challenged,
        elapsed_ms,
        get_active_stalled_requests,
        record_stall_rejected,
        record_stall_start,
        record_stall_end,
        render_block_body,
        generate_tarpit_html,
    )
    .await
    {
        FullWafDecisionOutcome::Respond(response) => Some(response),
        FullWafDecisionOutcome::Pass => None,
    }
}

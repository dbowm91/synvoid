use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::{HttpConfig, MainConfig};
use crate::http::waf_decision::{
    full_request_waf_decision, resolve_full_request_waf_decision, should_skip_full_waf,
    FullWafDecisionOutcome,
};
use crate::router::{BackendType, RouteTarget};
use crate::waf::WafCore;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_buffered_request_waf<
    DropFn,
    LogFn,
    BlockedFn,
    BlockedEgressFn,
    ChallengedFn,
    ElapsedFn,
>(
    waf: &Arc<WafCore>,
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
    on_drop: DropFn,
    on_log: LogFn,
    on_blocked: BlockedFn,
    on_blocked_egress: BlockedEgressFn,
    on_challenged: ChallengedFn,
    elapsed_ms: ElapsedFn,
) -> Option<Response<BoxBody<Bytes, Infallible>>>
where
    DropFn: FnMut(),
    LogFn: FnMut(u16, u64),
    BlockedFn: FnMut(),
    BlockedEgressFn: FnMut(u64),
    ChallengedFn: FnMut(u64),
    ElapsedFn: FnMut() -> u64,
{
    if should_skip_full_waf(skip_waf, true, target)
        && !skip_waf
        && matches!(target.backend_type, BackendType::Serverless)
    {
        tracing::debug!(
            "serverless route with waf_mode=off - skipping WAF check for {} {}",
            method_str,
            path
        );
    }

    let waf_decision = full_request_waf_decision(
        waf,
        target,
        skip_waf,
        true,
        site_id,
        client_ip,
        method_str,
        path,
        query_string,
        headers,
        body_slice_ref,
        user_agent,
    )
    .await;

    match resolve_full_request_waf_decision(
        waf_decision,
        waf,
        client_ip,
        http_config,
        target,
        alt_svc,
        main_config,
        on_drop,
        on_log,
        on_blocked,
        on_blocked_egress,
        on_challenged,
        elapsed_ms,
    )
    .await
    {
        FullWafDecisionOutcome::Respond(response) => Some(response),
        FullWafDecisionOutcome::Pass => None,
    }
}

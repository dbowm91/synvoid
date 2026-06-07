use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use metrics::counter;

use synvoid_http_client::is_quictunnel_url;
use synvoid_proxy::{BackendType, RouteTarget, Router};
use synvoid_waf::WafDecision;

use crate::waf_decision::full_request_waf_decision;

pub enum StreamingRequestFastPathOutcome {
    Continue(hyper::body::Incoming),
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_streaming_request_fast_path<
    CheckFn,
    CheckFut,
    PassFn,
    PassFut,
    DecisionFn,
    DecisionFut,
>(
    target: &RouteTarget,
    router: &Arc<Router>,
    skip_waf: bool,
    parts: &http::request::Parts,
    body: hyper::body::Incoming,
    check_request_full: CheckFn,
    handle_pass: PassFn,
    handle_non_pass_decision: DecisionFn,
) -> Result<StreamingRequestFastPathOutcome, hyper::Error>
where
    CheckFn: FnOnce() -> CheckFut,
    CheckFut: Future<Output = WafDecision>,
    PassFn: FnOnce(hyper::body::Incoming) -> PassFut,
    PassFut: Future<Output = Result<StreamingRequestFastPathOutcome, hyper::Error>>,
    DecisionFn: FnOnce(WafDecision) -> DecisionFut,
    DecisionFut: Future<Output = Option<Response<BoxBody<Bytes, Infallible>>>>,
{
    let content_length_u64: Option<u64> = parts
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    let can_stream_request = (matches!(target.backend_type, BackendType::Upstream)
        || matches!(target.backend_type, BackendType::Serverless))
        && target.site_config.proxy.should_stream(
            content_length_u64,
            target.site_config.proxy.streaming_threshold_bytes,
        )
        && !is_quictunnel_url(&target.upstream);
    let needs_body_transform = router.plugin_manager().is_some()
        || target
            .site_config
            .r#static
            .enable_minification
            .unwrap_or(false)
        || target.site_config.image_rights.enabled.unwrap_or(false)
        || target
            .site_config
            .r#static
            .enable_compression
            .unwrap_or(false);

    if !can_stream_request || needs_body_transform {
        return Ok(StreamingRequestFastPathOutcome::Continue(body));
    }

    counter!("synvoid.http.request.streaming_path").increment(1);

    let is_serverless_backend = matches!(target.backend_type, BackendType::Serverless);
    let serverless_waf_off = target
        .site_config
        .serverless
        .as_ref()
        .is_some_and(|s| s.waf_mode == synvoid_config::serverless::ServerlessWafMode::Off);

    let waf_decision = full_request_waf_decision(
        skip_waf,
        false,
        is_serverless_backend,
        serverless_waf_off,
        check_request_full,
    )
    .await;

    match waf_decision {
        WafDecision::Pass => handle_pass(body).await,
        decision => {
            if let Some(response) = handle_non_pass_decision(decision).await {
                Ok(StreamingRequestFastPathOutcome::Respond(response))
            } else {
                Ok(StreamingRequestFastPathOutcome::Continue(body))
            }
        }
    }
}

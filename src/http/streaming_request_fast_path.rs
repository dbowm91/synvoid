use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use metrics::counter;

use crate::config::MainConfig;
use crate::http::streaming_waf_upstream_dispatch::handle_streaming_waf_upstream_pass;
use crate::http::waf_decision::full_request_waf_decision;
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::WafDecision;
use crate::router::{BackendType, RouteTarget, Router};
use crate::waf::WafCore;

pub enum StreamingRequestFastPathOutcome {
    Continue(hyper::body::Incoming),
    Respond(Response<BoxBody<Bytes, Infallible>>),
}

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_streaming_request_fast_path<DecisionFn, DecisionFut, LogFn>(
    target: &RouteTarget,
    router: &Arc<Router>,
    waf: &Arc<WafCore>,
    skip_waf: bool,
    site_id: &str,
    client_ip: std::net::IpAddr,
    method: &http::Method,
    path: &str,
    query_string: Option<&str>,
    parts: &http::request::Parts,
    user_agent: Option<&str>,
    body: hyper::body::Incoming,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
    #[cfg(feature = "mesh")] serverless_manager: &Option<
        Arc<crate::serverless::manager::ServerlessManager>,
    >,
    on_streaming_serverless_status: LogFn,
    handle_non_pass_decision: DecisionFn,
) -> Result<StreamingRequestFastPathOutcome, hyper::Error>
where
    DecisionFn: FnOnce(WafDecision) -> DecisionFut,
    DecisionFut: Future<Output = Option<Response<BoxBody<Bytes, Infallible>>>>,
    LogFn: FnOnce(u16),
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
        && !crate::http_client::is_quictunnel_url(&target.upstream);
    let needs_body_transform = router.plugin_manager().is_some()
        || target
            .site_config
            .r#static
            .enable_minification
            .unwrap_or(false)
        || target.site_config.image_poison.enabled.unwrap_or(false)
        || target
            .site_config
            .r#static
            .enable_compression
            .unwrap_or(false);

    if !can_stream_request || needs_body_transform {
        return Ok(StreamingRequestFastPathOutcome::Continue(body));
    }

    counter!("synvoid.http.request.streaming_path").increment(1);
    let method_str = method.to_string();

    let waf_decision = full_request_waf_decision(
        waf,
        target,
        skip_waf,
        false,
        site_id,
        client_ip,
        &method_str,
        path,
        query_string,
        &parts.headers,
        None,
        user_agent,
    )
    .await;

    match waf_decision {
        WafDecision::Pass => {
            #[cfg(feature = "mesh")]
            if matches!(target.backend_type, BackendType::Serverless) {
                if let Some(sm) = serverless_manager.as_ref() {
                    let streaming_waf = waf.streaming();
                    let stream_body =
                        crate::http_client::StreamingWafBody::new(body, streaming_waf, client_ip);
                    use http_body_util::BodyExt;
                    let body_bytes = match stream_body.collect().await {
                        Ok(collected) => collected.to_bytes(),
                        Err(_) => {
                            return Ok(StreamingRequestFastPathOutcome::Respond(
                                crate::http::response_builder::build_response_with_alt_svc(
                                    500,
                                    "Internal Server Error".to_string(),
                                    "text/plain",
                                    alt_svc,
                                    main_config,
                                ),
                            ));
                        }
                    };

                    return Ok(
                        match crate::serverless::manager::handle_serverless_function_streaming(
                            sm,
                            method,
                            path,
                            &parts.headers,
                            body_bytes,
                            crate::serverless::manager::CallerContext::local(),
                        )
                        .await
                        {
                            Ok(response) => {
                                let status = response.status();
                                on_streaming_serverless_status(status.as_u16());
                                let response = Response::builder()
                                    .status(status)
                                    .body(Full::new(response.into_body()).boxed())
                                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                                StreamingRequestFastPathOutcome::Respond(response)
                            }
                            Err(e) => {
                                tracing::error!("Streaming serverless error: {}", e);
                                StreamingRequestFastPathOutcome::Respond(
                                    crate::http::response_builder::build_response_with_alt_svc(
                                        500,
                                        "Internal Server Error".to_string(),
                                        "text/plain",
                                        alt_svc,
                                        main_config,
                                    ),
                                )
                            }
                        },
                    );
                }
            }

            Ok(StreamingRequestFastPathOutcome::Respond(
                handle_streaming_waf_upstream_pass(
                    target,
                    path,
                    method,
                    parts,
                    body,
                    client_ip,
                    waf,
                    alt_svc,
                    main_config,
                    upstream_client_registry,
                )
                .await?,
            ))
        }
        decision => {
            if let Some(response) = handle_non_pass_decision(decision).await {
                Ok(StreamingRequestFastPathOutcome::Respond(response))
            } else {
                Ok(StreamingRequestFastPathOutcome::Continue(body))
            }
        }
    }
}

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::MainConfig;
use crate::http::streaming_waf_upstream_dispatch::handle_streaming_waf_upstream_pass;
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::WafDecision;
#[cfg(feature = "mesh")]
use crate::router::BackendType;
use crate::router::{RouteTarget, Router};
use crate::waf::WafCore;
#[cfg(feature = "mesh")]
use http_body_util::{BodyExt, Full};

pub use synvoid_http::StreamingRequestFastPathOutcome;

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
    _on_streaming_serverless_status: LogFn,
    handle_non_pass_decision: DecisionFn,
) -> Result<StreamingRequestFastPathOutcome, hyper::Error>
where
    DecisionFn: FnOnce(WafDecision) -> DecisionFut,
    DecisionFut: Future<Output = Option<Response<BoxBody<Bytes, Infallible>>>>,
    LogFn: FnOnce(u16),
{
    let method_str = method.to_string();

    synvoid_http::maybe_handle_streaming_request_fast_path(
        target,
        router,
        skip_waf,
        parts,
        body,
        || {
            waf.check_request_full(
                Some(site_id),
                client_ip,
                &method_str,
                path,
                query_string,
                &parts.headers,
                None,
                user_agent,
                None,
                Some(&target.site_config.bot),
                None,
            )
        },
        |body| async move {
            #[cfg(feature = "mesh")]
            if matches!(target.backend_type, BackendType::Serverless) {
                if let Some(sm) = serverless_manager.as_ref() {
                    let streaming_waf = waf.streaming();
                    let stream_body =
                        crate::http_client::StreamingWafBody::new(body, streaming_waf, client_ip);
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
                                _on_streaming_serverless_status(status.as_u16());
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
        },
        handle_non_pass_decision,
    )
    .await
}

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

#[cfg(feature = "mesh")]
use http_body_util::{BodyExt, Full};
use synvoid_config::MainConfig;
#[cfg(feature = "mesh")]
use synvoid_http_client::StreamingWafBody;
use synvoid_http_client::StreamingWafScanner;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
#[cfg(feature = "mesh")]
use synvoid_proxy::BackendType;
use synvoid_proxy::RouteTarget;

#[cfg(feature = "mesh")]
use crate::response_builder::build_response_with_alt_svc;
use crate::streaming_request_fast_path::StreamingRequestFastPathOutcome;
use crate::streaming_waf_upstream_dispatch::{
    handle_streaming_waf_upstream_pass, StreamingWafUpstreamError,
};

#[allow(clippy::too_many_arguments)]
pub async fn handle_streaming_request_pass<ServerlessStatusFn, PermissionDeniedFn>(
    target: RouteTarget,
    path: String,
    method: http::Method,
    parts: http::request::Parts,
    body: hyper::body::Incoming,
    client_ip: std::net::IpAddr,
    streaming_waf: Option<Box<dyn StreamingWafScanner>>,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    #[cfg(feature = "mesh")] serverless_manager: &Option<
        Arc<synvoid_serverless::ServerlessManager>,
    >,
    _on_serverless_status: ServerlessStatusFn,
    on_permission_denied: PermissionDeniedFn,
) -> Result<StreamingRequestFastPathOutcome, hyper::Error>
where
    ServerlessStatusFn: FnOnce(u16),
    PermissionDeniedFn: FnOnce() -> Response<BoxBody<Bytes, Infallible>>,
{
    #[cfg(feature = "mesh")]
    if matches!(target.backend_type, BackendType::Serverless) {
        if let Some(sm) = serverless_manager.as_ref() {
            let stream_body = StreamingWafBody::new(body, streaming_waf, client_ip);
            let body_bytes = match stream_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(StreamingRequestFastPathOutcome::Respond(
                        build_response_with_alt_svc(
                            500,
                            "Internal Server Error".to_string(),
                            "text/plain",
                            &alt_svc,
                            main_config.as_ref(),
                        ),
                    ));
                }
            };

            return Ok(
                match synvoid_serverless::manager::handle_serverless_function_streaming(
                    sm,
                    &method,
                    &path,
                    &parts.headers,
                    body_bytes,
                    synvoid_serverless::CallerContext::local(),
                )
                .await
                {
                    Ok(response) => {
                        let status = response.status();
                        _on_serverless_status(status.as_u16());
                        let response = Response::builder()
                            .status(status)
                            .body(Full::new(response.into_body()).boxed())
                            .unwrap_or_else(|_| crate::fallback_error_boxed());
                        StreamingRequestFastPathOutcome::Respond(response)
                    }
                    Err(e) => {
                        tracing::error!("Streaming serverless error: {}", e);
                        StreamingRequestFastPathOutcome::Respond(build_response_with_alt_svc(
                            500,
                            "Internal Server Error".to_string(),
                            "text/plain",
                            &alt_svc,
                            main_config.as_ref(),
                        ))
                    }
                },
            );
        }
    }

    match handle_streaming_waf_upstream_pass(
        &target,
        &path,
        &method,
        &parts,
        body,
        client_ip,
        streaming_waf,
        &alt_svc,
        &main_config,
        &upstream_client_registry,
    )
    .await
    {
        Ok(response) => Ok(StreamingRequestFastPathOutcome::Respond(response)),
        Err(StreamingWafUpstreamError::PermissionDenied) => Ok(
            StreamingRequestFastPathOutcome::Respond(on_permission_denied()),
        ),
    }
}

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;

use synvoid_config::MainConfig;
use synvoid_http_client::{
    send_request_streaming_generic, upstream_tls_from_site_config, ErasedBodyImpl,
    StreamingWafBody, StreamingWafScanner,
};
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::{
    build_forward_headers, build_headers_to_filter_for_site, filter_response_headers_buf,
    ForwardedProtocol, PreparedUpstreamTarget, RouteTarget,
};

use crate::response_builder::build_response_with_alt_svc;
use crate::response_helpers::apply_security_headers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingWafUpstreamError {
    PermissionDenied,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_streaming_waf_upstream_pass<S>(
    target: &RouteTarget,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    body: hyper::body::Incoming,
    client_ip: std::net::IpAddr,
    streaming_waf: Option<S>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, StreamingWafUpstreamError>
where
    S: StreamingWafScanner + Send + Sync + Unpin + 'static,
{
    let upstream_target =
        PreparedUpstreamTarget::new(&target.upstream, path, Some(&target.site_config.proxy));
    let headers_to_filter = build_headers_to_filter_for_site(
        &main_config.security.more_clear_headers,
        &target.site_config.security.more_clear_headers,
        &target.site_config.security_headers.more_clear_headers,
    );
    let forward_header_map = build_forward_headers(
        client_ip,
        &parts.headers,
        target
            .site_config
            .proxy
            .headers
            .as_ref()
            .unwrap_or(&synvoid_config::site::ProxyHeadersConfig::default()),
        ForwardedProtocol::Http,
    );
    let tls_config = target
        .site_config
        .proxy
        .upstream
        .as_ref()
        .and_then(|u| u.tls.as_ref())
        .and_then(upstream_tls_from_site_config);
    let streaming_client =
        upstream_client_registry.get_or_create_streaming(&target.site_id, tls_config.as_ref());
    let stream_body = StreamingWafBody::new(body, streaming_waf, client_ip);
    let erased_body = ErasedBodyImpl::new(stream_body);

    Ok(
        match send_request_streaming_generic(
            streaming_client.as_ref(),
            method.clone(),
            &upstream_target.url,
            erased_body,
            forward_header_map,
            Some(upstream_target.timeout),
        )
        .await
        {
            Ok(upstream_resp) => {
                let (resp_parts, upstream_body) = upstream_resp.into_parts();
                let status = resp_parts.status.as_u16();
                let body_len = resp_parts
                    .headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);

                let filtered_headers =
                    filter_response_headers_buf(&resp_parts.headers, &headers_to_filter);
                let mut builder = Response::builder().status(status);
                for (key, value) in filtered_headers.iter() {
                    if let Ok(v) = value.to_str() {
                        builder = builder.header(key.as_str(), v);
                    }
                }
                if let Some(alt_svc) = alt_svc {
                    builder = builder.header("Alt-Svc", alt_svc.as_str());
                }
                builder = apply_security_headers(
                    builder,
                    &target.site_config.security_headers,
                    main_config.security.global_security_headers,
                );

                if let Some(max_size) = upstream_target.max_response_size {
                    if body_len > 0 && body_len as usize > max_size {
                        return Ok(build_response_with_alt_svc(
                            502,
                            "Bad Gateway".to_string(),
                            "text/plain",
                            alt_svc,
                            main_config,
                        ));
                    }
                }

                builder
                    .body(
                        upstream_body
                            .map_err(|e| {
                                tracing::warn!("Upstream body stream error: {}", e);
                                unreachable!()
                            })
                            .boxed(),
                    )
                    .unwrap_or_else(|_| {
                        build_response_with_alt_svc(
                            500,
                            crate::reason_phrase(500).to_string(),
                            "text/plain",
                            alt_svc,
                            main_config,
                        )
                    })
            }
            Err(e) => {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                        return Err(StreamingWafUpstreamError::PermissionDenied);
                    }
                }
                tracing::error!("Upstream streaming request error: {}", e);
                build_response_with_alt_svc(
                    502,
                    "Bad Gateway".to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                )
            }
        },
    )
}

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;

use crate::config::site::ProxyHeadersConfig;
use crate::config::MainConfig;
use crate::http_client::{send_request_streaming_generic, ErasedBodyImpl, UpstreamTlsConfig};
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::{
    build_forward_headers, build_headers_to_filter_for_site, filter_response_headers_buf,
    ForwardedProtocol, PreparedUpstreamTarget,
};
use crate::router::RouteTarget;
use crate::waf::WafCore;

#[allow(clippy::too_many_arguments)]
pub async fn handle_streaming_waf_upstream_pass(
    target: &RouteTarget,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    body: hyper::body::Incoming,
    client_ip: std::net::IpAddr,
    waf: &Arc<WafCore>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
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
            .unwrap_or(&ProxyHeadersConfig::default()),
        ForwardedProtocol::Http,
    );
    let tls_config = target
        .site_config
        .proxy
        .upstream
        .as_ref()
        .and_then(|u| u.tls.as_ref())
        .and_then(UpstreamTlsConfig::from_site_config);
    let streaming_client =
        upstream_client_registry.get_or_create_streaming(&target.site_id, tls_config.as_ref());
    let streaming_waf = waf.streaming();
    let stream_body = crate::http_client::StreamingWafBody::new(body, streaming_waf, client_ip);
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
                builder = crate::http::response_helpers::apply_security_headers(
                    builder,
                    target,
                    main_config,
                );

                if let Some(max_size) = upstream_target.max_response_size {
                    if body_len > 0 && body_len as usize > max_size {
                        return Ok(crate::http::response_builder::build_response_with_alt_svc(
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
                        crate::http::response_builder::build_response_with_alt_svc(
                            500,
                            crate::http::reason_phrase(500).to_string(),
                            "text/plain",
                            alt_svc,
                            main_config,
                        )
                    })
            }
            Err(e) => {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                        let body = waf.error_page_manager.render_page_with_theme(
                            403,
                            Some("Forbidden"),
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
                        return Ok(crate::http::response_builder::build_response_with_alt_svc(
                            403,
                            body,
                            "text/html",
                            alt_svc,
                            main_config,
                        ));
                    }
                }
                tracing::error!("Upstream streaming request error: {}", e);
                crate::http::response_builder::build_response_with_alt_svc(
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

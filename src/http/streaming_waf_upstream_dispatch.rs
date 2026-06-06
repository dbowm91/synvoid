use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::MainConfig;
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::router::RouteTarget;
use crate::waf::WafCore;

/// Root compatibility wrapper around the extracted `synvoid-http` implementation.
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
    match synvoid_http::handle_streaming_waf_upstream_pass(
        target,
        path,
        method,
        parts,
        body,
        client_ip,
        waf.streaming(),
        alt_svc,
        main_config,
        upstream_client_registry,
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(synvoid_http::StreamingWafUpstreamError::PermissionDenied) => {
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
            Ok(crate::http::response_builder::build_response_with_alt_svc(
                403,
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
    }
}

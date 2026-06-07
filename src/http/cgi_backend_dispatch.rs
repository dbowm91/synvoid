use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::MainConfig;
use crate::router::RouteTarget;
use crate::waf::WafCore;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_cgi_backend(
    target: &RouteTarget,
    site_id: &str,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    client_ip: IpAddr,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    waf: &Arc<WafCore>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    synvoid_http::maybe_handle_cgi_backend(
        target,
        site_id,
        path,
        method,
        parts,
        full_body_arc,
        client_ip,
        alt_svc,
        main_config,
        |status, message| {
            let site_theme = target
                .site_config
                .error_pages
                .theme
                .as_ref()
                .map(|theme_config| theme_config.to_theme_config(waf.error_page_manager.theme()));
            waf.error_page_manager
                .render_page_with_theme(status, message, site_theme.as_ref())
        },
    )
    .await
}

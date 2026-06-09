use bytes::Bytes;
use std::convert::Infallible;
use std::sync::Arc;

use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::MainConfig;
use crate::http::apply_image_rights_marking;
use crate::router::{RouteTarget, Router};
use crate::waf::WafCore;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_fastcgi_or_php_backend(
    target: &RouteTarget,
    router: &Arc<Router>,
    waf: &Arc<WafCore>,
    site_id: &str,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    synvoid_http::maybe_handle_fastcgi_or_php_backend(
        target.clone(),
        Arc::clone(router),
        site_id.to_string(),
        path.to_string(),
        method.clone(),
        parts.clone(),
        full_body_arc.clone(),
        alt_svc.clone(),
        Arc::clone(main_config),
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
        apply_image_rights_marking,
    )
    .await
}

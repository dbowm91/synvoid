// Root compatibility shim — canonical implementation is in synvoid-http.
use std::sync::Arc;

use crate::config::MainConfig;
use crate::router::{RouteTarget, Router};

pub async fn maybe_handle_axum_dynamic_backend(
    router: &Arc<Router>,
    target: &RouteTarget,
    site_id: &str,
    path: &str,
    parts: &http::request::Parts,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Option<
    http::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>>,
> {
    let plugin_manager = router
        .plugin_manager()
        .and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>());
    synvoid_http::maybe_handle_axum_dynamic_backend(
        plugin_manager.map(|pm| pm as &dyn synvoid_http::AxumDynamicRouterLookup),
        target,
        site_id,
        path,
        parts,
        alt_svc,
        main_config,
    )
    .await
}

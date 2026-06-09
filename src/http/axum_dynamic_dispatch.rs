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
    let plugin_manager: Option<Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>> =
        router
            .plugin_manager()
            .and_then(|pm| {
                let arc_any: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(pm);
                arc_any.downcast::<crate::plugin::PluginManager>().ok()
            })
            .map(|arc| arc as Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>);
    synvoid_http::maybe_handle_axum_dynamic_backend(
        plugin_manager,
        target.clone(),
        site_id.to_string(),
        path.to_string(),
        parts.clone(),
        alt_svc.clone(),
        Arc::clone(main_config),
    )
    .await
}

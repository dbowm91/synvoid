use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;
use std::sync::Arc;
use tower::Service;

use crate::config::MainConfig;
use crate::router::{BackendType, RouteTarget, Router};

pub async fn maybe_handle_axum_dynamic_backend(
    router: &Arc<Router>,
    target: &RouteTarget,
    site_id: &str,
    path: &str,
    parts: &http::request::Parts,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::AxumDynamic) {
        return None;
    }

    if let Some(pm) = router.plugin_manager().and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>()) {
        let plugin_router = if let Some(ref plugin_name) = target.backend_plugin {
            pm.get_axum_router_by_name(plugin_name)
        } else {
            pm.get_axum_router()
        };

        if let Some(plugin_router) = plugin_router {
            tracing::debug!(
                "Routing to AxumDynamic plugin for site {} path {}",
                site_id,
                path
            );
            let mut plugin_req_builder = http::Request::builder()
                .method(parts.method.clone())
                .uri(parts.uri.clone());
            for (name, value) in parts.headers.iter() {
                plugin_req_builder = plugin_req_builder.header(name, value);
            }
            let plugin_req = plugin_req_builder
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| http::Request::new(axum::body::Body::empty()));

            let mut router = (*plugin_router).clone();
            let response = router.call(plugin_req).await;
            return Some(match response {
                Ok(axum_resp) => {
                    let (resp_parts, resp_body) = axum_resp.into_parts();
                    let collected: Result<http_body_util::Collected<Bytes>, _> =
                        resp_body.collect().await;
                    let resp_bytes = match collected {
                        Ok(c) => c.to_bytes(),
                        Err(_) => Bytes::from_static(&[]),
                    };
                    Response::from_parts(resp_parts, Full::new(resp_bytes).boxed())
                }
                Err(e) => crate::http::response_builder::build_response_with_alt_svc(
                    500,
                    format!("Plugin error: {}", e),
                    "text/plain",
                    alt_svc,
                    main_config,
                ),
            });
        }
    }

    tracing::warn!(
        "AxumDynamic backend for site {} but no plugin loaded, falling back to upstream",
        site_id
    );
    None
}

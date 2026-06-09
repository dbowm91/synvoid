use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use tower::Service;

use synvoid_config::MainConfig;
use synvoid_proxy::{BackendType, RouteTarget};

pub trait AxumDynamicRouterLookup: Send + Sync {
    fn get_axum_router(&self) -> Option<Arc<axum::Router>>;
    fn get_axum_router_by_name(&self, name: &str) -> Option<Arc<axum::Router>>;
}

pub async fn maybe_handle_axum_dynamic_backend(
    router_lookup: Option<Arc<dyn AxumDynamicRouterLookup + Send + Sync>>,
    target: RouteTarget,
    site_id: String,
    path: String,
    parts: http::request::Parts,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::AxumDynamic) {
        return None;
    }

    if let Some(router_lookup) = router_lookup {
        let plugin_router = if let Some(plugin_name) = target.backend_plugin.as_deref() {
            router_lookup.get_axum_router_by_name(plugin_name)
        } else {
            router_lookup.get_axum_router()
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
                Err(e) => crate::response_builder::build_response_with_alt_svc(
                    500,
                    format!("Plugin error: {}", e),
                    "text/plain",
                    &alt_svc,
                    main_config.as_ref(),
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

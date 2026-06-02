use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::app_server::GranianSupervisor;
use crate::config::MainConfig;
use crate::router::{BackendType, RouteTarget};

pub async fn maybe_handle_app_server_backend(
    app_servers: &Option<Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>>,
    target: &RouteTarget,
    site_id: &str,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::AppServer) {
        return None;
    }

    if let Some(app_servers) = app_servers {
        let app_servers_read = app_servers.read().await;
        if let Some(supervisor) = app_servers_read.get(site_id) {
            let body_bytes_for_appserver: Bytes = full_body_arc.as_ref().clone();
            match supervisor
                .forward_request(
                    method.clone(),
                    &parts.uri.to_string(),
                    &parts.headers,
                    body_bytes_for_appserver,
                )
                .await
            {
                Ok(response) => return Some(response.map(|b| Full::new(b).boxed())),
                Err(e) => {
                    tracing::warn!(
                        "AppServer (Granian) error for site {} path {}: {}",
                        site_id,
                        path,
                        e
                    );
                    return Some(crate::http::response_builder::build_response_with_alt_svc(
                        502,
                        format!("Backend Error: {}", e),
                        "text/plain",
                        alt_svc,
                        main_config,
                    ));
                }
            }
        }
    }

    tracing::warn!(
        "AppServer backend for site {} but no app server running",
        site_id
    );
    Some(crate::http::response_builder::build_response_with_alt_svc(
        502,
        "Backend misconfigured: app server not available".to_string(),
        "text/plain",
        alt_svc,
        main_config,
    ))
}

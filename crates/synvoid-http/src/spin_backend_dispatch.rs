use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use synvoid_config::MainConfig;
use synvoid_plugin_runtime::spin::handler::{
    get_global_spin_apps_manager, SpinHttpHandler, SpinRequest,
};
use synvoid_proxy::{BackendType, RouteTarget};

pub async fn maybe_handle_spin_backend(
    target: RouteTarget,
    site_id: String,
    path: String,
    parts: http::request::Parts,
    full_body_arc: Arc<Bytes>,
    ipc: Option<Arc<tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>>>,
    worker_id: Option<synvoid_ipc::WorkerId>,
    main_config: Arc<MainConfig>,
    client_ip: IpAddr,
    method_str: String,
    start: Instant,
    user_agent: Option<String>,
    alt_svc: Option<String>,
    on_log: impl Fn(
        Option<Arc<tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>>>,
        Option<synvoid_ipc::WorkerId>,
        &Arc<MainConfig>,
        IpAddr,
        &str,
        &str,
        u16,
        u64,
        &str,
        Option<&str>,
        bool,
    ),
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::Spin) {
        return None;
    }

    let Some(spin_app_name) = target.spin_app_name.as_ref() else {
        tracing::warn!(
            "Spin backend for site {} but no spin_app_name configured",
            site_id
        );
        return Some(crate::response_builder::build_response_with_alt_svc(
            502,
            "Spin backend misconfigured: no spin_app_name".to_string(),
            "text/plain",
            &alt_svc,
            &main_config,
        ));
    };

    let spin_apps_manager = get_global_spin_apps_manager();
    let Some(runtime) = spin_apps_manager.get(spin_app_name) else {
        tracing::warn!(
            "Spin backend for site {} but app '{}' not found in SpinAppsManager",
            site_id,
            spin_app_name
        );
        return Some(crate::response_builder::build_response_with_alt_svc(
            502,
            format!("Spin app '{}' not found", spin_app_name),
            "text/plain",
            &alt_svc,
            &main_config,
        ));
    };

    let handler = SpinHttpHandler::new(runtime);
    let spin_request = SpinRequest::new(parts.method, path.clone())
        .with_headers(parts.headers)
        .with_env(HashMap::new());

    let body_for_spin = full_body_arc.as_ref().clone();
    let spin_request = if !body_for_spin.is_empty() {
        spin_request.with_body(body_for_spin)
    } else {
        spin_request
    };

    match handler.handle_request(spin_request).await {
        Ok(spin_response) => {
            let status = spin_response.status;
            on_log(
                ipc,
                worker_id,
                &main_config,
                client_ip,
                &method_str,
                &path,
                status.as_u16(),
                start.elapsed().as_millis() as u64,
                &site_id,
                user_agent.as_deref(),
                false,
            );
            let mut response_builder = Response::builder().status(status);
            for (key, value) in spin_response.headers.iter() {
                response_builder =
                    response_builder.header(key.as_str(), value.to_str().unwrap_or(""));
            }
            Some(
                response_builder
                    .body(Full::new(spin_response.body).boxed())
                    .unwrap_or_else(|_| crate::fallback_error_boxed()),
            )
        }
        Err(e) => {
            tracing::warn!("Spin handler error for {}: {}", path, e);
            Some(crate::response_builder::build_response_with_alt_svc(
                502,
                format!("Spin Error: {}", e),
                "text/plain",
                &alt_svc,
                &main_config,
            ))
        }
    }
}

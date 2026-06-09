use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;

use synvoid_app_handlers::cgi::{CgiError, CgiHandler};
use synvoid_config::MainConfig;
use synvoid_proxy::{BackendType, RouteTarget};

pub async fn maybe_handle_cgi_backend(
    target: RouteTarget,
    site_id: String,
    path: String,
    method: http::Method,
    parts: http::request::Parts,
    full_body_arc: Arc<Bytes>,
    client_ip: IpAddr,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    render_error_page: impl Fn(u16, Option<&str>) -> String,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::Cgi) {
        return None;
    }

    if let Some(ref cgi_config) = target.site_config.proxy.cgi {
        match CgiHandler::new(cgi_config) {
            Ok(handler) => {
                let body_bytes_for_cgi: Bytes = full_body_arc.as_ref().clone();
                match handler
                    .execute(
                        &method,
                        &parts.uri,
                        &parts.headers,
                        body_bytes_for_cgi,
                        Some(client_ip),
                    )
                    .await
                {
                    Ok(response) => {
                        return Some(response.into_http_response().map(|b| Full::new(b).boxed()));
                    }
                    Err(e) => {
                        tracing::warn!("CGI error for site {} path {}: {}", site_id, path, e);
                        let status = match &e {
                            CgiError::NotFound(_) => 404,
                            CgiError::Forbidden(_) => 403,
                            CgiError::Timeout => 504,
                            _ => 502,
                        };
                        return Some(crate::response_builder::build_response_with_alt_svc(
                            status,
                            render_error_page(status, Some(&format!("CGI Error: {}", e))),
                            "text/plain",
                            &alt_svc,
                            &main_config,
                        ));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "CGI handler creation failed for site {} path {}: {}",
                    site_id,
                    path,
                    e
                );
                return Some(crate::response_builder::build_response_with_alt_svc(
                    500,
                    render_error_page(500, Some(&format!("CGI Configuration Error: {}", e))),
                    "text/plain",
                    &alt_svc,
                    &main_config,
                ));
            }
        }
    }

    tracing::warn!(
        "CGI backend for site {} but no CGI config configured",
        site_id
    );
    Some(crate::response_builder::build_response_with_alt_svc(
        502,
        render_error_page(502, Some("Backend misconfigured: no CGI root configured")),
        "text/plain",
        &alt_svc,
        &main_config,
    ))
}

pub mod yara_rate_limit;

use axum::http::StatusCode;
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::RwLock;
use std::sync::LazyLock;

#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

pub async fn extract_client_ip_middleware(mut request: Request, next: Next) -> Response {
    let client_ip = extract_client_ip_from_request(&request);
    request.extensions_mut().insert(ClientIp(client_ip));
    next.run(request).await
}

static TRUSTED_PROXIES: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

fn is_trusted_proxy(ip: &str) -> bool {
    let guard = TRUSTED_PROXIES.read();
    !guard.is_empty() && guard.iter().any(|p| p == ip)
}

fn extract_client_ip_from_request(request: &Request) -> String {
    let direct_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string());

    if let Some(ref ip) = direct_ip {
        if is_trusted_proxy(ip) {
            if let Some(header) = request.headers().get("x-forwarded-for") {
                if let Ok(s) = header.to_str() {
                    if let Some(client_ip) = s.split(',').next() {
                        let ip = client_ip.trim();
                        if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                            return ip.to_string();
                        }
                    }
                }
            }
        }
        return ip.clone();
    }

    direct_ip.unwrap_or_else(|| "unknown".to_string())
}

pub async fn auth_middleware_with_state(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<super::state::AdminState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    if request.uri().path().starts_with("/ws/") {
        return next.run(request).await;
    }

    let client_ip = request
        .extensions()
        .get::<ClientIp>()
        .map(|ip| ip.0.as_str())
        .unwrap_or("unknown");

    let bearer_token: Option<String> = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string());

    if let Some(token) = bearer_token {
        if super::auth::verify_admin_token(&token, &state.security.admin_token) {
            super::auth::AUTH_RATE_LIMITER.record_success(client_ip);
            request
                .extensions_mut()
                .insert(super::handlers::common::AuthenticatedUser {
                    username: "admin".to_string(),
                    role: super::handlers::common::RequiredRole::Admin,
                });
            return next.run(request).await;
        }
    }

    super::auth::AUTH_RATE_LIMITER.record_failure(client_ip);
    tracing::warn!("Auth middleware: authentication failed for {}", client_ip);
    StatusCode::UNAUTHORIZED.into_response()
}

pub async fn csrf_middleware(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<super::state::AdminState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let method = request.method();

    let requires_csrf = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
        && !path.starts_with("/ws/")
        && !path.starts_with("/stats")
        && !path.eq("/health")
        && !path.eq("/config/schema")
        && !path.eq("/logs");

    if !requires_csrf {
        return next.run(request).await;
    }

    let csrf_token = request
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let bearer_token: Option<String> = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string());

    if let Some(token) = csrf_token {
        if let Some(session_id) = bearer_token {
            if state.validate_csrf(&token, &session_id) {
                return next.run(request).await;
            }
        }
    }

    tracing::warn!("CSRF validation failed for {} {}", method, path);
    StatusCode::FORBIDDEN.into_response()
}

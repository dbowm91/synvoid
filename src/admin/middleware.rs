pub mod yara_rate_limit;

use axum::http::StatusCode;
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::IpAddr;
use std::sync::LazyLock;
use parking_lot::RwLock;

#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

static TRUSTED_PROXIES: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

pub fn set_trusted_proxies(proxies: Vec<String>) {
    let mut guard = TRUSTED_PROXIES.write();
    *guard = proxies;
}

pub async fn extract_client_ip_middleware(mut request: Request, next: Next) -> Response {
    let trusted: Vec<String> = TRUSTED_PROXIES.read().clone();
    let client_ip = extract_client_ip(&request, &trusted);
    request.extensions_mut().insert(ClientIp(client_ip));
    next.run(request).await
}

pub fn extract_client_ip(request: &Request, trusted_proxies: &[String]) -> String {
    let direct_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string());

    let direct_ip_str = match direct_ip {
        Some(ref ip) => ip.clone(),
        None => return "unknown".to_string(),
    };

    let is_trusted = trusted_proxies.iter().any(|p| {
        if let (Ok(proxy), Ok(direct)) = (p.parse::<IpAddr>(), direct_ip_str.parse::<IpAddr>()) {
            proxy == direct
        } else {
            false
        }
    });

    if is_trusted {
        if let Some(header) = request.headers().get("x-forwarded-for") {
            if let Ok(s) = header.to_str() {
                if let Some(client_ip) = s.split(',').next() {
                    let ip = client_ip.trim();
                    if !ip.is_empty() && ip.parse::<IpAddr>().is_ok() {
                        return ip.to_string();
                    }
                }
            }
        }
    }

    direct_ip_str
}

pub async fn auth_middleware_with_state(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<super::state::AdminState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    if path == "/health" || path.starts_with("/ws/") {
        return next.run(request).await;
    }

    if path == "/api/openapi.json" || path.starts_with("/api/docs") {
        return next.run(request).await;
    }

    let client_ip = request
        .extensions()
        .get::<ClientIp>()
        .map(|ip| ip.0.as_str())
        .unwrap_or("unknown");

    if super::auth::AUTH_RATE_LIMITER.is_locked(client_ip) {
        let retry_after = super::auth::AUTH_RATE_LIMITER
            .retry_after(client_ip)
            .unwrap_or(super::auth::AUTH_LOCKOUT_DURATION);
        tracing::warn!(
            "Auth middleware: client {} is locked out, retry after {:?}",
            client_ip,
            retry_after
        );
        let body = serde_json::json!({
            "error": "Too Many Requests",
            "message": "Too many failed authentication attempts. Please retry later."
        });
        let mut response = axum::Json(body).into_response();
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from(retry_after.as_secs()),
        );
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, response).into_response();
    }

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

    let session_id = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string());

    let csrf_token = match csrf_token {
        Some(token) => token,
        None => {
            tracing::warn!(
                "CSRF validation failed for {} {} - missing CSRF token",
                method,
                path
            );
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    let session_id = match session_id {
        Some(id) => id,
        None => {
            tracing::warn!(
                "CSRF validation failed for {} {} - missing session",
                method,
                path
            );
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    if state.validate_csrf(&csrf_token, &session_id) {
        return next.run(request).await;
    }

    tracing::warn!("CSRF validation failed for {} {}", method, path);
    StatusCode::FORBIDDEN.into_response()
}

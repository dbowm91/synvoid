pub mod yara_rate_limit;

use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::LazyLock;

use crate::admin::SESSION_COOKIE_NAME;

pub use synvoid_admin::rate_limit::ClientIp;

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
        super::metrics_events::record_auth_lockout();
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

    if let Some(session_id) = get_session_cookie(&request) {
        if state.validate_session(&session_id) {
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
    super::metrics_events::record_auth_failure();
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
        && !path.eq("/config/schema");

    if !requires_csrf {
        return next.run(request).await;
    }

    let bearer_token: Option<String> = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string());

    if bearer_token.is_some() {
        return next.run(request).await;
    }

    let session_id = get_session_cookie(&request);

    let session_id = match session_id {
        Some(id) => id,
        None => {
            tracing::warn!(
                "CSRF validation failed for {} {} - missing session cookie",
                method,
                path
            );
            super::metrics_events::record_csrf_failure();
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    if !state.validate_session(&session_id) {
        tracing::warn!(
            "CSRF validation failed for {} {} - invalid session",
            method,
            path
        );
        super::metrics_events::record_csrf_failure();
        return StatusCode::FORBIDDEN.into_response();
    }

    let csrf_token = request
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let csrf_token = match csrf_token {
        Some(token) => token,
        None => {
            tracing::warn!(
                "CSRF validation failed for {} {} - missing CSRF token",
                method,
                path
            );
            super::metrics_events::record_csrf_failure();
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    if state.validate_csrf(&csrf_token, &session_id) {
        return next.run(request).await;
    }

    tracing::warn!("CSRF validation failed for {} {}", method, path);
    super::metrics_events::record_csrf_failure();
    StatusCode::FORBIDDEN.into_response()
}

fn get_session_cookie(request: &Request) -> Option<String> {
    request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').find_map(|c| {
                let c = c.trim();
                if c.starts_with(&format!("{}=", SESSION_COOKIE_NAME)) {
                    Some(c[SESSION_COOKIE_NAME.len() + 1..].to_string())
                } else {
                    None
                }
            })
        })
}

pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    headers
        .entry("x-content-type-options")
        .or_insert_with(|| HeaderValue::from_static("nosniff"));

    headers
        .entry("referrer-policy")
        .or_insert_with(|| HeaderValue::from_static("strict-origin-when-cross-origin"));

    headers
        .entry("x-frame-options")
        .or_insert_with(|| HeaderValue::from_static("DENY"));

    headers.entry("content-security-policy").or_insert_with(|| {
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'"
        )
    });

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_client_ip_direct_connection() {
        let mut request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let addr: std::net::SocketAddr = "192.168.1.100:8080".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let ip = extract_client_ip(&request, &[]);
        assert_eq!(ip, "192.168.1.100");
    }

    #[test]
    fn test_extract_client_ip_untrusted_proxy_ignored() {
        let mut request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let addr: std::net::SocketAddr = "192.168.1.1:8080".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        request.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1, 192.168.1.1"),
        );

        let ip = extract_client_ip(&request, &[]);
        assert_eq!(ip, "192.168.1.1");
    }

    #[test]
    fn test_extract_client_ip_trusted_proxy_forwards() {
        let mut request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let addr: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        request.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.50, 10.0.0.1"),
        );

        let ip = extract_client_ip(&request, &["10.0.0.1".to_string()]);
        assert_eq!(ip, "203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_trusted_proxy_invalid_header_falls_back() {
        let mut request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let addr: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));

        let ip = extract_client_ip(&request, &["10.0.0.1".to_string()]);
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn test_extract_client_ip_no_connect_info() {
        let request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let ip = extract_client_ip(&request, &[]);
        assert_eq!(ip, "unknown");
    }

    #[test]
    fn test_extract_client_ip_multiple_xff_uses_first() {
        let mut request = Request::builder().body(axum::body::Body::empty()).unwrap();

        let addr: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        request.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.50, 70.41.3.18, 10.0.0.1"),
        );

        let ip = extract_client_ip(&request, &["10.0.0.1".to_string()]);
        assert_eq!(ip, "203.0.113.50");
    }

    #[tokio::test]
    async fn test_auth_rate_limiter_independent_ips() {
        let limiter = super::super::auth::AuthRateLimiter::new();
        let id_a = "192.168.1.10";
        let id_b = "192.168.1.20";

        for _ in 0..super::super::auth::MAX_AUTH_ATTEMPTS {
            limiter.record_failure(id_a);
        }

        assert!(limiter.is_locked(id_a));
        assert!(!limiter.is_locked(id_b));
    }

    #[tokio::test]
    async fn test_auth_rate_limiter_success_clears_only_that_ip() {
        let limiter = super::super::auth::AuthRateLimiter::new();
        let id_a = "10.0.0.1";
        let id_b = "10.0.0.2";

        for _ in 0..super::super::auth::MAX_AUTH_ATTEMPTS {
            limiter.record_failure(id_a);
            limiter.record_failure(id_b);
        }

        limiter.record_success(id_a);

        assert!(!limiter.is_locked(id_a));
        assert!(limiter.is_locked(id_b));
    }
}

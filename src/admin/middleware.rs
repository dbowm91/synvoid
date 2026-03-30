use axum::http::StatusCode;
use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};

#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

pub async fn extract_client_ip_middleware(mut request: Request, next: Next) -> Response {
    let client_ip = extract_client_ip_from_request(&request);
    request.extensions_mut().insert(ClientIp(client_ip));
    next.run(request).await
}

fn extract_client_ip_from_request(request: &Request) -> String {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').last())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|c| c.0.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

pub async fn auth_middleware_with_state(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<super::state::AdminState>>,
    request: Request,
    next: Next,
) -> Response {
    // Skip auth for health endpoint
    if request.uri().path() == "/health" {
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
            return next.run(request).await;
        }
    }

    super::auth::AUTH_RATE_LIMITER.record_failure(client_ip);
    tracing::warn!("Auth middleware: authentication failed for {}", client_ip);
    StatusCode::UNAUTHORIZED.into_response()
}

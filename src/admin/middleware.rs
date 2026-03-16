use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};

#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

pub async fn auth_middleware(
    TypedHeader(auth_header): TypedHeader<Authorization<Bearer>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let state = request
        .extensions()
        .get::<super::state::AdminState>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    if super::auth::constant_time_compare(auth_header.token(), &state.admin_token) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

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
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|c| c.0.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

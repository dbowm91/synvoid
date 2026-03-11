use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn csrf_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    
    let is_safe_method = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    
    if is_safe_method {
        return Ok(next.run(request).await);
    }
    
    let csrf_token = get_csrf_token_from_request(&request);
    
    if let Some(token) = csrf_token {
        let state = request
            .extensions()
            .get::<super::state::AdminState>();
        
        if let Some(state) = state {
            if state.validate_csrf(&token) {
                return Ok(next.run(request).await);
            }
        }
    }
    
    tracing::warn!("CSRF validation failed for {} {}", method, request.uri());
    Err(StatusCode::FORBIDDEN)
}

fn get_csrf_token_from_request(request: &Request<Body>) -> Option<String> {
    if let Some(cookie) = request.headers().get("cookie") {
        if let Ok(cookie_str) = cookie.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if part.starts_with("csrf_token=") {
                    return Some(part["csrf_token=".len()..].to_string());
                }
            }
        }
    }
    
    if let Some(token) = request.headers().get("x-csrf-token") {
        return token.to_str().ok().map(|s| s.to_string());
    }
    
    if let Some(token) = request.headers().get("x-xsrf-token") {
        return token.to_str().ok().map(|s| s.to_string());
    }
    
    None
}

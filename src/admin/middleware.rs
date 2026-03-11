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

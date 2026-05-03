use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use super::super::state::AdminState;
use super::common::StatusResponse;

const SESSION_COOKIE_NAME: &str = "maluwaf_session";

pub async fn create_session(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let bearer_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = bearer_token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if !super::super::auth::verify_admin_token(token, &state.security.admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let session_id = state.create_session();
    let csrf_token = state.generate_csrf_token(session_id.clone());

    let mut response = Json(StatusResponse::success("Session created")).into_response();

    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600",
        SESSION_COOKIE_NAME, session_id
    );

    if cfg!(not(debug_assertions)) {
        cookie = format!("{}; Secure", cookie);
    }

    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| {
            HeaderValue::from_static("maluwaf_session=error; Path=/; HttpOnly")
        }),
    );

    response.headers_mut().insert(
        "X-CSRF-Token",
        HeaderValue::from_str(&csrf_token).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    response
}

pub async fn get_csrf_token(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let session_id = headers
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
        });

    let Some(session_id) = session_id else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if !state.validate_session(&session_id) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let csrf_token = state.generate_csrf_token(session_id);

    let mut response = Json(serde_json::json!({
        "csrf_token": csrf_token
    }))
    .into_response();

    response.headers_mut().insert(
        "X-CSRF-Token",
        HeaderValue::from_str(&csrf_token).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    response
}

pub async fn delete_session(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let session_id = headers
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
        });

    let Some(session_id) = session_id else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.invalidate_session(&session_id);
    state.invalidate_csrf_tokens_for_session(&session_id);

    let mut response = Json(StatusResponse::success("Session deleted")).into_response();

    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        SESSION_COOKIE_NAME, ""
    );
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    response
}

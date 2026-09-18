use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use super::super::state::AdminState;
use crate::admin::SESSION_COOKIE_NAME;
use hex;
use sha2::Digest;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use uuid::Uuid;

pub async fn create_session(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let bearer_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = bearer_token else {
        // No token: one bounded dummy verify for constant work (Phase 43 D).
        super::super::auth::verify_dummy_admin_token_async().await;
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // Exactly one bounded real verify. The async verifier already applies
    // minimum-delay padding, so no second dummy bcrypt is added on failure.
    if !super::super::auth::verify_admin_token_async(token, &state.security.admin_token).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let session_id = state.create_session();
    let csrf_token = state.generate_csrf_token(session_id.clone());

    let audit_id = Uuid::new_v4().to_string();

    let session_id_hash = hex::encode(sha2::Sha256::digest(session_id.as_bytes()));
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "create_session".to_string(),
        target_kind: "session".to_string(),
        target_id: session_id_hash,
        prior_state: None,
        requested_state: None,
        resulting_state: Some(serde_json::json!({
            "session_created": true,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    let result = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "session".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Session created".to_string(),
    };
    let mut response = Json(result).into_response();

    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600",
        SESSION_COOKIE_NAME, session_id
    );

    if state.secure_cookie {
        cookie = format!("{}; Secure", cookie);
    }

    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| {
            HeaderValue::from_static("synvoid_session=error; Path=/; HttpOnly")
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

    let audit_id = Uuid::new_v4().to_string();

    let session_id_hash = hex::encode(sha2::Sha256::digest(session_id.as_bytes()));
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "delete_session".to_string(),
        target_kind: "session".to_string(),
        target_id: session_id_hash,
        prior_state: None,
        requested_state: None,
        resulting_state: Some(serde_json::json!({
            "session_deleted": true,
        })),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::AppliedLocalOnly,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    let result = AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "session".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::AppliedLocalOnly,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Session deleted".to_string(),
    };
    let mut response = Json(result).into_response();

    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        SESSION_COOKIE_NAME, ""
    );
    if state.secure_cookie {
        cookie = format!("{}; Secure", cookie);
    }
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    response
}

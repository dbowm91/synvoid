use super::super::state::AdminState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use utoipa::ToSchema;

use super::common::OptionalAuth;

#[derive(Debug, Serialize, ToSchema)]
pub struct PhpPoolStatus {
    pub socket: String,
    pub is_draining: bool,
    pub active_connections: usize,
    pub in_use_connections: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhpPoolReloadRequest {
    pub socket: String,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
}

fn default_drain_timeout() -> u64 {
    30
}

#[utoipa::path(
    get,
    path = "/system/php-pools",
    responses(
        (status = 200, description = "List of PHP-FPM pool statuses", body = Vec<PhpPoolStatus>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn list_php_pools(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<PhpPoolStatus>>, StatusCode> {
    let status = crate::fastcgi::get_all_pool_statuses();

    Ok(Json(
        status
            .into_iter()
            .map(|s| PhpPoolStatus {
                socket: s.socket,
                is_draining: s.is_draining,
                active_connections: s.active_connections,
                in_use_connections: s.in_use_connections,
            })
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/system/php-pools/reload",
    request_body = PhpPoolReloadRequest,
    responses(
        (status = 200, description = "PHP-FPM pool reload initiated", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
#[axum::debug_handler]
pub async fn reload_php_pool(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<PhpPoolReloadRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let timeout = Duration::from_secs(req.drain_timeout_secs);

    if let Err(e) = crate::fastcgi::drain_and_reload_pool(&req.socket, timeout).await {
        tracing::error!("Failed to reload PHP-FPM pool for {}: {}", req.socket, e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "php.pool.reload".to_string(),
        target_kind: "php_pool".to_string(),
        target_id: req.socket.clone(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    _state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: req.socket.clone(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!("PHP-FPM pool reload initiated for {}", req.socket),
    }))
}

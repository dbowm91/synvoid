#![allow(dead_code)]

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use utoipa::ToSchema;

use super::common::OptionalAuth;
use crate::admin::state::AdminState;

#[derive(Debug, Deserialize)]
pub struct IssueTierKeyRequest {
    pub org_id: String,
    pub tier: u32,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTierKeyRequest {
    pub org_id: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UnbindTierKeyRequest {
    pub org_id: String,
    pub key_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TierKeyInfo {
    pub key_id: String,
    pub tier: u32,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_by: String,
    pub bound_to: Option<String>,
    pub is_unspent: bool,
    pub revoked: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TierKeyListResponse {
    pub tier_keys: Vec<TierKeyInfo>,
    pub total: usize,
    pub unspent_count: usize,
}

pub async fn list_tier_keys(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TierKeyListResponse>, StatusCode> {
    let org_key_manager = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let all_keys = org_key_manager.list_all_tier_keys();
    let total = all_keys.len();
    let unspent_count = all_keys
        .iter()
        .filter(|(_, k)| k.is_unspent && !k.revoked)
        .count();

    let tier_keys: Vec<TierKeyInfo> = all_keys
        .into_iter()
        .map(|(org_id, key)| TierKeyInfo {
            key_id: key.key_id,
            tier: key.tier,
            valid_from: key.valid_from,
            valid_until: key.valid_until,
            issued_by: key.issued_by,
            bound_to: key.bound_to.or(Some(org_id)),
            is_unspent: key.is_unspent,
            revoked: key.revoked,
        })
        .collect();

    Ok(Json(TierKeyListResponse {
        tier_keys,
        total,
        unspent_count,
    }))
}

pub async fn issue_tier_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<IssueTierKeyRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let org_key_manager = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match org_key_manager.issue_tier_key(&req.org_id, req.tier) {
        Ok(key) => {
            let audit_id = uuid::Uuid::new_v4().to_string();

            let audit_event = AdminAuditEvent {
                audit_id: audit_id.clone(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
                actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                action: "issue_tier_key".to_string(),
                target_kind: "tier_key".to_string(),
                target_id: key.key_id.clone(),
                prior_state: None,
                requested_state: Some(serde_json::json!({
                    "org_id": req.org_id,
                    "tier": req.tier,
                })),
                resulting_state: Some(serde_json::json!({
                    "key_id": key.key_id,
                    "org_id": req.org_id,
                    "tier": req.tier,
                })),
                mutation_status: AdminMutationStatus::Applied,
                propagation_status: PropagationStatus::NotApplicable,
                event_id: None,
            };
            state.audit.log_audit_event(&audit_event);

            tracing::info!(
                "Tier key {} issued for org {} (tier {})",
                key.key_id,
                req.org_id,
                req.tier
            );
            Ok(Json(
                AdminMutationResult::applied(
                    format!("Tier key {} issued successfully", key.key_id),
                    format!("Tier key {} issued for org {}", key.key_id, req.org_id),
                )
                .with_audit_id(audit_id),
            ))
        }
        Err(e) => {
            tracing::error!("Failed to issue tier key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn revoke_tier_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<RevokeTierKeyRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let org_key_manager = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match org_key_manager.revoke_tier_key(&req.org_id, &req.key_id) {
        Ok(true) => {
            let audit_id = uuid::Uuid::new_v4().to_string();

            let audit_event = AdminAuditEvent {
                audit_id: audit_id.clone(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
                actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                action: "revoke_tier_key".to_string(),
                target_kind: "tier_key".to_string(),
                target_id: req.key_id.clone(),
                prior_state: None,
                requested_state: Some(serde_json::json!({
                    "org_id": req.org_id,
                    "key_id": req.key_id,
                })),
                resulting_state: Some(serde_json::json!({
                    "key_id": req.key_id,
                    "org_id": req.org_id,
                    "revoked": true,
                })),
                mutation_status: AdminMutationStatus::Applied,
                propagation_status: PropagationStatus::NotApplicable,
                event_id: None,
            };
            state.audit.log_audit_event(&audit_event);

            tracing::info!("Tier key {} revoked for org {}", req.key_id, req.org_id);
            Ok(Json(
                AdminMutationResult::applied(
                    format!("Tier key {} revoked successfully", req.key_id),
                    format!("Tier key {} revoked for org {}", req.key_id, req.org_id),
                )
                .with_audit_id(audit_id),
            ))
        }
        Ok(false) => Ok(Json(AdminMutationResult::noop(
            req.key_id.clone(),
            format!("Tier key {} not found", req.key_id),
        ))),
        Err(e) => {
            tracing::error!("Failed to revoke tier key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn unbind_tier_key(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UnbindTierKeyRequest>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let org_key_manager = state
        .mesh
        .org_key_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match org_key_manager.unbind_tier_key(&req.org_id, &req.key_id) {
        Ok(true) => {
            let audit_id = uuid::Uuid::new_v4().to_string();

            let audit_event = AdminAuditEvent {
                audit_id: audit_id.clone(),
                timestamp: synvoid_utils::safe_unix_timestamp(),
                actor: AdminActor::new(AdminMutationAuthority::AdminManual),
                action: "unbind_tier_key".to_string(),
                target_kind: "tier_key".to_string(),
                target_id: req.key_id.clone(),
                prior_state: None,
                requested_state: Some(serde_json::json!({
                    "org_id": req.org_id,
                    "key_id": req.key_id,
                })),
                resulting_state: Some(serde_json::json!({
                    "key_id": req.key_id,
                    "org_id": req.org_id,
                    "unbound": true,
                })),
                mutation_status: AdminMutationStatus::Applied,
                propagation_status: PropagationStatus::NotApplicable,
                event_id: None,
            };
            state.audit.log_audit_event(&audit_event);

            tracing::info!("Tier key {} unbound for org {}", req.key_id, req.org_id);
            Ok(Json(
                AdminMutationResult::applied(
                    format!("Tier key {} unbound successfully", req.key_id),
                    format!("Tier key {} unbound for org {}", req.key_id, req.org_id),
                )
                .with_audit_id(audit_id),
            ))
        }
        Ok(false) => Ok(Json(AdminMutationResult::noop(
            req.key_id.clone(),
            format!("Tier key {} not found", req.key_id),
        ))),
        Err(e) => {
            tracing::error!("Failed to unbind tier key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

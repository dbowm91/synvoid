use super::super::state::AdminState;
use crate::waf::threat_level::SqliteBackup;
use crate::waf::ThreatHistorySample;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
use utoipa::ToSchema;

use super::common::OptionalAuth;

const DEFAULT_THREAT_LEVEL_DB_PATH: &str = "/var/lib/synvoid/threat_level/history.db";
const DEFAULT_THREAT_LEVEL_BACKUP_DIR: &str = "/var/lib/synvoid/threat_level/backups";

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ThreatLevelStatusResponse {
    pub level: u8,
    pub score: f64,
    pub request_score: f64,
    pub attack_score: f64,
    pub rate_limit_score: f64,
    pub throttling_multiplier: f64,
    pub is_learning: bool,
    pub learning_progress: f64,
    pub has_baseline: bool,
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub attacks_per_minute: u32,
    pub rate_limit_hits: u32,
    pub blocked: u32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ThreatLevelHistoryResponse {
    pub minute: Vec<HistorySample>,
    pub hour: Vec<HistorySample>,
    pub day: Vec<HistorySample>,
    pub week: Vec<HistorySample>,
    pub month: Vec<HistorySample>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HistorySample {
    pub timestamp: i64,
    pub level: u8,
    pub score: f64,
    pub requests_per_minute: u32,
    pub attacks_per_minute: u32,
    pub rate_limit_hits: u32,
    pub blocked: u32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BaselineStatsResponse {
    pub baselines: Vec<BaselineMetric>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BaselineMetric {
    pub metric_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub min_value: f64,
    pub max_value: f64,
    pub samples: u64,
    pub computed_at: i64,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SetLevelRequest {
    pub level: u8,
}

#[utoipa::path(
    get,
    path = "/threat-level",
    responses(
        (status = 200, description = "Threat level status", body = ThreatLevelStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn get_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ThreatLevelStatusResponse>, StatusCode> {
    let threat_level = state
        .threat_level_manager()
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let (status, metrics) = tokio::task::spawn_blocking(move || {
        let status = threat_level.get_status();
        let metrics = threat_level.get_metrics();
        (status, metrics)
    })
    .await
    .map_err(|e| {
        tracing::error!("Failed to get status (task join): {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ThreatLevelStatusResponse {
        level: status.level,
        score: status.score,
        request_score: status.request_score,
        attack_score: status.attack_score,
        rate_limit_score: status.rate_limit_score,
        throttling_multiplier: status.throttling_multiplier,
        is_learning: status.is_learning,
        learning_progress: status.learning_progress,
        has_baseline: status.has_baseline,
        requests_per_second: metrics.requests_per_second,
        requests_per_minute: metrics.requests_per_minute,
        attacks_per_minute: metrics.attacks_per_minute,
        rate_limit_hits: metrics.rate_limit_hits_per_minute,
        blocked: metrics.blocked_per_minute,
    }))
}

#[utoipa::path(
    get,
    path = "/threat-level/history",
    responses(
        (status = 200, description = "Threat level history", body = ThreatLevelHistoryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn get_history(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ThreatLevelHistoryResponse>, StatusCode> {
    let threat_level = state
        .threat_level_manager()
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let history = tokio::task::spawn_blocking(move || threat_level.get_history())
        .await
        .map_err(|e| {
            tracing::error!("Failed to get history (task join): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let map_sample = |s: ThreatHistorySample| HistorySample {
        timestamp: s.timestamp,
        level: s.level,
        score: s.score,
        requests_per_minute: s.requests_per_minute,
        attacks_per_minute: s.attacks_per_minute,
        rate_limit_hits: s.rate_limit_hits,
        blocked: s.blocked,
    };

    Ok(Json(ThreatLevelHistoryResponse {
        minute: history.minute.into_iter().map(map_sample).collect(),
        hour: history.hour.into_iter().map(map_sample).collect(),
        day: history.day.into_iter().map(map_sample).collect(),
        week: history.week.into_iter().map(map_sample).collect(),
        month: history.month.into_iter().map(map_sample).collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/threat-level/baseline",
    responses(
        (status = 200, description = "Baseline statistics", body = BaselineStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn get_baseline(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BaselineStatsResponse>, StatusCode> {
    let threat_level = state
        .threat_level_manager()
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let baselines = tokio::task::spawn_blocking(move || threat_level.get_baselines())
        .await
        .map_err(|e| {
            tracing::error!("Failed to get baselines (task join): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(BaselineStatsResponse {
        baselines: baselines
            .into_iter()
            .map(|b| BaselineMetric {
                metric_name: b.metric_name,
                mean: b.mean,
                std_dev: b.std_dev,
                min_value: b.min_value,
                max_value: b.max_value,
                samples: b.samples,
                computed_at: b.computed_at,
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/threat-level/reset",
    responses(
        (status = 200, description = "Baseline reset", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn reset_baseline(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let threat_level = state.threat_level_manager().ok_or(StatusCode::NOT_FOUND)?;

    threat_level.reset_baseline();

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "threat_level.reset_baseline".to_string(),
        target_kind: "threat_level".to_string(),
        target_id: "baseline".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "baseline".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Baseline reset and learning restarted".to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/threat-level/set/{level}",
    params(
        ("level" = u8, Path, description = "Threat level (1-5)")
    ),
    responses(
        (status = 200, description = "Threat level set", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn set_level(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(level): Path<u8>,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let threat_level = state.threat_level_manager().ok_or(StatusCode::NOT_FOUND)?;

    let level = level.clamp(1, 5);
    threat_level.set_level(level);

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "threat_level.set".to_string(),
        target_kind: "threat_level".to_string(),
        target_id: level.to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: format!("threat_level_{}", level),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!("Threat level set to {}", level),
    }))
}

#[utoipa::path(
    post,
    path = "/threat-level/auto",
    responses(
        (status = 200, description = "Threat level set to auto", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn set_auto(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let threat_level = state.threat_level_manager().ok_or(StatusCode::NOT_FOUND)?;

    threat_level.reset_to_auto();

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "threat_level.auto".to_string(),
        target_kind: "threat_level".to_string(),
        target_id: "auto".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "auto".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Threat level set to auto mode".to_string(),
    }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupsListResponse {
    pub backups: Vec<serde_json::Value>,
}

#[utoipa::path(
    post,
    path = "/threat-level/history/backup",
    responses(
        (status = 200, description = "Backup created", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn create_backup(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let _threat_level = state.threat_level_manager().ok_or(StatusCode::NOT_FOUND)?;

    let db_path = PathBuf::from(DEFAULT_THREAT_LEVEL_DB_PATH);
    let backup_dir = PathBuf::from(DEFAULT_THREAT_LEVEL_BACKUP_DIR);

    let site_id = "global".to_string();

    let _backup = tokio::task::spawn_blocking(move || {
        SqliteBackup::create_backup(&db_path, &backup_dir, &site_id)
    })
    .await
    .map_err(|e| {
        tracing::error!("Failed to create backup (task join): {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .map_err(|e| {
        tracing::error!("Failed to create backup: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "threat_level.backup.create".to_string(),
        target_kind: "backup".to_string(),
        target_id: "backup".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "backup".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Backup created".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/threat-level/history/backups",
    responses(
        (status = 200, description = "List of backups", body = BackupsListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn list_backups(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BackupsListResponse>, StatusCode> {
    let backup_dir = PathBuf::from("/var/lib/synvoid/threat_level/backups");

    let backups = tokio::task::spawn_blocking(move || SqliteBackup::list_backups(&backup_dir))
        .await
        .map_err(|e| {
            tracing::error!("Failed to list backups (task join): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .unwrap_or_default();

    Ok(Json(BackupsListResponse {
        backups: backups
            .into_iter()
            .map(|b| serde_json::to_value(b).unwrap_or(serde_json::Value::Null))
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeleteBackupQuery {
    path: String,
}

#[utoipa::path(
    delete,
    path = "/threat-level/history/backups",
    params(
        ("path" = String, Query, description = "Backup path to delete")
    ),
    responses(
        (status = 200, description = "Backup deleted", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn delete_backup(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<DeleteBackupQuery>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let path = query.path.clone();

    tokio::task::spawn_blocking(move || SqliteBackup::delete_backup(&path))
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete backup (task join): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            tracing::error!("Failed to delete backup: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "threat_level.backup.delete".to_string(),
        target_kind: "backup".to_string(),
        target_id: "backup".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "backup".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Backup deleted".to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/threat-level/history/prune",
    responses(
        (status = 200, description = "History pruned", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn prune_history(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let threat_level = state
        .threat_level_manager()
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let deleted = tokio::task::spawn_blocking(move || threat_level.prune_history())
        .await
        .map_err(|e| {
            tracing::error!("Failed to prune history (task join): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map_err(|e| {
            tracing::error!("Failed to prune history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "threat_level.history.prune".to_string(),
        target_kind: "history".to_string(),
        target_id: "history".to_string(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "history".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!("Pruned {} history records", deleted),
    }))
}

#[utoipa::path(
    get,
    path = "/threat-level/history/stats",
    responses(
        (status = 200, description = "History statistics"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Threat level manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "threat_level"
)]
pub async fn get_history_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let threat_level = state
        .threat_level_manager()
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    let sample_count = tokio::task::spawn_blocking(move || threat_level.get_history_sample_count())
        .await
        .map_err(|e| {
            tracing::error!("Failed to get history stats (task join): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "sample_count": sample_count,
        "retention_days": 365,
    })))
}

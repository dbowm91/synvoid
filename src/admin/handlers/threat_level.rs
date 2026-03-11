use axum::{
    extract::{State, Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use super::super::state::AdminState;
use super::super::auth::{require_auth, OptionalAuth};
use crate::waf::ThreatLevelManager;
use crate::waf::threat_level::{BackupInfo, SqliteBackup};

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatLevelHistoryResponse {
    pub minute: Vec<HistorySample>,
    pub hour: Vec<HistorySample>,
    pub day: Vec<HistorySample>,
    pub week: Vec<HistorySample>,
    pub month: Vec<HistorySample>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HistorySample {
    pub timestamp: i64,
    pub level: u8,
    pub score: f64,
    pub requests_per_minute: u32,
    pub attacks_per_minute: u32,
    pub rate_limit_hits: u32,
    pub blocked: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineStatsResponse {
    pub baselines: Vec<BaselineMetric>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineMetric {
    pub metric_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub min_value: f64,
    pub max_value: f64,
    pub samples: u64,
    pub computed_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetLevelRequest {
    pub level: u8,
}

pub async fn get_status(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<ThreatLevelStatusResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let status = threat_level.get_status();
    let metrics = threat_level.get_metrics();

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

pub async fn get_history(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<ThreatLevelHistoryResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let history = threat_level.get_history();

    Ok(Json(ThreatLevelHistoryResponse {
        minute: history.minute.iter().map(|s| HistorySample {
            timestamp: s.timestamp,
            level: s.level,
            score: s.score,
            requests_per_minute: s.requests_per_minute,
            attacks_per_minute: s.attacks_per_minute,
            rate_limit_hits: s.rate_limit_hits,
            blocked: s.blocked,
        }).collect(),
        hour: history.hour.iter().map(|s| HistorySample {
            timestamp: s.timestamp,
            level: s.level,
            score: s.score,
            requests_per_minute: s.requests_per_minute,
            attacks_per_minute: s.attacks_per_minute,
            rate_limit_hits: s.rate_limit_hits,
            blocked: s.blocked,
        }).collect(),
        day: history.day.iter().map(|s| HistorySample {
            timestamp: s.timestamp,
            level: s.level,
            score: s.score,
            requests_per_minute: s.requests_per_minute,
            attacks_per_minute: s.attacks_per_minute,
            rate_limit_hits: s.rate_limit_hits,
            blocked: s.blocked,
        }).collect(),
        week: history.week.iter().map(|s| HistorySample {
            timestamp: s.timestamp,
            level: s.level,
            score: s.score,
            requests_per_minute: s.requests_per_minute,
            attacks_per_minute: s.attacks_per_minute,
            rate_limit_hits: s.rate_limit_hits,
            blocked: s.blocked,
        }).collect(),
        month: history.month.iter().map(|s| HistorySample {
            timestamp: s.timestamp,
            level: s.level,
            score: s.score,
            requests_per_minute: s.requests_per_minute,
            attacks_per_minute: s.attacks_per_minute,
            rate_limit_hits: s.rate_limit_hits,
            blocked: s.blocked,
        }).collect(),
    }))
}

pub async fn get_baseline(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<BaselineStatsResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let baselines = threat_level.get_baselines();

    Ok(Json(BaselineStatsResponse {
        baselines: baselines.iter().map(|b| BaselineMetric {
            metric_name: b.metric_name.clone(),
            mean: b.mean,
            std_dev: b.std_dev,
            min_value: b.min_value,
            max_value: b.max_value,
            samples: b.samples,
            computed_at: b.computed_at,
        }).collect(),
    }))
}

pub async fn reset_baseline(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    threat_level.reset_baseline();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "Baseline reset and learning restarted"
    })))
}

pub async fn set_level(
    State(state): State<Arc<AdminState>>,
    Path(level): Path<u8>,
    auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let level = level.clamp(1, 5);
    threat_level.set_level(level);

    Ok(Json(serde_json::json!({
        "status": "ok",
        "level": level
    })))
}

pub async fn set_auto(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    threat_level.reset_to_auto();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "Threat level set to auto mode"
    })))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupResponse {
    pub status: String,
    pub backup: BackupInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupsListResponse {
    pub backups: Vec<BackupInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PruneResponse {
    pub status: String,
    pub deleted_count: usize,
}

pub async fn create_backup(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<BackupResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let db_path = PathBuf::from("/var/lib/rustwaf/threat_level/history.db");
    let backup_dir = PathBuf::from("/var/lib/rustwaf/threat_level/backups");

    let site_id = "global".to_string();

    let backup = SqliteBackup::create_backup(&db_path, &backup_dir, &site_id)
        .map_err(|e| {
            tracing::error!("Failed to create backup: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(BackupResponse {
        status: "ok".to_string(),
        backup,
    }))
}

pub async fn list_backups(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<BackupsListResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let backup_dir = PathBuf::from("/var/lib/rustwaf/threat_level/backups");

    let backups = SqliteBackup::list_backups(&backup_dir)
        .unwrap_or_default();

    Ok(Json(BackupsListResponse { backups }))
}

#[derive(Debug, Deserialize)]
pub struct DeleteBackupQuery {
    path: String,
}

pub async fn delete_backup(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<DeleteBackupQuery>,
    auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    SqliteBackup::delete_backup(&query.path)
        .map_err(|e| {
            tracing::error!("Failed to delete backup: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "Backup deleted"
    })))
}

pub async fn prune_history(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<PruneResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let deleted = threat_level.prune_history()
        .map_err(|e| {
            tracing::error!("Failed to prune history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(PruneResponse {
        status: "ok".to_string(),
        deleted_count: deleted,
    }))
}

pub async fn get_history_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let threat_level = match &state.threat_level_manager {
        Some(tl) => tl,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let sample_count = threat_level.get_history_sample_count();

    Ok(Json(serde_json::json!({
        "sample_count": sample_count,
        "retention_days": 365,
    })))
}

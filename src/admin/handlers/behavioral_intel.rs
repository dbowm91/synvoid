use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct BehavioralStatsResponse {
    pub fingerprint_count: usize,
    pub version: u64,
}

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct BehavioralConfigResponse {
    pub enabled: bool,
    pub min_samples_for_fingerprint: u64,
    pub fingerprint_ttl_secs: u64,
    pub high_severity_threshold: u32,
}

#[utoipa::path(
    get,
    path = "/mesh/behavioral/stats",
    responses(
        (status = 200, description = "Behavioral intelligence statistics", body = BehavioralStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Behavioral intelligence not available"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_behavioral_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BehavioralStatsResponse>, StatusCode> {
    let manager = state
        .waf_tracking
        .behavioral_intel_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(BehavioralStatsResponse {
        fingerprint_count: manager.get_fingerprint_count(),
        version: manager.get_version(),
    }))
}

#[utoipa::path(
    get,
    path = "/mesh/behavioral/config",
    responses(
        (status = 200, description = "Behavioral intelligence configuration", body = BehavioralConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Behavioral intelligence not available"),
        (status = 500, description = "Internal server error")
    ),
    tag = "mesh"
)]
pub async fn get_behavioral_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BehavioralConfigResponse>, StatusCode> {
    let manager = state
        .waf_tracking
        .behavioral_intel_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let config = manager.get_config();

    Ok(Json(BehavioralConfigResponse {
        enabled: config.enabled,
        min_samples_for_fingerprint: config.min_samples_for_fingerprint,
        fingerprint_ttl_secs: config.fingerprint_ttl_secs,
        high_severity_threshold: config.high_severity_threshold,
    }))
}

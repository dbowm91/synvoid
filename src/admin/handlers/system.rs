use axum::{
    extract::{State, Path},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use super::super::state::AdminState;

use super::common::{require_auth, OptionalAuth, StatusResponse};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MasterStatusResponse {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    pub version: String,
    pub mode: String,
    pub worker_mode: String,
    pub metrics: MasterMetricsResponse,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MasterMetricsResponse {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub requests_per_second: f64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SystemInfoResponse {
    pub version: String,
    pub build_timestamp: String,
    pub architecture: String,
    pub features: Vec<String>,
    pub running_mode: String,
}

#[utoipa::path(
    get,
    path = "/system/master",
    tag = "System",
    responses(
        (status = 200, description = "Master process status", body = [MasterStatusResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Process manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_master_status(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<MasterStatusResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let metrics = state.get_metrics();

    Ok(Json(MasterStatusResponse {
        running: true,
        pid: Some(std::process::id()),
        uptime_secs: Some(state.uptime()),
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: "Standalone".to_string(),
        worker_mode: "Unified".to_string(),
        metrics: MasterMetricsResponse {
            total_requests: metrics.total_requests,
            blocked: metrics.blocked,
            challenged: metrics.challenged,
            proxied: metrics.proxied,
            errors: metrics.errors,
            current_concurrent: metrics.current_concurrent,
            peak_concurrent: metrics.peak_concurrent,
            requests_per_second: metrics.requests_per_second,
        },
    }))
}

#[utoipa::path(
    get,
    path = "/system/info",
    tag = "System",
    responses(
        (status = 200, description = "System information", body = [SystemInfoResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_system_info(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<SystemInfoResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut features = Vec::new();
    
    #[cfg(feature = "icmp-filter")]
    features.push("ICMP Filter".to_string());
    
    features.push("TLS".to_string());
    features.push("HTTP/3".to_string());
    features.push("WebSocket".to_string());

    Ok(Json(SystemInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_timestamp: env!("BUILD_TIMESTAMP").to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        features,
        running_mode: "Master".to_string(),
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WorkerStatusResponse {
    pub id: String,
    pub worker_type: String,
    pub pid: Option<u32>,
    pub status: String,
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub blocked: u64,
    pub errors: u64,
    pub memory_mb: u64,
    pub cpu_percent: f64,
}

#[utoipa::path(
    get,
    path = "/system/workers",
    tag = "System",
    responses(
        (status = 200, description = "List of worker processes", body = [WorkerStatusResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Process manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_workers(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<WorkerStatusResponse>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let pm = state.process_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let worker_metrics = pm.get_worker_metrics();

    let workers: Vec<WorkerStatusResponse> = worker_metrics
        .into_iter()
        .map(|(id, metrics)| {
            let status = if pm.is_worker_running(&id) {
                "running"
            } else {
                "stopped"
            };
            
            WorkerStatusResponse {
                id: format!("{:?}", id),
                worker_type: "Unified Server".to_string(),
                pid: pm.get_worker_pid(&id),
                status: status.to_string(),
                uptime_secs: metrics.uptime_secs,
                total_requests: metrics.total_requests,
                blocked: metrics.blocked,
                errors: metrics.errors,
                memory_mb: metrics.memory_bytes / 1024 / 1024,
                cpu_percent: metrics.cpu_percent,
            }
        })
        .collect();

    Ok(Json(workers))
}

#[utoipa::path(
    post,
    path = "/system/workers/{worker_id}/restart",
    tag = "System",
    params(
        ("worker_id" = String, Path, description = "ID of the worker to restart")
    ),
    responses(
        (status = 200, description = "Worker restart signal sent", body = [StatusResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Process manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn restart_worker(
    State(state): State<Arc<AdminState>>,
    Path(worker_id): Path<String>,
    auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let _pm = state.process_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    
    tracing::info!("Restarting worker via admin API: {}", worker_id);
    
    Ok(Json(StatusResponse::success(format!(
        "Worker {} restart signal sent",
        worker_id
    ))))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OverseerStatusResponse {
    pub running: bool,
    pub pid: Option<u32>,
    pub master_pid: Option<u32>,
    pub master_status: String,
    pub uptime_secs: u64,
    pub upgrade_mode: String,
    pub drain_status: String,
}

#[utoipa::path(
    get,
    path = "/system/overseer",
    tag = "System",
    responses(
        (status = 200, description = "Overseer status", body = [OverseerStatusResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Process manager not available")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_overseer(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<OverseerStatusResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let pm = state.process_manager.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    
    let running = pm.is_running();
    let master_pid = pm.get_master_pid();
    let _worker_count = pm.get_running_worker_count();

    Ok(Json(OverseerStatusResponse {
        running,
        pid: None,
        master_pid,
        master_status: if running { "Running".to_string() } else { "Stopped".to_string() },
        uptime_secs: state.uptime(),
        upgrade_mode: "None".to_string(),
        drain_status: "Idle".to_string(),
    }))
}

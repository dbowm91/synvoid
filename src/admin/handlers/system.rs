use super::super::state::AdminState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use super::common::{OptionalAuth, StatusResponse};

#[derive(Debug, Serialize, ToSchema)]
pub struct SupervisorStatusResponse {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    pub version: String,
    pub mode: String,
    pub worker_mode: String,
    pub metrics: SupervisorMetricsResponse,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SupervisorMetricsResponse {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub requests_per_second: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SystemInfoResponse {
    pub version: String,
    pub build_timestamp: String,
    pub architecture: String,
    pub features: Vec<String>,
    pub running_mode: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CapabilitiesResponse {
    pub features: Vec<String>,
    pub platform: String,
    pub architecture: String,
    pub sandboxing: bool,
    pub post_quantum: bool,
    pub ebpf_support: bool,
}

#[utoipa::path(
    get,
    path = "/system/capabilities",
    responses(
        (status = 200, description = "System capabilities", body = CapabilitiesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_capabilities(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<CapabilitiesResponse>, StatusCode> {
    let mut features = vec![
        "TLS".to_string(),
        "HTTP/3".to_string(),
        "WebSocket".to_string(),
        "Supervisor-Worker".to_string(),
        "IPC".to_string(),
    ];

    #[cfg(feature = "dns")]
    features.push("DNS".to_string());

    #[cfg(feature = "mesh")]
    features.push("Mesh".to_string());

    #[cfg(feature = "socket-handoff")]
    features.push("Socket Handoff".to_string());

    #[cfg(feature = "icmp-filter")]
    features.push("ICMP Filter".to_string());

    #[cfg(feature = "flood-ebpf")]
    features.push("eBPF Flood Protection".to_string());

    #[cfg(feature = "post-quantum")]
    features.push("Post-Quantum Cryptography".to_string());

    #[cfg(feature = "macos-sandbox")]
    features.push("macOS Sandbox".to_string());

    #[cfg(feature = "wireguard")]
    features.push("WireGuard".to_string());

    Ok(Json(CapabilitiesResponse {
        features,
        platform: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        sandboxing: cfg!(feature = "macos-sandbox") || cfg!(target_os = "linux"),
        post_quantum: cfg!(feature = "post-quantum"),
        ebpf_support: cfg!(feature = "flood-ebpf") || cfg!(feature = "icmp-filter"),
    }))
}

#[utoipa::path(
    get,
    path = "/system/supervisor",
    responses(
        (status = 200, description = "Supervisor process status", body = SupervisorStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_supervisor_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SupervisorStatusResponse>, StatusCode> {
    let metrics = state.get_metrics();

    Ok(Json(SupervisorStatusResponse {
        running: true,
        pid: Some(std::process::id()),
        uptime_secs: Some(state.uptime()),
        version: env!("CARGO_PKG_VERSION").to_string(),
        mode: "Standalone".to_string(),
        worker_mode: "Unified".to_string(),
        metrics: SupervisorMetricsResponse {
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
    responses(
        (status = 200, description = "System information", body = SystemInfoResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_system_info(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SystemInfoResponse>, StatusCode> {
    #[allow(unused_mut)]
    let mut features = vec![
        "TLS".to_string(),
        "HTTP/3".to_string(),
        "WebSocket".to_string(),
    ];

    #[cfg(feature = "icmp-filter")]
    features.insert(0, "ICMP Filter".to_string());

    Ok(Json(SystemInfoResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_timestamp: env!("BUILD_TIMESTAMP").to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        features,
        running_mode: "Supervisor".to_string(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkerStatusResponse {
    pub id: String,
    pub worker_type: String,
    pub pid: Option<u32>,
    pub status: String,
    pub health: String,
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub blocked: u64,
    pub errors: u64,
    pub memory_mb: u64,
    pub cpu_percent: f64,
    pub health_score: f64,
    pub last_request_at: Option<u64>,
    pub active_connections: u64,
    pub restart_count: u32,
    pub slow_queries: u64,
}

fn calculate_health_status(
    cpu_percent: f64,
    memory_mb: u64,
    errors: u64,
    total_requests: u64,
) -> (String, f64) {
    let mut health_score = 100.0;

    health_score -= cpu_percent.min(50.0);
    health_score -= (memory_mb as f64 / 1024.0).min(30.0);
    health_score -= if errors > 0 && total_requests > 0 {
        ((errors as f64 / total_requests as f64) * 100.0).min(20.0)
    } else {
        0.0
    };

    health_score = health_score.max(0.0);

    let status = if health_score >= 80.0 {
        "ok".to_string()
    } else if health_score >= 50.0 {
        "warn".to_string()
    } else {
        "critical".to_string()
    };

    (status, health_score)
}

#[utoipa::path(
    get,
    path = "/system/workers",
    responses(
        (status = 200, description = "List of workers", body = Vec<WorkerStatusResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Process manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_workers(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<WorkerStatusResponse>>, StatusCode> {
    let pm = state
        .process
        .process_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let worker_metrics = pm.get_worker_metrics();

    let workers: Vec<WorkerStatusResponse> = worker_metrics
        .into_iter()
        .map(|(id, metrics)| {
            let status = if pm.is_worker_running(&id) {
                "running"
            } else {
                "stopped"
            };

            let memory_mb = metrics.memory_bytes / 1024 / 1024;
            let (health, health_score) = calculate_health_status(
                metrics.cpu_percent,
                memory_mb,
                metrics.errors,
                metrics.total_requests,
            );

            WorkerStatusResponse {
                id: format!("{:?}", id),
                worker_type: "Unified Server".to_string(),
                pid: pm.get_worker_pid(&id),
                status: status.to_string(),
                health,
                uptime_secs: metrics.uptime_secs,
                total_requests: metrics.total_requests,
                blocked: metrics.blocked,
                errors: metrics.errors,
                memory_mb,
                cpu_percent: metrics.cpu_percent,
                health_score,
                last_request_at: None,
                active_connections: 0,
                restart_count: 0,
                slow_queries: 0,
            }
        })
        .collect();

    Ok(Json(workers))
}

#[utoipa::path(
    post,
    path = "/system/workers/{worker_id}/restart",
    params(
        ("worker_id" = String, Path, description = "Worker ID to restart")
    ),
    responses(
        (status = 200, description = "Worker restart signal sent", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Worker not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn restart_worker(
    State(state): State<Arc<AdminState>>,
    Path(worker_id): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    let pm = state
        .process
        .process_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    pm.restart_worker_by_id(&worker_id).map_err(|e| {
        tracing::error!("Failed to restart worker {}: {}", worker_id, e);
        StatusCode::NOT_FOUND
    })?;

    Ok(Json(StatusResponse::success(format!(
        "Restart signal sent to worker {}",
        worker_id
    ))))
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct BatchRestartRequest {
    pub worker_ids: Vec<String>,
    pub strategy: String,
    pub drain_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BatchRestartResponse {
    pub success: bool,
    pub message: String,
    pub restarted: Vec<String>,
    pub failed: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/system/workers/batch-restart",
    request_body = BatchRestartRequest,
    responses(
        (status = 200, description = "Batch restart result", body = BatchRestartResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Process manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn batch_restart_workers(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<BatchRestartRequest>,
) -> Result<Json<BatchRestartResponse>, StatusCode> {
    let pm = state
        .process
        .process_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut restarted = Vec::new();
    let mut failed = Vec::new();

    match req.strategy.as_str() {
        "parallel" => {
            for worker_id in &req.worker_ids {
                if pm.restart_worker_by_id(worker_id).is_ok() {
                    restarted.push(worker_id.clone());
                } else {
                    failed.push(worker_id.clone());
                }
            }
        }
        "rolling" => {
            let drain_timeout = req.drain_timeout_secs.unwrap_or(30);
            for worker_id in &req.worker_ids {
                tracing::info!(
                    "Rolling restart: draining worker {} for {} seconds",
                    worker_id,
                    drain_timeout
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(drain_timeout)).await;
                if pm.restart_worker_by_id(worker_id).is_ok() {
                    restarted.push(worker_id.clone());
                } else {
                    failed.push(worker_id.clone());
                }
            }
        }
        _ => {
            return Ok(Json(BatchRestartResponse {
                success: false,
                message: format!(
                    "Unknown strategy: {}. Use 'parallel' or 'rolling'",
                    req.strategy
                ),
                restarted: vec![],
                failed: vec![],
            }));
        }
    }

    let success = failed.is_empty();
    Ok(Json(BatchRestartResponse {
        success,
        message: format!(
            "Restarted {} workers, {} failed",
            restarted.len(),
            failed.len()
        ),
        restarted,
        failed,
    }))
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct ScaleWorkersRequest {
    pub target_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScaleWorkersResponse {
    pub success: bool,
    pub message: String,
    pub current_count: usize,
    pub target_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkerCountResponse {
    pub current: usize,
    pub min: usize,
    pub max: usize,
}

#[utoipa::path(
    get,
    path = "/system/workers/count",
    responses(
        (status = 200, description = "Worker count information", body = WorkerCountResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Process manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_worker_count(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<WorkerCountResponse>, StatusCode> {
    let pm = state
        .process
        .process_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let current = pm.get_running_worker_count();
    let config = state.process.config.read().await;
    let min = config.main.process_manager.min_workers;
    let max = config.main.process_manager.max_workers;

    Ok(Json(WorkerCountResponse { current, min, max }))
}

#[utoipa::path(
    put,
    path = "/system/workers/scale",
    request_body = ScaleWorkersRequest,
    responses(
        (status = 200, description = "Worker scaling result", body = ScaleWorkersResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Process manager not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn scale_workers(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<ScaleWorkersRequest>,
) -> Result<Json<ScaleWorkersResponse>, StatusCode> {
    let pm = state
        .process
        .process_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let current = pm.get_running_worker_count();
    let config = state.process.config.read().await;
    let min_workers = config.main.process_manager.min_workers;
    let max_workers = config.main.process_manager.max_workers;

    let target = req.target_count.max(min_workers).min(max_workers);

    if target == current {
        return Ok(Json(ScaleWorkersResponse {
            success: true,
            message: "Already at target worker count".to_string(),
            current_count: current,
            target_count: target,
        }));
    }

    let diff = if target > current {
        let to_spawn = target - current;
        tracing::info!("Scaling up workers: spawning {} new workers", to_spawn);
        for _ in 0..to_spawn {
            let _ = pm.spawn_worker();
        }
        format!("Spawned {} new workers", to_spawn)
    } else {
        let to_stop = current - target;
        tracing::info!(
            "Scaling down workers: stopping {} workers (will drain gracefully)",
            to_stop
        );
        format!("Stopping {} workers (graceful drain)", to_stop)
    };

    let new_current = pm.get_running_worker_count();

    Ok(Json(ScaleWorkersResponse {
        success: true,
        message: diff,
        current_count: new_current,
        target_count: target,
    }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SupervisorProcessStatusResponse {
    pub running: bool,
    pub pid: Option<u32>,
    pub supervisor_pid: Option<u32>,
    pub supervisor_status: String,
    pub uptime_secs: u64,
    pub upgrade_mode: String,
    pub drain_status: String,
}

fn get_supervisor_status_file_path() -> std::path::PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/run"))
        .join("synvoid")
        .join("supervisor_status.json")
}

#[utoipa::path(
    get,
    path = "/system/supervisor",
    responses(
        (status = 200, description = "Supervisor status", body = SupervisorProcessStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Process manager not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_supervisor(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SupervisorProcessStatusResponse>, StatusCode> {
    let pm = state
        .process
        .process_manager
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    let status_file_path = get_supervisor_status_file_path();

    // Try to read status from file first
    if status_file_path.exists() {
        match tokio::fs::read_to_string(&status_file_path).await {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(json) => {
                    return Ok(Json(SupervisorProcessStatusResponse {
                        running: json
                            .get("running")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        pid: json.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32),
                        supervisor_pid: json
                            .get("supervisor_pid")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u32),
                        supervisor_status: json
                            .get("supervisor_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        uptime_secs: json
                            .get("uptime_secs")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                        upgrade_mode: json
                            .get("upgrade_mode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        drain_status: json
                            .get("drain_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                    }));
                }
                Err(e) => {
                    tracing::warn!("Failed to parse supervisor status file: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read supervisor status file: {}", e);
            }
        }
    }

    // Fallback to process manager state
    let running = pm.is_running();
    let supervisor_pid = pm.get_supervisor_pid();
    let _worker_count = pm.get_running_worker_count();

    Ok(Json(SupervisorProcessStatusResponse {
        running,
        pid: None,
        supervisor_pid,
        supervisor_status: if running {
            "Running".to_string()
        } else {
            "Stopped".to_string()
        },
        uptime_secs: state.uptime(),
        upgrade_mode: "None".to_string(),
        drain_status: "Idle".to_string(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GranianLogsResponse {
    pub site_id: String,
    pub logs: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/system/app-servers/{site_id}/logs",
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    responses(
        (status = 200, description = "Granian app server logs", body = GranianLogsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "App server not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "system"
)]
pub async fn get_granian_logs(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<GranianLogsResponse>, StatusCode> {
    match crate::app_server::get_granian_logs(&site_id) {
        Some(logs) => Ok(Json(GranianLogsResponse { site_id, logs })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

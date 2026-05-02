use super::super::audit::AuditLog;
use super::super::middleware::ClientIp;
use super::super::state::AdminState;
use super::common::{OptionalAuth, StatusResponse};
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::config::honeypot_port::HoneypotPortConfig;

#[derive(Debug, Serialize, ToSchema)]
pub struct HoneypotPortConfigResponse {
    pub config: HoneypotPortConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateHoneypotPortConfigRequest {
    pub config: HoneypotPortConfig,
}

async fn persist_main_config_and_notify(state: &Arc<AdminState>) -> Result<(), StatusCode> {
    let main_config_path = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.join("main.toml")
    };

    let toml_content = {
        let cfg = state.process.config.read().await;
        toml::to_string_pretty(&cfg.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    {
        let _guard = state.metrics.config_write_lock.write().await;
        tokio::fs::write(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    if let Some(ref pm) = state.process.process_manager {
        let config_dir = state.process.config.read().await.config_dir.clone();
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(())
}

#[utoipa::path(
    get,
    path = "/honeypot/config",
    responses(
        (status = 200, description = "Honeypot port configuration", body = HoneypotPortConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "honeypot"
)]
pub async fn get_honeypot_port_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HoneypotPortConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(HoneypotPortConfigResponse {
        config: config.main.honeypot_port.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/honeypot/config",
    request_body = UpdateHoneypotPortConfigRequest,
    responses(
        (status = 200, description = "Honeypot port config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "honeypot"
)]
pub async fn update_honeypot_port_config(
    State(state): State<Arc<AdminState>>,
    Extension(client_ip): Extension<ClientIp>,
    Json(req): Json<UpdateHoneypotPortConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let mut config = state.process.config.write().await;
    config.main.honeypot_port = req.config.clone();
    drop(config);

    if let Some(ref controller) = state.honeypot.port_honeypot_controller {
        if let Err(e) = controller.update_config(req.config.clone()) {
            return Ok(Json(StatusResponse::error(format!(
                "Failed to update honeypot config: {}",
                e
            ))));
        }
    }

    state.audit.log(AuditLog::new(
        None,
        None,
        "honeypot.config.update".to_string(),
        "honeypot/config".to_string(),
        client_ip.0.clone(),
        None,
        None,
        true,
    ));

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Honeypot port config updated.",
    )))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HoneypotStatusResponse {
    pub enabled: bool,
    pub paused: bool,
    pub pause_reason: Option<String>,
    pub active_ports: Vec<u16>,
    pub total_connections: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct HoneypotControlRequest {
    pub command: String,
    pub reason: Option<String>,
    pub duration_secs: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HoneypotControlResponse {
    pub success: bool,
    pub message: String,
    pub status: Option<HoneypotStatusResponse>,
}

#[utoipa::path(
    get,
    path = "/honeypot/status",
    responses(
        (status = 200, description = "Honeypot status", body = HoneypotStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "honeypot"
)]
pub async fn get_honeypot_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HoneypotStatusResponse>, StatusCode> {
    let (enabled, paused, pause_reason, active_ports, total_connections) =
        if let Some(ref controller) = state.honeypot.port_honeypot_controller {
            let status = controller.get_status();
            let total_conn = controller
                .get_runner()
                .and_then(|r| r.storage().get_connection_count().ok())
                .unwrap_or(0) as u64;
            (
                controller.is_running(),
                status.paused,
                status.pause_reason,
                status.active_ports,
                total_conn,
            )
        } else {
            (false, false, None, vec![], 0)
        };

    Ok(Json(HoneypotStatusResponse {
        enabled,
        paused,
        pause_reason,
        active_ports,
        total_connections,
    }))
}

#[utoipa::path(
    post,
    path = "/honeypot/control",
    request_body = HoneypotControlRequest,
    responses(
        (status = 200, description = "Honeypot control result", body = HoneypotControlResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Honeypot controller not found"),
        (status = 400, description = "Invalid command"),
        (status = 500, description = "Internal server error")
    ),
    tag = "honeypot"
)]
pub async fn control_honeypot(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<HoneypotControlRequest>,
) -> Result<Json<HoneypotControlResponse>, StatusCode> {
    let controller = state
        .honeypot
        .port_honeypot_controller
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;

    match req.command.as_str() {
        "disable" => {
            if let Some(runner) = controller.get_runner() {
                runner.stop();
            }
        }
        "enable" | "pause" | "resume" => {}
        _ => {
            return Ok(Json(HoneypotControlResponse {
                success: false,
                message: format!("Unknown command: {}", req.command),
                status: None,
            }));
        }
    };

    let status = controller.get_status();
    let total_connections = controller
        .get_runner()
        .and_then(|r| r.storage().get_connection_count().ok())
        .unwrap_or(0) as u64;

    Ok(Json(HoneypotControlResponse {
        success: true,
        message: format!("Command {} executed successfully", req.command),
        status: Some(HoneypotStatusResponse {
            enabled: controller.is_running(),
            paused: status.paused,
            pause_reason: status.pause_reason,
            active_ports: status.active_ports,
            total_connections,
        }),
    }))
}

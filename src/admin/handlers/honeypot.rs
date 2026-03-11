use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::common::OptionalAuth;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HoneypotStatusResponse {
    pub enabled: bool,
    pub paused: bool,
    pub pause_reason: Option<String>,
    pub active_ports: Vec<u16>,
    pub total_connections: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct HoneypotControlRequest {
    pub command: String,
    pub reason: Option<String>,
    pub duration_secs: Option<u32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HoneypotControlResponse {
    pub success: bool,
    pub message: String,
    pub status: Option<HoneypotStatusResponse>,
}

pub async fn get_honeypot_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HoneypotStatusResponse>, StatusCode> {
    let (enabled, paused, pause_reason, active_ports) = if let Some(ref hp_controller) = state.port_honeypot_controller {
        let status = hp_controller.get_status();
        (status.enabled, status.paused, status.pause_reason, status.active_ports)
    } else {
        (false, false, None, vec![])
    };
    
    let total_connections = state.port_honeypot_runner.as_ref()
        .map(|r| r.storage().get_connection_count().unwrap_or(0) as u64)
        .unwrap_or(0);
    
    Ok(Json(HoneypotStatusResponse {
        enabled,
        paused,
        pause_reason,
        active_ports,
        total_connections,
    }))
}

pub async fn control_honeypot(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<HoneypotControlRequest>,
) -> Result<Json<HoneypotControlResponse>, StatusCode> {
    let hp_controller = state.port_honeypot_controller.as_ref()
        .ok_or_else(|| StatusCode::NOT_FOUND)?;
    
    let command = match req.command.as_str() {
        "enable" => crate::honeypot_port::HoneypotControlCommand::Enable,
        "disable" => crate::honeypot_port::HoneypotControlCommand::Disable,
        "pause" => crate::honeypot_port::HoneypotControlCommand::Pause {
            reason: req.reason.unwrap_or_else(|| "manual".to_string()),
            duration_secs: req.duration_secs,
        },
        "resume" => crate::honeypot_port::HoneypotControlCommand::Resume,
        _ => return Ok(Json(HoneypotControlResponse {
            success: false,
            message: format!("Unknown command: {}", req.command),
            status: None,
        })),
    };
    
    hp_controller.handle_control_command(command)
        .map_err(|_e| StatusCode::BAD_REQUEST)?;
    
    let status = hp_controller.get_status();
    let total_connections = state.port_honeypot_runner.as_ref()
        .map(|r| r.storage().get_connection_count().unwrap_or(0) as u64)
        .unwrap_or(0);
    
    Ok(Json(HoneypotControlResponse {
        success: true,
        message: format!("Command {} executed successfully", req.command),
        status: Some(HoneypotStatusResponse {
            enabled: status.enabled,
            paused: status.paused,
            pause_reason: status.pause_reason,
            active_ports: status.active_ports,
            total_connections,
        }),
    }))
}

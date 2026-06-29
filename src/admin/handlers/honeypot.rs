use super::super::middleware::ClientIp;
use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
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
        (status = 200, description = "Honeypot port config updated", body = AdminMutationResult<String>),
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
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let mut config = state.process.config.write().await;
    config.main.honeypot_port = req.config.clone();
    drop(config);

    if let Some(ref controller) = state.honeypot.port_honeypot_controller {
        if let Err(e) = controller.update_config(req.config.clone()) {
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::Failed,
                target: "honeypot_port".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: format!("Failed to update honeypot config: {}", e),
            }));
        }
    }

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual)
            .with_source_ip(client_ip.0.clone()),
        action: "honeypot.config.update".to_string(),
        target_kind: "honeypot_port".to_string(),
        target_id: "honeypot_port".to_string(),
        prior_state: None,
        requested_state: Some(serde_json::to_value(&req.config).unwrap_or(serde_json::Value::Null)),
        resulting_state: Some(serde_json::to_value(&req.config).unwrap_or(serde_json::Value::Null)),
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    persist_main_config_and_notify(&state).await?;
    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "honeypot_port".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: "Honeypot port config updated".to_string(),
    }))
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
        (status = 200, description = "Honeypot control result", body = AdminMutationResult<String>),
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
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
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
            return Ok(Json(AdminMutationResult {
                status: AdminMutationStatus::InvalidRejected,
                target: "honeypot".to_string(),
                local_store_mutated: false,
                propagation: PropagationStatus::NotApplicable,
                event_id: None,
                audit_id: None,
                message: format!("Unknown command: {}", req.command),
            }));
        }
    };

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "honeypot.control".to_string(),
        target_kind: "honeypot".to_string(),
        target_id: "honeypot".to_string(),
        prior_state: None,
        requested_state: Some(serde_json::json!({"command": req.command})),
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: "honeypot".to_string(),
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: format!("Command {} executed successfully", req.command),
    }))
}

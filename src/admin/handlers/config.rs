use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::super::auth::{require_auth, OptionalAuth};
use crate::log_controller;

#[derive(Debug, Serialize)]
pub struct MainConfigResponse {
    pub config: crate::config::main::MainConfig,
}

pub async fn get_main_config(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<MainConfigResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    
    Ok(Json(MainConfigResponse {
        config: config.main.clone(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMainConfigRequest {
    pub config: crate::config::main::MainConfig,
}

#[derive(Debug, Serialize)]
pub struct UpdateConfigResponse {
    pub status: String,
    pub message: String,
}

pub async fn update_main_config(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Json(req): Json<UpdateMainConfigRequest>,
) -> Result<Json<UpdateConfigResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let toml_content = match toml::to_string_pretty(&req.config) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to serialize config: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if let Err(e) = std::fs::write("config/main.toml", toml_content) {
        tracing::error!("Failed to write main config: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(UpdateConfigResponse {
        status: "success".to_string(),
        message: "Configuration updated. Reload required.".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct ConfigFieldSchema {
    pub path: String,
    pub label: String,
    pub field_type: String,
    pub default: Option<serde_json::Value>,
    pub description: String,
    pub impact: Option<String>,
    pub options: Option<Vec<String>>,
}

pub async fn get_config_schema(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<ConfigFieldSchema>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let schema = vec![
        ConfigFieldSchema {
            path: "server.host".to_string(),
            label: "Listen Host".to_string(),
            field_type: "string".to_string(),
            default: Some(serde_json::json!("0.0.0.0")),
            description: "IP address to bind the main server to".to_string(),
            impact: Some("Use 0.0.0.0 for all interfaces, 127.0.0.1 for localhost only".to_string()),
            options: None,
        },
        ConfigFieldSchema {
            path: "server.port".to_string(),
            label: "Listen Port".to_string(),
            field_type: "integer".to_string(),
            default: Some(serde_json::json!(8080)),
            description: "TCP port for the main HTTP server".to_string(),
            impact: Some("Ensure port is not already in use".to_string()),
            options: None,
        },
        ConfigFieldSchema {
            path: "ratelimit.ip.per_second".to_string(),
            label: "Requests per Second (per IP)".to_string(),
            field_type: "integer".to_string(),
            default: Some(serde_json::json!(10)),
            description: "Maximum requests allowed per IP per second".to_string(),
            impact: Some("Lower values provide stronger protection but may block legitimate burst traffic".to_string()),
            options: None,
        },
        ConfigFieldSchema {
            path: "ratelimit.ip.per_minute".to_string(),
            label: "Requests per Minute (per IP)".to_string(),
            field_type: "integer".to_string(),
            default: Some(serde_json::json!(60)),
            description: "Maximum requests allowed per IP per minute".to_string(),
            impact: None,
            options: None,
        },
        ConfigFieldSchema {
            path: "attack_detection.paranoia_level".to_string(),
            label: "Paranoia Level".to_string(),
            field_type: "enum".to_string(),
            default: Some(serde_json::json!(1)),
            description: "Detection sensitivity level".to_string(),
            impact: Some("Higher levels catch more attacks but increase false positives".to_string()),
            options: Some(vec!["1 - Low".to_string(), "2 - Medium".to_string(), "3 - High".to_string()]),
        },
        ConfigFieldSchema {
            path: "bot.block_ai_crawlers".to_string(),
            label: "Block AI Crawlers".to_string(),
            field_type: "boolean".to_string(),
            default: Some(serde_json::json!(true)),
            description: "Block known AI/ML web crawlers and scrapers".to_string(),
            impact: None,
            options: None,
        },
        ConfigFieldSchema {
            path: "logging.level".to_string(),
            label: "Log Level".to_string(),
            field_type: "enum".to_string(),
            default: Some(serde_json::json!("info")),
            description: "Minimum log level to record".to_string(),
            impact: None,
            options: Some(vec!["trace".to_string(), "debug".to_string(), "info".to_string(), "warn".to_string(), "error".to_string()]),
        },
    ];

    Ok(Json(schema))
}

pub async fn reload_config(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<UpdateConfigResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut config = state.config.write().await;
    let results = config.reload_all();
    
    let loaded = results.iter().filter(|r| r.1.is_ok()).count();
    let failed = results.iter().filter(|r| r.1.is_err()).count();

    Ok(Json(UpdateConfigResponse {
        status: if failed == 0 { "success" } else { "partial" }.to_string(),
        message: format!("Loaded {} configs, {} failed", loaded, failed),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SetLogLevelRequest {
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct LogLevelResponse {
    pub status: String,
    pub level: String,
    pub message: String,
}

pub async fn set_log_level(
    State(_state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Json(req): Json<SetLogLevelRequest>,
) -> Result<Json<LogLevelResponse>, StatusCode> {
    if !require_auth(&auth, &_state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match log_controller::set_log_level(&req.level) {
        Ok(level) => Ok(Json(LogLevelResponse {
            status: "success".to_string(),
            level,
            message: "Log level updated".to_string(),
        })),
        Err(e) => {
            tracing::warn!("Invalid log level request: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn get_log_level(
    State(_state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<LogLevelResponse>, StatusCode> {
    if !require_auth(&auth, &_state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let level = log_controller::get_log_level();
    Ok(Json(LogLevelResponse {
        status: "success".to_string(),
        level,
        message: "Current log level".to_string(),
    }))
}

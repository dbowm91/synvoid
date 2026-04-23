use super::super::audit::AuditLog;
use super::super::state::AdminState;
use crate::log_controller;
use axum::{extract::State, http::StatusCode, Json};
use schemars::schema_for;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use super::common::{OptionalAuth, StatusResponse};

#[derive(Debug, Serialize, ToSchema)]
pub struct MainConfigResponse {
    pub config: serde_json::Value,
}

fn redact_admin_token(config: &mut serde_json::Value) {
    if let serde_json::Value::Object(ref mut map) = config {
        if let Some(serde_json::Value::Object(ref mut admin)) = map.get_mut("admin") {
            admin.remove("token");
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/config/main",
    responses(
        (status = 200, description = "Main configuration", body = MainConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_main_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MainConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;

    let mut config_value =
        serde_json::to_value(&config.main).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    redact_admin_token(&mut config_value);

    Ok(Json(MainConfigResponse {
        config: config_value,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMainConfigRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    put,
    path = "/api/config/main",
    request_body = UpdateMainConfigRequest,
    responses(
        (status = 200, description = "Configuration updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_main_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMainConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let main_config: crate::config::main::MainConfig = serde_json::from_value(req.config.clone())
        .map_err(|e| {
        tracing::error!("Failed to parse config: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    main_config.validate().map_err(|e| {
        tracing::error!("Config validation failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let toml_content = toml::to_string_pretty(&main_config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let config_dir = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.clone()
    };

    let main_config_path = config_dir.join("main.toml");

    {
        let _guard = state.metrics.config_write_lock.write().await;
        tokio::fs::write(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    {
        let mut cfg = state.process.config.write().await;
        if cfg.load_main(&main_config_path).is_ok() {
            cfg.discover_sites();
        }
    }

    if let Some(ref pm) = state.process.process_manager {
        pm.broadcast_config_reload(config_dir).await;
    }

    state.audit.log(AuditLog::new(
        None,
        Some("admin".to_string()),
        "update_main_config".to_string(),
        "config/main".to_string(),
        "unknown".to_string(),
        None,
        Some("Main configuration updated".to_string()),
        true,
    ));

    Ok(Json(StatusResponse::success(
        "Configuration updated and reloaded to workers.",
    )))
}

#[utoipa::path(
    get,
    path = "/api/config/schema",
    responses(
        (status = 200, description = "JSON Schema of configuration"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_config_schema(_auth: OptionalAuth) -> Result<Json<serde_json::Value>, StatusCode> {
    let schema = schema_for!(crate::config::main::MainConfig);
    Ok(Json(
        serde_json::to_value(schema).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/config/reload",
    responses(
        (status = 200, description = "Configuration reloaded", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn reload_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _config_dir = {
        let config = state.process.config.read().await;
        config.config_dir.clone()
    };

    let mut config = state.process.config.write().await;
    let results = config.reload_all();

    let loaded = results.iter().filter(|r| r.1.is_ok()).count();
    let failed = results.iter().filter(|r| r.1.is_err()).count();

    let mimes_config = &config.main.mimes;
    let mut mimes_reloaded = false;
    let mut mimes_error = None;

    if mimes_config.enabled {
        if let Some(ref mimes_file) = mimes_config.file {
            match crate::mime::reload_mimes_from_file(mimes_file) {
                Ok(()) => {
                    mimes_reloaded = true;
                }
                Err(e) => {
                    mimes_error = Some(e.to_string());
                }
            }
        }
    }

    // Only broadcast to workers if all reloads succeeded
    let broadcast_success = failed == 0;

    drop(config);
    if broadcast_success {
        if let Some(ref pm) = state.process.process_manager {
            let config_dir = state.process.config.read().await.config_dir.clone();
            pm.broadcast_config_reload(config_dir).await;
        }
    }

    let message = if mimes_reloaded {
        if broadcast_success {
            format!(
                "Reloaded {} configs, {} failed, mimes reloaded, workers notified",
                loaded, failed
            )
        } else {
            format!(
                "Reloaded {} configs, {} failed (workers not notified)",
                loaded, failed
            )
        }
    } else if let Some(err) = mimes_error {
        if broadcast_success {
            format!(
                "Reloaded {} configs, {} failed, mimes reload failed: {}, workers notified",
                loaded, failed, err
            )
        } else {
            format!(
                "Reloaded {} configs, {} failed, mimes reload failed: {} (workers not notified)",
                loaded, failed, err
            )
        }
    } else if broadcast_success {
        format!(
            "Reloaded {} configs, {} failed, workers notified",
            loaded, failed
        )
    } else {
        format!(
            "Reloaded {} configs, {} failed (workers not notified)",
            loaded, failed
        )
    };

    Ok(Json(StatusResponse {
        status: if failed == 0 { "success" } else { "partial" }.to_string(),
        message,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetLogLevelRequest {
    pub level: String,
}

#[utoipa::path(
    put,
    path = "/api/config/log-level",
    request_body = SetLogLevelRequest,
    responses(
        (status = 200, description = "Log level set", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid log level"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn set_log_level(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<SetLogLevelRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    match log_controller::set_log_level(&req.level) {
        Ok(level) => Ok(Json(StatusResponse {
            status: "success".to_string(),
            message: format!("Log level set to {}", level),
        })),
        Err(e) => {
            tracing::warn!("Invalid log level request: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/config/log-level",
    responses(
        (status = 200, description = "Current log level", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_log_level(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    let level = log_controller::get_log_level();
    Ok(Json(StatusResponse {
        status: "success".to_string(),
        message: format!("Current log level: {}", level),
    }))
}

#[utoipa::path(
    get,
    path = "/api/config/export",
    responses(
        (status = 200, description = "Exported configuration as TOML"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn export_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<String, StatusCode> {
    let config = state.process.config.read().await;
    let toml_content = toml::to_string_pretty(&config.main).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(toml_content)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportConfigRequest {
    pub config: String,
}

fn validate_config_paths(content: &str) -> Result<(), String> {
    let parsed: toml::Value = toml::from_str(content)
        .map_err(|e| format!("Failed to parse TOML for path validation: {}", e))?;

    let sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh",
        "/root/.ssh",
        "/proc/",
        "/sys/",
        "/dev/",
    ];

    fn check_value(
        value: &toml::Value,
        key: &str,
        sensitive: &[&str],
        violations: &mut Vec<String>,
    ) {
        match value {
            toml::Value::String(s) => {
                let is_path_key = key.ends_with("_path")
                    || key.ends_with("_dir")
                    || key.ends_with("_file")
                    || s.contains('/')
                    || s.contains('\\');

                if is_path_key {
                    if s.contains("..") {
                        violations.push(format!("Path traversal detected in '{}': '{}'", key, s));
                    }
                    let lower = s.to_lowercase();
                    for sensitive_path in sensitive {
                        if lower.starts_with(&sensitive_path.to_lowercase()) {
                            violations
                                .push(format!("Sensitive path reference in '{}': '{}'", key, s));
                            break;
                        }
                    }
                }
            }
            toml::Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    check_value(item, &format!("{}[{}]", key, i), sensitive, violations);
                }
            }
            toml::Value::Table(table) => {
                for (k, v) in table {
                    check_value(v, &format!("{}.{}", key, k), sensitive, violations);
                }
            }
            _ => {}
        }
    }

    let mut violations = Vec::new();
    if let toml::Value::Table(table) = &parsed {
        for (k, v) in table {
            check_value(v, k, &sensitive_paths, &mut violations);
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

#[utoipa::path(
    post,
    path = "/api/config/import",
    request_body = ImportConfigRequest,
    responses(
        (status = 200, description = "Configuration imported", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn import_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<ImportConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    validate_config_paths(&req.config).map_err(|e| {
        tracing::error!("Config path validation failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let parsed: crate::config::main::MainConfig = toml::from_str(&req.config).map_err(|e| {
        tracing::error!("Failed to parse config TOML: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    parsed.validate().map_err(|e| {
        tracing::error!("Config validation failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let toml_content = toml::to_string_pretty(&parsed).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let main_config_path = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.join("main.toml")
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

    let mut config = state.process.config.write().await;
    if let Err(e) = config.load_main(&main_config_path) {
        tracing::error!("Failed to reload imported config in memory: {}", e);
    }
    drop(config);

    if let Some(ref pm) = state.process.process_manager {
        let config_dir = state.process.config.read().await.config_dir.clone();
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(Json(StatusResponse::success(
        "Configuration imported and reloaded.",
    )))
}

use crate::utils::check_regex_complexity;

#[derive(Debug, Serialize, ToSchema)]
pub struct RegexCheckResult {
    pub pattern: String,
    pub safe: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckRegexRequest {
    pub pattern: String,
}

#[utoipa::path(
    post,
    path = "/api/config/check-regex",
    request_body = CheckRegexRequest,
    responses(
        (status = 200, description = "Regex check result", body = RegexCheckResult),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn check_regex(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CheckRegexRequest>,
) -> Result<Json<RegexCheckResult>, StatusCode> {
    let result = check_regex_complexity(&req.pattern);

    Ok(Json(RegexCheckResult {
        pattern: req.pattern,
        safe: result.safe,
        reason: result.reason,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OverseerConfigResponse {
    pub config: crate::config::OverseerConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOverseerConfigRequest {
    pub config: crate::config::OverseerConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/overseer",
    responses(
        (status = 200, description = "Overseer configuration", body = OverseerConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_overseer_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<OverseerConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(OverseerConfigResponse {
        config: config.main.overseer.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/overseer",
    request_body = UpdateOverseerConfigRequest,
    responses(
        (status = 200, description = "Overseer config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_overseer_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateOverseerConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    let main_config_path = {
        let mut config = state.process.config.write().await;
        config.main.overseer = req.config.clone();
        config.main.validate().map_err(|e| {
            tracing::error!("Config validation failed: {}", e);
            StatusCode::BAD_REQUEST
        })?;
        config.config_dir.join("main.toml")
    };

    let config = state.process.config.read().await;
    let toml_content = toml::to_string_pretty(&config.main).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    drop(config);

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let reload_path = std::env::current_dir()
        .map_err(|e| {
            tracing::error!("Failed to get current dir: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .join(".overseer_reload");

    if let Err(e) = tokio::fs::write(&reload_path, "1").await {
        tracing::warn!("Failed to write overseer reload signal: {}", e);
    } else {
        tracing::info!("Overseer reload signal written to {:?}", reload_path);
    }

    tracing::info!("Overseer config updated - reload signal sent");

    Ok(Json(StatusResponse::success(
        "Overseer config updated and reload signal sent.",
    )))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessManagerConfigResponse {
    pub config: crate::config::ProcessManagerConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProcessManagerConfigRequest {
    pub config: crate::config::ProcessManagerConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/process-manager",
    responses(
        (status = 200, description = "Process manager configuration", body = ProcessManagerConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_process_manager_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ProcessManagerConfigResponse>, StatusCode> {
    if let Some(ref pm) = state.process.process_manager {
        Ok(Json(ProcessManagerConfigResponse {
            config: pm.get_config(),
        }))
    } else {
        let config = state.process.config.read().await;
        Ok(Json(ProcessManagerConfigResponse {
            config: config.main.process_manager.clone(),
        }))
    }
}

#[utoipa::path(
    put,
    path = "/api/config/process-manager",
    request_body = UpdateProcessManagerConfigRequest,
    responses(
        (status = 200, description = "Process manager config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_process_manager_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateProcessManagerConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let needs_restart = if let Some(ref pm) = state.process.process_manager {
        match pm.update_config(req.config.clone()) {
            Ok(restart_needed) => {
                tracing::info!("Process manager config updated dynamically");
                restart_needed
            }
            Err(e) => {
                tracing::error!("Failed to update process manager config: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    } else {
        true
    };

    let _guard = state.metrics.config_write_lock.write().await;

    let (main_config_path, toml_content) = {
        let mut config = state.process.config.write().await;
        config.main.process_manager = req.config;
        config.main.validate().map_err(|e| {
            tracing::error!("Config validation failed: {}", e);
            StatusCode::BAD_REQUEST
        })?;
        let path = config.config_dir.join("main.toml");
        let content = toml::to_string_pretty(&config.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        (path, content)
    };

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if needs_restart {
        Ok(Json(StatusResponse::success(
            "Process manager config updated. Restart required for changes to take effect.",
        )))
    } else {
        Ok(Json(StatusResponse::success(
            "Process manager config updated and applied dynamically.",
        )))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SupervisorConfigResponse {
    pub config: crate::config::SupervisorConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSupervisorConfigRequest {
    pub config: crate::config::SupervisorConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/supervisor",
    responses(
        (status = 200, description = "Supervisor configuration", body = SupervisorConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_supervisor_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SupervisorConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SupervisorConfigResponse {
        config: config.main.supervisor.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/supervisor",
    request_body = UpdateSupervisorConfigRequest,
    responses(
        (status = 200, description = "Supervisor config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_supervisor_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateSupervisorConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.supervisor = req.config.clone();
    }

    let main_config_path = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.join("main.toml")
    };

    let toml_content = tokio::fs::read_to_string(&main_config_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut main_config: crate::config::MainConfig =
        toml::from_str(&toml_content).map_err(|e| {
            tracing::error!("Failed to parse main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    main_config.supervisor = req.config;

    main_config.validate().map_err(|e| {
        tracing::error!("Config validation failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let toml_content = toml::to_string_pretty(&main_config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let reload_path = std::env::current_dir()
        .map_err(|e| {
            tracing::error!("Failed to get current dir: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .join(".worker_reload");

    if let Err(e) = tokio::fs::write(&reload_path, "1").await {
        tracing::warn!("Failed to write worker reload signal: {}", e);
    } else {
        tracing::info!("Worker reload signal written to {:?}", reload_path);
    }

    if let Some(ref pm) = state.process.process_manager {
        pm.reload_config();
    }

    tracing::info!("Supervisor config updated - reload signal sent to workers");

    Ok(Json(StatusResponse::success(
        "Supervisor config updated and reload signal sent to workers.",
    )))
}

// --- TLS config ---

#[derive(Debug, Serialize)]
pub struct TlsConfigResponse {
    pub config: crate::config::tls::TlsConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTlsConfigRequest {
    pub config: crate::config::tls::TlsConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/tls",
    responses(
        (status = 200, description = "TLS configuration", body = TlsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_tls_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TlsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TlsConfigResponse {
        config: config.main.tls.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/tls",
    request_body = UpdateTlsConfigRequest,
    responses(
        (status = 200, description = "TLS config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_tls_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTlsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tls = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("TLS config updated.")))
}

// --- HTTP config ---

#[derive(Debug, Serialize)]
pub struct HttpConfigResponse {
    pub config: crate::config::http::HttpConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateHttpConfigRequest {
    pub config: crate::config::http::HttpConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/http",
    responses(
        (status = 200, description = "HTTP configuration", body = HttpConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_http_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HttpConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(HttpConfigResponse {
        config: config.main.http.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/http",
    request_body = UpdateHttpConfigRequest,
    responses(
        (status = 200, description = "HTTP config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_http_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateHttpConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.http = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("HTTP config updated.")))
}

// --- ACME config ---

#[derive(Debug, Serialize)]
pub struct AcmeConfigResponse {
    pub config: crate::config::tls::AcmeConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAcmeConfigRequest {
    pub config: crate::config::tls::AcmeConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/acme",
    responses(
        (status = 200, description = "ACME configuration", body = AcmeConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_acme_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AcmeConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(AcmeConfigResponse {
        config: config.main.tls.acme.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/acme",
    request_body = UpdateAcmeConfigRequest,
    responses(
        (status = 200, description = "ACME config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_acme_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateAcmeConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tls.acme = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("ACME config updated.")))
}

// --- HTTP/3 config ---

#[derive(Debug, Serialize)]
pub struct Http3ConfigResponse {
    pub config: crate::config::http::Http3Config,
}

#[derive(Debug, Deserialize)]
pub struct UpdateHttp3ConfigRequest {
    pub config: crate::config::http::Http3Config,
}

#[utoipa::path(
    get,
    path = "/api/config/http3",
    responses(
        (status = 200, description = "HTTP/3 configuration", body = Http3ConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_http3_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Http3ConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(Http3ConfigResponse {
        config: config.main.http3.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/http3",
    request_body = UpdateHttp3ConfigRequest,
    responses(
        (status = 200, description = "HTTP/3 config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_http3_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateHttp3ConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.http3 = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("HTTP/3 config updated.")))
}

// --- Security config ---

#[derive(Debug, Serialize)]
pub struct SecurityConfigResponse {
    pub config: crate::config::security::MainSecurityConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecurityConfigRequest {
    pub config: crate::config::security::MainSecurityConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/security",
    responses(
        (status = 200, description = "Security configuration", body = SecurityConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_security_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SecurityConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SecurityConfigResponse {
        config: config.main.security.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/security",
    request_body = UpdateSecurityConfigRequest,
    responses(
        (status = 200, description = "Security config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_security_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateSecurityConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.security = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Security config updated.")))
}

// --- Tunnel config ---

#[derive(Debug, Serialize)]
pub struct TunnelConfigResponse {
    pub config: crate::config::tunnel::TunnelConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTunnelConfigRequest {
    pub config: crate::config::tunnel::TunnelConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/tunnel",
    responses(
        (status = 200, description = "Tunnel configuration", body = TunnelConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_tunnel_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TunnelConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TunnelConfigResponse {
        config: config.main.tunnel.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/tunnel",
    request_body = UpdateTunnelConfigRequest,
    responses(
        (status = 200, description = "Tunnel config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_tunnel_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTunnelConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tunnel = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Tunnel config updated.")))
}

// --- Plugins config ---

#[derive(Debug, Serialize)]
pub struct PluginsConfigResponse {
    pub config: crate::config::plugins::PluginConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePluginsConfigRequest {
    pub config: crate::config::plugins::PluginConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/plugins",
    responses(
        (status = 200, description = "Plugins configuration", body = PluginsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_plugins_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PluginsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(PluginsConfigResponse {
        config: config.main.plugins.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/plugins",
    request_body = UpdatePluginsConfigRequest,
    responses(
        (status = 200, description = "Plugins config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_plugins_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdatePluginsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.plugins = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Plugins config updated.")))
}

// --- Logging config ---

#[derive(Debug, Serialize)]
pub struct LoggingConfigResponse {
    pub config: crate::config::logging::LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateLoggingConfigRequest {
    pub config: crate::config::logging::LoggingConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/logging",
    responses(
        (status = 200, description = "Logging configuration", body = LoggingConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_logging_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<LoggingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(LoggingConfigResponse {
        config: config.main.logging.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/logging",
    request_body = UpdateLoggingConfigRequest,
    responses(
        (status = 200, description = "Logging config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_logging_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateLoggingConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.logging = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Logging config updated.")))
}

// --- Traffic shaping config ---

#[derive(Debug, Serialize)]
pub struct TrafficShapingConfigResponse {
    pub config: crate::config::traffic::TrafficShapingConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTrafficShapingConfigRequest {
    pub config: crate::config::traffic::TrafficShapingConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/traffic-shaping",
    responses(
        (status = 200, description = "Traffic shaping configuration", body = TrafficShapingConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_traffic_shaping_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TrafficShapingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TrafficShapingConfigResponse {
        config: config.main.traffic_shaping.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/traffic-shaping",
    request_body = UpdateTrafficShapingConfigRequest,
    responses(
        (status = 200, description = "Traffic shaping config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_traffic_shaping_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTrafficShapingConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.traffic_shaping = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Traffic shaping config updated.",
    )))
}

// --- Threat level config ---

#[derive(Debug, Serialize)]
pub struct ThreatLevelConfigResponse {
    pub config: crate::config::protection::ThreatLevelConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateThreatLevelConfigRequest {
    pub config: crate::config::protection::ThreatLevelConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/threat-level",
    responses(
        (status = 200, description = "Threat level configuration", body = ThreatLevelConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_threat_level_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ThreatLevelConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(ThreatLevelConfigResponse {
        config: config.main.threat_level.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/threat-level",
    request_body = UpdateThreatLevelConfigRequest,
    responses(
        (status = 200, description = "Threat level config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_threat_level_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateThreatLevelConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.threat_level = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Threat level config updated.",
    )))
}

// --- IP feeds config ---

#[derive(Debug, Serialize)]
pub struct IpFeedsConfigResponse {
    pub config: crate::config::protection::IpFeedConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIpFeedsConfigRequest {
    pub config: crate::config::protection::IpFeedConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/ip-feeds",
    responses(
        (status = 200, description = "IP feeds configuration", body = IpFeedsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_ip_feeds_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IpFeedsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(IpFeedsConfigResponse {
        config: config.main.ip_feeds.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/ip-feeds",
    request_body = UpdateIpFeedsConfigRequest,
    responses(
        (status = 200, description = "IP feeds config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_ip_feeds_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateIpFeedsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.ip_feeds = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("IP feeds config updated.")))
}

// --- DNS config (feature-gated) ---

#[cfg(feature = "dns")]
#[derive(Debug, Serialize)]
pub struct DnsConfigResponse {
    pub config: crate::config::dns::DnsConfig,
}

#[cfg(feature = "dns")]
#[derive(Debug, Deserialize)]
pub struct UpdateDnsConfigRequest {
    pub config: crate::config::dns::DnsConfig,
}

#[cfg(feature = "dns")]
#[utoipa::path(
    get,
    path = "/api/config/dns",
    responses(
        (status = 200, description = "DNS configuration", body = DnsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_dns_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<DnsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(DnsConfigResponse {
        config: config.main.dns.clone(),
    }))
}

#[cfg(feature = "dns")]
#[utoipa::path(
    put,
    path = "/api/config/dns",
    request_body = UpdateDnsConfigRequest,
    responses(
        (status = 200, description = "DNS config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_dns_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateDnsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.dns = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("DNS config updated.")))
}

// --- Rate limits config ---

#[derive(Debug, Serialize)]
pub struct RateLimitsConfigResponse {
    pub rate_limit_memory: crate::config::limits::RateLimitMemoryConfig,
    pub proxy_limits: crate::config::limits::ProxyLimitsConfig,
    pub blocklist_limits: crate::config::limits::BlocklistLimitsConfig,
    pub defaults: crate::config::defaults::RateLimitDefaults,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRateLimitsConfigRequest {
    pub rate_limit_memory: Option<crate::config::limits::RateLimitMemoryConfig>,
    pub proxy_limits: Option<crate::config::limits::ProxyLimitsConfig>,
    pub blocklist_limits: Option<crate::config::limits::BlocklistLimitsConfig>,
    pub defaults: Option<crate::config::defaults::RateLimitDefaults>,
}

#[utoipa::path(
    get,
    path = "/api/config/rate-limits",
    responses(
        (status = 200, description = "Rate limits configuration", body = RateLimitsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_rate_limits_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RateLimitsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(RateLimitsConfigResponse {
        rate_limit_memory: config.main.rate_limit_memory.clone(),
        proxy_limits: config.main.proxy_limits.clone(),
        blocklist_limits: config.main.blocklist_limits.clone(),
        defaults: config.main.defaults.ratelimit.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/rate-limits",
    request_body = UpdateRateLimitsConfigRequest,
    responses(
        (status = 200, description = "Rate limits config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_rate_limits_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateRateLimitsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        if let Some(v) = req.rate_limit_memory {
            config.main.rate_limit_memory = v;
        }
        if let Some(v) = req.proxy_limits {
            config.main.proxy_limits = v;
        }
        if let Some(v) = req.blocklist_limits {
            config.main.blocklist_limits = v;
        }
        if let Some(v) = req.defaults {
            config.main.defaults.ratelimit = v;
        }
    }

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Rate limits config updated.")))
}

// --- Bot detection config ---

#[derive(Debug, Serialize)]
pub struct BotDetectionConfigResponse {
    pub config: crate::config::defaults::BotDefaults,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBotDetectionConfigRequest {
    pub config: crate::config::defaults::BotDefaults,
}

#[utoipa::path(
    get,
    path = "/api/config/bot-detection",
    responses(
        (status = 200, description = "Bot detection configuration", body = BotDetectionConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_bot_detection_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BotDetectionConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(BotDetectionConfigResponse {
        config: config.main.defaults.bot.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/bot-detection",
    request_body = UpdateBotDetectionConfigRequest,
    responses(
        (status = 200, description = "Bot detection config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_bot_detection_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateBotDetectionConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.defaults.bot = req.config;
    }

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "Bot detection config updated.",
    )))
}

// --- Mesh config ---

#[derive(Debug, Serialize)]
pub struct MeshConfigResponse {
    pub config: Option<crate::config::mesh::MeshConfig>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMeshConfigRequest {
    pub config: Option<crate::config::mesh::MeshConfig>,
}

#[utoipa::path(
    get,
    path = "/api/config/mesh",
    responses(
        (status = 200, description = "Mesh configuration", body = MeshConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_mesh_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MeshConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(MeshConfigResponse {
        config: config.main.mesh.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/mesh",
    request_body = UpdateMeshConfigRequest,
    responses(
        (status = 200, description = "Mesh config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_mesh_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMeshConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    {
        let mut config = state.process.config.write().await;
        config.main.mesh = req.config;
    }

    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Mesh config updated.")))
}

// --- Mime types config ---

#[derive(Debug, Serialize)]
pub struct MimeTypesConfigResponse {
    pub config: crate::config::protection::MimesConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMimeTypesConfigRequest {
    pub config: crate::config::protection::MimesConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/mime-types",
    responses(
        (status = 200, description = "MIME types configuration", body = MimeTypesConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_mime_types_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MimeTypesConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(MimeTypesConfigResponse {
        config: config.main.mimes.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/mime-types",
    request_body = UpdateMimeTypesConfigRequest,
    responses(
        (status = 200, description = "MIME types config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_mime_types_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMimeTypesConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.mimes = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("MIME types config updated.")))
}

// --- TCP/UDP Defaults config ---

#[derive(Debug, Serialize)]
pub struct TcpUdpDefaultsConfigResponse {
    pub tcp: crate::config::network::TcpDefaults,
    pub udp: crate::config::network::UdpDefaults,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTcpUdpDefaultsConfigRequest {
    pub tcp: Option<crate::config::network::TcpDefaults>,
    pub udp: Option<crate::config::network::UdpDefaults>,
}

#[utoipa::path(
    get,
    path = "/api/config/tcp-udp-defaults",
    responses(
        (status = 200, description = "TCP/UDP defaults configuration", body = TcpUdpDefaultsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_tcp_udp_defaults_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TcpUdpDefaultsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TcpUdpDefaultsConfigResponse {
        tcp: config.main.tcp.clone(),
        udp: config.main.udp.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/tcp-udp-defaults",
    request_body = UpdateTcpUdpDefaultsConfigRequest,
    responses(
        (status = 200, description = "TCP/UDP defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_tcp_udp_defaults_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTcpUdpDefaultsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        if let Some(tcp) = req.tcp {
            config.main.tcp = tcp;
        }
        if let Some(udp) = req.udp {
            config.main.udp = udp;
        }
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success(
        "TCP/UDP defaults config updated.",
    )))
}

// --- Fallback config ---

#[derive(Debug, Serialize)]
pub struct FallbackConfigResponse {
    pub config: crate::config::server::FallbackConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFallbackConfigRequest {
    pub config: crate::config::server::FallbackConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/fallback",
    responses(
        (status = 200, description = "Fallback configuration", body = FallbackConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_fallback_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<FallbackConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(FallbackConfigResponse {
        config: config.main.fallback.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/fallback",
    request_body = UpdateFallbackConfigRequest,
    responses(
        (status = 200, description = "Fallback config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_fallback_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateFallbackConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.fallback = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Fallback config updated.")))
}

// --- Upgrade config ---

#[derive(Debug, Serialize)]
pub struct UpgradeConfigResponse {
    pub config: Option<crate::config::upgrade::UpgradeConfig>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUpgradeConfigRequest {
    pub config: Option<crate::config::upgrade::UpgradeConfig>,
}

#[utoipa::path(
    get,
    path = "/api/config/upgrade",
    responses(
        (status = 200, description = "Upgrade configuration", body = UpgradeConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_upgrade_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<UpgradeConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(UpgradeConfigResponse {
        config: config.main.upgrade.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/upgrade",
    request_body = UpdateUpgradeConfigRequest,
    responses(
        (status = 200, description = "Upgrade config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_upgrade_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateUpgradeConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.upgrade = req.config;
    }
    persist_main_config_and_notify(&state).await?;
    Ok(Json(StatusResponse::success("Upgrade config updated.")))
}

// --- Validate config ---

#[derive(Debug, Deserialize)]
pub struct ValidateConfigRequest {
    pub config: crate::config::main::MainConfig,
}

#[derive(Debug, Serialize)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub errors: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/api/config/validate",
    request_body = ValidateConfigRequest,
    responses(
        (status = 200, description = "Configuration validation result", body = ValidateConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn validate_config(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<ValidateConfigRequest>,
) -> Result<Json<ValidateConfigResponse>, StatusCode> {
    match req.config.validate() {
        Ok(()) => Ok(Json(ValidateConfigResponse {
            valid: true,
            errors: vec![],
        })),
        Err(e) => Ok(Json(ValidateConfigResponse {
            valid: false,
            errors: vec![format!("{}: {}", e.field, e.message)],
        })),
    }
}

// --- Bulk Config Bundle ---

#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigBundleResponse {
    pub config: crate::config::main::MainConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateConfigBundleRequest {
    pub config: crate::config::main::MainConfig,
}

#[utoipa::path(
    get,
    path = "/api/config/bundle",
    responses(
        (status = 200, description = "Full configuration bundle", body = ConfigBundleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_config_bundle(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ConfigBundleResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(ConfigBundleResponse {
        config: config.main.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/api/config/bundle",
    request_body = UpdateConfigBundleRequest,
    responses(
        (status = 200, description = "Configuration bundle updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_config_bundle(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateConfigBundleRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    req.config.validate().map_err(|e| {
        tracing::error!("Config validation failed: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let toml_content = toml::to_string_pretty(&req.config).map_err(|e| {
        tracing::error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let config_dir = {
        let cfg = state.process.config.read().await;
        cfg.config_dir.clone()
    };

    let main_config_path = config_dir.join("main.toml");

    {
        let _guard = state.metrics.config_write_lock.write().await;
        tokio::fs::write(&main_config_path, toml_content)
            .await
            .map_err(|e| {
                tracing::error!("Failed to write main config: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    {
        let mut cfg = state.process.config.write().await;
        if cfg.load_main(&main_config_path).is_ok() {
            cfg.discover_sites();
        }
    }

    if let Some(ref pm) = state.process.process_manager {
        pm.broadcast_config_reload(config_dir).await;
    }

    state.audit.log(AuditLog::new(
        None,
        Some("admin".to_string()),
        "update_config_bundle".to_string(),
        "config/bundle".to_string(),
        "unknown".to_string(),
        None,
        Some("Full configuration bundle updated".to_string()),
        true,
    ));

    Ok(Json(StatusResponse::success(
        "Configuration bundle updated and reloaded to workers.",
    )))
}

// --- Helper: persist MainConfig to TOML file ---

async fn persist_main_config_and_notify(state: &Arc<AdminState>) -> Result<(), StatusCode> {
    let (main_config_path, toml_content, config_dir) = {
        let config = state.process.config.read().await;
        config.main.validate().map_err(|e| {
            tracing::error!("Config validation failed: {}", e);
            StatusCode::BAD_REQUEST
        })?;
        let path = config.config_dir.join("main.toml");
        let content = toml::to_string_pretty(&config.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        (path, content, config.config_dir.clone())
    };

    tokio::fs::write(&main_config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write main config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Broadcast config reload to workers
    if let Some(ref pm) = state.process.process_manager {
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(())
}

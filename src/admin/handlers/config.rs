use super::super::audit::{AuditLog, ConfigVersion};
use super::super::state::AdminState;
use crate::log_controller;
use axum::{extract::State, http::StatusCode, Json};
use regex::Regex;
use schemars::schema_for;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
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
    path = "/config/main",
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
    path = "/config/main",
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
    // Save snapshot before making changes
    save_config_snapshot(&state, Some("Before update_main_config".to_string())).await?;

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
    path = "/config/schema",
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
    path = "/config/reload",
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
    let mesh_enabled = {
        let config = state.process.config.read().await;
        config
            .main
            .mesh
            .as_ref()
            .map(|m| m.enabled)
            .unwrap_or(false)
    };

    if mesh_enabled {
        return Ok(Json(StatusResponse::restart_required(
            "Config hot-reload is not supported when mesh feature is enabled. Mesh, \
            YARA rules, threat intel, and honeypot changes require full worker restart. \
            Please restart the worker to apply mesh-related configuration changes.",
        )));
    }

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
                "Hot reload applied: {} configs reloaded, {} failed, mimes reloaded, workers notified",
                loaded, failed
            )
        } else {
            format!(
                "Partial reload: {} configs reloaded, {} failed (workers not notified)",
                loaded, failed
            )
        }
    } else if let Some(err) = mimes_error {
        if broadcast_success {
            format!(
                "Hot reload applied: {} configs reloaded, {} failed, mimes reload failed: {}, workers notified",
                loaded, failed, err
            )
        } else {
            format!(
                "Partial reload: {} configs reloaded, {} failed, mimes reload failed: {} (workers not notified)",
                loaded, failed, err
            )
        }
    } else if broadcast_success {
        format!(
            "Hot reload applied: {} configs reloaded, {} failed, workers notified",
            loaded, failed
        )
    } else {
        format!(
            "Partial reload: {} configs reloaded, {} failed (workers not notified)",
            loaded, failed
        )
    };

    if failed == 0 {
        Ok(Json(StatusResponse::hot_reload_applied(message)))
    } else {
        Ok(Json(StatusResponse::partial_reload(message)))
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetLogLevelRequest {
    pub level: String,
}

#[utoipa::path(
    put,
    path = "/config/log-level",
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
    path = "/config/log-level",
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
    path = "/config/export",
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
    path = "/config/import",
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
    save_config_snapshot(&state, Some("Before import_config".to_string())).await?;

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
    path = "/config/check-regex",
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

    if result.safe {
        let start = Instant::now();
        match Regex::new(&req.pattern) {
            Ok(_) => {
                let elapsed = start.elapsed();
                if elapsed.as_millis() > 100 {
                    return Ok(Json(RegexCheckResult {
                        pattern: req.pattern,
                        safe: false,
                        reason: Some(format!(
                            "Regex compilation took {}ms (limit 100ms) - potential ReDoS",
                            elapsed.as_millis()
                        )),
                    }));
                }
            }
            Err(e) => {
                return Ok(Json(RegexCheckResult {
                    pattern: req.pattern,
                    safe: false,
                    reason: Some(format!("Invalid regex: {}", e)),
                }));
            }
        }
    }

    Ok(Json(RegexCheckResult {
        pattern: req.pattern,
        safe: result.safe,
        reason: result.reason,
    }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OverseerConfigResponse {
    pub config: crate::config::OverseerConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOverseerConfigRequest {
    pub config: crate::config::OverseerConfig,
}

#[utoipa::path(
    get,
    path = "/config/overseer",
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
    path = "/config/overseer",
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
    save_config_snapshot(&state, Some("Before update_overseer_config".to_string())).await?;

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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ProcessManagerConfigResponse {
    pub config: crate::config::ProcessManagerConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProcessManagerConfigRequest {
    pub config: crate::config::ProcessManagerConfig,
}

#[utoipa::path(
    get,
    path = "/config/process-manager",
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
    path = "/config/process-manager",
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
    save_config_snapshot(
        &state,
        Some("Before update_process_manager_config".to_string()),
    )
    .await?;

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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SupervisorConfigResponse {
    pub config: crate::config::SupervisorConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSupervisorConfigRequest {
    pub config: crate::config::SupervisorConfig,
}

#[utoipa::path(
    get,
    path = "/config/supervisor",
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
    path = "/config/supervisor",
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
    save_config_snapshot(&state, Some("Before update_supervisor_config".to_string())).await?;

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

#[derive(Debug, Serialize, ToSchema)]
pub struct TlsConfigResponse {
    pub config: crate::config::tls::TlsConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTlsConfigRequest {
    pub config: crate::config::tls::TlsConfig,
}

#[utoipa::path(
    get,
    path = "/config/tls",
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
    path = "/config/tls",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("TLS config updated.")))
}

// --- HTTP config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct HttpConfigResponse {
    pub config: crate::config::http::HttpConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateHttpConfigRequest {
    pub config: crate::config::http::HttpConfig,
}

#[utoipa::path(
    get,
    path = "/config/http",
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
    path = "/config/http",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("HTTP config updated.")))
}

// --- ACME config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct AcmeConfigResponse {
    pub config: crate::config::tls::AcmeConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAcmeConfigRequest {
    pub config: crate::config::tls::AcmeConfig,
}

#[utoipa::path(
    get,
    path = "/config/acme",
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
    path = "/config/acme",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("ACME config updated.")))
}

// --- HTTP/3 config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct Http3ConfigResponse {
    pub config: crate::config::http::Http3Config,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateHttp3ConfigRequest {
    pub config: crate::config::http::Http3Config,
}

#[utoipa::path(
    get,
    path = "/config/http3",
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
    path = "/config/http3",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("HTTP/3 config updated.")))
}

// --- Security config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityConfigResponse {
    pub config: crate::config::security::MainSecurityConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSecurityConfigRequest {
    pub config: crate::config::security::MainSecurityConfig,
}

#[utoipa::path(
    get,
    path = "/config/security",
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
    path = "/config/security",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Security config updated.")))
}

// --- Static config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct StaticConfigResponse {
    pub config: crate::config::security::MainStaticConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateStaticConfigRequest {
    pub config: crate::config::security::MainStaticConfig,
}

#[utoipa::path(
    get,
    path = "/config/static",
    responses(
        (status = 200, description = "Static configuration", body = StaticConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_static_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<StaticConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(StaticConfigResponse {
        config: config.main.static_config.clone().unwrap_or_default(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/static",
    request_body = UpdateStaticConfigRequest,
    responses(
        (status = 200, description = "Static config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_static_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateStaticConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.static_config = Some(req.config);
    }
    persist_with_snapshot(&state, "Static config updated").await?;
    Ok(Json(StatusResponse::success("Static config updated.")))
}

// --- Tunnel config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TunnelConfigResponse {
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTunnelConfigRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/config/tunnel",
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
        config: serde_json::to_value(&config.main.tunnel).map_err(|e| {
            tracing::error!("Failed to serialize tunnel config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
    }))
}

#[utoipa::path(
    put,
    path = "/config/tunnel",
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
    let tunnel_config: crate::config::tunnel::TunnelConfig = serde_json::from_value(req.config)
        .map_err(|e| {
            tracing::error!("Failed to parse tunnel config: {}", e);
            StatusCode::BAD_REQUEST
        })?;
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tunnel = tunnel_config;
    }
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Tunnel config updated.")))
}

// --- Plugins config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct PluginsConfigResponse {
    pub config: crate::config::plugins::PluginConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePluginsConfigRequest {
    pub config: crate::config::plugins::PluginConfig,
}

#[utoipa::path(
    get,
    path = "/config/plugins",
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
    path = "/config/plugins",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Plugins config updated.")))
}

// --- Logging config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct LoggingConfigResponse {
    pub config: crate::config::logging::LoggingConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLoggingConfigRequest {
    pub config: crate::config::logging::LoggingConfig,
}

#[utoipa::path(
    get,
    path = "/config/logging",
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
    path = "/config/logging",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Logging config updated.")))
}

// --- Metrics config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct MetricsConfigResponse {
    pub config: crate::config::admin::MetricsConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMetricsConfigRequest {
    pub config: crate::config::admin::MetricsConfig,
}

#[utoipa::path(
    get,
    path = "/config/metrics",
    responses(
        (status = 200, description = "Metrics configuration", body = MetricsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_metrics_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MetricsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(MetricsConfigResponse {
        config: config.main.metrics.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/metrics",
    request_body = UpdateMetricsConfigRequest,
    responses(
        (status = 200, description = "Metrics config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_metrics_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMetricsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.metrics = req.config;
    }
    persist_with_snapshot(&state, "Metrics config updated").await?;
    Ok(Json(StatusResponse::success("Metrics config updated.")))
}

// --- Tokio config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TokioConfigResponse {
    pub config: crate::config::http::TokioConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTokioConfigRequest {
    pub config: crate::config::http::TokioConfig,
}

#[utoipa::path(
    get,
    path = "/config/tokio",
    responses(
        (status = 200, description = "Tokio configuration", body = TokioConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_tokio_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TokioConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TokioConfigResponse {
        config: config.main.tokio.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/tokio",
    request_body = UpdateTokioConfigRequest,
    responses(
        (status = 200, description = "Tokio config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_tokio_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTokioConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.tokio = req.config;
    }
    persist_with_snapshot(&state, "Tokio config updated").await?;
    Ok(Json(StatusResponse::success("Tokio config updated.")))
}

// --- Traffic shaping config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TrafficShapingConfigResponse {
    pub config: crate::config::traffic::TrafficShapingConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTrafficShapingConfigRequest {
    pub config: crate::config::traffic::TrafficShapingConfig,
}

#[utoipa::path(
    get,
    path = "/config/traffic-shaping",
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
    path = "/config/traffic-shaping",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success(
        "Traffic shaping config updated.",
    )))
}

// --- Threat level config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct ThreatLevelConfigResponse {
    pub config: crate::config::protection::ThreatLevelConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateThreatLevelConfigRequest {
    pub config: crate::config::protection::ThreatLevelConfig,
}

#[utoipa::path(
    get,
    path = "/config/threat-level",
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
    path = "/config/threat-level",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success(
        "Threat level config updated.",
    )))
}

// --- IP feeds config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct IpFeedsConfigResponse {
    pub config: crate::config::protection::IpFeedConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIpFeedsConfigRequest {
    pub config: crate::config::protection::IpFeedConfig,
}

#[utoipa::path(
    get,
    path = "/config/ip-feeds",
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
    path = "/config/ip-feeds",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("IP feeds config updated.")))
}

// --- DNS config (feature-gated) ---

#[cfg(feature = "dns")]
#[derive(Debug, Serialize, ToSchema)]
pub struct DnsConfigResponse {
    pub config: serde_json::Value,
}

#[cfg(feature = "dns")]
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDnsConfigRequest {
    pub config: serde_json::Value,
}

#[cfg(feature = "dns")]
#[utoipa::path(
    get,
    path = "/config/dns",
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
        config: serde_json::to_value(&config.main.dns).map_err(|e| {
            tracing::error!("Failed to serialize DNS config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
    }))
}

#[cfg(feature = "dns")]
#[utoipa::path(
    put,
    path = "/config/dns",
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
    let dns_config: crate::config::dns::DnsConfig =
        serde_json::from_value(req.config).map_err(|e| {
            tracing::error!("Failed to parse DNS config: {}", e);
            StatusCode::BAD_REQUEST
        })?;
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.dns = dns_config;
    }
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("DNS config updated.")))
}

// --- Rate limits config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct RateLimitsConfigResponse {
    pub rate_limit_memory: crate::config::limits::RateLimitMemoryConfig,
    pub proxy_limits: crate::config::limits::ProxyLimitsConfig,
    pub blocklist_limits: crate::config::limits::BlocklistLimitsConfig,
    pub defaults: crate::config::defaults::RateLimitDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRateLimitsConfigRequest {
    pub rate_limit_memory: Option<crate::config::limits::RateLimitMemoryConfig>,
    pub proxy_limits: Option<crate::config::limits::ProxyLimitsConfig>,
    pub blocklist_limits: Option<crate::config::limits::BlocklistLimitsConfig>,
    pub defaults: Option<crate::config::defaults::RateLimitDefaults>,
}

#[utoipa::path(
    get,
    path = "/config/rate-limits",
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
    path = "/config/rate-limits",
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

    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Rate limits config updated.")))
}

// --- Bot detection config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct BotDetectionConfigResponse {
    pub config: crate::config::defaults::BotDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateBotDetectionConfigRequest {
    pub config: crate::config::defaults::BotDefaults,
}

#[utoipa::path(
    get,
    path = "/config/bot-detection",
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
    path = "/config/bot-detection",
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

    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success(
        "Bot detection config updated.",
    )))
}

// --- Mesh config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct MeshConfigResponse {
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMeshConfigRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/config/mesh",
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
    let mesh_value =
        serde_json::to_value(&config.main.mesh).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(MeshConfigResponse { config: mesh_value }))
}

#[utoipa::path(
    put,
    path = "/config/mesh",
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

    let mesh_config: crate::config::mesh::MeshConfig =
        serde_json::from_value(req.config).map_err(|_| StatusCode::BAD_REQUEST)?;

    {
        let mut config = state.process.config.write().await;
        config.main.mesh = Some(mesh_config);
    }

    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Mesh config updated.")))
}

// --- Mime types config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct MimeTypesConfigResponse {
    pub config: crate::config::protection::MimesConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMimeTypesConfigRequest {
    pub config: crate::config::protection::MimesConfig,
}

#[utoipa::path(
    get,
    path = "/config/mime-types",
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
    path = "/config/mime-types",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("MIME types config updated.")))
}

// --- TCP/UDP Defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TcpUdpDefaultsConfigResponse {
    pub tcp: crate::config::network::TcpDefaults,
    pub udp: crate::config::network::UdpDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTcpUdpDefaultsConfigRequest {
    pub tcp: Option<crate::config::network::TcpDefaults>,
    pub udp: Option<crate::config::network::UdpDefaults>,
}

#[utoipa::path(
    get,
    path = "/config/tcp-udp-defaults",
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
    path = "/config/tcp-udp-defaults",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success(
        "TCP/UDP defaults config updated.",
    )))
}

// --- Fallback config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct FallbackConfigResponse {
    pub config: crate::config::server::FallbackConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateFallbackConfigRequest {
    pub config: crate::config::server::FallbackConfig,
}

#[utoipa::path(
    get,
    path = "/config/fallback",
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
    path = "/config/fallback",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Fallback config updated.")))
}

// --- Upgrade config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct UpgradeConfigResponse {
    pub config: Option<crate::config::upgrade::UpgradeConfig>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUpgradeConfigRequest {
    pub config: Option<crate::config::upgrade::UpgradeConfig>,
}

#[utoipa::path(
    get,
    path = "/config/upgrade",
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
    path = "/config/upgrade",
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
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Upgrade config updated.")))
}

// --- Rule Feed config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleFeedConfigResponse {
    pub enabled: bool,
    pub url: String,
    pub update_interval_hours: u32,
    pub auto_apply: bool,
    pub allow_downgrade: bool,
    pub public_key_prefix: Option<String>,
    pub public_key_configured: bool,
    pub storage_dir: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRuleFeedConfigRequest {
    pub config: crate::config::RuleFeedConfig,
}

#[utoipa::path(
    get,
    path = "/config/rule-feed",
    responses(
        (status = 200, description = "Rule feed configuration", body = RuleFeedConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_rule_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<RuleFeedConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    let rule_feed = &config.main.rule_feed;
    let public_key_prefix = rule_feed.public_key.as_ref().map(|k| {
        if k.len() > 8 {
            format!("{}...", &k[..8])
        } else {
            k.clone()
        }
    });
    let storage_dir = rule_feed.storage_dir.as_ref().map(|d| {
        std::path::Path::new(d)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| d.clone())
    });
    Ok(Json(RuleFeedConfigResponse {
        enabled: rule_feed.enabled,
        url: rule_feed.url.clone(),
        update_interval_hours: rule_feed.update_interval_hours,
        auto_apply: rule_feed.auto_apply,
        allow_downgrade: rule_feed.allow_downgrade,
        public_key_prefix,
        public_key_configured: rule_feed.public_key.is_some(),
        storage_dir,
    }))
}

#[utoipa::path(
    put,
    path = "/config/rule-feed",
    request_body = UpdateRuleFeedConfigRequest,
    responses(
        (status = 200, description = "Rule feed config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_rule_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateRuleFeedConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.rule_feed = req.config;
    }
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("Rule feed config updated.")))
}

// --- YARA Feed config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct YaraFeedConfigResponse {
    pub enabled: bool,
    pub url: String,
    pub update_interval_hours: u32,
    pub elevated_interval_hours: u32,
    pub auto_apply: bool,
    pub allow_downgrade: bool,
    pub signer_public_key_prefix: Option<String>,
    pub signer_public_key_configured: bool,
    pub max_rules_size_kb: u32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateYaraFeedConfigRequest {
    pub config: crate::config::YaraRuleFeedConfig,
}

#[utoipa::path(
    get,
    path = "/config/yara-feed",
    responses(
        (status = 200, description = "YARA feed configuration", body = YaraFeedConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_yara_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<YaraFeedConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    let yara_feed = &config.main.yara_feed;
    let signer_public_key_prefix = if !yara_feed.signer_public_key.is_empty() {
        Some(if yara_feed.signer_public_key.len() > 8 {
            format!("{}...", &yara_feed.signer_public_key[..8])
        } else {
            yara_feed.signer_public_key.clone()
        })
    } else {
        None
    };
    Ok(Json(YaraFeedConfigResponse {
        enabled: yara_feed.enabled,
        url: yara_feed.url.clone(),
        update_interval_hours: yara_feed.update_interval_hours,
        elevated_interval_hours: yara_feed.elevated_interval_hours,
        auto_apply: yara_feed.auto_apply,
        allow_downgrade: yara_feed.allow_downgrade,
        signer_public_key_prefix,
        signer_public_key_configured: !yara_feed.signer_public_key.is_empty(),
        max_rules_size_kb: yara_feed.max_rules_size_kb,
    }))
}

#[utoipa::path(
    put,
    path = "/config/yara-feed",
    request_body = UpdateYaraFeedConfigRequest,
    responses(
        (status = 200, description = "YARA feed config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_yara_feed_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateYaraFeedConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.yara_feed = req.config;
    }
    persist_with_snapshot(&state, "TLS config updated").await?;
    Ok(Json(StatusResponse::success("YARA feed config updated.")))
}

// --- Validate config ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateConfigRequest {
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub errors: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/config/validate",
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
    let main_config: crate::config::main::MainConfig =
        serde_json::from_value(req.config).map_err(|_| StatusCode::BAD_REQUEST)?;
    match main_config.validate() {
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
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateConfigBundleRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/config/bundle",
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
        config: serde_json::to_value(config.main.clone()).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
    }))
}

#[utoipa::path(
    put,
    path = "/config/bundle",
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
    save_config_snapshot(&state, Some("Before update_config_bundle".to_string())).await?;

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

async fn save_config_snapshot(
    state: &Arc<AdminState>,
    description: Option<String>,
) -> Result<ConfigVersion, StatusCode> {
    let toml_content = {
        let config = state.process.config.read().await;
        let content = toml::to_string_pretty(&config.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        content
    };

    state
        .config_versions
        .save_version(&toml_content, description)
        .map_err(|e| {
            tracing::error!("Failed to save config version: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn persist_with_snapshot(
    state: &Arc<AdminState>,
    description: &str,
) -> Result<(), StatusCode> {
    save_config_snapshot(state, Some(description.to_string())).await?;
    persist_main_config_and_notify(state).await
}

// --- Config Versions ---

#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigVersionsResponse {
    pub versions: Vec<ConfigVersion>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigVersionContentResponse {
    pub version: ConfigVersion,
    pub content: String,
}

#[utoipa::path(
    get,
    path = "/config/versions",
    responses(
        (status = 200, description = "List of config versions", body = ConfigVersionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn list_config_versions(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ConfigVersionsResponse>, StatusCode> {
    let versions = state.config_versions.list_versions();
    Ok(Json(ConfigVersionsResponse { versions }))
}

#[utoipa::path(
    get,
    path = "/config/versions/{id}",
    responses(
        (status = 200, description = "Config version content", body = ConfigVersionContentResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Version not found")
    ),
    tag = "config"
)]
pub async fn get_config_version(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<ConfigVersionContentResponse>, StatusCode> {
    let version = state
        .config_versions
        .get_version(&id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let content = state
        .config_versions
        .get_version_content(&id)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ConfigVersionContentResponse { version, content }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RollbackRequest {
    #[allow(dead_code)]
    pub description: Option<String>,
}

#[utoipa::path(
    post,
    path = "/config/rollback/{id}",
    responses(
        (status = 200, description = "Config rolled back", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Version not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn rollback_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(_req): Json<RollbackRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    // Save current config as a version before rolling back
    let current_content = {
        let config = state.process.config.read().await;
        toml::to_string_pretty(&config.main).map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    let _ = state
        .config_versions
        .save_version(&current_content, Some(format!("Before rollback to {}", id)));

    let main_config_path = {
        let config = state.process.config.read().await;
        config.config_dir.join("main.toml")
    };

    state
        .config_versions
        .rollback(&id, &main_config_path)
        .map_err(|e| {
            tracing::error!("Failed to rollback config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Reload config in memory
    {
        let mut cfg = state.process.config.write().await;
        if cfg.load_main(&main_config_path).is_ok() {
            cfg.discover_sites();
        }
    }

    // Broadcast to workers
    if let Some(ref pm) = state.process.process_manager {
        let config_dir = state.process.config.read().await.config_dir.clone();
        pm.broadcast_config_reload(config_dir).await;
    }

    state.audit.log(AuditLog::new(
        None,
        Some("admin".to_string()),
        "rollback_config".to_string(),
        "config".to_string(),
        "unknown".to_string(),
        None,
        Some(format!("Rolled back to version {}", id)),
        true,
    ));

    Ok(Json(StatusResponse::success(format!(
        "Configuration rolled back to version {}.",
        id
    ))))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigDiffResponse {
    pub from_id: String,
    pub to_id: String,
    pub additions: usize,
    pub deletions: usize,
    pub diff: String,
}

#[derive(Debug, Deserialize)]
pub struct DiffQueryParams {
    pub from: String,
    pub to: String,
}

fn compute_line_diff(old_content: &str, new_content: &str) -> String {
    let old_lines: Vec<&str> = old_content.lines().collect();
    let new_lines: Vec<&str> = new_content.lines().collect();

    let mut diff = String::new();
    let mut i = 0;
    let mut j = 0;
    let mut additions = 0;
    let mut deletions = 0;

    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
            diff.push_str(&format!("  {}\n", old_lines[i]));
            i += 1;
            j += 1;
        } else if j < new_lines.len()
            && (i >= old_lines.len() || !new_lines[j..].contains(&old_lines[i]))
        {
            diff.push_str(&format!("+ {}\n", new_lines[j]));
            additions += 1;
            j += 1;
        } else if i < old_lines.len() {
            diff.push_str(&format!("- {}\n", old_lines[i]));
            deletions += 1;
            i += 1;
        }
    }

    format!("+{} -{}\n\n{}", additions, deletions, diff)
}

#[utoipa::path(
    get,
    path = "/config/diff",
    params(
        ("from" = String, Query, description = "Source version ID"),
        ("to" = String, Query, description = "Target version ID")
    ),
    responses(
        (status = 200, description = "Config diff result", body = ConfigDiffResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Version not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn diff_config_versions(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    axum::extract::Query(params): axum::extract::Query<DiffQueryParams>,
) -> Result<Json<ConfigDiffResponse>, StatusCode> {
    let from_content = state
        .config_versions
        .get_version_content(&params.from)
        .ok_or(StatusCode::NOT_FOUND)?;

    let to_content = state
        .config_versions
        .get_version_content(&params.to)
        .ok_or(StatusCode::NOT_FOUND)?;

    let diff = compute_line_diff(&from_content, &to_content);

    let additions = diff.matches("+ ").count();
    let deletions = diff.matches("- ").count();

    Ok(Json(ConfigDiffResponse {
        from_id: params.from,
        to_id: params.to,
        additions,
        deletions,
        diff,
    }))
}

// ============================================================================
// DefaultsConfig sub-config handlers
// ============================================================================

// --- Honeypot config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct HoneypotDefaultsResponse {
    pub config: crate::config::defaults::HoneypotDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateHoneypotDefaultsRequest {
    pub config: crate::config::defaults::HoneypotDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/honeypot",
    responses(
        (status = 200, description = "Honeypot defaults configuration", body = HoneypotDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_honeypot_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HoneypotDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(HoneypotDefaultsResponse {
        config: config.main.defaults.honeypot.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/honeypot",
    request_body = UpdateHoneypotDefaultsRequest,
    responses(
        (status = 200, description = "Honeypot defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_honeypot_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateHoneypotDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.honeypot = req.config;
    }
    persist_with_snapshot(&state, "Honeypot defaults updated").await?;
    Ok(Json(StatusResponse::success("Honeypot defaults updated.")))
}

// --- Honeypot Probe config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct HoneypotProbingDefaultsResponse {
    pub config: crate::config::defaults::HoneypotProbingDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateHoneypotProbingDefaultsRequest {
    pub config: crate::config::defaults::HoneypotProbingDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/honeypot-probe",
    responses(
        (status = 200, description = "Honeypot probing defaults configuration", body = HoneypotProbingDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_honeypot_probing_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HoneypotProbingDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(HoneypotProbingDefaultsResponse {
        config: config.main.defaults.honeypot_probe.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/honeypot-probe",
    request_body = UpdateHoneypotProbingDefaultsRequest,
    responses(
        (status = 200, description = "Honeypot probing defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_honeypot_probing_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateHoneypotProbingDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.honeypot_probe = req.config;
    }
    persist_with_snapshot(&state, "Honeypot probe defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Honeypot probing defaults updated.",
    )))
}

// --- Blocked defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct BlockedDefaultsResponse {
    pub config: crate::config::defaults::BlockedDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateBlockedDefaultsRequest {
    pub config: crate::config::defaults::BlockedDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/blocked",
    responses(
        (status = 200, description = "Blocked defaults configuration", body = BlockedDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_blocked_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BlockedDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(BlockedDefaultsResponse {
        config: config.main.defaults.blocked.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/blocked",
    request_body = UpdateBlockedDefaultsRequest,
    responses(
        (status = 200, description = "Blocked defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_blocked_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateBlockedDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.blocked = req.config;
    }
    persist_with_snapshot(&state, "Blocked defaults updated").await?;
    Ok(Json(StatusResponse::success("Blocked defaults updated.")))
}

// --- Suspicious words config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct SuspiciousWordsConfigResponse {
    pub config: crate::config::defaults::SuspiciousWordsConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSuspiciousWordsConfigRequest {
    pub config: crate::config::defaults::SuspiciousWordsConfig,
}

#[utoipa::path(
    get,
    path = "/config/defaults/suspicious-words",
    responses(
        (status = 200, description = "Suspicious words configuration", body = SuspiciousWordsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_suspicious_words_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SuspiciousWordsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SuspiciousWordsConfigResponse {
        config: config.main.defaults.suspicious_words.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/suspicious-words",
    request_body = UpdateSuspiciousWordsConfigRequest,
    responses(
        (status = 200, description = "Suspicious words config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_suspicious_words_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateSuspiciousWordsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.suspicious_words = req.config;
    }
    persist_with_snapshot(&state, "Suspicious words defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Suspicious words defaults updated.",
    )))
}

// --- Upstream errors config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamErrorsConfigResponse {
    pub config: crate::config::defaults::UpstreamErrorsConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUpstreamErrorsConfigRequest {
    pub config: crate::config::defaults::UpstreamErrorsConfig,
}

#[utoipa::path(
    get,
    path = "/config/defaults/upstream-errors",
    responses(
        (status = 200, description = "Upstream errors configuration", body = UpstreamErrorsConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_upstream_errors_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<UpstreamErrorsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(UpstreamErrorsConfigResponse {
        config: config.main.defaults.upstream_errors.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/upstream-errors",
    request_body = UpdateUpstreamErrorsConfigRequest,
    responses(
        (status = 200, description = "Upstream errors config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_upstream_errors_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateUpstreamErrorsConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.upstream_errors = req.config;
    }
    persist_with_snapshot(&state, "Upstream errors defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Upstream errors defaults updated.",
    )))
}

// --- Error pages config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorPagesDefaultsResponse {
    pub config: crate::config::defaults::ErrorPagesDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateErrorPagesDefaultsRequest {
    pub config: crate::config::defaults::ErrorPagesDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/error-pages",
    responses(
        (status = 200, description = "Error pages defaults configuration", body = ErrorPagesDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_error_pages_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ErrorPagesDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(ErrorPagesDefaultsResponse {
        config: config.main.defaults.error_pages.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/error-pages",
    request_body = UpdateErrorPagesDefaultsRequest,
    responses(
        (status = 200, description = "Error pages defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_error_pages_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateErrorPagesDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.error_pages = req.config;
    }
    persist_with_snapshot(&state, "Error pages defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Error pages defaults updated.",
    )))
}

// --- CSS challenge config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct CssChallengeDefaultsResponse {
    pub config: crate::config::defaults::CssChallengeDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCssChallengeDefaultsRequest {
    pub config: crate::config::defaults::CssChallengeDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/css-challenge",
    responses(
        (status = 200, description = "CSS challenge defaults configuration", body = CssChallengeDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_css_challenge_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<CssChallengeDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(CssChallengeDefaultsResponse {
        config: config.main.defaults.css_challenge.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/css-challenge",
    request_body = UpdateCssChallengeDefaultsRequest,
    responses(
        (status = 200, description = "CSS challenge defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_css_challenge_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateCssChallengeDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.css_challenge = req.config;
    }
    persist_with_snapshot(&state, "CSS challenge defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "CSS challenge defaults updated.",
    )))
}

// --- POW challenge config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct PowChallengeDefaultsResponse {
    pub config: crate::config::defaults::PowChallengeDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePowChallengeDefaultsRequest {
    pub config: crate::config::defaults::PowChallengeDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/pow-challenge",
    responses(
        (status = 200, description = "POW challenge defaults configuration", body = PowChallengeDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_pow_challenge_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PowChallengeDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(PowChallengeDefaultsResponse {
        config: config.main.defaults.pow_challenge.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/pow-challenge",
    request_body = UpdatePowChallengeDefaultsRequest,
    responses(
        (status = 200, description = "POW challenge defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_pow_challenge_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdatePowChallengeDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.pow_challenge = req.config;
    }
    persist_with_snapshot(&state, "POW challenge defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "POW challenge defaults updated.",
    )))
}

// --- Challenge priority config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct ChallengeDefaultsResponse {
    pub config: crate::config::defaults::ChallengeDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateChallengeDefaultsRequest {
    pub config: crate::config::defaults::ChallengeDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/challenge",
    responses(
        (status = 200, description = "Challenge defaults configuration", body = ChallengeDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_challenge_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ChallengeDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(ChallengeDefaultsResponse {
        config: config.main.defaults.challenge.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/challenge",
    request_body = UpdateChallengeDefaultsRequest,
    responses(
        (status = 200, description = "Challenge defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_challenge_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateChallengeDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.challenge = req.config;
    }
    persist_with_snapshot(&state, "Challenge defaults updated").await?;
    Ok(Json(StatusResponse::success("Challenge defaults updated.")))
}

// --- Auth defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthDefaultsResponse {
    pub config: crate::config::defaults::AuthDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAuthDefaultsRequest {
    pub config: crate::config::defaults::AuthDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/auth",
    responses(
        (status = 200, description = "Auth defaults configuration", body = AuthDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_auth_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AuthDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(AuthDefaultsResponse {
        config: config.main.defaults.auth.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/auth",
    request_body = UpdateAuthDefaultsRequest,
    responses(
        (status = 200, description = "Auth defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_auth_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateAuthDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.auth = req.config;
    }
    persist_with_snapshot(&state, "Auth defaults updated").await?;
    Ok(Json(StatusResponse::success("Auth defaults updated.")))
}

// --- Worker pool defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkerPoolDefaultsResponse {
    pub config: crate::config::defaults::WorkerPoolDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkerPoolDefaultsRequest {
    pub config: crate::config::defaults::WorkerPoolDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/worker-pool",
    responses(
        (status = 200, description = "Worker pool defaults configuration", body = WorkerPoolDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_worker_pool_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<WorkerPoolDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(WorkerPoolDefaultsResponse {
        config: config.main.defaults.worker_pool.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/worker-pool",
    request_body = UpdateWorkerPoolDefaultsRequest,
    responses(
        (status = 200, description = "Worker pool defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_worker_pool_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateWorkerPoolDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.worker_pool = req.config;
    }
    persist_with_snapshot(&state, "Worker pool defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Worker pool defaults updated.",
    )))
}

// --- Persistence config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct PersistenceConfigResponse {
    pub config: crate::config::defaults::PersistenceConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePersistenceConfigRequest {
    pub config: crate::config::defaults::PersistenceConfig,
}

#[utoipa::path(
    get,
    path = "/config/defaults/persistence",
    responses(
        (status = 200, description = "Persistence configuration", body = PersistenceConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_persistence_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PersistenceConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(PersistenceConfigResponse {
        config: config.main.defaults.persistence.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/persistence",
    request_body = UpdatePersistenceConfigRequest,
    responses(
        (status = 200, description = "Persistence config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_persistence_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdatePersistenceConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.persistence = req.config;
    }
    persist_with_snapshot(&state, "Persistence defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Persistence defaults updated.",
    )))
}

// --- Tarpit defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TarpitDefaultsResponse {
    pub config: crate::config::network::TarpitDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTarpitDefaultsRequest {
    pub config: crate::config::network::TarpitDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/tarpit",
    responses(
        (status = 200, description = "Tarpit defaults configuration", body = TarpitDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_tarpit_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TarpitDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TarpitDefaultsResponse {
        config: config.main.defaults.tarpit.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/tarpit",
    request_body = UpdateTarpitDefaultsRequest,
    responses(
        (status = 200, description = "Tarpit defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_tarpit_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTarpitDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.tarpit = req.config;
    }
    persist_with_snapshot(&state, "Tarpit defaults updated").await?;
    Ok(Json(StatusResponse::success("Tarpit defaults updated.")))
}

// --- Upload defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadDefaultsResponse {
    pub config: crate::config::upload::UploadDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUploadDefaultsRequest {
    pub config: crate::config::upload::UploadDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/upload",
    responses(
        (status = 200, description = "Upload defaults configuration", body = UploadDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_upload_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<UploadDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(UploadDefaultsResponse {
        config: config.main.defaults.upload.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/upload",
    request_body = UpdateUploadDefaultsRequest,
    responses(
        (status = 200, description = "Upload defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_upload_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateUploadDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.upload = req.config;
    }
    persist_with_snapshot(&state, "Upload defaults updated").await?;
    Ok(Json(StatusResponse::success("Upload defaults updated.")))
}

// --- Traffic shaping defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TrafficShapingDefaultsResponse {
    pub config: crate::config::traffic::TrafficShapingDefaults,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTrafficShapingDefaultsRequest {
    pub config: crate::config::traffic::TrafficShapingDefaults,
}

#[utoipa::path(
    get,
    path = "/config/defaults/traffic-shaping",
    responses(
        (status = 200, description = "Traffic shaping defaults configuration", body = TrafficShapingDefaultsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_traffic_shaping_sub_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TrafficShapingDefaultsResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TrafficShapingDefaultsResponse {
        config: config.main.defaults.traffic_shaping.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/traffic-shaping",
    request_body = UpdateTrafficShapingDefaultsRequest,
    responses(
        (status = 200, description = "Traffic shaping defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_traffic_shaping_sub_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateTrafficShapingDefaultsRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.traffic_shaping = req.config;
    }
    persist_with_snapshot(&state, "Traffic shaping defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "Traffic shaping defaults updated.",
    )))
}

// --- ASN scraping defaults config ---

#[derive(Debug, Serialize, ToSchema)]
pub struct AsnScrapingConfigResponse {
    pub config: crate::config::defaults::AsnScrapingConfig,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAsnScrapingConfigRequest {
    pub config: crate::config::defaults::AsnScrapingConfig,
}

#[utoipa::path(
    get,
    path = "/config/defaults/asn-scraping",
    responses(
        (status = 200, description = "ASN scraping defaults configuration", body = AsnScrapingConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn get_asn_scraping_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AsnScrapingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(AsnScrapingConfigResponse {
        config: config.main.defaults.asn_scraping.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/config/defaults/asn-scraping",
    request_body = UpdateAsnScrapingConfigRequest,
    responses(
        (status = 200, description = "ASN scraping defaults config updated", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 500, description = "Internal server error")
    ),
    tag = "config"
)]
pub async fn update_asn_scraping_defaults(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateAsnScrapingConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    {
        let mut config = state.process.config.write().await;
        config.main.defaults.asn_scraping = req.config;
    }
    persist_with_snapshot(&state, "ASN scraping defaults updated").await?;
    Ok(Json(StatusResponse::success(
        "ASN scraping defaults updated.",
    )))
}

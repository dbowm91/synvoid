use super::super::state::AdminState;
use crate::log_controller;
use axum::{extract::State, http::StatusCode, Json};
use schemars::schema_for;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::common::{OptionalAuth, StatusResponse};

#[derive(Debug, Serialize)]
pub struct MainConfigResponse {
    pub config: crate::config::main::MainConfig,
}

pub async fn get_main_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MainConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;

    Ok(Json(MainConfigResponse {
        config: config.main.clone(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMainConfigRequest {
    pub config: crate::config::main::MainConfig,
}

pub async fn get_config_schema(_auth: OptionalAuth) -> Result<Json<serde_json::Value>, StatusCode> {
    let schema = schema_for!(crate::config::main::MainConfig);
    Ok(Json(
        serde_json::to_value(schema).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

pub async fn update_main_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateMainConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
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

    // Update in-memory config and broadcast to workers
    {
        let mut cfg = state.process.config.write().await;
        if cfg.load_main(&main_config_path).is_ok() {
            cfg.discover_sites();
        }
    }

    // Broadcast to workers if process manager is available
    if let Some(ref pm) = state.process.process_manager {
        pm.broadcast_config_reload(config_dir).await;
    }

    Ok(Json(StatusResponse::success(
        "Configuration updated and reloaded to workers.",
    )))
}

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

#[derive(Debug, Deserialize)]
pub struct SetLogLevelRequest {
    pub level: String,
}

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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct RegexCheckResult {
    pub pattern: String,
    pub safe: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CheckRegexRequest {
    pub pattern: String,
}

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

pub async fn get_overseer_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<OverseerConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(OverseerConfigResponse {
        config: config.main.overseer.clone(),
    }))
}

pub async fn update_overseer_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<UpdateOverseerConfigRequest>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;

    let main_config_path = {
        let mut config = state.process.config.write().await;
        config.main.overseer = req.config;
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

pub async fn get_supervisor_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SupervisorConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SupervisorConfigResponse {
        config: config.main.supervisor.clone(),
    }))
}

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

pub async fn get_tls_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TlsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TlsConfigResponse {
        config: config.main.tls.clone(),
    }))
}

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

pub async fn get_http_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<HttpConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(HttpConfigResponse {
        config: config.main.http.clone(),
    }))
}

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

// --- Security config ---

#[derive(Debug, Serialize)]
pub struct SecurityConfigResponse {
    pub config: crate::config::security::MainSecurityConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecurityConfigRequest {
    pub config: crate::config::security::MainSecurityConfig,
}

pub async fn get_security_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SecurityConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(SecurityConfigResponse {
        config: config.main.security.clone(),
    }))
}

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

pub async fn get_tunnel_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TunnelConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TunnelConfigResponse {
        config: config.main.tunnel.clone(),
    }))
}

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

pub async fn get_plugins_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PluginsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(PluginsConfigResponse {
        config: config.main.plugins.clone(),
    }))
}

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

pub async fn get_logging_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<LoggingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(LoggingConfigResponse {
        config: config.main.logging.clone(),
    }))
}

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

pub async fn get_traffic_shaping_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<TrafficShapingConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(TrafficShapingConfigResponse {
        config: config.main.traffic_shaping.clone(),
    }))
}

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

pub async fn get_threat_level_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ThreatLevelConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(ThreatLevelConfigResponse {
        config: config.main.threat_level.clone(),
    }))
}

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

pub async fn get_ip_feeds_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<IpFeedsConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(IpFeedsConfigResponse {
        config: config.main.ip_feeds.clone(),
    }))
}

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

pub async fn get_bot_detection_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BotDetectionConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(BotDetectionConfigResponse {
        config: config.main.defaults.bot.clone(),
    }))
}

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

pub async fn get_mesh_config(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<MeshConfigResponse>, StatusCode> {
    let config = state.process.config.read().await;
    Ok(Json(MeshConfigResponse {
        config: config.main.mesh.clone(),
    }))
}

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

// --- Helper: persist MainConfig to TOML file ---

async fn persist_main_config_and_notify(state: &Arc<AdminState>) -> Result<(), StatusCode> {
    let (main_config_path, toml_content, config_dir) = {
        let config = state.process.config.read().await;
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

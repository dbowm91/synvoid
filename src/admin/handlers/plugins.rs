use super::super::state::{AdminState, ReloadEvent};
use super::common::OptionalAuth;
use crate::plugin::wasm_metrics::{get_all_wasm_metrics, get_wasm_metrics};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PluginStatus {
    pub plugins: Vec<PluginStatusInfo>,
    pub reload_events: Vec<ReloadEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PluginStatusInfo {
    pub name: String,
    pub path: Option<String>,
    pub plugin_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WasmModuleInfo {
    pub name: String,
    pub version: Option<String>,
    pub sync_status: String,
    pub distributed_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WasmModulesResponse {
    pub modules: Vec<WasmModuleInfo>,
    pub total: usize,
}

#[utoipa::path(
    get,
    path = "/api/plugins/metrics",
    responses(
        (status = 200, description = "All plugins metrics"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "plugins"
)]
pub async fn get_all_plugins_metrics(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let all_metrics = get_all_wasm_metrics();

    let result: serde_json::Map<String, serde_json::Value> = all_metrics
        .into_iter()
        .map(|(name, metrics)| {
            let obj = serde_json::json!({
                "invocations": metrics.invocations,
                "decisions_pass": metrics.decisions_pass,
                "decisions_block": metrics.decisions_block,
                "decisions_challenge": metrics.decisions_challenge,
                "errors": metrics.errors,
                "fuel_consumed": metrics.fuel_consumed,
                "avg_duration_ms": metrics.avg_duration_ms(),
                "pass_rate": metrics.pass_rate(),
            });
            (name, obj)
        })
        .collect();

    Ok(Json(serde_json::json!({ "plugins": result })))
}

#[utoipa::path(
    get,
    path = "/api/plugins/{plugin_name}/metrics",
    params(
        ("plugin_name" = String, Path, description = "Plugin name")
    ),
    responses(
        (status = 200, description = "Plugin metrics"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Plugin not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "plugins"
)]
pub async fn get_plugin_metrics(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(plugin_name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let metrics = get_wasm_metrics(&plugin_name);

    if metrics.invocations == 0
        && metrics.decisions_pass == 0
        && metrics.decisions_block == 0
        && metrics.decisions_challenge == 0
        && metrics.errors == 0
    {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(serde_json::json!({
        "name": plugin_name,
        "invocations": metrics.invocations,
        "decisions_pass": metrics.decisions_pass,
        "decisions_block": metrics.decisions_block,
        "decisions_challenge": metrics.decisions_challenge,
        "errors": metrics.errors,
        "fuel_consumed": metrics.fuel_consumed,
        "avg_duration_ms": metrics.avg_duration_ms(),
        "pass_rate": metrics.pass_rate(),
    })))
}

#[utoipa::path(
    get,
    path = "/api/plugins/status",
    responses(
        (status = 200, description = "Plugins status", body = PluginStatus),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "plugins"
)]
pub async fn get_plugins_status(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<PluginStatus>, StatusCode> {
    let mut plugins = Vec::new();

    if let Some(ref pm) = state.process.plugin_manager {
        let plugin_info = pm.wasm_manager().get_plugin_info();
        for info in plugin_info {
            plugins.push(PluginStatusInfo {
                name: info.name,
                path: info.path.map(|p| p.to_string_lossy().to_string()),
                plugin_type: "wasm".to_string(),
            });
        }
    }

    let reload_events: Vec<ReloadEvent> = state
        .plugins
        .reload_log
        .read()
        .iter()
        .rev()
        .take(100)
        .cloned()
        .collect();

    Ok(Json(PluginStatus {
        plugins,
        reload_events,
    }))
}

#[utoipa::path(
    post,
    path = "/api/plugins/{plugin_name}/reload",
    params(
        ("plugin_name" = String, Path, description = "Plugin name to reload")
    ),
    responses(
        (status = 200, description = "Plugin reloaded"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Plugin not found"),
        (status = 503, description = "Plugin manager unavailable"),
        (status = 500, description = "Internal server error")
    ),
    tag = "plugins"
)]
pub async fn reload_plugin(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(plugin_name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Some(ref pm) = state.process.plugin_manager {
        let result = pm.wasm_manager().reload_plugin_by_name(&plugin_name);

        let timestamp = chrono::Utc::now().to_rfc3339();
        let (success, error_msg) = match result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        let event = ReloadEvent {
            timestamp: timestamp.clone(),
            plugin_name: plugin_name.clone(),
            success,
            error: error_msg.clone(),
        };

        state.plugins.reload_log.write().push_back(event);

        if success {
            tracing::info!("Plugin '{}' reloaded successfully", plugin_name);
            Ok(Json(serde_json::json!({
                "success": true,
                "message": format!("Plugin '{}' reloaded successfully", plugin_name),
                "timestamp": timestamp,
            })))
        } else {
            tracing::error!("Failed to reload plugin '{}': {:?}", plugin_name, error_msg);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[utoipa::path(
    get,
    path = "/api/plugins/mesh/modules",
    responses(
        (status = 200, description = "Mesh WASM modules", body = WasmModulesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "plugins"
)]
pub async fn get_mesh_wasm_modules(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<WasmModulesResponse>, StatusCode> {
    let modules: Vec<WasmModuleInfo> = Vec::new();

    Ok(Json(WasmModulesResponse {
        total: modules.len(),
        modules,
    }))
}

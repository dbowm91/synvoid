use super::common::{OptionalAuth, StatusResponse};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::admin::state::AdminState;
use crate::spin::handler::get_global_spin_apps_manager;
use crate::spin::runtime::{SpinRuntime, SpinRuntimeConfig};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpinAppStatus {
    pub name: String,
    pub manifest_path: String,
    pub component_count: usize,
    pub instance_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpinAppsStatus {
    pub apps: Vec<SpinAppStatus>,
    pub total_apps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpinAppManifestInfo {
    pub name: String,
    pub version: String,
    pub trigger_type: String,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpinManifestResponse {
    pub manifest: SpinAppManifestInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSpinAppRequest {
    pub name: String,
    pub manifest_path: String,
    pub timeout_seconds: Option<u64>,
    pub max_instances: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpinAppResponse {
    pub success: bool,
    pub name: String,
    pub message: String,
}

#[utoipa::path(
    get,
    path = "/spin/apps",
    responses(
        (status = 200, description = "List of Spin applications", body = SpinAppsStatus),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "spin"
)]
pub async fn list_spin_apps(_auth: OptionalAuth) -> Result<Json<SpinAppsStatus>, StatusCode> {
    let manager = get_global_spin_apps_manager();
    let apps = manager.list_apps();

    let mut app_statuses = Vec::new();
    for app_name in &apps {
        if let Some(runtime) = manager.get(app_name) {
            let manifest = runtime.get_manifest();
            let component_count = manifest.as_ref().map(|m| m.components.len()).unwrap_or(0);
            let instance_count = runtime.list_instances().len();

            app_statuses.push(SpinAppStatus {
                name: app_name.clone(),
                manifest_path: runtime.config.manifest_path.to_string_lossy().to_string(),
                component_count,
                instance_count,
            });
        }
    }

    Ok(Json(SpinAppsStatus {
        total_apps: app_statuses.len(),
        apps: app_statuses,
    }))
}

#[utoipa::path(
    get,
    path = "/spin/apps/{name}/manifest",
    params(
        ("name" = String, Path, description = "Spin app name")
    ),
    responses(
        (status = 200, description = "Spin app manifest", body = SpinManifestResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Spin app not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "spin"
)]
pub async fn get_spin_app_manifest(
    Path(name): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<SpinManifestResponse>, StatusCode> {
    let manager = get_global_spin_apps_manager();
    let runtime = manager.get(&name).ok_or(StatusCode::NOT_FOUND)?;

    let manifest = runtime.get_manifest().ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(SpinManifestResponse {
        manifest: SpinAppManifestInfo {
            name: manifest.name,
            version: manifest.version,
            trigger_type: manifest.trigger_type,
            components: manifest.components.iter().map(|c| c.id.clone()).collect(),
        },
    }))
}

#[utoipa::path(
    post,
    path = "/spin/apps",
    request_body = CreateSpinAppRequest,
    responses(
        (status = 200, description = "Spin app created", body = SpinAppResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Spin app already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "spin"
)]
pub async fn create_spin_app(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CreateSpinAppRequest>,
) -> Result<Json<SpinAppResponse>, StatusCode> {
    let manager = get_global_spin_apps_manager();

    if manager.get(&req.name).is_some() {
        return Err(StatusCode::CONFLICT);
    }

    let config = SpinRuntimeConfig {
        manifest_path: std::path::PathBuf::from(&req.manifest_path),
        app_name: req.name.clone(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        max_instances: req.max_instances.unwrap_or(10),
        default_timeout_seconds: req.timeout_seconds.unwrap_or(30),
        kv_store: None,
    };

    let runtime = SpinRuntime::new(config).map_err(|e| {
        tracing::error!("Failed to create Spin runtime: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let runtime = Arc::new(runtime);
    manager
        .register(&req.name, runtime.clone())
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        "Created Spin app '{}' from manifest '{}'",
        req.name,
        req.manifest_path
    );

    Ok(Json(SpinAppResponse {
        success: true,
        name: req.name,
        message: "Spin app created".to_string(),
    }))
}

#[utoipa::path(
    delete,
    path = "/spin/apps/{name}",
    params(
        ("name" = String, Path, description = "Spin app name")
    ),
    responses(
        (status = 200, description = "Spin app deleted", body = StatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Spin app not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "spin"
)]
pub async fn delete_spin_app(
    Path(name): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<StatusResponse>, StatusCode> {
    let manager = get_global_spin_apps_manager();

    if manager.get(&name).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    manager.unregister(&name);

    tracing::info!("Deleted Spin app '{}'", name);

    Ok(Json(StatusResponse::success(format!(
        "Spin app '{}' deleted",
        name
    ))))
}

#[utoipa::path(
    get,
    path = "/spin/apps/{name}/instances",
    params(
        ("name" = String, Path, description = "Spin app name")
    ),
    responses(
        (status = 200, description = "Spin app instances"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Spin app not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "spin"
)]
pub async fn get_spin_app_instances(
    Path(name): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let manager = get_global_spin_apps_manager();
    let runtime = manager.get(&name).ok_or(StatusCode::NOT_FOUND)?;

    let instances = runtime.list_instances();

    Ok(Json(serde_json::json!({
        "app_name": name,
        "instances": instances,
        "count": instances.len()
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spin_app_status_serialization() {
        let status = SpinAppStatus {
            name: "test-app".to_string(),
            manifest_path: "/path/to/spin.toml".to_string(),
            component_count: 2,
            instance_count: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("test-app"));
    }

    #[test]
    fn test_create_spin_app_request_serialization() {
        let request = CreateSpinAppRequest {
            name: "my-app".to_string(),
            manifest_path: "/path/to/spin.toml".to_string(),
            timeout_seconds: Some(60),
            max_instances: Some(5),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("my-app"));
    }
}

use super::common::OptionalAuth;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synvoid_core::admin_mutation::{
    AdminActor, AdminAuditEvent, AdminMutationAuthority, AdminMutationResult, AdminMutationStatus,
    PropagationStatus,
};
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
        (status = 200, description = "Spin app created"),
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
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
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
        idle_timeout_seconds: 300,
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

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: req.name,
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: None,
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
        (status = 200, description = "Spin app deleted", body = AdminMutationResult<String>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Spin app not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "spin"
)]
pub async fn delete_spin_app(
    State(state): State<Arc<AdminState>>,
    Path(name): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<AdminMutationResult<String>>, StatusCode> {
    let manager = get_global_spin_apps_manager();

    if manager.get(&name).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    manager.unregister(&name);

    let audit_id = uuid::Uuid::new_v4().to_string();
    let audit_event = AdminAuditEvent {
        audit_id: audit_id.clone(),
        timestamp: synvoid_utils::safe_unix_timestamp(),
        actor: AdminActor::new(AdminMutationAuthority::AdminManual),
        action: "spin.app.delete".to_string(),
        target_kind: "spin_app".to_string(),
        target_id: name.clone(),
        prior_state: None,
        requested_state: None,
        resulting_state: None,
        mutation_status: AdminMutationStatus::Applied,
        propagation_status: PropagationStatus::NotApplicable,
        event_id: None,
    };
    state.audit.log_audit_event(&audit_event);

    let result_message = format!("Spin app '{}' deleted", name);
    tracing::info!("Deleted Spin app '{}'", name);

    Ok(Json(AdminMutationResult {
        status: AdminMutationStatus::Applied,
        target: name,
        local_store_mutated: true,
        propagation: PropagationStatus::NotApplicable,
        event_id: None,
        audit_id: Some(audit_id),
        message: result_message,
    }))
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

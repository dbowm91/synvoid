use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::common::{OptionalAuth, config_path};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SiteInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub default_upstream: String,
    pub routes: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SiteDetail {
    pub id: String,
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/sites",
    tag = "Sites",
    responses(
        (status = 200, description = "List of sites"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_sites(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<SiteInfo>>, StatusCode> {

    let config = state.process.config.read().await;
    
    let sites: Vec<SiteInfo> = config.sites.iter().map(|(id, site)| {
        SiteInfo {
            id: id.clone(),
            domains: site.site.domains.clone(),
            default_upstream: site.site.upstream.default.clone(),
            routes: site.site.upstream.routes.clone(),
        }
    }).collect();

    Ok(Json(sites))
}

#[utoipa::path(
    get,
    path = "/sites/{site_id}",
    tag = "Sites",
    responses(
        (status = 200, description = "Site details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_site(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteDetail>, StatusCode> {

    let config = state.process.config.read().await;
    
    match config.sites.get(&site_id) {
        Some(site) => {
            let json = serde_json::to_value(&site.site).unwrap_or(serde_json::Value::Null);
            Ok(Json(SiteDetail {
                id: site_id,
                config: json,
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateSiteRequest {
    pub domains: Vec<String>,
    pub default_upstream: String,
}

#[utoipa::path(
    post,
    path = "/sites",
    tag = "Sites",
    responses(
        (status = 200, description = "Site created"),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_site(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CreateSiteRequest>,
) -> Result<Json<SiteDetail>, StatusCode> {

    if req.domains.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let site_id = req.domains.first()
        .cloned()
        .ok_or(StatusCode::BAD_REQUEST)?;
    
    let site_config = crate::config::site::SiteConfig {
        site: crate::config::site::SiteInfo {
            domains: req.domains,
            listen: Vec::new(),
            upstream: crate::config::site::UpstreamConfig {
                default: req.default_upstream,
                routes: std::collections::HashMap::new(),
                tunnel_mappings: std::collections::HashMap::new(),
            },
        },
        ..Default::default()
    };

    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };
    
    let toml_content = toml::to_string_pretty(&site_config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let toml_content_for_broadcast = toml_content.clone();

    // Hold write lock across both file write and in-memory update to prevent TOCTOU
    let _guard = state.metrics.config_write_lock.write().await;
    tokio::fs::write(&config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write site config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut config = state.process.config.write().await;
    config.load_site(config_path.clone())
        .map_err(|e| {
            tracing::error!("Failed to load new site: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let site_id_for_broadcast = site_id.clone();
    drop(config);
    drop(_guard);

    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mesh_transport_clone = mesh_transport.clone();
        let version = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        tokio::spawn(async move {
            match mesh_transport_clone.broadcast_site_config_to_origins(&site_id_for_broadcast, &toml_content_for_broadcast, version).await {
                Ok((success, fail)) => {
                    tracing::info!("Broadcast new site config for {}: {} success, {} failed", site_id_for_broadcast, success, fail);
                }
                Err(e) => {
                    tracing::warn!("Failed to broadcast new site config for {}: {}", site_id_for_broadcast, e);
                }
            }
        });
    }

    Ok(Json(SiteDetail {
        id: site_id,
        config: serde_json::to_value(&site_config).unwrap_or(serde_json::Value::Null),
    }))
}

#[utoipa::path(
    delete,
    path = "/sites/{site_id}",
    tag = "Sites",
    responses(
        (status = 204, description = "Site deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_site(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<StatusCode, StatusCode> {

    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };

    // Hold write lock across both file removal and in-memory update to prevent TOCTOU
    let _guard = state.metrics.config_write_lock.write().await;
    tokio::fs::remove_file(&config_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete site config file: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut config = state.process.config.write().await;
    config.sites.remove(&site_id);

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateSiteRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    put,
    path = "/sites/{site_id}",
    tag = "Sites",
    responses(
        (status = 200, description = "Site updated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_site(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
    Json(req): Json<UpdateSiteRequest>,
) -> Result<Json<SiteDetail>, StatusCode> {

    let config: crate::config::site::SiteConfig = serde_json::from_value(req.config.clone())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if config.site.domains.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Err(e) = config.validate() {
        tracing::warn!("Site config validation failed: {}", e);
        return Err(StatusCode::BAD_REQUEST);
    }

    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };

    let toml_content = toml::to_string_pretty(&config)
        .map_err(|e| {
            tracing::error!("Failed to serialize config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    let toml_content_for_broadcast = toml_content.clone();

    // Hold write lock across both file write and in-memory update to prevent TOCTOU
    let _guard = state.metrics.config_write_lock.write().await;
    tokio::fs::write(&config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write site config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut state_config = state.process.config.write().await;
    state_config.sites.insert(site_id.clone(), config.clone());

    let site_id_for_broadcast = site_id.clone();
    let version = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    drop(state_config);
    drop(_guard);

    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mesh_transport_clone = mesh_transport.clone();
        
        tokio::spawn(async move {
            match mesh_transport_clone.broadcast_site_config_to_origins(&site_id_for_broadcast, &toml_content_for_broadcast, version).await {
                Ok((success, fail)) => {
                    tracing::info!("Broadcast site config for {}: {} success, {} failed", site_id_for_broadcast, success, fail);
                }
                Err(e) => {
                    tracing::warn!("Failed to broadcast site config for {}: {}", site_id_for_broadcast, e);
                }
            }
        });
    }

    Ok(Json(SiteDetail {
        id: site_id,
        config: req.config,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SiteThemeResponse {
    pub site_id: String,
    pub preset: Option<String>,
    pub mode: Option<String>,
    pub allow_only: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateSiteThemeRequest {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow_only: Option<String>,
}

#[utoipa::path(
    get,
    path = "/sites/{site_id}/theme",
    tag = "Sites",
    responses(
        (status = 200, description = "Site theme"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_site_theme(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteThemeResponse>, StatusCode> {

    let config = state.process.config.read().await;
    
    let site = config.sites.get(&site_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let theme = &site.error_pages.theme;
    
    Ok(Json(SiteThemeResponse {
        site_id: site_id.clone(),
        preset: theme.as_ref().and_then(|t| t.preset.clone()),
        mode: theme.as_ref().and_then(|t| t.mode.clone()),
        allow_only: theme.as_ref().and_then(|t| t.allow_only.clone()),
    }))
}

#[utoipa::path(
    put,
    path = "/sites/{site_id}/theme",
    tag = "Sites",
    responses(
        (status = 200, description = "Site theme updated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_site_theme(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
    Json(req): Json<UpdateSiteThemeRequest>,
) -> Result<Json<SiteThemeResponse>, StatusCode> {

    // Hold write lock across both in-memory update and file write to prevent TOCTOU
    let _guard = state.metrics.config_write_lock.write().await;
    let mut config = state.process.config.write().await;

    let site = config.sites.get_mut(&site_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    if req.preset.is_some() || req.mode.is_some() || req.allow_only.is_some() {
        site.error_pages.theme = Some(crate::config::site::SiteThemeConfig {
            preset: req.preset,
            mode: req.mode,
            allow_only: req.allow_only,
            colors: None,
        });
    }

    let theme = &site.error_pages.theme;
    let response = SiteThemeResponse {
        site_id: site_id.clone(),
        preset: theme.as_ref().and_then(|t| t.preset.clone()),
        mode: theme.as_ref().and_then(|t| t.mode.clone()),
        allow_only: theme.as_ref().and_then(|t| t.allow_only.clone()),
    };

    let site_config = site.clone();
    drop(config);

    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };
    let toml_content = toml::to_string_pretty(&site_config)
        .map_err(|e| {
            tracing::error!("Failed to serialize site config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tokio::fs::write(&config_path, toml_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write site config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(response))
}

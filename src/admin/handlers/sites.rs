use super::super::state::AdminState;
use super::common::{config_path, OptionalAuth};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub default_upstream: String,
    pub routes: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteDetail {
    pub id: String,
    pub config: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/sites",
    responses(
        (status = 200, description = "List of sites", body = Vec<SiteInfo>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn list_sites(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<SiteInfo>>, StatusCode> {
    let config = state.process.config.read().await;

    let sites: Vec<SiteInfo> = config
        .sites
        .iter()
        .map(|(id, site)| SiteInfo {
            id: id.clone(),
            domains: site.site.domains.clone(),
            default_upstream: site.site.upstream.default.clone(),
            routes: site.site.upstream.routes.clone(),
        })
        .collect();

    Ok(Json(sites))
}

#[utoipa::path(
    get,
    path = "/sites/{site_id}",
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    responses(
        (status = 200, description = "Site details", body = SiteDetail),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSiteRequest {
    pub domains: Vec<String>,
    pub default_upstream: String,
}

#[utoipa::path(
    post,
    path = "/sites",
    request_body = CreateSiteRequest,
    responses(
        (status = 200, description = "Site created", body = SiteDetail),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn create_site(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CreateSiteRequest>,
) -> Result<Json<SiteDetail>, StatusCode> {
    if req.domains.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let site_id = req
        .domains
        .first()
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

    let toml_content =
        toml::to_string_pretty(&site_config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
    config.load_site(config_path.clone()).map_err(|e| {
        tracing::error!("Failed to load new site: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let site_id_for_broadcast = site_id.clone();
    #[cfg(feature = "mesh")]
    let proxy_cache_preferences = site_config
        .proxy
        .cache
        .as_ref()
        .map(crate::mesh::protocol::ProxyCachePreferences::from);
    #[cfg(not(feature = "mesh"))]
    let proxy_cache_preferences: Option<()> = None;
    let _ = &toml_content_for_broadcast;
    let _ = &site_id_for_broadcast;
    let _ = &proxy_cache_preferences;
    drop(config);
    drop(_guard);

    #[cfg(feature = "mesh")]
    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mesh_transport_clone = mesh_transport.clone();
        let mesh_transport_for_publish = mesh_transport.clone();
        let version = crate::utils::safe_unix_timestamp();

        tokio::spawn(async move {
            match mesh_transport_clone
                .broadcast_site_config_to_origins(
                    &site_id_for_broadcast,
                    &toml_content_for_broadcast,
                    version,
                    proxy_cache_preferences,
                )
                .await
            {
                Ok((success, fail)) => {
                    tracing::info!(
                        "Broadcast new site config for {}: {} success, {} failed",
                        site_id_for_broadcast,
                        success,
                        fail
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to broadcast new site config for {}: {}",
                        site_id_for_broadcast,
                        e
                    );
                }
            }
        });

        mesh_transport_for_publish.publish_single_site_transform_config(&site_id, &site_config);
    }

    Ok(Json(SiteDetail {
        id: site_id,
        config: serde_json::to_value(&site_config).unwrap_or(serde_json::Value::Null),
    }))
}

#[utoipa::path(
    delete,
    path = "/sites/{site_id}",
    params(
        ("site_id" = String, Path, description = "Site ID to delete")
    ),
    responses(
        (status = 204, description = "Site deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
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
    tokio::fs::remove_file(&config_path).await.map_err(|e| {
        tracing::error!("Failed to delete site config file: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut config = state.process.config.write().await;
    config.sites.remove(&site_id);

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSiteRequest {
    pub config: serde_json::Value,
}

#[utoipa::path(
    put,
    path = "/sites/{site_id}",
    params(
        ("site_id" = String, Path, description = "Site ID to update")
    ),
    request_body = UpdateSiteRequest,
    responses(
        (status = 200, description = "Site updated", body = SiteDetail),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid configuration"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn update_site(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
    Json(req): Json<UpdateSiteRequest>,
) -> Result<Json<SiteDetail>, StatusCode> {
    let config: crate::config::site::SiteConfig =
        serde_json::from_value(req.config.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;

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

    let toml_content = toml::to_string_pretty(&config).map_err(|e| {
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
    #[cfg(feature = "mesh")]
    let proxy_cache_preferences = config
        .proxy
        .cache
        .as_ref()
        .map(crate::mesh::protocol::ProxyCachePreferences::from);
    #[cfg(not(feature = "mesh"))]
    let proxy_cache_preferences: Option<()> = None;
    let version = crate::utils::safe_unix_timestamp();
    let _ = (&toml_content_for_broadcast, &site_id_for_broadcast, &proxy_cache_preferences, &version);
    drop(state_config);
    drop(_guard);

    #[cfg(feature = "mesh")]
    if let Some(ref mesh_transport) = state.mesh.mesh_transport {
        let mesh_transport_clone = mesh_transport.clone();
        let mesh_transport_for_publish = mesh_transport.clone();

        tokio::spawn(async move {
            match mesh_transport_clone
                .broadcast_site_config_to_origins(
                    &site_id_for_broadcast,
                    &toml_content_for_broadcast,
                    version,
                    proxy_cache_preferences,
                )
                .await
            {
                Ok((success, fail)) => {
                    tracing::info!(
                        "Broadcast site config for {}: {} success, {} failed",
                        site_id_for_broadcast,
                        success,
                        fail
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to broadcast site config for {}: {}",
                        site_id_for_broadcast,
                        e
                    );
                }
            }
        });

        mesh_transport_for_publish.publish_single_site_transform_config(&site_id, &config);
    }

    Ok(Json(SiteDetail {
        id: site_id,
        config: req.config,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteThemeResponse {
    pub site_id: String,
    pub preset: Option<String>,
    pub mode: Option<String>,
    pub allow_only: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
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
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    responses(
        (status = 200, description = "Site theme", body = SiteThemeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn get_site_theme(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteThemeResponse>, StatusCode> {
    let config = state.process.config.read().await;

    let site = config.sites.get(&site_id).ok_or(StatusCode::NOT_FOUND)?;

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
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    request_body = UpdateSiteThemeRequest,
    responses(
        (status = 200, description = "Site theme updated", body = SiteThemeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
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

    let site = config
        .sites
        .get_mut(&site_id)
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
    let toml_content = toml::to_string_pretty(&site_config).map_err(|e| {
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

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteBotDetectionResponse {
    pub site_id: String,
    pub inherit: Option<bool>,
    pub block_ai_crawlers: Option<bool>,
    pub enable_css_honeypot: Option<bool>,
    pub enable_js_challenge: Option<bool>,
    pub challenge_type: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSiteBotDetectionRequest {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub block_ai_crawlers: Option<bool>,
    #[serde(default)]
    pub enable_css_honeypot: Option<bool>,
    #[serde(default)]
    pub enable_js_challenge: Option<bool>,
    #[serde(default)]
    pub challenge_type: Option<String>,
}

#[utoipa::path(
    get,
    path = "/sites/{site_id}/bot-detection",
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    responses(
        (status = 200, description = "Site bot detection config", body = SiteBotDetectionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn get_site_bot_detection(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteBotDetectionResponse>, StatusCode> {
    let config = state.process.config.read().await;

    let site = config.sites.get(&site_id).ok_or(StatusCode::NOT_FOUND)?;

    let bot = &site.bot;

    Ok(Json(SiteBotDetectionResponse {
        site_id,
        inherit: bot.inherit,
        block_ai_crawlers: bot.block_ai_crawlers,
        enable_css_honeypot: bot.enable_css_honeypot,
        enable_js_challenge: bot.enable_js_challenge,
        challenge_type: bot.challenge_type.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/sites/{site_id}/bot-detection",
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    request_body = UpdateSiteBotDetectionRequest,
    responses(
        (status = 200, description = "Site bot detection config updated", body = SiteBotDetectionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn update_site_bot_detection(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
    Json(req): Json<UpdateSiteBotDetectionRequest>,
) -> Result<Json<SiteBotDetectionResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    let mut config = state.process.config.write().await;

    let site = config
        .sites
        .get_mut(&site_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    if req.inherit.is_some()
        || req.block_ai_crawlers.is_some()
        || req.enable_css_honeypot.is_some()
        || req.enable_js_challenge.is_some()
        || req.challenge_type.is_some()
    {
        if let Some(v) = req.inherit {
            site.bot.inherit = Some(v);
        }
        if let Some(v) = req.block_ai_crawlers {
            site.bot.block_ai_crawlers = Some(v);
        }
        if let Some(v) = req.enable_css_honeypot {
            site.bot.enable_css_honeypot = Some(v);
        }
        if let Some(v) = req.enable_js_challenge {
            site.bot.enable_js_challenge = Some(v);
        }
        if let Some(v) = req.challenge_type {
            site.bot.challenge_type = Some(v);
        }
    }

    let response = SiteBotDetectionResponse {
        site_id: site_id.clone(),
        inherit: site.bot.inherit,
        block_ai_crawlers: site.bot.block_ai_crawlers,
        enable_css_honeypot: site.bot.enable_css_honeypot,
        enable_js_challenge: site.bot.enable_js_challenge,
        challenge_type: site.bot.challenge_type.clone(),
    };

    let site_config = site.clone();
    drop(config);

    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };
    let toml_content = toml::to_string_pretty(&site_config).map_err(|e| {
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

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteErrorPagesResponse {
    pub site_id: String,
    pub inherit: Option<bool>,
    pub mode: Option<String>,
    pub custom_directory: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSiteErrorPagesRequest {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub custom_directory: Option<String>,
}

#[utoipa::path(
    get,
    path = "/sites/{site_id}/error-pages",
    responses(
        (status = 200, description = "Site error pages config", body = SiteErrorPagesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn get_site_error_pages(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteErrorPagesResponse>, StatusCode> {
    let config = state.process.config.read().await;

    let site = config.sites.get(&site_id).ok_or(StatusCode::NOT_FOUND)?;

    let error_pages = &site.error_pages;

    Ok(Json(SiteErrorPagesResponse {
        site_id: site_id.clone(),
        inherit: error_pages.inherit,
        mode: error_pages.mode.clone(),
        custom_directory: error_pages.custom_directory.clone(),
    }))
}

#[utoipa::path(
    put,
    path = "/sites/{site_id}/error-pages",
    request_body = UpdateSiteErrorPagesRequest,
    responses(
        (status = 200, description = "Site error pages updated", body = SiteErrorPagesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "sites"
)]
pub async fn update_site_error_pages(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
    Json(req): Json<UpdateSiteErrorPagesRequest>,
) -> Result<Json<SiteErrorPagesResponse>, StatusCode> {
    let _guard = state.metrics.config_write_lock.write().await;
    let mut config = state.process.config.write().await;

    let site = config
        .sites
        .get_mut(&site_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    if req.inherit.is_some() || req.mode.is_some() || req.custom_directory.is_some() {
        site.error_pages.inherit = req.inherit;
        site.error_pages.mode = req.mode;
        site.error_pages.custom_directory = req.custom_directory;
    }

    let response = SiteErrorPagesResponse {
        site_id: site_id.clone(),
        inherit: site.error_pages.inherit,
        mode: site.error_pages.mode.clone(),
        custom_directory: site.error_pages.custom_directory.clone(),
    };

    let site_config = site.clone();
    drop(config);

    let config_path = {
        let cfg = state.process.config.read().await;
        config_path(&cfg.sites_dir, &site_id)
    };
    let toml_content = toml::to_string_pretty(&site_config).map_err(|e| {
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

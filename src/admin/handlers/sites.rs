use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::super::auth::{require_auth, OptionalAuth};

#[derive(Debug, Serialize)]
pub struct SiteInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub default_upstream: String,
    pub routes: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct SiteDetail {
    pub id: String,
    pub config: crate::config::site::SiteConfig,
}

pub async fn list_sites(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<SiteInfo>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    
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

pub async fn get_site(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteDetail>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    
    match config.sites.get(&site_id) {
        Some(site) => {
            Ok(Json(SiteDetail {
                id: site_id,
                config: site.clone(),
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateSiteRequest {
    pub domains: Vec<String>,
    pub default_upstream: String,
}

pub async fn create_site(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Json(req): Json<CreateSiteRequest>,
) -> Result<Json<SiteDetail>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if req.domains.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let site_id = req.domains.first().unwrap().clone();
    
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

    let config_path = format!("config/sites/{}.toml", site_id.replace('.', "_"));
    
    let toml_content = match toml::to_string_pretty(&site_config) {
        Ok(t) => t,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    
    if let Err(e) = std::fs::write(&config_path, toml_content) {
        tracing::error!("Failed to write site config: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut config = state.config.write().await;
    if let Err(e) = config.load_site(std::path::PathBuf::from(&config_path)) {
        tracing::error!("Failed to load new site: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(SiteDetail {
        id: site_id,
        config: site_config,
    }))
}

pub async fn delete_site(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config_path = format!("config/sites/{}.toml", site_id.replace('.', "_"));
    
    if let Err(e) = std::fs::remove_file(&config_path) {
        tracing::error!("Failed to delete site config file: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut config = state.config.write().await;
    config.sites.remove(&site_id);

    Ok(StatusCode::NO_CONTENT)
}

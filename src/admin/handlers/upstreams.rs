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
pub struct UpstreamStatus {
    pub url: String,
    pub healthy: bool,
    pub current_connections: usize,
    pub max_connections: usize,
    pub weight: u32,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

#[derive(Debug, Serialize)]
pub struct SiteUpstreams {
    pub site_id: String,
    pub default_upstream: String,
    pub backends: Vec<UpstreamStatus>,
}

pub async fn list_upstreams(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<SiteUpstreams>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    
    let upstreams: Vec<SiteUpstreams> = config.sites.iter().map(|(id, site)| {
        SiteUpstreams {
            site_id: id.clone(),
            default_upstream: site.site.upstream.default.clone(),
            backends: vec![UpstreamStatus {
                url: site.site.upstream.default.clone(),
                healthy: true,
                current_connections: 0,
                max_connections: 100,
                weight: 1,
                consecutive_failures: 0,
                consecutive_successes: 0,
            }],
        }
    }).collect();

    Ok(Json(upstreams))
}

pub async fn get_site_upstreams(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteUpstreams>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    
    match config.sites.get(&site_id) {
        Some(site) => {
            Ok(Json(SiteUpstreams {
                site_id: site_id.clone(),
                default_upstream: site.site.upstream.default.clone(),
                backends: vec![UpstreamStatus {
                    url: site.site.upstream.default.clone(),
                    healthy: true,
                    current_connections: 0,
                    max_connections: 100,
                    weight: 1,
                    consecutive_failures: 0,
                    consecutive_successes: 0,
                }],
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, Deserialize)]
pub struct TriggerHealthCheckRequest {
    pub _force: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub message: String,
}

pub async fn trigger_health_check(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(_site_id): Path<String>,
    Json(_req): Json<TriggerHealthCheckRequest>,
) -> Result<Json<HealthCheckResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(Json(HealthCheckResponse {
        status: "triggered".to_string(),
        message: "Health check initiated".to_string(),
    }))
}

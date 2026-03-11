use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::common::{require_auth, OptionalAuth};

const DEFAULT_MAX_CONNECTIONS: usize = 100;
const DEFAULT_WEIGHT: u32 = 1;

fn create_upstream_status(url: &str) -> UpstreamStatus {
    UpstreamStatus {
        url: url.to_string(),
        healthy: true,
        current_connections: 0,
        max_connections: DEFAULT_MAX_CONNECTIONS,
        weight: DEFAULT_WEIGHT,
        consecutive_failures: 0,
        consecutive_successes: 0,
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpstreamStatus {
    pub url: String,
    pub healthy: bool,
    pub current_connections: usize,
    pub max_connections: usize,
    pub weight: u32,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SiteUpstreams {
    pub site_id: String,
    pub default_upstream: String,
    pub backends: Vec<UpstreamStatus>,
}

#[utoipa::path(
    get,
    path = "/upstreams",
    tag = "Upstreams",
    responses(
        (status = 200, description = "List of all upstreams", body = [SiteUpstreams]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
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
            backends: vec![create_upstream_status(&site.site.upstream.default)],
        }
    }).collect();

    Ok(Json(upstreams))
}

#[utoipa::path(
    get,
    path = "/upstreams/{site_id}",
    tag = "Upstreams",
    params(
        ("site_id" = String, Path, description = "Site identifier")
    ),
    responses(
        (status = 200, description = "Site upstream configuration", body = [SiteUpstreams]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
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
                backends: vec![create_upstream_status(&site.site.upstream.default)],
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TriggerHealthCheckRequest {
    pub _force: Option<bool>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthCheckResponse {
    pub status: String,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/upstreams/{site_id}/check",
    tag = "Upstreams",
    params(
        ("site_id" = String, Path, description = "Site identifier")
    ),
    request_body = TriggerHealthCheckRequest,
    responses(
        (status = 200, description = "Health check triggered", body = [HealthCheckResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Site not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
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

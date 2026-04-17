use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use std::sync::Arc;

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

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamStatus {
    pub url: String,
    pub healthy: bool,
    pub current_connections: usize,
    pub max_connections: usize,
    pub weight: u32,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiteUpstreams {
    pub site_id: String,
    pub default_upstream: String,
    pub backends: Vec<UpstreamStatus>,
}

#[utoipa::path(
    get,
    path = "/api/upstreams",
    responses(
        (status = 200, description = "List of upstreams", body = Vec<SiteUpstreams>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "upstreams"
)]
pub async fn list_upstreams(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<SiteUpstreams>>, StatusCode> {
    let config = state.process.config.read().await;

    let upstreams: Vec<SiteUpstreams> = config
        .sites
        .iter()
        .map(|(id, site)| SiteUpstreams {
            site_id: id.clone(),
            default_upstream: site.site.upstream.default.clone(),
            backends: vec![create_upstream_status(&site.site.upstream.default)],
        })
        .collect();

    Ok(Json(upstreams))
}

#[utoipa::path(
    get,
    path = "/api/upstreams/{site_id}",
    params(
        ("site_id" = String, Path, description = "Site ID")
    ),
    responses(
        (status = 200, description = "Site upstreams", body = SiteUpstreams),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "upstreams"
)]
pub async fn get_site_upstreams(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
) -> Result<Json<SiteUpstreams>, StatusCode> {
    let config = state.process.config.read().await;

    match config.sites.get(&site_id) {
        Some(site) => Ok(Json(SiteUpstreams {
            site_id: site_id.clone(),
            default_upstream: site.site.upstream.default.clone(),
            backends: vec![create_upstream_status(&site.site.upstream.default)],
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TriggerHealthCheckRequest {
    pub _force: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthCheckResponse {
    pub status: String,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/api/upstreams/{site_id}/health-check",
    params(
        ("site_id" = String, Path, description = "Site ID to check")
    ),
    request_body = TriggerHealthCheckRequest,
    responses(
        (status = 200, description = "Health check result", body = HealthCheckResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Site not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "upstreams"
)]
pub async fn trigger_health_check(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(site_id): Path<String>,
    Json(req): Json<TriggerHealthCheckRequest>,
) -> Result<Json<HealthCheckResponse>, StatusCode> {
    let config = state.process.config.read().await;
    let site = config.sites.get(&site_id).ok_or(StatusCode::NOT_FOUND)?;
    let upstream_url = &site.site.upstream.default;

    let force = req._force.unwrap_or(false);
    tracing::info!(
        "Health check triggered for site {} (upstream: {}, force: {})",
        site_id,
        upstream_url,
        force
    );

    let is_healthy = check_upstream_tcp(upstream_url).await;

    Ok(Json(HealthCheckResponse {
        status: if is_healthy { "healthy" } else { "unhealthy" }.to_string(),
        message: if is_healthy {
            format!("Upstream {} is healthy", upstream_url)
        } else {
            format!("Upstream {} is unreachable", upstream_url)
        },
    }))
}

async fn check_upstream_tcp(url: &str) -> bool {
    let host_port = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let p = p.trim_end_matches('/').parse::<u16>().unwrap_or(80);
        (h.trim_end_matches('/'), p)
    } else {
        (host_port.trim_end_matches('/'), 80)
    };

    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .is_ok()
}

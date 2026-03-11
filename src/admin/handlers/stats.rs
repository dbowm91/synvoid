use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sysinfo::System;
use super::super::state::AdminState;
use super::super::auth::{require_auth, OptionalAuth};

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStats {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub requests_per_second: f64,
    pub active_connections: u32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub cpu_usage_percent: f32,
    pub sites_loaded: usize,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SiteStats {
    pub site_id: String,
    pub domains: Vec<String>,
    pub requests_per_second: f64,
    pub active_connections: u32,
    pub blocked_requests: u64,
    pub avg_response_time_ms: f64,
    pub upstream_healthy: bool,
}

pub async fn get_summary(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<SystemStats>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    let sites_count = config.sites.len();
    drop(config);

    let mut sys = System::new_all();
    sys.refresh_all();
    
    let memory_used = sys.used_memory() / 1024 / 1024;
    let memory_total = sys.total_memory() / 1024 / 1024;
    let cpus = sys.cpus();
    let cpu_usage = if !cpus.is_empty() {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    } else {
        0.0
    };
    
    let stats = SystemStats {
        uptime_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_requests: 0,
        requests_per_second: 0.0,
        active_connections: 0,
        memory_used_mb: memory_used,
        memory_total_mb: memory_total,
        cpu_usage_percent: cpu_usage,
        sites_loaded: sites_count,
        healthy_backends: 0,
        unhealthy_backends: 0,
    };

    Ok(Json(stats))
}

pub async fn get_sites_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<SiteStats>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    
    let site_stats: Vec<SiteStats> = config.sites.iter().map(|(id, site)| {
        SiteStats {
            site_id: id.clone(),
            domains: site.site.domains.clone(),
            requests_per_second: 0.0,
            active_connections: 0,
            blocked_requests: 0,
            avg_response_time_ms: 0.0,
            upstream_healthy: true,
        }
    }).collect();

    Ok(Json(site_stats))
}

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::{AdminState, AggregatedMetrics};
use super::common::{require_auth, OptionalAuth};
use crate::metrics::{get_proxy_cache_hits, get_proxy_cache_misses};

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct SystemStats {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub requests_per_second: f64,
    pub blocked_per_second: f64,
    pub active_connections: u32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub cpu_usage_percent: f32,
    pub sites_loaded: usize,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
    pub blocked_total: u64,
    pub challenged_total: u64,
    pub proxied_total: u64,
    pub errors_total: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub peak_concurrent: u64,
    pub time_validation_errors: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct SiteStats {
    pub site_id: String,
    pub domains: Vec<String>,
    pub requests_per_second: f64,
    pub active_connections: u32,
    pub blocked_requests: u64,
    pub challenged_requests: u64,
    pub proxied_requests: u64,
    pub errors: u64,
    pub avg_response_time_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub upstream_healthy: bool,
}

#[utoipa::path(
    get,
    path = "/stats/summary",
    tag = "Stats",
    responses(
        (status = 200, description = "System statistics", body = [SystemStats]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
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

    let metrics = state.get_metrics();
    let resources = state.get_system_resources();
    
    let stats = SystemStats {
        uptime_secs: state.uptime(),
        total_requests: metrics.total_requests,
        requests_per_second: metrics.requests_per_second,
        blocked_per_second: metrics.blocked_per_second,
        active_connections: metrics.current_concurrent as u32,
        memory_used_mb: resources.memory_used_mb,
        memory_total_mb: resources.memory_total_mb,
        cpu_usage_percent: resources.cpu_usage_percent,
        sites_loaded: sites_count,
        healthy_backends: metrics.healthy_backends,
        unhealthy_backends: metrics.unhealthy_backends,
        blocked_total: metrics.blocked,
        challenged_total: metrics.challenged,
        proxied_total: metrics.proxied,
        errors_total: metrics.errors,
        avg_latency_ms: metrics.avg_latency_ms,
        p50_latency_ms: metrics.p50_latency_ms,
        p95_latency_ms: metrics.p95_latency_ms,
        p99_latency_ms: metrics.p99_latency_ms,
        peak_concurrent: metrics.peak_concurrent,
        time_validation_errors: resources.time_validation_errors,
    };

    Ok(Json(stats))
}

#[utoipa::path(
    get,
    path = "/stats/sites",
    tag = "Stats",
    responses(
        (status = 200, description = "Per-site statistics", body = [SiteStats]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_sites_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<SiteStats>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    let site_metrics = state.get_site_metrics();
    let _global_metrics = state.get_metrics();
    let uptime = state.uptime();
    
    let site_stats: Vec<SiteStats> = config.sites.iter().map(|(id, site)| {
        let site_metric = site_metrics.get(id);
        
        let site_uptime = uptime.max(1);
        let site_rps = if let Some(ref sm) = site_metric {
            sm.total_requests as f64 / site_uptime as f64
        } else {
            0.0
        };
        
        SiteStats {
            site_id: id.clone(),
            domains: site.site.domains.clone(),
            requests_per_second: site_rps,
            active_connections: site_metric.map(|m| m.current_concurrent as u32).unwrap_or(0),
            blocked_requests: site_metric.map(|m| m.blocked).unwrap_or(0),
            challenged_requests: site_metric.map(|m| m.challenged).unwrap_or(0),
            proxied_requests: site_metric.map(|m| m.proxied).unwrap_or(0),
            errors: site_metric.map(|m| m.errors).unwrap_or(0),
            avg_response_time_ms: site_metric.map(|m| m.avg_latency_ms).unwrap_or(0.0),
            p50_latency_ms: site_metric.map(|m| m.p50_latency_ms).unwrap_or(0.0),
            p95_latency_ms: site_metric.map(|m| m.p95_latency_ms).unwrap_or(0.0),
            p99_latency_ms: site_metric.map(|m| m.p99_latency_ms).unwrap_or(0.0),
            upstream_healthy: site_metric.map(|m| m.upstream_healthy).unwrap_or(true),
        }
    }).collect();

    Ok(Json(site_stats))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MetricsHistoryParams {
    pub seconds: Option<u64>,
}

#[utoipa::path(
    get,
    path = "/stats/history",
    tag = "Stats",
    params(
        ("seconds" = Option<u64>, Query, description = "Number of seconds of history to return (default 300)")
    ),
    responses(
        (status = 200, description = "Historical metrics data"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_metrics_history(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    axum::extract::Query(params): axum::extract::Query<MetricsHistoryParams>,
) -> Result<Json<Vec<AggregatedMetrics>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let seconds = params.seconds.unwrap_or(300);
    let history = state.get_metrics_history(seconds);

    Ok(Json(history))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttackStats {
    pub total_blocked: u64,
    pub by_type: std::collections::HashMap<String, u64>,
}

#[utoipa::path(
    get,
    path = "/stats/attacks",
    tag = "Stats",
    responses(
        (status = 200, description = "Attack statistics", body = [AttackStats]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_attack_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<AttackStats>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let metrics = state.get_metrics();

    let stats = AttackStats {
        total_blocked: metrics.blocked,
        by_type: metrics.blocked_by_type,
    };

    Ok(Json(stats))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CacheStats {
    pub proxy_cache_hits: u64,
    pub proxy_cache_misses: u64,
    pub proxy_cache_hit_rate: f64,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
    pub static_cache_hit_rate: f64,
}

#[utoipa::path(
    get,
    path = "/stats/cache",
    tag = "Stats",
    responses(
        (status = 200, description = "Cache statistics", body = [CacheStats]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_cache_stats(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<CacheStats>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let proxy_hits = get_proxy_cache_hits();
    let proxy_misses = get_proxy_cache_misses();
    let proxy_total = proxy_hits + proxy_misses;
    let proxy_hit_rate = if proxy_total > 0 {
        (proxy_hits as f64 / proxy_total as f64) * 100.0
    } else {
        0.0
    };

    let (static_cache_hits, static_cache_misses) = if let Some(ref pm) = state.process_manager {
        pm.get_static_worker_cache_stats()
    } else {
        (0, 0)
    };
    let static_total = static_cache_hits + static_cache_misses;
    let static_cache_hit_rate = if static_total > 0 {
        (static_cache_hits as f64 / static_total as f64) * 100.0
    } else {
        0.0
    };

    let stats = CacheStats {
        proxy_cache_hits: proxy_hits,
        proxy_cache_misses: proxy_misses,
        proxy_cache_hit_rate: proxy_hit_rate,
        static_cache_hits,
        static_cache_misses,
        static_cache_hit_rate,
    };

    Ok(Json(stats))
}

use crate::metrics::bandwidth::{get_global_bandwidth_tracker, BandwidthPayload};

#[utoipa::path(
    get,
    path = "/stats/bandwidth",
    tag = "Stats",
    responses(
        (status = 200, description = "Bandwidth statistics"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_bandwidth(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<BandwidthPayload>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tracker = get_global_bandwidth_tracker();
    let payload = tracker.to_payload();

    Ok(Json(payload))
}

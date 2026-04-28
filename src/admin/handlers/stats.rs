use super::super::state::{AdminState, AggregatedMetrics};
use super::common::OptionalAuth;
use crate::metrics::{get_proxy_cache_hits, get_proxy_cache_misses, RequestLogPayload};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct SystemStats {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub requests_per_second: f64,
    #[schema(example = 0.05)]
    pub blocked_per_second: f64,
    pub active_connections: u32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    #[schema(example = 12.5)]
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

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
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
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
}

#[utoipa::path(
    get,
    path = "/stats/summary",
    responses(
        (status = 200, description = "System statistics", body = SystemStats),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_summary(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<SystemStats>, StatusCode> {
    let config = state.process.config.read().await;
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
    responses(
        (status = 200, description = "Site statistics", body = Vec<SiteStats>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_sites_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<SiteStats>>, StatusCode> {
    let config = state.process.config.read().await;
    let site_metrics = state.get_site_metrics();
    let _global_metrics = state.get_metrics();
    let uptime = state.uptime();

    let site_stats: Vec<SiteStats> = config
        .sites
        .iter()
        .map(|(id, site)| {
            let site_metric = site_metrics.get(id);

            let site_uptime = uptime.max(1);
            let site_rps = if let Some(sm) = site_metric {
                sm.total_requests as f64 / site_uptime as f64
            } else {
                0.0
            };

            SiteStats {
                site_id: id.clone(),
                domains: site.site.domains.clone(),
                requests_per_second: site_rps,
                active_connections: site_metric
                    .map(|m| m.current_concurrent as u32)
                    .unwrap_or(0),
                blocked_requests: site_metric.map(|m| m.blocked).unwrap_or(0),
                challenged_requests: site_metric.map(|m| m.challenged).unwrap_or(0),
                proxied_requests: site_metric.map(|m| m.proxied).unwrap_or(0),
                errors: site_metric.map(|m| m.errors).unwrap_or(0),
                avg_response_time_ms: site_metric.map(|m| m.avg_latency_ms).unwrap_or(0.0),
                p50_latency_ms: site_metric.map(|m| m.p50_latency_ms).unwrap_or(0.0),
                p95_latency_ms: site_metric.map(|m| m.p95_latency_ms).unwrap_or(0.0),
                p99_latency_ms: site_metric.map(|m| m.p99_latency_ms).unwrap_or(0.0),
                upstream_healthy: site_metric.map(|m| m.upstream_healthy).unwrap_or(true),
                bytes_received: site_metric.map(|m| m.bytes_received).unwrap_or(0),
                bytes_sent: site_metric.map(|m| m.bytes_sent).unwrap_or(0),
                proxied_bytes_sent: site_metric.map(|m| m.proxied_bytes_sent).unwrap_or(0),
                proxied_bytes_received: site_metric.map(|m| m.proxied_bytes_received).unwrap_or(0),
                mesh_bytes_sent: site_metric.map(|m| m.mesh_bytes_sent).unwrap_or(0),
                mesh_bytes_received: site_metric.map(|m| m.mesh_bytes_received).unwrap_or(0),
            }
        })
        .collect();

    Ok(Json(site_stats))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MetricsHistoryParams {
    pub seconds: Option<u64>,
}

#[utoipa::path(
    get,
    path = "/stats/history",
    params(
        ("seconds" = Option<u64>, Query, description = "Time window in seconds (default: 300)")
    ),
    responses(
        (status = 200, description = "Metrics history"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_metrics_history(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    axum::extract::Query(params): axum::extract::Query<MetricsHistoryParams>,
) -> Result<Json<Vec<AggregatedMetrics>>, StatusCode> {
    let seconds = params.seconds.unwrap_or(300);
    let history = state.get_metrics_history(seconds);

    Ok(Json(history))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AttackStats {
    pub total_blocked: u64,
    pub by_type: std::collections::HashMap<String, u64>,
}

#[utoipa::path(
    get,
    path = "/stats/attacks",
    responses(
        (status = 200, description = "Attack statistics", body = AttackStats),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_attack_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<AttackStats>, StatusCode> {
    let metrics = state.get_metrics();

    let stats = AttackStats {
        total_blocked: metrics.blocked,
        by_type: metrics.blocked_by_type,
    };

    Ok(Json(stats))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
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
    responses(
        (status = 200, description = "Cache statistics", body = CacheStats),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_cache_stats(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<CacheStats>, StatusCode> {
    let proxy_hits = get_proxy_cache_hits();
    let proxy_misses = get_proxy_cache_misses();
    let proxy_total = proxy_hits + proxy_misses;
    let proxy_hit_rate = if proxy_total > 0 {
        (proxy_hits as f64 / proxy_total as f64) * 100.0
    } else {
        0.0
    };

    let (static_cache_hits, static_cache_misses) =
        if let Some(ref pm) = state.process.process_manager {
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
    responses(
        (status = 200, description = "Bandwidth statistics"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_bandwidth(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<BandwidthPayload>, StatusCode> {
    let tracker = get_global_bandwidth_tracker().map_err(|e| {
        tracing::error!("{}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let payload = tracker.to_payload();

    Ok(Json(payload))
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct RequestLogResponse {
    pub id: String,
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_time_ms: u32,
    pub site_id: String,
    pub user_agent: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RequestLogsResponse {
    pub entries: Vec<RequestLogResponse>,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RequestLogsQuery {
    pub site_id: Option<String>,
    pub method: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[utoipa::path(
    get,
    path = "/stats/request-logs",
    params(
        ("site_id" = Option<String>, Query, description = "Filter by site ID"),
        ("method" = Option<String>, Query, description = "Filter by HTTP method"),
        ("status" = Option<String>, Query, description = "Filter by status code prefix"),
        ("search" = Option<String>, Query, description = "Search in path and IP"),
        ("limit" = Option<usize>, Query, description = "Number of logs to return (max 1000)"),
        ("offset" = Option<usize>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "Request logs", body = RequestLogsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "stats"
)]
pub async fn get_request_logs(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Query(query): Query<RequestLogsQuery>,
) -> Result<Json<RequestLogsResponse>, StatusCode> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let all_logs = if let Some(ref pm) = state.process.process_manager {
        pm.get_request_logs()
    } else {
        Vec::new()
    };

    let filtered: Vec<RequestLogPayload> = all_logs
        .iter()
        .filter(|log| {
            if let Some(ref site_id) = query.site_id {
                if &log.site_id != site_id {
                    return false;
                }
            }
            if let Some(ref method) = query.method {
                if !log.method.eq_ignore_ascii_case(method) {
                    return false;
                }
            }
            if let Some(ref status_prefix) = query.status {
                let status_str = log.status.to_string();
                if !status_str.starts_with(status_prefix) {
                    return false;
                }
            }
            if let Some(ref search) = query.search {
                let search_lower = search.to_lowercase();
                if !log.path.to_lowercase().contains(&search_lower)
                    && !log.client_ip.contains(&search_lower)
                {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let total = filtered.len();
    let has_more = offset + limit < total;

    let entries: Vec<RequestLogResponse> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .enumerate()
        .map(|(i, e)| RequestLogResponse {
            id: format!("log-{}", i),
            timestamp: chrono::DateTime::from_timestamp(e.timestamp as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            client_ip: e.client_ip,
            method: e.method,
            path: e.path,
            status: e.status,
            response_time_ms: e.response_time_ms,
            site_id: e.site_id,
            user_agent: e.user_agent,
            bytes_sent: e.bytes_sent,
            bytes_received: e.bytes_received,
        })
        .collect();

    Ok(Json(RequestLogsResponse {
        entries,
        total,
        has_more,
    }))
}

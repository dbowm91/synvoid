use crate::bandwidth::BandwidthPayload;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    #[default]
    Healthy,
    Unhealthy,
    Unknown,
}

impl HealthStatus {
    pub fn as_bool(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMetricsPayload {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub blocked_by_type: HashMap<String, u64>,
    pub upstream_healthy: HealthStatus,
    pub proxy_cache_hits: u64,
    pub proxy_cache_misses: u64,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
    pub total_backends: usize,
    pub metrics_timestamp_ms: u64,
}

#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogPayload {
    pub timestamp: u64,
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

#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct TimingStatsPayload {
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerMetricsPayload {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub uptime_secs: u64,
    pub memory_bytes: u64,
    pub cpu_percent: f64,
    pub event_loop_lag_ms: u64,
    pub request_queue_time_ms: TimingStatsPayload,
    pub inline_cpu_phase_times_ms: HashMap<String, TimingStatsPayload>,
    pub body_buffering_bytes_total: u64,
    pub offload_submissions_total: u64,
    pub offload_timeouts_total: u64,
    pub offload_rejections_total: u64,
    pub offload_fallbacks_total: u64,
    pub blocked_by_type: HashMap<String, u64>,
    pub per_site: HashMap<String, SiteMetricsPayload>,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
    pub bandwidth: BandwidthPayload,
    pub serverless_metrics: Vec<ServerlessMetrics>,
    pub health_score: f64,
    pub last_request_at: Option<u64>,
    pub active_connections: u64,
    pub restart_count: u32,
    pub mesh_phase: String,
    pub mesh_restart_attempts: u32,
    pub mesh_healthy: bool,
    pub mesh_degraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub proxy_cache_hits: u64,
    pub proxy_cache_misses: u64,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessMetrics {
    pub function_name: String,
    pub invocations_total: u64,
    pub errors_total: u64,
    pub avg_duration_ms: f64,
    pub active_instances: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedEventCounts {
    pub tls_reload: u64,
    pub threat_level: u64,
    pub process: u64,
    pub worker: u64,
    pub yara_broadcast: u64,
    pub total: u64,
}

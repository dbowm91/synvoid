use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use synvoid_core::admin_mutation::AdminAuditEvent;
use synvoid_ipc::ProcessManager;
use synvoid_metrics::payloads::SiteMetricsPayload;
use synvoid_waf::probe_tracker::{ProbeTracker, SuspiciousWordTracker, UpstreamErrorTracker};
use tokio::sync::RwLock as TokioRwLock;

use synvoid_config::ConfigManager;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AggregatedMetrics {
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
    pub requests_per_second: f64,
    pub blocked_per_second: f64,
    pub healthy_backends: usize,
    pub unhealthy_backends: usize,
    pub healthy_workers: usize,
    pub unhealthy_workers: usize,
    pub blocked_by_type: HashMap<String, u64>,
    pub metrics_timestamp_ms: u64,
}

#[derive(Clone, Default)]
pub struct SystemResources {
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub cpu_usage_percent: f32,
    pub time_validation_errors: u64,
}

#[derive(Debug, Clone)]
pub struct RequestLogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub action: String,
    pub target_resource: String,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub success: bool,
}

pub trait AdminStateProvider: Send + Sync {
    fn get_metrics(&self) -> AggregatedMetrics;
    fn get_site_metrics(&self) -> HashMap<String, SiteMetricsPayload>;
    fn get_metrics_history(&self, seconds: u64) -> Vec<AggregatedMetrics>;
    fn get_system_resources(&self) -> SystemResources;
    fn uptime(&self) -> u64;
    fn get_request_logs(
        &self,
        site_id: Option<&str>,
        method: Option<&str>,
        status_prefix: Option<&str>,
        search: Option<&str>,
        from_timestamp: Option<DateTime<Utc>>,
        to_timestamp: Option<DateTime<Utc>>,
        limit: usize,
        offset: usize,
    ) -> (Vec<RequestLogEntry>, usize, bool);
    fn probe_tracker(&self) -> Option<&Arc<ProbeTracker>>;
    fn suspicious_word_tracker(&self) -> Option<&Arc<SuspiciousWordTracker>>;
    fn upstream_error_tracker(&self) -> Option<&Arc<UpstreamErrorTracker>>;
    fn process_manager(&self) -> Option<&Arc<ProcessManager>>;
    fn config(&self) -> Arc<TokioRwLock<ConfigManager>>;
    fn get_audit_logs(&self, limit: usize, offset: usize) -> Vec<AuditLog>;
    fn get_audit_logs_for_user(&self, username: &str, limit: usize) -> Vec<AuditLog>;
    fn get_audit_logs_for_resource(&self, resource: &str, limit: usize) -> Vec<AuditLog>;
    fn audit_log_count(&self) -> usize;
    fn log_admin_audit_event(&self, event: &AdminAuditEvent);
}

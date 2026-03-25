use super::alerting::AlertManager;
use super::ws::broadcaster::Broadcaster;
use crate::config::ConfigManager;
use crate::mesh::transport::MeshTransport;
use crate::process::ProcessManager;
use crate::process::SiteMetricsPayload;
use crate::waf::{
    ProbeTracker, RuleFeedManagerForWaf, SuspiciousWordTracker, ThreatLevelManager,
    UpstreamErrorTracker,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock as TokioRwLock;

#[derive(Clone)]
pub struct AdminRateLimiter {
    inner: Arc<AdminRateLimiterInner>,
}

struct AdminRateLimiterInner {
    requests: RwLock<HashMap<String, (u32, Instant)>>,
    requests_per_minute: u32,
    burst: u32,
}

impl AdminRateLimiter {
    pub fn new(requests_per_minute: u32, burst: u32) -> Self {
        Self {
            inner: Arc::new(AdminRateLimiterInner {
                requests: RwLock::new(HashMap::new()),
                requests_per_minute,
                burst,
            }),
        }
    }

    pub fn check(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut requests = self.inner.requests.write();

        if let Some((count, window_start)) = requests.get(ip) {
            let elapsed = now.duration_since(*window_start);
            if elapsed.as_secs() < 60 {
                return *count < self.inner.requests_per_minute;
            }
        }

        requests.insert(ip.to_string(), (1, now));
        true
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut requests = self.inner.requests.write();
        requests.retain(|_, (_, window_start)| now.duration_since(*window_start).as_secs() < 120);
    }
}

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
    pub blocked_by_type: std::collections::HashMap<String, u64>,
}

#[derive(Clone, Default)]
pub struct SystemResources {
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub cpu_usage_percent: f32,
    pub time_validation_errors: u64,
}

#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<TokioRwLock<ConfigManager>>,
    pub admin_token: String,
    pub metrics_broadcaster: Arc<Broadcaster>,
    pub logs_broadcaster: Arc<Broadcaster>,
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub metrics: Arc<RwLock<AggregatedMetrics>>,
    pub system_resources: Arc<RwLock<SystemResources>>,
    pub metrics_history: Arc<RwLock<Vec<AggregatedMetrics>>>,
    pub site_metrics: Arc<RwLock<HashMap<String, SiteMetricsPayload>>>,
    pub start_time: Instant,
    pub process_manager: Option<Arc<ProcessManager>>,
    pub alert_manager: Option<Arc<AlertManager>>,
    pub mesh_transport: Option<Arc<MeshTransport>>,
    pub client_audit_manager: Option<Arc<crate::mesh::client_audit::ClientAuditManager>>,
    csrf_tokens: Arc<RwLock<std::collections::HashMap<String, CsrfTokenState>>>,
    pub rate_limiter: Option<Arc<AdminRateLimiter>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    #[cfg(feature = "icmp-filter")]
    pub icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
    pub port_honeypot_controller: Option<Arc<crate::honeypot_port::HoneypotMeshController>>,
    pub port_honeypot_runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
    pub request_logs: Arc<RwLock<Vec<RequestLogEntry>>>,
}

#[derive(Clone)]
pub struct RequestLogEntry {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
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

impl RequestLogEntry {
    pub fn new(
        client_ip: String,
        method: String,
        path: String,
        status: u16,
        response_time_ms: u32,
        site_id: String,
        user_agent: Option<String>,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            client_ip,
            method,
            path,
            status,
            response_time_ms,
            site_id,
            user_agent,
            bytes_sent,
            bytes_received,
        }
    }
}

const MAX_REQUEST_LOGS: usize = 10000;
const MAX_HISTORY_SIZE: usize = 3600;

impl AdminState {
    pub fn new(config: Arc<TokioRwLock<ConfigManager>>, admin_token: String) -> Self {
        Self {
            config,
            admin_token,
            metrics_broadcaster: Arc::new(Broadcaster::new(100)),
            logs_broadcaster: Arc::new(Broadcaster::new(1000)),
            probe_tracker: None,
            suspicious_word_tracker: None,
            upstream_error_tracker: None,
            threat_level_manager: None,
            metrics: Arc::new(RwLock::new(AggregatedMetrics::default())),
            system_resources: Arc::new(RwLock::new(SystemResources::default())),
            metrics_history: Arc::new(RwLock::new(Vec::with_capacity(MAX_HISTORY_SIZE))),
            site_metrics: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
            process_manager: None,
            alert_manager: Some(Arc::new(AlertManager::new())),
            mesh_transport: None,
            client_audit_manager: None,
            csrf_tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
            rate_limiter: None,
            rule_feed_manager: None,
            #[cfg(feature = "icmp-filter")]
            icmp_filter: None,
            port_honeypot_controller: None,
            port_honeypot_runner: None,
            request_logs: Arc::new(RwLock::new(Vec::with_capacity(MAX_REQUEST_LOGS))),
        }
    }

    pub fn with_rate_limiter(mut self, rate_limiter: Option<Arc<AdminRateLimiter>>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    pub fn with_probe_tracker(mut self, tracker: Option<Arc<ProbeTracker>>) -> Self {
        self.probe_tracker = tracker;
        self
    }

    pub fn with_suspicious_word_tracker(
        mut self,
        tracker: Option<Arc<SuspiciousWordTracker>>,
    ) -> Self {
        self.suspicious_word_tracker = tracker;
        self
    }

    pub fn with_upstream_error_tracker(
        mut self,
        tracker: Option<Arc<UpstreamErrorTracker>>,
    ) -> Self {
        self.upstream_error_tracker = tracker;
        self
    }

    pub fn with_threat_level_manager(mut self, manager: Option<Arc<ThreatLevelManager>>) -> Self {
        self.threat_level_manager = manager;
        self
    }

    pub fn with_rule_feed_manager(mut self, manager: Option<Arc<RuleFeedManagerForWaf>>) -> Self {
        self.rule_feed_manager = manager;
        self
    }

    pub fn with_process_manager(mut self, manager: Option<Arc<ProcessManager>>) -> Self {
        self.process_manager = manager;
        self
    }

    pub fn with_mesh_transport(mut self, transport: Option<Arc<MeshTransport>>) -> Self {
        self.mesh_transport = transport;
        self
    }

    pub fn with_client_audit_manager(
        mut self,
        manager: Option<Arc<crate::mesh::client_audit::ClientAuditManager>>,
    ) -> Self {
        self.client_audit_manager = manager;
        self
    }

    #[cfg(feature = "icmp-filter")]
    pub fn with_icmp_filter(mut self, filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>) -> Self {
        self.icmp_filter = filter;
        self
    }

    pub fn with_port_honeypot_controller(
        mut self,
        controller: Option<Arc<crate::honeypot_port::HoneypotMeshController>>,
    ) -> Self {
        self.port_honeypot_controller = controller;
        self
    }

    pub fn with_port_honeypot_runner(
        mut self,
        runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
    ) -> Self {
        self.port_honeypot_runner = runner;
        self
    }

    #[cfg(not(feature = "icmp-filter"))]
    pub fn with_icmp_filter(self, _filter: Option<Arc<TokioRwLock<()>>>) -> Self {
        self
    }

    pub fn probe_tracker(&self) -> Option<&Arc<ProbeTracker>> {
        self.probe_tracker.as_ref()
    }

    pub fn suspicious_word_tracker(&self) -> Option<&Arc<SuspiciousWordTracker>> {
        self.suspicious_word_tracker.as_ref()
    }

    pub fn upstream_error_tracker(&self) -> Option<&Arc<UpstreamErrorTracker>> {
        self.upstream_error_tracker.as_ref()
    }

    pub fn threat_level_manager(&self) -> Option<&Arc<ThreatLevelManager>> {
        self.threat_level_manager.as_ref()
    }

    #[cfg(feature = "icmp-filter")]
    pub fn icmp_filter(&self) -> Option<&Arc<TokioRwLock<IcmpFilterManager>>> {
        self.icmp_filter.as_ref()
    }

    pub fn update_metrics(&self, metrics: AggregatedMetrics) {
        *self.metrics.write() = metrics;
    }

    pub fn get_metrics(&self) -> AggregatedMetrics {
        self.metrics.read().clone()
    }

    pub async fn setup_site_config_sync(&self) {
        let mesh_transport = match &self.mesh_transport {
            Some(t) => t.clone(),
            None => {
                tracing::debug!("No mesh transport available for site config sync");
                return;
            }
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(32);
        mesh_transport.set_site_config_sync_callback(tx);

        let config = self.config.clone();
        
        tokio::spawn(async move {
            while let Some((site_id, config_json)) = rx.recv().await {
                tracing::info!("Received site config sync for site: {}", site_id);

                let config_path = {
                    let cfg = config.read().await;
                    cfg.sites_dir.join(format!("{}.toml", site_id.replace('.', "_")))
                };

                if let Err(e) = tokio::fs::write(&config_path, &config_json).await {
                    tracing::error!("Failed to write synced site config for {}: {}", site_id, e);
                    continue;
                }

                let mut cfg = config.write().await;
                if let Err(e) = cfg.load_site(std::path::PathBuf::from(&config_path)) {
                    tracing::error!("Failed to reload synced site config for {}: {}", site_id, e);
                } else {
                    tracing::info!("Successfully applied synced site config for {}", site_id);
                }
            }
        });
    }

    pub fn update_system_resources(&self, resources: SystemResources) {
        *self.system_resources.write() = resources;
    }

    pub fn get_system_resources(&self) -> SystemResources {
        (*self.system_resources.read()).clone()
    }

    pub fn add_metrics_to_history(&self, metrics: AggregatedMetrics) {
        let mut history = self.metrics_history.write();
        if history.len() >= MAX_HISTORY_SIZE {
            history.remove(0);
        }
        history.push(metrics);
    }

    pub fn get_metrics_history(&self, seconds: u64) -> Vec<AggregatedMetrics> {
        let history = self.metrics_history.read();
        let count = seconds.min(MAX_HISTORY_SIZE as u64) as usize;
        let start = if history.len() > count {
            history.len() - count
        } else {
            0
        };
        history[start..].to_vec()
    }

    pub fn update_site_metrics(&self, site_metrics: HashMap<String, SiteMetricsPayload>) {
        *self.site_metrics.write() = site_metrics;
    }

    pub fn get_site_metrics(&self) -> HashMap<String, SiteMetricsPayload> {
        self.site_metrics.read().clone()
    }

    pub fn add_request_log(&self, entry: RequestLogEntry) {
        let mut logs = self.request_logs.write();
        if logs.len() >= MAX_REQUEST_LOGS {
            logs.remove(0);
        }
        logs.push(entry);
    }

    pub fn get_request_logs(
        &self,
        site_id: Option<&str>,
        method: Option<&str>,
        status_prefix: Option<&str>,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> (Vec<RequestLogEntry>, usize, bool) {
        let logs = self.request_logs.read();

        let filtered: Vec<RequestLogEntry> = logs
            .iter()
            .filter(|log| {
                if let Some(site_id) = site_id {
                    if &log.site_id != site_id {
                        return false;
                    }
                }
                if let Some(method) = method {
                    if !log.method.eq_ignore_ascii_case(method) {
                        return false;
                    }
                }
                if let Some(prefix) = status_prefix {
                    let status_str = log.status.to_string();
                    if !status_str.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(search) = search {
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
        let result: Vec<RequestLogEntry> = filtered.into_iter().skip(offset).take(limit).collect();

        (result, total, has_more)
    }

    pub fn uptime(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn validate_csrf(&self, token: &str) -> bool {
        use std::time::Duration;

        let now = Instant::now();
        let csrf_tokens = self.csrf_tokens.read();

        if let Some(valid_token) = csrf_tokens.get(token) {
            if now.duration_since(valid_token.created) < Duration::from_secs(3600) {
                return true;
            }
        }

        false
    }

    pub fn generate_csrf_token(&self) -> String {
        use uuid::Uuid;

        let token = Uuid::new_v4().to_string();
        let now = Instant::now();

        self.csrf_tokens
            .write()
            .insert(token.clone(), CsrfTokenState { created: now });

        token
    }

    pub fn cleanup_expired_csrf_tokens(&self) {
        use std::time::Duration;

        let now = Instant::now();
        let mut tokens = self.csrf_tokens.write();

        tokens.retain(|_, v| now.duration_since(v.created) < Duration::from_secs(3600));
    }
}

struct CsrfTokenState {
    created: Instant,
}

static CURRENT_CONNECTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn get_current_connections() -> u64 {
    CURRENT_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_current_connections(count: u64) {
    CURRENT_CONNECTIONS.store(count, std::sync::atomic::Ordering::Relaxed);
}

pub fn get_cpu_memory_usage() -> (f32, f32) {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let cpus = sys.cpus();
    let cpu_percent = if !cpus.is_empty() {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    } else {
        0.0
    };
    let memory_percent = if sys.total_memory() > 0 {
        (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0
    } else {
        0.0
    };
    (cpu_percent, memory_percent)
}

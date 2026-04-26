use super::alerting::AlertManager;
use super::audit::{AuditState, ConfigVersionManager};
use super::ws::broadcaster::Broadcaster;
use crate::config::ConfigManager;
use crate::mesh::transport::MeshTransport;
use crate::plugin::PluginManager;
use crate::process::ProcessManager;
use crate::process::SiteMetricsPayload;
use crate::waf::{
    ProbeTracker, RuleFeedManagerForWaf, SuspiciousWordTracker, ThreatLevelManager,
    UpstreamErrorTracker,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock as TokioRwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadEvent {
    pub timestamp: String,
    pub plugin_name: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct AdminRateLimiter {
    inner: Arc<AdminRateLimiterInner>,
}

struct AdminRateLimiterInner {
    requests: RwLock<HashMap<String, (u32, Instant)>>,
    requests_per_minute: u32,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YaraRateLimitOp {
    Submit,
    BroadcastApply,
    ApproveReject,
    StatusList,
}

#[derive(Clone)]
pub struct YaraRateLimiter {
    inner: Arc<YaraRateLimiterInner>,
}

struct YaraRateLimiterInner {
    submit_limiter: AdminRateLimiter,
    broadcast_apply_limiter: AdminRateLimiter,
    approve_reject_limiter: AdminRateLimiter,
    status_list_limiter: AdminRateLimiter,
}

impl YaraRateLimiter {
    pub fn new(
        submit_limit: u32,
        broadcast_apply_limit: u32,
        approve_reject_limit: u32,
        status_list_limit: u32,
    ) -> Self {
        Self {
            inner: Arc::new(YaraRateLimiterInner {
                submit_limiter: AdminRateLimiter::new(submit_limit, 1),
                broadcast_apply_limiter: AdminRateLimiter::new(broadcast_apply_limit, 1),
                approve_reject_limiter: AdminRateLimiter::new(approve_reject_limit, 1),
                status_list_limiter: AdminRateLimiter::new(status_list_limit, 1),
            }),
        }
    }

    pub fn default_for_yara() -> Self {
        Self::new(10, 5, 10, 30)
    }

    pub fn check(&self, ip: &str, op: YaraRateLimitOp) -> bool {
        match op {
            YaraRateLimitOp::Submit => self.inner.submit_limiter.check(ip),
            YaraRateLimitOp::BroadcastApply => self.inner.broadcast_apply_limiter.check(ip),
            YaraRateLimitOp::ApproveReject => self.inner.approve_reject_limiter.check(ip),
            YaraRateLimitOp::StatusList => self.inner.status_list_limiter.check(ip),
        }
    }

    pub fn cleanup(&self) {
        self.inner.submit_limiter.cleanup();
        self.inner.broadcast_apply_limiter.cleanup();
        self.inner.approve_reject_limiter.cleanup();
        self.inner.status_list_limiter.cleanup();
    }

    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.cleanup();
            }
        });
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
pub struct MetricsState {
    pub metrics_broadcaster: Arc<Broadcaster>,
    pub metrics: Arc<RwLock<AggregatedMetrics>>,
    pub system_resources: Arc<RwLock<SystemResources>>,
    pub metrics_history: Arc<RwLock<VecDeque<AggregatedMetrics>>>,
    pub site_metrics: Arc<RwLock<HashMap<String, SiteMetricsPayload>>>,
    pub start_time: Instant,
    pub request_logs: Arc<RwLock<VecDeque<RequestLogEntry>>>,
    pub logs_broadcaster: Arc<Broadcaster>,
    pub config_write_lock: Arc<TokioRwLock<()>>,
}

#[derive(Clone)]
pub struct WafTrackingState {
    pub probe_tracker: Option<Arc<ProbeTracker>>,
    pub suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    pub upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    pub threat_level_manager: Option<Arc<ThreatLevelManager>>,
    pub rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    pub yara_rules: Option<Arc<crate::mesh::yara_rules::YaraRulesManager>>,
}

#[derive(Clone)]
pub struct SecurityState {
    pub admin_token: String,
    pub csrf_tokens: Arc<RwLock<std::collections::HashMap<String, CsrfTokenData>>>,
    pub rate_limiter: Option<Arc<AdminRateLimiter>>,
    pub yara_rate_limiter: Option<Arc<YaraRateLimiter>>,
}

#[derive(Clone)]
pub struct MeshState {
    pub mesh_transport: Option<Arc<MeshTransport>>,
    pub client_audit_manager: Option<Arc<crate::mesh::client_audit::ClientAuditManager>>,
}

#[derive(Clone)]
pub struct HoneypotState {
    pub port_honeypot_controller: Option<Arc<crate::honeypot_port::HoneypotMeshController>>,
    pub port_honeypot_runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
    #[cfg(feature = "icmp-filter")]
    pub icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
}

#[derive(Clone)]
pub struct ProcessState {
    pub config: Arc<TokioRwLock<ConfigManager>>,
    pub process_manager: Option<Arc<ProcessManager>>,
    pub alert_manager: Option<Arc<AlertManager>>,
    pub plugin_manager: Option<Arc<PluginManager>>,
}

#[derive(Clone)]
pub struct PluginsState {
    pub reload_log: Arc<RwLock<VecDeque<ReloadEvent>>>,
}

#[derive(Clone)]
pub struct AdminState {
    pub metrics: MetricsState,
    pub waf_tracking: WafTrackingState,
    pub security: SecurityState,
    pub mesh: MeshState,
    pub honeypot: HoneypotState,
    pub process: ProcessState,
    pub plugins: PluginsState,
    pub audit: AuditState,
    pub config_versions: ConfigVersionManager,
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
const MAX_CSRF_TOKENS_PER_SESSION: usize = 10;

impl AdminState {
    pub fn new(config: Arc<TokioRwLock<ConfigManager>>, admin_token: String) -> Self {
        Self {
            metrics: MetricsState {
                metrics_broadcaster: Arc::new(Broadcaster::new(100)),
                metrics: Arc::new(RwLock::new(AggregatedMetrics::default())),
                system_resources: Arc::new(RwLock::new(SystemResources::default())),
                metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_HISTORY_SIZE))),
                site_metrics: Arc::new(RwLock::new(HashMap::new())),
                start_time: Instant::now(),
                request_logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_REQUEST_LOGS))),
                logs_broadcaster: Arc::new(Broadcaster::new(1000)),
                config_write_lock: Arc::new(TokioRwLock::new(())),
            },
            waf_tracking: WafTrackingState {
                probe_tracker: None,
                suspicious_word_tracker: None,
                upstream_error_tracker: None,
                threat_level_manager: None,
                rule_feed_manager: None,
                yara_rules: None,
            },
            security: SecurityState {
                admin_token,
                csrf_tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
                rate_limiter: None,
                yara_rate_limiter: None,
            },
            mesh: MeshState {
                mesh_transport: None,
                client_audit_manager: None,
            },
            honeypot: HoneypotState {
                port_honeypot_controller: None,
                port_honeypot_runner: None,
                #[cfg(feature = "icmp-filter")]
                icmp_filter: None,
            },
            process: ProcessState {
                config,
                process_manager: None,
                alert_manager: Some(Arc::new(AlertManager::new())),
                plugin_manager: None,
            },
            plugins: PluginsState {
                reload_log: Arc::new(RwLock::new(VecDeque::new())),
            },
            audit: AuditState::new(),
            config_versions: ConfigVersionManager::new(std::path::PathBuf::new()),
        }
    }

    pub fn with_config_versions(mut self, config_versions: ConfigVersionManager) -> Self {
        self.config_versions = config_versions;
        self
    }

    pub fn with_rate_limiter(mut self, rate_limiter: Option<Arc<AdminRateLimiter>>) -> Self {
        self.security.rate_limiter = rate_limiter;
        self
    }

    pub fn with_yara_rate_limiter(mut self, rate_limiter: Option<Arc<YaraRateLimiter>>) -> Self {
        self.security.yara_rate_limiter = rate_limiter;
        self
    }

    pub fn with_probe_tracker(mut self, tracker: Option<Arc<ProbeTracker>>) -> Self {
        self.waf_tracking.probe_tracker = tracker;
        self
    }

    pub fn with_suspicious_word_tracker(
        mut self,
        tracker: Option<Arc<SuspiciousWordTracker>>,
    ) -> Self {
        self.waf_tracking.suspicious_word_tracker = tracker;
        self
    }

    pub fn with_upstream_error_tracker(
        mut self,
        tracker: Option<Arc<UpstreamErrorTracker>>,
    ) -> Self {
        self.waf_tracking.upstream_error_tracker = tracker;
        self
    }

    pub fn with_threat_level_manager(mut self, manager: Option<Arc<ThreatLevelManager>>) -> Self {
        self.waf_tracking.threat_level_manager = manager;
        self
    }

    pub fn with_rule_feed_manager(mut self, manager: Option<Arc<RuleFeedManagerForWaf>>) -> Self {
        self.waf_tracking.rule_feed_manager = manager;
        self
    }

    pub fn with_yara_rules(
        mut self,
        manager: Option<Arc<crate::mesh::yara_rules::YaraRulesManager>>,
    ) -> Self {
        self.waf_tracking.yara_rules = manager;
        self
    }

    pub fn with_process_manager(mut self, manager: Option<Arc<ProcessManager>>) -> Self {
        self.process.process_manager = manager;
        self
    }

    pub fn with_plugin_manager(mut self, manager: Option<Arc<PluginManager>>) -> Self {
        self.process.plugin_manager = manager;
        self
    }

    pub fn with_mesh_transport(mut self, transport: Option<Arc<MeshTransport>>) -> Self {
        self.mesh.mesh_transport = transport;
        self
    }

    pub fn with_client_audit_manager(
        mut self,
        manager: Option<Arc<crate::mesh::client_audit::ClientAuditManager>>,
    ) -> Self {
        self.mesh.client_audit_manager = manager;
        self
    }

    #[cfg(feature = "icmp-filter")]
    pub fn with_icmp_filter(mut self, filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>) -> Self {
        self.honeypot.icmp_filter = filter;
        self
    }

    pub fn with_port_honeypot_controller(
        mut self,
        controller: Option<Arc<crate::honeypot_port::HoneypotMeshController>>,
    ) -> Self {
        self.honeypot.port_honeypot_controller = controller;
        self
    }

    pub fn with_port_honeypot_runner(
        mut self,
        runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
    ) -> Self {
        self.honeypot.port_honeypot_runner = runner;
        self
    }

    pub fn with_honeypot_state(
        mut self,
        controller: Option<Arc<crate::honeypot_port::HoneypotMeshController>>,
        runner: Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
    ) -> Self {
        self.honeypot.port_honeypot_controller = controller;
        self.honeypot.port_honeypot_runner = runner;
        self
    }

    #[cfg(not(feature = "icmp-filter"))]
    pub fn with_icmp_filter(self, _filter: Option<Arc<TokioRwLock<()>>>) -> Self {
        self
    }

    pub fn probe_tracker(&self) -> Option<&Arc<ProbeTracker>> {
        self.waf_tracking.probe_tracker.as_ref()
    }

    pub fn suspicious_word_tracker(&self) -> Option<&Arc<SuspiciousWordTracker>> {
        self.waf_tracking.suspicious_word_tracker.as_ref()
    }

    pub fn upstream_error_tracker(&self) -> Option<&Arc<UpstreamErrorTracker>> {
        self.waf_tracking.upstream_error_tracker.as_ref()
    }

    pub fn threat_level_manager(&self) -> Option<&Arc<ThreatLevelManager>> {
        self.waf_tracking.threat_level_manager.as_ref()
    }

    #[cfg(feature = "icmp-filter")]
    pub fn icmp_filter(&self) -> Option<&Arc<TokioRwLock<IcmpFilterManager>>> {
        self.honeypot.icmp_filter.as_ref()
    }

    pub fn update_metrics(&self, metrics: AggregatedMetrics) {
        *self.metrics.metrics.write() = metrics;
    }

    pub fn get_metrics(&self) -> AggregatedMetrics {
        self.metrics.metrics.read().clone()
    }

    pub async fn setup_site_config_sync(&self) {
        let mesh_transport = match &self.mesh.mesh_transport {
            Some(t) => t.clone(),
            None => {
                tracing::debug!("No mesh transport available for site config sync");
                return;
            }
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(
            String,
            String,
            Option<crate::mesh::protocol::ProxyCachePreferences>,
        )>(32);
        mesh_transport.set_site_config_sync_callback(tx);

        let config = self.process.config.clone();
        let config_write_lock = self.metrics.config_write_lock.clone();

        tokio::spawn(async move {
            while let Some((site_id, config_json, proxy_cache_preferences)) = rx.recv().await {
                tracing::info!("Received site config sync for site: {}", site_id);

                let config_path = {
                    let cfg = config.read().await;
                    cfg.sites_dir
                        .join(format!("{}.toml", site_id.replace('.', "_")))
                };

                let final_config_json = if let Some(prefs) = proxy_cache_preferences {
                    match serde_json::from_str::<serde_json::Value>(&config_json) {
                        Ok(mut config) => {
                            let prefs_obj = serde_json::to_value(&prefs).unwrap_or_default();
                            config["proxy_cache_preferences"] = prefs_obj;
                            serde_json::to_string(&config).unwrap_or(config_json.clone())
                        }
                        Err(_) => config_json.clone(),
                    }
                } else {
                    config_json.clone()
                };

                {
                    let _guard = config_write_lock.write().await;
                    if let Err(e) = tokio::fs::write(&config_path, &final_config_json).await {
                        tracing::error!(
                            "Failed to write synced site config for {}: {}",
                            site_id,
                            e
                        );
                        continue;
                    }
                }

                let mut cfg = config.write().await;
                if let Err(e) = cfg.load_site(std::path::PathBuf::from(&config_path)) {
                    tracing::error!("Failed to reload synced site config for {}: {}", site_id, e);
                } else {
                    tracing::info!("Successfully applied synced site config for {}", site_id);
                    crate::http::server::invalidate_image_poison_cache_for_site(&site_id);
                }
            }
        });
    }

    pub fn update_system_resources(&self, resources: SystemResources) {
        *self.metrics.system_resources.write() = resources;
    }

    pub fn get_system_resources(&self) -> SystemResources {
        (*self.metrics.system_resources.read()).clone()
    }

    pub fn add_metrics_to_history(&self, metrics: AggregatedMetrics) {
        let mut history = self.metrics.metrics_history.write();
        if history.len() >= MAX_HISTORY_SIZE {
            history.pop_front();
        }
        history.push_back(metrics);
    }

    pub fn get_metrics_history(&self, seconds: u64) -> Vec<AggregatedMetrics> {
        let history = self.metrics.metrics_history.read();
        let count = seconds.min(MAX_HISTORY_SIZE as u64) as usize;
        let start = if history.len() > count {
            history.len() - count
        } else {
            0
        };
        history.iter().skip(start).cloned().collect()
    }

    pub fn update_site_metrics(&self, site_metrics: HashMap<String, SiteMetricsPayload>) {
        *self.metrics.site_metrics.write() = site_metrics;
    }

    pub fn get_site_metrics(&self) -> HashMap<String, SiteMetricsPayload> {
        self.metrics.site_metrics.read().clone()
    }

    pub fn add_request_log(&self, entry: RequestLogEntry) {
        let mut logs = self.metrics.request_logs.write();
        if logs.len() >= MAX_REQUEST_LOGS {
            logs.pop_front();
        }
        logs.push_back(entry);
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
        let logs = self.metrics.request_logs.read();

        let filtered: Vec<RequestLogEntry> = logs
            .iter()
            .filter(|log| {
                if let Some(site_id) = site_id {
                    if log.site_id != site_id {
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
        self.metrics.start_time.elapsed().as_secs()
    }

    pub fn validate_csrf(&self, token: &str, session_id: &str) -> bool {
        use std::time::Duration;

        let now = Instant::now();
        let csrf_tokens = self.security.csrf_tokens.read();

        if let Some(valid_token) = csrf_tokens.get(token) {
            if now.duration_since(valid_token.created) < Duration::from_secs(3600)
                && bool::from(
                    valid_token
                        .session_id
                        .as_bytes()
                        .ct_eq(session_id.as_bytes()),
                )
            {
                return true;
            }
        }

        false
    }

    pub fn generate_csrf_token(&self, session_id: String) -> String {
        use uuid::Uuid;

        let token = Uuid::new_v4().to_string();

        {
            let mut tokens = self.security.csrf_tokens.write();
            let count_for_session = tokens
                .iter()
                .filter(|(_, v)| v.session_id == session_id)
                .count();
            if count_for_session >= MAX_CSRF_TOKENS_PER_SESSION {
                let mut to_remove: Vec<_> = tokens
                    .iter()
                    .filter(|(_, v)| v.session_id == session_id)
                    .map(|(k, v)| (k.clone(), v.created))
                    .collect();
                to_remove.sort_by_key(|(_, created)| *created);
                let to_remove_count = count_for_session - MAX_CSRF_TOKENS_PER_SESSION + 1;
                for (key, _) in to_remove.into_iter().take(to_remove_count) {
                    tokens.remove(&key);
                }
            }
            tokens.insert(token.clone(), CsrfTokenData::new(session_id));
        }

        token
    }

    pub fn invalidate_csrf_tokens_for_session(&self, session_id: &str) {
        let mut tokens = self.security.csrf_tokens.write();
        tokens.retain(|_, v| v.session_id != session_id);
    }

    pub fn cleanup_expired_csrf_tokens(&self) {
        use std::time::Duration;

        let now = Instant::now();
        let mut tokens = self.security.csrf_tokens.write();

        tokens.retain(|_, v| now.duration_since(v.created) < Duration::from_secs(3600));
    }
}

pub struct CsrfTokenData {
    pub created: Instant,
    pub session_id: String,
}

impl CsrfTokenData {
    fn new(session_id: String) -> Self {
        Self {
            created: Instant::now(),
            session_id,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_state() -> AdminState {
        let config_dir = std::env::temp_dir();
        let config = Arc::new(TokioRwLock::new(crate::config::ConfigManager::new(
            config_dir,
        )));
        AdminState::new(config, "test_admin_token".to_string())
    }

    #[test]
    fn test_csrf_token_generation() {
        let state = create_test_state();
        let session_id = "test-session-123";

        let token = state.generate_csrf_token(session_id.to_string());
        assert!(!token.is_empty());
        assert_eq!(token.len(), 36);
    }

    #[test]
    fn test_csrf_token_generation_multiple_per_session() {
        let state = create_test_state();
        let session_id = "test-session-456";

        let tokens: Vec<String> = (0..5)
            .map(|_| state.generate_csrf_token(session_id.to_string()))
            .collect();

        for token in &tokens {
            assert!(state.validate_csrf(token, session_id));
        }
    }

    #[test]
    fn test_csrf_token_validation_valid() {
        let state = create_test_state();
        let session_id = "valid-session";

        let token = state.generate_csrf_token(session_id.to_string());
        assert!(state.validate_csrf(&token, session_id));
    }

    #[test]
    fn test_csrf_token_validation_invalid_token() {
        let state = create_test_state();
        let session_id = "some-session";

        let _token = state.generate_csrf_token(session_id.to_string());
        assert!(!state.validate_csrf("invalid-token", session_id));
    }

    #[test]
    fn test_csrf_token_validation_wrong_session() {
        let state = create_test_state();

        let token = state.generate_csrf_token("session-a".to_string());
        assert!(!state.validate_csrf(&token, "session-b"));
    }

    #[test]
    fn test_csrf_token_max_per_session() {
        let state = create_test_state();
        let session_id = "limited-session";

        for _ in 0..15 {
            let _ = state.generate_csrf_token(session_id.to_string());
        }

        let tokens = state.security.csrf_tokens.read();
        let count_for_session = tokens
            .iter()
            .filter(|(_, v)| v.session_id == session_id)
            .count();
        assert_eq!(count_for_session, MAX_CSRF_TOKENS_PER_SESSION);
    }

    #[test]
    fn test_invalidate_csrf_tokens_for_session() {
        let state = create_test_state();
        let session_id = "to-invalidate";

        state.generate_csrf_token(session_id.to_string());
        state.generate_csrf_token(session_id.to_string());

        state.invalidate_csrf_tokens_for_session(session_id);

        let tokens = state.security.csrf_tokens.read();
        assert_eq!(tokens.len(), 0);
    }

    #[test]
    fn test_cleanup_expired_csrf_tokens() {
        let state = create_test_state();
        let session_id = "cleanup-test";

        state.generate_csrf_token(session_id.to_string());

        state.cleanup_expired_csrf_tokens();
        assert_eq!(state.security.csrf_tokens.read().len(), 1);
    }

    #[test]
    fn test_admin_rate_limiter_check_allowed() {
        let limiter = AdminRateLimiter::new(100, 10);
        let ip = "192.168.1.1";

        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_admin_rate_limiter_multiple_ips() {
        let limiter = AdminRateLimiter::new(100, 10);

        assert!(limiter.check("192.168.1.1"));
        assert!(limiter.check("192.168.1.2"));
        assert!(limiter.check("192.168.1.3"));
    }

    #[test]
    fn test_admin_rate_limiter_cleanup() {
        let limiter = AdminRateLimiter::new(10, 1);
        let ip = "10.0.0.1";

        limiter.check(ip);
        limiter.check(ip);

        limiter.cleanup();

        assert!(limiter.check(ip));
    }

    #[test]
    fn test_yara_rate_limiter_operations() {
        let limiter = YaraRateLimiter::default_for_yara();
        let ip = "192.168.1.100";

        assert!(limiter.check(ip, YaraRateLimitOp::Submit));
        assert!(limiter.check(ip, YaraRateLimitOp::BroadcastApply));
        assert!(limiter.check(ip, YaraRateLimitOp::ApproveReject));
        assert!(limiter.check(ip, YaraRateLimitOp::StatusList));
    }

    #[test]
    fn test_yara_rate_limiter_separate_limits() {
        let limiter = YaraRateLimiter::new(2, 3, 4, 5);
        let ip = "test-ip";

        assert!(limiter.check(ip, YaraRateLimitOp::Submit));
        assert!(limiter.check(ip, YaraRateLimitOp::BroadcastApply));
        assert!(limiter.check(ip, YaraRateLimitOp::ApproveReject));
        assert!(limiter.check(ip, YaraRateLimitOp::StatusList));
    }

    #[test]
    fn test_csrf_token_data_creation() {
        let data = CsrfTokenData::new("session-xyz".to_string());
        assert_eq!(data.session_id, "session-xyz");
        assert!(data.created <= Instant::now());
    }

    #[test]
    fn test_request_log_entry_new() {
        let entry = RequestLogEntry::new(
            "192.168.1.1".to_string(),
            "GET".to_string(),
            "/test".to_string(),
            200,
            50,
            "site1".to_string(),
            Some("Mozilla/5.0".to_string()),
            1024,
            0,
        );

        assert!(!entry.id.is_empty());
        assert_eq!(entry.client_ip, "192.168.1.1");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/test");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.response_time_ms, 50);
    }

    #[test]
    fn test_request_log_entry_id_unique() {
        let entry1 = RequestLogEntry::new(
            "10.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
            201,
            100,
            "site2".to_string(),
            None,
            500,
            100,
        );

        let entry2 = RequestLogEntry::new(
            "10.0.0.2".to_string(),
            "POST".to_string(),
            "/api".to_string(),
            201,
            100,
            "site2".to_string(),
            None,
            500,
            100,
        );

        assert_ne!(entry1.id, entry2.id);
    }
}

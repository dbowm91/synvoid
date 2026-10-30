pub mod diagnostics;

// Re-exported for call sites that refer to these types by their full path.
// The nested per-section structs below (`RuntimeTaskSummary`, `PluginInfo`,
// `WorkerTaskStats`, …) are reachable through their parent's fields and are
// deliberately not re-exported here.
pub use diagnostics::{
    AuditLogsResponse, BlocklistHealthDiagnostics, ErrorPageResponse, FeaturesDiagnostics,
    PluginDiagnostics, RuntimeTasksDiagnostics, SecurityObservabilitySummary,
    ThreatIntelDiagnostics, UpdateErrorPageRequest,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    // The backend serializes `HealthStatus` (`healthy`/`unhealthy`/`unknown`,
    // lowercase) here — never a bool. A missing field degrades to `Unknown`
    // rather than failing the whole dashboard fetch.
    #[serde(default)]
    pub upstream_healthy: UpstreamHealth,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
}

/// Upstream health as reported by `GET /api/stats/sites`.
///
/// Mirrors the backend `HealthStatus` enum. `Unknown` is the steady state for
/// standalone mode (no health prober has reported yet) and must render as a
/// neutral third state — never red, never green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamHealth {
    Healthy,
    Unhealthy,
    #[default]
    Unknown,
}

impl UpstreamHealth {
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub default_upstream: String,
    pub routes: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamStatus {
    pub url: String,
    pub healthy: bool,
    pub current_connections: usize,
    pub max_connections: usize,
    pub weight: u32,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteUpstreams {
    pub site_id: String,
    pub default_upstream: String,
    pub backends: Vec<UpstreamStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub site_id: Option<String>,
    pub message: String,
    pub client_ip: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ConfigFieldSchema {
    pub path: String,
    pub label: String,
    pub field_type: String,
    pub default: Option<serde_json::Value>,
    pub description: String,
    pub impact: Option<String>,
    pub options: Option<Vec<String>>,
}

pub mod presets;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub build_timestamp: String,
    pub architecture: String,
    pub features: Vec<String>,
    pub running_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    pub version: String,
    pub mode: String,
    pub worker_mode: String,
    pub metrics: MasterMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterMetrics {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub proxied: u64,
    pub errors: u64,
    pub current_concurrent: u64,
    pub peak_concurrent: u64,
    pub requests_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub id: String,
    pub worker_type: String,
    pub pid: Option<u32>,
    pub status: String,
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub blocked: u64,
    pub errors: u64,
    pub memory_mb: u64,
    pub cpu_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCountResponse {
    pub current: usize,
    pub min: usize,
    pub max: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleWorkersResponse {
    pub success: bool,
    pub message: String,
    pub current_count: usize,
    pub target_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RealtimeMetrics {
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
    #[serde(default)]
    pub blocked_by_type: std::collections::HashMap<String, u64>,
    #[serde(default)]
    pub threat_level: Option<u8>,
    #[serde(default)]
    pub threat_level_is_manual: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct AttackStats {
    pub total_blocked: u64,
    #[serde(default)]
    pub by_type: std::collections::HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub proxy_cache_hits: u64,
    pub proxy_cache_misses: u64,
    pub proxy_cache_hit_rate: f64,
    pub static_cache_hits: u64,
    pub static_cache_misses: u64,
    pub static_cache_hit_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogsResponse {
    pub entries: Vec<RequestLogEntry>,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemePresetInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeColors {
    pub background: String,
    pub surface: String,
    pub primary: String,
    pub text: String,
    pub border: String,
    pub accent: String,
    pub accent_primary: String,
    pub accent_secondary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeColorsResponse {
    pub dark: ThemeColors,
    pub light: ThemeColors,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeResponse {
    pub preset: String,
    pub mode: String,
    #[serde(default)]
    pub dark_theme: String,
    #[serde(default)]
    pub light_theme: String,
    #[serde(default)]
    pub scheme: String,
    pub allow_only: String,
    pub colors: ThemeColorsResponse,
    pub presets_available: Vec<ThemePresetInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateThemeRequest {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub dark_theme: Option<String>,
    #[serde(default)]
    pub light_theme: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub allow_only: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteThemeResponse {
    pub site_id: String,
    pub preset: Option<String>,
    pub mode: Option<String>,
    pub allow_only: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteErrorPagesResponse {
    pub site_id: String,
    pub inherit: Option<bool>,
    pub mode: Option<String>,
    pub custom_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateSiteErrorPagesRequest {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub custom_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolBandwidth {
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolBandwidthPayload {
    pub http: ProtocolBandwidth,
    pub https: ProtocolBandwidth,
    pub http3: ProtocolBandwidth,
    pub tcp: ProtocolBandwidth,
    pub udp: ProtocolBandwidth,
    pub tunnel: ProtocolBandwidth,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteBandwidthPayload {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamBandwidthPayload {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonthlyPeriodPayload {
    pub period_start: String,
    pub days_elapsed: u32,
    pub days_remaining: u32,
    pub reset_mode: String,
    pub fixed_day: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BandwidthPayload {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub bytes_received_raw: u64,
    pub bytes_sent_raw: u64,
    pub proxied_bytes_received: u64,
    pub proxied_bytes_sent: u64,
    pub blocked_bytes_sent: u64,
    pub challenged_bytes_sent: u64,
    pub error_bytes_sent: u64,
    pub mesh_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub ingress_rate_bps: u64,
    pub egress_rate_bps: u64,
    pub monthly_bytes_received: u64,
    pub monthly_bytes_sent: u64,
    pub monthly_period: MonthlyPeriodPayload,
    pub per_protocol: ProtocolBandwidthPayload,
    #[serde(default)]
    pub per_site: std::collections::HashMap<String, SiteBandwidthPayload>,
    #[serde(default)]
    pub per_upstream: std::collections::HashMap<String, UpstreamBandwidthPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLevelStatus {
    pub level: u8,
    pub score: f64,
    pub request_score: f64,
    pub attack_score: f64,
    pub rate_limit_score: f64,
    pub throttling_multiplier: f64,
    pub is_learning: bool,
    pub learning_progress: f64,
    pub has_baseline: bool,
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub attacks_per_minute: u32,
    pub rate_limit_hits: u32,
    pub blocked: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySample {
    pub timestamp: i64,
    pub level: u8,
    pub score: f64,
    pub requests_per_minute: u32,
    pub attacks_per_minute: u32,
    pub rate_limit_hits: u32,
    pub blocked: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLevelHistory {
    pub minute: Vec<HistorySample>,
    pub hour: Vec<HistorySample>,
    pub day: Vec<HistorySample>,
    pub week: Vec<HistorySample>,
    pub month: Vec<HistorySample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetric {
    pub metric_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub min_value: f64,
    pub max_value: f64,
    pub samples: u64,
    pub computed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLevelBaseline {
    pub baselines: Vec<BaselineMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub timestamp: i64,
    pub level: u8,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupsListResponse {
    pub backups: Vec<BackupInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcessManagerConfig {
    #[serde(rename = "min_workers")]
    pub min_workers: usize,
    #[serde(rename = "max_workers")]
    pub max_workers: usize,
    #[serde(rename = "max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(rename = "restart_cooldown_secs")]
    pub restart_cooldown_secs: u64,
    #[serde(rename = "restart_backoff_max_secs")]
    pub restart_backoff_max_secs: u64,
    #[serde(rename = "heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(rename = "graceful_shutdown_timeout_secs")]
    pub graceful_shutdown_timeout_secs: u64,
    #[serde(rename = "worker_port_base")]
    pub worker_port_base: u16,
    #[serde(rename = "pre_spawn_workers")]
    pub pre_spawn_workers: usize,
    #[serde(rename = "warm_workers_target")]
    pub warm_workers_target: usize,
    #[serde(rename = "health_check_interval_secs")]
    pub health_check_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SupervisorConfig {
    #[serde(rename = "min_workers")]
    pub min_workers: usize,
    #[serde(rename = "max_workers")]
    pub max_workers: usize,
    #[serde(rename = "scale_up_threshold")]
    pub scale_up_threshold: f64,
    #[serde(rename = "scale_down_threshold")]
    pub scale_down_threshold: f64,
    #[serde(rename = "scale_up_cooldown_secs")]
    pub scale_up_cooldown_secs: u64,
    #[serde(rename = "scale_down_cooldown_secs")]
    pub scale_down_cooldown_secs: u64,
    #[serde(rename = "max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(rename = "restart_cooldown_secs")]
    pub restart_cooldown_secs: u64,
    #[serde(rename = "health_check_interval_secs")]
    pub health_check_interval_secs: u64,
    #[serde(rename = "graceful_shutdown_timeout_secs")]
    pub graceful_shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct HttpConfig {
    #[serde(rename = "request_timeout_secs")]
    pub request_timeout_secs: Option<u64>,
    #[serde(rename = "response_timeout_secs")]
    pub response_timeout_secs: Option<u64>,
    #[serde(rename = "keep_alive_timeout_secs")]
    pub keep_alive_timeout_secs: Option<u64>,
    #[serde(rename = "max_request_size_mb")]
    pub max_request_size_mb: Option<u64>,
    #[serde(rename = "max_response_size_mb")]
    pub max_response_size_mb: Option<u64>,
    #[serde(rename = "max_connections")]
    pub max_connections: Option<usize>,
    #[serde(rename = "max_concurrent_requests")]
    pub max_concurrent_requests: Option<usize>,
    #[serde(rename = "http2_enabled")]
    pub http2_enabled: Option<bool>,
    #[serde(rename = "compression_enabled")]
    pub compression_enabled: Option<bool>,
    #[serde(rename = "compression_min_size_bytes")]
    pub compression_min_size_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct LoggingConfig {
    #[serde(rename = "level")]
    pub level: Option<String>,
    #[serde(rename = "format")]
    pub format: Option<String>,
    #[serde(rename = "file_path")]
    pub file_path: Option<String>,
    #[serde(rename = "max_file_size_mb")]
    pub max_file_size_mb: Option<u64>,
    #[serde(rename = "max_files")]
    pub max_files: Option<u32>,
    #[serde(rename = "console_enabled")]
    pub console_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct SecurityConfig {
    #[serde(rename = "cors_enabled")]
    pub cors_enabled: Option<bool>,
    #[serde(rename = "cors_origins")]
    pub cors_origins: Option<Vec<String>>,
    #[serde(rename = "cors_allow_credentials")]
    pub cors_allow_credentials: Option<bool>,
    #[serde(rename = "cors_max_age_secs")]
    pub cors_max_age_secs: Option<u64>,
    #[serde(rename = "x_frame_options")]
    pub x_frame_options: Option<String>,
    #[serde(rename = "x_content_type_options")]
    pub x_content_type_options: Option<String>,
    #[serde(rename = "x_xss_protection")]
    pub x_xss_protection: Option<String>,
    #[serde(rename = "strict_transport_security")]
    pub strict_transport_security: Option<String>,
    #[serde(rename = "content_security_policy")]
    pub content_security_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct TrafficShapingConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "global_bandwidth_limit_mbps")]
    pub global_bandwidth_limit_mbps: Option<u64>,
    #[serde(rename = "per_site_limits")]
    pub per_site_limits: Option<std::collections::HashMap<String, u64>>,
    #[serde(rename = "upstream_limits")]
    pub upstream_limits: Option<std::collections::HashMap<String, u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct RateLimitsConfig {
    #[serde(rename = "mode")]
    pub mode: Option<String>,
    #[serde(rename = "per_ip_enabled")]
    pub per_ip_enabled: Option<bool>,
    #[serde(rename = "per_ip_requests_per_second")]
    pub per_ip_requests_per_second: Option<u32>,
    #[serde(rename = "per_ip_burst")]
    pub per_ip_burst: Option<u32>,
    #[serde(rename = "global_enabled")]
    pub global_enabled: Option<bool>,
    #[serde(rename = "global_requests_per_second")]
    pub global_requests_per_second: Option<u32>,
    #[serde(rename = "global_burst")]
    pub global_burst: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct BotDetectionConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "difficulty")]
    pub difficulty: Option<String>,
    #[serde(rename = "enable_challenge")]
    pub enable_challenge: Option<bool>,
    #[serde(rename = "enable_captcha")]
    pub enable_captcha: Option<bool>,
    #[serde(rename = "enable_js_challenge")]
    pub enable_js_challenge: Option<bool>,
    #[serde(rename = "enable_behavioral")]
    pub enable_behavioral: Option<bool>,
    #[serde(rename = "challenge_timeout_secs")]
    pub challenge_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct IpFeedsConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "feeds")]
    pub feeds: Option<Vec<IpFeedEntry>>,
    #[serde(rename = "update_interval_secs")]
    pub update_interval_secs: Option<u64>,
    #[serde(rename = "auto_update")]
    pub auto_update: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct IpFeedEntry {
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "format")]
    pub format: Option<String>,
    #[serde(rename = "update_interval_hours")]
    pub update_interval_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct TlsConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "min_tls_version")]
    pub min_tls_version: Option<String>,
    #[serde(rename = "ciphers")]
    pub ciphers: Option<Vec<String>>,
    #[serde(rename = "prefer_server_cipher_order")]
    pub prefer_server_cipher_order: Option<bool>,
    #[serde(rename = "http2_enabled")]
    pub http2_enabled: Option<bool>,
    #[serde(rename = "http3_enabled")]
    pub http3_enabled: Option<bool>,
    #[serde(rename = "ocsp_stapling_enabled")]
    pub ocsp_stapling_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DnsConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "port")]
    pub port: Option<u16>,
    #[serde(rename = "bind_addresses")]
    pub bind_addresses: Option<Vec<String>>,
    #[serde(rename = "allow_recursive")]
    pub allow_recursive: Option<bool>,
    #[serde(rename = "forwarders")]
    pub forwarders: Option<Vec<String>>,
    #[serde(rename = "block_tld")]
    pub block_tld: Option<Vec<String>>,
    #[serde(rename = "dnssec_enabled")]
    pub dnssec_enabled: Option<bool>,
    #[serde(rename = "nxdomain_redirect")]
    pub nxdomain_redirect: Option<String>,
    #[serde(rename = "rpz_enabled")]
    pub rpz_enabled: Option<bool>,
    #[serde(rename = "rpz_config")]
    pub rpz_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MeshConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "node_id")]
    pub node_id: Option<String>,
    #[serde(rename = "listen_port")]
    pub listen_port: Option<u16>,
    #[serde(rename = "peer_seed")]
    pub peer_seed: Option<String>,
    #[serde(rename = "global_nodes")]
    pub global_nodes: Option<Vec<String>>,
    #[serde(rename = "dht_enabled")]
    pub dht_enabled: Option<bool>,
    #[serde(rename = "anycast_enabled")]
    pub anycast_enabled: Option<bool>,
    #[serde(rename = "dns_registration_enabled")]
    pub dns_registration_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct TunnelConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "wireguard_enabled")]
    pub wireguard_enabled: Option<bool>,
    #[serde(rename = "quic_enabled")]
    pub quic_enabled: Option<bool>,
    #[serde(rename = "listen_port")]
    pub listen_port: Option<u16>,
    #[serde(rename = "max_connections")]
    pub max_connections: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct PluginsConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "plugins_dir")]
    pub plugins_dir: Option<String>,
    #[serde(rename = "loaded_plugins")]
    pub loaded_plugins: Option<Vec<String>>,
    #[serde(rename = "wasm_enabled")]
    pub wasm_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct HoneypotStatus {
    #[serde(rename = "running")]
    pub running: Option<bool>,
    #[serde(rename = "port")]
    pub port: Option<u16>,
    #[serde(rename = "protocols")]
    pub protocols: Option<Vec<String>>,
    #[serde(rename = "active_connections")]
    pub active_connections: Option<u32>,
    #[serde(rename = "blocked_attempts")]
    pub blocked_attempts: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct IcmpStatus {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "listen_address")]
    pub listen_address: Option<String>,
    #[serde(rename = "active_nodes")]
    pub active_nodes: Option<u32>,
    #[serde(rename = "packets_forwarded")]
    pub packets_forwarded: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[allow(dead_code)]
pub struct IcmpConfig {
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "listen_address")]
    pub listen_address: Option<String>,
    #[serde(rename = "max_ttl")]
    pub max_ttl: Option<u8>,
    #[serde(rename = "rate_limit_pps")]
    pub rate_limit_pps: Option<u32>,
    #[serde(rename = "backend_selection")]
    pub backend_selection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshAdminStatus {
    pub is_global_node: bool,
    pub node_id: Option<String>,
    pub connected_peers: usize,
    pub global_nodes: usize,
    pub edge_nodes: usize,
    pub genesis_key_configured: bool,
    pub genesis_public_key_fingerprint: Option<String>,
    pub signing_key_derived: bool,
    pub signing_public_key: Option<String>,
    pub quic_0rtt_enabled: bool,
    pub quic_0rtt_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveSigningKeyRequest {
    pub genesis_key_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveSigningKeyResponse {
    pub success: bool,
    pub signing_public_key: Option<String>,
    pub node_id: Option<String>,
    pub message: String,
}

// ── TCP/UDP listeners (`/api/tcp-udp/*`) ────────────────────────────────
// Mirrors `src/admin/handlers/tcp_udp.rs`. Note `protocol` is the site's TCP
// port *name* (the map key in `SiteTcpConfig::ports`), not a transport
// discriminator — the handler only surfaces TCP ports.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TcpUdpListener {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
    pub enabled: bool,
    pub active_connections: usize,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TcpUdpListenerList {
    pub listeners: Vec<TcpUdpListener>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TcpUdpProtocolInfo {
    pub name: String,
    pub description: String,
    pub supported: bool,
}

/// Typed view of `synvoid_core::admin_mutation::AdminMutationResult`, which
/// every mutating admin endpoint returns instead of a bare `{"success": true}`.
///
/// `target` is modelled as `serde_json::Value` rather than `String` because
/// the backend field is generic (`AdminMutationResult<T>`). Almost every
/// handler instantiates `T = String`, but `PUT /error-pages/{code}` sends
/// `json!(code)` where `code` is a `u16` — a JSON **number**. `String` does
/// not accept a number, so modelling it as `String` made that one endpoint
/// fail to deserialize.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AdminMutationResult {
    pub status: String,
    #[serde(default)]
    pub target: serde_json::Value,
    #[serde(default)]
    pub local_store_mutated: bool,
    #[serde(default)]
    pub propagation: String,
    #[serde(default)]
    pub audit_id: Option<String>,
    #[serde(default)]
    pub message: String,
}

impl AdminMutationResult {
    /// True only when the server actually applied the change.
    ///
    /// `AdminMutationStatus` is `#[serde(rename_all = "snake_case")]`, so the
    /// wire value is `"applied"` — not `"Applied"`. `NoOpAlreadyAbsent` and
    /// `InvalidRejected` arrive as HTTP 200 and changed nothing, so the UI must
    /// not report them as success.
    pub fn applied(&self) -> bool {
        self.status == "applied"
    }

    /// `target` rendered as text, for the common `T = String` case.
    pub fn target_display(&self) -> String {
        match &self.target {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        }
    }
}

#[cfg(test)]
mod upstream_health_tests {
    use super::*;

    fn site_stats_with(health_json: &str) -> SiteStats {
        let payload = format!(
            r#"{{"site_id":"blog","domains":["example.com"],"requests_per_second":0.0,
            "active_connections":0,"blocked_requests":0,"challenged_requests":0,
            "proxied_requests":0,"errors":0,"avg_response_time_ms":0.0,
            "p50_latency_ms":0.0,"p95_latency_ms":0.0,"p99_latency_ms":0.0,
            "upstream_healthy":{},"bytes_received":0,"bytes_sent":0,
            "proxied_bytes_sent":0,"proxied_bytes_received":0,"mesh_bytes_sent":0,
            "mesh_bytes_received":0}}"#,
            health_json
        );
        serde_json::from_str(&payload).expect("SiteStats must parse")
    }

    /// Pins the backend contract: `/api/stats/sites` emits lowercase
    /// `HealthStatus` strings, including `"unknown"` for sites no prober has
    /// reported on. A `bool` here was the dashboard parse error.
    #[test]
    fn all_three_health_strings_parse() {
        assert_eq!(
            site_stats_with(r#""healthy""#).upstream_healthy,
            UpstreamHealth::Healthy
        );
        assert_eq!(
            site_stats_with(r#""unhealthy""#).upstream_healthy,
            UpstreamHealth::Unhealthy
        );
        assert_eq!(
            site_stats_with(r#""unknown""#).upstream_healthy,
            UpstreamHealth::Unknown
        );
    }

    #[test]
    fn missing_health_degrades_to_unknown() {
        let payload = r#"{"site_id":"blog","domains":[],"requests_per_second":0.0,
            "active_connections":0,"blocked_requests":0,"challenged_requests":0,
            "proxied_requests":0,"errors":0,"avg_response_time_ms":0.0,
            "p50_latency_ms":0.0,"p95_latency_ms":0.0,"p99_latency_ms":0.0,
            "bytes_received":0,"bytes_sent":0,"proxied_bytes_sent":0,
            "proxied_bytes_received":0,"mesh_bytes_sent":0,"mesh_bytes_received":0}"#;
        let stats: SiteStats =
            serde_json::from_str(payload).expect("absent field must not fail the fetch");
        assert_eq!(stats.upstream_healthy, UpstreamHealth::Unknown);
    }

    #[test]
    fn only_healthy_counts_as_healthy() {
        assert!(UpstreamHealth::Healthy.is_healthy());
        assert!(!UpstreamHealth::Unhealthy.is_healthy());
        assert!(!UpstreamHealth::Unknown.is_healthy());
    }
}

#[cfg(test)]
mod admin_mutation_tests {
    use super::*;

    fn result(status: &str) -> AdminMutationResult {
        AdminMutationResult {
            status: status.to_string(),
            target: serde_json::Value::String("site-http".to_string()),
            local_store_mutated: true,
            propagation: "applied_local_only".to_string(),
            audit_id: None,
            message: "ok".to_string(),
        }
    }

    /// Pins the wire casing. `AdminMutationStatus` serializes snake_case, so a
    /// PascalCase comparison here would silently mark every real success as a
    /// failure in the UI.
    #[test]
    fn only_applied_counts_as_success() {
        assert!(result("applied").applied());
        assert!(!result("no_op_already_absent").applied());
        assert!(!result("invalid_rejected").applied());
        assert!(!result("duplicate_ignored").applied());
        assert!(!result("stale_ignored").applied());
    }

    #[test]
    fn missing_optional_fields_still_deserialize() {
        let minimal: AdminMutationResult = serde_json::from_str(r#"{"status":"applied"}"#)
            .expect("AdminMutationResult tolerates absent optional fields");
        assert!(minimal.applied());
        assert!(minimal.target_display().is_empty());
    }

    /// `PUT /api/error-pages/{code}` sends `target: json!(code)` where `code`
    /// is a `u16`, so the field is a JSON **number** on the wire. Modelling it
    /// as `String` made this endpoint fail to deserialize outright.
    #[test]
    fn numeric_targets_deserialize_and_render() {
        let numeric: AdminMutationResult = serde_json::from_str(
            r#"{"status":"applied","target":404,"local_store_mutated":true,
                "propagation":"applied_local_only","message":"Error page 404 updated"}"#,
        )
        .expect("a numeric target must not break deserialization");
        assert_eq!(numeric.target_display(), "404");
    }
}

#[cfg(test)]
mod theme_dual_scheme_tests {
    use super::*;

    fn colors_json() -> serde_json::Value {
        serde_json::json!({
            "dark": {
                "background": "#090808", "surface": "#12121a", "primary": "#E41951",
                "text": "#f0f0f5", "border": "#2a2a3a", "accent": "#1a1a24",
                "accent_primary": "#00d4aa", "accent_secondary": "#00b894"
            },
            "light": {
                "background": "#f8fafc", "surface": "#ffffff", "primary": "#c41e3a",
                "text": "#0f172a", "border": "#e2e8f0", "accent": "#f1f5f9",
                "accent_primary": "#059669", "accent_secondary": "#10b981"
            }
        })
    }

    /// Pins the Phase 04 wire shape: `GET /api/theme` carries the dual-scheme
    /// fields plus the `default` alias followed by the Halloy catalog.
    #[test]
    fn phase04_response_parses_with_dual_scheme_fields() {
        let payload = serde_json::json!({
            "preset": "default",
            "mode": "auto",
            "dark_theme": "Catppuccin Mocha",
            "light_theme": "Catppuccin Latte",
            "scheme": "system",
            "allow_only": "both",
            "colors": colors_json(),
            "presets_available": [
                {"id": "default", "name": "Default"},
                {"id": "Nord", "name": "Nord"}
            ]
        });
        let response: ThemeResponse =
            serde_json::from_value(payload).expect("Phase 04 ThemeResponse must parse");
        assert_eq!(response.dark_theme, "Catppuccin Mocha");
        assert_eq!(response.light_theme, "Catppuccin Latte");
        assert_eq!(response.scheme, "system");
        assert_eq!(response.presets_available[0].id, "default");
    }

    /// Older backends omit the three fields; the pickers must still load
    /// (with empty selections) instead of failing the whole fetch.
    #[test]
    fn legacy_response_without_new_fields_still_parses() {
        let payload = serde_json::json!({
            "preset": "dark",
            "mode": "dark",
            "allow_only": "both",
            "colors": colors_json(),
            "presets_available": []
        });
        let response: ThemeResponse =
            serde_json::from_value(payload).expect("legacy ThemeResponse must not fail the fetch");
        assert!(response.dark_theme.is_empty());
        assert!(response.light_theme.is_empty());
        assert!(response.scheme.is_empty());
    }

    /// The save path sends only the new fields (legacy `preset`/`mode` stay
    /// absent so the backend keeps its compat resolution untouched).
    #[test]
    fn save_request_carries_new_fields_without_legacy_compat() {
        let request = UpdateThemeRequest {
            preset: None,
            mode: None,
            dark_theme: Some("Nord".to_string()),
            light_theme: Some("Catppuccin Latte".to_string()),
            scheme: Some("system".to_string()),
            allow_only: None,
        };
        let body = serde_json::to_value(&request).expect("request must serialize");
        assert_eq!(body["dark_theme"], "Nord");
        assert_eq!(body["scheme"], "system");
        assert!(body["preset"].is_null());
    }
}

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
    pub upstream_healthy: bool,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub proxied_bytes_sent: u64,
    pub proxied_bytes_received: u64,
    pub mesh_bytes_sent: u64,
    pub mesh_bytes_received: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverseerStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub master_pid: Option<u32>,
    pub master_status: String,
    pub uptime_secs: u64,
    pub upgrade_mode: String,
    pub drain_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
pub struct OverseerConfig {
    pub auto_restart: bool,
    #[serde(rename = "restart_delay_secs")]
    pub restart_delay_secs: u64,
    #[serde(rename = "max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(rename = "health_check_interval_secs")]
    pub health_check_interval_secs: u64,
    #[serde(rename = "stable_uptime_secs")]
    pub stable_uptime_secs: u64,
    #[serde(rename = "upgrade_validation_timeout_secs")]
    pub upgrade_validation_timeout_secs: u64,
    #[serde(rename = "upgrade_drain_timeout_secs")]
    pub upgrade_drain_timeout_secs: u64,
    #[serde(rename = "upgrade_health_check_retries")]
    pub upgrade_health_check_retries: u32,
    #[serde(rename = "upgrade_health_check_interval_secs")]
    pub upgrade_health_check_interval_secs: u64,
    #[serde(rename = "ipc_read_timeout_ms")]
    pub ipc_read_timeout_ms: u64,
    #[serde(rename = "ipc_write_timeout_ms")]
    pub ipc_write_timeout_ms: u64,
    #[serde(rename = "master_startup_timeout_secs")]
    pub master_startup_timeout_secs: u64,
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

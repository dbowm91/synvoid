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
pub struct StatusResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub use presets::{
    get_presets, get_presets_by_category, PresetCategory, PresetConfig, ServerPreset,
    SettingSuggestion,
};

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

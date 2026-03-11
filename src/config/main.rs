use crate::config::geoip::GeoIpConfig;
use crate::theme::ThemeDefaults;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MainConfig {
    pub server: ServerConfig,
    pub fallback: FallbackConfig,
    pub admin: AdminConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tokio: TokioConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub http3: Http3Config,
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub threat_level: ThreatLevelConfig,
    #[serde(default)]
    pub ip_feeds: IpFeedConfig,
    #[serde(default)]
    pub rate_limit_memory: RateLimitMemoryConfig,
    #[serde(default)]
    pub proxy_limits: ProxyLimitsConfig,
    #[serde(default)]
    pub blocklist_limits: BlocklistLimitsConfig,
    #[serde(default)]
    pub tcp: TcpDefaults,
    #[serde(default)]
    pub udp: UdpDefaults,
    #[serde(default)]
    pub tarpit: TarpitDefaults,
    #[serde(default)]
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub traffic_shaping: TrafficShapingConfig,
    #[serde(default)]
    pub security: MainSecurityConfig,
    #[serde(default)]
    pub static_config: Option<MainStaticConfig>,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub host_v6: Option<String>,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "::1".to_string()]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HttpConfig {
    #[serde(default = "default_header_read_timeout")]
    pub header_read_timeout_secs: u64,
    #[serde(default = "default_keep_alive_timeout")]
    pub keep_alive_timeout_secs: u64,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_max_request_line_size")]
    pub max_request_line_size: usize,
    #[serde(default = "default_max_header_size_ingress")]
    pub max_header_size_ingress: usize,
    #[serde(default = "default_max_header_size_egress")]
    pub max_header_size_egress: usize,
    #[serde(default = "default_max_request_size")]
    pub max_request_size: usize,
    #[serde(default = "default_pipeline_limit")]
    pub pipeline_limit: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            header_read_timeout_secs: default_header_read_timeout(),
            keep_alive_timeout_secs: default_keep_alive_timeout(),
            max_headers: default_max_headers(),
            max_request_line_size: default_max_request_line_size(),
            max_header_size_ingress: default_max_header_size_ingress(),
            max_header_size_egress: default_max_header_size_egress(),
            max_request_size: default_max_request_size(),
            pipeline_limit: default_pipeline_limit(),
        }
    }
}

fn default_header_read_timeout() -> u64 {
    10
}
fn default_keep_alive_timeout() -> u64 {
    60
}
fn default_max_headers() -> usize {
    128
}
fn default_max_request_line_size() -> usize {
    8192
}
fn default_max_header_size_ingress() -> usize {
    4096
}
fn default_max_header_size_egress() -> usize {
    16384
}
fn default_max_request_size() -> usize {
    1048576
}
fn default_pipeline_limit() -> usize {
    32
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub watch_dir: Option<String>,
    #[serde(default = "default_prefer_post_quantum")]
    pub prefer_post_quantum: bool,
    #[serde(default = "default_tls_port")]
    pub port: u16,
    #[serde(default)]
    pub acme: AcmeConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            watch_dir: None,
            prefer_post_quantum: true,
            port: default_tls_port(),
            acme: AcmeConfig::default(),
        }
    }
}

fn default_tls_port() -> u16 {
    443
}

fn default_prefer_post_quantum() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub cache_dir: Option<String>,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Http3Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_http3_port")]
    pub port: u16,
    #[serde(default)]
    pub host_v6: Option<String>,
    #[serde(default = "default_alt_svc_max_age")]
    pub alt_svc_max_age: u64,
}

fn default_http3_port() -> u16 {
    443
}

fn default_alt_svc_max_age() -> u64 {
    86400
}

#[derive(Debug, Clone)]
pub struct TokioConfig {
    pub worker_threads: usize,
}

impl Serialize for TokioConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.worker_threads as u64)
    }
}

impl<'de> Deserialize<'de> for TokioConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawValue {
            String(String),
            Number(usize),
        }

        let raw = Option::<RawValue>::deserialize(deserializer)?;

        let worker_threads = match raw {
            Some(RawValue::String(s)) if s.to_lowercase() == "auto" => {
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4)
            }
            Some(RawValue::String(s)) => s.parse().unwrap_or_else(|_| {
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4)
            }),
            Some(RawValue::Number(n)) => n,
            None => std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
        };

        Ok(Self { worker_threads })
    }
}

impl Default for TokioConfig {
    fn default() -> Self {
        Self {
            worker_threads: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
        }
    }
}

fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FallbackConfig {
    #[serde(default = "default_fallback_mode")]
    pub mode: String,
    #[serde(default)]
    pub upstream: Option<String>,
}

fn default_fallback_mode() -> String {
    "return_404".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdminConfig {
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_port")]
    pub port: u16,
    #[serde(default = "default_admin_token")]
    pub token: String,
}

fn default_admin_enabled() -> bool {
    true
}

fn default_admin_port() -> u16 {
    8081
}

fn default_admin_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    token
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_access_log")]
    pub access_log: bool,
    #[serde(default)]
    pub access_log_dir: Option<String>,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_max_entries_per_file")]
    pub max_entries_per_file: u32,
    #[serde(default = "default_access_log_format")]
    pub access_log_format: String,
    #[serde(default)]
    pub exporter: LogExporterConfig,
    #[serde(default)]
    pub request_body_logging: RequestBodyLoggingConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            access_log: default_access_log(),
            access_log_dir: None,
            retention_days: default_retention_days(),
            max_entries_per_file: default_max_entries_per_file(),
            access_log_format: default_access_log_format(),
            exporter: LogExporterConfig::default(),
            request_body_logging: RequestBodyLoggingConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RequestBodyLoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_body_log_size")]
    pub max_size: usize,
    #[serde(default)]
    pub scrub_sensitive: bool,
    #[serde(default = "default_sensitive_fields")]
    pub sensitive_fields: Vec<String>,
}

impl Default for RequestBodyLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size: default_max_body_log_size(),
            scrub_sensitive: true,
            sensitive_fields: default_sensitive_fields(),
        }
    }
}

fn default_max_body_log_size() -> usize {
    1024
}

fn default_sensitive_fields() -> Vec<String> {
    vec![
        "password".to_string(),
        "passwd".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "api_key".to_string(),
        "apikey".to_string(),
        "authorization".to_string(),
        "access_token".to_string(),
        "refresh_token".to_string(),
        "credit_card".to_string(),
        "cc_number".to_string(),
        "ssn".to_string(),
        "social_security".to_string(),
    ]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogExporterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub elasticsearch: Option<ElasticsearchConfig>,
    #[serde(default)]
    pub loki: Option<LokiConfig>,
}

impl Default for LogExporterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            elasticsearch: None,
            loki: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElasticsearchConfig {
    pub url: String,
    #[serde(default = "default_es_index")]
    pub index: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_es_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_es_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

fn default_es_index() -> String {
    "rustwaf-logs".to_string()
}

fn default_es_batch_size() -> usize {
    100
}

fn default_es_flush_interval_secs() -> u64 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LokiConfig {
    pub url: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_loki_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_loki_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

fn default_loki_batch_size() -> usize {
    100
}

fn default_loki_flush_interval_secs() -> u64 {
    5
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_access_log() -> bool {
    true
}

fn default_retention_days() -> u32 {
    5
}

fn default_max_entries_per_file() -> u32 {
    50000
}

fn default_access_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DefaultsConfig {
    pub ratelimit: RateLimitDefaults,
    pub blocked: BlockedDefaults,
    pub honeypot: HoneypotDefaults,
    pub honeypot_probe: HoneypotProbingDefaults,
    pub suspicious_words: SuspiciousWordsConfig,
    pub upstream_errors: UpstreamErrorsConfig,
    pub error_pages: ErrorPagesDefaults,
    pub bot: BotDefaults,
    pub css_challenge: CssChallengeDefaults,
    pub pow_challenge: PowChallengeDefaults,
    pub auth: AuthDefaults,
    pub worker_pool: WorkerPoolDefaults,
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub rate_limit_memory: RateLimitMemoryConfig,
    #[serde(default)]
    pub proxy_limits: ProxyLimitsConfig,
    #[serde(default)]
    pub blocklist_limits: BlocklistLimitsConfig,
    #[serde(default)]
    pub tcp: TcpDefaults,
    #[serde(default)]
    pub udp: UdpDefaults,
    #[serde(default)]
    pub tarpit: TarpitDefaults,
    #[serde(default)]
    pub upload: UploadDefaults,
    #[serde(default)]
    pub theme: ThemeDefaults,
    #[serde(default)]
    pub traffic_shaping: TrafficShapingDefaults,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            ratelimit: RateLimitDefaults::default(),
            blocked: BlockedDefaults::default(),
            honeypot: HoneypotDefaults::default(),
            honeypot_probe: HoneypotProbingDefaults::default(),
            suspicious_words: SuspiciousWordsConfig::default(),
            upstream_errors: UpstreamErrorsConfig::default(),
            error_pages: ErrorPagesDefaults::default(),
            bot: BotDefaults::default(),
            css_challenge: CssChallengeDefaults::default(),
            pow_challenge: PowChallengeDefaults::default(),
            auth: AuthDefaults::default(),
            worker_pool: WorkerPoolDefaults::default(),
            persistence: PersistenceConfig::default(),
            rate_limit_memory: RateLimitMemoryConfig::default(),
            proxy_limits: ProxyLimitsConfig::default(),
            blocklist_limits: BlocklistLimitsConfig::default(),
            tcp: TcpDefaults::default(),
            udp: UdpDefaults::default(),
            tarpit: TarpitDefaults::default(),
            upload: UploadDefaults::default(),
            theme: ThemeDefaults::default(),
            traffic_shaping: TrafficShapingDefaults::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RateLimitDefaults {
    #[serde(default = "default_ratelimit_mode")]
    pub mode: String,
    pub ip: IpRateLimitConfig,
    pub global: GlobalRateLimitConfig,
    pub endpoints: Vec<EndpointRateLimitConfig>,
}

impl Default for RateLimitDefaults {
    fn default() -> Self {
        Self {
            mode: "shared".to_string(),
            ip: IpRateLimitConfig::default(),
            global: GlobalRateLimitConfig::default(),
            endpoints: vec![],
        }
    }
}

fn default_ratelimit_mode() -> String {
    "shared".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct IpRateLimitConfig {
    #[serde(default = "default_ip_per_second")]
    pub per_second: u32,
    #[serde(default = "default_ip_per_minute")]
    pub per_minute: u32,
    #[serde(default = "default_ip_per_5min")]
    pub per_5min: u32,
    #[serde(default = "default_ip_per_10min")]
    pub per_10min: u32,
    #[serde(default = "default_ip_per_hour")]
    pub per_hour: u32,
    #[serde(default = "default_ip_per_day")]
    pub per_day: u32,
    #[serde(default = "default_ip_burst")]
    pub burst: u32,
}

fn default_ip_per_second() -> u32 {
    10
}
fn default_ip_per_minute() -> u32 {
    60
}
fn default_ip_per_5min() -> u32 {
    200
}
fn default_ip_per_10min() -> u32 {
    350
}
fn default_ip_per_hour() -> u32 {
    500
}
fn default_ip_per_day() -> u32 {
    1000
}
fn default_ip_burst() -> u32 {
    20
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GlobalRateLimitConfig {
    #[serde(default = "default_global_per_second")]
    pub per_second: u32,
    #[serde(default = "default_global_per_minute")]
    pub per_minute: u32,
    #[serde(default = "default_global_per_5min")]
    pub per_5min: u32,
    #[serde(default = "default_global_max_connections")]
    pub max_connections: u32,
}

fn default_global_per_second() -> u32 {
    500
}
fn default_global_per_minute() -> u32 {
    5000
}
fn default_global_per_5min() -> u32 {
    20000
}
fn default_global_max_connections() -> u32 {
    1000
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EndpointRateLimitConfig {
    pub path_pattern: String,
    #[serde(default = "default_endpoint_per_minute")]
    pub per_minute: u32,
    #[serde(default = "default_endpoint_per_hour")]
    pub per_hour: u32,
    #[serde(default = "default_endpoint_burst")]
    pub burst: u32,
}

fn default_endpoint_per_minute() -> u32 {
    60
}
fn default_endpoint_per_hour() -> u32 {
    500
}
fn default_endpoint_burst() -> u32 {
    10
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatLevelConfig {
    #[serde(default = "default_threat_level_initial")]
    pub initial: u8,
    #[serde(default = "default_threat_level_auto_scale")]
    pub auto_scale: bool,
    #[serde(default = "default_scale_up_attacks")]
    pub scale_up_attacks_per_min: u32,
    #[serde(default = "default_scale_up_window")]
    pub scale_up_window_secs: u32,
    #[serde(default = "default_scale_down_attacks")]
    pub scale_down_attacks_per_min: u32,
    #[serde(default = "default_scale_down_window")]
    pub scale_down_window_secs: u32,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u32,
    #[serde(default = "default_persist_interval_normal")]
    pub persist_interval_normal_secs: u32,
    #[serde(default = "default_persist_interval_attack")]
    pub persist_interval_attack_secs: u32,
    #[serde(default = "default_auto_deescalate_timeout")]
    pub auto_deescalate_timeout_mins: u32,
    #[serde(default)]
    pub global_limits: ThreatLevelGlobalLimits,
    #[serde(default)]
    pub ban_durations: ThreatLevelBanDurations,
    #[serde(default)]
    pub escalation: ThreatLevelEscalation,
}

impl Default for ThreatLevelConfig {
    fn default() -> Self {
        Self {
            initial: default_threat_level_initial(),
            auto_scale: default_threat_level_auto_scale(),
            scale_up_attacks_per_min: default_scale_up_attacks(),
            scale_up_window_secs: default_scale_up_window(),
            scale_down_attacks_per_min: default_scale_down_attacks(),
            scale_down_window_secs: default_scale_down_window(),
            cooldown_secs: default_cooldown_secs(),
            persist_interval_normal_secs: default_persist_interval_normal(),
            persist_interval_attack_secs: default_persist_interval_attack(),
            auto_deescalate_timeout_mins: default_auto_deescalate_timeout(),
            global_limits: ThreatLevelGlobalLimits::default(),
            ban_durations: ThreatLevelBanDurations::default(),
            escalation: ThreatLevelEscalation::default(),
        }
    }
}

fn default_threat_level_initial() -> u8 {
    1
}
fn default_threat_level_auto_scale() -> bool {
    true
}
fn default_scale_up_attacks() -> u32 {
    50
}
fn default_scale_up_window() -> u32 {
    60
}
fn default_scale_down_attacks() -> u32 {
    10
}
fn default_scale_down_window() -> u32 {
    300
}
fn default_cooldown_secs() -> u32 {
    60
}
fn default_persist_interval_normal() -> u32 {
    60
}
fn default_persist_interval_attack() -> u32 {
    15
}
fn default_auto_deescalate_timeout() -> u32 {
    15
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatLevelGlobalLimits {
    #[serde(default = "default_level_1_multiplier")]
    pub level_1: f32,
    #[serde(default = "default_level_2_multiplier")]
    pub level_2: f32,
    #[serde(default = "default_level_3_multiplier")]
    pub level_3: f32,
    #[serde(default = "default_level_4_multiplier")]
    pub level_4: f32,
    #[serde(default = "default_level_5_multiplier")]
    pub level_5: f32,
}

impl Default for ThreatLevelGlobalLimits {
    fn default() -> Self {
        Self {
            level_1: 1.0,
            level_2: 0.75,
            level_3: 0.5,
            level_4: 0.25,
            level_5: 0.1,
        }
    }
}

fn default_level_1_multiplier() -> f32 {
    1.0
}
fn default_level_2_multiplier() -> f32 {
    0.75
}
fn default_level_3_multiplier() -> f32 {
    0.5
}
fn default_level_4_multiplier() -> f32 {
    0.25
}
fn default_level_5_multiplier() -> f32 {
    0.1
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatLevelBanDurations {
    #[serde(default = "default_level_1_base")]
    pub level_1_base: String,
    #[serde(default = "default_level_2_base")]
    pub level_2_base: String,
    #[serde(default = "default_level_3_base")]
    pub level_3_base: String,
    #[serde(default = "default_level_4_base")]
    pub level_4_base: String,
    #[serde(default = "default_level_5_base")]
    pub level_5_base: String,
}

impl Default for ThreatLevelBanDurations {
    fn default() -> Self {
        Self {
            level_1_base: "1h".to_string(),
            level_2_base: "4h".to_string(),
            level_3_base: "24h".to_string(),
            level_4_base: "7d".to_string(),
            level_5_base: "permanent".to_string(),
        }
    }
}

fn default_level_1_base() -> String {
    "1h".to_string()
}
fn default_level_2_base() -> String {
    "4h".to_string()
}
fn default_level_3_base() -> String {
    "24h".to_string()
}
fn default_level_4_base() -> String {
    "7d".to_string()
}
fn default_level_5_base() -> String {
    "permanent".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatLevelEscalation {
    #[serde(default = "default_escalation_enabled")]
    pub enabled: bool,
    #[serde(default = "default_violations_before_block")]
    pub violations_before_block: u32,
    #[serde(default = "default_violation_window")]
    pub violation_window_secs: u32,
    #[serde(default)]
    pub excluded_ips: Vec<String>,
}

impl Default for ThreatLevelEscalation {
    fn default() -> Self {
        Self {
            enabled: true,
            violations_before_block: 3,
            violation_window_secs: 300,
            excluded_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

fn default_escalation_enabled() -> bool {
    true
}
fn default_violations_before_block() -> u32 {
    3
}
fn default_violation_window() -> u32 {
    300
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpFeedConfig {
    #[serde(default = "default_ip_feed_enabled")]
    pub enabled: bool,
    #[serde(default = "default_feed_update_interval")]
    pub update_interval_hours: u32,
    #[serde(default = "default_feed_url")]
    pub url: String,
    #[serde(default)]
    pub max_permanent_blocks: usize,
}

impl Default for IpFeedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_interval_hours: 2,
            url: "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt"
                .to_string(),
            max_permanent_blocks: 1_000_000,
        }
    }
}

fn default_ip_feed_enabled() -> bool {
    true
}
fn default_feed_update_interval() -> u32 {
    2
}
fn default_feed_url() -> String {
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlockedDefaults {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_regex")]
    pub use_regex: bool,
    #[serde(default)]
    pub block_methods: Vec<String>,
    #[serde(default = "default_block_response")]
    pub block_response_code: u16,
}

impl Default for BlockedDefaults {
    fn default() -> Self {
        Self {
            paths: vec![
                "/.env".to_string(),
                "/.git".to_string(),
                "/wp-login.php".to_string(),
            ],
            use_regex: true,
            block_methods: vec!["GET".to_string(), "POST".to_string()],
            block_response_code: 403,
        }
    }
}

fn default_regex() -> bool {
    true
}
fn default_block_response() -> u16 {
    403
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BotDefaults {
    #[serde(default = "default_block_ai")]
    pub block_ai_crawlers: bool,
    #[serde(default = "default_true")]
    pub enable_css_honeypot: bool,
    #[serde(default)]
    pub enable_js_challenge: bool,
    #[serde(default)]
    pub known_bots_allow: Vec<String>,
    #[serde(default)]
    pub ai_crawlers_block: Vec<String>,
    #[serde(default = "default_challenge_cookie_name")]
    pub challenge_cookie_name: String,
    #[serde(default = "default_challenge_window")]
    pub challenge_window_secs: u64,
    #[serde(default = "default_js_difficulty")]
    pub js_difficulty: u8,
}

impl Default for BotDefaults {
    fn default() -> Self {
        Self {
            block_ai_crawlers: true,
            enable_css_honeypot: true,
            enable_js_challenge: false,
            known_bots_allow: vec![
                "googlebot".to_string(),
                "bingbot".to_string(),
                "yandex".to_string(),
                "duckduckbot".to_string(),
            ],
            ai_crawlers_block: vec![
                "GPTBot".to_string(),
                "ChatGPT-User".to_string(),
                "ClaudeBot".to_string(),
                "Claude-Web".to_string(),
                "CCBot".to_string(),
                "Google-Extended".to_string(),
            ],
            challenge_cookie_name: "waf_challenge".to_string(),
            challenge_window_secs: 300,
            js_difficulty: 1,
        }
    }
}

fn default_block_ai() -> bool {
    true
}
fn default_true() -> bool {
    true
}
fn default_honeypot_endpoints_file() -> String {
    "config/honeypot_endpoints.txt".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HoneypotDefaults {
    #[serde(default = "default_honeypot_endpoints_file")]
    pub endpoints_file: String,
    #[serde(default = "default_honeypot_paths_per_ip")]
    pub paths_per_ip: usize,
    #[serde(default = "default_honeypot_ttl")]
    pub ttl_secs: u64,
    pub block: HoneypotBlockDefaults,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HoneypotBlockDefaults {
    #[serde(default = "default_honeypot_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_honeypot_ban_duration")]
    pub ban_duration: String,
}

impl Default for HoneypotDefaults {
    fn default() -> Self {
        Self {
            endpoints_file: "config/honeypot_endpoints.txt".to_string(),
            paths_per_ip: 5,
            ttl_secs: 86400,
            block: HoneypotBlockDefaults::default(),
        }
    }
}

impl Default for HoneypotBlockDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: "24h".to_string(),
        }
    }
}

fn default_honeypot_paths_per_ip() -> usize {
    5
}
fn default_honeypot_ttl() -> u64 {
    86400
}
fn default_honeypot_block_enabled() -> bool {
    true
}
fn default_honeypot_ban_duration() -> String {
    "24h".to_string()
}

fn default_probing_enabled() -> bool {
    true
}
fn default_probing_max_endpoints() -> usize {
    3
}
fn default_probing_window() -> u64 {
    300
}
fn default_probing_retention() -> u64 {
    7
}
fn default_probing_max_records() -> usize {
    1000
}
fn default_probing_threshold() -> u8 {
    3
}
fn default_probing_ban_duration() -> u64 {
    900
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HoneypotProbingDefaults {
    #[serde(default = "default_probing_enabled")]
    pub enabled: bool,
    #[serde(default = "default_probing_max_endpoints")]
    pub max_endpoints_per_window: usize,
    #[serde(default = "default_probing_window")]
    pub window_secs: u64,
    #[serde(default = "default_probing_retention")]
    pub retention_days: u64,
    #[serde(default = "default_probing_max_records")]
    pub max_records: usize,
    #[serde(default = "default_probing_enabled")]
    pub auto_ban_elevated_threat: bool,
    #[serde(default = "default_probing_threshold")]
    pub elevated_threat_threshold: u8,
    #[serde(default = "default_probing_ban_duration")]
    pub elevated_ban_duration: u64,
}

impl Default for HoneypotProbingDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            max_endpoints_per_window: 3,
            window_secs: 300,
            retention_days: 7,
            max_records: 1000,
            auto_ban_elevated_threat: true,
            elevated_threat_threshold: 3,
            elevated_ban_duration: 900,
        }
    }
}

fn default_suspicious_words_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SuspiciousWordsConfig {
    #[serde(default = "default_suspicious_words_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub words: Vec<String>,
}

impl Default for SuspiciousWordsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            words: vec![
                "admin".to_string(),
                "administrator".to_string(),
                "backup".to_string(),
                "bak".to_string(),
                "config".to_string(),
                "debug".to_string(),
                ".git".to_string(),
                ".svn".to_string(),
                ".env".to_string(),
                "wp-admin".to_string(),
                "phpmyadmin".to_string(),
                "shell".to_string(),
                "webshell".to_string(),
                "passwd".to_string(),
                "shadow".to_string(),
                "id_rsa".to_string(),
                "database".to_string(),
                "db".to_string(),
                "sql".to_string(),
                "dump".to_string(),
                "restore".to_string(),
            ],
        }
    }
}

fn default_upstream_errors_enabled() -> bool {
    true
}
fn default_min_error_endpoints() -> usize {
    3
}
fn default_error_codes() -> Vec<u16> {
    vec![400, 401, 403, 404, 500, 502, 503]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamErrorsConfig {
    #[serde(default = "default_upstream_errors_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_error_endpoints")]
    pub min_error_endpoints: usize,
    #[serde(default = "default_probing_window")]
    pub window_secs: u64,
    #[serde(default = "default_error_codes")]
    pub error_codes: Vec<u16>,
    #[serde(default = "default_probing_enabled")]
    pub auto_ban_elevated_threat: bool,
    #[serde(default = "default_probing_threshold")]
    pub elevated_threat_threshold: u8,
    #[serde(default = "default_probing_ban_duration")]
    pub elevated_ban_duration: u64,
}

impl Default for UpstreamErrorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_error_endpoints: 3,
            window_secs: 300,
            error_codes: vec![400, 401, 403, 404, 500, 502, 503],
            auto_ban_elevated_threat: true,
            elevated_threat_threshold: 3,
            elevated_ban_duration: 900,
        }
    }
}

fn default_error_pages_directory() -> String {
    "config/error_pages".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorPagesDefaults {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_error_pages_directory")]
    pub directory: String,
}

impl Default for ErrorPagesDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: "config/error_pages".to_string(),
        }
    }
}

fn default_challenge_cookie_name() -> String {
    "waf_challenge".to_string()
}
fn default_challenge_window() -> u64 {
    300
}
fn default_js_difficulty() -> u8 {
    1
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CssChallengeDefaults {
    #[serde(default = "default_css_enabled")]
    pub enabled: bool,
    #[serde(default = "default_css_invalid_min")]
    pub invalid_count_min: u32,
    #[serde(default = "default_css_invalid_max")]
    pub invalid_count_max: u32,
    #[serde(default = "default_css_valid_count")]
    pub valid_count: u32,
    #[serde(default = "default_css_asset_path")]
    pub asset_path: String,
    #[serde(default)]
    pub valid_aspect_ratios: Vec<String>,
    #[serde(default = "default_css_window")]
    pub challenge_window_secs: u64,
    #[serde(default = "default_css_verification_window")]
    pub verification_window_secs: u32,
    pub block: CssBlockDefaults,
}

impl Default for CssChallengeDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            invalid_count_min: 80,
            invalid_count_max: 120,
            valid_count: 3,
            asset_path: "/_waf_assets".to_string(),
            valid_aspect_ratios: vec![
                "16/9".to_string(),
                "16/10".to_string(),
                "4/3".to_string(),
                "1/1".to_string(),
            ],
            challenge_window_secs: 300,
            verification_window_secs: 30,
            block: CssBlockDefaults::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CssBlockDefaults {
    #[serde(default = "default_css_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_css_ban_duration")]
    pub ban_duration: String,
}

impl Default for CssBlockDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: "24h".to_string(),
        }
    }
}

fn default_css_enabled() -> bool {
    true
}
fn default_css_invalid_min() -> u32 {
    80
}
fn default_css_invalid_max() -> u32 {
    120
}
fn default_css_valid_count() -> u32 {
    3
}
fn default_css_asset_path() -> String {
    "/_waf_assets".to_string()
}
fn default_css_window() -> u64 {
    300
}
fn default_css_verification_window() -> u32 {
    30
}
fn default_css_block_enabled() -> bool {
    true
}
fn default_css_ban_duration() -> String {
    "24h".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PowChallengeDefaults {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
    #[serde(default = "default_pow_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_pow_window")]
    pub window_secs: u64,
    #[serde(default = "default_true")]
    pub prefer_wasm: bool,
    pub block: PowBlockDefaults,
}

impl Default for PowChallengeDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            difficulty: 6,
            timeout_secs: 60,
            window_secs: 300,
            prefer_wasm: true,
            block: PowBlockDefaults::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PowBlockDefaults {
    #[serde(default = "default_pow_block_enabled")]
    pub enabled: bool,
    #[serde(default = "default_pow_ban_duration")]
    pub ban_duration: String,
}

impl Default for PowBlockDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: "1h".to_string(),
        }
    }
}

fn default_pow_difficulty() -> u8 {
    6
}
fn default_pow_timeout() -> u64 {
    60
}
fn default_pow_window() -> u64 {
    300
}
fn default_pow_block_enabled() -> bool {
    true
}
fn default_pow_ban_duration() -> String {
    "1h".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthDefaults {
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,
    #[serde(default = "default_auth_session_duration")]
    pub session_duration_secs: u64,
    #[serde(default = "default_auth_max_attempts")]
    pub max_login_attempts: u32,
    #[serde(default = "default_auth_lockout_duration")]
    pub lockout_duration_secs: u64,
    #[serde(default = "default_auth_login_path")]
    pub login_path: String,
}

impl Default for AuthDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            session_duration_secs: 86400,
            max_login_attempts: 3,
            lockout_duration_secs: 3600,
            login_path: "/_waf_login".to_string(),
        }
    }
}

fn default_auth_enabled() -> bool {
    false
}
fn default_auth_session_duration() -> u64 {
    86400
}
fn default_auth_max_attempts() -> u32 {
    3
}
fn default_auth_lockout_duration() -> u64 {
    3600
}
fn default_auth_login_path() -> String {
    "/_waf_login".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WorkerPoolDefaults {
    #[serde(default = "default_worker_pool_mode")]
    pub mode: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_worker_port_base")]
    pub worker_port_base: u16,
    #[serde(default = "default_auto_scale")]
    pub auto_scale: bool,
}

impl Default for WorkerPoolDefaults {
    fn default() -> Self {
        Self {
            mode: "shared".to_string(),
            workers: 4,
            worker_port_base: 9000,
            auto_scale: true,
        }
    }
}

fn default_worker_pool_mode() -> String {
    "shared".to_string()
}
fn default_workers() -> usize {
    4
}
fn default_worker_port_base() -> u16 {
    9000
}
fn default_auto_scale() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PersistenceConfig {
    #[serde(default = "default_persistence_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub data_dir: Option<String>,
    #[serde(default = "default_persist_interval_secs")]
    pub persist_interval_secs: u64,
    #[serde(default = "default_use_persistent_kv")]
    pub use_persistent_kv: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            data_dir: None,
            persist_interval_secs: 60,
            use_persistent_kv: false,
        }
    }
}

fn default_persistence_enabled() -> bool {
    true
}
fn default_persist_interval_secs() -> u64 {
    60
}
fn default_use_persistent_kv() -> bool {
    false
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RateLimitMemoryConfig {
    #[serde(default = "default_max_ip_entries")]
    pub max_ip_entries: usize,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_num_shards")]
    pub num_shards: usize,
}

impl Default for RateLimitMemoryConfig {
    fn default() -> Self {
        Self {
            max_ip_entries: 1_000_000,
            cleanup_interval_secs: 60,
            num_shards: 256,
        }
    }
}

fn default_max_ip_entries() -> usize {
    1_000_000
}
fn default_cleanup_interval() -> u64 {
    60
}
fn default_num_shards() -> usize {
    256
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyLimitsConfig {
    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,
    #[serde(default = "default_connection_pool_size")]
    pub connection_pool_size: usize,
}

impl Default for ProxyLimitsConfig {
    fn default() -> Self {
        Self {
            max_response_size: 10_000_000,
            connection_pool_size: 100,
        }
    }
}

fn default_max_response_size() -> usize {
    10_000_000
}
fn default_connection_pool_size() -> usize {
    100
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistLimitsConfig {
    #[serde(default = "default_max_block_entries")]
    pub max_entries: usize,
    #[serde(default = "default_blocklist_persist_interval")]
    pub persist_interval_secs: u64,
}

impl Default for BlocklistLimitsConfig {
    fn default() -> Self {
        Self {
            max_entries: 500_000,
            persist_interval_secs: 60,
        }
    }
}

fn default_max_block_entries() -> usize {
    500_000
}
fn default_blocklist_persist_interval() -> u64 {
    60
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TcpDefaults {
    #[serde(default = "default_tcp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tcp_worker_pool_size")]
    pub worker_pool_size: usize,
    #[serde(default)]
    pub protocols: HashMap<String, TcpProtocolConfig>,
}

impl Default for TcpDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_pool_size: 4,
            protocols: Self::default_protocols(),
        }
    }
}

impl TcpDefaults {
    fn default_protocols() -> HashMap<String, TcpProtocolConfig> {
        let mut protocols = HashMap::new();
        protocols.insert(
            "smtp".to_string(),
            TcpProtocolConfig {
                ports: vec![25, 587],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "imap".to_string(),
            TcpProtocolConfig {
                ports: vec![143, 993],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "pop3".to_string(),
            TcpProtocolConfig {
                ports: vec![110, 995],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "mysql".to_string(),
            TcpProtocolConfig {
                ports: vec![3306],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols.insert(
            "postgres".to_string(),
            TcpProtocolConfig {
                ports: vec![5432],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
            },
        );
        protocols
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TcpProtocolConfig {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub upstream_format: Option<String>,
    #[serde(default)]
    pub upstream_format_v6: Option<String>,
}

fn default_tcp_enabled() -> bool {
    false
}

fn default_tcp_worker_pool_size() -> usize {
    4
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UdpDefaults {
    #[serde(default = "default_udp_enabled")]
    pub enabled: bool,
    #[serde(default = "default_udp_worker_pool_size")]
    pub worker_pool_size: usize,
    #[serde(default)]
    pub protocols: HashMap<String, UdpProtocolConfig>,
}

impl Default for UdpDefaults {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_pool_size: 4,
            protocols: Self::default_protocols(),
        }
    }
}

impl UdpDefaults {
    fn default_protocols() -> HashMap<String, UdpProtocolConfig> {
        let mut protocols = HashMap::new();
        protocols.insert(
            "dns".to_string(),
            UdpProtocolConfig {
                ports: vec![53],
                upstream_format: Some("127.0.0.1:5353".to_string()),
                upstream_format_v6: Some("[::1]:5353".to_string()),
            },
        );
        protocols
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UdpProtocolConfig {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub upstream_format: Option<String>,
    #[serde(default)]
    pub upstream_format_v6: Option<String>,
}

fn default_udp_enabled() -> bool {
    false
}

fn default_udp_worker_pool_size() -> usize {
    4
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TarpitDefaults {
    #[serde(default = "default_tarpit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tarpit_depth")]
    pub max_depth: u32,
    #[serde(default = "default_tarpit_links")]
    pub links_per_page: u32,
    #[serde(default = "default_tarpit_delay")]
    pub response_delay_ms: u64,
    #[serde(default)]
    pub scraper_user_agents: Vec<String>,
    #[serde(default)]
    pub content_templates: Vec<String>,
}

impl Default for TarpitDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 10,
            links_per_page: 50,
            response_delay_ms: 100,
            scraper_user_agents: vec![
                "scrapy".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
                "python-urllib".to_string(),
                "aiohttp".to_string(),
                "httpx".to_string(),
                "go-http".to_string(),
                "node-fetch".to_string(),
                "axios".to_string(),
                "rubygems".to_string(),
                "java".to_string(),
                "okhttp".to_string(),
                "feedparser".to_string(),
                " UniversalFeedParser".to_string(),
                "libwww-perl".to_string(),
                "PySpider".to_string(),
                "scrapeloader".to_string(),
                "SiteAnalyzer".to_string(),
                "Screaming Frog".to_string(),
            ],
            content_templates: vec![],
        }
    }
}

fn default_tarpit_enabled() -> bool {
    true
}

fn default_tarpit_depth() -> u32 {
    10
}

fn default_tarpit_links() -> u32 {
    50
}

fn default_tarpit_delay() -> u64 {
    100
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UploadDefaults {
    #[serde(default = "default_upload_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_size")]
    pub max_size: String,
    #[serde(default = "default_memory_threshold")]
    pub memory_threshold: String,
    #[serde(default = "default_scan_with_yara")]
    pub scan_with_yara: bool,
    #[serde(default = "default_sandbox_enabled")]
    pub sandbox_enabled: bool,
    #[serde(default = "default_sandbox_dir")]
    pub sandbox_dir: String,
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: String,
    #[serde(default)]
    pub yara_rules_dir: Option<String>,
    #[serde(default = "default_yara_timeout_ms")]
    pub yara_timeout_ms: u64,
    #[serde(default)]
    pub allowed_types: UploadAllowedTypesDefaults,
}

impl Default for UploadDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: "100MB".to_string(),
            memory_threshold: "10MB".to_string(),
            scan_with_yara: true,
            sandbox_enabled: true,
            sandbox_dir: "/var/lib/rustwaf/sandbox".to_string(),
            quarantine_dir: "/var/lib/rustwaf/quarantine".to_string(),
            yara_rules_dir: None,
            yara_timeout_ms: 30000,
            allowed_types: UploadAllowedTypesDefaults::default(),
        }
    }
}

fn default_upload_enabled() -> bool {
    true
}
fn default_max_size() -> String {
    "100MB".to_string()
}
fn default_memory_threshold() -> String {
    "10MB".to_string()
}
fn default_scan_with_yara() -> bool {
    true
}
fn default_sandbox_enabled() -> bool {
    true
}
fn default_sandbox_dir() -> String {
    "/var/lib/rustwaf/sandbox".to_string()
}
fn default_quarantine_dir() -> String {
    "/var/lib/rustwaf/quarantine".to_string()
}
fn default_yara_timeout_ms() -> u64 {
    30000
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UploadAllowedTypesDefaults {
    #[serde(default = "default_allowed_types_mode")]
    pub mode: String,
    #[serde(default = "default_allowed_mime_types")]
    pub mime_types: Vec<String>,
}

impl Default for UploadAllowedTypesDefaults {
    fn default() -> Self {
        Self {
            mode: "allowlist".to_string(),
            mime_types: default_allowed_mime_types(),
        }
    }
}

fn default_allowed_types_mode() -> String {
    "allowlist".to_string()
}

fn default_allowed_mime_types() -> Vec<String> {
    vec![
        "image/jpeg".to_string(),
        "image/png".to_string(),
        "image/gif".to_string(),
        "image/webp".to_string(),
        "image/avif".to_string(),
        "image/bmp".to_string(),
        "image/svg+xml".to_string(),
        "video/mp4".to_string(),
        "video/webm".to_string(),
        "video/mpeg".to_string(),
        "video/quicktime".to_string(),
        "audio/mpeg".to_string(),
        "audio/ogg".to_string(),
        "audio/wav".to_string(),
        "audio/flac".to_string(),
        "audio/aac".to_string(),
        "application/pdf".to_string(),
        "application/msword".to_string(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string(),
        "application/vnd.ms-excel".to_string(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
        "application/vnd.ms-powerpoint".to_string(),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation".to_string(),
        "application/vnd.oasis.opendocument.text".to_string(),
        "application/vnd.oasis.opendocument.spreadsheet".to_string(),
        "application/vnd.oasis.opendocument.presentation".to_string(),
        "application/rtf".to_string(),
        "text/plain".to_string(),
        "text/csv".to_string(),
    ]
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MainSecurityConfig {
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default = "default_sanitize_forwarded")]
    pub sanitize_forwarded_headers: bool,
    #[serde(default)]
    pub global_security_headers: bool,
}

fn default_sanitize_forwarded() -> bool {
    true
}

impl MainConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: MainConfig = toml::from_str(&content)?;

        if config.admin.token.is_empty() || config.admin.token == "changeme" {
            config.admin.token = Self::generate_token();
        }

        Ok(config)
    }

    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();
        token
    }

    pub fn default_config() -> Self {
        MainConfig {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                host_v6: None,
                trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
            },
            fallback: FallbackConfig {
                mode: "return_404".to_string(),
                upstream: None,
            },
            admin: AdminConfig {
                enabled: true,
                port: 8081,
                token: Self::generate_token(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                access_log: true,
                access_log_dir: None,
                retention_days: 5,
                max_entries_per_file: 50000,
                access_log_format: "json".to_string(),
                exporter: LogExporterConfig::default(),
                request_body_logging: RequestBodyLoggingConfig::default(),
            },
            metrics: MetricsConfig {
                enabled: true,
                port: 9090,
            },
            tokio: TokioConfig::default(),
            http: HttpConfig::default(),
            tls: TlsConfig::default(),
            http3: Http3Config::default(),
            threat_level: ThreatLevelConfig::default(),
            ip_feeds: IpFeedConfig::default(),
            defaults: DefaultsConfig::default(),
            rate_limit_memory: RateLimitMemoryConfig::default(),
            proxy_limits: ProxyLimitsConfig::default(),
            blocklist_limits: BlocklistLimitsConfig::default(),
            tcp: TcpDefaults::default(),
            udp: UdpDefaults::default(),
            tarpit: TarpitDefaults::default(),
            persistence: PersistenceConfig::default(),
            traffic_shaping: TrafficShapingConfig::default(),
            security: MainSecurityConfig::default(),
            static_config: None,
            tunnel: TunnelConfig::default(),
            plugins: PluginConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TrafficShapingConfig {
    #[serde(default = "default_ts_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub global: GlobalTrafficShapingConfig,
    #[serde(default)]
    pub connection_limits: ConnectionLimitsConfig,
}

impl Default for TrafficShapingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global: GlobalTrafficShapingConfig::default(),
            connection_limits: ConnectionLimitsConfig::default(),
        }
    }
}

fn default_ts_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalTrafficShapingConfig {
    #[serde(default = "default_ingress_max")]
    pub ingress_max_mb_s: u64,
    #[serde(default = "default_egress_max")]
    pub egress_max_mb_s: u64,
    #[serde(default = "default_burst_allowance")]
    pub burst_allowance_mb: u64,
    #[serde(default = "default_burst_refill_ms")]
    pub burst_refill_ms: u64,
    #[serde(default = "default_attack_multiplier")]
    pub attack_mode_multiplier: f64,
}

impl Default for GlobalTrafficShapingConfig {
    fn default() -> Self {
        Self {
            ingress_max_mb_s: 128,
            egress_max_mb_s: 128,
            burst_allowance_mb: 10,
            burst_refill_ms: 100,
            attack_mode_multiplier: 0.5,
        }
    }
}

fn default_ingress_max() -> u64 {
    128
}
fn default_egress_max() -> u64 {
    128
}
fn default_burst_allowance() -> u64 {
    10
}
fn default_burst_refill_ms() -> u64 {
    100
}
fn default_attack_multiplier() -> f64 {
    0.5
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConnectionLimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_connection_queue_size")]
    pub connection_queue_size: u32,
    #[serde(default = "default_connection_queue_timeout_ms")]
    pub connection_queue_timeout_ms: u64,
    #[serde(default = "default_connection_burst")]
    pub connection_burst: u32,
}

impl Default for ConnectionLimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_ip: 10,
            connection_queue_size: 100,
            connection_queue_timeout_ms: 60000,
            connection_burst: 5,
        }
    }
}

fn default_max_connections() -> u32 {
    1000
}
fn default_max_connections_per_ip() -> u32 {
    10
}
fn default_connection_queue_size() -> u32 {
    100
}
fn default_connection_queue_timeout_ms() -> u64 {
    60000
}
fn default_connection_burst() -> u32 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TrafficShapingDefaults {
    #[serde(default = "default_ts_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub site: SiteTrafficShapingDefaults,
}

impl Default for TrafficShapingDefaults {
    fn default() -> Self {
        Self {
            enabled: true,
            site: SiteTrafficShapingDefaults::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SiteTrafficShapingDefaults {
    #[serde(default = "default_site_ingress_max")]
    pub ingress_max_mb_s: u64,
    #[serde(default = "default_site_egress_max")]
    pub egress_max_mb_s: u64,
    #[serde(default = "default_site_burst_allowance")]
    pub burst_allowance_mb: u64,
    #[serde(default)]
    pub connection: SiteConnectionDefaults,
}

impl Default for SiteTrafficShapingDefaults {
    fn default() -> Self {
        Self {
            ingress_max_mb_s: 12,
            egress_max_mb_s: 12,
            burst_allowance_mb: 5,
            connection: SiteConnectionDefaults::default(),
        }
    }
}

fn default_site_ingress_max() -> u64 {
    12
}
fn default_site_egress_max() -> u64 {
    12
}
fn default_site_burst_allowance() -> u64 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SiteConnectionDefaults {
    #[serde(default = "default_site_max_connections")]
    pub max_connections: Option<u32>,
    #[serde(default = "default_site_max_connections_per_ip")]
    pub max_connections_per_ip: Option<u32>,
    #[serde(default = "default_site_connection_queue_size")]
    pub connection_queue_size: Option<u32>,
    #[serde(default = "default_site_connection_burst")]
    pub connection_burst: Option<u32>,
}

impl Default for SiteConnectionDefaults {
    fn default() -> Self {
        Self {
            max_connections: None,
            max_connections_per_ip: None,
            connection_queue_size: None,
            connection_burst: None,
        }
    }
}

fn default_site_max_connections() -> Option<u32> {
    None
}
fn default_site_max_connections_per_ip() -> Option<u32> {
    None
}
fn default_site_connection_queue_size() -> Option<u32> {
    None
}
fn default_site_connection_burst() -> Option<u32> {
    None
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MainStaticConfig {
    #[serde(default = "default_static_worker_enabled")]
    pub enabled: Option<bool>,
    #[serde(default = "default_watch_interval_ms")]
    pub watch_interval_ms: Option<u64>,
    #[serde(default = "default_preload_on_startup")]
    pub preload_on_startup: Option<bool>,
    #[serde(default = "default_minified_base_dir")]
    pub minified_base_dir: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TunnelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub waf_peers: TunnelWafPeersConfig,
    #[serde(default)]
    pub vpn: TunnelVpnConfig,
    #[serde(default)]
    pub quic: TunnelQuicConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TunnelWafPeersConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bind_address: String,
    #[serde(default = "default_waf_peer_port")]
    pub port: u16,
    #[serde(default)]
    pub peers: std::collections::HashMap<String, TunnelPeerConfig>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub allow_unauthenticated: bool,
    #[serde(default)]
    pub require_tls: bool,
}

fn default_waf_peer_port() -> u16 {
    5001
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TunnelPeerConfig {
    pub address: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default = "default_peer_weight")]
    pub weight: u32,
    #[serde(default)]
    pub enabled: bool,
}

impl Default for TunnelPeerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            auth_token: String::new(),
            weight: 100,
            enabled: true,
        }
    }
}

fn default_peer_weight() -> u32 {
    100
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TunnelVpnConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wg_bind")]
    pub bind_address: String,
    #[serde(default = "default_wg_port")]
    pub port: u16,
    #[serde(default = "default_wg_interface")]
    pub interface: String,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(default)]
    pub persistent_keepalive: u16,
}

fn default_wg_bind() -> String {
    "0.0.0.0".to_string()
}

fn default_wg_port() -> u16 {
    51820
}

fn default_wg_interface() -> String {
    "wg0".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WireGuardPeerConfig {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_peer_keepalive")]
    pub persistent_keepalive: u16,
    #[serde(default)]
    pub enabled: bool,
}

fn default_peer_keepalive() -> u16 {
    25
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TunnelQuicConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_quic_bind")]
    pub bind_address: String,
    #[serde(default = "default_quic_port")]
    pub port: u16,
    #[serde(default = "default_quic_max_idle")]
    pub max_idle_timeout_secs: u64,
    #[serde(default = "default_quic_keepalive")]
    pub keepalive_interval_secs: u64,
    #[serde(default)]
    pub server: TunnelQuicServerConfig,
    #[serde(default)]
    pub client: TunnelQuicClientConfig,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub client_ca: Option<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_dedicated_worker")]
    pub dedicated_worker: bool,
    #[serde(default = "default_max_streams")]
    pub max_concurrent_streams: u64,
    #[serde(default = "default_max_stream_buffer")]
    pub max_stream_buffer_size: usize,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default)]
    pub auto_generate_certs: bool,
    #[serde(default)]
    pub cert_domain: Option<String>,
}

fn default_dedicated_worker() -> bool {
    true
}

fn default_max_streams() -> u64 {
    100
}

fn default_max_stream_buffer() -> usize {
    1024 * 1024
}

fn default_max_message_size() -> usize {
    1024 * 1024
}

fn default_quic_bind() -> String {
    "0.0.0.0".to_string()
}

fn default_quic_port() -> u16 {
    51821
}

fn default_quic_max_idle() -> u64 {
    300
}

fn default_quic_keepalive() -> u64 {
    25
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TunnelQuicServerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, PortMappingConfig>,
    #[serde(default)]
    pub require_client_cert: bool,
    #[serde(default)]
    pub allow_unauthenticated: bool,
    #[serde(default = "default_quic_server_max_connections")]
    pub max_connections: usize,
}

fn default_quic_server_max_connections() -> usize {
    1000
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PortMappingConfig {
    pub port: u16,
    pub protocol: String,
    pub upstream_host: Option<String>,
    pub upstream_port: Option<u16>,
}

impl Default for PortMappingConfig {
    fn default() -> Self {
        Self {
            port: 80,
            protocol: "tcp".to_string(),
            upstream_host: Some("127.0.0.1".to_string()),
            upstream_port: Some(80),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TunnelQuicClientConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, PortMappingConfig>,
    #[serde(default)]
    pub peers: std::collections::HashMap<String, TunnelQuicPeerConfig>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub server_ca: Option<String>,
    #[serde(default)]
    pub verify_server: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TunnelQuicPeerConfig {
    pub address: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default = "default_peer_weight")]
    pub weight: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
}

impl Default for TunnelQuicPeerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            auth_token: String::new(),
            weight: 100,
            enabled: true,
            server_name: None,
        }
    }
}

fn default_static_worker_enabled() -> Option<bool> {
    Some(true)
}

fn default_watch_interval_ms() -> Option<u64> {
    Some(5000)
}

fn default_preload_on_startup() -> Option<bool> {
    Some(true)
}

fn default_minified_base_dir() -> Option<String> {
    Some("/var/cache/rustwaf/minified".to_string())
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PluginConfig {
    #[serde(default)]
    pub wasm: WasmPluginGlobalConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WasmPluginGlobalConfig {
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: usize,
    #[serde(default = "default_max_cpu_fuel")]
    pub max_cpu_fuel: u64,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub plugins: Vec<WasmPluginInstanceConfig>,
}

impl Default for WasmPluginGlobalConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_cpu_fuel: 0,
            timeout_seconds: 30,
            plugins: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WasmPluginInstanceConfig {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub max_memory_mb: Option<usize>,
    #[serde(default)]
    pub max_cpu_fuel: Option<u64>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn default_max_memory_mb() -> usize {
    64
}

fn default_max_cpu_fuel() -> u64 {
    0
}

fn default_timeout_seconds() -> u64 {
    30
}

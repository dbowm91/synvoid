use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteConfig {
    pub site: SiteInfo,
    #[serde(default)]
    pub ratelimit: SiteRateLimitConfig,
    #[serde(default)]
    pub blocked: SiteBlockedConfig,
    #[serde(default)]
    pub bot: SiteBotConfig,
    #[serde(default)]
    pub honeypot_probe: SiteProbeConfig,
    #[serde(default)]
    pub error_pages: SiteErrorPagesConfig,
    #[serde(default)]
    pub css_challenge: SiteCssChallengeConfig,
    #[serde(default)]
    pub whitelist: SiteWhitelistConfig,
    #[serde(default)]
    pub worker_pool: SiteWorkerPoolConfig,
    #[serde(default)]
    pub logging: SiteLoggingConfig,
    #[serde(default)]
    pub proxy: SiteProxyConfig,
    #[serde(default)]
    pub tcp: SiteTcpConfig,
    #[serde(default)]
    pub tarpit: SiteTarpitConfig,
    #[serde(default)]
    pub attack_detection: SiteAttackDetectionConfig,
    #[serde(default)]
    pub upload: SiteUploadConfig,
    #[serde(default)]
    pub auth: SiteAuthConfig,
    #[serde(default)]
    pub r#static: SiteStaticConfig,
    #[serde(default)]
    pub security: SiteSecurityConfig,
    #[serde(default)]
    pub security_headers: SiteSecurityHeadersConfig,
    #[serde(default)]
    pub traffic_shaping: SiteTrafficShapingConfig,
    #[serde(default)]
    pub grpc: SiteGrpcConfig,
    #[serde(default)]
    pub websocket: SiteWebSocketConfig,
    #[serde(default)]
    pub tunnel: SiteTunnelConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteProxyConfig {
    #[serde(default)]
    pub max_response_size: Option<usize>,

    #[serde(default)]
    pub headers: Option<ProxyHeadersConfig>,

    #[serde(default)]
    pub upstream: Option<ProxyUpstreamConfig>,

    #[serde(default)]
    pub fastcgi: Option<FastCgiConfig>,

    #[serde(default)]
    pub php: Option<PhpConfig>,

    #[serde(default)]
    pub cgi: Option<CgiConfig>,

    #[serde(default)]
    pub backend: Option<BackendConfig>,

    #[serde(default)]
    pub locations: Vec<LocationConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProxyHeadersConfig {
    #[serde(default)]
    pub clear: Vec<String>,

    #[serde(default)]
    pub set: Vec<HeaderOverride>,

    #[serde(default)]
    pub forward: Vec<String>,

    #[serde(default)]
    pub hide: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HeaderOverride {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProxyUpstreamConfig {
    #[serde(default)]
    pub keepalive: Option<usize>,

    #[serde(default)]
    pub connect_timeout: Option<String>,

    #[serde(default)]
    pub send_timeout: Option<String>,

    #[serde(default)]
    pub read_timeout: Option<String>,

    #[serde(default)]
    pub buffering: Option<bool>,

    #[serde(default)]
    pub buffer_size: Option<String>,

    #[serde(default)]
    pub tls: Option<UpstreamTlsConfig>,

    #[serde(default)]
    pub servers: Vec<String>,

    #[serde(default)]
    pub backup_servers: Vec<String>,

    #[serde(default)]
    pub retry: Option<RetryConfig>,

    #[serde(default)]
    pub buffering_config: Option<BufferingConfig>,

    #[serde(default)]
    pub cache: Option<ProxyCacheConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RetryConfig {
    #[serde(default = "default_retry_enabled")]
    pub enabled: bool,

    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    #[serde(default)]
    pub timeout_ms: Option<u64>,

    #[serde(default = "default_retry_on_error")]
    pub retry_on_error: bool,

    #[serde(default = "default_retry_on_timeout")]
    pub retry_on_timeout: bool,

    #[serde(default = "default_retry_status_codes")]
    pub retry_on_status: Vec<u16>,

    #[serde(default = "default_retry_non_idempotent")]
    pub retry_non_idempotent: bool,
}

fn default_retry_enabled() -> bool {
    false
}
fn default_max_retries() -> u32 {
    3
}
fn default_retry_on_error() -> bool {
    true
}
fn default_retry_on_timeout() -> bool {
    true
}
fn default_retry_status_codes() -> Vec<u16> {
    vec![502, 503, 504]
}
fn default_retry_non_idempotent() -> bool {
    false
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct BufferingConfig {
    #[serde(default)]
    pub enabled: Option<bool>,

    #[serde(default)]
    pub buffer_size: Option<String>,

    #[serde(default)]
    pub buffer_count: Option<usize>,

    #[serde(default)]
    pub busy_size: Option<String>,

    #[serde(default)]
    pub request_buffering: Option<bool>,

    #[serde(default)]
    pub client_body_buffer: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProxyCacheConfig {
    #[serde(default)]
    pub enable: Option<bool>,

    #[serde(default)]
    pub path: Option<String>,

    #[serde(default)]
    pub max_size: Option<String>,

    #[serde(default = "default_cache_inactive")]
    pub inactive: u64,

    #[serde(default)]
    pub use_temp_file: Option<bool>,

    #[serde(default = "default_cache_valid_status")]
    pub valid_status: Vec<u16>,

    #[serde(default = "default_cache_methods")]
    pub methods: Vec<String>,

    #[serde(default)]
    pub use_stale: Vec<String>,

    #[serde(default = "default_cache_min_uses")]
    pub min_uses: u32,

    #[serde(default)]
    pub key: Option<String>,

    #[serde(default)]
    pub vary_by: Vec<String>,

    #[serde(default)]
    pub memory_max: Option<String>,

    #[serde(default)]
    pub disk_max: Option<String>,
}

fn default_cache_inactive() -> u64 {
    3600
}
fn default_cache_valid_status() -> Vec<u16> {
    vec![200, 301, 302, 304]
}
fn default_cache_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}
fn default_cache_min_uses() -> u32 {
    1
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UpstreamTlsConfig {
    #[serde(default)]
    pub enabled: Option<bool>,

    #[serde(default)]
    pub cert: Option<String>,

    #[serde(default)]
    pub key: Option<String>,

    #[serde(default)]
    pub ca_cert: Option<String>,

    #[serde(default)]
    pub skip_verify: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FastCgiConfig {
    #[serde(default)]
    pub socket: Option<String>,

    #[serde(default)]
    pub script_filename: Option<String>,

    #[serde(default)]
    pub index: Option<String>,

    #[serde(default)]
    pub params: Option<HashMap<String, String>>,

    #[serde(default)]
    pub split_path_info: Option<String>,

    #[serde(default)]
    pub try_files: Option<String>,

    #[serde(default)]
    pub connect_timeout: Option<u64>,

    #[serde(default)]
    pub send_timeout: Option<u64>,

    #[serde(default)]
    pub read_timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PhpConfig {
    #[serde(default)]
    pub socket: Option<String>,

    #[serde(default)]
    pub host: Option<String>,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub root: Option<String>,

    #[serde(default)]
    pub index: Option<String>,

    #[serde(default)]
    pub upload_tmp: Option<String>,

    #[serde(default)]
    pub extensions_dir: Option<String>,

    #[serde(default)]
    pub ini_settings: Option<HashMap<String, String>>,

    #[serde(default)]
    pub connect_timeout: Option<u64>,

    #[serde(default)]
    pub send_timeout: Option<u64>,

    #[serde(default)]
    pub read_timeout: Option<u64>,

    #[serde(default)]
    pub disable_functions: Option<Vec<String>>,

    #[serde(default)]
    pub open_basedir: Option<String>,

    #[serde(default)]
    pub allow_url_fopen: Option<bool>,

    #[serde(default)]
    pub max_execution_time: Option<u64>,

    #[serde(default)]
    pub memory_limit: Option<String>,

    #[serde(default)]
    pub upload_max_filesize: Option<String>,

    #[serde(default)]
    pub post_max_size: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct CgiConfig {
    #[serde(default)]
    pub root: Option<String>,

    #[serde(default)]
    pub index: Option<String>,

    #[serde(default)]
    pub pass_variables: Option<bool>,

    #[serde(default)]
    pub timeout: Option<u64>,

    #[serde(default)]
    pub stdout_stderr_merge: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LocationConfig {
    pub path: String,
    #[serde(default)]
    pub backend: Option<BackendConfig>,
    #[serde(default)]
    pub fastcgi: Option<FastCgiLocationConfig>,
    #[serde(default)]
    pub php: Option<PhpLocationConfig>,
    #[serde(default)]
    pub cgi: Option<CgiLocationConfig>,
    #[serde(default)]
    pub proxy: Option<LocationProxyConfig>,
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
}

impl LocationConfig {
    pub fn is_method_allowed(&self, method: &str) -> bool {
        if let Some(ref allowed) = self.allowed_methods {
            let method_upper = method.to_uppercase();
            allowed.iter().any(|m| m.to_uppercase() == method_upper)
        } else {
            true
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FastCgiLocationConfig {
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub script_filename: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub split_path_info: Option<String>,
    #[serde(default)]
    pub try_files: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub send_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PhpLocationConfig {
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub upload_tmp: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    #[serde(default)]
    pub send_timeout: Option<u64>,
    #[serde(default)]
    pub read_timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct CgiLocationConfig {
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct LocationProxyConfig {
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum BackendConfig {
    #[serde(rename = "upstream")]
    Upstream { url: Option<String> },

    #[serde(rename = "axum")]
    Axum {
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "axum-dynamic")]
    AxumDynamic {
        #[serde(default)]
        plugin: Option<String>,
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "fastcgi")]
    FastCgi {
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "static")]
    Static {
        #[serde(default)]
        enabled: Option<bool>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteTcpConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ports: HashMap<String, SitePortConfig>,
    #[serde(default)]
    pub filter: Option<SiteProtocolFilterConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SitePortConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub filter: Option<String>, // "allow", "drop", "challenge"
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteProtocolFilterConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub http_on_smtp: Option<String>,
    #[serde(default)]
    pub http_on_imap: Option<String>,
    #[serde(default)]
    pub http_on_mysql: Option<String>,
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
    #[serde(default)]
    pub blocked: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteGrpcConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub max_message_size: Option<usize>,
    #[serde(default)]
    pub enable_request_validation: Option<bool>,
    #[serde(default)]
    pub enable_streaming: Option<bool>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub h2c_enabled: Option<bool>,
    #[serde(default)]
    pub h2_enabled: Option<bool>,
    #[serde(default)]
    pub reflection_enabled: Option<bool>,
    #[serde(default)]
    pub health_check_enabled: Option<bool>,
    #[serde(default)]
    pub max_concurrent_streams: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteWebSocketConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub max_message_size: Option<usize>,
    #[serde(default)]
    pub mask_required: Option<bool>,
    #[serde(default)]
    pub enable_frame_validation: Option<bool>,
    #[serde(default)]
    pub enable_message_validation: Option<bool>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub ping_interval_secs: Option<u64>,
    #[serde(default)]
    pub ping_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteTunnelConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteTarpitConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub links_per_page: Option<u32>,
    #[serde(default)]
    pub response_delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteCssChallengeConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub invalid_count_min: Option<u32>,
    #[serde(default)]
    pub invalid_count_max: Option<u32>,
    #[serde(default)]
    pub valid_count: Option<u32>,
    #[serde(default)]
    pub asset_path: Option<String>,
    #[serde(default)]
    pub valid_aspect_ratios: Option<Vec<String>>,
    #[serde(default)]
    pub verification_window_secs: Option<u32>,
    #[serde(default)]
    pub block: Option<SiteCssBlockConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteCssBlockConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ban_duration: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteListenConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ssl: Option<bool>,
    #[serde(default)]
    pub http2: Option<bool>,
    #[serde(default)]
    pub http3: Option<bool>,
    #[serde(default)]
    pub default_server: Option<bool>,
    #[serde(default)]
    pub proxy_protocol: Option<bool>,
}

impl SiteListenConfig {
    pub fn to_socket_addr(&self, default_port: u16) -> Option<SocketAddr> {
        let port = self.port.unwrap_or(default_port);
        let addr = self.address.as_deref().unwrap_or("0.0.0.0");

        let addr_clean = addr.trim_start_matches('[').trim_end_matches(']');

        if let Ok(ip) = addr_clean.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, port));
        }

        if let Ok(mut addrs) = (addr_clean, port).to_socket_addrs() {
            return addrs.next();
        }

        None
    }

    pub fn is_ssl(&self) -> bool {
        self.ssl.unwrap_or(false)
    }

    pub fn is_default_server(&self) -> bool {
        self.default_server.unwrap_or(false)
    }

    pub fn is_http2_enabled(&self) -> bool {
        self.http2.unwrap_or(true)
    }

    pub fn is_http3_enabled(&self) -> bool {
        self.http3.unwrap_or(false)
    }

    pub fn is_proxy_protocol(&self) -> bool {
        self.proxy_protocol.unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteInfo {
    pub domains: Vec<String>,
    #[serde(default)]
    pub listen: Vec<SiteListenConfig>,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UpstreamConfig {
    #[serde(default = "default_upstream")]
    pub default: String,
    #[serde(default)]
    pub routes: HashMap<String, String>,
    #[serde(default)]
    pub tunnel_mappings: HashMap<String, u16>,
}

fn default_upstream() -> String {
    "http://127.0.0.1:8000".to_string()
}

impl UpstreamConfig {
    pub fn get_upstream(&self, path: &str) -> String {
        for (route_prefix, upstream) in &self.routes {
            if path.starts_with(route_prefix) {
                return self.resolve_tunnel_upstream(upstream);
            }
        }
        self.resolve_tunnel_upstream(&self.default)
    }

    fn resolve_tunnel_upstream(&self, upstream: &str) -> String {
        if upstream.starts_with("tunnel:") {
            let identifier = upstream
                .trim_start_matches("tunnel:")
                .trim_start_matches("tunnel://");
            if let Some(&port) = self.tunnel_mappings.get(identifier) {
                return format!("http://127.0.0.1:{}", 6000 + (port % 1000));
            }
            tracing::warn!("No tunnel mapping found for identifier: {}", identifier);
        }
        upstream.to_string()
    }

    pub fn is_tunnel_upstream(&self, upstream: &str) -> bool {
        upstream.starts_with("tunnel:") || upstream.starts_with("tunnel://")
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteRateLimitConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub ip: Option<IpRateLimitOverride>,
    #[serde(default)]
    pub global: Option<GlobalRateLimitOverride>,
    #[serde(default)]
    pub endpoints: Vec<EndpointRateLimitConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IpRateLimitOverride {
    pub per_second: Option<u32>,
    pub per_minute: Option<u32>,
    pub per_5min: Option<u32>,
    pub per_hour: Option<u32>,
    pub per_day: Option<u32>,
    pub burst: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalRateLimitOverride {
    pub per_second: Option<u32>,
    pub per_minute: Option<u32>,
    pub per_5min: Option<u32>,
    pub max_connections: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EndpointRateLimitConfig {
    pub path_pattern: String,
    pub per_minute: Option<u32>,
    pub per_hour: Option<u32>,
    pub burst: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteBlockedConfig {
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub use_regex: Option<bool>,
    #[serde(default)]
    pub block_methods: Option<Vec<String>>,
    #[serde(default)]
    pub block_response_code: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteBotConfig {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub block_ai_crawlers: Option<bool>,
    #[serde(default)]
    pub enable_css_honeypot: Option<bool>,
    #[serde(default)]
    pub enable_js_challenge: Option<bool>,
    #[serde(default)]
    pub challenge_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteProbeConfig {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub suspicious_words_enabled: Option<bool>,
    #[serde(default)]
    pub upstream_errors_enabled: Option<bool>,
    #[serde(default)]
    pub upstream_errors_auto_ban: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteErrorPagesConfig {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub custom_directory: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteWhitelistConfig {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub user_agents: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteWorkerPoolConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub workers: Option<usize>,
}

impl SiteConfig {
    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: SiteConfig = toml::from_str(&content)?;

        if config.site.domains.is_empty() {
            return Err("Site config must have at least one domain".into());
        }

        Ok(config)
    }

    pub fn site_id(&self) -> String {
        self.site.domains.first().cloned().unwrap_or_default()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteLoggingConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteAttackDetectionConfig {
    #[serde(default = "default_attack_detection_enabled")]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub paranoia_level: Option<u8>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub sqli: SiteSqliConfig,
    #[serde(default)]
    pub xss: SiteXssConfig,
    #[serde(default)]
    pub path_traversal: SitePathTraversalConfig,
    #[serde(default)]
    pub rfi: SiteRfiConfig,
    #[serde(default)]
    pub ssrf: SiteSsrfConfig,
}

fn default_attack_detection_enabled() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteSqliConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteXssConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SitePathTraversalConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteRfiConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteSsrfConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
    #[serde(default)]
    pub block_private_ips: Option<bool>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteUploadConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub max_size: Option<String>,
    #[serde(default)]
    pub memory_threshold: Option<String>,
    #[serde(default)]
    pub scan_with_yara: Option<bool>,
    #[serde(default)]
    pub sandbox_enabled: Option<bool>,
    #[serde(default)]
    pub allowed_types: SiteAllowedTypesConfig,
    #[serde(default)]
    pub paths: Vec<SitePathUploadConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteAllowedTypesConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub mime_types: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SitePathUploadConfig {
    pub pattern: String,
    #[serde(default)]
    pub max_size: Option<String>,
    #[serde(default)]
    pub scan_with_yara: Option<bool>,
    #[serde(default)]
    pub allowed_types: SiteAllowedTypesConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteAuthConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub login_path: Option<String>,
    #[serde(default)]
    pub session_duration_secs: Option<u64>,
    #[serde(default)]
    pub max_login_attempts: Option<u32>,
    #[serde(default)]
    pub lockout_duration_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteStaticConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub default_root: Option<String>,
    #[serde(default)]
    pub default_cache_ttl: Option<u64>,
    #[serde(default)]
    pub max_file_size: Option<String>,
    #[serde(default)]
    pub allow_symlinks: Option<bool>,
    #[serde(default = "default_block_hidden_files")]
    pub block_hidden_files: Option<bool>,
    #[serde(default)]
    pub enable_compression: Option<bool>,
    #[serde(default)]
    pub compression_min_size: Option<usize>,
    #[serde(default = "default_gzip_on_the_fly")]
    pub gzip_on_the_fly: Option<bool>,
    #[serde(default = "default_gzip_level")]
    pub gzip_level: Option<u32>,
    #[serde(default = "default_gzip_min_size")]
    pub gzip_min_size: Option<usize>,
    #[serde(default = "default_gzip_types")]
    pub gzip_types: Option<Vec<String>>,
    #[serde(default)]
    pub directory_listing: Option<bool>,
    #[serde(default)]
    pub directory_listing_format: Option<String>,
    #[serde(default)]
    pub locations: Vec<StaticLocation>,
    #[serde(default)]
    pub minified_dir: Option<String>,
    #[serde(default = "default_enable_minification")]
    pub enable_minification: Option<bool>,
    #[serde(default = "default_enable_html_minification")]
    pub enable_html_minification: Option<bool>,
    #[serde(default = "default_enable_css_minification")]
    pub enable_css_minification: Option<bool>,
    #[serde(default = "default_enable_js_minification")]
    pub enable_js_minification: Option<bool>,
    #[serde(default = "default_enable_brotli")]
    pub enable_brotli: Option<bool>,
    #[serde(default = "default_brotli_level")]
    pub brotli_level: Option<u32>,
    #[serde(default = "default_enable_file_cache")]
    pub enable_file_cache: Option<bool>,
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: Option<usize>,
    #[serde(default = "default_cache_ttl_seconds")]
    pub cache_ttl_seconds: Option<u64>,
    #[serde(default = "default_enable_file_watching")]
    pub enable_file_watching: Option<bool>,
    #[serde(default = "default_watch_interval_ms")]
    pub watch_interval_ms: Option<u64>,
    #[serde(default = "default_preload_on_startup")]
    pub preload_on_startup: Option<bool>,
}

fn default_block_hidden_files() -> Option<bool> {
    Some(true)
}

fn default_gzip_on_the_fly() -> Option<bool> {
    Some(true)
}

fn default_gzip_level() -> Option<u32> {
    Some(5)
}

fn default_gzip_min_size() -> Option<usize> {
    Some(256)
}

fn default_gzip_types() -> Option<Vec<String>> {
    Some(vec![
        "text/html".to_string(),
        "text/css".to_string(),
        "text/javascript".to_string(),
        "application/javascript".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
        "application/atom+xml".to_string(),
        "application/rss+xml".to_string(),
        "application/vnd.ms-fontobject".to_string(),
        "application/x-font-ttf".to_string(),
        "application/x-web-app-manifest+json".to_string(),
        "font/opentype".to_string(),
        "font/ttf".to_string(),
        "font/eot".to_string(),
        "font/otf".to_string(),
        "image/svg+xml".to_string(),
        "image/x-icon".to_string(),
        "text/x-component".to_string(),
        "text/x-cross-domain-policy".to_string(),
    ])
}

fn default_enable_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_html_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_css_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_js_minification() -> Option<bool> {
    Some(true)
}

fn default_enable_brotli() -> Option<bool> {
    Some(true)
}

fn default_brotli_level() -> Option<u32> {
    Some(11)
}

fn default_enable_file_cache() -> Option<bool> {
    Some(true)
}

fn default_cache_max_entries() -> Option<usize> {
    Some(10000)
}

fn default_cache_ttl_seconds() -> Option<u64> {
    Some(3600)
}

fn default_enable_file_watching() -> Option<bool> {
    Some(true)
}

fn default_watch_interval_ms() -> Option<u64> {
    Some(5000)
}

fn default_preload_on_startup() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StaticLocation {
    pub path: String,
    pub root: String,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub try_files: Option<Vec<String>>,
    #[serde(default)]
    pub cache_ttl: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteSecurityConfig {
    #[serde(default)]
    pub reject_unknown_hosts: Option<bool>,
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default)]
    pub upstream: SiteUpstreamConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteUpstreamConfig {
    #[serde(default)]
    pub tls: Option<SiteUpstreamTlsConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteUpstreamTlsConfig {
    #[serde(default = "default_tls_verify")]
    pub verify: Option<bool>,
    #[serde(default)]
    pub ca_cert: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub skip_verify: Option<bool>,
}

fn default_tls_verify() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteSecurityHeadersConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "default_security_headers_enabled")]
    pub strict_transport_security: Option<String>,
    #[serde(default)]
    pub content_security_policy: Option<String>,
    #[serde(default)]
    pub x_frame_options: Option<String>,
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: Option<String>,
    #[serde(default = "default_x_xss_protection")]
    pub x_xss_protection: Option<String>,
    #[serde(default)]
    pub referrer_policy: Option<String>,
    #[serde(default)]
    pub permissions_policy: Option<String>,
    #[serde(default)]
    pub cache_control: Option<String>,
    #[serde(default)]
    pub expect_ct: Option<String>,
    #[serde(default = "default_cross_domain_policy")]
    pub x_permitted_cross_domain_policies: Option<String>,
    #[serde(default = "default_download_options")]
    pub x_download_options: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default)]
    pub cors: SiteCorsConfig,
    #[serde(default)]
    pub cookie: SiteCookieConfig,
}

fn default_security_headers_enabled() -> Option<String> {
    Some("max-age=31536000; includeSubDomains".to_string())
}

fn default_x_content_type_options() -> Option<String> {
    Some("nosniff".to_string())
}

fn default_x_xss_protection() -> Option<String> {
    Some("1; mode=block".to_string())
}

fn default_cross_domain_policy() -> Option<String> {
    Some("none".to_string())
}

fn default_download_options() -> Option<String> {
    Some("noopen".to_string())
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteCorsConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allow_origin: Option<String>,
    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub allow_headers: Option<Vec<String>>,
    #[serde(default)]
    pub allow_credentials: Option<bool>,
    #[serde(default)]
    pub max_age: Option<u64>,
    #[serde(default)]
    pub expose_headers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteCookieConfig {
    #[serde(default)]
    pub secure: Option<bool>,
    #[serde(default)]
    pub httponly: Option<bool>,
    #[serde(default)]
    pub samesite: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SiteTrafficShapingConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub ingress_max_mb_s: Option<u64>,
    #[serde(default)]
    pub egress_max_mb_s: Option<u64>,
    #[serde(default)]
    pub burst_allowance_mb: Option<u64>,
    #[serde(default)]
    pub connection: SiteTrafficConnectionConfig,
}

impl Default for SiteTrafficShapingConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            inherit: Some(true),
            ingress_max_mb_s: None,
            egress_max_mb_s: None,
            burst_allowance_mb: None,
            connection: SiteTrafficConnectionConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteTrafficConnectionConfig {
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub max_connections_per_ip: Option<u32>,
    #[serde(default)]
    pub connection_queue_size: Option<u32>,
    #[serde(default)]
    pub connection_burst: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteGeoipConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteBasicAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub users: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub realm: Option<String>,
}

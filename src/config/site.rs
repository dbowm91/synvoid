#![allow(
    clippy::redundant_closure,
    clippy::manual_range_contains,
    clippy::collapsible_if
)]

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use super::validation::{parse_size_string, ConfigValidationError};
use crate::theme::ThemeColors;

fn default_some_true() -> Option<bool> {
    Some(true)
}

fn default_wasm_on_error() -> WasmOnError {
    WasmOnError::FailOpen
}

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
    pub udp: SiteUdpConfig,
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

    #[serde(default)]
    pub app_server: SiteAppServerConfig,
    #[serde(default)]
    pub serverless: Option<super::serverless::ServerlessConfig>,
    #[serde(default)]
    pub image_poison: SiteImagePoisonConfig,
    #[serde(default)]
    pub file_manager: SiteFileManagerConfig,
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

    #[serde(default)]
    pub cache: Option<ProxyCacheConfig>,

    #[serde(default)]
    pub tls_passthrough: Option<bool>,

    #[serde(default)]
    pub wasm_plugins: Option<Vec<String>>,

    #[serde(default = "default_wasm_on_error")]
    pub wasm_on_error: WasmOnError,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WasmOnError {
    #[default]
    FailOpen,
    FailClosed,
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

    #[serde(default)]
    pub allowed_protocols: Option<Vec<String>>,
}

impl ProxyUpstreamConfig {
    pub fn allows_protocol(&self, protocol: &str) -> bool {
        let allowed: Vec<String> = match &self.allowed_protocols {
            None => vec!["http".to_string()],
            Some(allowed) if allowed.is_empty() => vec!["http".to_string()],
            Some(allowed) => allowed.clone(),
        };

        // Check for "all" or "*" keyword - allows everything
        if allowed.iter().any(|p| {
            let p_lower = p.to_lowercase();
            p_lower == "all" || p_lower == "*"
        }) {
            return true;
        }

        let protocol_lower = protocol.to_lowercase();
        allowed.iter().any(|p| {
            let p_lower = p.to_lowercase();
            p_lower == protocol_lower
                || (p_lower == "tcp" && !protocol_lower.is_empty() && protocol_lower != "udp")
                || (p_lower == "udp"
                    && (protocol_lower == "udp"
                        || protocol_lower == "quic"
                        || protocol_lower == "wireguard"
                        || protocol_lower == "mesh_quic"))
                || (p_lower == "http"
                    && (protocol_lower.starts_with("http") || protocol_lower == "websocket"))
        })
    }

    pub fn is_protocol_restricted(&self) -> bool {
        matches!(&self.allowed_protocols, Some(v) if !v.is_empty())
    }

    pub fn allows_all_protocols(&self) -> bool {
        match &self.allowed_protocols {
            None => false,
            Some(allowed) if allowed.is_empty() => false,
            Some(allowed) => allowed.iter().any(|p| {
                let p_lower = p.to_lowercase();
                p_lower == "all" || p_lower == "*"
            }),
        }
    }
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

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

    #[serde(default)]
    pub stale_while_revalidate: Option<u64>,

    #[serde(default)]
    pub stale_if_error: Option<u64>,
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

    #[serde(default)]
    pub skip_verify_reason: Option<String>,
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
    #[serde(default)]
    pub serverless: Option<super::serverless::ServerlessConfig>,
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

    #[serde(rename = "axum-dynamic")]
    AxumDynamic {
        #[serde(default)]
        plugin: Option<String>,
        #[serde(default)]
        socket: Option<String>,
    },

    #[serde(rename = "app-server")]
    AppServer {
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
pub struct SiteUdpConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ports: HashMap<String, SiteUdpPortConfig>,
    #[serde(default)]
    pub filter: Option<SiteProtocolFilterConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteUdpPortConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub expected_protocol: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
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
pub struct SiteAppServerConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub app_path: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub workers: Option<u32>,
    #[serde(default)]
    pub blocking_threads: Option<u32>,
    #[serde(default)]
    pub socket_path: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub python_path: Option<String>,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default)]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub restart_on_failure: Option<bool>,
    #[serde(default)]
    pub max_restarts: Option<u32>,
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default)]
    pub health_check_interval_secs: Option<u64>,
    #[serde(default)]
    pub health_check_timeout_secs: Option<u64>,
    #[serde(default = "default_some_true")]
    pub auto_install_granian: Option<bool>,
    #[serde(default = "default_some_true")]
    pub auto_detect_venv: Option<bool>,
    #[serde(default = "default_some_true")]
    pub auto_detect_app: Option<bool>,
}

impl SiteAppServerConfig {
    pub fn socket_path_for_site(&self, site_id: &str, worker_id: usize) -> std::path::PathBuf {
        if let Some(ref path) = self.socket_path {
            std::path::PathBuf::from(path)
        } else {
            std::env::temp_dir().join(format!("maluwaf-{}-app-{}.sock", site_id, worker_id))
        }
    }
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
    /// Challenge type: "pow", "css", or "auto" (default: "auto" - POW first, fallback to CSS)
    /// Currently unused - reserved for future challenge selection logic
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
    pub mode: Option<String>,
    #[serde(default)]
    pub custom_directory: Option<String>,
    #[serde(default)]
    pub theme: Option<SiteThemeConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteThemeConfig {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow_only: Option<String>,
    #[serde(default)]
    pub colors: Option<ThemeColors>,
}

impl SiteThemeConfig {
    pub fn to_theme_config(
        &self,
        default_theme: &crate::theme::ThemeConfig,
    ) -> crate::theme::ThemeConfig {
        let preset = self.preset.as_deref().unwrap_or("default");
        let preset_enum = crate::theme::ThemePreset::from(preset);

        let colors = self.colors.clone().unwrap_or_else(|| preset_enum.colors());

        crate::theme::ThemeConfig {
            mode: self
                .mode
                .as_deref()
                .map(|m| crate::theme::ThemeMode::from(m))
                .unwrap_or(default_theme.mode),
            restriction: self
                .allow_only
                .as_deref()
                .map(|a| crate::theme::ThemeRestriction::from(a))
                .unwrap_or(default_theme.restriction),
            colors,
            spacing: default_theme.spacing.clone(),
            effects: default_theme.effects.clone(),
            branding: default_theme.branding.clone(),
        }
    }
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
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "Failed to read site config from {}",
                path.as_ref().display()
            )
        })?;
        let config: SiteConfig =
            toml::from_str(&content).context("Failed to parse site config TOML")?;

        if config.site.domains.is_empty() {
            anyhow::bail!("Site config must have at least one domain");
        }

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.site.validate()?;
        self.ratelimit.validate()?;
        self.attack_detection.validate()?;
        self.upload.validate()?;
        self.security_headers.validate()?;
        self.app_server.validate()?;
        self.grpc.validate()?;
        self.websocket.validate()?;
        self.file_manager.validate()?;
        Ok(())
    }

    pub fn site_id(&self) -> String {
        self.site.domains.first().cloned().unwrap_or_default()
    }

    pub fn app_server_config(&self) -> crate::app_server::AppServerConfig {
        let site_config = &self.app_server;

        crate::app_server::AppServerConfig {
            enabled: site_config.enabled.unwrap_or(false),
            app_path: site_config.app_path.clone().unwrap_or_default(),
            interface: site_config
                .interface
                .as_ref()
                .map(|s| crate::app_server::GranianInterface::from(s.as_str()))
                .unwrap_or(crate::app_server::GranianInterface::Asgi),
            workers: site_config.workers.unwrap_or(1),
            blocking_threads: site_config.blocking_threads.unwrap_or(4),
            socket_path: site_config
                .socket_path
                .as_ref()
                .map(std::path::PathBuf::from),
            port: site_config.port,
            host: site_config.host.clone(),
            python_path: site_config
                .python_path
                .as_ref()
                .map(std::path::PathBuf::from),
            working_directory: site_config
                .working_directory
                .as_ref()
                .map(std::path::PathBuf::from),
            env: site_config.env.clone().unwrap_or_default(),
            restart_on_failure: site_config.restart_on_failure.unwrap_or(true),
            max_restarts: site_config.max_restarts.unwrap_or(5),
            health_check_path: site_config
                .health_check_path
                .clone()
                .unwrap_or_else(|| "/".to_string()),
            health_check_interval_secs: site_config.health_check_interval_secs.unwrap_or(10),
            health_check_timeout_secs: site_config.health_check_timeout_secs.unwrap_or(5),
            auto_install_granian: site_config.auto_install_granian.unwrap_or(true),
            auto_detect_venv: site_config.auto_detect_venv.unwrap_or(true),
            auto_detect_app: site_config.auto_detect_app.unwrap_or(true),
        }
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
    pub theme: Option<SiteThemeConfig>,
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
    #[serde(default = "default_enable_svg_compression")]
    pub enable_svg_compression: Option<bool>,
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

fn default_enable_svg_compression() -> Option<bool> {
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
pub struct SiteFileManagerConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub max_file_size: Option<String>,
    #[serde(default)]
    pub blocked_extensions: Vec<String>,
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
    #[serde(default)]
    pub allow_hidden_files: Option<bool>,
    #[serde(default)]
    pub allow_symlinks: Option<bool>,
    #[serde(default)]
    pub require_auth: Option<bool>,
}

impl SiteFileManagerConfig {
    pub fn validate(&self) -> Result<(), super::validation::ConfigValidationError> {
        if let Some(ref max_size) = self.max_file_size {
            if let Err(e) = super::validation::parse_size_string(max_size) {
                return Err(super::validation::ConfigValidationError {
                    field: "file_manager.max_file_size".to_string(),
                    message: format!("Invalid size format: {}", e),
                });
            }
        }
        Ok(())
    }
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
    #[serde(default)]
    pub skip_verify_reason: Option<String>,
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

    // Stealth settings
    #[serde(default = "default_some_true")]
    pub date_header: Option<bool>,
    #[serde(default = "default_date_jitter")]
    pub date_jitter_seconds: Option<u32>,
    #[serde(default)]
    pub server_token: Option<String>,
}

fn default_security_headers_enabled() -> Option<String> {
    Some("max-age=31536000; includeSubDomains".to_string())
}

fn default_x_content_type_options() -> Option<String> {
    Some("nosniff".to_string())
}

fn default_x_xss_protection() -> Option<String> {
    Some("0".to_string())
}

fn default_cross_domain_policy() -> Option<String> {
    Some("none".to_string())
}

fn default_download_options() -> Option<String> {
    Some("noopen".to_string())
}

fn default_date_jitter() -> Option<u32> {
    Some(5)
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
    #[serde(default = "default_allow_wildcard_cors")]
    pub allow_wildcard_cors: bool,
}

fn default_allow_wildcard_cors() -> bool {
    false
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

impl SiteInfo {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.domains.is_empty() {
            return Err(ConfigValidationError {
                field: "site.domains".to_string(),
                message: "At least one domain is required".to_string(),
            });
        }
        for domain in &self.domains {
            if domain.is_empty() {
                return Err(ConfigValidationError {
                    field: "site.domains".to_string(),
                    message: "Domain cannot be empty".to_string(),
                });
            }
            if domain.len() > 253 {
                return Err(ConfigValidationError {
                    field: "site.domains".to_string(),
                    message: format!("Domain too long: {}", domain),
                });
            }
        }
        self.upstream.validate()
    }
}

impl UpstreamConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.default.is_empty() {
            return Err(ConfigValidationError {
                field: "site.upstream.default".to_string(),
                message: "Default upstream is required".to_string(),
            });
        }
        if !self.default.starts_with("http://")
            && !self.default.starts_with("https://")
            && !self.default.starts_with("tunnel:")
            && !self.default.starts_with("unix:")
        {
            return Err(ConfigValidationError {
                field: "site.upstream.default".to_string(),
                message: "Upstream must start with http://, https://, tunnel:, or unix:"
                    .to_string(),
            });
        }
        for (route, upstream) in &self.routes {
            if route.is_empty() {
                return Err(ConfigValidationError {
                    field: "site.upstream.routes".to_string(),
                    message: "Route pattern cannot be empty".to_string(),
                });
            }
            if upstream.is_empty() {
                return Err(ConfigValidationError {
                    field: "site.upstream.routes".to_string(),
                    message: format!("Upstream for route {} cannot be empty", route),
                });
            }
        }
        Ok(())
    }
}

impl SiteRateLimitConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref mode) = self.mode {
            match mode.as_str() {
                "shared" | "isolated" => {}
                _ => {
                    return Err(ConfigValidationError {
                        field: "ratelimit.mode".to_string(),
                        message: "Mode must be 'shared' or 'isolated'".to_string(),
                    });
                }
            }
        }
        for endpoint in &self.endpoints {
            if endpoint.path_pattern.is_empty() {
                return Err(ConfigValidationError {
                    field: "ratelimit.endpoints".to_string(),
                    message: "Path pattern cannot be empty".to_string(),
                });
            }
        }
        Ok(())
    }
}

impl SiteAttackDetectionConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref action) = self.action {
            match action.as_str() {
                "stall" | "block" | "log" => {}
                _ => {
                    return Err(ConfigValidationError {
                        field: "attack_detection.action".to_string(),
                        message: "Action must be 'stall', 'block', or 'log'".to_string(),
                    });
                }
            }
        }
        if let Some(level) = self.paranoia_level {
            if level < 1 || level > 3 {
                return Err(ConfigValidationError {
                    field: "attack_detection.paranoia_level".to_string(),
                    message: "Paranoia level must be between 1 and 3".to_string(),
                });
            }
        }
        Ok(())
    }
}

impl SiteUploadConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref max_size) = self.max_size {
            if let Err(e) = parse_size_string(max_size) {
                return Err(ConfigValidationError {
                    field: "upload.max_size".to_string(),
                    message: format!("Invalid size format: {}", e),
                });
            }
        }
        for path_config in &self.paths {
            if path_config.pattern.is_empty() {
                return Err(ConfigValidationError {
                    field: "upload.paths".to_string(),
                    message: "Path pattern cannot be empty".to_string(),
                });
            }
        }
        Ok(())
    }
}

impl SiteSecurityHeadersConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref samesite) = self.cookie.samesite {
            match samesite.to_lowercase().as_str() {
                "strict" | "lax" | "none" => {}
                _ => {
                    return Err(ConfigValidationError {
                        field: "security_headers.cookie.samesite".to_string(),
                        message: "SameSite must be 'strict', 'lax', or 'none'".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl SiteAppServerConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.app_path.is_none() {
                return Err(ConfigValidationError {
                    field: "app_server.app_path".to_string(),
                    message: "App path is required when app server is enabled".to_string(),
                });
            }
            if let Some(ref interface) = self.interface {
                match interface.to_lowercase().as_str() {
                    "asgi" | "rsgi" | "wsgi" => {}
                    _ => {
                        return Err(ConfigValidationError {
                            field: "app_server.interface".to_string(),
                            message: "Interface must be 'asgi', 'rsgi', or 'wsgi'".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

impl SiteGrpcConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.upstream.is_none() {
                return Err(ConfigValidationError {
                    field: "grpc.upstream".to_string(),
                    message: "Upstream is required when gRPC is enabled".to_string(),
                });
            }
        }
        Ok(())
    }
}

impl SiteWebSocketConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled.unwrap_or(false) {
            if self.upstream.is_none() {
                return Err(ConfigValidationError {
                    field: "websocket.upstream".to_string(),
                    message: "Upstream is required when WebSocket is enabled".to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SiteImagePoisonConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default = "default_poison_level")]
    pub level: Option<String>,
    #[serde(default = "default_poison_intensity")]
    pub intensity: Option<f32>,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default = "default_max_dimension")]
    pub max_dimension: Option<u32>,
    #[serde(default = "default_jpeg_quality")]
    pub jpeg_quality: Option<u8>,
}

fn default_poison_level() -> Option<String> {
    Some("standard".to_string())
}

fn default_poison_intensity() -> Option<f32> {
    Some(0.5)
}

fn default_max_dimension() -> Option<u32> {
    Some(4096)
}

fn default_jpeg_quality() -> Option<u8> {
    Some(85)
}

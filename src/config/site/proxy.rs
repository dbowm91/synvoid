use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::backend::{BackendConfig, CgiConfig, FastCgiConfig, LocationConfig, PhpConfig};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WasmOnError {
    #[default]
    FailOpen,
    FailClosed,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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
    pub tls_passthrough_warn_only: Option<bool>,

    #[serde(default)]
    pub wasm_plugins: Option<Vec<String>>,

    #[serde(default = "default_wasm_on_error")]
    pub wasm_on_error: WasmOnError,
}

fn default_wasm_on_error() -> WasmOnError {
    WasmOnError::FailOpen
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct HeaderOverride {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
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

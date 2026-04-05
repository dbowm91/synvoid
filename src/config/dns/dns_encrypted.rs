use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct DnsDotConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_dot_port")]
    pub port: u16,

    #[serde(default)]
    pub bind_address: String,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_true")]
    pub use_system_cert_store: bool,
}

fn default_dot_port() -> u16 {
    853
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct DnsDohConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_doh_port")]
    pub port: u16,

    #[serde(default)]
    pub bind_address: String,

    #[serde(default = "default_doh_path")]
    pub path: String,

    #[serde(default)]
    pub json_path: String,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_true")]
    pub use_system_cert_store: bool,
}

fn default_doh_port() -> u16 {
    443
}

fn default_doh_path() -> String {
    "/dns-query".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct DnsDoqConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_doq_port")]
    pub port: u16,

    #[serde(default)]
    pub bind_address: String,

    #[serde(default)]
    pub tls_cert_path: Option<String>,

    #[serde(default)]
    pub tls_key_path: Option<String>,

    #[serde(default = "default_true")]
    pub use_system_cert_store: bool,

    #[serde(default = "default_doq_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    #[serde(default = "default_doq_idle_timeout")]
    pub idle_timeout_secs: u64,
}

fn default_doq_port() -> u16 {
    853
}

fn default_doq_max_concurrent_streams() -> u32 {
    100
}

fn default_doq_idle_timeout() -> u64 {
    30
}

use super::defaults::default_true;

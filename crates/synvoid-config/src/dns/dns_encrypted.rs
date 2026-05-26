use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
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

impl DnsDotConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.port == 0 {
            return Err(DnsConfigError::InvalidDot(
                "port cannot be zero when DOT is enabled".to_string(),
            ));
        }

        if self.use_system_cert_store {
            return Ok(());
        }

        if self.tls_cert_path.is_none() || self.tls_key_path.is_none() {
            return Err(DnsConfigError::InvalidDot(
                "tls_cert_path and tls_key_path must be specified when not using system cert store"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

fn default_dot_port() -> u16 {
    853
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
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

impl DnsDohConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.port == 0 {
            return Err(DnsConfigError::InvalidDoh(
                "port cannot be zero when DOH is enabled".to_string(),
            ));
        }

        if self.path.is_empty() {
            return Err(DnsConfigError::InvalidDoh(
                "path cannot be empty when DOH is enabled".to_string(),
            ));
        }

        if self.use_system_cert_store {
            return Ok(());
        }

        if self.tls_cert_path.is_none() || self.tls_key_path.is_none() {
            return Err(DnsConfigError::InvalidDoh(
                "tls_cert_path and tls_key_path must be specified when not using system cert store"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

fn default_doh_port() -> u16 {
    443
}

fn default_doh_path() -> String {
    "/dns-query".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
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

impl DnsDoqConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.port == 0 {
            return Err(DnsConfigError::InvalidDoq(
                "port cannot be zero when DOQ is enabled".to_string(),
            ));
        }

        if self.max_concurrent_streams == 0 {
            return Err(DnsConfigError::InvalidDoq(
                "max_concurrent_streams must be greater than zero".to_string(),
            ));
        }

        if self.idle_timeout_secs == 0 {
            return Err(DnsConfigError::InvalidDoq(
                "idle_timeout_secs must be greater than zero".to_string(),
            ));
        }

        if self.use_system_cert_store {
            return Ok(());
        }

        if self.tls_cert_path.is_none() || self.tls_key_path.is_none() {
            return Err(DnsConfigError::InvalidDoq(
                "tls_cert_path and tls_key_path must be specified when not using system cert store"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

use super::defaults::default_true;

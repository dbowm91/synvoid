use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{unsupported, DnsConfigError};

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

fn default_dot_port() -> u16 {
    853
}

/// Phase 45: shared bind-address/port validation for encrypted transports.
/// An enabled transport must name an explicit, parseable IP and a non-zero
/// port so invalid addresses fail at validation time — before listener
/// startup — with the same semantics as `dns.bind_address`/`dns.port`.
fn validate_encrypted_bind(
    section: &str,
    bind_address: &str,
    port: u16,
) -> Result<(), DnsConfigError> {
    if port == 0 {
        return Err(unsupported(
            &format!("dns.{}.port", section),
            "port cannot be zero when the transport is enabled.",
        ));
    }
    if bind_address.is_empty() {
        return Err(unsupported(
            &format!("dns.{}.bind_address", section),
            "bind_address must be set explicitly when the transport is enabled \
             (e.g. \"0.0.0.0\" or \"127.0.0.1\"). Empty values fail here \
             instead of at listener startup.",
        ));
    }
    if bind_address.parse::<std::net::IpAddr>().is_err() {
        return Err(unsupported(
            &format!("dns.{}.bind_address", section),
            &format!(
                "invalid bind address '{}': must be a parseable IP address.",
                bind_address
            ),
        ));
    }
    Ok(())
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

impl DnsDotConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }
        validate_encrypted_bind("dot", &self.bind_address, self.port)
    }
}

impl DnsDohConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }
        // Note: `path`/`json_path` are consumed by the DoH router (unknown
        // paths return 404), so no fail-closed rejection applies to them.
        validate_encrypted_bind("doh", &self.bind_address, self.port)
    }
}

impl DnsDoqConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }
        validate_encrypted_bind("doq", &self.bind_address, self.port)?;
        if self.max_concurrent_streams == 0 {
            return Err(unsupported(
                "dns.doq.max_concurrent_streams",
                "must be greater than zero when DoQ is enabled.",
            ));
        }
        if self.idle_timeout_secs == 0 {
            return Err(unsupported(
                "dns.doq.idle_timeout_secs",
                "must be greater than zero when DoQ is enabled.",
            ));
        }
        Ok(())
    }
}

use super::defaults::default_true;

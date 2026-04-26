use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

mod dns_anycast;
mod dns_dnssec;
mod dns_encrypted;
mod dns_firewall;
mod dns_mesh;
mod dns_misc;
mod dns_rate_limit;
mod dns_recursive;
mod dns_settings;
mod dns_zones;

pub use dns_anycast::*;
pub use dns_dnssec::*;
pub use dns_encrypted::*;
pub use dns_firewall::*;
pub use dns_mesh::*;
pub use dns_misc::*;
pub use dns_rate_limit::*;
pub use dns_recursive::*;
pub use dns_settings::*;
pub use dns_zones::*;

mod defaults {
    pub fn default_true() -> bool {
        true
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    #[default]
    Standalone,
    Mesh,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DnsRateLimitMode {
    #[default]
    Shared,
    Dedicated,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DnsSecAlgorithm {
    #[default]
    Ed25519,
    RsaSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsSecKeyType {
    #[default]
    Zsk,
    Ksk,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_dns_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_dns_port")]
    pub port: u16,

    #[serde(default)]
    pub mode: DnsMode,

    #[serde(default)]
    pub ratelimit: DnsRateLimitConfig,

    #[serde(default)]
    pub rrl: DnsRrlConfig,

    #[serde(default)]
    pub firewall: DnsFirewallConfig,

    #[serde(default)]
    pub settings: DnsSettingsConfig,

    #[serde(default)]
    pub mesh: DnsMeshConfig,

    #[serde(default)]
    pub zones: DnsZonesConfig,

    #[serde(default)]
    pub limits: DnsLimitsConfig,

    #[serde(default)]
    pub dnssec: DnsSecConfig,

    #[serde(default)]
    pub dot: DnsDotConfig,

    #[serde(default)]
    pub doh: DnsDohConfig,

    #[serde(default)]
    pub doq: DnsDoqConfig,

    #[serde(default)]
    pub rpz: DnsRpzConfig,

    #[serde(default)]
    pub dns64: Dns64Config,

    #[serde(default)]
    pub prefetch: DnsPrefetchConfig,

    #[serde(default)]
    pub trust_anchors: TrustAnchorConfig,

    #[serde(default)]
    pub anycast: DnsAnycastConfig,

    #[serde(default)]
    pub recursive: RecursiveDnsConfig,
}

fn default_dns_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_dns_port() -> u16 {
    53
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_dns_bind_address(),
            port: default_dns_port(),
            mode: DnsMode::Standalone,
            ratelimit: DnsRateLimitConfig::default(),
            rrl: DnsRrlConfig::default(),
            firewall: DnsFirewallConfig::default(),
            settings: DnsSettingsConfig::default(),
            mesh: DnsMeshConfig::default(),
            zones: DnsZonesConfig::default(),
            limits: DnsLimitsConfig::default(),
            dnssec: DnsSecConfig::default(),
            dot: DnsDotConfig::default(),
            doh: DnsDohConfig::default(),
            doq: DnsDoqConfig::default(),
            rpz: DnsRpzConfig::default(),
            dns64: Dns64Config::default(),
            prefetch: DnsPrefetchConfig::default(),
            trust_anchors: TrustAnchorConfig::default(),
            anycast: DnsAnycastConfig::default(),
            recursive: RecursiveDnsConfig::default(),
        }
    }
}

impl DnsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.port == 0 {
            return Err(DnsConfigError::InvalidPort(
                "Port cannot be zero".to_string(),
            ));
        }

        if self.bind_address.parse::<std::net::IpAddr>().is_err()
            && self.bind_address != "0.0.0.0"
            && self.bind_address != "::"
        {
            return Err(DnsConfigError::InvalidBindAddress(format!(
                "Invalid bind address: {}",
                self.bind_address
            )));
        }

        self.ratelimit.validate()?;
        self.rrl.validate()?;
        self.settings.validate()?;
        self.dnssec.validate()?;

        if let DnsMode::Mesh = self.mode {
            self.mesh.validate()?;
        }

        self.anycast.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DnsConfigError {
    InvalidPort(String),
    InvalidBindAddress(String),
    InvalidRateLimit(String),
    InvalidRrl(String),
    InvalidSettings(String),
    InvalidDnsSec(String),
    InvalidMesh(String),
    InvalidAnycast(String),
    InvalidRecursive(String),
}

impl std::fmt::Display for DnsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsConfigError::InvalidPort(msg) => write!(f, "Invalid port: {}", msg),
            DnsConfigError::InvalidBindAddress(msg) => write!(f, "Invalid bind address: {}", msg),
            DnsConfigError::InvalidRateLimit(msg) => write!(f, "Invalid rate limit: {}", msg),
            DnsConfigError::InvalidRrl(msg) => write!(f, "Invalid RRL: {}", msg),
            DnsConfigError::InvalidSettings(msg) => write!(f, "Invalid settings: {}", msg),
            DnsConfigError::InvalidDnsSec(msg) => write!(f, "Invalid DNSSEC: {}", msg),
            DnsConfigError::InvalidMesh(msg) => write!(f, "Invalid mesh: {}", msg),
            DnsConfigError::InvalidAnycast(msg) => write!(f, "Invalid anycast: {}", msg),
            DnsConfigError::InvalidRecursive(msg) => write!(f, "Invalid recursive DNS: {}", msg),
        }
    }
}

impl std::error::Error for DnsConfigError {}

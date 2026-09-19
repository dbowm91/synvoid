use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::validation::ConfigValidationError;

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
        self.recursive.validate()?;
        self.limits
            .validate()
            .map_err(DnsConfigError::InvalidSettings)?;

        if let DnsMode::Mesh = self.mode {
            self.mesh.validate()?;
        }

        self.anycast.validate()?;

        // Phase 45 fail-closed contract: deferred features must not be
        // activatable. A default/inactive value stays parseable, but any
        // non-default value that the runtime would silently ignore is
        // rejected here with a typed config path. See
        // `architecture/dns_config_runtime_matrix.md`.
        self.rpz.validate()?;
        self.prefetch.validate()?;
        self.trust_anchors.validate()?;
        self.firewall.validate()?;
        self.dot.validate()?;
        self.doh.validate()?;
        self.doq.validate()?;

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
    /// Phase 45 fail-closed contract: the operator tried to activate a
    /// deferred/unsupported feature. `path` is the typed config path
    /// (e.g. `dns.rpz.enabled`); `reason` explains what to do instead.
    /// Default/inactive values stay parseable — only activation is rejected.
    Unsupported {
        path: String,
        reason: String,
    },
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
            DnsConfigError::Unsupported { path, reason } => {
                write!(f, "Unsupported DNS feature at {}: {}", path, reason)
            }
        }
    }
}

impl std::error::Error for DnsConfigError {}

impl From<DnsConfigError> for ConfigValidationError {
    fn from(err: DnsConfigError) -> Self {
        let message = err.to_string();
        let field = match err {
            DnsConfigError::InvalidPort(_) => "dns.port".to_string(),
            DnsConfigError::InvalidBindAddress(_) => "dns.bind_address".to_string(),
            DnsConfigError::InvalidRateLimit(_) => "dns.ratelimit".to_string(),
            DnsConfigError::InvalidRrl(_) => "dns.rrl".to_string(),
            DnsConfigError::InvalidSettings(_) => "dns.settings".to_string(),
            DnsConfigError::InvalidDnsSec(_) => "dns.dnssec".to_string(),
            DnsConfigError::InvalidMesh(_) => "dns.mesh".to_string(),
            DnsConfigError::InvalidAnycast(_) => "dns.anycast".to_string(),
            DnsConfigError::InvalidRecursive(_) => "dns.recursive".to_string(),
            DnsConfigError::Unsupported { path, .. } => path.clone(),
        };
        ConfigValidationError { field, message }
    }
}

/// Convenience constructor for Phase 45 fail-closed rejections.
///
/// `path` must be the typed serde config path (e.g. `dns.rpz.enabled`).
pub(crate) fn unsupported(path: &str, reason: &str) -> DnsConfigError {
    DnsConfigError::Unsupported {
        path: path.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod phase45_contract_tests {
    use super::*;

    fn valid_base() -> DnsConfig {
        DnsConfig::default()
    }

    fn expect_unsupported(cfg: &DnsConfig, path: &str) {
        match cfg.validate() {
            Err(DnsConfigError::Unsupported {
                path: actual,
                reason: _,
            }) => assert_eq!(actual, path, "wrong typed config path"),
            other => panic!("expected Unsupported({}), got {:?}", path, other),
        }
    }

    #[test]
    fn default_config_validates() {
        assert!(valid_base().validate().is_ok());
    }

    #[test]
    fn unsupported_error_carries_typed_path() {
        let err = unsupported("dns.rpz.enabled", "no engine");
        assert!(err.to_string().contains("dns.rpz.enabled"));
        let field_err: crate::validation::ConfigValidationError = err.into();
        assert_eq!(field_err.field, "dns.rpz.enabled");
    }

    #[test]
    fn rpz_activation_rejected() {
        let mut cfg = valid_base();
        cfg.rpz.enabled = true;
        expect_unsupported(&cfg, "dns.rpz.enabled");
    }

    #[test]
    fn prefetch_activation_rejected() {
        let mut cfg = valid_base();
        cfg.prefetch.enabled = true;
        expect_unsupported(&cfg, "dns.prefetch.enabled");
    }

    #[test]
    fn trust_anchor_activation_rejected() {
        let mut cfg = valid_base();
        cfg.trust_anchors.enabled = true;
        expect_unsupported(&cfg, "dns.trust_anchors.enabled");
    }

    #[test]
    fn anycast_activation_rejected() {
        let mut cfg = valid_base();
        cfg.anycast.enabled = true;
        cfg.anycast.bind_addresses = vec!["10.0.0.1".to_string()];
        expect_unsupported(&cfg, "dns.anycast.enabled");
    }

    #[test]
    fn dynamic_update_activation_rejected() {
        let mut cfg = valid_base();
        cfg.settings.dynamic_update.enabled = true;
        expect_unsupported(&cfg, "dns.settings.dynamic_update.enabled");
    }

    #[test]
    fn notify_activation_rejected() {
        let mut cfg = valid_base();
        cfg.settings.notify.enabled = true;
        expect_unsupported(&cfg, "dns.settings.notify.enabled");
    }

    #[test]
    fn allow_transfer_nonempty_rejected() {
        let mut cfg = valid_base();
        cfg.settings.allow_transfer = vec!["10.0.0.2".to_string()];
        expect_unsupported(&cfg, "dns.settings.allow_transfer");
    }

    #[test]
    fn transfer_knob_deviations_rejected() {
        let mut cfg = valid_base();
        cfg.settings.allow_wildcard_transfer = true;
        expect_unsupported(&cfg, "dns.settings.allow_wildcard_transfer");

        let mut cfg = valid_base();
        cfg.settings.wildcard_transfer_requires_tsig = false;
        expect_unsupported(&cfg, "dns.settings.wildcard_transfer_requires_tsig");

        let mut cfg = valid_base();
        cfg.settings.require_tsig = false;
        expect_unsupported(&cfg, "dns.settings.require_tsig");

        let mut cfg = valid_base();
        cfg.settings.ixfr_enabled = false;
        expect_unsupported(&cfg, "dns.settings.ixfr_enabled");

        let mut cfg = valid_base();
        cfg.settings.ixfr_history_size = 50;
        expect_unsupported(&cfg, "dns.settings.ixfr_history_size");

        let mut cfg = valid_base();
        cfg.settings.ixfr_fallback_to_axfr = false;
        expect_unsupported(&cfg, "dns.settings.ixfr_fallback_to_axfr");
    }

    #[test]
    fn padding_and_qname_activation_rejected() {
        let mut cfg = valid_base();
        cfg.settings.padding.enabled = true;
        expect_unsupported(&cfg, "dns.settings.padding.enabled");

        let mut cfg = valid_base();
        cfg.settings.qname_privacy.enabled = true;
        expect_unsupported(&cfg, "dns.settings.qname_privacy.enabled");
    }

    #[test]
    fn firewall_ignored_knobs_rejected_only_when_enabled() {
        // Disabled firewall: whole section inactive, stays parseable.
        let mut cfg = valid_base();
        cfg.firewall.rebinding_protection.enabled = true;
        assert!(cfg.validate().is_ok());

        // Enabled firewall with serde defaults except rebinding off: valid.
        let mut cfg = valid_base();
        cfg.firewall.enabled = true;
        cfg.firewall.max_rules = 1000;
        assert!(cfg.validate().is_ok());

        let mut cfg = valid_base();
        cfg.firewall.enabled = true;
        cfg.firewall.max_rules = 1000;
        cfg.firewall.rebinding_protection.enabled = true;
        expect_unsupported(&cfg, "dns.firewall.rebinding_protection.enabled");

        let mut cfg = valid_base();
        cfg.firewall.enabled = true;
        cfg.firewall.max_rules = 10;
        expect_unsupported(&cfg, "dns.firewall.max_rules");

        let mut cfg = valid_base();
        cfg.firewall.enabled = true;
        cfg.firewall.max_rules = 1000;
        cfg.firewall.default_action = FirewallAction::Block;
        expect_unsupported(&cfg, "dns.firewall.default_action");
    }

    #[test]
    fn encrypted_transport_bind_validation() {
        // Disabled transports accept empty binds (inactive).
        assert!(valid_base().validate().is_ok());

        let mut cfg = valid_base();
        cfg.dot.enabled = true;
        cfg.dot.port = 853;
        expect_unsupported(&cfg, "dns.dot.bind_address");

        let mut cfg = valid_base();
        cfg.dot.enabled = true;
        cfg.dot.bind_address = "not-an-ip".to_string();
        cfg.dot.port = 853;
        expect_unsupported(&cfg, "dns.dot.bind_address");

        let mut cfg = valid_base();
        cfg.dot.enabled = true;
        cfg.dot.bind_address = "127.0.0.1".to_string();
        cfg.dot.port = 0;
        expect_unsupported(&cfg, "dns.dot.port");

        let mut cfg = valid_base();
        cfg.doh.enabled = true;
        cfg.doh.bind_address = "::1".to_string();
        cfg.doh.port = 443;
        assert!(cfg.validate().is_ok());

        let mut cfg = valid_base();
        cfg.doq.enabled = true;
        cfg.doq.bind_address = "127.0.0.1".to_string();
        cfg.doq.port = 853;
        cfg.doq.max_concurrent_streams = 100;
        cfg.doq.idle_timeout_secs = 30;
        assert!(cfg.validate().is_ok());

        let mut cfg = valid_base();
        cfg.doq.enabled = true;
        cfg.doq.bind_address = "127.0.0.1".to_string();
        cfg.doq.port = 853;
        cfg.doq.max_concurrent_streams = 0;
        cfg.doq.idle_timeout_secs = 30;
        expect_unsupported(&cfg, "dns.doq.max_concurrent_streams");
    }

    #[test]
    fn recursive_scope_response_rejected() {
        let mut cfg = valid_base();
        cfg.recursive.enabled = true;
        cfg.recursive.ecs.include_scope_in_response = true;
        expect_unsupported(&cfg, "dns.recursive.ecs.include_scope_in_response");
    }

    #[test]
    fn recursive_nested_firewall_contract() {
        let mut cfg = valid_base();
        cfg.recursive.enabled = true;
        cfg.recursive.firewall.enabled = true;
        cfg.recursive.firewall.max_rules = 1000;
        cfg.recursive.firewall.rebinding_protection.enabled = true;
        match cfg.validate() {
            Err(DnsConfigError::Unsupported { path, .. }) => {
                assert_eq!(path, "dns.recursive.firewall.rebinding_protection.enabled")
            }
            other => panic!("expected nested firewall rejection, got {:?}", other),
        }
    }

    #[test]
    fn recursive_invalid_bind_rejected_before_startup() {
        let mut cfg = valid_base();
        cfg.recursive.enabled = true;
        cfg.recursive.bind_address = "not-an-ip".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn limits_zero_timeouts_rejected() {
        let mut cfg = valid_base();
        cfg.limits.max_tcp_idle_time_secs = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = valid_base();
        cfg.limits.max_tcp_query_time_secs = 0;
        assert!(cfg.validate().is_err());
    }
}

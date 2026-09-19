use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{unsupported, DnsConfigError};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsLimitsConfig {
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,

    #[serde(default = "default_max_concurrent_queries")]
    pub max_concurrent_queries: usize,

    #[serde(default = "default_max_query_size")]
    pub max_query_size: usize,

    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,

    #[serde(default = "default_max_records_per_response")]
    pub max_records_per_response: usize,

    #[serde(default = "default_max_tcp_idle_time")]
    pub max_tcp_idle_time_secs: u64,

    #[serde(default = "default_max_tcp_query_time")]
    pub max_tcp_query_time_secs: u64,

    #[serde(default = "default_udp_buffer_size")]
    pub udp_buffer_size: usize,

    #[serde(default)]
    pub enable_graceful_degradation: bool,
}

fn default_max_tcp_connections() -> usize {
    500
}

fn default_max_concurrent_queries() -> usize {
    2500
}

fn default_max_query_size() -> usize {
    65535
}

fn default_max_response_size() -> usize {
    65535
}

fn default_max_records_per_response() -> usize {
    1000
}

fn default_max_tcp_idle_time() -> u64 {
    300
}

fn default_max_tcp_query_time() -> u64 {
    30
}

fn default_udp_buffer_size() -> usize {
    65535
}

impl Default for DnsLimitsConfig {
    fn default() -> Self {
        Self {
            max_tcp_connections: default_max_tcp_connections(),
            max_concurrent_queries: default_max_concurrent_queries(),
            max_query_size: default_max_query_size(),
            max_response_size: default_max_response_size(),
            max_records_per_response: default_max_records_per_response(),
            max_tcp_idle_time_secs: default_max_tcp_idle_time(),
            max_tcp_query_time_secs: default_max_tcp_query_time(),
            udp_buffer_size: default_udp_buffer_size(),
            enable_graceful_degradation: false,
        }
    }
}

/// Minimum UDP buffer size: 512 bytes (minimum DNS message size per RFC 1035).
const UDP_BUFFER_SIZE_MIN: usize = 512;
/// Maximum UDP buffer size: 65535 bytes (UDP datagram max, matches EDNS0 maximum).
const UDP_BUFFER_SIZE_MAX: usize = 65535;

impl DnsLimitsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.udp_buffer_size < UDP_BUFFER_SIZE_MIN {
            return Err(format!(
                "udp_buffer_size {} is below minimum {}",
                self.udp_buffer_size, UDP_BUFFER_SIZE_MIN
            ));
        }
        if self.udp_buffer_size > UDP_BUFFER_SIZE_MAX {
            return Err(format!(
                "udp_buffer_size {} exceeds maximum {}",
                self.udp_buffer_size, UDP_BUFFER_SIZE_MAX
            ));
        }
        if self.max_tcp_connections == 0 {
            return Err("max_tcp_connections cannot be zero".to_string());
        }
        if self.max_concurrent_queries == 0 {
            return Err("max_concurrent_queries cannot be zero".to_string());
        }
        if self.max_tcp_idle_time_secs == 0 {
            return Err("max_tcp_idle_time_secs cannot be zero".to_string());
        }
        if self.max_tcp_query_time_secs == 0 {
            return Err("max_tcp_query_time_secs cannot be zero".to_string());
        }
        Ok(())
    }

    /// Return UDP buffer size clamped to sane bounds.
    pub fn effective_udp_buffer_size(&self) -> usize {
        self.udp_buffer_size
            .clamp(UDP_BUFFER_SIZE_MIN, UDP_BUFFER_SIZE_MAX)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsFirewallConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub default_action: FirewallAction,

    #[serde(default = "default_true")]
    pub block_internal_ips: bool,

    #[serde(default = "default_true")]
    pub block_zone_transfers: bool,

    #[serde(default = "default_firewall_max_rules")]
    pub max_rules: usize,

    #[serde(default)]
    pub rebinding_protection: RebindingProtectionConfig,
}

use super::defaults::default_true;

fn default_firewall_max_rules() -> usize {
    1000
}

impl DnsFirewallConfig {
    /// Phase 45 fail-closed contract. The firewall wires `block_internal_ips`
    /// and `block_zone_transfers` into `DnsFirewall` rules, but
    /// `default_action`, `max_rules`, and `rebinding_protection` have no
    /// runtime consumer (`evaluate_query` defaults to Allow when no rule
    /// matches; `check_rebinding_protection` is never called from the query
    /// path). Non-default values are rejected while the firewall is enabled;
    /// when the firewall itself is disabled the whole section is inactive
    /// and stays parseable.
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        self.validate_at("dns.firewall")
    }

    pub fn validate_at(&self, base: &str) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.default_action != FirewallAction::Allow {
            return Err(unsupported(
                &format!("{}.default_action", base),
                "only the default (allow) is enforced: unmatched queries are \
                 always allowed. Configurable default-action is deferred.",
            ));
        }
        if self.max_rules != default_firewall_max_rules() {
            return Err(unsupported(
                &format!("{}.max_rules", base),
                "rule-count limits are not enforced. Restore the default.",
            ));
        }
        if self.rebinding_protection.enabled {
            return Err(unsupported(
                &format!("{}.rebinding_protection.enabled", base),
                "DNS rebinding protection is not enforced in the query path \
                 (check_rebinding_protection is never called). Set explicitly \
                 to false until response-path enforcement lands.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct RebindingProtectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_min_rebinding_ttl")]
    pub min_ttl_for_internal: u32,

    #[serde(default)]
    pub allowed_internal_domains: Vec<String>,

    #[serde(default)]
    pub block_short_ttl_internal: bool,
}

fn default_min_rebinding_ttl() -> u32 {
    1800
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_validate_default_ok() {
        let limits = DnsLimitsConfig::default();
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn limits_validate_udp_buffer_too_small() {
        let limits = DnsLimitsConfig {
            udp_buffer_size: 100,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
        let err = limits.validate().unwrap_err();
        assert!(err.contains("below minimum"));
    }

    #[test]
    fn limits_validate_udp_buffer_too_large() {
        let limits = DnsLimitsConfig {
            udp_buffer_size: 100_000,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
        let err = limits.validate().unwrap_err();
        assert!(err.contains("exceeds maximum"));
    }

    #[test]
    fn limits_validate_max_tcp_connections_zero() {
        let limits = DnsLimitsConfig {
            max_tcp_connections: 0,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
        let err = limits.validate().unwrap_err();
        assert!(err.contains("cannot be zero"));
    }

    #[test]
    fn limits_validate_max_concurrent_queries_zero() {
        let limits = DnsLimitsConfig {
            max_concurrent_queries: 0,
            ..Default::default()
        };
        assert!(limits.validate().is_err());
        let err = limits.validate().unwrap_err();
        assert!(err.contains("cannot be zero"));
    }

    #[test]
    fn effective_udp_buffer_size_clamps() {
        let small = DnsLimitsConfig {
            udp_buffer_size: 100,
            ..Default::default()
        };
        assert_eq!(small.effective_udp_buffer_size(), 512);

        let large = DnsLimitsConfig {
            udp_buffer_size: 100_000,
            ..Default::default()
        };
        assert_eq!(large.effective_udp_buffer_size(), 65535);

        let normal = DnsLimitsConfig {
            udp_buffer_size: 4096,
            ..Default::default()
        };
        assert_eq!(normal.effective_udp_buffer_size(), 4096);
    }
}

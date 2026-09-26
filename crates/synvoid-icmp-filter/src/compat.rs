//! Exhaustive typed adapter: enforcement DTO -> canonical policy.
//!
//! Phase 85 replaces serde-shape conversion with this explicit boundary.
//! Every field is mapped or rejected with a typed error; no field is
//! defaulted merely because the other struct lacks it.
//!
//! The crate-level [`crate::config::IcmpFilterConfig`] remains as a
//! serialization DTO for backwards compatibility. [`crate::policy`] is the
//! single semantic owner.

use crate::{
    config::{Direction, FilterType, IcmpFilterConfig, InterfaceSpec},
    error::IcmpFilterError,
    policy::{
        BackendOptions, IcmpPolicy, IcmpRule, IcmpSelector, IcmpVerdict, InterfaceSelector,
        PolicyDirection, RateLimitPolicy, RequestedBackend,
    },
};

/// Typed adaptation failure. Each variant names the offending field/value so
/// operators can fix persisted config instead of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptError {
    InvalidTableName(String),
    InvalidInterface(String),
    InvalidRateLimit(String),
    Inexpressible(String),
}

impl std::fmt::Display for AdaptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTableName(s) => write!(f, "invalid table name: {s}"),
            Self::InvalidInterface(s) => write!(f, "invalid interface: {s}"),
            Self::InvalidRateLimit(s) => write!(f, "invalid rate limit: {s}"),
            Self::Inexpressible(s) => write!(f, "inexpressible policy: {s}"),
        }
    }
}

impl std::error::Error for AdaptError {}

impl From<AdaptError> for IcmpFilterError {
    fn from(e: AdaptError) -> Self {
        match &e {
            AdaptError::Inexpressible(_) => Self::Unsupported(e.to_string()),
            _ => Self::Adapt(e.to_string()),
        }
    }
}

/// Validate one interface name with the canonical operational rule:
/// 1-15 chars, alphanumeric plus `_`, `.`, `-` (Linux ifname reality).
pub fn validate_interface_name(name: &str) -> Result<(), AdaptError> {
    if name.is_empty() || name.len() > 15 {
        return Err(AdaptError::InvalidInterface(format!(
            "'{name}': must be 1-15 chars"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(AdaptError::InvalidInterface(format!(
            "'{name}': alphanumeric plus underscore/dot/hyphen only"
        )));
    }
    Ok(())
}

fn map_direction(d: Direction) -> PolicyDirection {
    match d {
        Direction::Both => PolicyDirection::Both,
        Direction::Inbound => PolicyDirection::Inbound,
        Direction::Outbound => PolicyDirection::Outbound,
    }
}

fn map_interfaces(spec: &InterfaceSpec) -> Result<InterfaceSelector, AdaptError> {
    match spec {
        InterfaceSpec::All => Ok(InterfaceSelector::All),
        InterfaceSpec::Specific(ifaces) => {
            for iface in ifaces {
                validate_interface_name(iface)?;
            }
            Ok(InterfaceSelector::Specific(ifaces.clone()))
        }
    }
}

fn map_verdict(action: crate::config::IcmpAction) -> IcmpVerdict {
    match action {
        crate::config::IcmpAction::Block => IcmpVerdict::Block,
        crate::config::IcmpAction::Allow => IcmpVerdict::Allow,
    }
}

fn map_requested(ft: FilterType) -> RequestedBackend {
    match ft {
        FilterType::Auto => RequestedBackend::Auto,
        FilterType::Nftables => RequestedBackend::Nftables,
        FilterType::Ebpf => RequestedBackend::Ebpf,
        FilterType::Pf => RequestedBackend::Pf,
        FilterType::Wfp => RequestedBackend::Wfp,
        FilterType::WindowsFirewall => RequestedBackend::WindowsFirewall,
    }
}

/// Adapt a crate DTO into `(policy, backend options)`.
///
/// - v4 rules map under family V4; v6 rules map under family V6. Legacy
///   numeric types are never reinterpreted across families.
/// - `rate_limit: None` or `Some(disabled)` maps to `None`. Enabled with
///   `packets_per_second == 0` is rejected (not silently disabled).
/// - Table names are validated, then canonicalized
///   (`synvoid_icmp` -> `synvoid-icmp`).
pub fn adapt_config_to_policy(
    cfg: &IcmpFilterConfig,
) -> Result<(IcmpPolicy, BackendOptions), AdaptError> {
    // Validate first so invalid input fails before any mapping.
    cfg.validate().map_err(AdaptError::Inexpressible)?;

    let mut rules = Vec::with_capacity(cfg.icmp_type_rules.len() + cfg.icmpv6_type_rules.len());
    for r in &cfg.icmp_type_rules {
        if let Some(d) = &r.description {
            if d.len() > 256 {
                return Err(AdaptError::Inexpressible(format!(
                    "v4 rule type {} description exceeds 256 chars",
                    r.icmp_type
                )));
            }
        }
        rules.push(IcmpRule {
            selector: IcmpSelector::raw_v4(r.icmp_type, r.icmp_code),
            verdict: map_verdict(r.action),
            description: r.description.clone(),
        });
    }
    for r in &cfg.icmpv6_type_rules {
        if let Some(d) = &r.description {
            if d.len() > 256 {
                return Err(AdaptError::Inexpressible(format!(
                    "v6 rule type {} description exceeds 256 chars",
                    r.icmp_type
                )));
            }
        }
        rules.push(IcmpRule {
            selector: IcmpSelector::raw_v6(r.icmp_type, r.icmp_code),
            verdict: map_verdict(r.action),
            description: r.description.clone(),
        });
    }

    let rate_limit = match &cfg.rate_limit {
        None => None,
        Some(rl) if !rl.enabled => None,
        Some(rl) => {
            if rl.packets_per_second == 0 {
                return Err(AdaptError::InvalidRateLimit(
                    "packets_per_second must be > 0 when enabled".to_string(),
                ));
            }
            // First contract: existing behavior is explicitly Global.
            Some(RateLimitPolicy::global(rl.packets_per_second, rl.burst))
        }
    };

    let table = BackendOptions::canonicalize_table_name(&cfg.table_name);
    if !crate::config::is_valid_identifier(&table) {
        return Err(AdaptError::InvalidTableName(table));
    }
    if let Some(p) = &cfg.ebpf_bytecode_path {
        if p.is_empty() {
            return Err(AdaptError::Inexpressible(
                "ebpf_bytecode_path must not be empty when present".to_string(),
            ));
        }
    }

    let policy = IcmpPolicy {
        direction: map_direction(cfg.direction),
        interfaces: map_interfaces(&cfg.interfaces)?,
        rules,
        exempt_ips: cfg.exempt_ips.clone(),
        rate_limit,
    };
    let backend = BackendOptions {
        table_name: table,
        ebpf_bytecode_path: cfg.ebpf_bytecode_path.clone(),
        requested: map_requested(cfg.filter_type),
    };
    Ok((policy, backend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IcmpAction, IcmpTypeRule};
    use std::net::IpAddr;

    #[test]
    fn exhaustive_v4_v6_separation() {
        let cfg = IcmpFilterConfig::new()
            .with_icmp_type_rules(vec![IcmpTypeRule::new(8, IcmpAction::Block)])
            .with_icmpv6_type_rules(vec![IcmpTypeRule::new(128, IcmpAction::Block)]);
        let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].selector.type_u8(), 8);
        assert_eq!(
            policy.rules[0].selector.family(),
            crate::policy::IcmpFamily::V4
        );
        assert_eq!(policy.rules[1].selector.type_u8(), 128);
        assert_eq!(
            policy.rules[1].selector.family(),
            crate::policy::IcmpFamily::V6
        );
    }

    #[test]
    fn invalid_interface_rejected() {
        let cfg = IcmpFilterConfig::new()
            .with_interfaces(InterfaceSpec::Specific(vec!["bad name!".to_string()]));
        assert!(adapt_config_to_policy(&cfg).is_err());
    }

    #[test]
    fn rate_limit_disabled_maps_to_none() {
        let cfg = IcmpFilterConfig::new();
        let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
        assert!(policy.rate_limit.is_none());
    }

    #[test]
    fn legacy_table_canonicalized() {
        let cfg = IcmpFilterConfig::new().with_table_name("synvoid_icmp");
        let (_, backend) = adapt_config_to_policy(&cfg).unwrap();
        assert_eq!(backend.table_name, "synvoid-icmp");
    }

    #[test]
    fn exempt_ips_preserved_exactly() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let cfg = IcmpFilterConfig::new().with_exempt_ips(vec![ip]);
        let (policy, _) = adapt_config_to_policy(&cfg).unwrap();
        assert_eq!(policy.exempt_ips, vec![ip]);
    }
}

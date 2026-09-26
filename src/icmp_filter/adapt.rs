//! Composition-boundary adapter: application config -> portable policy.
//!
//! Phase 85 replaces the admin JSON round-trip
//! (`serde_json::to_value`/`from_value` between two `IcmpFilterConfig`
//! types) with this exhaustive typed conversion. It lives at the composition
//! boundary (root `src/icmp_filter`), not inside the portable
//! `synvoid-icmp-filter` policy model, so the reusable contract stays free
//! of SynVoid config/admin types.

use std::net::IpAddr;
use synvoid_icmp_filter::policy::{
    BackendOptions, IcmpPolicy, IcmpRule, IcmpSelector, IcmpVerdict, InterfaceSelector,
    PolicyDirection, RateLimitPolicy, RequestedBackend,
};

/// Typed failure for application-config adaptation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigAdaptError {
    InvalidExemptIp(String),
    InvalidInterface(String),
    InvalidTableName(String),
    InvalidRateLimit(String),
    Inexpressible(String),
}

impl std::fmt::Display for ConfigAdaptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExemptIp(s) => write!(f, "invalid exempt IP: {s}"),
            Self::InvalidInterface(s) => write!(f, "invalid interface: {s}"),
            Self::InvalidTableName(s) => write!(f, "invalid table name: {s}"),
            Self::InvalidRateLimit(s) => write!(f, "invalid rate limit: {s}"),
            Self::Inexpressible(s) => write!(f, "inexpressible configuration: {s}"),
        }
    }
}

impl std::error::Error for ConfigAdaptError {}

fn validate_interface_name(name: &str) -> Result<(), ConfigAdaptError> {
    if name.is_empty() || name.len() > 15 {
        return Err(ConfigAdaptError::InvalidInterface(format!(
            "'{name}': must be 1-15 chars"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(ConfigAdaptError::InvalidInterface(format!(
            "'{name}': alphanumeric plus underscore/dot/hyphen only"
        )));
    }
    Ok(())
}

fn is_valid_table(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Adapt application config to `(portable policy, backend options)`.
///
/// Mapping contract (documented, no silent reinterpretation):
/// - `icmp_type_rules` map under family V4; `icmpv6_type_rules` map under
///   family V6. Legacy configs without a v6 list yield zero v6 rules.
/// - Exempt addresses parse exactly once here; the first invalid address
///   aborts with [`ConfigAdaptError::InvalidExemptIp`].
/// - Rate-limit `enabled=false` (or absent semantics) maps to `None`.
///   `scope` must be the explicit `global` spelling the config DTO carries;
///   any other scope value is a hard error (no emulation).
/// - Backend knobs (`table_name`, eBPF path, requested backend) validate
///   separately from protocol policy. `synvoid_icmp` normalizes to the
///   canonical `synvoid-icmp`.
pub fn adapt_app_config_to_policy(
    cfg: &synvoid_config::icmp_filter::IcmpFilterConfig,
) -> Result<(IcmpPolicy, BackendOptions), ConfigAdaptError> {
    if !is_valid_table(&cfg.table_name) {
        return Err(ConfigAdaptError::InvalidTableName(cfg.table_name.clone()));
    }

    let interfaces = match &cfg.interfaces {
        synvoid_config::icmp_filter::InterfaceSpec::All => InterfaceSelector::All,
        synvoid_config::icmp_filter::InterfaceSpec::Specific(ifaces) => {
            for iface in ifaces {
                validate_interface_name(iface)?;
            }
            InterfaceSelector::Specific(ifaces.clone())
        }
    };

    // Parse exempt addresses exactly once.
    let mut exempt_ips = Vec::with_capacity(cfg.exempt_ips.len());
    for raw in &cfg.exempt_ips {
        match raw.parse::<IpAddr>() {
            Ok(ip) => exempt_ips.push(ip),
            Err(_) => return Err(ConfigAdaptError::InvalidExemptIp(raw.clone())),
        }
    }

    let direction = match cfg.direction {
        synvoid_config::icmp_filter::Direction::Both => PolicyDirection::Both,
        synvoid_config::icmp_filter::Direction::Inbound => PolicyDirection::Inbound,
        synvoid_config::icmp_filter::Direction::Outbound => PolicyDirection::Outbound,
    };

    let mut rules = Vec::with_capacity(cfg.icmp_type_rules.len() + cfg.icmpv6_type_rules.len());
    for r in &cfg.icmp_type_rules {
        if let Some(d) = &r.description {
            if d.len() > 256 {
                return Err(ConfigAdaptError::Inexpressible(format!(
                    "v4 rule type {} description exceeds 256 chars",
                    r.icmp_type
                )));
            }
        }
        rules.push(IcmpRule {
            selector: IcmpSelector::raw_v4(r.icmp_type, r.icmp_code),
            verdict: match r.action {
                synvoid_config::icmp_filter::IcmpAction::Block => IcmpVerdict::Block,
                synvoid_config::icmp_filter::IcmpAction::Allow => IcmpVerdict::Allow,
            },
            description: r.description.clone(),
        });
    }
    for r in &cfg.icmpv6_type_rules {
        if let Some(d) = &r.description {
            if d.len() > 256 {
                return Err(ConfigAdaptError::Inexpressible(format!(
                    "v6 rule type {} description exceeds 256 chars",
                    r.icmp_type
                )));
            }
        }
        rules.push(IcmpRule {
            selector: IcmpSelector::raw_v6(r.icmp_type, r.icmp_code),
            verdict: match r.action {
                synvoid_config::icmp_filter::IcmpAction::Block => IcmpVerdict::Block,
                synvoid_config::icmp_filter::IcmpAction::Allow => IcmpVerdict::Allow,
            },
            description: r.description.clone(),
        });
    }

    // Rate-limit semantics are explicit: the config DTO carries scope
    // (currently only global). Disabled maps to None.
    let rate_limit = if !cfg.rate_limit.enabled {
        None
    } else {
        if cfg.rate_limit.packets_per_second == 0 {
            return Err(ConfigAdaptError::InvalidRateLimit(
                "packets_per_second must be > 0 when enabled".to_string(),
            ));
        }
        // The DTO scope enum has one variant today; match exhaustively so a
        // future variant fails closed here instead of defaulting silently.
        match cfg.rate_limit.scope {
            synvoid_config::icmp_filter::RateLimitScope::Global => Some(RateLimitPolicy::global(
                cfg.rate_limit.packets_per_second,
                cfg.rate_limit.burst,
            )),
        }
    };

    if let Some(p) = &cfg.custom_ebpf_bytecode_path {
        if p.is_empty() {
            return Err(ConfigAdaptError::Inexpressible(
                "ebpf bytecode path must not be empty when present".to_string(),
            ));
        }
    }

    let policy = IcmpPolicy {
        direction,
        interfaces,
        rules,
        exempt_ips,
        rate_limit,
    };
    let backend = BackendOptions {
        table_name: BackendOptions::canonicalize_table_name(&cfg.table_name),
        ebpf_bytecode_path: cfg.custom_ebpf_bytecode_path.clone(),
        requested: match cfg.filter_type {
            synvoid_config::icmp_filter::FilterType::Auto => RequestedBackend::Auto,
            synvoid_config::icmp_filter::FilterType::Nftables => RequestedBackend::Nftables,
            synvoid_config::icmp_filter::FilterType::Ebpf => RequestedBackend::Ebpf,
            synvoid_config::icmp_filter::FilterType::Pf => RequestedBackend::Pf,
            synvoid_config::icmp_filter::FilterType::Wfp => RequestedBackend::Wfp,
            synvoid_config::icmp_filter::FilterType::WindowsFirewall => {
                RequestedBackend::WindowsFirewall
            }
        },
    };
    Ok((policy, backend))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_v4_list_stays_v4() {
        let mut cfg = synvoid_config::icmp_filter::IcmpFilterConfig::new();
        cfg.icmp_type_rules
            .push(synvoid_config::icmp_filter::IcmpTypeRule::new(
                8,
                synvoid_config::icmp_filter::IcmpAction::Block,
            ));
        let (policy, _) = adapt_app_config_to_policy(&cfg).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(
            policy.rules[0].selector.family(),
            synvoid_icmp_filter::policy::IcmpFamily::V4
        );
        // Legacy v4 numeric 8 is NOT reinterpreted as v6.
        assert!(policy
            .rules_for_family(synvoid_icmp_filter::policy::IcmpFamily::V6)
            .next()
            .is_none());
    }

    #[test]
    fn invalid_exempt_ip_rejected() {
        let mut cfg = synvoid_config::icmp_filter::IcmpFilterConfig::new();
        cfg.exempt_ips.push("not-an-ip".to_string());
        let err = adapt_app_config_to_policy(&cfg).unwrap_err();
        assert!(matches!(err, ConfigAdaptError::InvalidExemptIp(_)));
    }
}

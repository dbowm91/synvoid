//! RFC-aware ICMP policy validation (Phase 85, Workstream E).
//!
//! Informed by RFC 4890 (ICMPv6 firewalling) and RFC 8201 (path MTU
//! discovery). Validation never rewrites user rules; it returns structured
//! findings. Strict mode upgrades critical hazards to errors. Explicit
//! acknowledgement opts out per hazard — there is no silent downgrade.

use crate::policy::{IcmpFamily, IcmpPolicy, IcmpRule, IcmpV6Type, IcmpVerdict};
use serde::{Deserialize, Serialize};

/// Role the filtered host plays. Router/transit semantics differ from a
/// plain host (e.g. ND handling), so the caller must state the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationRole {
    Host,
    RouterTransit,
}

/// Advisory vs blocking finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Warning,
    Error,
}

/// One structured validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFinding {
    pub severity: FindingSeverity,
    /// Stable machine-readable code, e.g. `icmpv6_ptb_blocked`.
    pub code: &'static str,
    pub message: String,
    /// Index into `IcmpPolicy.rules`, when the finding names a rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
}

/// Explicit operator acknowledgement for intentionally dangerous policy.
/// Each hazard must be opted into individually; there is no blanket override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ValidationOverride {
    #[serde(default)]
    pub allow_block_packet_too_big: bool,
    #[serde(default)]
    pub allow_block_neighbor_discovery: bool,
}

/// Validate a policy without mutating it.
///
/// `strict` upgrades critical PMTUD/ND hazards from warning to error.
/// The default SynVoid migration path uses non-strict (preserve behavior,
/// surface diagnostics); operators who want a hard gate opt into strict.
///
/// ```
/// use synvoid_icmp_filter::policy::{IcmpPolicy, IcmpRule, IcmpSelector, IcmpV6Type, IcmpVerdict};
/// use synvoid_icmp_filter::validation::{
///     validate_policy, ValidationOverride, ValidationRole,
/// };
///
/// let mut policy = IcmpPolicy::default();
/// policy.rules.push(IcmpRule::new(
///     IcmpSelector::V6 { icmp_type: IcmpV6Type::PacketTooBig, code: None },
///     IcmpVerdict::Block,
/// ));
/// let findings = validate_policy(&policy, ValidationRole::Host, false, ValidationOverride::default());
/// assert!(findings.iter().any(|f| f.code == "icmpv6_ptb_blocked"));
/// ```
pub fn validate_policy(
    policy: &IcmpPolicy,
    role: ValidationRole,
    strict: bool,
    overrides: ValidationOverride,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    let critical = |strict: bool| {
        if strict {
            FindingSeverity::Error
        } else {
            FindingSeverity::Warning
        }
    };

    for (idx, rule) in policy.rules.iter().enumerate() {
        if rule.verdict != IcmpVerdict::Block {
            continue;
        }
        match rule.selector {
            crate::policy::IcmpSelector::V6 { icmp_type, .. } => {
                check_v6_rule(
                    idx,
                    rule,
                    icmp_type,
                    role,
                    strict,
                    overrides,
                    critical,
                    &mut findings,
                );
            }
            crate::policy::IcmpSelector::V4 { .. } => {
                // IPv4 ping filtering is the ordinary case; no RFC-critical
                // hazard attaches to blocking echo alone. Reserved for
                // future v4-specific advisories.
            }
        }
    }

    findings
}

#[allow(clippy::too_many_arguments)]
fn check_v6_rule(
    idx: usize,
    rule: &IcmpRule,
    icmp_type: IcmpV6Type,
    role: ValidationRole,
    strict: bool,
    overrides: ValidationOverride,
    critical: impl Fn(bool) -> FindingSeverity,
    findings: &mut Vec<PolicyFinding>,
) {
    let blocks_ptb = icmp_type == IcmpV6Type::PacketTooBig;
    if blocks_ptb && !overrides.allow_block_packet_too_big {
        findings.push(PolicyFinding {
            severity: critical(strict),
            code: "icmpv6_ptb_blocked",
            message: format!(
                "rule {idx} blocks ICMPv6 Packet Too Big (type 2); \
                 this breaks Path MTU Discovery per RFC 8201 and can black-hole \
                 IPv6 connections. Override explicitly with \
                 allow_block_packet_too_big if intentional.{}",
                rule_description_suffix(rule),
            ),
            rule_index: Some(idx),
        });
    }

    let is_nd = matches!(
        icmp_type,
        IcmpV6Type::RouterSolicitation
            | IcmpV6Type::RouterAdvertisement
            | IcmpV6Type::NeighborSolicitation
            | IcmpV6Type::NeighborAdvertisement
    );
    if is_nd && !overrides.allow_block_neighbor_discovery {
        let sev = match (role, strict) {
            // ND is essential on a host; blocking it is critical.
            (ValidationRole::Host, _) => critical(strict),
            // Transit may filter ND deliberately, but it deserves a warning.
            (ValidationRole::RouterTransit, _) => FindingSeverity::Warning,
        };
        findings.push(PolicyFinding {
            severity: sev,
            code: "icmpv6_nd_blocked",
            message: format!(
                "rule {idx} blocks ICMPv6 {} (type {}), required for IPv6 \
                 neighbor discovery per RFC 4890 (role: {:?}). Override \
                 explicitly with allow_block_neighbor_discovery if intentional.{}",
                icmp_type.name(),
                icmp_type.as_u8(),
                role,
                rule_description_suffix(rule),
            ),
            rule_index: Some(idx),
        });
    }

    // Blocking Destination Unreachable / Time Exceeded / Parameter Problem
    // degrades diagnostics but is not a correctness hazard on its own; keep
    // it advisory and out of strict-error scope.
    if matches!(
        icmp_type,
        IcmpV6Type::DestinationUnreachable
            | IcmpV6Type::TimeExceeded
            | IcmpV6Type::ParameterProblem
    ) {
        findings.push(PolicyFinding {
            severity: FindingSeverity::Warning,
            code: "icmpv6_diagnostic_blocked",
            message: format!(
                "rule {idx} blocks ICMPv6 {} (type {}); error reporting and \
                 diagnostics will degrade (RFC 4890 §4.3 advisory).{}",
                icmp_type.name(),
                icmp_type.as_u8(),
                rule_description_suffix(rule),
            ),
            rule_index: Some(idx),
        });
    }
}

fn rule_description_suffix(rule: &IcmpRule) -> String {
    match &rule.description {
        Some(d) => format!(" Description: {d}"),
        None => String::new(),
    }
}

/// Convenience: does this policy block ICMPv6 Packet Too Big?
pub fn blocks_packet_too_big(policy: &IcmpPolicy) -> bool {
    policy
        .rules_for_family(IcmpFamily::V6)
        .any(|r| r.verdict == IcmpVerdict::Block && r.selector.type_u8() == 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{IcmpPolicy, IcmpRule, IcmpSelector, IcmpV6Type, IcmpVerdict};

    fn block_v6(t: IcmpV6Type) -> IcmpRule {
        IcmpRule::new(
            IcmpSelector::V6 {
                icmp_type: t,
                code: None,
            },
            IcmpVerdict::Block,
        )
    }

    #[test]
    fn ptb_block_warns_by_default_errors_when_strict() {
        let mut policy = IcmpPolicy::default();
        policy.rules.push(block_v6(IcmpV6Type::PacketTooBig));
        let warn = validate_policy(
            &policy,
            ValidationRole::Host,
            false,
            ValidationOverride::default(),
        );
        assert!(warn.iter().any(|f| f.code == "icmpv6_ptb_blocked"));
        assert!(warn.iter().all(|f| f.severity == FindingSeverity::Warning));
        let strict = validate_policy(
            &policy,
            ValidationRole::Host,
            true,
            ValidationOverride::default(),
        );
        assert!(strict
            .iter()
            .any(|f| f.code == "icmpv6_ptb_blocked" && f.severity == FindingSeverity::Error));
    }

    #[test]
    fn ptb_override_silences_finding() {
        let mut policy = IcmpPolicy::default();
        policy.rules.push(block_v6(IcmpV6Type::PacketTooBig));
        let out = validate_policy(
            &policy,
            ValidationRole::Host,
            true,
            ValidationOverride {
                allow_block_packet_too_big: true,
                ..Default::default()
            },
        );
        assert!(!out.iter().any(|f| f.code == "icmpv6_ptb_blocked"));
    }

    #[test]
    fn nd_block_flagged_with_role() {
        let mut policy = IcmpPolicy::default();
        policy
            .rules
            .push(block_v6(IcmpV6Type::NeighborSolicitation));
        let host = validate_policy(
            &policy,
            ValidationRole::Host,
            false,
            ValidationOverride::default(),
        );
        assert!(host.iter().any(|f| f.code == "icmpv6_nd_blocked"));
        let transit = validate_policy(
            &policy,
            ValidationRole::RouterTransit,
            false,
            ValidationOverride::default(),
        );
        assert!(transit.iter().any(|f| f.code == "icmpv6_nd_blocked"));
    }

    #[test]
    fn validator_does_not_rewrite_rules() {
        let mut policy = IcmpPolicy::default();
        policy.rules.push(block_v6(IcmpV6Type::PacketTooBig));
        let before = policy.clone();
        let _ = validate_policy(
            &policy,
            ValidationRole::Host,
            true,
            ValidationOverride::default(),
        );
        assert_eq!(policy, before);
    }
}

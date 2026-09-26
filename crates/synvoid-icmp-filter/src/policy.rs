//! Portable ICMP enforcement policy (Phase 85 canonical semantic owner).
//!
//! This module owns enforcement semantics. It is intentionally independent of:
//! TOML/OpenAPI schema concerns, admin DTOs, metrics names, tracing text,
//! config file paths, SynVoid process/runtime handles, and eBPF artifact
//! discovery policy. Backend knobs (table identity, eBPF object path) live in
//! [`BackendOptions`], not in the protocol policy value.
//!
//! Serialization here uses neutral lowercase `serde` only so scope/policy
//! values round-trip deterministically. It must not gain `schemars`/`utoipa`
//! or SynVoid config/admin dependencies.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Canonical internal nftables/PF table identity.
///
/// Legacy persisted configs may carry `"synvoid_icmp"` (underscore). Adapters
/// normalize that spelling to this canonical value; all other valid names
/// pass through unchanged.
pub const CANONICAL_TABLE_NAME: &str = "synvoid-icmp";
/// Legacy underscore spelling accepted on read for backwards compatibility.
pub const LEGACY_TABLE_NAME_UNDERSCORE: &str = "synvoid_icmp";

/// Address family. Numeric ICMP type `N` is meaningless without this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IcmpFamily {
    V4,
    V6,
}

/// Terminal verdict for a matched rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IcmpVerdict {
    Block,
    Allow,
}

/// Packet direction the policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDirection {
    #[default]
    Both,
    Inbound,
    Outbound,
}

/// Interface selection. Names are validated by adapters (1-15 chars,
/// alphanumeric plus `_`, `.`, `-`); resolution to indices happens in
/// backends, never here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum InterfaceSelector {
    #[default]
    All,
    Specific(Vec<String>),
}

impl InterfaceSelector {
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// Typed ICMPv4 message vocabulary with an explicit raw escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpV4Type {
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    Redirect,
    EchoRequest,
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    InformationRequest,
    InformationReply,
    AddressMaskRequest,
    AddressMaskReply,
    /// Unknown/reserved type explicitly allowed by the operator.
    #[serde(untagged)]
    Raw(u8),
}

impl IcmpV4Type {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::EchoReply => 0,
            Self::DestinationUnreachable => 3,
            Self::SourceQuench => 4,
            Self::Redirect => 5,
            Self::EchoRequest => 8,
            Self::RouterAdvertisement => 9,
            Self::RouterSolicitation => 10,
            Self::TimeExceeded => 11,
            Self::ParameterProblem => 12,
            Self::TimestampRequest => 13,
            Self::TimestampReply => 14,
            Self::InformationRequest => 15,
            Self::InformationReply => 16,
            Self::AddressMaskRequest => 17,
            Self::AddressMaskReply => 18,
            Self::Raw(v) => v,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable,
            4 => Self::SourceQuench,
            5 => Self::Redirect,
            8 => Self::EchoRequest,
            9 => Self::RouterAdvertisement,
            10 => Self::RouterSolicitation,
            11 => Self::TimeExceeded,
            12 => Self::ParameterProblem,
            13 => Self::TimestampRequest,
            14 => Self::TimestampReply,
            15 => Self::InformationRequest,
            16 => Self::InformationReply,
            17 => Self::AddressMaskRequest,
            18 => Self::AddressMaskReply,
            other => Self::Raw(other),
        }
    }

    /// Human-readable name for diagnostics (never a wire value).
    pub fn name(self) -> &'static str {
        match self {
            Self::EchoReply => "echo_reply",
            Self::DestinationUnreachable => "destination_unreachable",
            Self::SourceQuench => "source_quench",
            Self::Redirect => "redirect",
            Self::EchoRequest => "echo_request",
            Self::RouterAdvertisement => "router_advertisement",
            Self::RouterSolicitation => "router_solicitation",
            Self::TimeExceeded => "time_exceeded",
            Self::ParameterProblem => "parameter_problem",
            Self::TimestampRequest => "timestamp_request",
            Self::TimestampReply => "timestamp_reply",
            Self::InformationRequest => "information_request",
            Self::InformationReply => "information_reply",
            Self::AddressMaskRequest => "address_mask_request",
            Self::AddressMaskReply => "address_mask_reply",
            Self::Raw(_) => "raw",
        }
    }

    pub fn is_named(self) -> bool {
        !matches!(self, Self::Raw(_))
    }
}

/// Typed ICMPv6 message vocabulary with an explicit raw escape hatch.
///
/// Covers the current SynVoid rules plus the operationally significant
/// neighbor-discovery / path-MTU messages called out in the Phase 85 plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpV6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    Redirect,
    /// Unknown/reserved type explicitly allowed by the operator.
    #[serde(untagged)]
    Raw(u8),
}

impl IcmpV6Type {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::DestinationUnreachable => 1,
            Self::PacketTooBig => 2,
            Self::TimeExceeded => 3,
            Self::ParameterProblem => 4,
            Self::EchoRequest => 128,
            Self::EchoReply => 129,
            Self::RouterSolicitation => 133,
            Self::RouterAdvertisement => 134,
            Self::NeighborSolicitation => 135,
            Self::NeighborAdvertisement => 136,
            Self::Redirect => 137,
            Self::Raw(v) => v,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::DestinationUnreachable,
            2 => Self::PacketTooBig,
            3 => Self::TimeExceeded,
            4 => Self::ParameterProblem,
            128 => Self::EchoRequest,
            129 => Self::EchoReply,
            133 => Self::RouterSolicitation,
            134 => Self::RouterAdvertisement,
            135 => Self::NeighborSolicitation,
            136 => Self::NeighborAdvertisement,
            137 => Self::Redirect,
            other => Self::Raw(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::DestinationUnreachable => "destination_unreachable",
            Self::PacketTooBig => "packet_too_big",
            Self::TimeExceeded => "time_exceeded",
            Self::ParameterProblem => "parameter_problem",
            Self::EchoRequest => "echo_request",
            Self::EchoReply => "echo_reply",
            Self::RouterSolicitation => "router_solicitation",
            Self::RouterAdvertisement => "router_advertisement",
            Self::NeighborSolicitation => "neighbor_solicitation",
            Self::NeighborAdvertisement => "neighbor_advertisement",
            Self::Redirect => "redirect",
            Self::Raw(_) => "raw",
        }
    }

    pub fn is_named(self) -> bool {
        !matches!(self, Self::Raw(_))
    }
}

/// Family-bound type/code selector. The family is load-bearing: numeric type
/// `N` never flows without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "lowercase")]
pub enum IcmpSelector {
    V4 {
        #[serde(rename = "type")]
        icmp_type: IcmpV4Type,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<u8>,
    },
    V6 {
        #[serde(rename = "type")]
        icmp_type: IcmpV6Type,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<u8>,
    },
}

impl IcmpSelector {
    pub fn family(self) -> IcmpFamily {
        match self {
            Self::V4 { .. } => IcmpFamily::V4,
            Self::V6 { .. } => IcmpFamily::V6,
        }
    }

    pub fn type_u8(self) -> u8 {
        match self {
            Self::V4 { icmp_type, .. } => icmp_type.as_u8(),
            Self::V6 { icmp_type, .. } => icmp_type.as_u8(),
        }
    }

    pub fn code(self) -> Option<u8> {
        match self {
            Self::V4 { code, .. } | Self::V6 { code, .. } => code,
        }
    }

    pub fn raw_v4(icmp_type: u8, code: Option<u8>) -> Self {
        Self::V4 {
            icmp_type: IcmpV4Type::from_u8(icmp_type),
            code,
        }
    }

    pub fn raw_v6(icmp_type: u8, code: Option<u8>) -> Self {
        Self::V6 {
            icmp_type: IcmpV6Type::from_u8(icmp_type),
            code,
        }
    }
}

/// One portable policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpRule {
    #[serde(rename = "match")]
    pub selector: IcmpSelector,
    pub verdict: IcmpVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl IcmpRule {
    pub fn new(selector: IcmpSelector, verdict: IcmpVerdict) -> Self {
        Self {
            selector,
            verdict,
            description: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Explicit rate-limit scope. The initial contract supports only the
/// semantics current backends truthfully implement (`Global`). Richer scopes
/// must be capability-gated by later phases, never emulated silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitScope {
    #[default]
    Global,
}

/// Rate-limit policy with defined scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub packets_per_second: u32,
    pub burst: u32,
    #[serde(default)]
    pub scope: RateLimitScope,
    /// When true, a backend that cannot express the exact scope must fail
    /// rather than install a weaker approximation. Defaults to strict.
    #[serde(default = "default_strict")]
    pub strict: bool,
}

fn default_strict() -> bool {
    true
}

impl RateLimitPolicy {
    pub fn global(packets_per_second: u32, burst: u32) -> Self {
        Self {
            packets_per_second,
            burst,
            scope: RateLimitScope::Global,
            strict: true,
        }
    }
}

/// Portable enforcement policy: the single semantic owner for Phase 85.
///
/// ```
/// use synvoid_icmp_filter::policy::{
///     IcmpFamily, IcmpPolicy, IcmpRule, IcmpSelector, IcmpVerdict,
/// };
///
/// let mut policy = IcmpPolicy::default();
/// // Numeric type 8 is ambiguous without a family; the selector binds it.
/// policy.rules.push(IcmpRule::new(
///     IcmpSelector::raw_v4(8, None),
///     IcmpVerdict::Block,
/// ));
/// assert_eq!(policy.rules_for_family(IcmpFamily::V4).count(), 1);
/// assert_eq!(policy.rules_for_family(IcmpFamily::V6).count(), 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpPolicy {
    #[serde(default)]
    pub direction: PolicyDirection,
    #[serde(default)]
    pub interfaces: InterfaceSelector,
    #[serde(default)]
    pub rules: Vec<IcmpRule>,
    #[serde(default)]
    pub exempt_ips: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitPolicy>,
}

impl Default for IcmpPolicy {
    fn default() -> Self {
        Self {
            direction: PolicyDirection::Both,
            interfaces: InterfaceSelector::All,
            rules: Vec::new(),
            exempt_ips: Vec::new(),
            rate_limit: None,
        }
    }
}

impl IcmpPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rules_for_family(&self, family: IcmpFamily) -> impl Iterator<Item = &IcmpRule> {
        self.rules
            .iter()
            .filter(move |r| r.selector.family() == family)
    }

    /// Capability requirements a backend must satisfy to express this policy
    /// exactly. Phase 86 evaluates backend capability against this, not
    /// against a single static boolean.
    pub fn requirements(&self) -> PolicyRequirements {
        PolicyRequirements {
            needs_rate_limit_global: self.rate_limit.is_some(),
            needs_interface_filtering: !self.interfaces.is_all(),
            needs_type_matching: !self.rules.is_empty(),
            needs_code_matching: self.rules.iter().any(|r| r.selector.code().is_some()),
            needs_v6: self.rules_for_family(IcmpFamily::V6).next().is_some(),
        }
    }
}

/// Backend-neutral requirement summary derived from a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRequirements {
    pub needs_rate_limit_global: bool,
    pub needs_interface_filtering: bool,
    pub needs_type_matching: bool,
    pub needs_code_matching: bool,
    pub needs_v6: bool,
}

/// Requested backend. `Auto` may probe and fall back in a documented order;
/// every other variant is strict (Phase 86 enforces no silent fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RequestedBackend {
    #[default]
    Auto,
    Nftables,
    Ebpf,
    Pf,
    Wfp,
    WindowsFirewall,
}

/// Backend-specific knobs. Deliberately outside the protocol policy value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendOptions {
    #[serde(default = "canonical_table_name")]
    pub table_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ebpf_bytecode_path: Option<String>,
    #[serde(default)]
    pub requested: RequestedBackend,
}

fn canonical_table_name() -> String {
    CANONICAL_TABLE_NAME.to_string()
}

impl Default for BackendOptions {
    fn default() -> Self {
        Self {
            table_name: CANONICAL_TABLE_NAME.to_string(),
            ebpf_bytecode_path: None,
            requested: RequestedBackend::Auto,
        }
    }
}

impl BackendOptions {
    /// Normalize a persisted table name to the canonical representation.
    /// The legacy underscore spelling maps to the canonical hyphen spelling;
    /// every other value passes through for identifier validation downstream.
    pub fn canonicalize_table_name(name: &str) -> String {
        if name == LEGACY_TABLE_NAME_UNDERSCORE {
            CANONICAL_TABLE_NAME.to_string()
        } else {
            name.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_separation_type_8_differs() {
        // Numeric type 8 without a family would be ambiguous (v4 echo vs
        // unassigned v6); the selector keeps them distinct.
        let v4 = IcmpSelector::raw_v4(8, None);
        let v6 = IcmpSelector::raw_v6(8, None);
        assert_eq!(v4.family(), IcmpFamily::V4);
        assert_eq!(v6.family(), IcmpFamily::V6);
        assert_ne!(v4, v6);
        assert_eq!(v4.type_u8(), 8);
        assert_eq!(v6.type_u8(), 8);
    }

    #[test]
    fn named_and_raw_round_trip() {
        let named = IcmpSelector::V6 {
            icmp_type: IcmpV6Type::PacketTooBig,
            code: None,
        };
        assert_eq!(named.type_u8(), 2);
        let raw = IcmpSelector::raw_v6(200, Some(3));
        assert!(matches!(
            raw,
            IcmpSelector::V6 {
                icmp_type: IcmpV6Type::Raw(200),
                code: Some(3)
            }
        ));
        // Unknown values stay representable, not rejected.
        let json = serde_json::to_string(&raw).unwrap();
        let back: IcmpSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(raw, back);
    }

    #[test]
    fn rate_limit_scope_serializes_global() {
        let policy = RateLimitPolicy::global(10, 20);
        assert_eq!(policy.scope, RateLimitScope::Global);
        assert!(policy.strict);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("global"));
        let back: RateLimitPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn canonicalize_legacy_table_name() {
        assert_eq!(
            BackendOptions::canonicalize_table_name("synvoid_icmp"),
            "synvoid-icmp"
        );
        assert_eq!(BackendOptions::canonicalize_table_name("custom"), "custom");
    }
}

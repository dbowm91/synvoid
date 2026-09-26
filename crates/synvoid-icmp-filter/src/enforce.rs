//! Compile-before-mutate enforcement boundary (Phase 87).
//!
//! Invariant: a policy update must not destroy known-working enforcement
//! merely because the replacement later fails to compile, install, or
//! verify. Every update therefore compiles completely before any kernel
//! mutation, installs through backend transaction/staging semantics, and
//! verifies live state before the new generation is recorded as applied.
//!
//! This module is free of `metrics`/`tracing`/admin/config types: the core
//! contract returns structured receipts and reports. Lifecycle metrics live
//! in `crate::metrics` and are caller-owned.

use crate::{
    policy::{BackendOptions, IcmpPolicy, PolicyRequirements},
    traits::{check_policy_compatibility, FilterBackend},
};
use serde::{Deserialize, Serialize};

/// FNV-1a 64 over the canonical policy JSON. Field order is struct order
/// (serde), so equal policies hash equally across processes.
pub fn policy_fingerprint(policy: &IcmpPolicy) -> u64 {
    let json = serde_json::to_string(policy).unwrap_or_default();
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in json.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn fingerprint_hex(fingerprint: u64) -> String {
    format!("{fingerprint:016x}")
}

/// Concrete install plan produced without touching kernel state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub backend: FilterBackend,
    pub fingerprint: u64,
    /// Backend-scoped ownership identity (table, anchor path, provider tag).
    /// Disable/update must not touch objects outside this identity.
    pub ownership_tag: String,
    /// Human-readable concrete objects to install (for receipts/debugging).
    pub operations_summary: String,
    /// Expected rule cardinality for backends whose readback is
    /// presence-plus-count (PF). `None` where exact readback applies.
    pub expected_rule_count: Option<usize>,
    /// Non-semantic warnings (never change what gets installed).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Compile result: either an exact plan or explicit unsupported requirements.
/// There is no degraded-semantics default; weakening requires a future
/// explicit caller opt-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCompileResult {
    Exact(EnforcementPlan),
    Unsupported {
        requirements: PolicyRequirements,
        reasons: Vec<String>,
    },
}

/// Pure compilation: policy + backend capabilities + backend options.
/// Performs zero kernel mutation.
///
/// ```
/// use synvoid_icmp_filter::enforce::{compile_policy, PolicyCompileResult};
/// use synvoid_icmp_filter::policy::{BackendOptions, IcmpPolicy, IcmpRule, IcmpSelector, IcmpVerdict};
/// use synvoid_icmp_filter::traits::FilterBackend;
///
/// let mut policy = IcmpPolicy::default();
/// policy.rules.push(IcmpRule::new(
///     IcmpSelector::raw_v4(8, None),
///     IcmpVerdict::Block,
/// ));
/// match compile_policy(FilterBackend::Nftables, &policy, &BackendOptions::default()) {
///     PolicyCompileResult::Exact(plan) => assert!(plan.ownership_tag.contains("nft:inet:")),
///     PolicyCompileResult::Unsupported { reasons, .. } => panic!("{reasons:?}"),
/// }
/// ```
pub fn compile_policy(
    backend: FilterBackend,
    policy: &IcmpPolicy,
    options: &BackendOptions,
) -> PolicyCompileResult {
    if let Err(mismatches) = check_policy_compatibility(backend, policy) {
        return PolicyCompileResult::Unsupported {
            requirements: policy.requirements(),
            reasons: mismatches
                .iter()
                .map(|m| format!("{}: {}", m.requirement, m.detail))
                .collect(),
        };
    }
    if !crate::config::is_valid_identifier(&options.table_name) {
        return PolicyCompileResult::Unsupported {
            requirements: policy.requirements(),
            reasons: vec![format!("invalid table name: {}", options.table_name)],
        };
    }
    if let Some(p) = &options.ebpf_bytecode_path {
        if p.is_empty() {
            return PolicyCompileResult::Unsupported {
                requirements: policy.requirements(),
                reasons: vec!["ebpf bytecode path must not be empty".to_string()],
            };
        }
    }

    let fingerprint = policy_fingerprint(policy);
    let ownership_tag = ownership_tag_for(backend, &options.table_name, fingerprint);
    let operations_summary = operations_summary_for(backend, policy, options, fingerprint);

    PolicyCompileResult::Exact(EnforcementPlan {
        backend,
        fingerprint,
        ownership_tag,
        operations_summary,
        expected_rule_count: expected_rule_count_for(backend, policy),
        warnings: Vec::new(),
    })
}

/// Backend-scoped ownership identity. Narrow enough that disable/update
/// cannot delete unrelated operator rules or another instance's objects.
pub fn ownership_tag_for(backend: FilterBackend, table: &str, fingerprint: u64) -> String {
    match backend {
        FilterBackend::Nftables => format!("nft:inet:{table}:gen:{}", fingerprint_hex(fingerprint)),
        FilterBackend::Ebpf => format!("ebpf:{table}:gen:{}", fingerprint_hex(fingerprint)),
        FilterBackend::Pf => format!("pf:anchor:{}", pf_anchor_for(table)),
        FilterBackend::Wfp => format!("wfp:provider:{}", wfp_provider_name(table)),
        FilterBackend::WindowsFirewall => {
            format!("winfw:prefix:{}", winfw_rule_prefix(table))
        }
    }
}

/// PF anchor identity. macOS uses a table-nested sub-anchor so two
/// instances cannot share one anchor; FreeBSD nests under the table name
/// per local convention.
pub fn pf_anchor_for(table: &str) -> String {
    #[cfg(target_os = "freebsd")]
    {
        format!("{table}.icmp")
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        format!("synvoid.icmp/{table}")
    }
}

/// WFP provider display name scoped by table. The stable provider GUID is
/// derived from this string at install time (FNV-128 fold).
pub fn wfp_provider_name(table: &str) -> String {
    format!("synvoid_ICMP_{table}")
}

/// Windows Firewall rule prefix scoped by table (single-owner-per-table).
/// Table names are identifier-validated, so interpolation is safe.
pub fn winfw_rule_prefix(table: &str) -> String {
    format!("synvoid_ICMP_{table}")
}

/// Legacy unscoped prefix retained only for best-effort stale cleanup.
pub const WINFW_LEGACY_PREFIX: &str = "synvoid_ICMP";

fn operations_summary_for(
    backend: FilterBackend,
    policy: &IcmpPolicy,
    options: &BackendOptions,
    fingerprint: u64,
) -> String {
    format!(
        "{backend:?} install fp={} rules={} exempt={} rate={} table={}",
        fingerprint_hex(fingerprint),
        policy.rules.len(),
        policy.exempt_ips.len(),
        policy.rate_limit.is_some(),
        options.table_name,
    )
}

fn expected_rule_count_for(backend: FilterBackend, policy: &IcmpPolicy) -> Option<usize> {
    match backend {
        // PF readback is presence-plus-cardinality: exempt passes + per-rule
        // lines + two base blocks. Computed by the same rule builder the
        // backend uses (see PfFilter::planned_rule_count).
        FilterBackend::Pf => Some(policy.exempt_ips.len() + policy.rules.len() + 2),
        _ => None,
    }
}

/// Live verification outcome for owned objects only. Unrelated operator
/// firewall state is tolerated: only the plan's ownership identity is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    Verified,
    Absent,
    Drifted { detail: String },
    Unknown { detail: String },
}

/// Enforcement confidence derived from desired vs verified state. A value
/// is "verified at generation N", never continuously authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementState {
    Applied,
    Absent,
    Drifted,
    Unknown,
}

/// Receipt for one successful verified install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReceipt {
    pub backend: FilterBackend,
    pub fingerprint: u64,
    pub generation: u64,
    /// Seconds since Unix epoch (via safe clock at apply time).
    pub applied_at_secs: u64,
    pub ownership_tag: String,
}

/// Desired vs applied vs verified report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub backend: FilterBackend,
    pub desired_fingerprint: Option<u64>,
    pub desired_generation: u64,
    pub last_receipt: Option<ApplyReceipt>,
    pub live: EnforcementState,
    pub last_verify_error: Option<String>,
}

/// Driver state for the replacement state machine. Held by the manager;
/// `FakeBackend` tests drive it without kernel access.
#[derive(Debug, Clone, Default)]
pub struct DriverState {
    pub generation: u64,
    pub desired_fingerprint: Option<u64>,
    pub last_receipt: Option<ApplyReceipt>,
    pub live: Option<EnforcementState>,
    pub last_verify_error: Option<String>,
}

/// Install failure with stage attribution for receipts and metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStage {
    Compile,
    Prepare,
    Apply,
    Commit,
    Verify,
    Cleanup,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{IcmpPolicy, IcmpRule, IcmpSelector, IcmpVerdict};

    fn echo_policy() -> IcmpPolicy {
        let mut p = IcmpPolicy::default();
        p.rules.push(IcmpRule::new(
            IcmpSelector::raw_v4(8, None),
            IcmpVerdict::Block,
        ));
        p
    }

    #[test]
    fn fingerprint_stable_and_family_sensitive() {
        let a = echo_policy();
        let b = echo_policy();
        assert_eq!(policy_fingerprint(&a), policy_fingerprint(&b));
        let mut c = IcmpPolicy::default();
        c.rules.push(IcmpRule::new(
            IcmpSelector::raw_v6(8, None),
            IcmpVerdict::Block,
        ));
        assert_ne!(policy_fingerprint(&a), policy_fingerprint(&c));
    }

    #[test]
    fn compile_exact_for_nftables() {
        let policy = echo_policy();
        let options = BackendOptions::default();
        match compile_policy(FilterBackend::Nftables, &policy, &options) {
            PolicyCompileResult::Exact(plan) => {
                assert_eq!(plan.fingerprint, policy_fingerprint(&policy));
                assert!(plan.ownership_tag.contains("nft:inet:"));
                assert!(plan.operations_summary.contains("rules=1"));
            }
            PolicyCompileResult::Unsupported { reasons, .. } => {
                panic!("expected exact, got {reasons:?}")
            }
        }
    }

    #[test]
    fn compile_rejects_rate_limit_on_wfp() {
        let mut policy = echo_policy();
        policy.rate_limit = Some(crate::policy::RateLimitPolicy::global(10, 20));
        match compile_policy(FilterBackend::Wfp, &policy, &BackendOptions::default()) {
            PolicyCompileResult::Unsupported { reasons, .. } => {
                assert!(reasons.iter().any(|r| r.contains("rate_limit")));
            }
            PolicyCompileResult::Exact(_) => panic!("WFP must not compile rate limits"),
        }
    }

    #[test]
    fn ownership_tags_are_backend_scoped() {
        let fp = 0x1234;
        assert!(ownership_tag_for(FilterBackend::Nftables, "t", fp).contains("nft:inet:t"));
        assert!(ownership_tag_for(FilterBackend::Wfp, "t", fp).contains("wfp:provider:"));
        assert!(winfw_rule_prefix("my-table").starts_with("synvoid_ICMP_my-table"));
        assert_ne!(winfw_rule_prefix("a"), winfw_rule_prefix("b"));
    }
}

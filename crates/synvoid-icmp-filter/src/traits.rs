//! Backend capability, compatibility, and filter traits (Phase 86).
//!
//! `BackendCapabilities` describes static backend expressiveness only —
//! what a backend can express in principle. Runtime facts (compiled into
//! this build, mechanism present, privilege held, currently selected,
//! currently enforcing) live in `crate::platform::BackendProbe` and,
//! from Phase 87, verified enforcement state. Policy compatibility is
//! evaluated against the Phase 85 `IcmpPolicy`, not a single boolean.
//!
//! Capability tiers used in docs:
//! - `supported`: native privileged proof recorded (Phase 88 matrix).
//! - `experimental`: compiles; behavior best-effort, no native proof yet.
//! - `compile-only`: cross-target `cargo check` evidence only.
//! - `unsupported`: no backend (NetBSD: NPF is the future trigger).

use crate::{
    config::IcmpFilterConfig,
    enforce::{EnforcementPlan, VerificationOutcome},
    error::Result,
    policy::IcmpPolicy,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterBackend {
    #[default]
    Nftables,
    Ebpf,
    Pf,
    WindowsFirewall,
    Wfp,
}

impl FilterBackend {
    /// Documented `Auto` fallback priority (Linux-first baseline; WFP is the
    /// Windows primary; winfw is compatibility-only and never auto-picked
    /// ahead of WFP).
    pub fn auto_priority() -> &'static [FilterBackend] {
        // Order is platform-filtered by callers via `compiled_for_host`.
        &[
            FilterBackend::Nftables,
            FilterBackend::Ebpf,
            FilterBackend::Pf,
            FilterBackend::Wfp,
        ]
    }
}

/// Static expressiveness of one backend. No runtime state: a `true` here
/// never means "currently enforcing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub backend: FilterBackend,
    /// Block verdicts expressible.
    pub supports_block: bool,
    /// Allow verdicts expressible (exemptions/per-rule allow).
    pub supports_allow: bool,
    /// Global-scope rate limiting (the only scope Phase 85 defines).
    /// Per-source / per-type scopes are unsupported everywhere.
    pub supports_rate_limit_global: bool,
    /// Per-rule ICMP type matching.
    pub supports_type_matching: bool,
    /// Per-rule ICMP code matching (may differ per backend variant).
    pub supports_code_matching: bool,
    /// Interface-scoped rules. Some backends require a resolvable
    /// interface index rather than a name.
    pub supports_interface_filtering: bool,
    /// Interface filtering requires a numeric index/LUID; names must be
    /// resolved before install (WFP).
    pub interface_requires_index: bool,
    /// Engine transactions available for atomic replacement (WFP, nftables
    /// batch). Backends without transactions report staged replacement
    /// with explicit rollback limits in Phase 87.
    pub supports_transactions: bool,
}

impl BackendCapabilities {
    pub fn for_backend(backend: FilterBackend) -> Self {
        match backend {
            FilterBackend::Nftables => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit_global: true,
                supports_type_matching: true,
                supports_code_matching: true,
                supports_interface_filtering: true,
                interface_requires_index: false,
                supports_transactions: true,
            },
            FilterBackend::Ebpf => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit_global: true,
                supports_type_matching: true,
                supports_code_matching: true,
                supports_interface_filtering: true,
                interface_requires_index: false,
                supports_transactions: false,
            },
            FilterBackend::Pf => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit_global: true,
                supports_type_matching: true,
                supports_code_matching: true,
                supports_interface_filtering: true,
                interface_requires_index: false,
                // PF anchor reload is staged, not transactional; Phase 87
                // reports the reduced guarantee explicitly.
                supports_transactions: false,
            },
            // Compatibility fallback: COM firewall rules are visible to
            // Defender/GPO tooling but offer no transactions, no rate
            // limiting, and no live readback. Never auto-preferred.
            FilterBackend::WindowsFirewall => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit_global: false,
                supports_type_matching: true,
                supports_code_matching: true,
                supports_interface_filtering: true,
                interface_requires_index: false,
                supports_transactions: false,
            },
            // Primary Windows lane: typed protocol/ICMP conditions plus
            // engine transactions.
            FilterBackend::Wfp => Self {
                backend,
                supports_block: true,
                supports_allow: true,
                supports_rate_limit_global: false,
                supports_type_matching: true,
                supports_code_matching: true,
                supports_interface_filtering: true,
                interface_requires_index: true,
                supports_transactions: true,
            },
        }
    }
}

/// One unmet policy requirement on a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityMismatch {
    pub requirement: &'static str,
    pub detail: String,
}

/// Evaluate a requested policy against static backend expressiveness.
/// Returns `Ok(())` when the backend can express the policy exactly;
/// otherwise every mismatch (never a silent downgrade).
pub fn check_policy_compatibility(
    backend: FilterBackend,
    policy: &IcmpPolicy,
) -> std::result::Result<(), Vec<CapabilityMismatch>> {
    let caps = BackendCapabilities::for_backend(backend);
    let req = policy.requirements();
    let mut mismatches = Vec::new();

    if req.needs_rate_limit_global && !caps.supports_rate_limit_global {
        mismatches.push(CapabilityMismatch {
            requirement: "rate_limit_global",
            detail: format!(
                "{backend:?} implements no global rate limit; requested \
                 {}/s burst {}",
                policy.rate_limit.map(|r| r.packets_per_second).unwrap_or(0),
                policy.rate_limit.map(|r| r.burst).unwrap_or(0),
            ),
        });
    }
    if req.needs_type_matching && !caps.supports_type_matching {
        mismatches.push(CapabilityMismatch {
            requirement: "type_matching",
            detail: format!("{backend:?} cannot match ICMP types"),
        });
    }
    if req.needs_code_matching && !caps.supports_code_matching {
        mismatches.push(CapabilityMismatch {
            requirement: "code_matching",
            detail: format!("{backend:?} cannot match ICMP codes"),
        });
    }
    if req.needs_interface_filtering && !caps.supports_interface_filtering {
        mismatches.push(CapabilityMismatch {
            requirement: "interface_filtering",
            detail: format!("{backend:?} cannot scope rules to interfaces"),
        });
    }

    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterStatus {
    pub enabled: bool,
    pub backend: FilterBackend,
    pub config: IcmpFilterConfig,
}

pub trait IcmpFilter: Debug + Send + Sync {
    fn enable(&mut self) -> Result<()>;
    fn disable(&mut self) -> Result<()>;
    fn is_enabled(&self) -> bool;
    fn is_enforcing(&self) -> bool;
    fn backend(&self) -> FilterBackend;
    fn status(&self) -> FilterStatus;
    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<()>;
    fn config(&self) -> &IcmpFilterConfig;

    /// Idempotent ensure-present. Default: enable unless already enabled.
    /// Backends with atomic replace override for single-shot semantics.
    fn ensure_enabled(&mut self) -> Result<()> {
        if self.is_enabled() {
            return Ok(());
        }
        self.enable()
    }

    /// Idempotent ensure-absent. Default: disable unless already disabled,
    /// so benign double-disable is not an error for reconciliation.
    fn ensure_disabled(&mut self) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        self.disable()
    }

    /// Live readback of owned objects for a plan. The default is honest
    /// `Unknown`: backends without readback must not claim verification.
    fn verify_ownership(&self, plan: &EnforcementPlan) -> VerificationOutcome {
        let _ = plan;
        VerificationOutcome::Unknown {
            detail: "backend implements no live readback".to_string(),
        }
    }
}

pub trait IcmpFilterFactory: Debug + Send + Sync {
    fn create(&self, config: IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>>;
    fn backend(&self) -> FilterBackend;
    fn is_available(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IcmpAction, IcmpTypeRule};
    use crate::policy::RateLimitPolicy;

    fn blocking_echo() -> IcmpPolicy {
        let mut p = IcmpPolicy::default();
        p.rules.push(crate::policy::IcmpRule::new(
            crate::policy::IcmpSelector::raw_v4(8, None),
            crate::policy::IcmpVerdict::Block,
        ));
        p
    }

    #[test]
    fn winfw_rejects_rate_limit_wfp_accepts_types() {
        let mut policy = blocking_echo();
        policy.rate_limit = Some(RateLimitPolicy::global(10, 20));
        // Neither Windows lane implements rate limiting: exact semantics
        // fail rather than install a weaker rule set.
        assert!(check_policy_compatibility(FilterBackend::Wfp, &policy).is_err());
        assert!(check_policy_compatibility(FilterBackend::WindowsFirewall, &policy).is_err());
        // nftables expresses the same policy exactly.
        assert!(check_policy_compatibility(FilterBackend::Nftables, &policy).is_ok());
    }

    #[test]
    fn plain_type_policy_fits_wfp() {
        let policy = blocking_echo();
        assert!(check_policy_compatibility(FilterBackend::Wfp, &policy).is_ok());
    }

    #[test]
    fn static_capability_has_no_runtime_state() {
        // Static descriptors must not claim enforcement: every lane reports
        // the same shape regardless of host privilege.
        for backend in [
            FilterBackend::Nftables,
            FilterBackend::Ebpf,
            FilterBackend::Pf,
            FilterBackend::WindowsFirewall,
            FilterBackend::Wfp,
        ] {
            let caps = BackendCapabilities::for_backend(backend);
            assert_eq!(caps.backend, backend);
        }
        // WFP is the only lane requiring index resolution; winfw keeps
        // friendly names (its documented compatibility value).
        assert!(BackendCapabilities::for_backend(FilterBackend::Wfp).interface_requires_index);
        assert!(
            !BackendCapabilities::for_backend(FilterBackend::WindowsFirewall)
                .interface_requires_index
        );
    }

    #[test]
    fn legacy_rule_helpers_still_available() {
        let rule = IcmpTypeRule::new(8, IcmpAction::Block);
        assert!(rule.is_block());
    }
}

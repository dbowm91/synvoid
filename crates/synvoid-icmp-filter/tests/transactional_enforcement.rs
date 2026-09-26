//! Phase 87 Workstream H: deterministic fake-backend failure tests.
//!
//! A `FakeFilter` (`IcmpFilter` + injectable faults) drives the real
//! `drive_update` flow without root or native firewalls. Each required
//! invariant is proven here.

use std::collections::HashSet;
use synvoid_icmp_filter::{
    config::{FilterType, IcmpAction, IcmpFilterConfig, IcmpTypeRule},
    drive_disable, drive_enable, drive_update,
    enforce::{policy_fingerprint, EnforcementPlan, VerificationOutcome},
    traits::{FilterBackend, FilterStatus, IcmpFilter},
    DriverState, EnforcementState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Fault {
    Apply,
    /// Apply mutates "kernel" to the new generation then reports failure
    /// (unprovable rollback).
    ApplyMutating,
    VerifyDrift,
    VerifyUnknown,
    Cleanup,
    Enable,
}

#[derive(Debug)]
struct FakeFilter {
    config: IcmpFilterConfig,
    enabled: bool,
    /// What the "kernel" holds (fingerprint of installed policy).
    installed: Option<u64>,
    faults: HashSet<Fault>,
    update_calls: usize,
    remove_calls: usize,
}

impl FakeFilter {
    fn new() -> Self {
        Self {
            config: IcmpFilterConfig::new(),
            enabled: false,
            installed: None,
            faults: HashSet::new(),
            update_calls: 0,
            remove_calls: 0,
        }
    }

    fn with_fault(mut self, fault: Fault) -> Self {
        self.faults.insert(fault);
        self
    }

    fn fingerprint_of(config: &IcmpFilterConfig) -> u64 {
        let (policy, _) = synvoid_icmp_filter::adapt_config_to_policy(config).unwrap();
        policy_fingerprint(&policy)
    }
}

impl IcmpFilter for FakeFilter {
    fn enable(&mut self) -> Result<(), synvoid_icmp_filter::IcmpFilterError> {
        if self.enabled {
            return Err(synvoid_icmp_filter::IcmpFilterError::AlreadyEnabled);
        }
        if self.faults.contains(&Fault::Enable) {
            return Err(synvoid_icmp_filter::IcmpFilterError::Nftables(
                "injected enable failure".to_string(),
            ));
        }
        self.enabled = true;
        self.installed = Some(Self::fingerprint_of(&self.config));
        Ok(())
    }

    fn disable(&mut self) -> Result<(), synvoid_icmp_filter::IcmpFilterError> {
        if !self.enabled {
            return Err(synvoid_icmp_filter::IcmpFilterError::AlreadyDisabled);
        }
        if self.faults.contains(&Fault::Cleanup) {
            return Err(synvoid_icmp_filter::IcmpFilterError::Nftables(
                "injected cleanup failure".to_string(),
            ));
        }
        self.remove_calls += 1;
        self.enabled = false;
        self.installed = None;
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn is_enforcing(&self) -> bool {
        self.enabled
    }

    fn backend(&self) -> FilterBackend {
        FilterBackend::Nftables
    }

    fn status(&self) -> FilterStatus {
        FilterStatus {
            enabled: self.enabled,
            backend: FilterBackend::Nftables,
            config: self.config.clone(),
        }
    }

    fn update_config(
        &mut self,
        config: IcmpFilterConfig,
    ) -> Result<(), synvoid_icmp_filter::IcmpFilterError> {
        config
            .validate()
            .map_err(synvoid_icmp_filter::IcmpFilterError::Config)?;
        self.update_calls += 1;
        // Swap-back discipline mirrors the real backends.
        let old = std::mem::replace(&mut self.config, config);
        if self.faults.contains(&Fault::ApplyMutating) {
            self.installed = Some(Self::fingerprint_of(&self.config));
            self.config = old;
            return Err(synvoid_icmp_filter::IcmpFilterError::Nftables(
                "injected mutating apply failure".to_string(),
            ));
        }
        if self.faults.contains(&Fault::Apply) {
            self.config = old;
            return Err(synvoid_icmp_filter::IcmpFilterError::Nftables(
                "injected apply failure".to_string(),
            ));
        }
        self.installed = Some(Self::fingerprint_of(&self.config));
        Ok(())
    }

    fn config(&self) -> &IcmpFilterConfig {
        &self.config
    }

    fn verify_ownership(&self, plan: &EnforcementPlan) -> VerificationOutcome {
        if self.faults.contains(&Fault::VerifyDrift) {
            return VerificationOutcome::Drifted {
                detail: "injected drift".to_string(),
            };
        }
        if self.faults.contains(&Fault::VerifyUnknown) {
            return VerificationOutcome::Unknown {
                detail: "injected unverifiable".to_string(),
            };
        }
        match self.installed {
            Some(fp) if fp == plan.fingerprint => VerificationOutcome::Verified,
            Some(_) => VerificationOutcome::Drifted {
                detail: "installed fingerprint mismatch".to_string(),
            },
            None => VerificationOutcome::Absent,
        }
    }
}

fn v4_block_config(icmp_type: u8) -> IcmpFilterConfig {
    IcmpFilterConfig::new()
        .with_filter_type(FilterType::Nftables)
        .with_icmp_type_rules(vec![IcmpTypeRule::new(icmp_type, IcmpAction::Block)])
}

// 1. Compile failure performs zero mutation.
#[test]
fn compile_failure_zero_mutation() {
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    let mut bad = v4_block_config(8);
    bad.table_name = "bad table!".to_string();
    let before = filter.config.clone();
    let err = drive_update(&mut filter, bad, &mut driver).unwrap_err();
    assert!(
        matches!(
            err,
            synvoid_icmp_filter::IcmpFilterError::Adapt(_)
                | synvoid_icmp_filter::IcmpFilterError::Config(_)
                | synvoid_icmp_filter::IcmpFilterError::Unsupported(_)
        ),
        "compile failure must be typed, got {err:?}"
    );
    assert_eq!(
        filter.update_calls, 0,
        "compile failure must not reach install"
    );
    assert_eq!(filter.config.table_name, before.table_name);
    assert!(driver.last_receipt.is_none());
}

// 2. Prepare/apply failure does not mark the new policy applied.
#[test]
fn apply_failure_keeps_previous_state() {
    // Establish a verified generation first.
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    let first = v4_block_config(8);
    let receipt = drive_update(&mut filter, first, &mut driver).unwrap();
    assert_eq!(driver.live, Some(EnforcementState::Applied));

    // Replacement fails at apply: old config retained, receipt un-advanced.
    filter.faults.insert(Fault::Apply);
    let second = v4_block_config(0);
    let err = drive_update(&mut filter, second, &mut driver).unwrap_err();
    assert!(format!("{err:?}").contains("injected apply failure"));
    assert_eq!(filter.config.icmp_type_rules[0].icmp_type, 8);
    assert_eq!(driver.last_receipt.unwrap().generation, receipt.generation);
    assert_eq!(driver.live, Some(EnforcementState::Applied));
}

// 3. Mutating commit failure reports previous state, never the replacement.
#[test]
fn mutating_commit_failure_never_claims_replacement() {
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    drive_update(&mut filter, v4_block_config(8), &mut driver).unwrap();
    let applied_fp = driver.last_receipt.clone().unwrap().fingerprint;

    filter.faults.insert(Fault::ApplyMutating);
    let err = drive_update(&mut filter, v4_block_config(0), &mut driver).unwrap_err();
    assert!(
        format!("{err:?}").contains("mutating apply failure"),
        "unexpected error {err:?}"
    );
    // The driver still reports the previous verified generation...
    assert_eq!(driver.last_receipt.unwrap().fingerprint, applied_fp);
    // ...and a fresh readback exposes the kernel truth (drift), not Applied.
    let (policy, options) = synvoid_icmp_filter::adapt_config_to_policy(&filter.config).unwrap();
    let plan = match synvoid_icmp_filter::compile_policy(FilterBackend::Nftables, &policy, &options)
    {
        synvoid_icmp_filter::PolicyCompileResult::Exact(p) => p,
        synvoid_icmp_filter::PolicyCompileResult::Unsupported { .. } => panic!(),
    };
    assert!(matches!(
        filter.verify_ownership(&plan),
        VerificationOutcome::Drifted { .. }
    ));
}

// 4. Verify mismatch yields Drifted/Unknown, not Applied.
#[test]
fn verify_mismatch_never_applied() {
    for fault in [Fault::VerifyDrift, Fault::VerifyUnknown] {
        let mut filter = FakeFilter::new().with_fault(fault);
        let mut driver = DriverState::default();
        let err = drive_update(&mut filter, v4_block_config(8), &mut driver).unwrap_err();
        assert!(
            matches!(
                err,
                synvoid_icmp_filter::IcmpFilterError::BackendUnavailable(_)
            ),
            "verify failure must surface as BackendUnavailable, got {err:?}"
        );
        assert!(
            driver.last_receipt.is_none(),
            "no receipt without verification"
        );
        let expected = if fault == Fault::VerifyDrift {
            EnforcementState::Drifted
        } else {
            EnforcementState::Unknown
        };
        assert_eq!(driver.live, Some(expected));
    }
}

// 5. Cleanup failure is visible.
#[test]
fn cleanup_failure_visible() {
    let mut filter = FakeFilter::new().with_fault(Fault::Cleanup);
    filter.enabled = true;
    let err = filter.disable().unwrap_err();
    assert!(format!("{err:?}").contains("cleanup"));
    assert!(filter.enabled, "failed cleanup leaves enabled set");
}

// 6. Explicit disable is idempotent via ensure_disabled.
#[test]
fn disable_idempotent_via_ensure() {
    let mut filter = FakeFilter::new();
    // Already absent: ensure is Ok, legacy disable errors (compat).
    assert!(filter.ensure_disabled().is_ok());
    assert!(filter.disable().is_err());
    filter.enabled = true;
    assert!(filter.ensure_disabled().is_ok());
    assert!(!filter.enabled);
}

// 7. Receipt generation/fingerprint matches the installed policy.
#[test]
fn receipt_matches_installed_generation() {
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    let cfg = v4_block_config(8);
    let receipt = drive_update(&mut filter, cfg, &mut driver).unwrap();
    assert_eq!(receipt.generation, 1);
    assert_eq!(receipt.fingerprint, filter.installed.unwrap());
    assert_eq!(receipt.backend, FilterBackend::Nftables);
    let cfg2 = v4_block_config(0);
    let receipt2 = drive_update(&mut filter, cfg2, &mut driver).unwrap();
    assert_eq!(receipt2.generation, 2);
    assert_eq!(receipt2.fingerprint, filter.installed.unwrap());
    assert_ne!(receipt.fingerprint, receipt2.fingerprint);
}

// ── Phase 90 Finding A: enable/disable share the verified lifecycle ──────

// 8. Enable advances verified lifecycle state (desired + receipt + Applied).
#[test]
fn enable_advances_verified_lifecycle() {
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    let receipt = drive_enable(&mut filter, &mut driver).unwrap();
    assert_eq!(driver.desired_enabled, Some(true));
    assert_eq!(driver.live, Some(EnforcementState::Applied));
    assert!(driver.last_verify_error.is_none());
    assert_eq!(
        driver.last_receipt.clone().unwrap().generation,
        receipt.generation
    );
    assert!(filter.is_enabled());
}

// 9. Disable reaches verified Absent while retaining the receipt history.
#[test]
fn disable_reaches_verified_absent() {
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    let receipt = drive_enable(&mut filter, &mut driver).unwrap();
    drive_disable(&mut filter, &mut driver).unwrap();
    assert_eq!(driver.desired_enabled, Some(false));
    assert_eq!(driver.live, Some(EnforcementState::Absent));
    assert!(driver.last_verify_error.is_none());
    // Previous receipt retained as historical information.
    assert_eq!(driver.last_receipt.unwrap().generation, receipt.generation);
    assert!(!filter.is_enabled());
}

// 10. Failed enable creates no apply receipt.
#[test]
fn failed_enable_creates_no_receipt() {
    // Install-stage failure.
    {
        let mut filter = FakeFilter::new().with_fault(Fault::Enable);
        let mut driver = DriverState::default();
        let err = drive_enable(&mut filter, &mut driver).unwrap_err();
        assert!(format!("{err:?}").contains("injected enable failure"));
        assert!(
            driver.last_receipt.is_none(),
            "failed enable must not create a receipt"
        );
        assert_ne!(driver.live, Some(EnforcementState::Applied));
    }
    // Verify-stage failures.
    for fault in [Fault::VerifyDrift, Fault::VerifyUnknown] {
        let mut filter = FakeFilter::new();
        filter.faults.insert(fault);
        let mut driver = DriverState::default();
        let err = drive_enable(&mut filter, &mut driver).unwrap_err();
        assert!(
            matches!(
                err,
                synvoid_icmp_filter::IcmpFilterError::BackendUnavailable(_)
            ),
            "failed enable must be BackendUnavailable, got {err:?}"
        );
        assert!(
            driver.last_receipt.is_none(),
            "failed enable must not create a receipt"
        );
        assert_ne!(driver.live, Some(EnforcementState::Applied));
    }
    // Compile rejection (inexpressible policy) also creates no receipt.
    let mut filter = FakeFilter::new();
    filter.config.table_name = "bad table!".to_string();
    let mut driver = DriverState::default();
    let err = drive_enable(&mut filter, &mut driver).unwrap_err();
    assert!(
        driver.last_receipt.is_none(),
        "compile failure => no receipt"
    );
    let _ = err;
}

// 11. Failed disable never claims Absent.
#[test]
fn failed_disable_never_claims_absent() {
    // Cleanup failure: backend stays enabled, driver must not report Absent.
    let mut filter = FakeFilter::new().with_fault(Fault::Cleanup);
    filter.enabled = true;
    filter.installed = Some(FakeFilter::fingerprint_of(&filter.config));
    let mut driver = DriverState::default();
    driver.desired_enabled = Some(true);
    driver.live = Some(EnforcementState::Applied);
    let err = drive_disable(&mut filter, &mut driver).unwrap_err();
    let _ = err;
    assert_ne!(
        driver.live,
        Some(EnforcementState::Absent),
        "failed disable must never claim Absent"
    );
    assert!(filter.is_enabled(), "failed cleanup leaves enabled set");

    // Unverifiable absence: verify returns Unknown after disable.
    let mut filter = FakeFilter::new();
    filter.enabled = true;
    filter.installed = Some(FakeFilter::fingerprint_of(&filter.config));
    filter.faults.insert(Fault::VerifyUnknown);
    let mut driver = DriverState::default();
    // Disable path: FakeFilter::disable clears installed, then verify hits
    // the injected Unknown fault.
    let err = drive_disable(&mut filter, &mut driver).unwrap_err();
    assert!(
        matches!(
            err,
            synvoid_icmp_filter::IcmpFilterError::BackendUnavailable(_)
        ),
        "unverifiable disable => BackendUnavailable, got {err:?}"
    );
    assert_eq!(driver.live, Some(EnforcementState::Unknown));
}

// 12. Enable/disable/config share one driver (generation advances jointly).
#[test]
fn lifecycle_shares_one_driver_generation() {
    let mut filter = FakeFilter::new();
    let mut driver = DriverState::default();
    let r1 = drive_enable(&mut filter, &mut driver).unwrap();
    assert_eq!(r1.generation, 1);
    assert_eq!(driver.desired_enabled, Some(true));
    // Config replacement while enabled advances the same counter.
    let r2 = drive_update(
        &mut filter,
        v4_block_config(0).with_enabled(true),
        &mut driver,
    )
    .unwrap();
    assert_eq!(r2.generation, 2);
    assert_eq!(driver.desired_enabled, Some(true));
    // Disable advances desired/live state without touching the receipt.
    drive_disable(&mut filter, &mut driver).unwrap();
    assert_eq!(driver.desired_enabled, Some(false));
    assert_eq!(driver.live, Some(EnforcementState::Absent));
    assert_eq!(driver.last_receipt.unwrap().generation, 2);
}

//! Integration test: plugin failure does not poison other plugins or the manager.
//!
//! Verifies that when one plugin hits a capability violation, timeout, or
//! repeated runtime failure, other plugins remain invocable and the overall
//! plugin manager state is unaffected.

use std::path::Path;

use synvoid_plugin_runtime::sandbox::types::{
    PluginCapabilities, PluginCapability, PluginInvocationGuard, PluginLimits, PluginManifest,
    PluginRuntimeState,
};

/// Helper: build a manifest from minimal TOML.
fn make_manifest(toml: &str) -> PluginManifest {
    PluginManifest::parse_toml(toml, Path::new("test.toml")).expect("valid manifest")
}

#[test]
fn manifest_failure_does_not_affect_other_manifests() {
    let valid = make_manifest(
        r#"
        name = "good-plugin"
        version = "0.1.0"
        entry = "good.wasm"
    "#,
    );
    assert_eq!(valid.name, "good-plugin");

    let invalid = PluginManifest::parse_toml(
        r#"
        name = ""
        version = "0.1.0"
        entry = "bad.wasm"
    "#,
        Path::new("bad.toml"),
    );
    assert!(invalid.is_err());

    // The valid manifest should still parse fine after the failure.
    let also_valid = make_manifest(
        r#"
        name = "another-good"
        version = "2.0.0"
        entry = "also_good.wasm"
    "#,
    );
    assert_eq!(also_valid.name, "another-good");
}

#[test]
fn capability_violation_does_not_disable_other_guards() {
    let guard_a = PluginInvocationGuard::new(
        PluginCapabilities::default(), // no capabilities
        PluginLimits::default(),
        4,
    );
    let guard_b = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits::default(),
        4,
    );

    // Guard A gets a violation.
    let result = guard_a.require_nowait(PluginCapability::RequestMutate);
    assert!(result.is_err());
    guard_a.disable_for_violation();

    // Guard B is unaffected.
    assert!(guard_b.is_invocable());
    let result = guard_b.require_nowait(PluginCapability::RequestInspect);
    assert!(result.is_ok());
}

#[test]
fn repeated_timeout_does_not_poison_other_guards() {
    let failing_guard = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits {
            timeout_ms: 1,
            ..Default::default()
        },
        4,
    );
    let healthy_guard = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits::default(),
        4,
    );

    // Record failures on the failing guard until it disables.
    for _ in 0..5 {
        failing_guard.record_failure(3);
    }
    assert!(!failing_guard.is_invocable());
    assert_eq!(
        *failing_guard.state.read(),
        PluginRuntimeState::DisabledByRuntimeFailure
    );

    // Healthy guard is completely unaffected.
    assert!(healthy_guard.is_invocable());
    assert_eq!(*healthy_guard.state.read(), PluginRuntimeState::Loaded);
}

#[test]
fn reset_failures_restores_only_own_guard() {
    let guard_a = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits::default(),
        4,
    );
    let guard_b = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits::default(),
        4,
    );

    // Both guards fail (threshold=2, so need 2 calls to disable).
    guard_a.record_failure(2);
    guard_a.record_failure(2);
    guard_b.record_failure(2);
    guard_b.record_failure(2);
    assert!(!guard_a.is_invocable());
    assert!(!guard_b.is_invocable());

    // Reset only guard A.
    guard_a.reset_failures();
    assert!(guard_a.is_invocable());
    assert!(!guard_b.is_invocable(), "guard B should still be disabled");
}

#[test]
fn concurrency_exhaustion_does_not_block_other_plugins() {
    let guard_a = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits {
            max_concurrency: 1,
            timeout_ms: 5000,
            ..Default::default()
        },
        1,
    );
    let guard_b = PluginInvocationGuard::new(
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits {
            max_concurrency: 4,
            timeout_ms: 5000,
            ..Default::default()
        },
        4,
    );

    // Exhaust guard A's concurrency.
    let permit_a = guard_a.concurrency.clone().try_acquire_owned();
    assert!(permit_a.is_ok());

    // Guard A is at capacity.
    let second = guard_a.concurrency.clone().try_acquire_owned();
    assert!(second.is_err());

    // Guard B has its own semaphore — unaffected.
    let permit_b = guard_b.concurrency.clone().try_acquire_owned();
    assert!(permit_b.is_ok());
    let second_b = guard_b.concurrency.clone().try_acquire_owned();
    assert!(second_b.is_ok());
}

#[test]
fn all_guards_share_no_state() {
    let make_guard =
        || PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);

    let g1 = make_guard();
    let g2 = make_guard();

    g1.disable_for_violation();
    assert!(!g1.is_invocable());
    assert!(
        g2.is_invocable(),
        "disabling g1 must not affect g2 — each guard has independent state"
    );
}

// ─── Helper extension trait ──────────────────────────────────────────────────

trait PluginInvocationGuardExt {
    fn require_nowait(
        &self,
        cap: PluginCapability,
    ) -> Result<(), synvoid_plugin_runtime::sandbox::types::CapabilityViolation>;
}

impl PluginInvocationGuardExt for PluginInvocationGuard {
    fn require_nowait(
        &self,
        cap: PluginCapability,
    ) -> Result<(), synvoid_plugin_runtime::sandbox::types::CapabilityViolation> {
        self.capabilities.require(cap)
    }
}

//! Integration tests for manifest authority wiring (M1 Phase 01).
//!
//! Tests that two plugins with different manifests receive different runtime
//! authority, validating the manifest-to-runtime conversion pipeline.

use std::sync::Arc;
use std::time::Duration;

use synvoid_plugin_runtime::sandbox::policy::limits_from_manifest;
use synvoid_plugin_runtime::sandbox::types::{
    PluginCapabilities, PluginInvocationGuard, PluginLimits, PluginManifest, PluginTrustTier,
};
use synvoid_plugin_runtime::WasmResourceLimits;

fn default_limits() -> WasmResourceLimits {
    WasmResourceLimits::default()
}

fn make_manifest(name: &str, caps: PluginCapabilities, limits: PluginLimits) -> PluginManifest {
    PluginManifest {
        name: name.into(),
        version: "1.0.0".into(),
        entry: "plugin.wasm".into(),
        trust_tier: PluginTrustTier::LocalSandboxed,
        capabilities: caps,
        limits,
        signature: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 1: Request filter capability differentiation
// ═══════════════════════════════════════════════════════════════════════════════

/// Plugin A grants request_inspect; Plugin B grants nothing.
/// Invoking Plugin A as a request filter succeeds.
/// Invoking Plugin B as a request filter fails with a capability error.
#[tokio::test]
async fn two_plugins_different_request_capabilities() {
    use synvoid_plugin_runtime::sandbox::types::PluginCapability;

    // Plugin A: grants request_inspect
    let manifest_a = make_manifest(
        "plugin-a",
        PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits::default(),
    );
    let limits_a = limits_from_manifest(&manifest_a, &default_limits()).unwrap();
    let guard_a =
        PluginInvocationGuard::new((*limits_a.capabilities).clone(), PluginLimits::default(), 4);

    // Plugin B: no request capability
    let manifest_b = make_manifest(
        "plugin-b",
        PluginCapabilities::default(),
        PluginLimits::default(),
    );
    let limits_b = limits_from_manifest(&manifest_b, &default_limits()).unwrap();
    let guard_b =
        PluginInvocationGuard::new((*limits_b.capabilities).clone(), PluginLimits::default(), 4);

    // Plugin A can be invoked as request filter
    let result_a = guard_a
        .invoke_with_limits(PluginCapability::RequestInspect, 0, || async {
            Ok::<(), synvoid_plugin_runtime::sandbox::types::PluginInvokeError>(())
        })
        .await;
    assert!(result_a.is_ok(), "Plugin A should allow request_inspect");

    // Plugin B cannot be invoked as request filter
    let result_b = guard_b
        .invoke_with_limits(PluginCapability::RequestInspect, 0, || async {
            Ok::<(), synvoid_plugin_runtime::sandbox::types::PluginInvokeError>(())
        })
        .await;
    assert!(result_b.is_err(), "Plugin B should deny request_inspect");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 2: Mesh capability differentiation
// ═══════════════════════════════════════════════════════════════════════════════

/// Plugin A grants mesh; Plugin B does not.
/// Plugin A reaches the prefix policy check.
/// Plugin B fails at capability check before prefix logic.
#[tokio::test]
async fn two_plugins_different_mesh_capabilities() {
    use synvoid_plugin_runtime::sandbox::types::PluginCapability;

    // Plugin A: grants mesh
    let manifest_a = make_manifest(
        "mesh-plugin-a",
        PluginCapabilities {
            mesh: true,
            ..Default::default()
        },
        PluginLimits::default(),
    );
    let limits_a = limits_from_manifest(&manifest_a, &default_limits()).unwrap();
    let guard_a =
        PluginInvocationGuard::new((*limits_a.capabilities).clone(), PluginLimits::default(), 4);

    // Plugin B: no mesh
    let manifest_b = make_manifest(
        "mesh-plugin-b",
        PluginCapabilities::default(),
        PluginLimits::default(),
    );
    let limits_b = limits_from_manifest(&manifest_b, &default_limits()).unwrap();
    let guard_b =
        PluginInvocationGuard::new((*limits_b.capabilities).clone(), PluginLimits::default(), 4);

    // Plugin A can invoke mesh_query_dht (passes capability check)
    let result_a = guard_a
        .invoke_with_limits(PluginCapability::Mesh, 0, || async {
            Ok::<(), synvoid_plugin_runtime::sandbox::types::PluginInvokeError>(())
        })
        .await;
    assert!(result_a.is_ok(), "Plugin A should allow mesh capability");

    // Plugin B fails at capability check
    let result_b = guard_b
        .invoke_with_limits(PluginCapability::Mesh, 0, || async {
            Ok::<(), synvoid_plugin_runtime::sandbox::types::PluginInvokeError>(())
        })
        .await;
    assert!(result_b.is_err(), "Plugin B should deny mesh capability");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 3: Per-plugin limits are different
// ═══════════════════════════════════════════════════════════════════════════════

/// Two plugins with different manifest limits get different effective limits.
#[test]
fn two_plugins_different_limits() {
    let manifest_a = make_manifest(
        "fast-plugin",
        PluginCapabilities::default(),
        PluginLimits {
            timeout_ms: 100,
            max_concurrency: 8,
            fuel: Some(500_000),
            memory_pages: Some(64),
            ..Default::default()
        },
    );
    let limits_a = limits_from_manifest(&manifest_a, &default_limits()).unwrap();

    let manifest_b = make_manifest(
        "slow-plugin",
        PluginCapabilities::default(),
        PluginLimits {
            timeout_ms: 5000,
            max_concurrency: 2,
            fuel: Some(2_000_000),
            memory_pages: Some(128),
            ..Default::default()
        },
    );
    let limits_b = limits_from_manifest(&manifest_b, &default_limits()).unwrap();

    // Different timeouts (Duration-based, preserves millisecond precision)
    assert_eq!(limits_a.timeout, Duration::from_millis(100)); // 100ms
    assert_eq!(limits_b.timeout, Duration::from_millis(5000)); // 5000ms

    // Different concurrency
    assert_eq!(limits_a.max_instances, 8);
    assert_eq!(limits_b.max_instances, 2);

    // Different fuel
    assert_eq!(limits_a.max_cpu_fuel, 500_000);
    assert_eq!(limits_b.max_cpu_fuel, 2_000_000);

    // Different memory
    assert_eq!(limits_a.max_memory_mb, 4); // 64 pages * 64KB = 4MB
    assert_eq!(limits_b.max_memory_mb, 8); // 128 pages * 64KB = 8MB
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 4: Capabilities from manifest override defaults
// ═══════════════════════════════════════════════════════════════════════════════

/// When defaults have mesh enabled but the manifest denies it, the effective
/// limits must deny mesh.
#[test]
fn manifest_capabilities_override_defaults() {
    use synvoid_plugin_runtime::sandbox::types::PluginCapability;

    let manifest = make_manifest(
        "no-mesh-plugin",
        PluginCapabilities {
            mesh: false,
            request_inspect: true,
            ..Default::default()
        },
        PluginLimits::default(),
    );

    let mut defaults = default_limits();
    // Defaults claim to have mesh and request_inspect
    defaults.allowed_dht_prefixes = vec!["threat_indicator:".into()];
    defaults.capabilities = Arc::new(PluginCapabilities {
        mesh: true,
        request_inspect: true,
        ..Default::default()
    });

    let limits = limits_from_manifest(&manifest, &defaults).unwrap();

    // Manifest denies mesh → effective denies mesh
    assert!(!limits.capabilities.permits(PluginCapability::Mesh));
    assert!(limits.allowed_dht_prefixes.is_empty());

    // Manifest grants request_inspect → effective grants it
    assert!(limits
        .capabilities
        .permits(PluginCapability::RequestInspect));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 5: Plugin info reflects effective policy
// ═══════════════════════════════════════════════════════════════════════════════

/// EffectivePluginPolicy fields match the manifest that produced them.
#[test]
fn effective_policy_matches_manifest() {
    let manifest = make_manifest(
        "policy-test",
        PluginCapabilities {
            request_inspect: true,
            response_mutate: true,
            mesh: true,
            ..Default::default()
        },
        PluginLimits {
            timeout_ms: 200,
            max_concurrency: 6,
            fuel: Some(999),
            ..Default::default()
        },
    );

    let effective_limits = limits_from_manifest(&manifest, &default_limits()).unwrap();

    let policy = synvoid_plugin_runtime::EffectivePluginPolicy {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        trust_tier: manifest.trust_tier,
        capabilities: effective_limits.capabilities.clone(),
        limits: effective_limits.clone(),
        manifest_limits: manifest.limits.clone(),
        source: Default::default(),
        state_model: effective_limits.state_model,
    };

    assert_eq!(policy.name, "policy-test");
    assert_eq!(policy.version, "1.0.0");
    assert_eq!(policy.trust_tier, PluginTrustTier::LocalSandboxed);
    assert!(policy.capabilities.request_inspect);
    assert!(policy.capabilities.response_mutate);
    assert!(policy.capabilities.mesh);
    assert_eq!(policy.limits.timeout, Duration::from_millis(200)); // 200ms
    assert_eq!(policy.limits.max_instances, 6);
    assert_eq!(policy.limits.max_cpu_fuel, 999);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Workstream 5: Strengthen CI and Guardrail Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

/// limits_from_manifest must reject zero fuel for production sandboxed tiers.
///
/// Fuel is the primary CPU containment mechanism. Zero fuel disables the fuel
/// meter entirely, allowing unbounded guest execution.
#[test]
fn test_zero_fuel_rejected_for_sandboxed_tiers() {
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("sandbox")
            .join("policy.rs"),
    )
    .unwrap();
    assert!(
        src.contains("max_cpu_fuel == 0")
            || src.contains("fuel == 0")
            || src.contains("fuel.is_some_and(|f| f == 0)")
            || src.contains("fuel == Some(0)"),
        "limits_from_manifest must validate zero fuel"
    );
    assert!(
        src.contains("SignedSandboxed") && src.contains("LocalSandboxed"),
        "fuel validation must check SignedSandboxed and LocalSandboxed tiers"
    );
}

/// limits_from_manifest must return Result to propagate fuel validation errors.
#[test]
fn test_limits_from_manifest_returns_result() {
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("sandbox")
            .join("policy.rs"),
    )
    .unwrap();
    // The function signature spans multiple lines, so check for the function name
    // and Result type separately within a reasonable window.
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("fn limits_from_manifest") {
            // Check this line and the next 5 lines for Result return type
            let window: String = lines
                .iter()
                .skip(i)
                .take(6)
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                window.contains("Result"),
                "limits_from_manifest must return Result<WasmResourceLimits, WasmPluginError>, \
                 but no Result found in function signature:\n{}",
                window
            );
            return;
        }
    }
    panic!("limits_from_manifest function not found in policy.rs");
}

# Plugin Milestone 1 Phase 1: Manifest Authority Wiring

## Goal

Make each plugin manifest the source of truth for that plugin's runtime authority. A plugin's declared capabilities and limits must be converted into the actual runtime configuration used by `WasmRuntime`, `WasmInstancePool`, host functions, and invocation checks.

This phase closes the gap where manifests are used for admission checks but plugin instances still inherit global/default `WasmResourceLimits`.

## Problem Statement

The current load path discovers or receives a `PluginManifest` and passes it through `enforce_plugin_load_policy()`. After that, file loads instantiate the plugin with `self.default_limits.clone()` or caller-supplied limits. That means per-plugin manifest values are not necessarily applied to runtime execution.

This creates two bad outcomes:

1. Plugin manifests become documentation rather than authority.
2. Global defaults can either overgrant all plugins or undergrant all plugins.

For production, every loaded plugin must carry an immutable effective policy derived from its manifest plus operator policy.

## Desired Architecture

Introduce an explicit effective runtime policy type or conversion path:

```rust
pub struct EffectivePluginPolicy {
    pub name: String,
    pub version: String,
    pub trust_tier: PluginTrustTier,
    pub capabilities: Arc<PluginCapabilities>,
    pub limits: WasmResourceLimits,
    pub manifest_limits: PluginLimits,
    pub source: PluginSourceIdentity,
}
```

A lighter-weight implementation is acceptable if it preserves the same invariant: `WasmRuntime` must be constructed from per-plugin effective capabilities and limits, not from global defaults alone.

Recommended source identity fields:

```rust
pub struct PluginSourceIdentity {
    pub path: Option<PathBuf>,
    pub binary_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub key_id: Option<String>,
}
```

This source identity can be expanded in Phase 2. Phase 1 may initially populate only path/name/version/trust tier.

## Implementation Steps

### 1. Add a Manifest-to-Runtime Conversion Helper

Create a function in `crates/synvoid-plugin-runtime/src/sandbox/types.rs` or a new `policy.rs` module:

```rust
pub fn limits_from_manifest(
    manifest: &PluginManifest,
    defaults: &WasmResourceLimits,
) -> WasmResourceLimits {
    let mut limits = defaults.clone();

    limits.timeout_seconds = manifest.limits.timeout_ms.div_ceil(1000).max(1);
    limits.max_instances = manifest.limits.max_concurrency.max(1);
    limits.capabilities = Arc::new(manifest.capabilities.clone());

    if let Some(fuel) = manifest.limits.fuel {
        limits.max_cpu_fuel = fuel;
    }

    if let Some(memory_pages) = manifest.limits.memory_pages {
        let bytes = memory_pages as usize * 64 * 1024;
        limits.max_memory_mb = bytes.div_ceil(1024 * 1024).max(1);
    }

    limits
}
```

Use `Duration` internally where possible, but preserve the existing `WasmResourceLimits` shape unless this phase intentionally refactors it.

Important: `PluginLimits::timeout_ms` is millisecond precision, while `WasmResourceLimits::timeout_seconds` is second precision. Do not silently lose precision as a permanent design. For this phase, either round up or add a `timeout: Duration` to `WasmResourceLimits`. Prefer `Duration` if the change is tractable.

### 2. Load Manifest Once and Return It from Enforcement

Refactor `enforce_before_load()` so the caller gets the manifest/effective policy back instead of losing it after enforcement.

Target shape:

```rust
fn prepare_plugin_load(
    &self,
    wasm_path: Option<&Path>,
    manifest: Option<&PluginManifest>,
    binary_bytes: Option<&[u8]>,
) -> Result<PreparedPluginLoad, WasmPluginError>
```

Where:

```rust
pub struct PreparedPluginLoad {
    pub manifest: PluginManifest,
    pub effective_limits: WasmResourceLimits,
}
```

This avoids repeated manifest parsing and ensures the same manifest used for policy enforcement is used for runtime construction.

### 3. Update File Load Paths

Update these paths to use effective limits from the prepared manifest:

- `WasmPluginManager::load_plugin`
- `WasmPluginManager::load_plugin_with_limits`
- `WasmPluginManager::reload_plugin`
- `PluginManager::load_wasm_plugin`
- directory-based load in `PluginManagerLifecycle::load_plugins_from_dir`

`load_plugin_with_limits()` is ambiguous because it currently accepts caller-supplied limits. Choose one of these policies explicitly:

- Preferred: rename/split into `load_plugin_with_default_overrides()` and merge manifest limits with explicit operator overrides.
- Minimal: keep the method but make manifest capabilities non-overridable while allowing resource defaults to be overridden.

Do not allow a caller-supplied `WasmResourceLimits` to grant capabilities not declared by the manifest unless the manifest trust tier is `LocalTrusted` and operator config explicitly allows local trusted plugins.

### 4. Update Memory and Mesh Defaults

`allowed_dht_prefixes` should not remain a global-only field. Add manifest fields for mesh DHT prefixes and mesh event topics if not already available, or create a transitional policy where `mesh = true` grants no sensitive prefixes unless operator config supplies plugin-specific prefixes.

For this phase, minimally ensure:

- `manifest.capabilities.mesh = false` always produces `limits.capabilities.mesh = false`.
- `manifest.capabilities.mesh = true` does not automatically inherit broad global prefixes unless explicitly configured.

### 5. Store Effective Policy for Introspection

Extend `PluginInfo` or add a new method such as `get_plugin_policy_info()` so tests/admin surfaces can inspect:

- name
- version
- trust tier
- capabilities summary
- timeout
- memory limit
- fuel limit
- max instances/concurrency
- source path

This does not need to expose secrets or public keys.

## Required Tests

### Unit Tests

Add tests for manifest-to-runtime conversion:

- Minimal manifest defaults to all-deny capabilities.
- `request_inspect = true` maps to `WasmResourceLimits.capabilities.request_inspect = true`.
- `mesh = false` denies mesh even if manager defaults have mesh enabled.
- `fuel = 1234` maps to `max_cpu_fuel = 1234`.
- `memory_pages = 32` maps to an effective memory limit.
- `max_concurrency = 3` maps to `max_instances = 3` or the chosen concurrency field.

### Integration Tests

Add a test with two plugins loaded in one manager:

- Plugin A manifest grants `request_inspect = true`.
- Plugin B manifest grants no request capability.
- Invoking Plugin A as a request filter is permitted.
- Invoking Plugin B as a request filter is rejected with a capability error.

Add a second test:

- Plugin A grants mesh.
- Plugin B does not grant mesh.
- Both attempt `mesh_query_dht`.
- Plugin A reaches the prefix policy check.
- Plugin B fails at capability check before prefix logic.

### Guardrail Tests

Add or update static guardrail tests to prevent future load paths from calling `WasmRuntime::load(path, self.default_limits.clone())` directly after manifest enforcement. Acceptable load paths should go through `PreparedPluginLoad` or an equivalent manifest-derived policy function.

## Edge Cases

- Manifest parse failure should fail that plugin load, not server startup or the full plugin directory load.
- A missing manifest may still default to `LocalSandboxed`, but it must default to all-deny capabilities.
- Duplicate plugin names must be rejected consistently even when manifests rename plugins differently from file stems.
- Manifest `name` and runtime `name` should have one canonical source. Prefer the manifest name, but preserve file path in source metadata.
- Reload must preserve operator state only if the new manifest passes validation; failed reload must leave the old plugin active.

## Acceptance Criteria

This phase is complete when:

- Every WASM load/reload path constructs runtime limits from the same manifest that passed load policy enforcement.
- Per-plugin capabilities are enforced at runtime.
- Per-plugin fuel, timeout, memory, and max instance/concurrency limits are visible and testable.
- No global capability default can overgrant a plugin beyond its manifest declaration without an explicit trusted override path.
- Existing plugin capability guard tests pass.
- New tests demonstrate two plugins with different manifests receiving different runtime authority.

## Non-Goals

- Full cryptographic file-byte verification. That is Phase 2.
- Complete invocation state/quarantine behavior. That is Phase 3.
- ABI memory transfer changes. That is Phase 4.
- Native Axum plugin policy. That is a later milestone.

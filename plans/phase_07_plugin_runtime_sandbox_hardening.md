# Phase 7 Plan: Plugin Runtime, Sandbox, and Capability Manifest Hardening

Status: detailed handoff plan.

Roadmap position: Phase 7 of `plans/roadmap.md`.

Primary goal: make plugins an explicit extension boundary with trust tiers, manifests, default-deny capabilities, lifecycle ownership, failure isolation, and production signing policy.

## Context

The server lifecycle pass made plugin hot-reload ownership structurally safer by keeping `PluginRuntimeOwner` alive for the full server runtime. This phase hardens the plugin trust and execution boundary itself.

SynVoid has WASM/plugin runtime pieces and hot-reload behavior. The security risk is not only task ownership; it is ambient authority. Plugins should not implicitly gain filesystem, network, mesh, admin, persistence, metrics, or request-mutation privileges merely because they load successfully.

## Non-Goals

Do not design a full plugin marketplace.

Do not require signing for development hot-reload mode.

Do not implement Python/pyo3 plugins.

Do not expose mesh/admin capabilities to plugins unless explicitly declared and default-denied.

Do not rewrite the WASM runtime unless a minimal capability gate cannot be added otherwise.

## Deliverables

1. Plugin trust tier model.
2. Plugin manifest schema with declared capabilities.
3. Default-deny capability checks at plugin load and runtime call sites.
4. Production signing verification path or explicit production-disabled unsigned policy.
5. Resource limits: timeout, memory/fuel if supported, input/output size, concurrency.
6. Failure isolation: plugin failure disables/degrades that plugin without poisoning the server runtime.
7. Guardrails preventing ambient capability additions.
8. Architecture doc: `architecture/plugin_runtime_sandbox.md`.

## Phase A: Inventory Plugin Runtime Surfaces

Run:

```bash
rg "Plugin|plugin|wasm|WASM|hot_reload|capability|manifest|load_plugins|GlobalPluginManager|PluginManagerLifecycle" src crates examples architecture tests
rg "filesystem|fs::|std::fs|network|TcpStream|UdpSocket|reqwest|hyper|mesh|admin|metrics|persistence" src/plugin crates/synvoid-plugin-runtime
```

Create an inventory table in `architecture/plugin_runtime_sandbox.md`:

```markdown
| Surface | File | Current authority | Target capability | Notes |
|---------|------|-------------------|-------------------|-------|
| request inspection | ... | implicit | request_inspect | |
| request mutation | ... | implicit | request_mutate | |
| filesystem | ... | unknown | filesystem_read/write | default denied |
```

Classify plugin entry points:

- request inspection,
- request mutation,
- response inspection,
- response mutation,
- metrics emission,
- persistence,
- filesystem,
- network,
- mesh/DHT,
- admin/control-plane events,
- hot-reload/development only.

## Phase B: Define Trust Tiers

Add a type near plugin runtime configuration. Prefer a shared plugin runtime crate if one exists; otherwise `src/plugin/trust.rs` or `crates/synvoid-plugin-runtime/src/trust.rs`.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PluginTrustTier {
    Disabled,
    LocalTrusted,
    LocalSandboxed,
    SignedSandboxed,
    DevelopmentHotReload,
}
```

Semantics:

- `Disabled`: plugin cannot load.
- `LocalTrusted`: local operator explicitly trusts plugin; still bounded by declared capabilities where practical.
- `LocalSandboxed`: unsigned local plugin, sandbox limits enforced, restricted capabilities.
- `SignedSandboxed`: signature verified and sandbox limits enforced.
- `DevelopmentHotReload`: development-only, permissive reload, must not be enabled in production mode unless explicit config override.

Add config mapping from existing plugin config to trust tier. Preserve backwards compatibility by defaulting old configs to the safest practical tier. If existing behavior was permissive, require a compatibility warning.

## Phase C: Define Manifest Schema

Add a manifest file format, preferably TOML or JSON. Example: `synvoid-plugin.toml` next to the plugin module.

```toml
name = "example-plugin"
version = "0.1.0"
entry = "plugin.wasm"
trust_tier = "LocalSandboxed"

[capabilities]
request_inspect = true
request_mutate = false
response_inspect = true
response_mutate = false
metrics = true
persistence = false
filesystem_read = []
filesystem_write = []
network = []
mesh = false
admin_events = false

[limits]
timeout_ms = 50
max_input_bytes = 262144
max_output_bytes = 262144
max_concurrency = 4
memory_pages = 64
fuel = 1000000
```

Rust type:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub entry: String,
    pub trust_tier: PluginTrustTier,
    pub capabilities: PluginCapabilities,
    pub limits: PluginLimits,
    pub signature: Option<PluginSignatureConfig>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PluginCapabilities {
    pub request_inspect: bool,
    pub request_mutate: bool,
    pub response_inspect: bool,
    pub response_mutate: bool,
    pub metrics: bool,
    pub persistence: bool,
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    pub network: Vec<String>,
    pub mesh: bool,
    pub admin_events: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginLimits {
    pub timeout_ms: u64,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_concurrency: usize,
    pub memory_pages: Option<u32>,
    pub fuel: Option<u64>,
}
```

Manifest parse failure should fail plugin load, not server startup, unless configured fail-closed.

## Phase D: Default-Deny Capability Enforcement

Add a `PluginCapabilitySet` runtime representation and require call sites to check before invoking capability-sensitive hooks.

Example:

```rust
impl PluginCapabilities {
    pub fn permits(&self, capability: PluginCapability) -> bool {
        match capability {
            PluginCapability::RequestInspect => self.request_inspect,
            PluginCapability::RequestMutate => self.request_mutate,
            PluginCapability::Mesh => self.mesh,
            PluginCapability::AdminEvents => self.admin_events,
            // ...
        }
    }
}
```

Enforcement points:

- Request inspect hook requires `request_inspect`.
- Request mutation hook requires `request_mutate`.
- Response inspect hook requires `response_inspect`.
- Response mutation hook requires `response_mutate`.
- Metrics API requires `metrics`.
- Persistence API requires `persistence`.
- Filesystem access requires path allowlist and canonicalization.
- Network access requires destination allowlist.
- Mesh/admin access should remain disabled unless explicitly supported; guard against accidental exposure.

Filesystem rules:

- Canonicalize paths.
- Reject symlink escape from allowed root.
- Deny absolute paths unless explicitly configured.
- Separate read/write allowlists.

Network rules:

- Default deny.
- If allowed, require host/port allowlist.
- Avoid DNS wildcard semantics unless implemented carefully.

## Phase E: Resource Limits

Enforce limits at plugin invocation boundaries.

Minimum limits:

- timeout per invocation,
- max input size,
- max output size,
- max concurrent invocations per plugin.

If WASM runtime supports memory/fuel:

- set memory pages limit,
- set fuel limit,
- fail closed on unsupported hard limits unless trust tier is `LocalTrusted` and config explicitly allows fallback.

Example wrapper:

```rust
async fn invoke_with_limits<F, T>(
    plugin: &LoadedPlugin,
    capability: PluginCapability,
    input_len: usize,
    fut: F,
) -> Result<T, PluginInvokeError>
where
    F: Future<Output = Result<T, PluginInvokeError>>,
{
    plugin.capabilities.require(capability)?;
    plugin.limits.check_input(input_len)?;
    let _permit = plugin.concurrency.acquire().await?;
    tokio::time::timeout(plugin.limits.timeout(), fut)
        .await
        .map_err(|_| PluginInvokeError::Timeout)?
}
```

## Phase F: Signing Policy

Add signing verification for `SignedSandboxed` or document explicit production block for unsigned plugins.

Preferred model:

- Manifest includes signature metadata.
- Signature covers plugin binary hash and manifest fields.
- Trusted public keys are configured in server config.
- Verification happens before plugin instantiation.

If full signing is too large, implement this policy now:

- `SignedSandboxed` requires signature and fails load if verification unavailable.
- `DevelopmentHotReload` requires `dev_mode = true` or equivalent explicit config.
- Production mode rejects unsigned plugins unless `allow_unsigned_plugins = true` is set with warning.

Do not silently accept unsigned plugins in production defaults.

## Phase G: Failure Isolation

Define plugin failure state:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginRuntimeState {
    Loaded,
    DisabledByConfig,
    DisabledByCapabilityViolation,
    DisabledByLoadError,
    DisabledByRuntimeFailure,
    Quarantined,
}
```

Behavior:

- Capability violation disables or rejects that invocation; repeated violations quarantine plugin.
- Timeout increments failure counter; threshold disables plugin.
- Panic/trap disables plugin instance and optionally reloads clean instance under backoff.
- Plugin failure should not fail the whole request unless hook is configured fail-closed.
- Fail-open/fail-closed policy must be explicit per hook or plugin category.

## Phase H: Guardrails

Add `tests/plugin_capability_boundary_guard.rs`.

Guard checks:

- No new plugin runtime API exposes filesystem/network/mesh/admin without capability token check.
- Manifest schema docs include every `PluginCapability` variant.
- Development hot reload cannot be enabled without explicit dev-mode check.
- No `unwrap()`/`expect()` in plugin manifest parsing paths that can be triggered by plugin files.
- No `mem::forget` or detached hot-reload watcher ownership regression.

Use narrow allowlists with liveness checks.

## Phase I: Tests

Unit tests:

- `manifest_parses_minimal_valid_plugin`
- `manifest_missing_capabilities_defaults_deny`
- `manifest_invalid_entry_rejected`
- `filesystem_path_canonicalization_rejects_escape`
- `network_default_denied`
- `request_mutation_denied_without_capability`
- `timeout_disables_or_reports_plugin`
- `concurrency_limit_enforced`
- `development_hot_reload_requires_dev_mode`
- `signed_sandboxed_requires_signature`
- `plugin_failure_does_not_poison_manager`

Integration-style tests if feasible:

- load a test WASM plugin with inspect-only capability,
- verify mutation hook denied,
- verify output size limit,
- verify hot-reload owner survives server runtime setup.

## Phase J: Documentation

Create `architecture/plugin_runtime_sandbox.md`.

Include:

- trust tiers,
- manifest schema,
- capability list,
- default-deny rules,
- resource limits,
- signing policy,
- failure isolation,
- production/development differences,
- known deferred items.

Update `AGENTS.md` with:

```bash
cargo test --test plugin_capability_boundary_guard
```

## Verification Commands

```bash
cargo fmt --all -- --check
cargo check --no-default-features --features mesh,dns
cargo check
cargo test --test plugin_capability_boundary_guard
cargo test -p synvoid --lib plugin
cargo test -p synvoid-plugin-runtime
cargo test -p synvoid --lib server::plugin_runtime
cargo test --test unified_server_lifecycle_ownership_guard
```

Adjust names to actual crate/module paths.

## Acceptance Criteria

This phase is complete when:

- Every loaded plugin has a manifest or an explicit compatibility failure path.
- Capability defaults are deny.
- Request/response mutation requires declared capability.
- Filesystem/network/mesh/admin access is denied unless explicitly declared and implemented safely.
- Production signing policy is explicit.
- Plugin invocation has timeout, size, and concurrency limits.
- Plugin failure is isolated to plugin state, not server runtime failure, unless fail-closed is configured.
- Hot reload remains owned by server lifecycle.
- Guardrails prevent ambient capability expansion.

## Handoff Notes

Start with manifest parsing and capability checks. Do not attempt full signing and WASM runtime refactor in the same first patch if it becomes too large.

Default-deny is more important than feature richness. It is acceptable for this phase to deny capabilities that are not yet safely implemented.

# Plugin Runtime Sandbox Hardening (Phase 7)

SynVoid's plugin system runs WASM modules in a sandboxed runtime with explicit trust tiers, a default-deny capability manifest, resource limits, signing policy, and failure isolation. Plugins never inherit ambient authority from the server process.

## Trust Tiers

The `PluginTrustTier` enum controls what a plugin can request and how strictly its sandbox is enforced. Defined in `crates/synvoid-plugin-runtime/src/sandbox/types.rs`.

| Variant | Semantics |
|---------|-----------|
| `Disabled` | Plugin cannot load. Safest default for unknown configs. |
| `LocalTrusted` | Local operator explicitly trusts the plugin; still bounded by declared capabilities where practical. |
| `LocalSandboxed` | **Default.** Unsigned local plugin with sandbox limits enforced and restricted capabilities. |
| `SignedSandboxed` | Signature verified and sandbox limits enforced. |
| `DevelopmentHotReload` | Development-only: permissive reload, must not be enabled in production mode unless explicit config override is set. |

Serialization uses `snake_case` (`"local_sandboxed"`, `"signed_sandboxed"`, etc.).

## Manifest Schema

Each plugin provides a `synvoid-plugin.toml` manifest. The `PluginManifest` struct is parsed via `toml::from_str` with validation for non-empty `name` and `entry`.

```toml
name = "example-plugin"
version = "0.1.0"
entry = "plugin.wasm"
trust_tier = "local_sandboxed"

[capabilities]
request_inspect = true
request_mutate = false
response_inspect = true
response_mutate = false
metrics = true
persistence = false
filesystem_read = []        # path allowlist (e.g. ["/tmp/cache/*"])
filesystem_write = []       # path allowlist
network = []                # host:port allowlist (e.g. ["api.example.com:443"])
mesh = false
admin_events = false

[limits]
timeout_ms = 50
max_input_bytes = 262144    # 256 KB
max_output_bytes = 262144   # 256 KB
max_concurrency = 4
memory_pages = 64           # optional, 64 KiB per page
fuel = 1000000              # optional, wasmtime fuel

[signature]
signature = "abcd1234..."
key_id = "key1"
algorithm = "ed25519"
```

Manifest parse failure fails plugin load, not server startup.

## Capability Model

The `PluginCapability` enum defines 11 fine-grained capability tokens. `PluginCapabilities` is a default-deny struct where every field must be explicitly granted.

| Capability | Type | Description |
|------------|------|-------------|
| `RequestInspect` | `bool` | Read-only inspection of incoming requests. |
| `RequestMutate` | `bool` | Mutation of incoming request headers/body. |
| `ResponseInspect` | `bool` | Read-only inspection of outgoing responses. |
| `ResponseMutate` | `bool` | Mutation of outgoing response headers/body. |
| `Metrics` | `bool` | Emit metrics (counters, gauges). |
| `Persistence` | `bool` | Access to the persistence API (KV store). |
| `FilesystemRead` | `Vec<String>` | Read from the filesystem (path allowlisted). |
| `FilesystemWrite` | `Vec<String>` | Write to the filesystem (path allowlisted). |
| `Network` | `Vec<String>` | Outbound network access (host/port allowlisted). |
| `Mesh` | `bool` | Access to mesh DHT queries. |
| `AdminEvents` | `bool` | Receive admin/control-plane events. |

### Default-Deny Rules

- All boolean capabilities default to `false`.
- All path/host allowlists default to empty (`Vec::new()`).
- `permits()` returns `true` only when the capability is explicitly enabled (bool `true` or non-empty allowlist).
- `require()` returns `Err(CapabilityViolation)` on denial.

### Enforcement Points

- Request inspect hook → `request_inspect`
- Request mutation hook → `request_mutate`
- Response inspect hook → `response_inspect`
- Response mutation hook → `response_mutate`
- Metrics API → `metrics`
- Persistence API → `persistence`
- Filesystem access → `filesystem_read` / `filesystem_write` (plus path canonicalization and allowlist check)
- Network access → `network` (host/port allowlist)
- Mesh/admin access → `mesh` / `admin_events` (explicit only, guarded against accidental exposure)

### Filesystem Rules

- Canonicalize paths before checking allowlists.
- Reject symlink escape from allowed root.
- Deny absolute paths unless explicitly configured.
- Separate read/write allowlists.

### Network Rules

- Default deny.
- If allowed, require host/port allowlist.
- Avoid DNS wildcard semantics unless implemented carefully.

## Resource Limits

`PluginLimits` is enforced at plugin invocation boundaries. All fields have safe defaults.

| Field | Default | Description |
|-------|---------|-------------|
| `timeout_ms` | `50` | Per-invocation timeout in milliseconds. |
| `max_input_bytes` | `262144` (256 KB) | Maximum input payload size. |
| `max_output_bytes` | `262144` (256 KB) | Maximum output payload size. |
| `max_concurrency` | `4` | Maximum concurrent invocations (backed by `tokio::sync::Semaphore`). |
| `memory_pages` | `None` | Optional WASM linear memory page limit (64 KiB per page). |
| `fuel` | `None` | Optional wasmtime fuel limit per invocation. |

Enforcement uses `check_input()`, `check_output()`, `timeout()`, and a semaphore permit acquired before each invocation.

## Signing Policy

`SigningPolicy` controls production signing enforcement:

| Policy | Behavior |
|--------|----------|
| `RequireSigned` | **Default.** Reject unsigned plugins; require valid signature. |
| `AllowUnsignedWithWarning` | Allow unsigned plugins with a warning. |
| `Disabled` | Development mode: signing not checked. |

The `verify_signing_policy()` function enforces:

- In development mode (`is_production = false`), signing is never enforced.
- In production with `RequireSigned`, plugins must have a `PluginSignatureConfig` or be rejected.
- `SignedSandboxed` trust tier with `RequireSigned` requires a signature.
- `DevelopmentHotReload` requires explicit dev-mode config externally.

Signature covers plugin binary hash and manifest fields. Trusted public keys are configured in server config. Full cryptographic verification is implemented in Phase 13 using Ed25519 via `ed25519-dalek`. The `verify_plugin_signature()` function verifies binary hashes, manifest hashes, and Ed25519 signatures against configured trusted keys.

### PluginSignatureConfig

```rust
pub struct PluginSignatureConfig {
    pub signature: String,    // hex-encoded Ed25519 signature
    pub key_id: String,       // public key identifier
    pub algorithm: String,    // "ed25519"
    pub binary_sha256: String, // SHA-256 hex digest of the plugin binary
    pub manifest_sha256: String, // SHA-256 hex digest of the canonical manifest payload
}
```

## Signature Verification (Phase 13)

The `verify_plugin_signature()` function performs full cryptographic verification:

1. Checks that `SignedSandboxed` plugins have a `[signature]` block.
2. Computes SHA-256 of the plugin binary and compares to `binary_sha256`.
3. Computes a canonical manifest signing payload (deterministic, excludes signature field) and SHA-256 hash, compares to `manifest_sha256`.
4. Resolves the trusted public key by `key_id` from `PluginLoadConfig.trusted_keys`.
5. Verifies the Ed25519 signature against the canonical manifest payload.

### Canonical Manifest Payload

The signing payload is a deterministic text format:
```
name={name}
version={version}
entry={entry}
trust_tier={trust_tier}
cap_{Capability}={enabled}
...
timeout_ms={timeout_ms}
max_input_bytes={max_input_bytes}
max_output_bytes={max_output_bytes}
max_concurrency={max_concurrency}
```

Capability flags are sorted alphabetically. Optional fields (`memory_pages`, `fuel`) are included only when present.

### Loader Enforcement

The `enforce_plugin_load_policy()` function enforces trust-tier rules at every plugin load path:

| Trust Tier | Enforcement |
|------------|-------------|
| `Disabled` | Always rejected |
| `SignedSandboxed` | Requires verified signature; fails closed if verification unavailable |
| `DevelopmentHotReload` | Requires `dev_mode = true` in `PluginLoadConfig` |
| `LocalTrusted` | Requires `allow_local_trusted = true` in `PluginLoadConfig` |
| `LocalSandboxed` | Permitted (unsigned, sandboxed) |

### Trusted Key Configuration

Trusted keys are configured in the plugin config:
```toml
[plugins]
dev_mode = false
allow_local_trusted = false

[[plugins.trusted_keys]]
key_id = "operator-key-1"
algorithm = "ed25519"
public_key = "base64-url-no-pad..."
```

Fail-closed rules:
- Missing key → rejected for `SignedSandboxed`
- Unknown key ID → rejected
- Malformed key → rejected
- Binary hash mismatch → rejected
- Manifest hash mismatch → rejected

## Failure Isolation

`PluginRuntimeState` tracks per-plugin lifecycle. A plugin failure disables or quarantines that plugin without poisoning the server runtime.

| State | Meaning |
|-------|---------|
| `Loaded` | Plugin loaded and ready (default). |
| `DisabledByConfig` | Plugin disabled by configuration. |
| `DisabledByCapabilityViolation` | Plugin disabled after a capability violation. |
| `DisabledByLoadError` | Plugin disabled after a load error. |
| `DisabledByRuntimeFailure` | Plugin disabled after a runtime failure (panic, trap, repeated timeout). |
| `Quarantined` | Plugin quarantined pending investigation. |

### Behavior

- Capability violation disables or rejects that invocation; repeated violations quarantine the plugin.
- Timeout increments a failure counter; at a configurable threshold the plugin transitions to `DisabledByRuntimeFailure`.
- Panic/trap disables the plugin instance and optionally reloads a clean instance under backoff.
- Plugin failure does not fail the whole request unless the hook is configured fail-closed.
- Fail-open/fail-closed policy is explicit per hook or plugin category.

### PluginInvocationGuard

The `PluginInvocationGuard` struct tracks per-plugin invocation state:

```rust
pub struct PluginInvocationGuard {
    pub capabilities: Arc<PluginCapabilities>,
    pub limits: PluginLimits,
    pub concurrency: Arc<Semaphore>,
    pub state: parking_lot::RwLock<PluginRuntimeState>,
    pub failure_count: parking_lot::RwLock<u32>,
}
```

Key methods:
- `is_invocable()` — returns `true` only when state is `Loaded`.
- `record_failure(threshold)` — increments failure count; disables at threshold.
- `reset_failures()` — resets counter and restores `Loaded`.
- `disable_for_violation()` — transitions to `DisabledByCapabilityViolation`.

## Production vs Development

| Aspect | Development | Production |
|--------|-------------|------------|
| Signing enforcement | Disabled | `RequireSigned` by default |
| `DevelopmentHotReload` tier | Permitted | Rejected unless explicit override |
| Mesh/admin capabilities in dev mode | Warned (non-fatal) | Rejected |
| Hot-reload | Permissive | Must be explicitly configured |
| Unsigned plugins | Allowed | Rejected or warned per policy |

## Known Deferred Items

- **Python/pyo3 plugins**: Not implemented. Plugin runtime is WASM-only.
- **Mesh/admin capabilities to plugins**: Explicitly default-denied. Not exposed unless future phases implement safe wrappers.
- **Full WASM runtime refactor**: Capability gates are added as a thin layer over the existing wasmtime runtime; no deep runtime changes were made.
- **Marketplace**: No plugin marketplace or registry.

## Plugin Runtime Surfaces

| Surface | File | Current Authority | Target Capability | Notes |
|---------|------|-------------------|-------------------|-------|
| Request inspection | `src/plugin/`, `src/worker/unified_server/` | implicit | `request_inspect` | |
| Request mutation | `src/plugin/`, `src/worker/unified_server/` | implicit | `request_mutate` | |
| Response inspection | `src/plugin/`, `src/worker/unified_server/` | implicit | `response_inspect` | |
| Response mutation | `src/plugin/`, `src/worker/unified_server/` | implicit | `response_mutate` | |
| Metrics emission | `src/plugin/` | implicit | `metrics` | |
| Persistence | `src/plugin/` | implicit | `persistence` | |
| Filesystem | `crates/synvoid-plugin-runtime/` | unknown | `filesystem_read` / `filesystem_write` | default denied, path allowlisted |
| Network | `crates/synvoid-plugin-runtime/` | unknown | `network` | default denied, host/port allowlisted |
| Mesh/DHT | `crates/synvoid-plugin-runtime/` | unknown | `mesh` | default denied |
| Admin/control-plane events | `crates/synvoid-plugin-runtime/` | unknown | `admin_events` | default denied |
| Hot-reload | `src/plugin/`, `src/server/` | lifecycle-owned | development-only | guarded by `PluginRuntimeOwner` |

## Guardrails

The `plugin_capability_boundary_guard` test suite (`tests/plugin_capability_boundary_guard.rs`) enforces:

- No plugin runtime API exposes filesystem/network/mesh/admin without capability token check.
- Manifest parsing never uses `unwrap()`/`expect()` on untrusted input.
- No `mem::forget` in plugin runtime source.
- Hot-reload watcher not detached (secondary guard to `unified_server_lifecycle_ownership_guard`).
- All 11 `PluginCapability` variants have corresponding `permits()` arms.
- `PluginCapabilities` default is all-deny.
- `DevelopmentHotReload` requires explicit config.

```bash
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
```

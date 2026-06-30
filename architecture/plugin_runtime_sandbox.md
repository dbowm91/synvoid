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

### Manifest-to-Runtime Conversion (M1 Phase 01)

`limits_from_manifest(manifest, defaults) -> Result<WasmResourceLimits, WasmPluginError>` is the single conversion path from a plugin manifest to runtime resource limits. All load paths use this function; no load path bypasses it to apply raw default limits.

- **Capabilities** always come from the manifest's `[capabilities]` section, never from server defaults. The manifest is the authoritative source for what a plugin can do.
- **Timeout** is converted from milliseconds to `Duration` with sub-second precision. `Duration::from_millis(timeout_ms.max(1))` maps manifest timeout_ms directly to runtime duration (e.g., 50ms manifest timeout maps to 50ms runtime, not 1s).
- **Fuel** maps directly from `manifest.limits.fuel` if present; otherwise falls back to the provided default. **Zero fuel is rejected for `SignedSandboxed` and `LocalSandboxed` tiers** — these tiers require a non-zero fuel budget to enforce execution limits.
- **Memory pages** maps directly from `manifest.limits.memory_pages` if present; otherwise falls back to the provided default.
- **Max concurrency** maps directly from `manifest.limits.max_concurrency`; defaults apply only when the manifest omits the field.

The mesh capability declared in the manifest does **not** inherit global DHT prefix access. Mesh permission is scoped strictly to what the manifest declares; no ambient authority leaks from the server's own DHT configuration.

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

The `enforce_plugin_load_policy()` function enforces trust-tier rules at every plugin load path. It returns `Result<Option<VerifiedPluginSignature>, PluginLoadError>`.

| Trust Tier | Enforcement |
|------------|-------------|
| `Disabled` | Always rejected |
| `SignedSandboxed` | Requires verified signature; fails closed if verification unavailable |
| `DevelopmentHotReload` | Requires `dev_mode = true` in `PluginLoadConfig` |
| `LocalTrusted` | Requires `allow_local_trusted = true` in `PluginLoadConfig` |
| `LocalSandboxed` | Permitted (unsigned, sandboxed) |

### Prepared Plugin Load (M1 Phase 01)

`prepare_plugin_load()` is the canonical entry point that wraps load-policy enforcement and manifest-to-runtime conversion into a single atomic step. It returns a `PreparedPluginLoad` struct:

```rust
pub struct PreparedPluginLoad {
    pub manifest: PluginManifest,
    pub effective_limits: WasmResourceLimits,
    pub source: PluginSourceIdentity,
    pub wasm_bytes: bytes::Bytes,
    pub verified_signature: Option<VerifiedPluginSignature>,
}
```

All load paths must use `prepare_plugin_load()`:

| Load Path | Responsibility |
|-----------|---------------|
| `load_plugin()` | Standard filesystem load; calls `prepare_plugin_load()` |
| `load_plugin_with_limits()` | Load with overridden defaults; calls `prepare_plugin_load()` with custom defaults |
| `reload_plugin()` | Hot-reload path; calls `prepare_plugin_load()` to re-validate manifest and recompute limits |
| `load_plugin_from_memory()` | In-memory load (tests/embedded); calls `prepare_plugin_load()` with no filesystem source |

Bypassing `prepare_plugin_load()` to apply raw `default_limits` is a guardrail violation enforced by the `manifest_authority_load_path_guard` test.

### Signed Byte Loading and TOCTOU Closure (M1 Phase 02)

File-based plugin loading reads WASM bytes once into memory, verifies those bytes, and instantiates from the same verified byte slice. This closes time-of-check/time-of-use (TOCTOU) races between policy enforcement and instantiation.

**Load flow:**
1. Reject symlink plugin files (unless explicit operator policy permits them later).
2. Canonicalize the `.wasm` path.
3. Discover the manifest from the canonical path.
4. Parse and validate the manifest.
5. Read the WASM bytes into memory (one read).
6. Compute `binary_sha256` from those bytes.
7. Enforce load policy with `Some(&wasm_bytes)`.
8. Instantiate from the same verified bytes via `Module::from_binary()`.

`WasmRuntime::load_with_policy()` uses pre-read bytes from `PreparedPluginLoad` via `Module::from_binary` when available; falls back to `Module::from_file` only for legacy callers without prepared loads.

### Strict SignedSandboxed Verification (M1 Phase 02)

For `PluginTrustTier::SignedSandboxed`:
- A `[signature]` block is **required**.
- `binary_sha256` must be **non-empty** and must match the actual bytes.
- `manifest_sha256` must be **non-empty** and must match the canonical manifest signing payload.
- `key_id` must resolve to a trusted key.
- `algorithm` must be `ed25519`.
- The Ed25519 signature must verify.

Empty hash fields are rejected in production. If backwards compatibility is needed for development, gate it behind `dev_mode = true` and never under `SignedSandboxed` production semantics.

### VerifiedPluginSignature (M1 Phase 02)

`verify_plugin_signature()` now returns `VerifiedPluginSignature` instead of `PluginSignatureVerification::Valid`:

```rust
pub struct VerifiedPluginSignature {
    pub key_id: String,
    pub binary_sha256: String,
    pub manifest_sha256: String,
    pub algorithm: PluginSignatureAlgorithm,
}
```

This metadata is stored in `PreparedPluginLoad.verified_signature` and exposed in plugin info/audit logs for operator observability.

### enforce_plugin_load_policy Return Type (M1 Phase 02)

`enforce_plugin_load_policy()` now returns `Result<Option<VerifiedPluginSignature>, PluginLoadError>`:
- `SignedSandboxed` returns `Some(verified)` with the verification metadata.
- All other tiers return `None`.

### Memory/Mesh Loads Require Metadata (M1 Phase 02)

`load_plugin_from_memory_with_manifest()` is the production path for mesh-delivered or memory-loaded plugins. It accepts an explicit `PluginManifest` and enforces policy via `prepare_plugin_load()`.

The existing `load_plugin_from_memory()` defaults to `LocalSandboxed` with all-deny capabilities. It cannot produce `SignedSandboxed` semantics without a manifest.

### Atomic Reload (M1 Phase 02)

`reload_plugin()` implements atomic replacement:
1. Read bytes and verify signature via `prepare_plugin_load()`.
2. Instantiate new runtime from verified bytes.
3. Acquire write lock.
4. Replace old runtime with new runtime.
5. Invalidate sorted cache.

If the new load fails at any point, the old plugin remains active. This avoids the sequence: remove old → try to load new → fail → leave no plugin.

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

### Mandatory Invocation Guard (M1 Phase 03)

Every plugin invocation now goes through `PluginInvocationGuard` as the mandatory boundary. The guard enforces capability checks, input limits, concurrency limits, runtime state, failure counters, and disable/quarantine transitions in the hot path.

**Architecture:**

Each `WasmRuntime` owns an `Arc<PluginInvocationGuard>` and a `PluginFailurePolicy`:

```rust
pub struct WasmRuntime {
    // ... existing fields ...
    guard: Arc<PluginInvocationGuard>,
    failure_policy: PluginFailurePolicy,
}
```

**`PluginFailurePolicy`** controls failure handling thresholds:

| Field | Default | Description |
|-------|---------|-------------|
| `failure_threshold` | `5` | Consecutive failures before disabling |
| `timeout_threshold` | `3` | Timeouts before disabling |
| `capability_violation_disables` | `true` | Capability violations immediately disable |
| `fail_closed_on_filter_error` | `true` | Request filter failures block requests |
| `fail_closed_on_transform_error` | `false` | Response transform failures pass through |

**`PluginFailureClass`** classifies errors for policy decisions:

| Class | Counts as Failure | Is Timeout |
|-------|-------------------|------------|
| `CapabilityViolation` | No | No |
| `Timeout` | Yes | Yes |
| `FuelExhausted` | Yes | No |
| `GuestTrap` | Yes | No |
| `MemoryViolation` | Yes | No |
| `HostApiViolation` | Yes | No |
| `LoadError` | Yes | No |
| `OtherRuntimeError` | Yes | No |

**Invocation flow:**

1. Guard checks `is_invocable()` — disabled plugins are skipped/failed per policy
2. Guard checks capability via `require_any_capability()`
3. Guard checks input size via `limits.check_input()`
4. Guard acquires concurrency permit (try_acquire for sync, acquire for async)
5. Guest function executes
6. On error: `record_and_classify_failure()` increments counters and may disable the plugin
7. After guest call: `capability_violation` field in `RequestContext` is checked for host-function violations

**Host-function violation tracking:**

The per-request `RequestContext` (WASM store data) includes `capability_violation: Option<PluginCapability>`. Host functions that detect violations set this field. After guest invocation returns, the runtime checks this field and calls `guard.disable_for_violation()` if set.

**Manager introspection:**

`WasmPluginManager` exposes:
- `get_plugin_state(name)` → `Option<PluginRuntimeState>`
- `get_plugin_failure_count(name)` → `Option<u32>`
- `reset_plugin_failures(name)` → `Result<()>`
- `quarantine_plugin(name)` → `Result<()>`

**Tests:**

```bash
cargo test -p synvoid-plugin-runtime -- test_plugin_failure
cargo test -p synvoid-plugin-runtime -- test_classify_failure
cargo test -p synvoid-plugin-runtime -- test_guard_
cargo test -p synvoid-plugin-runtime -- test_manager_
cargo test -p synvoid-plugin-runtime -- test_require_any
```

### ABI Memory Boundary Hardening (M1 Phase 04)

The host/guest WASM pointer-length ABI is now deterministic, non-overlapping, bounds-checked, and safe against malformed guest pointers.

**Key changes:**

1. **Fixed-offset fallback removed.** `write_to_guest_memory()` requires `guest_alloc`/`guest_free` exports. Plugins without allocator exports fail at write time with `WasmPluginError::LoadFailed`. The old fallback of writing all buffers at offset `1024` is gone.

2. **`GuestAbiPolicy` enum.** Controls ABI validation strictness per trust tier:
   - `ProductionPointerLength` — requires both `guest_alloc` AND `guest_free` exports. Used for `SignedSandboxed` and `LocalSandboxed` tiers.
   - `DevelopmentAllowMissingFree` — allows plugins with only `guest_alloc` (no `guest_free`). Used for `DevelopmentHotReload` and dev/test compatibility.
   - `validate_for_policy(&self, policy: GuestAbiPolicy) -> Result<(), WasmPluginError>` validates a module against the specified policy.

3. **`GuestAbiInfo` struct.** Metadata describing a module's ABI exports. `validate_guest_abi(&Module)` returns this struct for introspection and testing (public function).

4. **Single-frame allocation.** All 4 invocation paths (`filter_request`, `transform_response`, `handler`, `streaming handler`) now allocate a single contiguous `GuestInputFrame` per request via `write_request_input_frame()`. The frame contains serialized headers, body, and metadata in one allocation. `free_guest_input_frame()` releases the frame after guest execution.

5. **`checked_guest_range()` function.** Validates guest pointer+length pairs against memory bounds using checked arithmetic. Used by all host functions that read/write guest memory.

6. **`GuestAllocation` tracking.** Each allocation is tracked for safe cleanup. `free_guest_memory()` takes `&GuestAllocation`, logs failures, and returns `bool` (false if `guest_free` traps). Trapped instances are not returned to the pool.

7. **`serialize_headers()` hardened.** Now returns `Result<Vec<u8>, WasmPluginError>`. Validates header count, name length, and value length against `u16::MAX`. Checks total encoded size against input limits.

8. **Host functions use checked arithmetic.** `get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event` all use `checked_guest_range` instead of `saturating_add` for bounds checking.

**Required WASM exports for pointer-length ABI:**

| Export | Required | Description |
|--------|----------|-------------|
| `memory` | Yes | Linear memory |
| `guest_alloc` | Yes | Guest-side allocation |
| `guest_free` | Yes (production) / Optional (dev) | Guest-side deallocation; required for `ProductionPointerLength` policy, optional for `DevelopmentAllowMissingFree` |
| `filter_request` | At least one | WAF filter hook |
| `transform_response` | At least one | Response transform hook |
| `handle_request` | At least one | Serverless handler hook |

**Tests:**

```bash
cargo test -p synvoid-plugin-runtime -- test_checked_guest_range
cargo test -p synvoid-plugin-runtime -- test_guest_abi_info
cargo test -p synvoid-plugin-runtime -- test_validate_guest_abi
cargo test -p synvoid-plugin-runtime -- test_serialize_headers_rejects
cargo test -p synvoid-plugin-runtime -- test_write_to_guest_memory_requires_allocator
cargo test -p synvoid-plugin-runtime -- test_allocator_plugin_receives_distinct_ranges
cargo test -p synvoid-plugin-runtime -- test_guest_abi_policy
cargo test -p synvoid-plugin-runtime -- test_single_frame_allocation
cargo test --test abi_memory_boundary_guard
```

**Guardrail:** The `abi_memory_boundary_guard` test suite verifies the fixed-offset fallback is removed, `guest_alloc` is required, `GuestAbiPolicy` validation, single-frame allocation, `checked_guest_range` is defined, `serialize_headers` returns `Result`, and `GuestAllocation` exists.

## Production vs Development

| Aspect | Development | Production |
|--------|-------------|------------|
| Signing enforcement | Disabled | `RequireSigned` by default |
| `DevelopmentHotReload` tier | Permitted | Rejected unless explicit override |
| Mesh/admin capabilities in dev mode | Warned (non-fatal) | Rejected |
| Hot-reload | Permissive | Must be explicitly configured |
| Unsigned plugins | Allowed | Rejected or warned per policy |
| ABI policy | `DevelopmentAllowMissingFree` (guest_free optional) | `ProductionPointerLength` (guest_alloc+guest_free required) |
| Fuel budget | Optional (zero allowed) | Required non-zero for sandboxed tiers |

## Known Deferred Items

- **Python/pyo3 plugins**: Not implemented. Plugin runtime is WASM-only.
- **Mesh/admin capabilities to plugins**: Explicitly default-denied. Not exposed unless future phases implement safe wrappers.
- **Marketplace**: No plugin marketplace or registry.

## Plugin Runtime Surfaces

| Surface | File | Current Authority | Target Capability | Notes |
|---------|------|-------------------|-------------------|-------|
| Request inspection | `src/plugin/`, `src/worker/unified_server/` | manifest-derived via `EffectivePluginPolicy` | `request_inspect` | |
| Request mutation | `src/plugin/`, `src/worker/unified_server/` | manifest-derived via `EffectivePluginPolicy` | `request_mutate` | |
| Response inspection | `src/plugin/`, `src/worker/unified_server/` | manifest-derived via `EffectivePluginPolicy` | `response_inspect` | |
| Response mutation | `src/plugin/`, `src/worker/unified_server/` | manifest-derived via `EffectivePluginPolicy` | `response_mutate` | |
| Metrics emission | `src/plugin/` | manifest-derived via `EffectivePluginPolicy` | `metrics` | |
| Persistence | `src/plugin/` | manifest-derived via `EffectivePluginPolicy` | `persistence` | |
| Filesystem | `crates/synvoid-plugin-runtime/` | manifest-derived via `EffectivePluginPolicy` | `filesystem_read` / `filesystem_write` | default denied, path allowlisted |
| Network | `crates/synvoid-plugin-runtime/` | manifest-derived via `EffectivePluginPolicy` | `network` | default denied, host/port allowlisted |
| Mesh/DHT | `crates/synvoid-plugin-runtime/` | manifest-derived via `EffectivePluginPolicy` | `mesh` | default denied, no ambient DHT prefix |
| Admin/control-plane events | `crates/synvoid-plugin-runtime/` | manifest-derived via `EffectivePluginPolicy` | `admin_events` | default denied |
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
- GuestAbiPolicy is enforced: production requires both `guest_alloc` and `guest_free`.
- Single-frame allocation is used for all invocation paths.
- Zero fuel is rejected for sandboxed tiers.

```bash
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test abi_memory_boundary_guard
```

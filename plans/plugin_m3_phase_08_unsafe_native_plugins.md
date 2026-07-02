# Plugin Milestone 3 Phase 8: Unsafe Native Plugin Containment

## Goal

Reclassify and harden native Axum/shared-library plugins as explicitly unsafe native extensions, not sandboxed plugins. Native code loaded into the Synvoid process has process-equivalent authority: memory access, arbitrary syscalls, panic/UB potential, allocator interaction, thread spawning, and access to all linked process state. This phase makes that authority explicit, difficult to enable accidentally, and operationally auditable.

Milestones 1 and 2 hardened WASM plugins as the production sandbox path. Phase 8 separates that sandboxed path from native extension loading so operators and future contributors do not confuse the two security models.

## Non-Goals

- Do not attempt to sandbox in-process native shared libraries. That is not realistic.
- Do not add a Python/pyo3 plugin path in this phase.
- Do not design a full external plugin RPC protocol unless a narrow shim is needed for compatibility.
- Do not weaken the WASM trust boundary to accommodate native plugin behavior.

## Current Risk Model

Native shared libraries loaded by `libloading` run inside the Synvoid address space. Even with path validation and ABI version checks, they can:

- read or write process memory through unsafe code;
- call libc/syscalls directly;
- spawn threads or block executor resources;
- crash the process through UB or panics across FFI;
- bypass WASM manifest capabilities;
- bypass fuel, epoch interruption, guest ABI limits, and host API sub-capabilities.

Therefore native plugins must be treated as trusted operator extensions only.

## Workstream 1: Rename the Concept and Public API Surface

### Target

Make terminology unambiguous everywhere: native shared-library plugins are `unsafe_native_plugins` or `native_extensions`, not generic plugins and not sandboxed plugins.

### Implementation Steps

1. Audit naming across:

- `src/plugin/mod.rs`
- `src/plugin/axum_loader.rs`
- docs under `docs/PLUGINS.md`
- `architecture/plugin_runtime_sandbox.md`
- `AGENTS.md`
- config files and examples
- log messages and metrics

2. Rename operator-facing config keys where feasible:

```toml
[plugins]
wasm_enabled = true
unsafe_native_enabled = false
unsafe_native_hot_reload = false

[plugins.unsafe_native]
enabled = false
allow_in_production = false
paths = []
```

3. If compatibility requires old names, keep aliases with warnings:

- `native_plugins_enabled` -> deprecated alias for `unsafe_native_enabled`
- `load_axum_plugins_from_dir` -> internal legacy wrapper if needed

4. Update docs to state that the WASM plugin runtime is the only sandboxed production plugin model.
5. Add startup logs when unsafe native support is disabled, enabled in development, or enabled in production.

### Tests

- Config defaults leave unsafe native extensions disabled.
- Deprecated config key maps to the new key and emits warning.
- Docs/guardrail test prevents language implying native plugins are sandboxed.
- Logs or structured status clearly show unsafe native status.

### Acceptance Criteria

- No operator-facing surface calls native shared libraries simply “sandboxed plugins.”
- Unsafe native loading is visibly separate from WASM plugin loading.
- Defaults are disabled.

## Workstream 2: Production Gate and Operator Acknowledgement

### Target

A production deployment must not load native shared libraries unless the operator explicitly acknowledges the risk through a high-friction configuration path.

### Recommended Policy

Require all of the following in production:

```toml
[plugins.unsafe_native]
enabled = true
allow_in_production = true
risk_acknowledgement = "I understand native extensions run with full Synvoid process authority"
allowed_dirs = ["/opt/synvoid/native-extensions"]
```

Development mode may allow a shorter opt-in, but still not by default.

### Implementation Steps

1. Add an `UnsafeNativePluginConfig` type.
2. Add a production-mode check from existing environment/config mode.
3. Require `enabled = true` before any native loader path is reachable.
4. In production, require:

- `allow_in_production = true`
- exact `risk_acknowledgement` string or equivalent explicit acknowledgement
- non-empty allowlisted directories
- hot reload disabled unless separately acknowledged

5. Return structured startup errors rather than silently skipping or partially loading native extensions.
6. Add `unsafe_native_status()` to the plugin manager/operator status output.

### Tests

- Production default rejects native loading.
- Production with `enabled = true` but no acknowledgement rejects.
- Production with wrong acknowledgement rejects.
- Production with acknowledgement but no allowed dirs rejects.
- Development with explicit enable can load from a temp allowed dir.
- Native hot reload requires a separate explicit flag.

### Acceptance Criteria

- Unsafe native plugins cannot be enabled accidentally.
- Production enablement requires visible operator acknowledgement.
- Failures are explicit and visible at startup.

## Workstream 3: Fix Shared Library Lifetime and ABI Ownership

### Problem

Any native loader using `libloading::Library` must retain the `Library` handle for as long as any function pointers, routers, handlers, or values originating from the library may execute. Dropping the handle can unload code while references still exist.

### Target

Make native extension lifetime safe at the Rust API boundary.

### Implementation Steps

1. Change the native loaded object from only storing `Arc<Router<()>>` or equivalent to storing an owned handle:

```rust
pub struct UnsafeNativeExtension {
    pub name: String,
    pub path: PathBuf,
    pub canonical_path: PathBuf,
    pub library: Arc<libloading::Library>,
    pub router: Arc<Router<()>>,
    pub abi_version: String,
    pub loaded_at: SystemTime,
    pub sha256: String,
}
```

2. Ensure all native route wrappers hold an `Arc<UnsafeNativeExtension>` or a structure that keeps the `Library` alive.
3. Ensure unload/reload removes routes only after new routes are loaded and old in-flight references can drain.
4. Prevent `Library` from being dropped while in-flight requests may still execute. Use `Arc` reference semantics or a generation registry.
5. Catch panics at safe handler boundaries where possible. Do not allow unwinding across FFI.
6. Audit ABI function signatures:

- version function must return stable C ABI data or a documented Rust ABI if same compiler/toolchain is required;
- router creation must have clear ownership transfer;
- plugin must not return borrowed data that outlives the library.

### Tests

- Loading a native extension stores a retained library handle.
- Dropping manager after route removal drops the library only after no route refs remain.
- Reload keeps old generation alive while in-flight request holds reference.
- ABI version mismatch rejects before router creation.
- Panic during router creation is caught or results in safe startup failure.

### Acceptance Criteria

- There is no path where `Library` is dropped while plugin-derived router/handler may execute.
- ABI ownership rules are documented and tested.
- Reload generation semantics are safe.

## Workstream 4: Path, Hash, and Provenance Enforcement

### Target

Native extension loading should be tied to allowlisted directories, canonical paths, and optional hashes/signatures. Path hygiene should be stricter than general file loading.

### Implementation Steps

1. Canonicalize plugin path and allowed directories.
2. Reject symlinks unless an explicit unsafe config permits them.
3. Reject world-writable files or parent directories on Unix.
4. Require extension from a platform-specific allowlist:

- Linux: `.so`
- macOS: `.dylib`
- Windows: `.dll`

5. Compute SHA-256 of the native library before load.
6. Allow optional exact hash allowlist:

```toml
[[plugins.unsafe_native.allowed_libraries]]
path = "/opt/synvoid/native-extensions/foo.so"
sha256 = "..."
```

7. Emit audit log with:

- name
- canonical path
- hash
- ABI version
- config mode
- loader generation

8. Keep existing dangerous-name checks only as a weak hygiene layer, not a security boundary.

### Tests

- Path outside allowed dirs rejected.
- Symlink rejected by default.
- World-writable library rejected on Unix.
- World-writable parent dir rejected on Unix.
- Wrong extension rejected.
- Hash mismatch rejected.
- Hash match accepted.
- Audit metadata available in status output.

### Acceptance Criteria

- Native loading is path-scoped and provenance-recorded.
- Operators can identify exactly which library hash is loaded.
- Symlink and writable-path bypasses are tested.

## Workstream 5: Isolation Recommendation and Out-of-Process Alternative

### Target

Document and prepare an out-of-process native extension path as the recommended production alternative if native code is needed.

### Recommended Architecture

For production native extensibility, prefer an external service boundary:

- UDS or loopback HTTP/gRPC service.
- Explicit request/response schema.
- Timeout and concurrency limits at the client boundary.
- Separate process user, seccomp/AppArmor/systemd restrictions if deployed on Linux.
- Same capability policy concepts as WASM host APIs.

### Implementation Steps

1. Add docs section: “Recommended production native extension model: out-of-process.”
2. Add a placeholder trait if useful:

```rust
pub trait ExternalPluginClient {
    fn filter_request(&self, request: PluginHttpView<'_>) -> Result<PluginDecision, ExternalPluginError>;
}
```

3. Do not build full RPC in this phase unless the code already has a natural extension point.
4. Add config docs showing unsafe in-process native extension vs external plugin service.
5. State that external plugin work is a future milestone if needed.

### Acceptance Criteria

- Docs clearly recommend out-of-process native extensions for production.
- In-process native extension docs do not imply meaningful sandboxing.
- Future external plugin design has a clear placeholder or plan reference.

## Workstream 6: Native Extension Observability

### Target

Expose native extension state separately from WASM plugin state.

### Implementation Steps

1. Add native extension status fields:

- enabled/disabled
- production allowed/denied
- loaded count
- name
- canonical path
- sha256
- ABI version
- loaded_at
- generation
- hot_reload_enabled
- last_load_error

2. Add metrics:

- `synvoid_unsafe_native_extension_loaded_total`
- `synvoid_unsafe_native_extension_load_failed_total`
- `synvoid_unsafe_native_extension_reloaded_total`
- `synvoid_unsafe_native_extension_request_total` if routed through the same request surface

3. Add audit logs on load, reject, reload, unload.
4. Ensure metrics labels do not include unbounded path strings unless normalized/hash-only.

### Tests

- Status output contains hash and generation.
- Failed load records last error.
- Metrics emit bounded labels.
- Native extension status is not mixed into WASM plugin sandbox status.

### Acceptance Criteria

- Operators can distinguish WASM sandbox plugins from unsafe native extensions.
- Native extension audit trail is sufficient for incident review.

## Validation Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test abi_memory_boundary_guard
```

If native loader tests are in the root crate:

```bash
cargo test -p synvoid -- plugin_native
cargo test -p synvoid -- unsafe_native
```

## Completion Definition

This phase is complete when:

- Unsafe native extensions are disabled by default and separately named.
- Production native loading requires explicit operator risk acknowledgement.
- The `libloading::Library` handle is retained for the lifetime of any plugin-derived values.
- Native extension path/hash/provenance checks are enforced and tested.
- Hot reload for native code is gated separately from WASM hot reload.
- Docs clearly distinguish sandboxed WASM plugins from unsafe native extensions.

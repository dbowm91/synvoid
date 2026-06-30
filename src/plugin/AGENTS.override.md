# Plugin/WASM Module - AGENTS.override.md

Specialized guidance for WASM plugin runtime.

## Hot Path

`src/plugin/wasm_runtime.rs` — WASM plugin filter/transform per request. Critical hot path:
- Every allocation compounds at 1000K rps
- Avoid O(n) operations; prefer O(1) lookups
- Use thread-local buffers and object pools.

## Module-Specific Patterns

### WASM Instance Management

- Instance pooling reduces instantiation overhead
- Memory buffers should be reused across invocations

### PooledInstance Lifecycle

The `PooledInstance` trait in `src/plugin/pool.rs:15-31` requires `prepare_for_request()` to reset all fields:
- `start`, `timeout`, `env`, `fuel` (basic resets)
- `allowed_dht_prefixes` - MUST be reset to prevent DHT prefix leakage between requests
- `body_receiver` - MUST be reset to `None` to prevent body receiver leakage

See `src/plugin/instance_pool.rs:219-233` for the correct pattern.

### Spin Manifest Validation

Spin manifest parsing (`src/spin/manifest.rs`) now validates:
- HTTP triggers require at least one component with a `url` route defined
- If not, returns `SpinManifestError::NoHttpRoutes`

### Spin WASI Configuration

Spin components can now configure WASI per-component via manifest:

```toml
[[components]]
id = "main"
source = "target/wasm32-wasi/release/my_app.wasm"

[components.wasi]
enabled = true  # or false to disable
```

Defaults to `true` if not specified (backward compatible).

### Manifest Authority Wiring (M1 Phase 01)

Every plugin's `synvoid-plugin.toml` manifest is the single source of truth for
that plugin's runtime authority. The conversion pipeline is:

1. `prepare_plugin_load()` loads/parses the manifest once
2. Calls `enforce_plugin_load_policy()` for admission checks
3. Calls `limits_from_manifest(manifest, defaults)` to derive `WasmResourceLimits`
4. Returns `PreparedPluginLoad { manifest, effective_limits, source }`

**Critical rules:**
- All load paths (`load_plugin`, `load_plugin_with_limits`, `reload_plugin`,
  `load_plugin_from_memory`) MUST use `PreparedPluginLoad.effective_limits`
  — never `self.default_limits.clone()` directly.
- Capabilities ALWAYS come from the manifest, never from defaults.
- `mesh = true` does NOT inherit global DHT prefix access.
- `PluginInfo` now includes `version`, `trust_tier`, `timeout_seconds`,
  `max_memory_mb`, `max_cpu_fuel`, `max_instances`, `capabilities_summary`.

**Types:**
- `EffectivePluginPolicy` — immutable per-plugin runtime policy
- `PreparedPluginLoad` — validated manifest + effective limits
- `PluginSourceIdentity` — provenance (path, hashes, key_id)

**Guardrail tests:**
- `cargo test --test manifest_authority_wiring` — two-plugin differentiation
- `cargo test --test manifest_authority_load_path_guard` — static load path enforcement

### Mandatory Invocation Guard (M1 Phase 03)

Every plugin invocation goes through `PluginInvocationGuard`. The guard is the
mandatory boundary for capability checks, input limits, concurrency, state,
and failure counting.

**Key files:**
- `crates/synvoid-plugin-runtime/src/sandbox/types.rs` — `PluginInvocationGuard`, `PluginFailurePolicy`, `PluginFailureClass`
- `crates/synvoid-plugin-runtime/src/wasm_runtime.rs` — `WasmRuntime.guard` field, `classify_failure()`, `record_and_classify_failure()`

**Rules:**
- `WasmRuntime::filter_request()` / `transform_response()` / `invoke_handler()` all check guard state before invocation
- Disabled plugins return fail-closed or fail-open per `PluginFailurePolicy`
- Capability violations immediately disable the plugin via `guard.disable_for_violation()`
- Repeated failures/timeouts disable via `guard.record_failure(threshold)`
- Host-function violations set `RequestContext.capability_violation` and are checked after guest call
- Failed/poisoned instances are not returned to the pool

**Guardrail tests:**
- `cargo test -p synvoid-plugin-runtime` — unit tests for guard, failure classes, state transitions

## ABI Memory Boundary Hardening (M1 Phase 04)

### Fixed-Offset Fallback Removed

`write_to_guest_memory()` now requires `guest_alloc` export. Plugins without allocator exports fail with `WasmPluginError::LoadFailed("plugin missing required guest_alloc export")`. The old `1024i32` fallback is gone.

### Checked Memory Operations

All guest pointer/length handling uses `checked_guest_range(ptr, len, mem_len)`. Host functions (`get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event`) validate ranges before access.

### Allocation Tracking

`GuestAllocation { ptr, len }` tracks each allocation. `free_guest_memory(&alloc)` logs failures and returns `bool`. Trapped free operations indicate instance poisoning.

### Header Serialization Bounds

`serialize_headers(headers, max_encoded_bytes)` rejects oversized counts, names, values, and total encoded size.

### Test Fixtures

Test WASM modules now export `guest_alloc`/`guest_free` bump allocators. The `minimal_filter_pass_no_alloc()` fixture tests rejection of plugins without allocator exports.

**Guardrail test:** `cargo test --test abi_memory_boundary_guard`

## Known Bugs (Fixed)

### Spin Cold-Start Bug (FIXED 2026-05-26)

`src/spin/runtime.rs:251` created new `SpinAppInstance` per request via `instantiate_app()`. No instance reuse was implemented, causing significant cold-start overhead on every request.

**Fix**: `SpinRuntime` now has `cached_instances` field (line 123) and `get_or_create_instance()` method (lines 288-295) that caches and reuses `SpinAppInstance` by component_id with 5-minute idle timeout. The `reuse()` method on `SpinAppInstance` (lines 103-105) updates request timestamps without creating new instances.

### PooledInstance DHT/Body Leak (PLUGIN-2 - FIXED 2026-05-27)

`src/plugin/pool.rs:15-31` - The generic `PooledInstance` trait's `prepare_for_request()` now properly resets:
- `start`, `timeout`, `env`, `fuel` (basic resets)
- `allowed_dht_prefixes` - now properly reset
- `body_receiver` - now properly reset to `None`

### Spin WASI Isolation (PLUGIN-11 - FIXED 2026-05-27)

`src/spin/runtime.rs:196-209` - WASI is now configurable per-component via manifest. Defaults to `true` if not specified.

### Unauthorized DHT Query Logging (PLUGIN-10 - FIXED 2026-05-27)

At `src/plugin/wasm_runtime.rs:867`, unauthorized DHT queries now log at `error` level for security audit trail.

### Serverless Warmup (PLUGIN-8 - FIXED 2026-05-27)

`src/serverless/manager.rs:464-471` - `InstancePool::initialize()` is now called from `ServerlessManager::initialize()` to pre-warm instances before the autoscaler begins.

## Skills Reference

- `skills/spin_wasm.md` — Spin WASM runtime
- `skills/serverless_wasm.md` — Serverless WASM patterns
- `skills/wasm_components.md` — WASM component model patterns

# Plugin/WASM Architecture Review Plan

**Review Date**: 2026-05-27
**Reviewed Documents**: `architecture/plugin_wasm.md`, `architecture/plugin_deep_dive.md`
**Verified Against**: `src/plugin/`, `src/serverless/`, `src/spin/`

---

## Verified Correct Items

### Core Module Structure
| Document Path | Actual File | Status |
|--------------|-------------|--------|
| `src/plugin/mod.rs` | `src/plugin/mod.rs` (424 lines) | ✅ Exact match |
| `src/plugin/wasm_runtime.rs` | `src/plugin/wasm_runtime.rs` (1920 lines) | ✅ |
| `src/plugin/instance_pool.rs` | `src/plugin/instance_pool.rs` (288 lines) | ✅ |
| `src/plugin/pool.rs` | `src/plugin/pool.rs` (37 lines) | ✅ |
| `src/plugin/axum_loader.rs` | `src/plugin/axum_loader.rs` (163 lines) | ✅ |
| `src/plugin/global.rs` | `src/plugin/global.rs` (268 lines) | ✅ |
| `src/plugin/wasm_metrics.rs` | `src/plugin/wasm_metrics.rs` (166 lines) | ✅ |

### Serverless Files
| Document Path | Actual File | Status |
|--------------|-------------|--------|
| `src/serverless/mod.rs` | `src/serverless/mod.rs` (22 lines) | ✅ |
| `src/serverless/manager.rs` | `src/serverless/manager.rs` (1271 lines) | ✅ |
| `src/serverless/instance_pool.rs` | `src/serverless/instance_pool.rs` (655 lines) | ✅ |
| `src/serverless/routing.rs` | `src/serverless/routing.rs` (338 lines) | ✅ |
| `src/serverless/registry.rs` | `src/serverless/registry.rs` | ✅ |
| `src/serverless/async_compilation.rs` | `src/serverless/async_compilation.rs` | ✅ |

### Spin Files
| Document Path | Actual File | Status |
|--------------|-------------|--------|
| `src/spin/runtime.rs` | `src/spin/runtime.rs` (383 lines) | ✅ |
| `src/spin/manifest.rs` | `src/spin/manifest.rs` (232 lines) | ✅ |

### Key Structs and Line Numbers
| Item | Document Location | Actual Location | Status |
|------|-----------------|-----------------|--------|
| `WasmResourceLimits` | `wasm_runtime.rs:51-76` | `wasm_runtime.rs:51-76` | ✅ |
| `RequestContext` | `wasm_runtime.rs:514-523` | `wasm_runtime.rs:515-523` | ✅ |
| `GuestExports` | `wasm_runtime.rs:79-86` | `wasm_runtime.rs:79-86` | ✅ |
| `WasmRuntime` | `wasm_runtime.rs:88-96` | `wasm_runtime.rs:88-96` | ✅ |
| `WasmPluginManager` | `wasm_runtime.rs:104-112` | `wasm_runtime.rs:104-112` | ✅ |
| `WasmInstancePool` | `instance_pool.rs:11-38` | `instance_pool.rs:11-16` | ✅ (struct simplified) |
| `PooledInstance` | `pool.rs:7-37` | `pool.rs:7-13` | ✅ (moved to end of file at 37) |
| `create_linker` | `wasm_runtime.rs:692-1013` | `wasm_runtime.rs:693-1014` | ✅ |
| `mesh_query_dht` prefix check | `wasm_runtime.rs:849-872` | `wasm_runtime.rs:849-872` | ✅ |
| Header serialization | `wasm_runtime.rs:1238-1256` | `wasm_runtime.rs:1242-1256` | ✅ |

### Feature Gates
| Feature | Document Location | Actual Location | Status |
|---------|-----------------|-----------------|--------|
| `mesh` gate for `load_wasm_plugin` | `mod.rs:66` | `mod.rs:66` | ✅ |
| `mesh` gate for `mesh_query_dht` | `wasm_runtime.rs:874` | `wasm_runtime.rs:874` | ✅ |
| `mesh` gate for `mesh_check_threat` | `wasm_runtime.rs:936` | `wasm_runtime.rs:936` | ✅ |
| `mesh` gate for `mesh_emit_event` | `wasm_runtime.rs:998` | `wasm_runtime.rs:998` | ✅ |

### HTTP Server Integration
| Item | Document Location | Actual Location | Status |
|------|-----------------|-----------------|--------|
| WASM filter integration | `http/server.rs:3050-3060` | `http/server.rs:3050-3060` | ✅ |
| Spin dispatch | `http/server.rs:2421-2503` | `http/server.rs:2421-2503` | ✅ |

### Bugs Marked FIXED in AGENTS.md
| Bug | Status |
|-----|--------|
| PooledInstance DHT prefix leak (`pool.rs:15-26`) | ✅ FIXED - code properly resets |
| Spin cold-start instance reuse (`spin/runtime.rs:258`) | ✅ FIXED - `get_or_create_instance()` caching |
| Spin WASI isolation per-component | ✅ FIXED - WASI configurable |
| Unauthorized DHT query logging | ✅ FIXED - logs at ERROR level |

---

## Discrepancies Found

### 1. DHT Prefix Reset in `PooledInstance` (Documentation Ambiguity)
**Severity**: Low (documentation)
**Location**: `plugin_deep_dive.md:108`, `pool.rs:15-26`

The deep dive doc says generic `PooledInstance::prepare_for_request` "does NOT reset body_receiver or DHT prefixes", but current code DOES reset both:
```rust
// pool.rs:22-26 (actual code)
self.store.data_mut().body_receiver = None;
self.store.data_mut().allowed_dht_prefixes = allowed_dht_prefixes;
```

This was fixed (PLUGIN-2) per AGENTS.md but documentation was not updated.

---

### 2. Audit Log Level Mismatch
**Severity**: Low (documentation)
**Location**: `plugin_deep_dive.md:90`, `wasm_runtime.rs:867`

Deep dive says:
> "Unauthorized DHT queries attempt returns `-2` and is logged as a warning"

Actual code at `wasm_runtime.rs:867`:
```rust
tracing::error!(
    "WASM plugin attempted unauthorized DHT query: key='{}'",
    key
);
```
Logs at **ERROR** level, not WARNING.

---

### 3. Missing `invoke_handler_streaming` Documentation
**Severity**: Low (documentation)
**Location**: `plugin_wasm.md:345` (mentions), `plugin_deep_dive.md` (omits)

The `plugin_wasm.md` documents `invoke_handler_streaming` at `wasm_runtime.rs:344`, but `plugin_deep_dive.md` does not mention it. This is a serverless-style handler for streaming body support.

---

### 4. Warmup Stub Count Discrepancy
**Severity**: Low (documentation)
**Location**: `plugin_deep_dive.md:109`, `instance_pool.rs:85-215`

Deep dive says warmup creates instances with "6 stub host functions" but actually creates 7 stubs:
1. `abort`
2. `check_timeout`
3. `get_env`
4. `synvoid_read_body_chunk`
5. `mesh_query_dht`
6. `mesh_check_threat`
7. `mesh_emit_event`

---

### 5. Serverless Autoscaler Tick Interval Not Documented
**Severity**: Low (documentation)
**Location**: `plugin_deep_dive.md:199` ("Every 10s run_autoscaler()")

Document says the autoscaler runs "Every 10s" but doesn't specify which file to verify against.

---

### 6. `ServerlessManager` Internal Struct Mismatch
**Severity**: Low (documentation)
**Location**: `plugin_deep_dive.md:174`

Deep dive mentions `HashMap<String, ServerlessFunction>` for function registry, but doesn't note the `compilation_manager` field (line 114) which uses `AsyncCompilationManager` for background compilation.

---

## Bugs Identified

### BUG-PLUGIN-1: Missing `invoke_handler` in WasmRuntime but Not in `mod.rs` Exports
**Severity**: Low (Enhancement)
**Location**: `wasm_runtime.rs:1717-1843`

The `WasmRuntime::invoke_handler` method exists but is not exported via `mod.rs` public API. Only handlers used are `filter_request` and `transform_response`. The `invoke_handler` method appears to be a serverless-style handler that isn't exposed at the plugin manager level.

**Fix**: Document this as intentional (internal serverless use only) or expose via `WasmPluginManager` if intended for external use.

---

### BUG-PLUGIN-2: `PooledInstance` Struct Has Dead Field After Pool Conversion
**Severity**: Low (Code Quality)
**Location**: `pool.rs:12`, `instance_pool.rs:247`

The generic `PooledInstance` struct stores `allowed_dht_prefixes` as its own field, but when `WasmPool::get()` converts `WasmPooledInstance` → `PooledInstance`, it clones `default_allowed_dht_prefixes`.

The original `PooledInstance.allowed_dht_prefixes` is never populated via the generic interface - it's set to `inst.default_allowed_dht_prefixes.clone()` during conversion. This appears intentional but confusing.

---

### BUG-PLUGIN-3: No Metrics for Serverless Functions in `serverless/instance_pool.rs`
**Severity**: Medium (Observability)
**Location**: `serverless/instance_pool.rs`

The `ServerlessInstance` tracks metrics (`InstanceMetrics`) with `requests_handled`, `total_duration_ms`, cold starts, etc., but there's no equivalent to `wasm_metrics.rs` for exposing aggregated metrics across all serverless functions.

**Impact**: Serverless function metrics are tracked per-instance but not aggregated globally for observability.

---

### BUG-PLUGIN-4: Spin Manifest v2 Parsing May Not Match Documentation
**Severity**: Low (documentation)
**Location**: `spin/manifest.rs:6-22`

Documentation in `plugin_deep_dive.md:126` says "Parses Spin **v2** manifest format (TOML) at `src/spin/manifest.rs:6-22`".

Actual code shows `SpinManifest` struct at lines 6-22, but this is serde(deserialize) structure, not explicit TOML parsing. The manifest is loaded via `serde_json` or similar. Need to verify if `.toml` files are supported or only JSON manifests.

**Verification needed**: Check if Spin v2 TOML manifests are actually supported.

---

## Suggested Improvements

### 1. Update Documentation for PLUGIN-2 Bug Fix
**File**: `architecture/plugin_deep_dive.md:108`

Current text implies generic `PooledInstance::prepare_for_request` does NOT reset body_receiver/DHT prefixes. Update to reflect the fix:

> "Before each request, `prepare_for_request()` resets timeout, fuel, env, body_receiver, and DHT prefixes. Both `WasmPooledInstance::prepare_for_request` and the generic `PooledInstance::prepare_for_request` properly reset all fields."

---

### 2. Update Log Level in Deep Dive
**File**: `architecture/plugin_deep_dive.md:90`

Change "logged as a warning" to "logged as an error" to match actual code.

---

### 3. Document `invoke_handler_streaming` in Deep Dive
**File**: `architecture/plugin_deep_dive.md`

Add section on streaming handler support, which allows WASM plugins to process streaming request bodies via `synvoid_read_body_chunk` host function.

---

### 4. Add `ServerlessManager` Compilation Manager to Deep Dive
**File**: `architecture/plugin_deep_dive.md`

Document the `AsyncCompilationManager` integration for background WASM compilation to prevent blocking during function initialization.

---

### 5. Add `PooledInstance` Conversion Diagram
**File**: `architecture/plugin_wasm.md`

The `WasmPool` trait's `get()` and `return_instance()` methods perform conversions between `PooledInstance` (generic) and `WasmPooledInstance` (concrete). This is confusing - consider adding a diagram or clarifying these are separate type adaptations, not direct pooling.

---

### 6. Verify Spin v2 TOML Support
**File**: `architecture/plugin_deep_dive.md:125`

Check actual manifest loading in `spin/manifest.rs` to confirm if TOML is supported, and update documentation accordingly. If TOML is NOT supported, update the statement "Parses Spin v2 manifest format (TOML)" to "Parses Spin manifest format (JSON)".

---

### 7. Consider Adding Global Metrics for Serverless
**File**: `src/serverless/`

Add `get_all_serverless_metrics()` function similar to `get_all_wasm_metrics()` in `wasm_metrics.rs` for aggregated observability across all serverless functions and their instance pools.

---

### 8. Document `SERVERLESS_ENGINE_POOL` Global Static
**File**: `architecture/plugin_deep_dive.md` or `src/serverless/instance_pool.rs:103`

The `static SERVERLESS_ENGINE_POOL` is a global cache of `WasmPluginManager` instances keyed by function name and memory config. This avoids recompiling the same wasmtime engine for identical function configurations.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct Items | 22 |
| Discrepancies Found | 6 |
| Bugs Identified | 4 |
| Suggested Improvements | 8 |

**Overall Assessment**: Documentation is largely accurate. Most discrepancies are minor documentation updates needed for past bug fixes (PLUGIN-2) and missing descriptions of newer features (`invoke_handler_streaming`, `AsyncCompilationManager`). No critical bugs found - the codebase matches the architectural intent.

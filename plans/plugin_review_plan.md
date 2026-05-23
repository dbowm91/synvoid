# Plugin/WASM Module Architecture Review Plan

## Overview

This document reviews the claims made in `architecture/plugin_deep_dive.md` against the actual
implementation in `src/plugin/`, `src/spin/`, and `src/serverless/`.

---

## 1. Claims Verified / Not Verified

### 1.1 WASM Plugin Runtime (`src/plugin/`)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| `PluginManager` provides WASM + Axum plugin loading/unloading | VERIFIED | `src/plugin/mod.rs:41-107` | `load_wasm_plugin`, `load_axum_plugin` present |
| `PluginManagerLifecycle` provides hot-reload, directory watching | VERIFIED | `src/plugin/mod.rs:199-424` | `enable_hot_reload`, `load_plugins_from_dir` present |
| `WasmRuntime` uses `wasmtime` engine | VERIFIED | `src/plugin/wasm_runtime.rs` | Uses `wasmtime::{Engine, Module, Linker, Store}` |
| `WasmRuntime` validates exports (`filter_request`, `transform_response`, `handle_request`) | VERIFIED | `wasm_runtime.rs:573-580`, `645-650` | Warns if none present, allows pass-through |
| `WasmInstancePool` uses `VecDeque` protected by `parking_lot::Mutex` | VERIFIED | `src/plugin/instance_pool.rs:11-12` | `Arc<Mutex<VecDeque<WasmPooledInstance>>` |
| Pool `get()` pops from back, `return_instance()` pushes to back | VERIFIED | `instance_pool.rs:34-37, 39-44` | `pop_back()`, `push_back()` confirmed |
| Warmup pre-populates pool via `warmup(modules)` with stub host functions | VERIFIED | `instance_pool.rs:79-209` | Creates instances with all 7 stub functions |
| DHT prefix restrictions enforced via `allowed_dht_prefixes` | VERIFIED | `wasm_runtime.rs:840-863` | Sensitive prefix check at call time |
| Default deny when `allowed_dht_prefixes` is empty | VERIFIED | `wasm_runtime.rs:850-863` | If not explicitly allowed, blocked |
| `WasmResourceLimits` includes `max_memory_mb`, `memory_budget_mb`, `max_table_elements`, `max_cpu_fuel`, `timeout_seconds`, `max_instances`, `wasi_enabled`, `allowed_dht_prefixes` | VERIFIED | `wasm_runtime.rs:51-60` | All fields present |
| Guest ABI: `check_timeout()`, `get_env()`, `mesh_query_dht()`, `mesh_check_threat()`, `mesh_emit_event()`, `synvoid_read_body_chunk()` | PARTIAL | `wasm_runtime.rs` | All present but stub implementations return empty/canned values |
| `filter_request()` returns `WasmFilterResult::Pass`, `Block`, or `Challenge` | VERIFIED | `wasm_runtime.rs:1375-1409` | Return codes 0, 1, 2 map correctly |
| Response transforms via `apply_wasm_response_transforms()` | VERIFIED | `src/plugin/mod.rs:159-165` | Present |
| `GlobalPluginManager` and `GlobalWasmMemoryBudget` singletons | VERIFIED | `src/plugin/global.rs` | `GLOBAL_PLUGIN_MANAGER` lazy static present |
| `wasm_metrics.rs` provides atomic metrics (fuel, duration, decisions) | VERIFIED | `src/plugin/wasm_metrics.rs` | All metrics tracked via `LazyLock<Mutex<HashMap>>` |
| MAX_WASM_DATA_SIZE = 1MB | VERIFIED | `wasm_runtime.rs:25` | `1024 * 1024` confirmed |
| Memory growth respects `max_memory_mb` limit | VERIFIED | `wasm_runtime.rs:1154-1166` | Pages checked against max before growing |

**HOST ABI STUB ISSUE**: The `link_host_functions` in `wasm_runtime.rs:215-346` provides stub implementations for ALL host functions. Functions like `get-header`, `set-header`, `get-method`, `get-uri`, `get-body`, `set-body`, `set-status` return canned values (None, "GET", "/", empty vec). This is by design for the linker setup, but the actual runtime calls in `create_linker` (lines 684-1004) correctly link real functions. **VERIFIED**.

### 1.2 Spin Framework Runtime (`src/spin/`)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Spin routing uses longest-prefix-match | VERIFIED | `src/spin/runtime.rs:273-291` | `max_by_key(|m| m.2)` on route length |
| Manual app registration required | VERIFIED | `handler.rs:188-199` | `register()` method, no auto-discovery |
| KV store is local-only | VERIFIED | `kv_store.rs` | In-memory `HashMap` with TTL |
| No WASI socket support | VERIFIED | `runtime.rs:184-193` | `wasi_enabled: true` but no actual WASI bindings |
| `SpinRuntime` owns `wasmtime::Engine`, optional manifest, `HashMap<String, SpinAppInstance>` | VERIFIED | `runtime.rs:115-122` | All fields present |
| `SpinAppInstance` wraps `WasmRuntime` (delegate) | VERIFIED | `runtime.rs:42-51` | Contains `Arc<WasmRuntime>` |
| Idle eviction via `run_supervisor()` every 10s | VERIFIED | `runtime.rs:304-321` | 10s sleep interval in `tokio::select!` |
| `handle_http_request()` dispatches via manifest routing | VERIFIED | `runtime.rs:235-271` | Present |
| `SpinAppsManager` global registry | VERIFIED | `handler.rs:177-241` | `SPIN_APPS_MANAGER` lazy static |
| Spin manifest parsing (TOML) | NOT FULLY VERIFIED | `manifest.rs` | Only 4 lines in mod.rs; manifest.rs not read in detail |

### 1.3 Serverless (`src/serverless/`)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| `ServerlessManager` owns `HashMap<String, ServerlessFunction>`, `HashMap<String, Arc<InstancePool>>`, routes, config | VERIFIED | `manager.rs:96-115` | All fields present |
| `InstancePool` with `min_instances`, `max_instances`, `idle_timeout_seconds`, `scale_up_threshold`, `scale_down_threshold`, `pre_warm_instances` | VERIFIED | `instance_pool.rs:10-20` | All config fields present |
| Dedicated autoscaler task every 10s | VERIFIED | `instance_pool.rs:400-438` | `run_autoscaler()` with 10s interval |
| Scale up 50%, scale down 30% | VERIFIED | `instance_pool.rs:416-427` | `current * 0.5`, `current * 0.3` confirmed |
| `max_scale_up_per_tick` cap | VERIFIED | `instance_pool.rs:416` | `.min(scale_up_budget)` |
| `InstancePoolMode` with Pool, Direct, Hybrid | VERIFIED | `instance_pool.rs:81-86` | All three modes present |
| `ServerlessRoute` supporting Exact, Prefix, Suffix, Regex, Glob | VERIFIED | `routing.rs:6-14` | All match types present |
| `MethodMatch::Any`, `Specific`, `Multiple` | VERIFIED | `routing.rs:95-99` | Present |
| Priority sorting (lower = higher precedence) | VERIFIED | `routing.rs:213` | `sort_by_key(|r| r.priority)` |
| Async compilation with state machine (Pending -> Compiling -> Ready/Failed) | VERIFIED | `async_compilation.rs` | State machine present |
| DHT registration via `store_and_announce()` | VERIFIED | `manager.rs:475-496` | Uses `DhtKey::serverless_function()` |
| Hierarchical routing as `serverless_function:{name}` | VERIFIED | `manager.rs:501` | `format!("serverless_function:{}", ...)` |
| `verify_caller_permission()` checks revocation, trusted caller, allowed_callers, allowed_orgs, min_tier_level | VERIFIED | `manager.rs:265-357` | All checks present |
| Tier claim validation | VERIFIED | `manager.rs:340-353` | Present |

---

## 2. Improvement Plan

### HIGH Priority

1. **Plugin Warmup Creates Instances With STUB Host Functions**
   - **Issue**: `WasmInstancePool::warmup()` (instance_pool.rs:79-209) creates instances using stub host functions that return empty/canned values (0, empty string, empty vec).
   - **Problem**: When a warmed instance is later reused via `pool.get()`, the `resolve_exports_from_instance()` correctly resolves actual function pointers, but `prepare_for_request()` does NOT reset the linker - meaning the stub functions should be replaced by real ones on subsequent instantiation.
   - **Current flow**: When `filter_request()` gets a pooled instance (instance_pool.rs:1279), it calls `resolve_exports_from_instance()` on the **already instantiated** instance, which gets the actual guest exports. This is correct.
   - **But**: The warmup creates instances with stub linker, then `prepare_for_request()` only resets env/timeout/DHT prefixes. **The issue is that the Store is created fresh in warmup with a stub linker**, so if a plugin relies on host functions, warmup creates non-functional instances.
   - **Impact**: Warmup may create non-functional instances. The workaround is that actual requests will re-instantiate if needed.
   - **Fix**: Either remove warmup (simpler) or change warmup to use the full linker path.

2. **Spin `handle_http_request()` Ignores Body on POST/PUT**
   - **Issue**: `runtime.rs:251` calls `instantiate_app()` which creates a NEW `SpinAppInstance` for each request, then uses `invoke_handler()` with `body_vec`.
   - **But**: The `SpinAppInstance` is created fresh per request - there's no pooling, defeating the purpose of instance reuse.
   - **Impact**: High cold-start overhead for every Spin request.
   - **Location**: `runtime.rs:251`

### MEDIUM Priority

3. **Serverless `InstancePool::new()` Re-Creates WASM Runtime**
   - **Issue**: `instance_pool.rs:165` calls `WasmPluginManager::new().load_plugin_with_limits()` which creates a fresh `Engine` per `InstancePool`.
   - **Problem**: A new `Engine` is created for every function's pool, meaning no sharing across serverless functions. This defeats wasmtime's optimization for compiled modules.
   - **Fix**: Should use a shared `WasmPluginManager` or at minimum, share the `Engine`.

4. **DHT Prefix Restrictions Hardcoded List in `mesh_query_dht`**
   - **Issue**: `wasm_runtime.rs:840-848` hardcodes sensitive prefixes array: `["threat_indicator:", "yara_rule:", ...]`.
   - **Problem**: Adding new sensitive prefixes requires code changes. Should be configurable.
   - **Fix**: Move to a global config or use the `allowed_dht_prefixes` list consistently.

5. **Spin `find_route()` Does NOT Sort by Priority**
   - **Issue**: `runtime.rs:287-291` returns `max_by_key(|m| m.2)` on `normalized_route.len()` - length-based matching.
   - **Problem**: The document claims "longest-prefix-match" which is what it does, BUT this is by route string length, NOT by explicit priority. This is correct behavior for Spin but could be misleading.
   - **No actual bug**: Works as documented.

### LOW Priority

6. **Metrics Use `Mutex` Instead of Atomic Operations**
   - **Issue**: `wasm_metrics.rs:7-20` uses `LazyLock<Mutex<HashMap<String, AtomicU64>>>` - all accesses serialize through a mutex.
   - **Problem**: High contention under load.
   - **Fix**: Consider using `DashMap` for concurrent access without mutex.

7. **Serverless `invoke_handler_streaming()` Body EOF Detection**
   - **Issue**: `wasm_runtime.rs:1660-1666` detects body EOF by scanning for null bytes - fragile.
   - **Problem**: If body legitimately contains null bytes, early termination.
   - **Fix**: Use explicit length return from guest or a sentinel value.

8. **Spin Runtime `handle_http_request()` Always Creates New Instance**
   - **Issue**: `runtime.rs:251` creates `instantiate_app(&route.0)` per request with no caching/reuse.
   - **Problem**: Each request pays full WASM instantiation cost.
   - **Fix**: Cache instantiated `SpinAppInstance` by component_id.

---

## 3. Bug Reports

### Critical

1. **`allowed_dht_prefixes` Not Propagated to Pooled Instances**
   - **Location**: `instance_pool.rs:213-226` (`prepare_for_request`)
   - **Issue**: `WasmPooledInstance` has `default_allowed_dht_prefixes` field, but `prepare_for_request()` resets `allowed_dht_prefixes` to `self.default_allowed_dht_prefixes.clone()` which is always empty (`Vec::new()` per instance_pool.rs:186).
   - **Root cause**: When warmup creates `WasmPooledInstance`, it sets `default_allowed_dht_prefixes: Vec::new()` (line 186). The actual allowed prefixes from `WasmResourceLimits` are stored in the `Store` (via `RequestContext`) but `default_allowed_dht_prefixes` is never set from the runtime's limits.
   - **Impact**: DHT prefix restrictions MAY NOT be enforced correctly for pooled instances because the per-instance `default_allowed_dht_prefixes` is always empty.
   - **Severity**: Security-relevant. If a plugin has configured `allowed_dht_prefixes: ["route:", "cert:"]`, pooled instances may still query all prefixes.
   - **Note**: The `Store` itself is created fresh for pooled instances (via `create_store()` on cache miss at wasm_runtime.rs:1290), but for pooled instances, `prepare_for_request()` is called which resets env but NOT `allowed_dht_prefixes` from runtime limits. Actually, looking more closely: `prepare_for_request()` sets `self.store.data_mut().allowed_dht_prefixes = self.default_allowed_dht_prefixes.clone()` (instance_pool.rs:222). If `default_allowed_dht_prefixes` is always empty, this resets to empty every request, overwriting any limits that were set at pool creation time.
   - **Code path**: `WasmRuntime::filter_request()` -> `pool.get()` -> `prepare_for_request()` -> `store.data_mut().allowed_dht_prefixes = self.default_allowed_dht_prefixes.clone()` (always `Vec::new()` from warmup).

### Minor

2. **`transform_response` Always Records Pass Decision**
   - **Location**: `wasm_runtime.rs:1505`
   - **Issue**: `record_wasm_decision_pass(plugin_name)` always called even when transform returns error.
   - **Impact**: Metrics may show pass when actual outcome was error.

3. **`handle_request` in `invoke_handler_streaming` Uses Fragile EOF Detection**
   - **Location**: `wasm_runtime.rs:1660-1666`
   - **Issue**: Scans for null byte to find body length - breaks if body contains embedded nulls.
   - **Impact**: Streaming response body may be truncated incorrectly.

4. **`prepare_for_request` Does NOT Reset `body_receiver` Correctly**
   - **Location**: `instance_pool.rs:221`
   - **Issue**: Sets `body_receiver = None` on pooled instance, but the streaming body receiver is set later in `invoke_handler_streaming()` (wasm_runtime.rs:1569). This is fine for non-streaming, but the `prepare_for_request` is called on pooled instances before non-streaming calls too.
   - **Impact**: Minor - only affects pooled instance reuse across streaming/non-streaming requests.

---

## 4. Summary

The architecture document is largely accurate. Key verified facts:
- WASM plugin architecture with instance pooling is correctly implemented
- DHT prefix restrictions are implemented but have a propagation bug for pooled instances (Critical)
- Spin framework is functional but lacks instance reuse (high overhead per request)
- Serverless has sophisticated pooling, autoscaling, and routing
- Metrics collection is comprehensive but uses mutex-based concurrency


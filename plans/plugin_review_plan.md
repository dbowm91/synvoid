# Plugin Architecture Review - Improvement Plan

## Executive Summary

The `architecture/plugin_deep_dive.md` document provides a comprehensive overview of the plugin/serverless architecture but contains several **inaccuracies and outdated claims** that need correction. Most critically, the Spin framework integration is **more complete than documented** - it IS wired into the HTTP server dispatch at `src/http/server.rs:2412-2494`. However, the document significantly **overstates the maturity** of both the plugin and serverless modules.

---

## 1. Module Verification Status

| Module | Documented Status | Actual Status | Assessment |
|--------|------------------|---------------|------------|
| `src/plugin/` | Fully implemented | ~85% complete | **Accurate** - Core WASM runtime, pooling, metrics all present |
| `src/spin/` | "Partially implemented" | ~60% complete | **UNDERSTATED** - Actually wired into HTTP dispatch |
| `src/serverless/` | Full-featured with autoscaling | ~70% complete | **OVERSTATED** - Routing, instance pooling present; mesh integration incomplete |

---

## 2. Discrepancies Found

### 2.1 Spin Module - Documented vs Actual

#### Documentation Claim (line 78-79):
> "This module is partially implemented — manifest parsing works but routing integration and component mapping is NOT complete."

#### Actual State:
The Spin module **IS integrated** into the HTTP server dispatch pipeline at `src/http/server.rs:2412-2494`. When a site backend is configured with `BackendType::Spin`, the server:
1. Retrieves the `SpinRuntime` via `SpinAppsManager`
2. Creates a `SpinHttpHandler` wrapper
3. Dispatches requests through `SpinRequest` → `handle_request()` → `SpinRuntime::handle_http_request()`
4. The `find_route()` method in `SpinRuntime` (line 271-285) does route matching

**However**, the routing has significant limitations:
- Route matching only checks if path `starts_with` the route (line 279)
- No HTTP method filtering
- No route priority ordering
- Component-to-URL mapping is basic string prefix matching

#### Issue: PLUGIN-1 (Medium Severity)
**Location**: `src/spin/runtime.rs:271-285`

```rust
fn find_route(&self, manifest: &Manifest, path: &str) -> Result<(String, String), SpinRuntimeError> {
    for component in &manifest.components {
        if let Some(ref route) = component.url {
            let normalized_route = route.trim_end_matches('/');
            if path == normalized_route || path.starts_with(&format!("{}/", normalized_route)) {
                return Ok((component.id.clone(), route.clone()));
            }
        }
    }
    Err(SpinRuntimeError::RouteNotFound(path.to_string()))
}
```

**Problems**:
1. No HTTP method matching (all methods allowed)
2. No regex/glob support - only exact and prefix matching
3. Returns first matching route, no priority system
4. Does not support path parameters like `/users/{id}`

---

### 2.2 WasmPluginManager - Missing Method

#### Documentation Claim (line 19):
> `PluginManager` (WASM + Axum plugin loading/unloading), `PluginManagerLifecycle` (hot-reload, directory watching)

#### Actual State:
`PluginManager::load_wasm_plugin` exists but `WasmPluginManager` has a **missing implementation** for `load_plugin_from_memory` with priority parameter - only `load_from_bytes_with_priority` exists, not a proper public API method.

**Issue**: PLUGIN-2 (Low Severity)
**Location**: `src/plugin/wasm_runtime.rs:162-177`

The `load_plugin_from_memory` method at line 162 uses priority `0` always:
```rust
pub fn load_plugin_from_memory(
    &self,
    name: &str,
    data: &[u8],
    limits: WasmResourceLimits,
) -> Result<Arc<WasmRuntime>, WasmPluginError> {
    let runtime = WasmRuntime::load_from_bytes(name, data, limits)?;  // <-- Uses default priority 0
    ...
}
```

Should expose `load_plugin_from_memory_with_priority` for mesh-distributed plugins that need priority ordering.

---

### 2.3 Serverless Module - Feature Gating

#### Documentation Claim (line 121-125):
Documents `ServerlessManager`, `InstancePool`, `ServerlessRegistry`, `AsyncCompilationManager`

#### Actual State:
All these structs exist, BUT several key methods are **feature-gated** behind `#[cfg(feature = "mesh")]`:
- `ServerlessManager::set_record_store()` - mesh only
- `ServerlessManager::set_routing_manager()` - mesh only
- `ServerlessManager::verify_caller_permission()` - mesh only
- DHT registration and hierarchical routing - mesh only

**Issue**: PLUGIN-3 (Medium Severity)
**Location**: `src/serverless/manager.rs` lines 145-171

The mesh integration methods are present but conditionally compiled. Without the `mesh` feature, the serverless module cannot register functions in DHT or use hierarchical routing.

---

### 2.4 Guest ABI Host Functions - Incomplete Stubs

#### Documentation Claim (line 54-62):
| Function | Purpose |
|----------|---------|
| `check_timeout()` | Wall-clock timeout enforcement |
| `get_env(key)` | Environment variable access |
| `mesh_query_dht(key)` | DHT lookups |
| `mesh_check_threat(ip)` | Threat intelligence lookups |
| `mesh_emit_event(topic, data)` | Event publishing |
| `synvoid_read_body_chunk()` | Streaming body reading |

#### Actual State:
Most host functions are **stub implementations** that return dummy values:

| Function | Actual Behavior | Line Reference |
|----------|-----------------|----------------|
| `check_timeout()` | Works correctly - checks elapsed time | `wasm_runtime.rs:731-738` |
| `get_env(key)` | Returns empty string if key not found (CORRECT) | `wasm_runtime.rs:747-792` |
| `mesh_query_dht(key)` | Returns empty on non-mesh; with mesh, queries but returns empty for most keys | `wasm_runtime.rs:838-922` |
| `mesh_check_threat(ip)` | Returns 0 (CLEAN) always - stub | `wasm_runtime.rs:927-972` |
| `mesh_emit_event(topic, data)` | Logs and stores event, but DHT store may fail silently | `wasm_runtime.rs:977-1021` |
| `synvoid_read_body_chunk()` | Works for streaming | `wasm_runtime.rs:797-833` |

**Issue**: PLUGIN-4 (High Severity) - `mesh_check_threat` is a stub

**Location**: `src/plugin/wasm_runtime.rs:946-960`

```rust
#[cfg(feature = "mesh")]
let threat_result = if let Some(rs) = crate::mesh::get_global_record_store() {
    let key = format!("threat_indicator:{}:IpBlock", ip_str);
    if rs.get_record(&key).is_some() {
        tracing::debug!("WASM mesh_check_threat('{}') -> THREATENED", ip_str);
        1
    } else {
        0
    }
} else {
    0
};
```

This only checks for exact `threat_indicator:{ip}:IpBlock` records. If the threat indicator format differs or requires different key patterns, this will silently fail.

---

### 2.5 Component Model Support - Undocumented

#### Documentation Claim (line 42):
> "Validates exports (must have at least `filter_request`, `transform_response`, or `handle_request`)"

#### Actual State:
The code **does** have `load_component()` method (line 184-210) that supports the WASM Component Model with WIT-defined interfaces, but:
1. It's NOT documented in the architecture doc
2. The method is a stub - it loads the component but doesn't store or use it
3. No public API to actually invoke component model plugins

**Issue**: PLUGIN-5 (Low Severity)
**Location**: `src/plugin/wasm_runtime.rs:184-210`

```rust
pub fn load_component(&self, path: &Path) -> Result<(), WasmPluginError> {
    // ... loads component but only logs success, doesn't store instance
    tracing::info!("WASM component instantiated successfully with WIT-defined host interface");
    Ok(())  // <-- Returns OK but component is never used!
}
```

---

### 2.6 WasmResourceLimits - Missing Field

#### Documentation Claim (line 33):
> `WasmResourceLimits` — Resource constraints per plugin: `max_memory_mb`, `max_table_elements`, `max_cpu_fuel`, `timeout_seconds`, `max_instances`, `wasi_enabled`, `allowed_dht_prefixes`.

#### Actual State:
The actual struct at line 51-60 has an **additional field**:
```rust
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,
    pub max_table_elements: Option<usize>,
    pub max_cpu_fuel: u64,
    pub timeout_seconds: u64,
    pub max_instances: usize,
    pub memory_budget_mb: Option<usize>,  // <-- NOT documented
    pub wasi_enabled: bool,
    pub allowed_dht_prefixes: Vec<String>,
}
```

**Issue**: PLUGIN-6 (Low Severity) - Documentation missing `memory_budget_mb` field

---

## 3. Bugs Identified

### BUG-1: Spin find_route() Returns First Match Only (High)

**Location**: `src/spin/runtime.rs:271-285`

**Problem**: When multiple components have routes that could match a path, `find_route()` returns the first one found in the manifest order, not the best match.

**Example**: If manifest has:
```toml
[[components]]
id = "api"
url = "/api"

[[components]]
id = "api-users"  
url = "/api/users"
```

A request to `/api/users` would match `api` first (since `/api` is a prefix of `/api/users`).

**Impact**: Route priority is non-deterministic based on manifest ordering.

**Fix Required**: Implement proper route matching with longest-prefix-priority or explicit priority field.

---

### BUG-2: PooledInstance.prepare_for_request Doesn't Reset body_receiver (Medium)

**Location**: `src/plugin/instance_pool.rs:152-164`

```rust
pub(crate) fn prepare_for_request(
    &mut self,
    env: std::collections::HashMap<String, String>,
    timeout_seconds: u64,
) {
    self.store.data_mut().start = Instant::now();
    self.store.data_mut().timeout = Duration::from_secs(timeout_seconds);
    self.store.data_mut().env = env;
    self.store.data_mut().allowed_dht_prefixes = self.default_allowed_dht_prefixes.clone();
    // NOTE: body_receiver is NOT reset here
    if self.max_cpu_fuel > 0 {
        self.store.set_fuel(self.max_cpu_fuel).ok();
    }
}
```

**Problem**: When a pooled instance is reused, `body_receiver` from the previous request may still be set, causing `synvoid_read_body_chunk()` to return `None` (indicating EOF) immediately on subsequent requests that should have a body.

**Impact**: Streaming body reading can fail silently on pooled instances after first use.

---

### BUG-3: WasmInstancePool warmup Doesn't Link All Functions (Medium)

**Location**: `src/plugin/instance_pool.rs:79-148`

**Problem**: The `warmup()` method creates instances but only links `abort` and `check_timeout` host functions. It does not link:
- `get_env`
- `mesh_query_dht`
- `mesh_check_threat`
- `mesh_emit_event`
- `synvoid_read_body_chunk`

**Impact**: Warm instances cannot use DHT or environment functions until re-instantiated per-request with full linker setup.

---

### BUG-4: SpinRuntime Idle Eviction Uses Hardcoded Timeout (Low)

**Location**: `src/spin/runtime.rs:319-338`

```rust
async fn evict_idle_instances(&self) {
    let idle_timeout = Duration::from_secs(300);  // <-- Hardcoded 5 minutes
    ...
}
```

**Problem**: The idle timeout is hardcoded to 300 seconds (5 minutes), not configurable via `SpinRuntimeConfig`.

---

## 4. Missing Features (Not Bugs)

### 4.1 No WASI Socket Support for Spin

**Documentation Claim** (line 105):
> "No WASI socket support — Only in-memory KV store; no outbound HTTP capability"

**Actual State**: Confirmed - Spin KV store is in-memory only. No WASI sockets implementation exists.

---

### 4.2 No Spin HTTP Trigger Integration Beyond Dispatch

**Documentation Claim** (line 103):
> "No Spin HTTP trigger integration — While manifest parsing works, the actual HTTP trigger dispatch is not connected"

**Correction**: HTTP dispatch IS connected at `src/http/server.rs:2412-2494`. The issue is **routing depth** - it's basic prefix matching without method filtering or priority ordering.

---

## 5. Recommended Improvements

### Priority 1 (Critical)

| ID | File | Line | Issue | Recommended Fix |
|----|------|------|-------|-----------------|
| PLUGIN-1 | `src/spin/runtime.rs` | 271-285 | `find_route()` returns first match | Implement longest-prefix-match or explicit priority for route selection |
| BUG-2 | `src/plugin/instance_pool.rs` | 152-164 | `body_receiver` not reset in `prepare_for_request` | Add `self.store.data_mut().body_receiver = None;` |

### Priority 2 (High)

| ID | File | Line | Issue | Recommended Fix |
|----|------|------|-------|-----------------|
| PLUGIN-4 | `src/plugin/wasm_runtime.rs` | 946-960 | `mesh_check_threat` is stub returning 0 | Implement actual threat check or document as placeholder |
| BUG-3 | `src/plugin/instance_pool.rs` | 79-148 | warmup incomplete linker | Link all required functions during warmup |

### Priority 3 (Medium)

| ID | File | Line | Issue | Recommended Fix |
|----|------|------|-------|-----------------|
| PLUGIN-2 | `src/plugin/wasm_runtime.rs` | 162-177 | No `load_plugin_from_memory_with_priority` | Add method for priority support in mesh plugin distribution |
| PLUGIN-3 | `src/serverless/manager.rs` | 145-171 | Mesh-only features not documented | Add feature-gate documentation for serverless mesh integration |
| BUG-4 | `src/spin/runtime.rs` | 319 | Hardcoded idle timeout | Make configurable via `SpinRuntimeConfig.idle_timeout_seconds` |

### Priority 4 (Low)

| ID | File | Line | Issue | Recommended Fix |
|----|------|------|-------|-----------------|
| PLUGIN-5 | `src/plugin/wasm_runtime.rs` | 184-210 | `load_component()` is stub | Either implement fully or remove dead code |
| PLUGIN-6 | `architecture/plugin_deep_dive.md` | 33 | Missing `memory_budget_mb` in docs | Update documentation to include all struct fields |

---

## 6. Documentation Corrections Needed

### 6.1 Spin Module Status

**Current**: "routing integration and component mapping is NOT complete"  
**Correct**: "Basic HTTP dispatch is integrated via `src/http/server.rs:2412-2494`. Route matching uses prefix-only comparison without method filtering or priority ordering. Advanced routing (regex, glob, priority) is NOT implemented."

### 6.2 Spin Known Limitations

**Current**: "No Spin HTTP trigger integration"  
**Correct**: "Spin HTTP trigger integration exists at dispatch level. However, only basic prefix route matching is supported - no regex, glob, or explicit priority routing."

### 6.3 WasmResourceLimits Documentation

**Add**: `memory_budget_mb: Option<usize>` - Optional per-plugin memory budget override

### 6.4 Guest ABI Status

**Update** `mesh_check_threat` description: "Stub implementation - always returns 0 (CLEAN). Actual threat intelligence lookups require properly formatted `threat_indicator:{ip}:IpBlock` DHT records."

---

## 7. Verification Commands

```bash
# Verify plugin module compiles
cargo check --lib -p synvoid-plugin

# Verify spin module compiles
cargo check --lib -p synvoid-spin

# Verify serverless module compiles (core only)
cargo check --no-default-features --features ""

# Verify serverless with mesh
cargo check --lib --features mesh

# Run plugin tests
cargo test --lib plugin::

# Run spin tests
cargo test --lib spin::
```

---

## 8. Files Reviewed

| File | Lines | Assessment |
|------|-------|------------|
| `src/plugin/mod.rs` | 424 | Complete implementation |
| `src/plugin/wasm_runtime.rs` | 1922 | Core WASM runtime - mostly complete, component model stub |
| `src/plugin/instance_pool.rs` | 218 | Instance pooling - BUG-2, BUG-3 present |
| `src/plugin/pool.rs` | 33 | Generic pool trait - correct |
| `src/plugin/global.rs` | 268 | Global singletons - correct |
| `src/plugin/wasm_metrics.rs` | 166 | Metrics collection - complete |
| `src/plugin/axum_loader.rs` | 163 | Native plugin loading - complete |
| `src/spin/mod.rs` | 4 | Module declarations only |
| `src/spin/runtime.rs` | 409 | Spin runtime - PLUGIN-1, BUG-4 present |
| `src/spin/handler.rs` | 265 | HTTP handler - complete |
| `src/spin/kv_store.rs` | 152 | In-memory KV - complete |
| `src/spin/manifest.rs` | 197 | Manifest parsing - complete |
| `src/serverless/mod.rs` | 22 | Module exports - feature-gated |
| `src/serverless/manager.rs` | 1245 | Serverless manager - mesh integration incomplete |
| `src/serverless/routing.rs` | 338 | Route matching - complete |
| `src/admin/handlers/spin.rs` | 278 | Admin API for Spin - complete |
| `src/http/server.rs` | 4903 | HTTP dispatch - Spin integration present |

---

## 9. Summary

The Plugin architecture module is **partially complete** with the core WASM runtime being the most mature component. The Spin framework integration is **more functional than documented** but lacks advanced routing features. The serverless module has the most gap between documentation and implementation, particularly around mesh integration.

**Top 3 Actions Required**:
1. Fix `find_route()` to implement longest-prefix-match routing (PLUGIN-1)
2. Fix `body_receiver` reset in pooled instance preparation (BUG-2)  
3. Update architecture document to reflect actual state of Spin integration


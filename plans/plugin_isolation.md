# Plugin and Serverless Isolation Architecture

**Status**: Documented (Priority 9)

## Overview

WASM plugins and serverless functions run inside worker processes via `WasmPluginManager`.
Wasmtime provides sandboxing, but a plugin platform is still a high-risk extension point requiring
explicit architecture decisions around resource limits, host functions, memory budgets, hot reload,
and tenant boundaries.

## 1. Plugin as Extension vs Core

**Decision**: Plugins are an **extension**, not core functionality.

- Core WAF can start without plugin manager initialization
- Plugins are only loaded when explicitly configured via `main_config.plugins.wasm.plugins`
- Plugin system is opt-in via configuration, not a required startup dependency
- `GlobalPluginManager` singleton exists but is lazily initialized and only used when needed

**Evidence**:
- `src/server/mod.rs:819` creates plugin manager only when needed
- `src/worker/unified_server.rs:337` accesses global plugin manager for serverless only
- `PluginManager` is wrapped in `Option<Arc<PluginManager>>` in Router (src/router.rs:40)

## 2. Host Function Policy

### Host Functions by Category

#### Memory/Allocation Host Functions (Default Allow)

| Function | Module | Purpose | Default |
|----------|--------|---------|---------|
| `guest_alloc` | env | Allocate memory in WASM linear memory | Allow |
| `guest_free` | env | Free allocated memory | Allow |
| `abort` | env | WASM abort handler (tracing only) | Allow |

#### Request Context Host Functions (Default Allow)

| Function | Module | Purpose | Default |
|----------|--------|---------|---------|
| `check_timeout` | env | Check elapsed time vs timeout | Allow |
| `get_env` | env | Read env variable by key | Allow |

#### Mesh/DHT Host Functions (Restrictive - Require Explicit Allowlist)

| Function | Module | Purpose | Sensitive Prefix Check | Default |
|----------|--------|---------|------------------------|---------|
| `mesh_query_dht` | env | Query DHT for record by key | Yes - blocks sensitive prefixes | Deny |
| `mesh_check_threat` | env | Check if IP is in threat store | Yes - always blocks | Deny |
| `mesh_emit_event` | env | Emit event to mesh event store | Yes - blocks sensitive topics | Deny |

#### Component Model Host Functions (WIT-defined)

| Function | Instance | Purpose | Default |
|----------|----------|---------|---------|
| `log` | host | Structured logging | Allow |
| `get-header` | host | Read request header | Allow |
| `set-header` | host | Write request header | Allow |
| `get-method` | host | Read HTTP method | Allow |
| `get-uri` | host | Read request URI | Allow |
| `get-body` | host | Read request body | Allow |
| `set-body` | host | Write request body | Allow |
| `set-status` | host | Set response status code | Allow |
| `get-env` | host | Read environment variable | Allow |
| `check-timeout` | host | Check timeout elapsed | Allow |
| `mesh-query-dht` | host | Query DHT | Deny (requires allowlist) |
| `mesh-check-threat` | host | Check threat store | Deny (requires allowlist) |
| `mesh-emit-event` | host | Emit mesh event | Deny (requires allowlist) |

### Sensitive Prefix Enforcement (mesh_query_dht)

The `mesh_query_dht` host function enforces DHT access prefixes. The following prefixes
are considered sensitive and blocked by default:

```
threat_indicator:
yara_rule:
yara_rules_manifest:
edge_attestation:
dns_zone:
dns_record:
dns_domain_reg:
```

A plugin must have the exact prefix in `allowed_dht_prefixes` configuration to access these keys.
For example, if `allowed_dht_prefixes: ["threat_indicator:"]` is configured, the plugin can only
query keys starting with `threat_indicator:`.

### WASI Support

WASI is **disabled by default** (`wasi_enabled: false` in `WasmResourceLimits::default()`).
Even when `wasi_enabled: true` is set in config, WASI is a compile-time link option, not a runtime
capability grant.

## 3. Resource Limits

### Enforced Resource Limits

| Limit | Default | Config Field | Enforcement |
|-------|---------|--------------|-------------|
| Memory (WASM linear) | 64MB | `max_memory_mb` | `ResourceLimiter::memory_growing` |
| Table elements | None (unlimited) | `max_table_elements` | `ResourceLimiter::table_growing` |
| CPU fuel | 1,000,000 units | `max_cpu_fuel` | `store.set_fuel()` + fuel consumption tracking |
| Timeout (wall clock) | 30 seconds | `timeout_seconds` | `check_timeout()` called in each invocation |
| Max instances per runtime | 1 | `max_instances` | `WasmInstancePool` pool size |
| Request/response data size | 1MB | `MAX_WASM_DATA_SIZE` | Pre-copy check in `write_to_guest_memory` |

### Fuel/Timeout Enforcement Points

Fuel and timeouts are enforced for every invocation path:

1. **`filter_request`** - wasm_runtime.rs:1285-1290
   - Timeout checked at line 1263 via `Self::check_timeout(&*store)?`
   - Fuel consumed via `filter_fn.call()`
   - Fuel tracking at lines 1299-1304

2. **`transform_response`** - wasm_runtime.rs:1423
   - Timeout checked before calling transform_fn
   - Fuel consumed via `transform_fn.call()`
   - Fuel tracking at lines 1444-1449

3. **`handle_request` (serverless)** - wasm_runtime.rs:1526
   - Timeout checked before calling handle_fn
   - Fuel consumed via `handle_fn.call()`
   - Fuel tracking at lines 1565-1570

### Memory Budget Enforcement

**Issue Identified**: The `GlobalWasmMemoryBudget` in `global.rs` tracks allocations, but there is a bypass path:

1. `GlobalPluginManager::record_allocation()` (global.rs:143) uses key `"global"` not plugin-specific
2. `record_deallocation()` (global.rs:149) also uses `"global"`
3. Plugin-specific allocation tracking via `try_allocate("plugin_name", ...)` exists but is not called by `WasmPluginManager` or `WasmRuntime`

The `GlobalWasmMemoryBudget` is essentially a no-op for actual plugin memory enforcement since:
- `WasmRuntime::load()` doesn't call `try_allocate()`
- `WasmRuntime::create_store()` doesn't call `try_allocate()`
- Instance pooling doesn't track memory via `GlobalWasmMemoryBudget`

**Actual memory enforcement** comes from:
- `ResourceLimiter` implementation on `RequestContext` (wasm_runtime.rs:529-546)
- `memory_growing()` returns `Ok(desired <= self.max_memory)` to limit growth
- Per-runtime `max_memory_mb` limit applied at store creation (wasm_runtime.rs:962)

### Max Body Size Enforcement

Before copying request/response body into WASM memory:

```rust
const MAX_WASM_DATA_SIZE: usize = 1024 * 1024; // 1MB

// In write_to_guest_memory (wasm_runtime.rs:1074-1080)
if data_len > MAX_WASM_DATA_SIZE {
    return Err(WasmPluginError::SandboxError(format!(
        "data size {} exceeds max {}",
        data_len, MAX_WASM_DATA_SIZE
    )));
}
```

This check is applied before any memory allocation or copy occurs.

### Memory Budget Bypass Concerns

The plan notes "Confirm memory budget cannot be bypassed by reload or duplicate names". Current status:

- **Reload**: When `reload_plugin()` is called (wasm_runtime.rs:386), the old runtime is replaced.
  The `GlobalWasmMemoryBudget` is not updated on reload, but since the budget tracking is not connected
  to actual runtime memory, this is not a bypass concern - the budget is not enforcing anything.

- **Duplicate names**: `load_plugin()` in WasmPluginManager (wasm_runtime.rs:146) pushes to `runtimes` Vec
  without checking for duplicates. A malicious actor with config access could load the same plugin twice,
  doubling memory usage while budget shows only one allocation.

## 4. Hot Reload Status

### File Watcher Lifecycle Issue

In `src/server/mod.rs:874-880`:

```rust
// Enable hot-reload for plugin directory.
// The lifecycle (and its file watcher) is intentionally leaked
// so the watcher thread stays alive for the server's lifetime.
if let Err(e) = lifecycle.enable_hot_reload(plugin_dir) {
    tracing::debug!("Hot-reload not enabled: {}", e);
}
std::mem::forget(lifecycle);
```

**Issue**: The `PluginManagerLifecycle` is intentionally leaked to keep the watcher alive. The comment
acknowledges this is non-ideal - the watcher lifecycle is not properly tied to server shutdown.

**Proper pattern**: `PluginManagerLifecycle` implements `shutdown()` which drops `_watcher` (the Option),
but since we leak the lifecycle, `shutdown()` is never called.

### Plugin Reload Atomicity

The `reload_plugin()` method in `WasmPluginManager` (wasm_runtime.rs:386-415):

```rust
pub fn reload_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError> {
    // ... get name and priority from existing runtime ...
    let new_runtime = WasmRuntime::load_with_priority(...)?;
    let new_arc = Arc::new(new_runtime);

    {
        let mut runtimes = self.runtimes.write();
        runtimes.retain(|r| r.name() != name);  // Remove old
        runtimes.push(new_arc.clone());         // Add new
    }
    // ...
}
```

This is **atomic in terms of the runtimes list** - the old runtime is removed and new one added in
a single write lock. However:
- Existing in-flight requests using the old runtime will continue until they complete
- The old runtime stays alive as long as any in-flight requests hold references
- No explicit transition window or "all old requests drained" signal exists

### Hot Reload Summary

| Aspect | Status |
|--------|--------|
| File watcher exists | Yes |
| Watcher lifecycle tied to shutdown | **No** - intentionally leaked |
| Plugin reload is atomic (list update) | Yes |
| Old plugin instances drained before cleanup | No - reference counted |
| Reload contract documented | Yes (plans/reload_contract.md) |

## 5. Process Isolation

**Status**: Not implemented. Current Wasmtime sandboxing is considered sufficient for the target
deployment model.

The plan recommends deferring process isolation for untrusted plugins unless required.

## Open Items / Concerns

1. **Memory budget not enforced for individual plugins** - `GlobalWasmMemoryBudget` exists but is not
   wired to actual plugin loading/unloading. Per-plugin memory accounting is not active.

2. **Duplicate plugin name bypass** - Loading same plugin twice doubles memory usage under same budget.

3. **Hot reload watcher leak** - `PluginManagerLifecycle` is leaked in server startup, watcher never
   stopped cleanly on shutdown.

4. **WASI disabled by default but linked** - WASI functions are always linked if `wasi_enabled` is true,
   but no capability grant mechanism beyond config boolean.

## Recommendations

1. Wire `GlobalWasmMemoryBudget::try_allocate()` into `WasmRuntime::load()` and `deallocate()` into unload
2. Add duplicate name check in `WasmPluginManager::load_plugin()`
3. Replace `std::mem::forget(lifecycle)` with proper lifecycle management via `ServerSharedState`
4. Add explicit `restart_required` status for plugin config changes that can't be hot-reloaded
# Serverless Architecture Review - synvoid

**Review Date:** 2026-05-27
**Reviewed Document:** `architecture/serverless.md`
**Source Code Paths:** `src/serverless/`, `src/plugin/`

---

## Verified Correct Items

The following items in the documentation correctly match the implementation:

### Module Structure (Section 2)
| File | Documentation | Actual | Status |
|------|---------------|--------|--------|
| `mod.rs` | Public exports for serverless module | `src/serverless/mod.rs` (22 lines) | ✅ |
| `manager.rs` | Central `ServerlessManager` | `src/serverless/manager.rs` (1271 lines) | ✅ |
| `instance_pool.rs` | `InstancePool` with autoscaling | `src/serverless/instance_pool.rs` (655 lines) | ✅ |
| `async_compilation.rs` | `AsyncCompilationHandle/Manager` | `src/serverless/async_compilation.rs` (213 lines) | ✅ |
| `registry.rs` | `ServerlessRegistry` | `src/serverless/registry.rs` (108 lines) | ✅ |
| `routing.rs` | `ServerlessRoute` and route matching | `src/serverless/routing.rs` (338 lines) | ✅ |

### Plugin Module Structure (Section 2)
| File | Documentation | Actual | Status |
|------|---------------|--------|--------|
| `mod.rs` | `PluginManager` with hot-reload | `src/plugin/mod.rs` (424 lines) | ✅ |
| `wasm_runtime.rs` | `WasmRuntime` and `WasmPluginManager` | `src/plugin/wasm_runtime.rs` (1920 lines) | ✅ |
| `instance_pool.rs` | `WasmInstancePool` for filters | `src/plugin/instance_pool.rs` (288 lines) | ✅ |
| `pool.rs` | `PooledInstance` and `WasmPool` trait | `src/plugin/pool.rs` (37 lines) | ✅ |
| `axum_loader.rs` | Native Axum plugin loader | `src/plugin/axum_loader.rs` (163 lines) | ✅ |
| `global.rs` | Global `PluginManager` singleton | `src/plugin/global.rs` (268 lines) | ✅ |
| `wasm_metrics.rs` | Prometheus metrics | `src/plugin/wasm_metrics.rs` (166 lines) | ✅ |

### Core Data Structures (Section 3)
| Struct | Documentation Location | Actual Location | Status |
|--------|------------------------|-----------------|--------|
| `CallerContext` | `src/serverless/manager.rs` | `manager.rs:22-30` | ✅ |
| `ServerlessFunction` | `src/serverless/manager.rs` | `manager.rs:80-85` | ✅ |
| `ServerlessResponse` | `src/serverless/manager.rs` | `manager.rs:87-94` | ✅ |
| `ServerlessError` | `src/serverless/manager.rs` | `manager.rs:56-78` | ✅ |
| `InstancePoolConfig` | `src/serverless/instance_pool.rs` | `instance_pool.rs:10-21` | ✅ |
| `ServerlessInstance` | `src/serverless/instance_pool.rs` | `instance_pool.rs:64-71` | ✅ |
| `InstancePoolMode` | `src/serverless/instance_pool.rs` | `instance_pool.rs:81-87` | ✅ |
| `InstanceMetrics` | `src/serverless/instance_pool.rs` | `instance_pool.rs:39-48` | ✅ |
| `RouteMatch` | `src/serverless/routing.rs` | `routing.rs:5-15` | ✅ |
| `MethodMatch` | `src/serverless/routing.rs` | `routing.rs:94-99` | ✅ |
| `ServerlessRoute` | `src/serverless/routing.rs` | `routing.rs:111-117` | ✅ |
| `WasmResourceLimits` | `src/plugin/wasm_runtime.rs` | `wasm_runtime.rs:51-61` | ✅ |
| `RequestContext` | `src/plugin/wasm_runtime.rs` | `wasm_runtime.rs:515-523` | ✅ |
| `GuestExports` | `src/plugin/wasm_runtime.rs` | `wasm_runtime.rs:78-86` | ✅ |
| `WasmFilterResult` | `src/plugin/mod.rs` | `mod.rs:21-25` | ✅ |
| `WasmPluginError` | `src/plugin/mod.rs` | `mod.rs:27-37` | ✅ |
| `PluginManager` | `src/plugin/mod.rs` | `mod.rs:41-44` | ✅ |
| `PluginManagerLifecycle` | `src/plugin/mod.rs` | `mod.rs:202-207` | ✅ |

### Key API Signatures (Section 4)
| Function | Doc Line | Actual Line | Status |
|----------|----------|-------------|--------|
| `ServerlessManager::new()` | 247 | `manager.rs:118` | ✅ |
| `ServerlessManager::with_runtime()` | 250 | `manager.rs:140` | ✅ |
| `ServerlessManager::initialize()` | 253 | `manager.rs:359` | ✅ |
| `ServerlessManager::is_enabled()` | 256 | `manager.rs:784` | ✅ |
| `ServerlessManager::get_function()` | 259 | `manager.rs:732` | ✅ |
| `ServerlessManager::get_all_functions()` | 262 | `manager.rs:736` | ✅ |
| `ServerlessManager::find_matching_function()` | 265 | `manager.rs:744` | ✅ |
| `ServerlessManager::find_matching_route()` | 268 | `manager.rs:756` | ✅ |
| `handle_serverless_function()` | 305, 1049 | `manager.rs:1049` | ✅ |
| `InstancePool::new()` | 321 | `instance_pool.rs:161` | ✅ |
| `InstancePool::initialize()` | 325 | `instance_pool.rs:209` | ✅ |
| `InstancePool::get_instance()` | 328 | `instance_pool.rs:243` | ✅ |
| `InstancePool::return_instance()` | 331 | `instance_pool.rs:272` | ✅ |
| `InstancePool::scale_up()` | 334 | `instance_pool.rs:292` | ✅ |
| `InstancePool::scale_down()` | 337 | `instance_pool.rs:325` | ✅ |
| `InstancePool::run_autoscaler()` | 340 | `instance_pool.rs:415` | ✅ |
| `InstancePool::shutdown()` | 343 | `instance_pool.rs:455` | ✅ |
| `InstancePool::get_metrics()` | 346 | `instance_pool.rs:515` | ✅ |
| `InstancePool::check_health()` | 349 | `instance_pool.rs:571` | ✅ |
| `WasmRuntime::load()` | 366 | `wasm_runtime.rs:546` | ✅ |
| `WasmRuntime::load_from_bytes()` | 369 | `wasm_runtime.rs:550` | ✅ |
| `WasmRuntime::load_with_priority()` | 373 | `wasm_runtime.rs:622` | ✅ |
| `WasmRuntime::invoke_handler()` | 385 | `wasm_runtime.rs:1717` | ✅ |
| `PluginManager::new()` | 399 | `mod.rs:52` | ✅ |
| `PluginManager::load_wasm_plugin()` | 403 | `mod.rs:67,90` | ✅ |
| `PluginManager::load_axum_plugin()` | 406 | `mod.rs:95` | ✅ |
| `PluginManager::apply_wasm_filters()` | 409 | `mod.rs:141` | ✅ |
| `PluginManagerLifecycle::load_plugins_from_dir()` | 428 | `mod.rs:220` | ✅ |
| `PluginManagerLifecycle::enable_hot_reload()` | 434 | `mod.rs:302` | ✅ |

### Implementation Details Verified
| Item | Doc Location | Actual Location | Status |
|------|--------------|------------------|--------|
| Global engine pool | `instance_pool.rs:103-105` | `instance_pool.rs:103-105` | ✅ |
| Pre-warming at startup | lines 599-608 | `instance_pool.rs:209-228` | ✅ |
| Autoscaler loop | lines 614-629 | `instance_pool.rs:415-452` | ✅ |
| `ServerlessRoute::matches(path, method)` | `routing.rs:120` | `routing.rs:120` | ✅ |
| Sensitive DHT prefixes list | `wasm_runtime.rs:849-857` | `wasm_runtime.rs:849-857` | ✅ |
| ResourceLimiter impl | lines 646-656 | `wasm_runtime.rs:525-543` | ✅ |

---

## Discrepancies Found

### 1. Documentation Lists `pub async fn shutdown(&self)` for ServerlessManager (Critical)

**Doc Section:** 4, line 284
**Doc says:**
```rust
/// Graceful shutdown of all instance pools
pub async fn shutdown(&self);
```

**Actual:** `ServerlessManager` does NOT have a `shutdown` method. The `shutdown` method exists on `InstancePool` at `instance_pool.rs:455`.

**Impact:** High - API documentation is misleading; developers expecting `ServerlessManager::shutdown()` will get a compile error.

---

### 2. Missing `scheduler.rs` Module (Medium)

**Doc Section:** 2 (Key Submodules table)
**Documentation:** Does not list `scheduler.rs`
**Actual:** `src/serverless/scheduler.rs` exists with 170 lines containing `ServerlessScheduler`, `TimerEntry`, and `TimerPayload` trait.

**Impact:** Medium - The scheduler functionality is completely undocumented in the architecture document.

---

### 3. Missing Public Functions in ServerlessManager API (Medium)

**Doc Section:** 4 (Key APIs - ServerlessManager)
**Missing functions:**
| Function | Actual Line | Not in Doc |
|----------|-------------|------------|
| `has_function(&self) -> bool` | `manager.rs:740` | ✅ Missing |
| `get_subscribed_functions(&self, &str) -> Vec<String>` | `manager.rs:212` | ✅ Missing |
| `subscribe_to_event(&self, &str, String)` | `manager.rs:185` | ✅ Missing |
| `unsubscribe_from_event(&self, &str, &str)` | `manager.rs:200` | ✅ Missing |
| `publish_event(&self, &str, &[u8])` | `manager.rs:220` | ✅ Missing |
| `get_global_serverless_registry()` | `registry.rs:106` | ✅ Missing |

**Impact:** Medium - Event subscription system and utility functions not documented.

---

### 4. Missing `handle_serverless_function_streaming` (Medium)

**Doc Section:** 4 (Key APIs)
**Documentation:** Only shows `handle_serverless_function`
**Actual:** `handle_serverless_function_streaming` exists at `manager.rs:1224` with signature:
```rust
pub async fn handle_serverless_function_streaming(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Box<dyn ErasedBody>,
    _context: CallerContext,
) -> Result<Response<Bytes>, ServerlessError>
```

**Impact:** Medium - Streaming handler API not documented.

---

### 5. Missing AsyncCompilationHandle Methods in API (Low)

**Doc Section:** 4
**Documentation:** Mentions `AsyncCompilationHandle` only via `get_compilation_status`
**Actual:** `AsyncCompilationHandle` has additional methods:
- `start_compilation()` at `async_compilation.rs:51`
- `set_ready()` at `async_compilation.rs:60`
- `set_failed(String)` at `async_compilation.rs:71`
- `wait_for_completion()` at `async_compilation.rs:89`
- `poll_state()` at `async_compilation.rs:103`

**Impact:** Low - Async compilation API incomplete.

---

### 6. Missing Return Types in ServerlessManager API (Low)

**Doc Section:** 4
**Issue:** Several functions documented without return types:
- `subscribe_to_event` (line 275) - no return type shown
- `unsubscribe_from_event` (line 278) - no return type shown
- `publish_event` (line 281) - no return type shown
- `get_subscribed_functions` - not in doc at all

**Impact:** Low - Minor incompleteness.

---

## Bugs Identified

### BUG-SL-1: `handle_serverless_function` Missing from Non-Mesh Build

**Severity:** Medium
**Location:** `src/serverless/mod.rs:13-18`

**Issue:** `handle_serverless_function` is only exported when `#[cfg(feature = "mesh")]`. The documentation shows it at `manager.rs:1049` but the function signature is:

```rust
#[cfg(feature = "mesh")]
pub async fn handle_serverless_function(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    caller: CallerContext,
) -> Result<Response<Bytes>, ServerlessError>;
```

**Impact:** Without `mesh` feature, this entry point is not available. The doc doesn't mention this limitation.

---

### BUG-SL-2: PooledInstance allowed_dht_prefixes Not Reset on Return (Was Fixed)

**Severity:** N/A (FIXED)
**Location:** `src/plugin/pool.rs:15-26`
**AGENTS.md Status:** Fixed 2026-05-27

**Issue:** Previously, `PooledInstance` did not reset `allowed_dht_prefixes` between requests, causing potential data leakage between tenants. The `prepare_for_request` method at `pool.rs:16-30` now properly resets this field at line 26.

**Current Code (pool.rs:16-30):**
```rust
pub fn prepare_for_request(
    &mut self,
    env: std::collections::HashMap<String, String>,
    timeout_seconds: u64,
    allowed_dht_prefixes: Vec<String>,
) {
    self.store.data_mut().start = Instant::now();
    self.store.data_mut().timeout = Duration::from_secs(timeout_seconds);
    self.store.data_mut().env = env;
    self.store.data_mut().body_receiver = None;
    self.store.data_mut().allowed_dht_prefixes = allowed_dht_prefixes; // FIXED
    if self.max_cpu_fuel > 0 {
        self.store.set_fuel(self.max_cpu_fuel).ok();
    }
}
```

**Status:** ✅ Correctly fixed.

---

### BUG-SL-3: Documentation References Non-Existent `shutdown` on ServerlessManager

**Severity:** Medium
**Location:** `architecture/serverless.md:284`

**Issue:** Documentation claims `ServerlessManager` has `pub async fn shutdown(&self)` but this method doesn't exist. The `shutdown` is on `InstancePool`.

**Impact:** Developers following the documentation will get a compile error.

---

## Suggested Improvements

### IMP-1: Document `scheduler.rs` Module

The `ServerlessScheduler` and `TimerEntry` types are completely undocumented despite being part of the serverless module.建议在文档中添加：
```rust
// src/serverless/scheduler.rs

pub struct ServerlessScheduler { ... }
pub struct TimerEntry { ... }
pub trait TimerPayload { ... }
```

### IMP-2: Add `mesh` Feature Gate Notes

Section 8 (Feature Gates) correctly documents the mesh feature, but the `handle_serverless_function` entry point should explicitly note it's only available with `mesh` enabled.

### IMP-3: Document Event Subscription System

The `subscribe_to_event`, `unsubscribe_from_event`, and `publish_event` methods should be documented in the ServerlessManager API section.

### IMP-4: Add Streaming API Documentation

`handle_serverless_function_streaming` at `manager.rs:1224` should be documented alongside the synchronous version.

### IMP-5: Fix `shutdown` Documentation

Either:
1. Remove `pub async fn shutdown(&self)` from ServerlessManager docs, OR
2. Add actual `shutdown` method to `ServerlessManager` that calls shutdown on all pools

### IMP-6: Add Missing Return Types

Several methods in section 4 are missing return types in the documentation. Complete the signatures.

### IMP-7: Document Async Compilation API

Add `AsyncCompilationHandle` methods to documentation:
- `start_compilation()`
- `set_ready()`
- `set_failed(error: String)`
- `wait_for_completion() -> Result<(), WasmPluginError>`
- `poll_state() -> CompilationState`

### IMP-8: Add `has_function` to API

Document `ServerlessManager::has_function(&self, name: &str) -> bool` which exists at `manager.rs:740`.

### IMP-9: Document `get_global_serverless_registry`

Add this to the registry section or as a utility function.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct Items | 45+ |
| Discrepancies | 6 |
| Bugs (excluding fixed) | 1 |
| Suggested Improvements | 9 |

**Overall Assessment:** The architecture document is largely accurate and well-structured. The main issues are:
1. Documentation of `shutdown` method that doesn't exist on `ServerlessManager`
2. Missing `scheduler.rs` module from the overview
3. Several undocumented public functions (event subscription, streaming, utility methods)

The code quality is good, and the PooledInstance DHT prefix leak bug (BUG-SL-2) is correctly marked as FIXED in AGENTS.md.
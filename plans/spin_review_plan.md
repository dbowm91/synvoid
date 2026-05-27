# Spin WASM Runtime Architecture Review

**Review Date:** 2026-05-27
**Source Document:** `architecture/spin.md`
**Source Code:** `src/spin/`, `src/plugin/`

---

## Verified Correct Items

### Module Structure ✅
- All 4 modules exist: `runtime.rs` (383 lines), `manifest.rs` (232 lines), `kv_store.rs` (152 lines), `handler.rs` (265 lines)
- Total ~1,032 lines matches documentation

### Key Types ✅
- `SpinRuntimeConfig` - All fields match at `src/spin/runtime.rs:17-25`
- `SpinAppInstance` - All fields match at `src/spin/runtime.rs:41-50`
- `SpinRuntime` - All fields match at `src/spin/runtime.rs:119-127`
- `WasmResourceLimits` - All fields match at `src/plugin/wasm_runtime.rs:52-61`

### Error Hierarchy ✅
- `SpinRuntimeError` variants match at `src/spin/runtime.rs:342-360`
- `SpinHandlerError` variants match at `src/spin/handler.rs:107-115`
- `SpinManifestError` variants match at `src/spin/manifest.rs:147-157`

### KV Store Implementation ✅
- Uses `crate::utils::safe_unix_timestamp()` for TTL checks (per AGENTS.md standard)
- TTL check logic at `src/spin/kv_store.rs:27-31`

### Default Config Values ✅
- `idle_timeout_seconds: 300` at `runtime.rs:36`
- `max_instances: 10` at `runtime.rs:33`
- `default_timeout_seconds: 30` at `runtime.rs:34`

### WASI Default ✅
- Default `true` for Spin components at `runtime.rs:196`:
  ```rust
  let wasi_enabled = component.wasi.as_ref().map(|w| w.enabled).unwrap_or(true);
  ```

### Admin API Endpoints ✅
- All 5 endpoints correctly implemented at `src/admin/handlers/spin.rs`
- Routes registered at `src/admin/mod.rs:744-752`

### Cold-Start Caching Logic ✅
- Two-tier caching (`compiled_runtimes`, `cached_instances`) correctly documented
- 5-minute idle timeout implemented at `runtime.rs:294`
- `reuse()` called to update `last_request` and `request_count` at `runtime.rs:269`

---

## Discrepancies Found

### D1: Header Serialization Mismatch (Medium)
**Location:** `architecture/spin.md:369` vs `src/spin/runtime.rs:271`

The documentation states WASM modules receive headers in "compact binary format" via `WasmRuntime::serialize_headers()`, but `SpinRuntime::handle_http_request()` actually serializes headers as JSON via `SpinRuntime::serialize_headers_spin()` before passing to `invoke_handler()`.

**Impact:** Documentation implies binary format but Spin uses JSON. This is a functional difference, not a bug.

**Current code at `runtime.rs:271`:**
```rust
let headers_json = Self::serialize_headers_spin(headers);
```

### D2: Module Organization Description Inaccurate
**Location:** `architecture/spin.md:684`

Documentation states:
> `mod.rs` - Module declarations (handler, kv_store, manifest, runtime)

**Actual:** `mod.rs` only contains:
```rust
pub mod handler;
pub mod kv_store;
pub mod manifest;
pub mod runtime;
```

The module declarations are in each individual file, not in `mod.rs`. This is misleading.

### D3: SpinHttpHandler Async/Sync Confusion (Medium)
**Location:** `src/spin/handler.rs:126-174`

Two near-identical methods exist:
- `handle_request` (async) at lines 126-149
- `handle_request_sync` at lines 151-174

`http/server.rs:2441` calls `handler.handle_request(spin_request)` without `await`:
```rust
match handler.handle_request(spin_request).await {
```

This works because the async method is just a thin wrapper that synchronously calls `runtime.handle_http_request()` and wraps the result. However, the existence of both methods and the way it's called is confusing.

### D4: WasmRuntime Pool Field Documentation
**Location:** `architecture/spin.md:349-359`

The struct definition shows:
```rust
pool: Arc<WasmInstancePool>,
```

But the WasmInstancePool created in `load_with_priority()` is stored in the WasmRuntime. The documentation doesn't explain that this pool is pre-populated with instances up to `max_instances` (1 for Spin).

---

## Bugs Identified

### BUG-SPIN-1: Concurrent Instance Creation (Medium Severity)
**Location:** `src/spin/runtime.rs:289-303`

**Issue:** `get_or_create_instance()` has a race condition. Two concurrent requests for the same idle component can both see the cached instance as idle, both instantiate new instances, and both insert into `cached_instances`. The second insert overwrites the first.

```rust
fn get_or_create_instance(&self, component_id: &str) -> Result<SpinAppInstance, SpinRuntimeError> {
    if let Some(instance) = self.cached_instances.read().get(component_id).cloned() {
        if !instance.is_idle(Duration::from_secs(300)) {
            return Ok(instance);
        }
    }
    let instance = self.instantiate_app(component_id)?;  // Both threads can reach here
    self.cached_instances
        .write()
        .insert(component_id.to_string(), instance.clone());  // Second overwrites first
    Ok(instance)
}
```

**Impact:** Under high concurrency, multiple instances for the same component may be created, defeating the caching purpose and wasting memory.

**Fix:** Use `RwLock` to make the check-and-create atomic, or use `Entry` API with `or_insert_with()`.

### BUG-SPIN-2: Lock Acquisition Order Inconsistency (Low Severity)
**Location:** `src/spin/runtime.rs:289-303` vs `src/spin/runtime.rs:167-237`

`get_or_create_instance()` acquires `cached_instances` read lock first, then upgrade to write lock for insertion.

`instantiate_app()` acquires `compiled_runtimes` read lock, drops it, then acquires write lock for insertion.

This inconsistent locking pattern makes the code harder to reason about and could lead to deadlocks if more complex locking scenarios arise.

### BUG-SPIN-3: SpinAppsManager Uses Async-Await Without Await
**Location:** `src/http/server.rs:2441`

```rust
match handler.handle_request(spin_request).await {
```

The `.await` is present, so this is actually correct. However, the async `handle_request` method at `handler.rs:126-149` is misleading - it's not truly async (doesn't do any async operations), just wraps sync code in a future.

**Impact:** Low - works correctly but confusing design.

---

## Suggested Improvements

### IMP-1: Document Header Serialization Behavior
**File:** `architecture/spin.md`

Clarify that Spin components receive headers as JSON (via `SpinRuntime::serialize_headers_spin`), while raw WASM plugins receive binary format (via `WasmRuntime::serialize_headers`).

### IMP-2: Fix Module Organization Description
**File:** `architecture/spin.md:684`

Change from:
> `mod.rs` - Module declarations (handler, kv_store, manifest, runtime)

To something like:
> `mod.rs` - Module re-exports
> Each submodule contains its own implementation

### IMP-3: Add Lock Acquisition Order Documentation
**File:** `src/spin/runtime.rs`

Add internal documentation about the locking strategy used across methods.

### IMP-4: Consider Consolidating Async/Sync Handlers
**File:** `src/spin/handler.rs:126-174`

The async `handle_request` and sync `handle_request_sync` are nearly identical. Consider:
1. Making `handle_request` truly async if there's a benefit
2. Having `handle_request` call `handle_request_sync` internally
3. Documenting clearly when to use each

### IMP-5: Add Race Condition Test
**File:** `src/spin/runtime.rs`

Add a concurrent access test to verify `get_or_create_instance()` behavior under load.

### IMP-6: Update AGENTS.md Line Reference
**File:** `AGENTS.md`

The "Spin cold-start instance reuse" fix is referenced at `src/spin/runtime.rs:258`. The relevant code is actually at lines 289-303 (`get_or_create_instance`). Update line reference for accuracy.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 9 |
| Discrepancies | 4 |
| Bugs | 3 |
| Improvements | 6 |

**Overall Assessment:** The documentation is largely accurate. The Spin WASM runtime implementation is functionally correct and follows the documented architecture. The main issues are:
1. Minor documentation inaccuracies (header format, module organization)
2. One race condition in concurrent instance creation (BUG-SPIN-1)
3. Inconsistent locking patterns

The cold-start fix referenced in AGENTS.md is correctly implemented - the 5-minute idle timeout is at line 294, with the full `get_or_create_instance` logic spanning lines 289-303.
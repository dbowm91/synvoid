# Performance Optimization - Improvement Plan

**Status**: Planning
**Plan Number**: 18
**Last Updated**: 2026-04-27
**Implementation Phase**: To Be Scheduled

---

## Executive Summary

This plan addresses 13 performance issues identified during a comprehensive codebase performance review. The primary goal is optimization for the target scalability of **500K requests/second**.

### Issues Addressed by Priority

| Priority | # | Issue | Severity | Est. Allocations Saved/sec |
|----------|---|-------|----------|---------------------------|
| CRITICAL | 1 | WASM instance pooling bypass (`transform_response`/`invoke_handler`) | CRITICAL | 500K Store + instantiate |
| HIGH | 2 | WAF double normalization | HIGH | 500K normalization passes |
| HIGH | 3 | Mesh provider_stats lock contention | HIGH | 5M+ write locks eliminated |
| HIGH | 4 | HTTP server per-request allocations | HIGH | ~1-2M string allocations |
| HIGH | 5 | Cache key 5 sequential `replace()` calls | HIGH | 2.5M allocations |
| MEDIUM | 6 | O(n²) weighted_shuffle_providers algorithm | MEDIUM | 100x reduction |
| MEDIUM | 7 | serde_json → postcard in hot paths | MEDIUM | ~0.5-1ms/sec aggregate |
| MEDIUM | 8 | HashMap allocation in calculate_string_entropy | MEDIUM | 500K HashMap allocs |
| MEDIUM | 9 | Linear search in open_redirect redirect_param_patterns | MEDIUM | 78x fewer comparisons |
| MEDIUM | 10 | WASM linker recreation per request | MEDIUM | ~165K linker creations |
| MEDIUM | 11 | sorted_runtimes() re-sorts on every request | MEDIUM | 500K sorts eliminated |
| MEDIUM | 12 | WASM per-runtime request/env cloning | MEDIUM | 2x clones per runtime |
| LOW | 13 | O(n) backend lookup (dead code - future) | LOW | N/A (unused) |

---

## Architecture Overview

### Hot Path Locations

Per AGENTS.md, the following are confirmed hot paths executing on **every request**:

```
src/waf/attack_detection/     # WAF rule matching (per-request on ALL inputs)
src/mesh/proxy.rs              # Mesh proxy routing, caching, provider selection
src/http/server.rs             # HTTP request handling
src/http3/server.rs            # HTTP/3 QUIC request handling
src/proxy/mod.rs               # Upstream proxy, cookie/cache key construction
src/plugin/wasm_runtime.rs     # WASM plugin filter/transform per request
```

### Scalability Target Implications

At **500K requests/second**:
- 1 extra allocation/req × 500K = **500K allocations/sec**
- 8 extra allocations/req × 500K = **4M allocations/sec**
- Every write lock × 500K = significant blocking

---

## Phase 1: Critical Priority

### Issue 1: WASM Instance Pooling Bypass (CRITICAL)

**Problem**: `transform_response()` and `invoke_handler()` create **new `Store` + `instantiate()` per request** instead of using the instance pool. At 500K rps with transforms, this creates 500K Store allocations and 500K instantiate calls/sec.

**Location**: `src/plugin/wasm_runtime.rs:1158-1159, 1267-1268`

**Current Code**:
```rust
// transform_response() - lines 1157-1159
let mut store = self.create_store(env);      // ALWAYS creates new Store
let exports = self.instantiate(&mut store)?; // ALWAYS instantiates fresh

// invoke_handler() - lines 1267-1268
let mut store = self.create_store(env);      // ALWAYS creates new Store
let exports = self.instantiate(&mut store)?; // ALWAYS instantiates fresh
```

**Correct Pattern** (from `filter_request()` lines 1006-1019):
```rust
let pooled_instance = self.pool.get(&self.name);
if let Some(mut inst) = pooled_instance {
    inst.prepare_for_request(env, self.limits.timeout_seconds);
    let exports = WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
    let result = self.do_filter_request_with_exports(parts, body, &mut inst.store, exports);
    self.pool.return_instance(inst);
    return result;
}
// Fallback: create fresh store but don't pool
let mut store = self.create_store(env);
let exports = self.instantiate(&mut store)?;
self.do_filter_request_with_exports(parts, body, &mut store, exports)
```

**Implementation Steps**:

**Step 1.1**: Extract logic to helper methods

Create two new helper methods that take pre-instantiated store/exports:

```rust
// In wasm_runtime.rs, add after line 1019
fn do_transform_response_with_exports(
    &self,
    parts: RequestParts,
    body: Bytes,
    store: &mut Store<RequestContext>,
    exports: GuestExports,
) -> Result<TransformResult, WasmPluginError> {
    // Lines 1161-1228: existing transform_response logic
}

// Similarly for invoke_handler (lines 1270-1372)
fn do_invoke_handler_with_exports(
    &self,
    method: &str,
    uri: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    store: &mut Store<RequestContext>,
    exports: GuestExports,
) -> Result<HandlerResult, WasmPluginError> {
    // Lines 1270-1372: existing invoke_handler logic
}
```

**Step 1.2**: Rewrite `transform_response()` to use pooling

Replace lines 1157-1159:
```rust
// NEW: Uses pooled instance with fallback
if let Some(mut inst) = self.pool.get(&self.name) {
    inst.prepare_for_request(env, self.limits.timeout_seconds);
    let exports = WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
    let result = self.do_transform_response_with_exports(parts, body, &mut inst.store, exports);
    self.pool.return_instance(inst);
    return result;
}
// Fallback: create fresh store/instantiate (no pooling)
let mut store = self.create_store(env);
let exports = self.instantiate(&mut store)?;
self.do_transform_response_with_exports(parts, body, &mut store, exports)
```

**Step 1.3**: Rewrite `invoke_handler()` to use pooling

Replace lines 1267-1268 similarly.

**Files to Modify**:
- `src/plugin/wasm_runtime.rs` - Extract helpers, update both methods

**Verification**:
- `cargo test --lib --no-run` to verify test compilation
- `cargo test --test integration_test` for integration tests

---

### Issue 2: WASM Per-Runtime Cloning

**Problem**: `WasmPluginManager::filter_request()` clones `request` and `env` **per runtime** in the loop. With 3 runtimes, that's 3 clones each.

**Location**: `src/plugin/wasm_runtime.rs:233-245`

**Current Code**:
```rust
for runtime in self.sorted_runtimes().iter() {
    match runtime.filter_request(request.clone(), env.clone())? {  // Clone per runtime!
```

**Fix**: Clone once before the loop:

```rust
let request = request.clone();  // Clone once
let env = env.clone();          // Clone once
for runtime in self.sorted_runtimes().iter() {
    match runtime.filter_request(request.clone(), env.clone())? {
```

**Files to Modify**:
- `src/plugin/wasm_runtime.rs:238` - Clone before loop

---

## Phase 2: High Priority

### Issue 3: WAF Double Normalization

**Problem**: `SqliDetector`, `XssDetector`, and `SstiDetector` call `self.normalizer.normalize()` even though `check_sqli()` etc. already pass `NormalizedInputs` (already normalized via `NormalizedInputs::normalize_all()`).

**Call Flow**:
```
1. check_sqli() calls NormalizedInputs::normalize_all() ONCE
2. check_sqli() passes already-normalized inputs to sqli_detector.detect()
3. sqli_detector.detect() calls self.normalizer.normalize() AGAIN on same data
```

**Fix Options**:

**Option A** (Simplest): Add `detect_pre_normalized()` methods

Add methods to detectors that skip normalization:
```rust
// In SqliDetector, XssDetector, SstiDetector
pub fn detect_pre_normalized(
    &self,
    input: &str,
    location: &InputLocation,
) -> Option<WafMatch> {
    let search_target = input;  // Already normalized, no need to re-normalize
    self.pattern_detector.detect(search_target.as_bytes(), location.clone())
}
```

**Option B**: Modify detectors to detect on both original and normalized

Use the `detect_internal_normalized()` pattern from `detector_common.rs:248-254`.

**Recommended**: Option A - Add pre-normalized detect methods and update call sites.

**Implementation Steps**:

**Step 3.1**: Add `detect_pre_normalized()` to SqliDetector

**Location**: `src/waf/attack_detection/sqli.rs`

Add after `detect()` method (around line 35):
```rust
pub fn detect_pre_normalized(
    &self,
    input: &str,
    location: &InputLocation,
) -> Option<WafMatch> {
    self.pattern_detector.detect(input.as_bytes(), location.clone())
}
```

**Step 3.2**: Update SqliDetector call site

**Location**: `src/waf/attack_detection/mod.rs:427-465`

Change `check_sqli()` to pass normalized string directly:
```rust
// Around line 442-444
for (name, value) in &inputs.query_params {
    if let Some(result) = sqli_detector.detect_pre_normalized(
        &value.normalized,  // Already normalized by normalize_all()
        &InputLocation::QueryParam(name.clone()),
    ) {
        return Some(result);
    }
}
```

**Step 3.3**: Repeat for XssDetector and SstiDetector

**Files to Modify**:
- `src/waf/attack_detection/sqli.rs` - Add detect_pre_normalized
- `src/waf/attack_detection/xss.rs` - Add detect_pre_normalized
- `src/waf/attack_detection/ssti.rs` - Add detect_pre_normalized
- `src/waf/attack_detection/mod.rs` - Update call sites to use pre-normalized

---

### Issue 4: Mesh Provider Stats Lock Contention

**Problem**: `is_provider_unhealthy()` takes a `write()` lock on every request. At 500K rps with 10 providers = 5M+ write locks/sec.

**Location**: `src/mesh/proxy.rs:643-655`

**Current Code**:
```rust
fn is_provider_unhealthy(&self, provider_node_id: &str) -> bool {
    let is_unhealthy = {
        let mut stats = self.provider_stats.write();  // WRITE LOCK!
        if let Some(provider_stats) = stats.get_mut(provider_node_id) {
            provider_stats.decay();
            !provider_stats.is_available()
        } else {
            drop(stats);
            return self.is_provider_failed(provider_node_id);
        }
    };
    is_unhealthy
}
```

**Fix**: Replace `Arc<RwLock<HashMap>>` with `Arc<DashMap<String, ProviderStats>>`

**Implementation Steps**:

**Step 4.1**: Change struct declaration

**Location**: `src/mesh/proxy.rs:69`

**Change**:
```rust
// FROM:
provider_stats: Arc<RwLock<HashMap<String, ProviderStats>>>,
// TO:
provider_stats: Arc<DashMap<String, ProviderStats>>,
```

**Step 4.2**: Change initialization

**Location**: `src/mesh/proxy.rs:329`

**Change**:
```rust
// FROM:
let provider_stats = Arc::new(RwLock::new(HashMap::new()));
// TO:
let provider_stats = Arc::new(DashMap::new());
```

**Step 4.3**: Update `is_provider_unhealthy()` (lines 643-655)

**Change**:
```rust
fn is_provider_unhealthy(&self, provider_node_id: &str) -> bool {
    if let Some(mut stats) = self.provider_stats.get_mut(provider_node_id) {
        stats.decay();
        !stats.is_available()
    } else {
        self.is_provider_failed(provider_node_id)
    }
}
```

**Step 4.4**: Update `record_provider_success()` (lines 660-682)

**Change** to use DashMap entry API:
```rust
fn record_provider_success(&self, provider_node_id: &str) {
    self.clear_provider_failure(provider_node_id);
    match self.provider_stats.entry(provider_node_id.to_string()) {
        Entry::Occupied(mut e) => e.get_mut().record_success(),
        Entry::Vacant(e) => {
            let mut new_stats = ProviderStats::new();
            new_stats.record_success();
            e.insert(new_stats);
        }
    }
}
```

**Step 4.5**: Update `record_provider_failure()` (lines 684-713)

**Change** to use DashMap entry API similarly.

**Step 4.6**: Add import

**Location**: `src/mesh/proxy.rs:22`

**Add**:
```rust
use dashmap::mapref::entry::Entry;
```

**Files to Modify**:
- `src/mesh/proxy.rs` - Type declaration, initialization, 3 method updates, import

---

### Issue 5: HTTP Server Per-Request Allocations

**Problem**: Multiple unnecessary string allocations per HTTP request.

**Locations and Fixes**:

| Line | Current | Fix | Savings |
|------|---------|-----|---------|
| 1352 | `site_id.to_string()` | `let site_id: &str = &target.site_id` | ~32-64 bytes |
| 1416 | `method.to_string()` | `let method_str = method.as_str()` | ~4-8 bytes |
| 253 (HTTP/3) | `headers.clone()` | `let headers: &http::HeaderMap = request.headers()` | varies |

**Implementation Steps**:

**Step 5.1**: Eliminate `site_id.to_string()` at line 1352

**Location**: `src/http/server.rs:1352`

**Change**:
```rust
// FROM:
let site_id = target.site_id.to_string();
// TO:
let site_id: &str = &target.site_id;
```

Update all usages to use `&site_id` instead of `site_id.clone()`.

**Step 5.2**: Eliminate `method.to_string()` at line 1416

**Location**: `src/http/server.rs:1416`

**Change**:
```rust
// FROM:
let method_str = method.to_string();
// TO:
let method_str = method.as_str();
```

**Step 5.3**: Eliminate `headers.clone()` in HTTP/3

**Location**: `src/http3/server.rs:253`

**Change**:
```rust
// FROM:
let headers = request.headers().clone();
// TO:
let headers: &http::HeaderMap = request.headers();
```

**Files to Modify**:
- `src/http/server.rs` - Lines 1352, 1416
- `src/http3/server.rs` - Line 253

---

### Issue 6: Cache Key 5 Sequential `replace()` Calls

**Problem**: `CacheKeyBuilder::build()` does 5 sequential `replace()` calls, each allocating a new String. At 500K cached requests/sec = 2.5M allocations.

**Location**: `src/proxy_cache/key.rs:32-37`

**Current Code**:
```rust
let key = key_pattern
    .replace("$scheme", scheme)
    .replace("$request_method", method.as_str())
    .replace("$host", host)
    .replace("$request_uri", &uri_str)
    .replace("$site_id", site_id);
```

**Fix**: Single-pass replacement with pre-calculated capacity.

**Implementation**:

**Step 6.1**: Add single-pass build function

**Location**: `src/proxy_cache/key.rs`

**Add after line 30**:
```rust
fn build_cache_key_single_pass(
    pattern: &str,
    scheme: &str,
    method: &str,
    host: &str,
    uri: &str,
    site_id: &str,
) -> String {
    // Pre-calculate output capacity
    let capacity = pattern.len() + scheme.len() + method.len() + host.len() + uri.len() + site_id.len() + 64;
    let mut result = String::with_capacity(capacity);

    let mut last_end = 0;
    for (placeholder, value) in [
        ("$scheme", scheme),
        ("$request_method", method),
        ("$host", host),
        ("$request_uri", uri),
        ("$site_id", site_id),
    ] {
        if let Some(pos) = pattern[last_end..].find(placeholder) {
            result.push_str(&pattern[last_end..last_end + pos]);
            result.push_str(value);
            last_end += pos + placeholder.len();
        }
    }
    result.push_str(&pattern[last_end..]);
    result
}
```

**Step 6.2**: Replace original build() implementation

**Change** line 32-37 to call the new function:
```rust
build_cache_key_single_pass(
    &self.pattern,
    scheme,
    method.as_str(),
    host,
    &uri_str,
    site_id,
)
```

**Files to Modify**:
- `src/proxy_cache/key.rs` - Add single-pass function, update build()

---

## Phase 3: Medium Priority

### Issue 7: O(n²) weighted_shuffle_providers Algorithm

**Problem**: `weighted_shuffle_providers()` uses `remaining.retain()` which is O(n) per iteration, resulting in O(n²) total.

**Location**: `src/mesh/proxy.rs:747-783`

**Quick Fix** (lines 779): Change `retain()` to `swap_remove()`:
```rust
// FROM:
remaining.retain(|&x| x != selected_idx);
// TO:
if let Some(pos) = remaining.iter().position(|&x| x == selected_idx) {
    remaining.swap_remove(pos);
}
```

**Better Fix**: Use `weighted_rand` crate for alias method O(n) construction.

---

### Issue 8: serde_json → postcard in Hot Paths

**Problem**: Multiple hot path operations use `serde_json` instead of `postcard` per AGENTS.md guidance.

**Priority hot paths to migrate**:

| File | Line | Struct |
|------|------|--------|
| `proxy.rs` | 1283 | `ProxyCachePreferences` |
| `proxy.rs` | 1408 | `DhtTransformEntry` |
| `topology.rs` | 761, 869 | `VerifiedUpstream` |
| `transport.rs` | 917 | `CapabilityAttestation` |

**Keep JSON for** (human readability needed):
- `record_store_persist.rs` - Persistence files
- `topology.rs` - Peer persistence to file

**Implementation**:

**Step 8.1**: Add rkyv derives to hot path structs

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct ProxyCachePreferences { ... }
```

**Step 8.2**: Replace serde_json calls with `crate::serialization`

```rust
// FROM:
serde_json::from_slice::<ProxyCachePreferences>(&record.value)
// TO:
crate::serialization::deserialize::<ProxyCachePreferences>(&record.value)
```

---

### Issue 9: HashMap in calculate_string_entropy

**Problem**: `calculate_string_entropy()` creates `HashMap<char, usize>` per request. URLs are almost exclusively ASCII - use fixed array instead.

**Location**: `src/waf/attack_detection/mod.rs:405-425`

**Fix**: Use fixed 128-element array for ASCII:

```rust
fn calculate_string_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }

    let mut counts: [usize; 128] = [0; 128];
    let mut len: usize = 0;

    for c in s.chars() {
        if c as u32 < 128 {
            counts[c as usize] += 1;
            len += 1;
        } else {
            // Non-ASCII fallback
            return Self::calculate_string_entropy_hashmap(s);
        }
    }

    let len_f = len as f32;
    counts.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / len_f;
            -p * p.log2()
        })
        .sum()
}
```

---

### Issue 10: Linear Search in Open Redirect redirect_param_patterns

**Problem**: 78 redirect param patterns searched sequentially with `.any(|param| input.contains(param))` - O(78 × input_length).

**Location**: `src/waf/attack_detection/open_redirect.rs:108-112`

**Fix**: Use Aho-Corasick (already used extensively in codebase).

**Implementation**:

**Step 10.1**: Add `redirect_param_matcher` field

**Location**: `src/waf/attack_detection/open_redirect.rs:10-13`

**Change struct**:
```rust
pub struct OpenRedirectDetector {
    inner: BasePatternDetector,
    redirect_param_matcher: Arc<AhoCorasick>,  // ADD
}
```

**Step 10.2**: Build automaton in new()

**Location**: `open_redirect.rs:16-106`

**Add after pattern initialization**:
```rust
let redirect_param_matcher = Arc::new(
    AhoCorasick::new(redirect_param_patterns).unwrap()
);
```

**Step 10.3**: Replace linear search

**Change** lines 108-112:
```rust
// FROM:
fn is_redirect_param(&self, input_lower: &str) -> bool {
    self.redirect_param_patterns
        .iter()
        .any(|param| input_lower.contains(param))
}
// TO:
fn is_redirect_param(&self, input_lower: &str) -> bool {
    self.redirect_param_matcher.find(input_lower).is_some()
}
```

---

### Issue 11: WASM Linker Recreation Per Request

**Problem**: `instantiate()` at line 500 creates a new `Linker` and registers 6 host functions (260 lines) every request in fallback path.

**Location**: `src/plugin/wasm_runtime.rs:500`

**Fix**: Cache the Linker in `WasmRuntime` struct.

**Implementation**:

**Step 11.1**: Add cached_linker field

**Location**: `src/plugin/wasm_runtime.rs:82-89`

**Change**:
```rust
use std::cell::OnceLock;

pub struct WasmRuntime {
    engine: Engine,
    module: Module,
    limits: WasmResourceLimits,
    name: String,
    priority: i32,
    pool: Arc<WasmInstancePool>,
    cached_linker: OnceLock<Linker>,  // ADD
}
```

**Step 11.2**: Add get_or_create_linker method

**Add after line 495**:
```rust
fn get_or_create_linker(&self) -> Result<&Linker, WasmPluginError> {
    self.cached_linker.get_or_try_init(|| {
        let mut linker = Linker::new(&self.engine);
        // ... lines 508-767: all func_wrap calls ...
        Ok(linker)
    }).map_err(|e| WasmPluginError::LoadFailed(format!("linker init: {}", e)))
}
```

**Step 11.3**: Use cached linker in instantiate()

**Change** line 500:
```rust
// FROM:
let mut linker = Linker::new(&self.engine);
// TO:
let linker = self.get_or_create_linker()?;
```

---

### Issue 12: sorted_runtimes() Re-sorts on Every Request

**Problem**: `sorted_runtimes()` collects, clones, and sorts runtimes on every call.

**Location**: `src/plugin/wasm_runtime.rs:121-125`

**Fix**: Add cache with invalidation.

**Implementation**:

**Step 12.1**: Add cached_sorted field

**Location**: `src/plugin/wasm_runtime.rs:97-104`

**Change**:
```rust
pub struct WasmPluginManager {
    runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
    cached_sorted: RwLock<Option<Vec<Arc<WasmRuntime>>>>,  // ADD
    // ... existing fields ...
}
```

**Step 12.2**: Initialize in new()

**Location**: line 107-114

**Add**:
```rust
cached_sorted: RwLock::new(None),
```

**Step 12.3**: Update sorted_runtimes()

**Change** lines 121-125:
```rust
fn sorted_runtimes(&self) -> Vec<Arc<WasmRuntime>> {
    if let Some(cached) = self.cached_sorted.read().as_ref() {
        return cached.clone();
    }
    let mut runtimes: Vec<Arc<WasmRuntime>> = self.runtimes.read().iter().cloned().collect();
    runtimes.sort_by_key(|r| r.priority());
    *self.cached_sorted.write() = Some(runtimes.clone());
    runtimes
}
```

**Step 12.4**: Invalidate on load/unload/reload

Add to end of `load_plugin()`, `load_plugin_from_memory()`, `load_plugin_with_limits()`, `unload_plugin()`, `reload_plugin()`:
```rust
self.cached_sorted.write().take();
```

---

### Issue 13: O(n) Backend Lookup (Dead Code)

**Finding**: `MeshBackendPool` and all its methods (`get_backend()`, `select_backend()`, etc.) are **defined but never called** anywhere in the codebase. This is dead code until wired up.

**Recommendation**: Low priority. If/when connected:
1. Change `Vec` to `HashMap` for O(1) `get_backend()` and `remove_backend()`
2. Keep `Vec` for `select_backend()` since it needs to filter by health (O(n) unavoidable)

---

## Implementation Order

| Phase | Issue | Description | Complexity | Est. Time |
|-------|-------|-------------|------------|------------|
| 1.1 | Issue 1 | WASM pooling fix (CRITICAL) | High | 2-3 hours |
| 1.2 | Issue 2 | WASM per-runtime cloning | Low | 15 min |
| 2.1 | Issue 3 | WAF double normalization | Medium | 2 hours |
| 2.2 | Issue 4 | Provider stats DashMap | Medium | 1 hour |
| 2.3 | Issue 5 | HTTP server allocations | Low | 1 hour |
| 2.4 | Issue 6 | Cache key single-pass | Medium | 1 hour |
| 3.1 | Issue 7 | weighted_shuffle swap_remove | Low | 15 min |
| 3.2 | Issue 8 | serde_json → postcard | Medium | 2-3 hours |
| 3.3 | Issue 9 | Entropy array | Low | 30 min |
| 3.4 | Issue 10 | Aho-Corasick redirect | Medium | 1 hour |
| 3.5 | Issue 11 | WASM linker cache | Medium | 1 hour |
| 3.6 | Issue 12 | sorted_runtimes cache | Low | 30 min |

---

## Files Requiring Changes

| File | Issues |
|------|--------|
| `src/plugin/wasm_runtime.rs` | 1, 2, 11, 12 |
| `src/waf/attack_detection/mod.rs` | 3, 9 |
| `src/waf/attack_detection/sqli.rs` | 3 |
| `src/waf/attack_detection/xss.rs` | 3 |
| `src/waf/attack_detection/ssti.rs` | 3 |
| `src/waf/attack_detection/open_redirect.rs` | 10 |
| `src/mesh/proxy.rs` | 4, 7 |
| `src/http/server.rs` | 5 |
| `src/http3/server.rs` | 5 |
| `src/proxy_cache/key.rs` | 6 |
| `src/mesh/backend.rs` | 13 (future) |

---

## Testing Requirements

### Critical Tests (After Implementation)

1. **WASM pooling**: Verify pooled instances are reused for `transform_response` and `invoke_handler`
2. **WAF normalization**: Verify detection still works correctly after removing double normalization
3. **Provider stats**: Verify health checks still work with DashMap (no race conditions)
4. **HTTP allocations**: Verify no functionality regression with borrowed strings
5. **Cache key**: Verify cache keys are identical before/after optimization

### Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Check specific module compiles
cargo check --lib -p maluwaf
```

---

## Dependencies

- `dashmap` crate (already used extensively)
- `ahocorasick` crate (already used extensively)
- `postcard` / `rkyv` serialization (already in codebase)
- `weighted_rand` crate (for Issue 7 alias method - optional)

---

## Risk Assessment

| Issue | Risk | Mitigation |
|-------|------|------------|
| 1 (WASM pooling) | Medium - Pooling logic is subtle | Extensive integration tests |
| 2 (WASM cloning) | Low - Simple change | Unit tests |
| 3 (WAF normalization) | Medium - Could miss edge cases | Regression tests for all detectors |
| 4 (DashMap) | Low - DashMap is used elsewhere | Verify no deadlocks |
| 5 (HTTP allocations) | Low - Borrowed data is safe | Compile-time guarantees |
| 6 (Cache key) | Low - String building is deterministic | Unit tests |
| 7 (swap_remove) | Low - Algorithm correctness unchanged | Math proof unchanged |
| 8 (postcard) | Medium - Schema evolution | Add version field if needed |
| 9 (entropy array) | Low - Fallback to HashMap for Unicode | Only affects non-ASCII |
| 10 (Aho-Corasick) | Low - Same matching semantics | Unit tests |
| 11 (linker cache) | Low - Linker is stateless | Same behavior |
| 12 (sorted cache) | Low - Cache invalidation on write | Integration tests |

---

## Open Questions

1. **WASM pooling completeness**: Should `transform_response` and `invoke_handler` warm up the pool during initialization, or is the current on-demand approach acceptable?

2. **Cache key backward compatibility**: Does changing cache key generation affect existing cached entries? Should there be a migration strategy?

3. **serde_json deprecation**: For hot path migrations, should we maintain JSON fallback for backwards compatibility during transition, or is a clean break acceptable?

4. **Weighted shuffle correctness**: The current algorithm has subtle bias issues (noted in Issue 7 analysis). Should we fix the sampling algorithm as well as the O(n²) issue?

---

## Summary

This plan addresses 13 performance issues with an estimated **7+ million operations/second reduction** at the 500K rps target:

| Category | Operations Saved/sec |
|----------|---------------------|
| Allocations eliminated | ~3.5M |
| Write locks eliminated | 5M+ |
| Sorts eliminated | 500K |
| Comparisons reduced | 78x for redirect params |

**Estimated total implementation time**: 12-15 hours across all issues.


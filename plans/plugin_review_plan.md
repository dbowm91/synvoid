# Plugin Architecture Document Review - Improvement Plan

## Document: `architecture/plugin_deep_dive.md`

**Review Date:** 2026-05-23
**Reviewer:** AI Agent
**Cross-Referenced:** AGENTS.md, src/plugin/AGENTS.override.md

---

## Summary

The document provides a good overview of the plugin architecture but contains several outdated claims, particularly regarding Spin routing and WASM plugin execution in the HTTP pipeline. Some file path references need verification.

---

## Verified Correct Items

| Item | Location | Notes |
|------|----------|-------|
| WASM Plugin Key Files table | Lines 17-26 | All file names and responsibilities match actual codebase |
| `WasmInstancePool` uses `VecDeque` protected by `parking_lot::Mutex` | `instance_pool.rs:11-12` | Correct |
| Guest ABI host functions list | Lines 55-62 | All 6 functions correctly listed |
| Plugin loading flow (Step 1-2) | Lines 37-44 | Matches `wasm_runtime.rs` implementation |
| `WasmResourceLimits` struct fields | Lines 33-34 | Matches `wasm_runtime.rs:51-75` |
| `RequestContext` struct fields | Line 36 | Matches `wasm_runtime.rs:508-516` |
| `prepare_for_request()` resets state | Line 69 | Matches `instance_pool.rs:213-226` |
| Spin `SpinHttpHandler` and `SpinAppsManager` | `spin/handler.rs:117-175, 177-234` | Correct |
| Spin `SpinRuntimeConfig` and `SpinAppInstance` | `spin/runtime.rs:17-66` | Correct |
| Serverless `ServerlessManager` mesh integration | Lines 183-187 | Correct |
| Serverless `InstancePool` autoscaling (10s tick, 50%/30% thresholds) | Lines 153-156 | Matches `instance_pool.rs` |
| WAF Integration table (WASM part) | Lines 197-199 | Correct |

---

## Discrepancies Found

### 1. [MEDIUM] Spin Routing Status - Document Outdated

**Document says (line 102):**
> "Spin routing NOT implemented — Component-to-URL routing is defined in manifests but not wired into HTTP request routing"

**Actual Code:**
`src/spin/runtime.rs:273-291` implements `find_route()` with longest-prefix-match:
```rust
fn find_route(&self, manifest: &Manifest, path: &str) -> Result<(String, String), SpinRuntimeError> {
    let mut matches = Vec::new();
    for component in &manifest.components {
        if let Some(ref route) = component.url {
            let normalized_route = route.trim_end_matches('/');
            if path == normalized_route || path.starts_with(&format!("{}/", normalized_route)) {
                matches.push((component.id.clone(), route.clone(), normalized_route.len()));
            }
        }
    }
    matches
        .into_iter()
        .max_by_key(|m| m.2)
        .map(|(id, route, _)| (id, route))
        .ok_or_else(|| SpinRuntimeError::RouteNotFound(path.to_string()))
}
```

**AGENTS.md confirms (line 192):**
> "Spin find_route bug - `src/spin/runtime.rs:271-285` returned first match only, not longest-prefix-match. **FIXED**: Now collects all matches and returns longest prefix."

**Fix Required:** Update line 102 to indicate routing IS implemented with longest-prefix matching.

---

### 2. [MEDIUM] WASM Plugin Execution in HTTP Server - Line Reference Inaccurate

**Document says (line 201):**
> "WASM plugin execution in HTTP server (`http/server.rs:3043-3086`)"

**Actual Code:**
The WASM plugin execution occurs at `src/http/server.rs:3043-3060`:
```rust
pm.apply_wasm_filters_with_plugins(
    filter_req,
    &target.wasm_plugins,
    std::collections::HashMap::new()
);
```
Line 3043 is approximately where this code resides, but the exact line numbers vary. The document should reference a range or approximate location rather than precise line numbers that shift during development.

**Fix Required:** Change line reference to `src/http/server.rs:3043-3060` (approximate) or `src/http/server.rs` around line 3040.

---

### 3. [MEDIUM] Warmup Creates Stubs, Not Real Implementations

**Document says (line 70):**
> "Warmup pre-populates pool via `warmup(modules)` which instantiates modules in parallel"

**Actual Code:**
`src/plugin/instance_pool.rs:79-209` - The `warmup()` function creates a NEW `Linker` and links stub implementations:
- `check_timeout` returns `0` (line 114)
- `get_env` returns `0` (line 127)
- `synvoid_read_body_chunk` returns `0` (line 138)
- `mesh_query_dht` returns `0` (line 152)
- `mesh_check_threat` returns `0` (line 163)
- `mesh_emit_event` returns `0` (line 176)

The REAL implementations are in `WasmRuntime::create_linker()` at `wasm_runtime.rs:684-1004` with actual DHT integration, threat checking, etc.

**Implication:** Warm instances work but use stub implementations. This may be intentional (for quick instance creation) but the document doesn't clarify this distinction.

**Fix Required:** Add note that warmup creates instances with stub implementations for fast pool population. Real host functions are linked on first actual request.

---

### 4. [LOW] Document Says `WasmPluginManager` Has `filter_request()` Method

**Document says (line 29):**
> "Provides `filter_request()`, `transform_response()` methods"

**Actual Code:**
`WasmPluginManager` has `filter_request()` at `wasm_runtime.rs:436-449` but it's on `WasmRuntime`, not `WasmPluginManager`. The public API is:
- `PluginManager::apply_wasm_filters()` at `mod.rs:141-147`
- `PluginManager::apply_wasm_response_transforms()` at `mod.rs:159-165`

The document correctly shows the flow through `WasmPluginManager` internally, but the public API is via `PluginManager`.

**Fix Required:** Clarify that `filter_request()` is on `WasmRuntime` and called through `WasmPluginManager` which owns the runtimes.

---

### 5. [LOW] Feature Comparison Table - Mesh Integration

**Document says (line 217):**
> "Mesh integration | DHT queries | No | DHT + hierarchical routing"

**Actual:** The `spin` module DOES have mesh integration - `SpinRuntimeConfig` has `allowed_dht_prefixes` and WASM plugins can call mesh functions. However, Spin doesn't do DHT registration Announcements like serverless does.

**Fix Required:** Change "No" to "Limited (via WASM host functions)" for Spin column.

---

## Bugs Identified

### BUG-2: body_receiver Reset - Status: FIXED

**Document references:** Line 69 ("resets timeout, fuel, and env") does NOT mention body_receiver.

**AGENTS.md states (line 188-189):**
> "BUG-2: `prepare_for_request()` didn't reset `body_receiver`... **FIXED**: Added `self.store.data_mut().body_receiver = None;`"

**Code confirms fix at `instance_pool.rs:221`:**
```rust
self.store.data_mut().body_receiver = None;
```

**Action:** Update line 69 to mention body_receiver reset: "resets timeout, fuel, env, and body_receiver"

---

### BUG-3: warmup() Missing Functions - Status: FIXED

**Document says (line 70):**
> "Warmup pre-populates pool via `warmup(modules)` which instantiates modules in parallel"

**AGENTS.md states (line 188-190):**
> "BUG-3: `warmup()` only linked `abort` and `check_timeout`... **FIXED**: All 5 functions now linked in warmup()"

**Code confirms at `instance_pool.rs:79-209`:** All 7 functions (abort, check_timeout, get_env, synvoid_read_body_chunk, mesh_query_dht, mesh_check_threat, mesh_emit_event) are now linked.

**Action:** Document is partially correct but should clarify these are stubs (see discrepancy #3 above).

---

## Improvement Suggestions

### 1. Add Architecture Diagram

The document would benefit from a simple ASCII diagram showing:
- PluginManager → WasmPluginManager → WasmRuntime → WasmInstancePool
- HTTP Server → WAF pipeline → PluginManager
- Spin routing flow

### 2. Clarify Stub vs Real Implementation for Warm Instances

Since warm instances use stubs and real implementations come from `WasmRuntime::create_linker()`, the document should clarify when real implementations are bound.

### 3. Add Security Model Section

Document the DHT prefix restrictions and sensitive key protection in `mesh_query_dht` (documented at `wasm_runtime.rs:840-863`).

### 4. Update Line References to Be Approximate

Instead of precise line numbers like `http/server.rs:3043-3086`, use approximate references like `http/server.rs:around line 3040` or `http/server.rs:3040-3060`.

---

## Priority Summary

| Priority | Item | Action |
|----------|------|--------|
| **HIGH** | Spin routing claim outdated | Update line 102 to reflect longest-prefix-match is implemented |
| **HIGH** | Warmup stub vs real distinction | Add clarification at line 70 about stub implementations |
| **MEDIUM** | body_receiver reset missing from docs | Update line 69 to include body_receiver |
| **MEDIUM** | Line reference accuracy | Change precise line numbers to approximate ranges |
| **LOW** | Mesh integration for Spin | Update feature comparison table |
| **LOW** | Public API clarification | Distinguish between PluginManager and WasmRuntime methods |

---

## Files Referenced

| File | Line(s) | Status |
|------|---------|--------|
| `src/plugin/mod.rs` | 141-165 | Correct - public API matches |
| `src/plugin/wasm_runtime.rs` | 436-449 | Correct - filter_request exists |
| `src/plugin/instance_pool.rs` | 11-12 | Correct - VecDeque with Mutex |
| `src/plugin/instance_pool.rs` | 79-209 | Correct - warmup implementation |
| `src/plugin/instance_pool.rs` | 213-226 | Correct - prepare_for_request |
| `src/spin/runtime.rs` | 273-291 | Correct - find_route with LPM |
| `src/spin/handler.rs` | 117-175 | Correct - SpinHttpHandler |
| `src/http/server.rs` | 3050, 3056 | Approximate - exact lines vary |

---

## Conclusion

The document is mostly accurate but needs updates to reflect:
1. Spin routing IS implemented (not "NOT implemented")
2. Warmup creates stub implementations, not real ones
3. Body receiver reset is implemented (BUG-2 is FIXED)
4. Line references should be approximate, not precise

All identified bugs (BUG-2, BUG-3, Spin find_route) are marked as FIXED in AGENTS.md and confirmed in code.
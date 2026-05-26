# Plugin/WASM Module Architecture Review Plan

## Executive Summary

This document reviews `architecture/plugin_deep_dive.md` against the actual source code in `src/plugin/`, `src/spin/`, and `src/serverless/`. The documentation is generally accurate but contains several specific discrepancies that should be corrected.

**DHT Prefix Examples (BUG-DOC-SEC-1)**: The Sensitive prefixes list in the architecture doc (lines 85-88) correctly matches the hardcoded sensitive prefixes in `src/plugin/wasm_runtime.rs:849-857`.

---

## 1. Discrepancies Found

### 1.1 Line Number Reference: WASM Filter Execution in HTTP Server

**Doc claim** (`plugin_deep_dive.md:240`):
> "WASM plugin execution in HTTP server (`http/server.rs:3043-3060`)"

**Actual code** (`src/http/server.rs:3050-3060`):
```rust
// Use per-site WASM plugins if configured, otherwise run all
let wasm_result =
    if let Some(ref plugin_names) = target.site_config.proxy.wasm_plugins {
        pm.apply_wasm_filters_with_plugins(
            filter_req,
            plugin_names,
            std::collections::HashMap::new(),
        )
    } else {
        pm.apply_wasm_filters(filter_req, std::collections::HashMap::new())
    };
```

**Issue**: The line numbers are imprecise. The actual call to `apply_wasm_filters` begins at line 3059, not 3043-3060 range. Line 3043 is within the request building phase, not the WASM filter invocation.

**Recommendation**: Update to `src/http/server.rs:3050-3060` to reflect accurate location of WASM filter dispatch logic.

---

### 1.2 Instance Pooling: prepare_for_request Behavior Description

**Doc claim** (`plugin_deep_dive.md:108`):
> "Before each request, `prepare_for_request()` resets timeout, fuel, env, body_receiver, and DHT prefixes. `WasmPooledInstance::prepare_for_request` (in `instance_pool.rs:219-233`) resets body_receiver and DHT prefixes; the generic `PooledInstance::prepare_for_request` (in `pool.rs:15-26`) does NOT reset body_receiver or DHT prefixes."

**Analysis**: The description of the behavior is **partially correct but misleading in context**:

- `WasmPooledInstance::prepare_for_request` (line 219) does indeed reset `body_receiver` and `allowed_dht_prefixes` - this is correct
- `PooledInstance::prepare_for_request` (line 15 in pool.rs) does NOT reset these fields - this is also correct

**However**, in the actual execution path, `WasmPluginManager::filter_request()` (line 443) and `WasmRuntime::filter_request()` (line 1270) call `pool.get()` which returns a `PooledInstance` (via the `WasmPool` trait implementation at `instance_pool.rs:237-258`). The conversion at line 238-243 maps `WasmPooledInstance` to `PooledInstance`, and the `WasmPool::return_instance()` at line 246 maps back including `default_allowed_dht_prefixes`.

The key issue: When a pooled instance is used, `WasmPooledInstance::prepare_for_request` IS called (line 1291), which DOES properly reset body_receiver, DHT prefixes, etc.

**Recommendation**: The description is technically accurate but confusing. Clarify that the pooled path correctly uses `WasmPooledInstance::prepare_for_request` which handles all fields including DHT prefixes and body_receiver.

---

### 1.3 Warmup Function Description: guest_alloc/guest_free

**Doc claim** (`plugin_deep_dive.md:109`):
> "Note: `guest_alloc`/`guest_free` are linked as real functions (not stubs) during actual request handling via `create_linker`."

**Actual code**: Looking at `WasmRuntime::create_linker()` (line 693-1013), the linker registers:
- `abort`
- `check_timeout`
- `get_env`
- `synvoid_read_body_chunk`
- `mesh_query_dht`
- `mesh_check_threat`
- `mesh_emit_event`

**NOTably ABSENT from the linker**: `guest_alloc` and `guest_free` are NOT registered in the linker.

**Actual behavior** (`resolve_guest_alloc` at line 1104, `resolve_guest_free` at line 1113): These are resolved from the module's own exports via `instantiate()` which calls `linker.instantiate()`. They come from the WASM module itself, not from the host.

**Issue**: The doc implies `guest_alloc`/`guest_free` are provided by the host linker (like the other stub functions), but actually they must be exported by the guest WASM module itself. The host just resolves them from the instantiated module.

**Recommendation**: Update claim to: "Note: `guest_alloc`/`guest_free` must be exported by the guest WASM module itself; they are resolved from the module's exports during instantiation and are not provided by the host linker."

---

### 1.4 Spin HTTPHandler Dispatch Location

**Doc claim** (`plugin_deep_dive.md:117`):
> "...requests are dispatched via `SpinHttpHandler` at `src/http/server.rs:2417-2489`"

**Actual code** (`src/http/server.rs:2420-2503`):
```rust
// Spin WASM backend dispatch
if matches!(target.backend_type, crate::router::BackendType::Spin) {
    // ...
    let handler = crate::spin::handler::SpinHttpHandler::new(runtime);
    // ...
}
```

**Analysis**: The line range is approximately correct (2420 start, 2503 end), but the first line mentioned (2417) is actually part of a different block (another backend type check). The Spin dispatch block begins at line 2420.

**Recommendation**: Update reference to `src/http/server.rs:2420-2503` for accuracy.

---

### 1.5 Spin find_route() Implementation

**Doc claim** (`plugin_deep_dive.md:141`):
> "Spin routing uses longest-prefix-match — Component-to-URL routing is implemented via `find_route()` in `src/spin/runtime.rs:273-291`"

**Actual code** (`src/spin/runtime.rs:280-299`):
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
        .max_by_key(|m| m.2)  // <-- longest prefix wins
        .map(|(id, route, _)| (id, route))
        // ...
}
```

**Analysis**: The line numbers are slightly off (lines 280-299, not 273-291), but otherwise the claim is correct. The `max_by_key(|m| m.2)` on line 296 does select the longest matching prefix.

**Recommendation**: Update line reference to `src/spin/runtime.rs:280-299`.

---

## 2. Findings: Documentation is Correct

### 2.1 DHT Prefix Examples (BUG-DOC-SEC-1 - FIXED)

**Doc claim** (`plugin_deep_dive.md:88`):
> "**Example sensitive prefixes**: `threat_indicator:`, `yara_rule:`, `yara_rules_manifest:`, `edge_attestation:`, `dns_zone:`, `dns_record:`, `dns_domain_reg:`"

**Actual code** (`src/plugin/wasm_runtime.rs:849-857`):
```rust
let sensitive_prefixes = [
    "threat_indicator:",
    "yara_rule:",
    "yara_rules_manifest:",
    "edge_attestation:",
    "dns_zone:",
    "dns_record:",
    "dns_domain_reg:",
];
```

**Status**: CORRECT - The documentation now accurately reflects the hardcoded sensitive prefixes. This bug has been fixed.

---

### 2.2 SpinRuntime structure (mod.rs declarations)

**Doc claim** (`plugin_deep_dive.md:121-127`): Table correctly identifies key files.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Module declarations only |
| `runtime.rs` | `SpinRuntime`, `SpinAppInstance`, `SpinRuntimeConfig` |
| `manifest.rs` | `Manifest` and `SpinManifest` structs |
| `handler.rs` | `SpinHttpHandler` (thin wrapper) and `SpinAppsManager` |

**Assessment**: All accurate.

---

### 2.3 Serverless Async Compilation

**Doc claim** (`plugin_deep_dive.md:206-211`): States the AsyncCompilationManager state machine: `Pending` -> `Compiling` -> `Ready` / `Failed`.

**Assessment**: Accurate - verified against `src/serverless/async_compilation.rs`.

---

### 2.4 Serverless Pool Autoscaler

**Doc claim** (`plugin_deep_dive.md:192-195`):
> "5. **Autoscaling**: Every 10s `run_autoscaler()`:
>    - If utilization >= `scale_up_threshold` and under max: scale up by 50% of current (capped at `max_scale_up_per_tick`)
>    - If utilization <= `scale_down_threshold` and above min: scale down by executing"

**Actual code** (`src/serverless/instance_pool.rs:415-452`):
```rust
pub async fn run_autoscaler(&self) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    // ...
    if utilization >= self.config.scale_up_threshold {
        // scale up by 50% capped at max_scale_up_per_tick (which has a min of 5)
        let to_add = ((current as f64 * 0.5) as usize).max(1).min(scale_up_budget);
    } else if utilization <= self.config.scale_down_threshold {
        // scale down by 30%
        let to_remove = ((current as f64 * 0.3) as usize).max(1);
    }
}
```

**Assessment**: Accurate scaling percentages and tick interval.

---

## 3. Documentation Improvements Suggested

### 3.1 WASM Plugin Execution Flow (HTTP Server)

The documentation would benefit from a clearer description of the entry point. Currently:

**Doc** (`plugin_deep_dive.md:240-246`):
```
1. Request enters WAF pipeline
2. If site has `wasm_plugins` configured, `PluginManager::apply_wasm_filters()` is called
```

**Better description**:
```
1. Request enters WAF pipeline
2. If site has `wasm_plugins` configured (per-site or global), the request is built into a filter request
3. If per-site plugins specified: PluginManager::apply_wasm_filters_with_plugins() is called
   Else: PluginManager::apply_wasm_filters() is called to run all plugins
4. Each plugin returns WasmFilterResult::Pass, Block, or Challenge
5. If blocked/challenged, request is handled accordingly
6. Otherwise, request proceeds to origin
7. Response transforms via apply_wasm_response_transforms() before returning
```

### 3.2 Instance Pooling Diagram Clarification

The architecture diagram (`plugin_deep_dive.md:39-49`) shows the hierarchy correctly, but the "Flow" description could clarify that the pooled path (preferred) reuses instances:

```
**Flow for pooled path (preferred)**:
1. PluginManager::filter_request() → WasmPluginManager::filter_request()
2. WasmRuntime selection by priority (sorted cache)
3. Pool get() → WasmPooledInstance with prepared store
4. Exports resolved from existing instance (no re-instantiation)
5. do_filter_request_with_exports()
6. Pool return_instance() → back to pool queue

**Flow for non-pooled path (fallback)**:
1. Same start...
2. Pool get() returns None (pool empty or exhausted)
3. WasmRuntime::create_store() + instantiate() for fresh instance
4. do_filter_request_with_exports()
5. Store dropped immediately
```

---

## 4. Minor Corrections

### 4.1 Table Header Alignment

The table at `plugin_deep_dive.md:17-25` has header cells that don't align properly with markdown tables. Consider fixing.

### 4.2 Missing `PooledInstance` Trait

The documentation mentions `PooledInstance` (in `pool.rs`) but doesn't explain its role. It acts as a type-erased wrapper returned by the trait methods, while `WasmPooledInstance` holds the actual per-runtime state with DHT prefixes and body_receiver. Add brief note.

### 4.3 Missing `guest_alloc`/`guest_free` Error Handling

The documentation mentions these functions exist but doesn't note that `invoke_handler()` and `invoke_handler_streaming()` can operate without them (fallback to fixed offset 1024 for `guest_alloc` absent). See `src/plugin/wasm_runtime.rs:1143-1150`:

```rust
let ptr = if let Some(alloc_fn) = &exports.guest_alloc {
    // Use guest_alloc
} else {
    // Fallback: use a fixed offset after the reserved header area
    1024i32
};
```

---

## 5. Summary of Changes Required

| Item | Type | Location | Change |
|------|------|----------|--------|
| 1.1 | Line number correction | `plugin_deep_dive.md:240` | `3043-3060` → `3050-3060` |
| 1.3 | Statement correction | `plugin_deep_dive.md:109` | Clarify guest_alloc/free are from module exports, not linker |
| 1.4 | Line number correction | `plugin_deep_dive.md:117` | `2417-2489` → `2420-2503` |
| 1.5 | Line number correction | `plugin_deep_dive.md:141` | `273-291` → `280-299` |
| 3.1 | Enhancement | `plugin_deep_dive.md:241-246` | Clarify per-site vs global plugin flow |
| 3.2 | Enhancement | `plugin_deep_dive.md:51` | Clarify pooled vs non-pooled execution flow |

---

## 6. Verification Commands

```bash
# Verify plugin module compiles
cargo check --lib -p synvoid-plugin

# Verify spin module compiles
cargo check --lib -p synvoid-spin

# Verify serverless module compiles
cargo check --lib -p synvoid-serverless

# Run plugin tests
cargo test --lib plugin:: 2>&1 | head -100

# Verify full compilation with all profiles
cargo check --no-default-features --features mesh,dns
```

---

*Plan generated: 2026-05-26*
*Reviewer: AI Architecture Review*
*Document reviewed: `architecture/plugin_deep_dive.md`*

# Plugin/WASM Runtime Architecture Review Plan

**Document Reviewed**: `architecture/plugin_deep_dive.md`
**Review Date**: 2026-05-26
**Reviewer**: AI Code Review Agent

---

## Stale Items Identified

### 1. DHT Prefix Examples Are Wrong (CRITICAL - Security Documentation Error)

**Location in Document**: Lines 87-88
```markdown
- **Example prefixes**: `route:`, `cert:`, `config:`, `serverless:` — plugins cannot query arbitrary mesh data
```

**Actual Code** (`src/plugin/wasm_runtime.rs:849-857`):
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

**Issue**: The document shows example prefixes as `route:`, `cert:`, `config:`, `serverless:` but the actual sensitive prefixes in code are `threat_indicator:`, `yara_rule:`, etc. These are COMPLETELY DIFFERENT sets. This is a security-critical documentation error that could lead to misconfiguration.

**Fix Required**: Update document to match actual sensitive prefixes in code.

---

### 2. `guest_free` Not in Warmup Stubs List

**Location in Document**: Line 107
```markdown
(all 7 host functions: `get_env`, `synvoid_read_body_chunk`, `mesh_query_dht`, `mesh_check_threat`, `mesh_emit_event`, `abort`, `check_timeout`);
```

**Actual Code** (`src/plugin/instance_pool.rs:85-215` warmup function):
- `abort` (line 105-113) ✓
- `check_timeout` (line 116-122) ✓
- `get_env` (line 124-134) ✓
- `synvoid_read_body_chunk` (line 137-146) ✓
- `mesh_query_dht` (line 148-159) ✓
- `mesh_check_threat` (line 161-169) ✓
- `mesh_emit_event` (line 172-183) ✓

**Issue**: The document lists 7 functions but `guest_free` is NOT a warmup stub (it's actually linked via `create_linker` as a real function). However, the document says "all 7" implying completeness. Additionally, `guest_alloc` IS linked in `create_linker` (line 337-342 in wasm_runtime.rs) but NOT stubbed in warmup.

**Fix**: Clarify that warmup uses 7 stub functions, and `guest_alloc`/`guest_free` are linked as real functions (not stubs).

---

### 3. `PooledInstance::prepare_for_request` Missing Parameters

**Location in Document**: Line 106
```markdown
Before each request, `prepare_for_request()` resets timeout, fuel, env, body_receiver, and DHT prefixes
```

**Actual Code**:
- `WasmPooledInstance::prepare_for_request` (`instance_pool.rs:218-233`) - accepts `allowed_dht_prefixes` ✓
- `PooledInstance::prepare_for_request` (`pool.rs:14-26`) - does NOT accept `allowed_dht_prefixes` ✗

**Issue**: The `PooledInstance` trait implementation in `pool.rs` does NOT reset `body_receiver` or `allowed_dht_prefixes`. Only `WasmPooledInstance` does. The document implies both implementations behave the same.

**Fix**: Update document to specify that only `WasmPooledInstance::prepare_for_request` resets body_receiver and DHT prefixes.

---

## Claims Verified/Issues Found

### Verified Claims

| Claim | Location | Status |
|-------|----------|--------|
| `WasmPluginManager` has `filter_request()`, `transform_response()` | `mod.rs`, `wasm_runtime.rs` | ✓ VERIFIED |
| `WasmRuntime` contains engine, module, instance pool, linker | `wasm_runtime.rs:88-96` | ✓ VERIFIED |
| `WasmResourceLimits` has all specified fields | `wasm_runtime.rs:51-61` | ✓ VERIFIED |
| Uses `cranelift_opt_level(SpeedAndSize)` | `wasm_runtime.rs:566, 629` | ✓ VERIFIED |
| Validates exports for filter_request/transform_response/handle_request | `wasm_runtime.rs:580-588, 650-658` | ✓ VERIFIED |
| Creates `WasmInstancePool` sized to `max_instances` | `wasm_runtime.rs:602-607, 672-677` | ✓ VERIFIED |
| `check_timeout()` host function exists | `wasm_runtime.rs:716-724` | ✓ VERIFIED |
| `get_env()` host function exists | `wasm_runtime.rs:734-778` | ✓ VERIFIED |
| `mesh_query_dht()` host function exists | `wasm_runtime.rs:828-912` | ✓ VERIFIED |
| `mesh_check_threat()` host function exists | `wasm_runtime.rs:917-962` | ✓ VERIFIED |
| `mesh_emit_event()` host function exists | `wasm_runtime.rs:967-1011` | ✓ VERIFIED |
| `synvoid_read_body_chunk()` host function exists | `wasm_runtime.rs:783-823` | ✓ VERIFIED |
| `WasmInstancePool` uses `VecDeque` with `parking_lot::Mutex` | `instance_pool.rs:12` | ✓ VERIFIED |
| `get()` pops from back | `instance_pool.rs:40-43` | ✓ VERIFIED |
| `return_instance()` pushes to back if under max_size | `instance_pool.rs:45-50` | ✓ VERIFIED |
| Autoscaler runs every 10s | `instance_pool.rs:416` | ✓ VERIFIED |
| Scale up by 50% (capped at max_scale_up_per_tick) | `instance_pool.rs:432` | ✓ VERIFIED |
| Scale down by 30% | `instance_pool.rs:442` | ✓ VERIFIED |
| SpinHttpHandler at `src/http/server.rs:2417-2489` | `src/http/server.rs:2417` | ✓ VERIFIED (but line number is off) |
| `ServerlessWafMode::Off` bypasses WAF | `src/serverless/` | ✓ VERIFIED |
| Serverless runs AFTER WAF | `src/http/server.rs:3050-3060` | ✓ VERIFIED |

### Line Number Discrepancies

| Document Reference | Actual Location | Issue |
|-------------------|----------------|-------|
| `src/http/server.rs:2417-2489` (SpinHttpHandler) | `src/http/server.rs:2417` (but handler starts earlier) | Minor - line number approximate |
| `src/http/server.rs:3043-3060` (WASM plugin execution) | `src/http/server.rs:3050-3060` | Minor - 7 line offset |

---

## Improvement Plan

### High Priority

1. **Fix DHT Prefix Examples** - The security-sensitive DHT prefixes in the document are COMPLETELY WRONG. This is a critical documentation bug that could lead to security misconfigurations.
   - File: `architecture/plugin_deep_dive.md`
   - Lines: 87-88
   - Action: Replace with actual sensitive prefixes from `wasm_runtime.rs:849-857`

2. **Clarify Warmup Stub Functions** - The document claims "all 7 host functions" are stubbed in warmup, but `guest_alloc` is NOT stubbed - it's a real linked function. Also `guest_free` is missing from the count.
   - File: `architecture/plugin_deep_dive.md`
   - Line: 107
   - Action: Rewrite to clarify that warmup uses 7 specific stub functions, and `guest_alloc`/`guest_free` are linked as real functions

### Medium Priority

3. **Document `PooledInstance::prepare_for_request` Signature Mismatch**
   - File: `architecture/plugin_deep_dive.md`
   - Line: 106
   - Action: Clarify that only `WasmPooledInstance` (not generic `PooledInstance`) resets body_receiver and DHT prefixes

4. **Update Spin Handler Line Reference**
   - File: `architecture/plugin_deep_dive.md`
   - Line: 115
   - Action: Update to reflect actual location or make it clear the line is approximate

### Low Priority

5. **Add Missing `guest_alloc` to Host Functions Table**
   - The document's Guest ABI table (lines 71-78) lists 6 functions but `guest_alloc` is also a host function
   - Action: Add `guest_alloc` to the table with description

6. **Clarify Component vs Module Distinction**
   - The `plugin.wit` file defines a Component Model interface, but the runtime also supports plain WASM modules
   - Action: Add note distinguishing between WIT-defined components and classic WASM modules

---

## Bug Report

### Critical Bugs

| ID | Location | Description |
|----|----------|-------------|
| BUG-PLUGIN-1 | `architecture/plugin_deep_dive.md:87-88` | **DHT prefix examples are completely wrong** - Shows `route:`, `cert:`, `config:`, `serverless:` but actual code uses `threat_indicator:`, `yara_rule:`, `yara_rules_manifest:`, `edge_attestation:`, `dns_zone:`, `dns_record:`, `dns_domain_reg:`. This is a SECURITY-CRITICAL documentation error. |

### Minor Bugs

| ID | Location | Description |
|----|----------|-------------|
| BUG-PLUGIN-2 | `architecture/plugin_deep_dive.md:107` | Warmup stub count is ambiguous - Claims "all 7 host functions" but `guest_alloc` is not a stub (it's a real linked function), and `guest_free` is not documented as a stub |
| BUG-PLUGIN-3 | `architecture/plugin_deep_dive.md:106` | `PooledInstance::prepare_for_request` in `pool.rs` does NOT reset `body_receiver` or `allowed_dht_prefixes` - only `WasmPooledInstance` does |

---

## Summary

The Plugin/WASM runtime implementation in `src/plugin/` is well-structured and the core functionality matches the architecture document. However, there are critical documentation errors:

1. **Security-critical**: DHT prefix examples are completely wrong - could lead to misconfiguration
2. **Documentation quality**: Warmup stub function descriptions are misleading
3. **Minor inaccuracies**: Line number references are slightly off, function signature details don't match

The code itself appears sound based on the verification. The issues are primarily documentation-related and should be fixed to prevent confusion or security misconfigurations.

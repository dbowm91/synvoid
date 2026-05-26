# App Handlers Architecture Review - Improvement Plan

**Review Date:** 2026-05-26
**Reviewer:** AI Architecture Review
**Document Reviewed:** `architecture/app_handlers.md`

---

## Executive Summary

The architecture document provides a reasonable high-level overview of SynVoid's application handlers but contains several factual errors, missing features, and stale line number references. The most significant issues are:

1. **Missing Granian/Python support** - Documented but not implemented
2. **Incorrect line number references** for static file handler
3. **Misleading instance pooling claims** that contradict actual implementation
4. **Missing CGI handler documentation** in overview
5. **Stale/incorrect function references**

---

## Section-by-Section Discrepancies

### 1. Static File Handler (lines 5-13)

#### Claim: "StaticFileHandler" exists at `src/static_files/handler.rs`
**Actual:** No `handler.rs` file exists. The `StaticFileHandler` struct is defined at `src/static_files/mod.rs:42`

**Discrepancy Type:** Incorrect file path
**Severity:** Low (documentation only)

#### Claim: "IPC Delegation: Heavy operations (CSS/JS minification, image compression) are delegated to the StaticWorker via IPC"
**Actual:** `src/static_files/client.rs` contains `MinifierClient` and `PoisonImageClient` that communicate via IPC to a static worker process. However:
- No `StaticWorker` process implementation found in the reviewed files
- `file_manager.rs` contains upload/file management but is separate from the static file serving

**Discrepancy Type:** Partially accurate - IPC mechanism exists but StaticWorker implementation not verified
**Severity:** Medium

---

### 2. FastCGI & PHP-FPM (lines 15-21)

#### Claim: "Response Streaming: Note: Known limitation - buffers entire stdout before sending; true streaming requires architectural change (APP-15)"
**Actual:** Confirmed at `src/fastcgi/mod.rs:96-103`:
```rust
let body_vec = body.to_vec();  // Buffers entire body
let output = client
    .execute(Request::new(params, &mut body_vec.as_slice()))
    .await
```
The FastCGI client collects full stdout before parsing.

**Discrepancy Type:** Accurate - APP-15 correctly documented
**Severity:** N/A (known limitation documented correctly)

#### Claim: "Connection pooling with health checks"
**Actual:** `src/fastcgi/pool.rs` fully implements `FastCgiPool` with:
- Connection pooling via `VecDeque<PooledConnection>` (line 61)
- Health checks with `start_health_check()` (line 148)
- Idle connection timeout via `max_idle_time` (line 165-175)
- Semaphore-based connection limiting (line 76)

**Discrepancy Type:** Accurate
**Severity:** N/A

---

### 3. Python (Granian) (lines 23-29)

#### Claim: "SynVoid includes built-in support for Python ASGI/WSGI applications using the **Granian** application server"
**Actual:** **NO evidence of Granian integration found in:**
- `src/static_files/`
- `src/php/`
- `src/fastcgi/`
- `src/cgi/`
- `src/serverless/`
- `src/spin/`

No `granian` module exists. No process spawning logic for Granian found.

**Discrepancy Type:** MAJOR - Feature documented but **NOT IMPLEMENTED**
**Severity:** High (missing feature disguised as existing feature)

#### Claim: "Supervisor process can spawn and manage Granian instances"
**Actual:** No Supervisor code for Granian found.

**Discrepancy Type:** Feature not implemented
**Severity:** High

---

### 4. Serverless WASM (Edge Functions) (lines 31-38)

#### Claim: "Instance Pooling: Maintains a pool of pre-initialized WASM instances... Instance pooling is supported for WAF plugins; the Spin runtime does not use instance pooling."
**Actual:** `src/serverless/instance_pool.rs:89-655` contains `InstancePool` which:
- Pre-warms instances (`pre_warm_instances`, line 19)
- Has idle timeout eviction (line 277-284)
- Implements autoscaling with `scale_up`/`scale_down`
- Tracks metrics including cold starts

However, `SpinRuntime` at `src/spin/runtime.rs:183-207` DOES cache compiled runtimes via `compiled_runtimes` HashMap but does NOT pool SpinAppInstances.

**Discrepancy Type:** Misleading - Generic serverless WASM has full instance pooling; Spin does have runtime caching but not instance pooling
**Severity:** Medium (documentation nuance incorrect)

#### Claim: "Mesh Distribution: WASM modules can be distributed globally across the mesh"
**Actual:** `src/serverless/manager.rs:401-422` shows DHT-based WASM loading when mesh feature is enabled:
```rust
if let Some(data) = wasm_dist.get_module_data(
    &func_def.name,
    crate::mesh::protocol::WasmModuleType::Serverless,
) {
    return runtime.load_plugin_from_memory(&func_def.name, &data, limits);
}
```

**Discrepancy Type:** Accurate (mesh-only feature)
**Severity:** N/A

---

### 5. Spin Application Support (lines 40-61)

#### Claim: "`SpinHttpHandler` at `src/spin/handler.rs:117`"
**Actual:** `SpinHttpHandler` struct is at `src/spin/handler.rs:117` - **CORRECT**

**Discrepancy Type:** None - line number accurate
**Severity:** N/A

#### Claim: "SpinHttpHandler routes requests through Spin runtime to appropriate component based on Spin manifest"
**Actual:** `src/spin/runtime.rs:256-278` shows `find_route()` with longest-prefix matching and `instantiate_app()` for each request

**Discrepancy Type:** Accurate
**Severity:** N/A

#### Claim: "Registration: Part of site configuration | Manual registration via Admin API"
**Actual:** `src/spin/handler.rs:188` shows `SpinAppsManager::register()`:
```rust
pub fn register(&self, name: &str, runtime: Arc<SpinRuntime>) -> Result<(), SpinHandlerError>
```

**Discrepancy Type:** Needs clarification - "Manual registration via Admin API" but register() is a direct method call, not necessarily Admin API
**Severity:** Low

---

## Missing Documentation

### CGI Handler
The document does not cover `src/cgi/mod.rs` at all. This module implements:
- CGI script execution via subprocess spawning
- Environment variable population
- Path traversal protection
- Script timeout handling

**Recommendation:** Add new section for CGI support

### Async Compilation
`src/serverless/async_compilation.rs` implements async WASM compilation but is not mentioned in documentation.

### File Manager
`src/static_files/file_manager.rs` implements file upload, malware scanning, and archive extraction but is not covered.

---

## Security Considerations

### 1. Path Traversal Protection
- **Static files:** `src/static_files/mod.rs:377-387` - canonicalizes path and validates within root
- **CGI:** `src/cgi/mod.rs:131-138` - validates canonical path starts with root
- **File Manager:** `src/file_manager.rs:348-356` - validates path traversal

**Status:** Properly implemented across handlers

### 2. File Permissions
CGI handler at `src/cgi/mod.rs:178-180` checks for executable bit:
```rust
if mode & 0o111 == 0 {
    return Err(CgiError::Forbidden("Script not executable".to_string()));
}
```

**Status:** Security-conscious design

### 3. Hidden File Blocking
- Static files: `src/static_files/mod.rs:390-399` with `.htaccess` exception
- File Manager: `src/file_manager.rs:413-415` configurable via `allow_hidden_files`

**Status:** Appropriately implemented

---

## Bugs and Implementation Issues

### BUG-FCGI-1: FastCGI Response Buffering (APP-15)
**Location:** `src/fastcgi/mod.rs:96-103`
**Issue:** Entire response body collected before sending to client
**Impact:** Cannot stream large PHP responses
**Fix:** Requires architectural change to use chunked transfer encoding

### BUG-SPIN-1: Spin Instance NOT Reused Per Request
**Location:** `src/spin/runtime.rs:256-278`
**Issue:** Each HTTP request calls `instantiate_app()` which creates a new `SpinAppInstance`:
```rust
let instance = self.instantiate_app(&route.0)?;  // Creates new instance each time
```
**Impact:** Higher overhead than necessary; compiled runtime is cached but not instance pool
**Note:** This may be by design for Spin semantics

### BUG-SERVERLESS-1: Instance Pool Returns Wrong Instance
**Location:** `src/serverless/instance_pool.rs:272-285`
**Issue:** `return_instance()` checks idle duration but logic seems inverted for eviction:
```rust
if idle_duration > idle_timeout {
    *instance.state.write() = InstanceState::Evicted;
    self.evict_instance(instance);
} else {
    instance.mark_idle();
    self.idle_instances.write().push(instance);
}
```
Shouldn't idle instances be kept, not evicted?

---

## Recommended Improvements

### 1. Fix Documentation Errors
| Item | Current | Correct |
|------|---------|---------|
| StaticFileHandler location | `src/static_files/handler.rs` | `src/static_files/mod.rs:42` |
| Granian support | Documented as built-in | Remove or mark as planned |
| Spin instance pooling | "Spin runtime does not use instance pooling" | Spin caches compiled runtimes but creates new instances per request |
| Spin registration | "Manual registration via Admin API" | Method-based registration (actual Admin API not verified) |

### 2. Add Missing Sections
- CGI Handler section (currently completely missing)
- File Manager section (upload handling, malware scanning)
- Async Compilation documentation
- Instance Pool metrics and monitoring

### 3. Clarify APP-15
Consider splitting into two issues:
- APP-15a: PHP-FPM response buffering (confirmed)
- APP-15b: Generic FastCGI streaming (would require protocol changes)

### 4. Document Connection Pooling Behavior
FastCGI pool and serverless pool have different characteristics:
- FastCGI: Connection reuse with health checks
- Serverless: Instance pre-warming + scaling

### 5. Update Line References
Update all line number references to allow for code growth:
- Consider using function names instead of line numbers
- Or add "as of [date]" to line references

---

## Verification Commands

To verify claims in this document:

```bash
# Verify StaticFileHandler location
grep -n "pub struct StaticFileHandler" src/static_files/mod.rs

# Verify APP-15 - response buffering
grep -n "body_vec" src/fastcgi/mod.rs

# Verify SpinHttpHandler line number
grep -n "pub struct SpinHttpHandler" src/spin/handler.rs

# Verify NO Granian integration
grep -ri "granian" src/ || echo "No Granian found"

# Verify instance pool for serverless
grep -n "pub struct InstancePool" src/serverless/instance_pool.rs
```

---

## Conclusion

The architecture document requires updates to:
1. Remove false claims about Granian support
2. Fix StaticFileHandler location reference
3. Clarify Spin vs generic WASM instance pooling
4. Add missing sections for CGI and File Manager
5. Correct line number references with dates or function names

Most core functionality is correctly documented. The main concerns are missing features presented as existing (Granian) and missing documentation for existing features (CGI, File Manager).

---

*This document is for review/analysis only. No code changes were made.*

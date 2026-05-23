# App Handlers Architecture Review Plan

**Document reviewed:** `architecture/app_handlers.md`
**Review date:** 2026-05-23
**Reviewer:** Architecture Review Agent

---

## 1. Claims Verified / Not Verified

### Static File Handler

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Directory Listings with configurable themes | **VERIFIED** | `src/static_files/mod.rs:761-811` | `directory_listing` field; renders via `directory::render_directory_listing()` |
| Path Normalization (path traversal protection) | **VERIFIED** | `src/static_files/mod.rs:338-397` | `resolve_path()` canonicalizes and validates paths against root |
| MIME Type Mapping | **VERIFIED** | `src/static_files/mod.rs:526-530` | Uses `MIME_REGISTRY` |
| gzip and brotli pre-compression | **VERIFIED** | `src/static_files/mod.rs:550-622` | Checks `.br` and `.gz` files, also `minified_cache_dir` |
| Built-in Minification via specialized background worker | **NOT VERIFIED** | `src/static_files/mod.rs:131-137` | `new_with_minifier()` accepts minifier params but they are UNUSED (`_` prefix). Minification is NOT integrated into the static file serving path |

### FastCGI & PHP-FPM

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Unix Socket & TCP Support | **VERIFIED** | `src/php/mod.rs:65-89` | `auto_detect_socket()` handles both |
| Environment Management (SCRIPT_FILENAME, etc.) | **VERIFIED** | `src/php/mod.rs:139-238` | `build_fcgi_config()` populates params including `SCRIPT_FILENAME` |
| Response Streaming | **PARTIAL** | `src/fastcgi/mod.rs:50+` | FastCgiClient exists but actual streaming behavior needs verification |
| "Efficiently streams large responses" | **UNVERIFIED** | `src/fastcgi/mod.rs` | Need to check if response body streaming works properly |

### Python (Granian)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Supervisor process spawns/manages Granian | **VERIFIED** | `src/app_server/granian.rs:312-963` | `GranianSupervisor` manages child process lifecycle |
| Unix Socket IPC | **VERIFIED** | `src/app_server/granian.rs:746-747` | `--uds` flag used with socket path |
| Simplified Deployment (Django, Flask, FastAPI) | **VERIFIED** | `src/app_server/granian.rs:334-374` | Auto-detects app path and interface |

### Serverless WASM (Edge Functions)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Wasmtime Integration | **VERIFIED** | `src/plugin/wasm_runtime.rs:10,14` | Uses `wasmtime::Engine`, `Module`, `Linker` |
| Instance Pooling | **VERIFIED** | `src/plugin/wasm_runtime.rs:595-598` | Creates `WasmInstancePool` |
| Resource Isolation (CPU, memory, syscall limits) | **VERIFIED** | `src/plugin/wasm_runtime.rs:51-75` | `WasmResourceLimits` struct with max_memory_mb, max_cpu_fuel, etc. |
| Mesh Distribution (WASM modules globally) | **VERIFIED** | `src/mesh/wasm_dist.rs` | `WasmDistManager` exists but actual mesh distribution needs verification |

### Spin Application Support

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Metadata Parsing (spin.toml) | **VERIFIED** | `src/spin/manifest.rs:82-120` | `Manifest::load()` and `Manifest::parse()` |
| Request Mapping to Spin components | **VERIFIED** | `src/spin/runtime.rs:273-292` | `find_route()` uses longest-prefix-match |
| Spin HttpHandler at server.rs:2423 | **VERIFIED** | `src/http/server.rs:2423` | Confirmed at line 2423 |
| SpinAppsManager::register() | **VERIFIED** | `src/spin/handler.rs:188-198` | Global `SpinAppsManager` |

### Spin vs Generic WASM Edge Functions Table

| Aspect | Documented | Code Location | Status |
|--------|-----------|---------------|--------|
| Runtime: Wasmtime with custom limits | Yes | `src/plugin/wasm_runtime.rs:51-75` | **VERIFIED** |
| Runtime: Custom Spin Runtime (SpinRuntime) | Yes | `src/spin/runtime.rs:115-122` | **VERIFIED** |
| Routing: Longest-prefix-match | Yes | `src/spin/runtime.rs:287-291` | **VERIFIED** |
| Routing: Spin manifest built-in trigger | Yes | `src/spin/manifest.rs:127-132` | **VERIFIED** |
| Manifest: spin.toml via manifest.rs | Yes | `src/spin/manifest.rs:89-91` | **VERIFIED** |
| Registration: Part of site configuration | Yes | `src/http/server.rs:2419-2422` | **VERIFIED** |
| Registration: Manual via Admin API | UNVERIFIED | Need to check admin API | **CLAIM UNVERIFIED** |
| Components: Single WASM module per route | Yes | `src/spin/runtime.rs:161-221` | **VERIFIED** |
| Components: Multiple named in manifest | Yes | `src/spin/manifest.rs:71-78` | **VERIFIED** |
| HTTP Dispatch: WasmHandler in server pipeline | **NOT EXACTLY** | No `WasmHandler` in server pipeline | **CODE DIFFERS** - generic WASM uses `WasmRuntime` directly in plugin pipeline, not a `WasmHandler` |

---

## 2. Improvement Plan

### HIGH PRIORITY

1. **Static File Minification Not Integrated**
   - **Issue**: `new_with_minifier()` accepts `_minifier_cache`, `_async_minifier_client` params (line 134-136) but they are unused - prefixed with `_`
   - **Impact**: Built-in minification claim in document is misleading; minification is NOT integrated into the static file serving path
   - **Location**: `src/static_files/mod.rs:131-137`
   - **Action**: Either integrate minification into the serving pipeline or remove the claim from documentation

2. **SpinHttpHandler Line Number in Document**
   - **Issue**: Document says `SpinHttpHandler` at line 2423, but code shows it's at line 2423 (confirmed)
   - **Issue**: Document mentions "WasmHandler" in server pipeline but no such handler exists - generic WASM uses `WasmRuntime` directly
   - **Location**: `architecture/app_handlers.md:58`
   - **Action**: Update document to correctly reflect generic WASM dispatch mechanism

### MEDIUM PRIORITY

3. **Spin Registration - Admin API Claim Unverified**
   - **Issue**: Document claims Spin apps are registered via Admin API but couldn't verify
   - **Action**: Verify and document actual registration mechanism

4. **FastCGI Streaming Not Verified**
   - **Issue**: Document claims "Efficiently streams large responses" but actual streaming behavior not verified
   - **Action**: Verify `FastCgiClient` response handling and document any limitations

### LOW PRIORITY

5. **Mesh WASM Distribution Implementation Gap**
   - **Issue**: `WasmDistManager` exists at `src/mesh/wasm_dist.rs` but actual mesh network integration unclear
   - **Action**: Verify actual distribution mechanism works as documented

---

## 3. Bug Report

### Minor Bugs

1. **Dead Minifier Parameters**
   - **Location**: `src/static_files/mod.rs:134-136`
   - **Description**: Parameters `_minifier_cache`, `_async_minifier_client` are never used (underscore prefix indicates intentionally unused)
   - **Severity**: Minor - technical debt, doesn't affect functionality but indicates incomplete implementation

2. **Documentation Inconsistency - Generic WASM Handler**
   - **Location**: `architecture/app_handlers.md:58`
   - **Description**: Document claims `WasmHandler` in server pipeline but code shows generic WASM uses `WasmRuntime` directly via plugin system
   - **Severity**: Minor - documentation drift

3. **Spin Supervisor Never Spawned**
   - **Location**: `src/spin/runtime.rs:304-324`
   - **Description**: `run_supervisor()` is defined but never called in the code path. The supervisor task that evicts idle instances and checks health never actually starts.
   - **Severity**: Minor - idle instance eviction doesn't work, but instances are cleaned up on shutdown

---

## Summary

The app_handlers.md document is largely accurate but has several issues:

1. **Static file minification claim is misleading** - minifier parameters are unused
2. **Spin vs Generic WASM table has incorrect handler reference** for generic WASM
3. **Spin supervisor never actually runs** despite being implemented

The document provides good high-level architecture but needs updates to reflect actual implementation state.

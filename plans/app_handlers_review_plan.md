# App Handlers Architecture Review Plan

> **Review Date**: 2026-05-27
> **Document**: `architecture/app_handlers.md`
> **Reviewer**: Code analysis against `src/` and `crates/` source

---

## Verified Correct Items

| Item | Document Location | Verified Location | Status |
|------|-------------------|-------------------|--------|
| `StaticFileHandler` struct | `src/static_files/mod.rs:42` | `src/static_files/mod.rs:42` | ✅ Correct |
| `BackendType` enum (11 variants) | `src/router.rs:66-78` | `src/router.rs:65-78` | ✅ Correct (1-line offset) |
| `GranianConfig` struct | `src/app_server/granian.rs:165` | `src/app_server/granian.rs:165` | ✅ Correct |
| `GranianSupervisor` struct | `src/app_server/granian.rs` (implied) | `src/app_server/granian.rs:299` | ✅ Correct |
| `InstancePool` serverless | `src/serverless/instance_pool.rs:11` | `src/serverless/instance_pool.rs:11` | ✅ Correct |
| `SpinHttpHandler` struct | `src/spin/handler.rs:117` | `src/spin/handler.rs:117` | ✅ Correct |
| `SpinManifest` | `src/spin/manifest.rs` | `src/spin/manifest.rs:7` | ✅ Correct |
| `ServerlessRoute` | `src/serverless/routing.rs:112` | `src/serverless/routing.rs:112` | ✅ Correct |
| Spin handler dispatch | `src/http/server.rs:2421-2503` | `src/http/server.rs:2421-2503` | ✅ Correct |
| AppServer (Granian) dispatch | `src/http/server.rs:2821` | `src/http/server.rs:2821` | ✅ Correct |
| Mesh backend dispatch | `src/http/server.rs:2872` | `src/http/server.rs:2872` | ✅ Correct |
| Static backend dispatch | `src/http/server.rs:2213` | `src/http/server.rs:2213` | ✅ Correct |
| AxumDynamic dispatch | `src/http/server.rs:2172` | `src/http/server.rs:2172` | ✅ Correct |
| CGI dispatch | `src/http/server.rs:2747` | `src/http/server.rs:2747` | ✅ Correct |
| `store_and_announce()` for DHT | `src/serverless/manager.rs:117` + mesh | `src/serverless/manager.rs:505,585` | ✅ Correct |
| `announce_serverless()` | mesh integration | `src/mesh/transport.rs:1041` | ✅ Correct |
| Granian 1047 lines | Document | `src/app_server/granian.rs` (1047 lines) | ✅ Correct |

---

## Discrepancies Found

### 1. QuicTunnel Line Reference Incorrect
- **Document says**: `src/tunnel/upstream.rs:120` for QuicTunnel
- **Actual**: Line 120 is `pub async fn add_static_mapping(...)` method
- **Correct reference**: `QuicTunnel` is defined in `src/router.rs:74` as enum variant
- **Actual handling**: `src/http/server.rs` doesn't have direct QuicTunnel dispatch; it's handled via `UpstreamAddress::QuicTunnel` in `src/upstream/address.rs:27`

### 2. APP-15 FastCGI Streaming Marked as Limitation - FIXED
- **Document says**: "Note: Known limitation - buffers entire stdout before sending; true streaming requires architectural change (APP-15)"
- **AGENTS.md states**: "APP-15 FastCGI streaming (`src/fastcgi/streaming.rs` - new streaming client with feature flag)" is **FIXED 2026-05-27**
- **Actual**: `src/fastcgi/streaming.rs:237-338` has `do_execute_stream()` that streams response chunks as they arrive

### 3. Spin Instance Pooling Documentation Inconsistent
- **Document says**: "Instance pooling is supported for WAF plugins; the Spin runtime does not use instance pooling."
- **Document also says**: Serverless `InstancePool` provides pooling
- **Actual Spin runtime**: Uses `cached_instances` HashMap at `src/spin/runtime.rs:299` with 5-min idle timeout (per AGENTS.md "Spin cold-start instance reuse FIXED 2026-05-26")
- **Serverless InstancePool**: Separate implementation at `src/serverless/instance_pool.rs:39` (ServerlessInstance struct)
- **Confusion**: The document doesn't clearly distinguish between Spin caching and Serverless InstancePool

### 4. Missing FastCgiPoolManager Architecture
- **Document**: Only mentions FastCGI environment management and streaming limitation
- **Actual**: `src/fastcgi/pool.rs` contains `FastCgiPoolManager` (line 23) and `FastCgiPool` for connection pooling
- **Pool manager** at `src/fastcgi/mod.rs:18`: `static FASTCGI_POOL_MANAGER: LazyLock<RwLock<pool::FastCgiPoolManager>>`

### 5. PHP Handler Line Number Off
- **Document says**: PHP-FPM via unix socket or TCP - no line specified
- **Actual**: PHP dispatch at `src/http/server.rs:2513-2519`

---

## Bugs Identified

### BUG-AH-1: Spin Runtime Does Not Use InstancePool (Medium)
- **Severity**: Medium (Documentation Inaccuracy)
- **Location**: `src/spin/runtime.rs:289-303`
- **Issue**: Spin uses `cached_instances` HashMap, NOT the generic `InstancePool` from `src/serverless/instance_pool.rs`
- **Impact**: Users may expect Spin functions to benefit from serverless-style autoscaling/pooling, but Spin has its own simple caching with 5-min idle timeout
- **AGENTS.md confirms**: "Spin cold-start instance reuse Fixed via `get_or_create_instance()` caching with 5-min idle timeout"

### BUG-AH-2: FastCGI Streaming Missing Feature Flag Documentation (Low)
- **Severity**: Low (Documentation)
- **Location**: `architecture/app_handlers.md:21`
- **Issue**: Document marks APP-15 as limitation, but AGENTS.md says it's fixed with feature flag
- **Impact**: Users won't know streaming is available

---

## Suggested Improvements

### 1. Update APP-15 Status (P2)
Remove the "Known limitation" note from section 2, as APP-15 is fixed per AGENTS.md.

### 2. Clarify Spin Instance Management (P2)
Add note that Spin uses `SpinRuntime.cached_instances` (5-min idle timeout) separate from Serverless `InstancePool`.

### 3. Add FastCgiPoolManager to Documentation (P3)
Document the connection pooling architecture at `src/fastcgi/pool.rs`.

### 4. Fix QuicTunnel Reference (P3)
Remove or correct the `src/tunnel/upstream.rs:120` reference - QuicTunnel handling is not directly in that file.

### 5. Add Feature Flag for FastCGI Streaming (P3)
Document which feature flag enables the streaming client (check if `#[cfg(feature = "...")]` exists on streaming implementation).

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 17 |
| Discrepancies | 5 |
| Bugs (Medium) | 1 |
| Bugs (Low) | 1 |
| Suggested Improvements | 5 |

**Overall Assessment**: The architecture document is largely accurate. Most line numbers are correct. The main issues are:
1. APP-15 FastCGI streaming marked as limitation but is fixed
2. Spin instance management documentation is confusing (Spin caching vs Serverless pooling)
3. Missing FastCgiPoolManager architecture documentation
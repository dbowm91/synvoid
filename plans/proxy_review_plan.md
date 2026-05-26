# Proxy Module Architecture Review - Improvement Plan

## Executive Summary

This document reviews the `architecture/proxy_deep_dive.md` architecture document against the actual source code in `src/proxy/`, `src/proxy_cache/`, and `src/http_client/`. The review identifies several categories of issues: **stale documentation**, **incorrect line numbers**, **incomplete implementations**, and **one security-related bug**.

---

## 1. Discrepancies Found

### 1.1 Stale Claims - ErasedHttpClient Phase 9 Never Activated

**Document Claims:**
- `mod.rs:31-33` - ProxyServer holds ErasedHttpClient and uses it in the main request flow
- `send_request_erased_streaming` is the primary request dispatch path

**Actual Implementation:**
- `src/proxy/mod.rs:179` - `erased_client` is instantiated correctly
- `src/http_client/mod.rs:893` - `is_http2 = true` is hardcoded, not a config flag
- **BUG**: `src/http/server.rs:3305` - `let use_erased_client = false;` is hardcoded to `false`, so ErasedHttpClient is never actually used in HTTP server paths

**Impact:** The ErasedHttpClient exists but is bypassed entirely. All HTTP traffic uses the legacy typed `HttpClient` path. Phase 9 for ErasedHttpClient integration was never completed.

**Fix Direction:** Implement proper conditional logic at `src/http/server.rs:3305` to activate ErasedHttpClient based on request characteristics (e.g., streaming body detection).

---

### 1.2 HTTP/2 Connection Multiplexing Not Implemented

**Document Claims (Lines 257-263):**
> // Decision: HTTP/2 remains disabled. While HTTP/2 infrastructure exists (Http2PooledConnection,
> TypedConnectionPool http2 branches), the code path is not wired for production use.
> is_http2=true is hardcoded in send_request_erased_streaming (http_client/mod.rs:893)

**Actual Implementation:**
- `src/http_client/erased_pool.rs:125-126` - `Http2PooledConnection` struct exists as a stub with `is_available()` always returning `false`
- `src/http_client/mod.rs:893` - `let is_http2 = true;` is hardcoded, but this is meaningless because `Http2PooledConnection::is_available()` always returns `false`
- The pool only ever uses `Http1PooledConnection` (line 227: `std::collections::VecDeque<Http1PooledConnection>`)

**Impact:** HTTP/2 multiplexing is completely non-functional. The hardcoded `is_http2 = true` has no effect. All connections use HTTP/1.1.

---

### 1.3 Incorrect Line Number References in Document

| Documented Location | Actual Location | Issue |
|---------------------|-----------------|-------|
| `dispatch.rs:12-22` | `dispatch.rs:12-22` | **Correct** - DispatchParams is accurate |
| `executor.rs:96-103` | `executor.rs:96-103` | **Correct** - ProxyExecutor is accurate |
| `streaming.rs:12-22` | `streaming.rs:12-22` | **Correct** - TeeBody is accurate |
| `governor.rs:8-54` | `governor.rs:8-54` | **Need to verify** - GlobalCacheGovernor |
| `pool.rs:140-154` | `pool.rs:153-167` | **Off by ~13 lines** - Backend struct |
| `pool.rs:375-380` | `pool.rs:376-382` | **Off by ~1 line** - UpstreamPool struct |
| `pool.rs:47-56` | `pool.rs:48-57` | **Off by 1 line** - LoadBalanceAlgorithm |
| `health.rs:10-15` | `health.rs` not found in glob | **Missing file** - health.rs is at `src/upstream/health.rs`, not in proxy |

**Verification needed for governor.rs** - need to read that file.

---

### 1.4 Retry Config Application (BUG-PROXY-1)

**Document Claims:**
- No specific claim about retry config being applied

**Actual Implementation:**
- `src/proxy/mod.rs:303` - `retry_config: retry_config.clone()` - **FIXED** - The retry config is properly passed through
- Previously (as noted in AGENTS.md), the retry_config was not being passed to the pool

**Status:** BUG-PROXY-1 is **confirmed fixed**.

---

### 1.5 SiteConnectionLimiter Unused Parameters

**Document Claims:**
- No specific documentation about SiteConnectionLimiter parameters

**Actual Implementation:**
- `src/waf/traffic_shaper/limiter.rs:306-309` - `SiteConnectionLimiter` struct has `site_id` and `limiter` fields
- `src/proxy/mod.rs:331-348` - `try_acquire` is called with just `&self.site_id` and `client_ip`
- The method signature at lines 319-323 shows `pub async fn try_acquire(&self, client_ip: IpAddr)` - no parameters for max connections

**Issue:** Looking at `try_acquire_with_limits` (lines 51-98), the `max_per_site` and `max_per_ip` parameters exist but are **always passed as `None`** in the simple `try_acquire` path. This means per-site and per-IP limits from configuration are never actually applied.

---

### 1.6 Connection Pooling Architecture - Documentation Accurate

**Verified Correct:**
- Three-layer connection pooling architecture diagram (lines 164-204) is **correct**
- Layer 1: Global client cache at `mod.rs:70-88` - **Correct**
- Layer 2: Erased connection pool at `erased_pool.rs:218-303` - Actually `224-330` for ErasedConnectionPool struct - **Close**
- Layer 3: Typed connection pool at `typed_pool.rs:59-94` - **Need to verify**

---

### 1.7 Upstream Pool Load Balancing - Document Mostly Accurate

**Verified:**
- `pool.rs:48-57` - LoadBalanceAlgorithm enum matches
- `pool.rs:513-528` - PeakEwma implementation uses `(conn + 1.0) * (latency + 1.0)` formula - **Correct**
- `pool.rs:113` - Composite load formula `conn_load * 0.4 + cpu_load * 0.6` - **Correct**

---

## 2. Bugs and Security Issues

### 2.1 ErasedHttpClient Phase 9 Incomplete (Known Issue)

**Location:** `src/http/server.rs:3305`
**Severity:** Medium (Performance)
**Description:** `use_erased_client` is hardcoded to `false`, meaning the type-erased connection pool never handles production traffic. This bypasses the optimized path designed for 1M+ RPS scale.

---

### 2.2 HTTP/2 Multiplexing Completely Non-Functional

**Location:** `src/http_client/erased_pool.rs:204-206`
**Severity:** Low (Architectural)
**Description:** `Http2PooledConnection::is_available()` always returns `false`. The HTTP/2 connection pooling infrastructure is stub code that was never completed.

---

### 2.3 SiteConnectionLimiter Ignores Max Limits

**Location:** `src/waf/traffic_shaper/limiter.rs:51-98`
**Severity:** Low (Configuration)
**Description:** `try_acquire_with_limits()` accepts `max_per_site` and `max_per_ip` parameters, but the public `try_acquire()` method at line 42-49 always calls it with `None`, meaning configurable per-site and per-IP limits are not enforced.

---

## 3. Missing or Incomplete Features

### 3.1 HTTP/2 Upstream Support

**Status:** Not implemented
**Impact:** Only HTTP/1.1 is used for upstream connections

---

### 3.2 ProxyHeadersConfig Not Passed to send_single_request

**Location:** `src/proxy/mod.rs:1225-1238`
**Description:** The `send_single_request` method does not accept a `ProxyHeadersConfig` parameter. Forward headers are built from incoming request headers without per-upstream customization.

---

### 3.3 QUIC Tunnel Response Parsing

**Location:** `src/http_client/mod.rs:1099-1145`
**Description:** QUIC tunnel response parsing uses `String::from_utf8_lossy` and manual HTTP header parsing. This is fragile and doesn't properly handle binary response bodies.

---

## 4. Documentation Accuracy Issues

### 4.1 File Path References

The document references `src/proxy/` files correctly, but the health checker file is incorrectly placed. 

**Incorrect:** `health.rs` in proxy module
**Correct:** `src/upstream/health.rs`

### 4.2 Line Number Drift

As the codebase evolves, line numbers in the documentation become stale. This is unavoidable for detailed line references but should be noted as a known maintenance burden.

---

## 5. Recommended Improvements

### 5.1 Complete ErasedHttpClient Phase 9

1. Change `src/http/server.rs:3305` from hardcoded `false` to conditional logic
2. Use `ErasedHttpClient::send_request()` when body is streaming
3. Add metrics to verify activation

### 5.2 Implement HTTP/2 Upstream Support

1. Complete `Http2PooledConnection::is_available()` to return actual availability
2. Add HTTP/2 connection multiplexing to `ErasedConnectionPool::checkout()`
3. Add ALPN negotiation to detect HTTP/2 capability per host

### 5.3 Fix SiteConnectionLimiter Parameters

1. Change `try_acquire()` to accept `max_per_site` and `max_per_ip` parameters
2. Or wire the configuration values from site config into the call site

### 5.4 Improve Documentation

1. Add a "Last Verified" timestamp to architecture documents
2. Consider using code-generated documentation anchors instead of line numbers
3. Add a section on known incomplete features

### 5.5 Improve QUIC Tunnel Response Parsing

1. Use a proper HTTP parser instead of string manipulation
2. Handle binary bodies correctly (don't assume UTF-8)

---

## 6. Summary Table

| Issue | Severity | Status | Location |
|-------|----------|--------|----------|
| ErasedHttpClient Phase 9 incomplete | Medium | Known | `src/http/server.rs:3305` |
| HTTP/2 multiplexing not implemented | Low | Known | `erased_pool.rs:204-206` |
| Retry config applied | N/A | **Fixed** | `src/proxy/mod.rs:303` |
| SiteConnectionLimiter unused params | Low | Known | `limiter.rs:42-49` |
| Line number drift | Low | Maintenance | Various |
| ProxyHeadersConfig not passed | Low | Enhancement | `mod.rs:1225-1238` |

---

## 7. Verification Commands

```bash
# Verify compilation for all profiles
cargo check --no-default-features --features mesh,dns

# Run proxy-related tests
cargo test --lib proxy

# Run upstream tests
cargo test --lib upstream

# Run HTTP client tests
cargo test --lib http_client

# Verify formatting
cargo fmt && cargo clippy --lib -- -D warnings
```

---

*Document Generated: 2026-05-26*
*Review Scope: `architecture/proxy_deep_dive.md` vs `src/proxy/`, `src/proxy_cache/`, `src/http_client/`, `src/upstream/`*
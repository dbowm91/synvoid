# Proxy & Upstream Architecture Review Plan

## Stale Items Identified

### 1. Document Reference to `mod.rs` Line Numbers (Minor)
- **Document**: `ProxyServer` struct documentation references `mod.rs:73-94`
- **Actual**: `ProxyServer` struct is at lines 73-94 - **CORRECT**
- **Document**: `DispatchParams` references `dispatch.rs:12-22`
- **Actual**: `DispatchParams` is at lines 12-22 - **CORRECT**

### 2. HTTP/2 Status (STALE - Known Issue)
- **Document claims**: HTTP/2 is part of the connection pooling strategy with `is_http2` flag in `PoolKey`
- **Code reality**: `send_request_erased_streaming` in `http_client/mod.rs:893` sets `is_http2 = true` but `ErasedConnectionPool` only supports HTTP/1.1 (see `erased_pool.rs:217-222` - `Http2PooledConnection::is_available()` returns `false`)
- **Status**: This is a known bug documented in `AGENTS.md` under "Known Implementation Issues": "HTTP/2 disabled ... is_http2 = false - infrastructure exists but unused"

### 3. `ErasedHttpClient` Usage in ProxyServer (STALE - Phase 9 Incomplete)
- **Document claims**: `forward_with_pool()` sends via `ErasedHttpClient`
- **Actual**: In `proxy/mod.rs:1227-1239`, `send_single_request` uses `send_request_erased_streaming` which DOES use `ErasedHttpClient`
- **However**: `use_erased_client` is hardcoded to `false` in `src/http/server.rs:3302` per AGENTS.md "ErasedHttpClient never used - Phase 9 incomplete"

### 4. Connection Pooling Layer Description (ACCURATE)
- The document correctly describes three-layer pooling and the diagram matches `mod.rs:70-88` for global cache, `erased_pool.rs:218-303` for erased pool, and `typed_pool.rs:59-94` for typed pool.

### 5. `ClientRegistry` Reference (STALE)
- **Document lists**: `client_registry.rs` as part of key proxy files with responsibility "Per-site HTTP client caching"
- **Actual code**: `client_registry.rs` exists and provides `UpstreamClientRegistry` but `ProxyServer` does NOT use it. Instead `ProxyServer` creates its own clients directly via `create_upstream_client()` in `new_with_pool_config()`.
- **Impact**: `UpstreamClientRegistry` is unused by the proxy module

---

## Claims Verified / Issues Found

### VERIFIED Claims

| Claim | Location | Status |
|-------|----------|--------|
| `ProxyServer::handle_request()` WAF integration | `mod.rs:371-481` | ✅ Verified - WAF check with Drop/Stall/Block/Challenge/Tarpit/Pass |
| `ProxyServer::forward_with_pool()` retry loop | `mod.rs:991-1121` | ✅ Verified - retries with backoff, backend selection |
| `TeeBody` streaming body wrapper | `streaming.rs:12-143` | ✅ Verified - implements `Body`, tees data for cache |
| `GlobalCacheGovernor` 512MB default | `governor.rs:12` | ✅ Verified - `DEFAULT_MAX_BUFFERED_BYTES = 512 * 1024 * 1024` |
| `Backend::is_available()` check | `pool.rs:281-284` | ✅ Verified - healthy + under connection limit |
| `Backend::connection_scope()` RAII guard | `pool.rs:302-305` | ✅ Verified - returns `ConnectionGuard` |
| `Backend::record_latency()` EWMA 90% weight | `pool.rs:307-318` | ✅ Code uses 90% weight (line 314: `old_ewma * 9 + latency_ms) / 10`) |
| Circuit breaker 3 failures | `pool.rs:332-343` | ✅ Verified - `failures >= 3` marks unhealthy |
| Circuit breaker recovery 3 successes | `pool.rs:324-330` | ✅ Verified - `successes >= 3` marks healthy |
| `composite_load()` formula | `pool.rs:367-373` | ✅ Verified - `(conn_load * 0.4) + (cpu_load * 0.6)` |
| `PeakEwma` cost formula | `pool.rs:513-528` | ✅ Verified - `(conn + 1.0) * (latency + 1.0)` |
| HealthChecker supports HEAD/GET/TCP | `health.rs:181-186` | ✅ Verified |
| HealthChecker failure_threshold=3 | `health.rs:42` | ✅ Verified - default 3 |
| HealthChecker recovery_threshold=2 | `health.rs:43` | ✅ Verified - default 2 |
| SharedConnectionTable 10s heartbeat timeout | `shared_state.rs:103-124` | ✅ Verified - `timeout_secs: u64` parameter, hardcoded 10s in call at line 108 |

### DISCREPANCIES FOUND

| Issue | Document Says | Code Does | Location |
|-------|---------------|-----------|----------|
| HTTP/2 connection reuse | PoolKey uses `is_http2` for HTTP/2 multiplexing | `Http2PooledConnection::is_available()` always returns `false` | `erased_pool.rs:205-206` |
| `ErasedHttpClient` actual usage | Used for upstream requests | `is_http2 = true` hardcoded but HTTP/2 pooled connections unavailable | `http_client/mod.rs:893` |
| `UpstreamClientRegistry` usage | Per-site client caching for proxy | `ProxyServer` creates its own clients, registry unused | `client_registry.rs`, `proxy/mod.rs:146-174` |
| `retry_config` parameter handling | BUG-PROXY-1 fixed - retry_config applied | Verified fixed at `mod.rs:303` | `proxy/mod.rs:303` |

---

## Improvement Plan

### High Priority

1. **Complete HTTP/2 Support or Remove Dead Code**
   - **Issue**: `is_http2 = true` is set but `Http2PooledConnection::is_available()` returns `false`
   - **Action**: Either implement HTTP/2 connection pooling or change `is_http2 = false` to avoid misleading behavior
   - **Files**: `http_client/erased_pool.rs:199-215`, `http_client/mod.rs:893`

2. **Connect `UpstreamClientRegistry` or Deprecate**
   - **Issue**: `UpstreamClientRegistry` exists but `ProxyServer` doesn't use it
   - **Action**: Either integrate it into `ProxyServer` or move it to a location where it's actually used
   - **Files**: `proxy/client_registry.rs`, `proxy/mod.rs:146-174`

### Medium Priority

3. **Document the `retry_config` Fix**
   - The fix for BUG-PROXY-1 (retry_config applied) at `mod.rs:303` should be mentioned in the document
   - Add note about retry logic in Request Flow section

4. **Add Missing `ProxyHeadersConfig` to `send_single_request`**
   - **Issue**: `send_single_request` calls `send_request_erased_streaming` but doesn't pass custom proxy headers config
   - `forward_with_pool` uses default headers, while dispatch-based flow uses `build_forward_headers` with config
   - **Location**: `proxy/mod.rs:1225`

5. **StreamingWafBody Integration Documentation**
   - The document mentions WAF scanning on chunks during streaming
   - `StreamingWafBody` exists in `http_client/mod.rs:133-223` but is not used in proxy flow
   - May be used in incoming request handling rather than upstream responses

### Low Priority

6. **Clarify Load Balancing Algorithm Names in Diagram**
   - Document lists "PeakEwma" but algorithm enum is `PeakEwma` - matches correctly
   - Add formula documentation for PeakEwma cost calculation

7. **Update Connection Pooling Diagram**
   - The diagram in the document correctly shows 3-layer pooling
   - Add note that Layer 2 (Erased) only supports HTTP/1.1 currently

---

## Bug Report

### Minor Bugs

1. **HTTP/2 Hardcoded to True but Not Supported**
   - **Severity**: Minor
   - **Location**: `http_client/mod.rs:893`
   - **Issue**: `is_http2 = true` is passed to `send_request_erased_streaming` but `Http2PooledConnection` returns `is_available() = false`, so HTTP/2 multiplexing is never used
   - **Expected**: Either implement HTTP/2 or set `is_http2 = false`
   - **Note**: This is a known issue documented in AGENTS.md

2. **Unused `UpstreamClientRegistry`**
   - **Severity**: Minor (code smell)
   - **Location**: `proxy/client_registry.rs`
   - **Issue**: `UpstreamClientRegistry` provides per-site HTTP client caching but `ProxyServer` doesn't use it, instead creating clients directly
   - **Impact**: Dead code that could cause confusion

3. **Inconsistent Retry Configuration Access**
   - **Severity**: Minor
   - **Location**: `proxy/mod.rs:998-1003` vs `proxy/mod.rs:303`
   - **Issue**: `forward_with_pool` accesses `retry_config` via `self.retry_config.as_ref()` inline rather than using stored `retry_config` at construction
   - **Note**: This is actually correct - the stored config at line 303 is `retry_config: retry_config.clone()` which is correct

---

## Summary

The architecture document is **largely accurate** with the following key issues:

1. **HTTP/2 Disabled**: The document implies HTTP/2 support exists for connection multiplexing, but `Http2PooledConnection::is_available()` always returns `false`. This is a known issue.

2. **Phase 9 Incomplete**: `ErasedHttpClient` usage is hardcoded to `false` in the HTTP server, so the proxy's `ErasedHttpClient` path may not be exercised in production.

3. **`UpstreamClientRegistry` Dead Code**: The per-site client registry exists but isn't used by `ProxyServer`.

The core proxy functionality (WAF integration, retry logic, cache buffering, load balancing, circuit breakers, health checking) is correctly documented and matches the implementation.

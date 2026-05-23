# Proxy Module Architecture Review Plan

**Review Date**: 2026-05-23  
**Document Reviewed**: `architecture/proxy_deep_dive.md`  
**Code Verified Against**: `src/proxy/`, `src/http_client/`, `src/upstream/`

---

## 1. Claims Verified / Not Verified

### 1.1 Proxy Module (`src/proxy/`)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| `ProxyServer` struct exists with HttpClient, ErasedHttpClient, upstream pool, cache, WAF reference | **VERIFIED** | `src/proxy/mod.rs:73-94` | Struct matches exactly |
| `handle_request()` is main entry point with WAF checking | **VERIFIED** | `src/proxy/mod.rs:315-567` | Full WAF integration at lines 371-481 |
| `handle_request_with_cache()` has PURGE support | **VERIFIED** | `src/proxy/mod.rs:604-766` | PURGE handling at lines 614-627 |
| `forward_with_pool()` has retry loop with backend selection | **VERIFIED** | `src/proxy/mod.rs:986-1116` | Retry logic matches doc |
| `DispatchParams` bundles all parameters for upstream dispatch | **VERIFIED** | `src/proxy/dispatch.rs:12-22` | Struct matches exactly |
| `ProxyExecutor` has caching-aware execution with `execute_with_cache()` | **VERIFIED** | `src/proxy/executor.rs:96-103` | Struct exists, method at lines 106-191 |
| `TeeBody` is body wrapper that streams while buffering for cache | **VERIFIED** | `src/proxy/streaming.rs:12-143` | Full implementation verified |
| `GlobalCacheGovernor` uses atomic compare-exchange for reservation tracking | **VERIFIED** | `src/proxy/governor.rs:8-54` | Uses `compare_exchange_weak` at line 28 |
| `GlobalCacheGovernor` has 512MB default limit | **VERIFIED** | `src/proxy/governor.rs:11` | `DEFAULT_MAX_BUFFERED_BYTES = 512 * 1024 * 1024` |

### 1.2 Upstream Module (`src/upstream/`)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| `Backend` struct has url, weight, max_connections, is_healthy, etc. | **VERIFIED** | `src/upstream/pool.rs:152-166` | Matches exactly |
| `Backend::is_available()` checks healthy + connection limit | **VERIFIED** | `src/upstream/pool.rs:279-283` | `is_healthy.is_running() && load < max` |
| `Backend::connection_scope()` is RAII guard | **VERIFIED** | `src/upstream/pool.rs:168-176` | Returns ConnectionGuard that calls decrement on drop |
| `Backend::record_latency()` uses EWMA with 90% weight | **PARTIAL** | `src/upstream/pool.rs:306-317` | Uses 90% weight: `(old * 9 + new) / 10` ✓ |
| `Backend::record_success()` / `record_failure()` with 3-failure threshold | **VERIFIED** | `src/upstream/pool.rs:323-342` | Circuit breaker verified |
| `Backend::composite_load()` formula `(conn_load * 0.4) + (cpu_load * 0.6)` | **VERIFIED** | `src/upstream/pool.rs:366-372` | Matches exactly |
| `UpstreamPool::select_backend()` for primary selection | **VERIFIED** | `src/upstream/pool.rs:411-419` | Implemented |
| `UpstreamPool::select_next_backend()` for failover | **VERIFIED** | `src/upstream/pool.rs:527-552` | Implemented |
| `LoadBalanceAlgorithm` enum: RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash | **VERIFIED** | `src/upstream/pool.rs:47-56` | Matches exactly |
| PeakEwma uses `cost = (connections + 1) * (latency + 1)` | **VERIFIED** | `src/upstream/pool.rs:499-509` | Implemented at line 503 |
| `HealthChecker` runs periodic checks via `tokio::time::interval` | **VERIFIED** | `src/upstream/health.rs:76-90` | Uses `interval()` at line 77 |
| HealthChecker supports HEAD, GET, TCP methods | **VERIFIED** | `src/upstream/health.rs:180-186` | All three variants handled |
| `HealthChecker` has configurable failure_threshold (3) and recovery_threshold (2) | **VERIFIED** | `src/upstream/health.rs:35-47` | Default values match |
| `SharedConnectionTable` uses mmap for cross-worker load balancing | **VERIFIED** | `src/upstream/shared_state.rs:1-134` | Full implementation |
| Layout: `[max_workers:u64][max_backends:u64][heartbeats:AtomicU64][connections:AtomicUsize]` | **VERIFIED** | `src/upstream/shared_state.rs:16-25` | Header + heartbeats + connections layout |
| `record_heartbeat()` for worker liveness | **VERIFIED** | `src/upstream/shared_state.rs:73-77` | Implemented |
| `sum_active_connections()` with 10s timeout | **VERIFIED** | `src/upstream/shared_state.rs:103-125` | `timeout_secs` parameter used at line 117 |

### 1.3 HTTP Client Module (`src/http_client/`)

| Claim | Status | Code Location | Notes |
|-------|--------|---------------|-------|
| Three-layer connection pooling: Global client cache, Erased pool, Typed pool | **VERIFIED** | `src/http_client/mod.rs:67-88`, `erased_pool.rs`, `typed_pool.rs` | All three layers verified |
| Global client cache: HttpClient by TLS config, 100 entry, 5min TTL | **VERIFIED** | `src/http_client/mod.rs:67-78` | `MAX_UPSTREAM_CLIENT_CACHE_SIZE = 100`, `UPSTREAM_CLIENT_CACHE_TTL_SECS = 300` |
| Erased connection pool: per-host HTTP/1.1 connection reuse | **VERIFIED** | `src/http_client/erased_pool.rs:221-300` | `checkout()` and `checkin()` pattern |
| Typed connection pool: per (authority, body_type) | **VERIFIED** | `src/http_client/typed_pool.rs:59-94` | `TypedPoolKey` includes body_type_id |
| Uses `rustls` with `aws_lc_rs` crypto | **VERIFIED** | `src/http_client/mod.rs:442-459` | Provider initialized at line 445 |
| `HostnameSkippingVerifier` wraps WebPkiServerVerifier | **VERIFIED** | `src/http_client/mod.rs:567-635` | Full implementation |
| `StreamingWafBody<B>` performs WAF scanning on chunks | **VERIFIED** | `src/http_client/mod.rs:133-223` | `poll_frame()` calls `sw.scan_chunk()` |
| `ErasedHttpClient` uses checkout → send → checkin pattern | **VERIFIED** | `src/http_client/erased_pool.rs:386-427` | Pattern at lines 408-421 |

---

## 2. Improvement Plan

### High Priority

| Issue | Location | Description |
|-------|----------|-------------|
| **Retry Config Not Propagated to `from_config()`** | `src/proxy/mod.rs:221-313` | The `from_config()` method creates `ProxyServer` but doesn't call `with_upstream_pool()` to set retry_config, buffering_config. The `retry_config` and `buffering_config` fields are set to `None` even though method accepts these parameters. This means retries are always disabled regardless of configuration. |
| **ErasedHttpClient `send_request` always uses `is_http2 = false`** | `src/proxy/mod.rs:1222` + `src/http_client/mod.rs:890` | In `send_request_erased_streaming()`, `is_http2` is hardcoded to `false`. The comment at line 890 says `let is_http2 = false;` which appears to be incomplete implementation - HTTP/2 support is not actually used despite the infrastructure being in place. |
| **Cache purge token comparison uses `ConstantTimeEq`** | `src/proxy/mod.rs:793` | Correctly uses `ct_eq()` for token comparison as per AGENTS.override.md guidance. Good. |
| **Potential memory leak in `TeeBody`** | `src/proxy/streaming.rs:96-108` | If `poll_frame` returns `Poll::Ready(Some(Ok(frame)))` with data but the cache insert at line 116 fails, the buffered data is silently dropped. This may be intentional, but the `reserved_bytes` from governor may not be properly released in all error paths. |

### Medium Priority

| Issue | Location | Description |
|-------|----------|-------------|
| **`apply_response_size_limit` cannot be used for true streaming** | `src/proxy/executor.rs:60-80` | The documentation comment at lines 61-69 explicitly states this is only for buffered responses. This is a known limitation documented in the architecture but could be clearer in the deep-dive. |
| **`TypedConnectionPool` hardcodes `https_or_http()`** | `src/http_client/typed_pool.rs:128` | While the erased pool respects `allow_plaintext`, the typed pool always allows HTTP. This inconsistency could cause issues in security-critical deployments. |
| **Health checker uses string-based URL parsing for TCP checks** | `src/upstream/health.rs:224-231` | TCP health check at line 228 uses `TcpStream::connect(url)` where `url` is the backend URL string. If the URL has a path component (e.g., `http://backend:8080/path`), the TCP connection will fail or behave unexpectedly. Should use `UpstreamAddress::parse()` instead. |
| **`Backend::record_latency` stores latency in milliseconds** | `src/upstream/pool.rs:307-317` | The EWMA calculation uses milliseconds internally, but there's no visibility into this unit. If latency tracking is exposed via metrics, it may be unclear that units are milliseconds. |
| **Missing `checkin` bounds check** | `src/http_client/erased_pool.rs:419` | After sending request, connection is always checked back in via `checkin(key, conn)`. If checkout succeeded but send failed, the connection may be in a bad state but still returned to pool. Should verify connection health before checkin. |

### Low Priority

| Issue | Location | Description |
|-------|----------|-------------|
| **`GlobalCacheGovernor` uses Relaxed ordering for load** | `src/proxy/governor.rs:20-21` | `MAX_BUFFERED_BYTES.load(Ordering::Relaxed)` is correct since it's a configuration value that doesn't need synchronization. Good. |
| **`CURRENT_BUFFERED_BYTES` uses SeqCst for compare_exchange** | `src/proxy/governor.rs:31` | Correct use of SeqCst for the value that needs strong consistency. Good. |
| **XFF truncation preserves newest entries** | `src/proxy/headers.rs:376-396` | `validate_and_truncate_xff()` at line 379-380 truncates to keep the most recent entries (newest first). This is correct for proxying but may differ from some expectations where oldest entries are preserved. |
| **`is_private_ip` has limited IPv6 support** | `src/proxy/headers.rs:90-117` | The function checks fc00, fe80, ff00, and ::1 but doesn't check for documentation-grade addresses like 2001:db8::/32. This is minor but could be improved. |
| **Missing `From<UpstreamClientKey>` for `UpstreamTlsConfig`** | `src/http_client/mod.rs:55-64` | The `From` implementation exists but is private (not `pub`). This is fine but worth noting if the upstream client caching is ever extended. |

---

## 3. Bug Report

### Critical

| Bug | Location | Impact | Description |
|-----|----------|--------|-------------|
| **Retry config not applied from `from_config()`** | `src/proxy/mod.rs:293-312` | **HIGH** - Retries are always disabled | `forward_with_pool()` checks `retry_config.as_ref()` at line 993, which will always be `None` when using `from_config()` since `with_upstream_pool()` is never called. The retry logic appears dead code unless users manually construct `ProxyServer` and call `with_upstream_pool()`. |

### Minor

| Bug | Location | Impact | Description |
|-----|----------|--------|-------------|
| **`send_request_erased_streaming` ignores HTTP/2 flag** | `src/http_client/mod.rs:890` | **LOW** - HTTP/2 never used | `is_http2 = false` is hardcoded. The pool key includes `is_http2` but it's never actually used. This is incomplete implementation but not a functional bug since HTTP/1.1 always works. |
| **QUIC tunnel response parsing is fragile** | `src/http_client/mod.rs:1096-1128` | **LOW** - Edge case parsing issues | Uses `String::from_utf8_lossy()` and split on `\r\n`. If the response contains binary data or the status line has extra spaces, parsing could fail silently. No unit tests cover malformed responses. |
| **Health check path appended without validation** | `src/upstream/health.rs:193-197` | **LOW** - Potential malformed URL | Uses `format!("{}{}", backend.url.trim_end_matches('/'), config.health_check_path)`. If `health_check_path` starts with `/` and backend URL ends with `/`, you get double slashes. If it doesn't start with `/`, you get missing separator. No validation. |
| **ErasedHttpClient clone shares pool** | `src/http_client/erased_pool.rs:435-441` | **LOW** - Thread safety concern | `Clone` for `ErasedHttpClient` clones the inner pool Arc. This is correct behavior - all clones share the same pool. Not a bug, but worth documenting. |

---

## 4. Additional Findings

### 4.1 Verified Correct Patterns

1. **Constant-time comparison for cache purge tokens**: Correctly implemented at `src/proxy/mod.rs:793`
2. **Hop-by-hop header stripping**: Properly implemented via `HOP_BY_HOP_HEADERS` constant
3. **XFF sanitization**: `validate_and_truncate_xff()` correctly filters private IPs and truncates chain
4. **Circuit breaker pattern**: 3 failures for unhealthy, 3 successes for healthy - correctly implemented
5. **Connection guard RAII**: `ConnectionGuard` properly decrements connections on drop

### 4.2 Architectural Notes

1. **TeeBody memory management**: Correctly uses `GlobalCacheGovernor` for reservation tracking with proper release on drop
2. **Two client patterns**: Both `ProxyExecutor` (sync, buffered) and `ProxyServer` (async, streaming) exist - this is intentional for different use cases
3. **Erased pool is actually used**: Unlike the `ErasedHttpClient` integration issue mentioned in AGENTS.md (which is in http/server.rs, not proxy), the erased pool in `send_request_erased_streaming` IS correctly used

### 4.3 Code Quality

The proxy module is well-structured with clear separation of concerns:
- `mod.rs` - orchestration
- `dispatch.rs` - low-level dispatch  
- `executor.rs` - caching execution
- `retry.rs` - retry logic
- `cache.rs` - cache response building
- `headers.rs` - header handling
- `streaming.rs` - body streaming with caching
- `governor.rs` - memory limiting
- `client_registry.rs` - per-site client caching

The upstream module is similarly well-organized with proper load balancing algorithms and health checking.

---

## 5. Recommendations

1. **Fix retry config propagation**: Call `with_upstream_pool()` in `from_config()` or initialize retry_config field directly
2. **Complete HTTP/2 support or remove is_http2 from PoolKey**: Either implement actual HTTP/2 connection multiplexing or remove the dead code
3. **Add health check TCP mode using UpstreamAddress::parse()**: Use the existing `UpstreamAddress::parse()` for TCP mode instead of raw URL parsing
4. **Consider adding connection health check before checkin**: Verify connection is still usable before returning to pool to avoid propagating bad connections

---

**End of Review**

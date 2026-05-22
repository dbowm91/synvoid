# HTTP/Proxy Architecture Review Plan

## Executive Summary

This review examined the HTTP/Proxy architecture documentation against the actual implementation in `src/proxy/`, `src/http/`, `src/http_client/`, and `src/upstream/` directories. The documentation is **largely accurate** with a few discrepancies, missing implementation details, and opportunities for improvement.

---

## 1. Documented vs Implemented Summary

### 1.1 Proxy Module (`src/proxy/`)

| Documented | Status | Notes |
|------------|--------|-------|
| `ProxyServer` struct with WAF integration | Implemented | `src/proxy/mod.rs:73-94` |
| `handle_request()` with WAF checking | Implemented | `src/proxy/mod.rs:315-538` |
| `handle_request_with_cache()` with PURGE support | Implemented | `src/proxy/mod.rs:575-723` |
| `forward_with_pool()` retry loop | Implemented | `src/proxy/mod.rs:942-1072` |
| `DispatchParams` struct | Implemented | `src/proxy/dispatch.rs:12-22` |
| `ProxyExecutor` with `execute_with_cache()` | Implemented | `src/proxy/executor.rs:96-339` |
| `TeeBody` streaming wrapper | Implemented | `src/proxy/streaming.rs:12-134` |
| `GlobalCacheGovernor` 512MB default | Implemented | `src/proxy/governor.rs:1-54` |
| `UpstreamPool` with load balancing | Implemented | `src/upstream/pool.rs:363-735` |
| Circuit breaker (3 failures) | Implemented | `src/upstream/pool.rs:319-330` |
| `HealthChecker` with configurable methods | Implemented | `src/upstream/health.rs:1-237` |
| `SharedConnectionTable` via mmap | Implemented | `src/upstream/shared_state.rs:1-193` |

### 1.2 HTTP Client Module (`src/http_client/`)

| Documented | Status | Notes |
|------------|--------|-------|
| Global client cache (100 entry, 5min TTL) | Implemented | `src/http_client/mod.rs:67-78` |
| Erased connection pool | Implemented | `src/http_client/erased_pool.rs:218-303` |
| Typed connection pool | Implemented | `src/http_client/typed_pool.rs` |
| `StreamingWafBody` | Implemented | `src/http_client/mod.rs:133-223` |
| `ErasedHttpClient` | Implemented | `src/http_client/erased_pool.rs:321-370` |
| TLS with `aws_lc_rs` | Implemented | `src/http_client/mod.rs:442` (uses aws-lc-rs crypto provider) |

### 1.3 HTTP Server (`src/http/`)

| Documented | Status | Notes |
|------------|--------|-------|
| `mesh_backend_pool` for `BackendType::Mesh` | Implemented | `src/http/server.rs:356,2863-3016` |
| Spin WASM support (partial) | Partial | See Section 2.1 |

---

## 2. Discrepancies and Issues

### 2.1 AGENTS.md Lesson Incorrect - Spin Framework Status

**AGENTS.md states (line 175):**
> "Spin framework partially implemented - `src/spin/` exists with manifest.rs, runtime.rs, handler.rs, kv_store.rs. However, routing integration and component mapping is NOT implemented."

**Actual Code:**
The Spin framework **IS integrated** into the HTTP server routing:

```rust
// src/http/server.rs:2411-2489
if matches!(target.backend_type, crate::router::BackendType::Spin) {
    if let Some(ref spin_app_name) = target.spin_app_name {
        let spin_apps_manager = crate::spin::handler::get_global_spin_apps_manager();
        if let Some(runtime) = spin_apps_manager.get(spin_app_name) {
            let handler = crate::spin::handler::SpinHttpHandler::new(runtime);
            // ... handles Spin requests
        }
    }
}
```

**Issue:** The Spin routing integration **IS implemented**. The Spin framework has:
- `src/spin/manifest.rs` - Spin manifest parsing
- `src/spin/runtime.rs` - Spin runtime
- `src/spin/handler.rs` - `SpinAppsManager` and `SpinHttpHandler`
- `src/spin/kv_store.rs` - Key-value store support

**Recommendation:** Update AGENTS.md line 175 to remove the claim that routing integration is not implemented. The issue is that full component mapping may be incomplete, but basic routing works.

### 2.2 File Path Reference Issues

**Issue:** `proxy_deep_dive.md` references `src/http/shared_handler.rs:4532` for functions that don't exist there.

The documentation says:
> "Known File Path Corrections - `src/http/shared_handler.rs` -> `src/http/server.rs:4532`"

**Verification:** While `src/http/server.rs` is the correct location, line numbers in documentation can drift as code changes.

**Recommendation:** Use function names instead of line numbers in documentation, or verify current locations with:
```bash
grep -n "collect_body_with_chunk_waf\|stream_body_with_waf" src/http/server.rs
```

### 2.3 Safe Headers Whitelist Count Discrepancy

**proxy_deep_dive.md states:**
> "TL-4 (SAFE_HEADERS whitelist): Already implemented in `src/proxy/cache.rs:97-126` with 29 headers"

**Actual Code:** `src/proxy/cache.rs:97-126` shows 27 headers in the SAFE_HEADERS array.

**Recommendation:** Update documentation to reflect accurate count of 27 headers.

### 2.4 GlobalCacheGovernor Memory Reservation Issue

**Location:** `src/proxy/streaming.rs:37-58`

**Issue:** When `GlobalCacheGovernor::try_reserve()` returns `false` (memory limit reached), the body **still streams** but without caching. There's no metric or log to indicate caching was bypassed due to memory pressure.

**Recommendation:** Add tracing debug log when caching is bypassed:
```rust
} else {
    if size_hint > max_size {
        tracing::debug!("Response too large to cache: {} bytes", size_hint);
    } else if health != HealthState::Normal {
        tracing::debug!("Health state {} prevents caching", health);
    } else {
        tracing::debug!("GlobalCacheGovernor limit reached, streaming without cache");
    }
    None
}
```

---

## 3. Recommended Improvements

### 3.1 Add Metrics to GlobalCacheGovernor

**File:** `src/proxy/governor.rs`

Currently, `GlobalCacheGovernor` has no way to expose its current state for monitoring.

**Recommendation:** Add Prometheus metrics:
```rust
impl GlobalCacheGovernor {
    pub fn try_reserve(bytes: usize) -> bool {
        // ... existing logic ...
        if success {
            gauge!("synvoid.cache.governor.reserved_bytes")
                .set(CURRENT_BUFFERED_BYTES.load(Ordering::Relaxed) as f64);
        }
        success
    }
}
```

### 3.2 Add Connection Pool Metrics to ErasedHttpClient

**File:** `src/http_client/erased_pool.rs`

**Recommendation:** Expose `idle_count()` and `total_idle_count()` via ErasedHttpClient for observability.

### 3.3 Update proxy_deep_dive.md

**Issue:** Document references file paths that may become stale.

**Recommendation:** Add a note that file paths are approximate and should be verified with grep.

---

## 4. Positive Findings

### 4.1 Well-Implemented Features

1. **Type-Erased Connection Pooling:** Fully implemented in `erased_pool.rs` with proper checkout/checkin pattern
2. **Stale-While-Revalidate:** Properly implemented with semaphore limiting concurrent revalidations (`src/proxy/mod.rs:639-670`)
3. **Cache PURGE Support:** Properly implemented with token-based auth using constant-time comparison (`src/proxy/mod.rs:741-817`)
4. **Circuit Breaker:** Correctly implements 3-failure threshold for marking backends unhealthy
5. **QUIC Tunnel Support:** Implemented in `http_client/mod.rs:959-1150`
6. **Load Balancing Algorithms:** All 6 algorithms implemented (RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash)
7. **Health Checker:** Supports HEAD, GET, and TCP health check methods

### 4.2 Security Patterns Correctly Applied

1. **Constant-Time Comparison:** Used for cache purge tokens (`src/proxy/mod.rs:750`)
2. **XFF Sanitization:** Implemented with private IP filtering (`src/proxy/headers.rs:376-396`)
3. **Hop-by-hop Header Stripping:** Properly implemented
4. **TLS Configuration:** Uses `aws-lc-rs` provider with proper fallback

---

## 5. Action Items

| Priority | Issue | File | Recommendation |
|----------|-------|------|----------------|
| Low | Spin framework status in AGENTS.md | `AGENTS.md:175` | Update to reflect that Spin routing IS implemented |
| Low | SAFE_HEADERS count mismatch | `proxy_deep_dive.md` | Correct count from 29 to 27 |
| Low | Missing cache bypass logging | `src/proxy/streaming.rs:53-55` | Add debug logging when caching is bypassed |
| Medium | File path references in docs | `proxy_deep_dive.md` | Add note about verifying paths |
| Low | Add metrics to GlobalCacheGovernor | `src/proxy/governor.rs` | Consider adding Prometheus metrics |

---

## 6. Verification Commands

```bash
# Check proxy module compiles
cargo check --lib -p synvoid-proxy 2>&1 | head -20

# Verify GlobalCacheGovernor exists
grep -n "GlobalCacheGovernor" src/proxy/governor.rs

# Verify ErasedConnectionPool implementation
grep -n "ErasedConnectionPool" src/http_client/erased_pool.rs

# Verify TeeBody with governor integration
grep -n "GlobalCacheGovernor::try_reserve" src/proxy/streaming.rs

# Check Spin integration
grep -n "BackendType::Spin" src/http/server.rs
```

---

## 7. Conclusion

The HTTP/Proxy architecture is **well-implemented** and the documentation is **mostly accurate**. The main issues are:

1. **Documentation drift** - Line numbers and some counts are outdated
2. **AGENTS.md incorrect** - Spin framework status is wrong
3. **Missing observability** - GlobalCacheGovernor lacks metrics

The core architecture is sound and follows the documented patterns. No critical bugs were identified.

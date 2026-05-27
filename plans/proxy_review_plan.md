# Proxy Architecture Review Plan

## Verified Correct Items

### Core Proxy Module
- `ProxyServer` struct correctly at `src/proxy/mod.rs:73-94` with all documented fields
- All 8 submodules exist: `dispatch.rs`, `executor.rs`, `cache.rs`, `headers.rs`, `retry.rs`, `governor.rs`, `streaming.rs`, `client_registry.rs`
- `DispatchParams` at `src/proxy/dispatch.rs:14-22`
- `ProxyExecutor` at `src/proxy/executor.rs:98-103`
- `TeeBody<B>` at `src/proxy/streaming.rs:12-22`
- `GlobalCacheGovernor` at `src/proxy/governor.rs:9-54`

### Upstream Module
- `Backend` struct at `src/upstream/pool.rs:154-167` with all documented fields
- `UpstreamPool` at `src/upstream/pool.rs:376-382`
- `LoadBalanceAlgorithm` enum at `src/upstream/pool.rs:49-56` with 6 variants: RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash
- Backend methods verified:
  - `is_available()` at pool.rs:281
  - `record_latency()` uses 90% weight: `(old_ewma * 9 + latency_ms) / 10` at pool.rs:307-318
  - `connection_scope()` at pool.rs:302
  - `record_success()`/`record_failure()` with 3-failure threshold at pool.rs:324-337
  - `composite_load()` with 0.4/0.6 weighting at pool.rs:367-373
- `HealthChecker` at `src/upstream/health.rs:11-15`
- `SharedConnectionTable` at `src/upstream/shared_state.rs:21-25`

### HTTP Client Module
- Three-layer connection pooling architecture documented correctly
- `StreamingWafBody` at `src/http_client/mod.rs:135`
- `ErasedConnectionPool` at `src/http_client/erased_pool.rs:224`
- Global client cache at `src/http_client/mod.rs:70-88`

### Request Flow
- WAF integration correctly documented - `check_request_full()` called with all parameters, decisions handled (Drop, Stall, Block, Challenge, ChallengeWithCookie, Tarpit, Pass) at mod.rs:395-492
- Retry logic correctly implemented with method idempotency checks, status code filtering, connection/timeout error detection
- `forward_with_pool()` retry loop correctly implemented at mod.rs:999-1108

### Configuration
- HTTP/2 now configurable via `ProxyServer::with_http2()` builder method (mod.rs:223-225)
- RetryConfig properly cloned and applied at mod.rs:310

### BackendType
- `BackendType` enum at `src/router.rs:66-77` has 11 variants (matches AGENTS.md): Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin

---

## Discrepancies Found

### 1. Documentation Line Reference Error (Low Severity)
**Location:** `architecture/proxy_deep_dive.md:262`

**Issue:** States "is_http2=true is hardcoded in send_request_erased_streaming (http_client/mod.rs:893)"

**Actual:** Line 893 in `http_client/mod.rs` is the `authority` extraction, not a hardcoded `is_http2=true`. The `is_http2` parameter is passed from caller at `proxy/mod.rs:1246`.

### 2. calculate_backoff Implementation Divergence (Medium Severity)
**Location:** `architecture/proxy.md:210-215` vs `src/proxy/retry.rs:47-49`

**Documentation says:**
```rust
pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let base = base_timeout_ms.unwrap_or(100);
    let exponential = 2_u64.pow(attempt.min(5));
    let jitter = rand() % 100;
    (base * exponential).saturating_add(jitter)
}
```

**Actual implementation:**
```rust
pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let delay = base_timeout_ms * 2u64.saturating_pow(attempt.min(5));
    delay.min(30000)
}
```

**Differences:**
- No `unwrap_or(100)` - requires non-None value
- Uses `saturating_pow` instead of `pow`
- No jitter added
- Has 30-second cap

### 3. Stale-While-Revalidate Semaphore Location Error (Low Severity)
**Location:** `architecture/proxy_deep_dive.md:244`

**States:** "semaphore-based limiting (`revalidation_semaphore` at `proxy_cache/store.rs:156`)"

**Actual:** `revalidation_semaphore()` method is at `src/proxy_cache/store.rs:241`

### 4. HTTP/2 Documentation Outdated (Low Severity)
**Location:** `architecture/proxy_deep_dive.md:260-264`

**Issue:** States "HTTP/2 remains disabled" and "is_http2=true is hardcoded". This was true previously but HTTP/2 is now configurable via `ProxyServer::with_http2()`.

### 5. BackendType Documentation Mismatch (Low Severity)
**Location:** `architecture/proxy.md:57-63`

**Documentation shows:**
```rust
pub enum BackendType {
    Single(String),           // Single upstream URL
    Pool(Vec<Backend>),      // Load-balanced pool
    Fallback(Vec<Backend>),  // Fallback chain
    // ... other variants
}
```

**Actual at router.rs:66-77:** 11 specific variants (Upstream, FastCgi, Php, Cgi, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin) - no Single/Pool/Fallback variants.

---

## Bugs Identified

### 1. Backend Latency EWMA Weighting Inverted (Medium Severity)
**Location:** `src/upstream/pool.rs:307-318`

**Issue:** Documentation at `architecture/proxy_deep_dive.md:112` states "(90% weight given to historical value: `(old_ewma * 9 + latency_ms) / 10`)"

**Actual:** The implementation gives 90% to the OLD value: `(old_ewma * 9 + latency_ms) / 10`

This means new observations are under-weighted (10%) rather than over-weighted (90%). The documentation is correct about intent, but implementation may not match intended behavior.

---

## Suggested Improvements

### 1. Document HTTP/2 Status Update (Documentation)
Update `proxy_deep_dive.md:260-264` to reflect that HTTP/2 is now configurable via `ProxyServer::with_http2()`, not hardcoded disabled.

### 2. Fix calculate_backoff Documentation (Documentation)
Update `proxy.md:210-215` to match actual implementation at `retry.rs:47-49`:
```rust
pub fn calculate_backoff(attempt: u32, base_timeout_ms: u64) -> u64 {
    let delay = base_timeout_ms * 2u64.saturating_pow(attempt.min(5));
    delay.min(30000)
}
```

### 3. Fix Line References (Documentation)
- `proxy_deep_dive.md:262` - Remove incorrect line reference to http_client/mod.rs:893
- `proxy_deep_dive.md:244` - Correct line reference from 156 to 241 for revalidation_semaphore

### 4. Update BackendType Documentation (Documentation)
Replace generic `Single`/`Pool`/`Fallback` example with actual 11-variant enum from router.rs:66-77.

### 5. Investigate Latency EWMA Weighting (Clarification)
The implementation `old_ewma * 9 + latency_ms) / 10` gives 90% weight to history. Documentation claims 90% to historical. Either:
- Documentation is wrong and implementation is correct (new observation = 10%)
- Implementation was supposed to be `(latency_ms * 9 + old_ewma) / 10` (90% to new)

### 6. ProxyHeadersConfig Enhancement Tracking (Enhancement - PR-6)
As documented at `proxy_deep_dive.md:272-276`, `ProxyHeadersConfig` is not passed through `send_single_request`. This is a known enhancement gap tracked as PR-6.

### 7. UpstreamClientRegistry Integration (Enhancement)
As documented at `proxy_deep_dive.md:266-270`, `UpstreamClientRegistry` exists but is not used by `ProxyServer::send_single_request`. Consider integrating for typed client management benefits.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 15 |
| Discrepancies | 5 |
| Bugs | 1 |
| Suggested Improvements | 7 |

**Overall Assessment:** The Proxy architecture documentation is largely accurate. The main issues are outdated line references and one implementation deviation (calculate_backoff missing jitter, latency EWMA weighting direction). The BUG-PROXY-1 retry_config fix mentioned in AGENTS.md has been verified as fixed. HTTP/2 configuration is now available but docs haven't been updated.
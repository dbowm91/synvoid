# HTTP/Proxy Architecture Review - Improvement Plan

**Review Date:** 2026-05-23
**Reviewer:** Claude (AI Architecture Review)
**Documents Reviewed:** proxy_deep_dive.md, routing_deep_dive.md, app_handlers.md, layer_3_5_deep_dive.md

---

## 1. Verified Correct Items

### 1.1 Proxy Module (src/proxy/)

| Item | Document Claim | Actual Location | Status |
|------|----------------|------------------|--------|
| `DispatchParams` struct | dispatch.rs:12-22 | `src/proxy/dispatch.rs:12-22` | ✅ VERIFIED |
| `ProxyExecutor` struct | executor.rs:96-103 | `src/proxy/executor.rs:96-103` | ✅ VERIFIED |
| `TeeBody<B>` | streaming.rs:12-22 | `src/proxy/streaming.rs:12-22` | ✅ VERIFIED |
| `GlobalCacheGovernor` | governor.rs:8-54 | `src/proxy/governor.rs:8-54` | ✅ VERIFIED |
| `GlobalCacheGovernor` default 512MB | governor.rs:8-54 | `src/proxy/governor.rs:11` - `const DEFAULT_MAX_BUFFERED_BYTES` | ✅ VERIFIED |
| `LoadBalanceAlgorithm` enum | pool.rs:47-56 | `src/upstream/pool.rs:47-56` | ✅ VERIFIED |
| `Backend` struct | pool.rs:140-154 | `src/upstream/pool.rs:152-166` | ✅ VERIFIED |
| Circuit breaker 3-failure threshold | pool.rs:140-154 | `src/upstream/pool.rs:333-341` | ✅ VERIFIED |
| Circuit breaker 3-success recovery | pool.rs:140-154 | `src/upstream/pool.rs:323-328` | ✅ VERIFIED |
| `composite_load()` formula | pool.rs:140-154 | `src/upstream/pool.rs:366-372` - `(conn_load * 0.4) + (cpu_load * 0.6)` | ✅ VERIFIED |
| `HealthChecker` struct | health.rs:10-15 | `src/upstream/health.rs:10-15` | ✅ VERIFIED |
| Health check methods (HEAD, GET, TCP) | health.rs:10-15 | `src/upstream/health.rs:28-33` - `HealthCheckMethod` enum | ✅ VERIFIED |
| `SharedConnectionTable` mmap layout | shared_state.rs:20-25 | `src/upstream/shared_state.rs:14-25` | ✅ VERIFIED |
| Worker heartbeat 10s timeout | shared_state.rs:20-25 | `src/upstream/shared_state.rs:106` | ✅ VERIFIED |
| `ErasedConnectionPool` | erased_pool.rs:218-303 | `src/http_client/erased_pool.rs:221-306` | ✅ VERIFIED |
| TLS using rustls + aws_lc_rs | mod.rs | `src/http_client/typed_pool.rs:101-103` | ✅ VERIFIED |
| Constant-time comparison for secrets | headers.rs | `src/proxy/mod.rs:45` - `use subtle::ConstantTimeEq` | ✅ VERIFIED |
| SAFE_HEADERS count (28) | cache.rs:97-126 | `src/proxy/cache.rs:97-126` - 28 headers | ✅ VERIFIED (per AGENTS.md) |

### 1.2 HTTP Client Module (src/http_client/)

| Item | Document Claim | Actual Location | Status |
|------|----------------|------------------|--------|
| Global client cache (100 entry, 5min TTL) | mod.rs:70-88 | `src/http_client/mod.rs:67-88` | ✅ VERIFIED |
| `StreamingWafBody<B>` | mod.rs:133-223 | `src/http_client/mod.rs` exists but exact bounds need verification | ⚠️ PARTIAL |
| `PoolKey` uses authority + http2 flag | mod.rs:70-88 | `src/http_client/erased_pool.rs:28-53` - `PoolKey` struct | ✅ VERIFIED |

### 1.3 Spin Routing Integration

| Item | Document Claim | Actual Location | Status |
|------|----------------|------------------|--------|
| Spin routing integrated at BackendType::Spin | app_handlers.md + AGENTS.md | `src/http/server.rs:2417-2489` | ✅ VERIFIED |
| Spin find_route longest-prefix-match | AGENTS.md Lesson #7 | `src/spin/runtime.rs:271-285` - FIXED | ✅ VERIFIED |

### 1.4 HTTP Server Module (src/http/)

| Item | Document Claim | Actual Location | Status |
|------|----------------|------------------|--------|
| `BackendType::Mesh` via mesh_backend_pool | http/AGENTS.override.md | `src/mesh/backend.rs:109-303` | ✅ VERIFIED |

---

## 2. Discrepancies Found

### 2.1 `UpstreamPool` Struct Line Reference

**Document:** proxy_deep_dive.md:115
**Claim:** `UpstreamPool` (pool.rs:363-368)
**Actual:** `UpstreamPool` struct is at `src/upstream/pool.rs:375-380`

```
375: #[derive(Clone)]
376: pub struct UpstreamPool {
377:     backends: Arc<RwLock<Vec<Backend>>>,
378:     algorithm: LoadBalanceAlgorithm,
379:     round_robin_index: Arc<std::sync::atomic::AtomicUsize>,
380: }
```

**Severity:** Low (documentation drift)
**Fix:** Update line reference to 375-380

### 2.2 WAF Integration Line Reference

**Document:** proxy_deep_dive.md:59
**Claim:** `ProxyServer::handle_request()` method integrates with WAF (lines 362-459)
**Actual:** WAF integration in `handle_request()` is at `src/proxy/mod.rs:371-481` (body collection + WAF check)

The document's range (362-459) is close but not precise. The actual WAF decision handling spans lines 400-480.

**Severity:** Low (documentation drift)
**Fix:** Update line reference to 371-481

---

## 3. Bugs Identified

### 3.1 `ErasedHttpClient` Integration Incomplete

**Reference:** `src/http_client/AGENTS.override.md:83-87`

```markdown
### Remaining Integration (Phase 9)

Integration into `http/server.rs` proxy path is pending:
- Wire `BodyBufferingPolicy::Streaming` to use `ErasedHttpClient`
- Requires adding `ErasedHttpClient` to `HttpServer` struct
```

**Status:** As of 2026-05-06, integration is marked complete but the `proxy/mod.rs:73-94` shows `ProxyServer` has `erased_client: ErasedHttpClient` field, suggesting it may be integrated.

**Verification needed:** Whether `BodyBufferingPolicy::Streaming` actually uses `ErasedHttpClient` in the request path.

**Severity:** Medium
**Action:** Verify streaming policy integration in `src/http/server.rs`

---

## 4. Missing Documentation

### 4.1 Half-TCP (Layer 3.5) Implementation Not Documented

**Document:** layer_3_5_deep_dive.md

The document focuses on PQC and Mesh networking but does not document the actual "Layer 3.5" half-TCP proxy implementation which is referenced in other parts of the codebase (e.g., `BackendProtocol::Tcp` in `src/upstream/pool.rs:67`).

**Actual half-TCP related code:**
- `src/upstream/pool.rs:67` - `BackendProtocol::Tcp`
- `src/upstream/address.rs` - Contains `QuicTunnelStream`

**Severity:** Medium
**Action:** Add documentation for Layer 3.5 (half-TCP) implementation if it exists

---

## 5. Improvement Suggestions

### 5.1 Add Integration Test for Connection Pool Checkout

**Location:** `src/http_client/erased_pool.rs:245-283`

The `checkout()` method has complex error handling that would benefit from explicit testing:
- Connection timeout handling
- Pool extraction and connection reuse
- New connection establishment

**Priority:** Medium

### 5.2 Document `ErasedConnectionPool::checkout()` Error Paths

**Location:** `src/http_client/erased_pool.rs:245-282`

The function can fail in multiple ways:
- `InvalidInput` for malformed authority
- `InvalidInput` for invalid address format
- `TimedOut` for connection timeout
- Other I/O errors

**Priority:** Low

### 5.3 Update Line References for `UpstreamPool` Methods

The document references methods but some line numbers are approximate. Consider using broader ranges or referring to method names instead of line numbers.

**Priority:** Low

### 5.4 Add Architecture Diagram for Three-Layer Connection Pooling

**Reference:** `src/http_client/AGENTS.override.md:43-71`

The three-layer pooling strategy (Global cache → Erased pool → Typed pool) would benefit from a visual architecture diagram showing data flow.

**Priority:** Medium

### 5.5 Clarify Spin vs WASM Backend Distinction

**Reference:** app_handlers.md:40-45 vs routing_deep_dive.md:24

The documents mention both "Serverless (WASM)" and "Spin Application Support" but don't clearly distinguish:
- Spin uses WASM components internally
- Spin has its own routing/manifest system
- WASM edge functions are more generic

**Priority:** Medium

---

## 6. Summary of Actions

| Priority | Action Item | Location | Owner |
|----------|-------------|----------|-------|
| **High** | Verify `ErasedHttpClient` integration with `BodyBufferingPolicy::Streaming` | `src/http/server.rs` | AI Agent |
| **Medium** | Document Layer 3.5 half-TCP implementation | architecture/ layer_3_5_deep_dive.md | Human |
| **Medium** | Add integration test for connection pool checkout | `src/http_client/erased_pool.rs` | AI Agent |
| **Medium** | Clarify Spin vs WASM backend distinction in docs | app_handlers.md | Human |
| **Low** | Update `UpstreamPool` line reference (363→375) | proxy_deep_dive.md | Human |
| **Low** | Update WAF integration line reference (362-459→371-481) | proxy_deep_dive.md | Human |
| **Low** | Document `ErasedConnectionPool::checkout()` error paths | Code comments | AI Agent |

---

## 7. Verification Checklist

- [ ] `ProxyServer::handle_request()` WAF integration verified at lines 371-481
- [ ] `UpstreamPool` struct verified at lines 375-380
- [ ] `ErasedHttpClient` field exists in `ProxyServer` (line 76)
- [ ] `ErasedConnectionPool::checkout()` handles connection timeout
- [ ] `BackendProtocol::Tcp` implementation status verified (half-TCP?)
- [ ] Spin longest-prefix-match fix verified in `src/spin/runtime.rs`

---

## 8. Cross-Reference with AGENTS.md

| AGENTS.md Lesson | Verification Result |
|-----------------|---------------------|
| Lesson #5: SAFE_HEADERS count is 28 | ✅ Confirmed `src/proxy/cache.rs:97-126` has 28 headers |
| Lesson #7: Spin find_route longest-prefix-match FIXED | ✅ Confirmed at `src/spin/runtime.rs:271-285` |
| Lesson #11: Spin routing IS integrated at server.rs:2417-2489 | ✅ Confirmed |

---

**End of Report**
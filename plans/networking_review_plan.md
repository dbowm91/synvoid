# Networking Architecture Review

## Verified Correct Items

| Item | Documentation | Actual |
|------|---------------|--------|
| ALPN HTTP/2 detection | `tls/server.rs:410-411` | ✅ `ALPN_HTTP2` constant at line 54, `is_http2` at line 411 |
| QUIC MAX_DATAGRAM_PAYLOAD | `src/tunnel/quic/messages.rs:4` | ✅ `const MAX_DATAGRAM_PAYLOAD: usize = 1200;` |
| TCP listener | `src/tcp/listener.rs` | ✅ File exists, 869 lines |
| Listener config | `src/listener/common.rs` | ✅ Defines `ListenerConfigBase`, `ListenerInstance`, `ConnectionContext`, `SocketOptionsBase` |
| AcmeDnsChallenge struct | `src/tls/acme_dns.rs:11-64` | ✅ Struct at lines 11-14, methods 17-63 |
| ACME DNS response builder | `src/dns/server/response.rs:782` | ✅ `build_acme_txt_response()` exists |
| ACME DNS query handling | `src/dns/server/query.rs:679-698` | ✅ Lines 699-720 handle `_acme-challenge.` queries |
| BufferPool location | `crates/synvoid-utils/src/buffer/pool.rs` | ✅ File exists, 1203 lines |
| SiteConnectionLimiter | `src/waf/traffic_shaper/limiter.rs:306-346` | ✅ Struct defined, confirmed dead code per AGENTS.md |

---

## Discrepancies Found

### D1: HTTP/2 Detection Reference (Low - Documentation Accuracy)
**Documentation says:** `src/http_client/mod.rs:893` with `is_http2 = true`

**Actual:** Line 893 in `src/http_client/mod.rs` is:
```rust
client.send_request(req, authority, is_http2, Some(t)).await
```
This is where `is_http2` is **used**, not where it's set. The actual HTTP/2 detection occurs at `src/tls/server.rs:411` via ALPN negotiation.

**Fix:** Update documentation to reference `src/tls/server.rs:411` for ALPN detection and `src/http_client/mod.rs:893` only for the usage.

### D2: HTTP/2 Pooling Status Understated (Medium - Documentation Accuracy)
**Documentation says:** "HTTP/2 pooled connections are not fully available in current implementation" and "infrastructure is in place but not wired"

**Actual:** The `Http2PooledConnection` is an **empty stub** at `src/http_client/erased_pool.rs:125-127`:
```rust
pub struct Http2PooledConnection {
    authority: http::uri::Authority,
}
```
Its `is_available()` returns `false` (line 204-206), and `PooledConnection` impl has no actual connection fields. This is classified as DEFERRED in `plans/plan.md` with status "hyper-util API incompatible".

**Impact:** Documentation implies partial functionality; reality is zero functionality for HTTP/2 pooling.

---

## Bugs Identified

### B1: HTTP/2 Connection Pooling Completely Non-Functional
- **Severity:** P2 (Performance)
- **Location:** `src/http_client/erased_pool.rs:125-127`
- **Issue:** `Http2PooledConnection` is an empty stub with only `authority` field. No actual HTTP/2 connection, sender, or IO fields exist.
- **Impact:** HTTP/2 upstream pooling cannot be implemented until this struct is properly implemented
- **Status:** Known - documented in `plans/plan.md` as DEFERRED (HTTP2-POOL item)

### B2: SiteConnectionLimiter Dead Code
- **Severity:** P3 (Code Quality)
- **Location:** `src/waf/traffic_shaper/limiter.rs:306-346`
- **Issue:** Struct is never instantiated anywhere in the codebase. Per-site limiting is achieved via global limiter's `try_acquire_with_limits()`.
- **Impact:** Unused code, potential maintenance burden
- **Status:** Known - documented in AGENTS.md and `plans/plan.md` (NR-1/WR-4)

---

## Suggested Improvements

### I1: Update Documentation for HTTP/2 Detection
Change line 10-11 from:
```
- **HTTP/2:** Infrastructure exists (see `src/http_client/mod.rs:893` with `is_http2 = true`)
```
To:
```
- **HTTP/2:** HTTP/2 detection occurs via ALPN during TLS handshake (`src/tls/server.rs:411`).
  The `is_http2` flag is passed to `send_request()` at `src/http_client/mod.rs:893`.
```

### I2: Clarify HTTP/2 Pooling Status
Change line 10 description from:
```
"HTTP/2 pooled connections are not fully available in current implementation"
```
To:
```
"HTTP/2 pooled connections are not implemented - Http2PooledConnection is a stub.
 See plans/plan.md HTTP2-POOL items for implementation requirements."
```

### I3: Add Reference to Plan Items
Add a note referencing the deferred HTTP2-POOL items from `plans/plan.md` for readers who want to understand the implementation requirements.

---

## Summary

- **Verified:** 9 of 9 checked items are correct
- **Discrepancies:** 2 (documentation accuracy issues)
- **Known Bugs:** 2 (both documented, one P2, one P3)
- **Improvements:** 3 documentation refinements

The documentation is generally accurate. The main issue is that HTTP/2 pooling status is understated - it should clearly indicate the feature is non-functional stub, not "not fully available."
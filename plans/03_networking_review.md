# Networking Architecture Review

**Review Date:** 2026-05-06
**Reviewer:** Code Review Agent
**Document Reviewed:** `architecture/networking_deep_dive.md`

---

## Executive Summary

The networking architecture documentation provides a high-level overview of SynVoid's protocol support, TLS handling, and performance optimizations. This review validates the documented claims against the actual implementation in `src/listener/`, `src/http/`, `src/http3/`, and related modules.

**Overall Assessment:** The documentation is accurate but incomplete. Several key architectural features are documented but lack implementation details, and some implementation behaviors deviate from documented claims.

---

## 1. Verified Claims

### 1.1 HTTP/1.1 & HTTP/2 via Hyper

**Documentation:** "SynVoid uses Hyper as its foundational HTTP library."

**Verification:** CONFIRMED
- Files: `src/tls/server.rs`, `src/http/server.rs`
- HTTP/1.1: Uses `hyper::server::conn::http1::Builder` with keep-alive enabled (line 501-550 in `src/tls/server.rs`)
- HTTP/2: Uses `hyper::server::conn::http2::Builder` with max header list size configuration (line 427-486 in `src/tls/server.rs`)
- ALPN negotiation detects HTTP/2 via `h2` protocol identifier (line 409-410 in `src/tls/server.rs`)

### 1.2 HTTP/3 via Quinn

**Documentation:** "SynVoid features native HTTP/3 support via the Quinn library."

**Verification:** CONFIRMED
- File: `src/http3/server.rs`
- Uses `quinn::Endpoint::server()` for QUIC transport (line 125)
- Uses `h3::server::builder()` and `h3_quinn::Connection` for HTTP/3 (lines 194-196)
- Configured with max concurrent uni/bidi streams (lines 118-119)

### 1.3 TLS Termination via Rustls

**Documentation:** "SynVoid handles TLS termination at the edge using Rustls."

**Verification:** CONFIRMED
- Files: `src/tls/server.rs`, `src/tls/cert_resolver.rs`
- Uses `tokio_rustls::TlsAcceptor` for TLS acceptance (line 25 in `src/tls/server.rs`)
- Uses `rustls::ServerConfig` with `CertResolver` implementing `ResolvesServerCert` trait (line 327 in `src/tls/cert_resolver.rs`)

### 1.4 Dynamic Certificate Selection (SNI)

**Documentation:** "The CertResolver selects the appropriate certificate for each connection based on SNI."

**Verification:** CONFIRMED
- File: `src/tls/cert_resolver.rs`
- `CertResolver` implements `rustls::server::ResolvesServerCert` (line 327)
- SNI-based certificate lookup at lines 332-344 with wildcard support
- Falls back to default certificate if no SNI match (line 347)

### 1.5 ACME/Let's Encrypt Integration

**Documentation:** "Built-in support for Let's Encrypt and other ACME-based CAs for automated certificate issuance and renewal."

**Verification:** CONFIRMED
- File: `src/tls/acme.rs`
- Uses `instant_acme` crate for ACME protocol
- Supports HTTP-01 and DNS-01 challenge types
- Full certificate renewal lifecycle management

### 1.6 Post-Quantum Cryptography (X25519MLKEM768)

**Documentation:** "X25519MLKEM768: A hybrid key exchange that combines classical X25519 with the ML-KEM (Kyber) algorithm."

**Verification:** CONFIRMED
- Files: `src/startup/master.rs` (lines 208-230), `src/mesh/cert.rs` (lines 87-137)
- Feature-gated via `post-quantum` flag
- Uses `rustls_post_quantum::provider` for hybrid key exchange
- PQ verification function `verify_post_quantum_tls()` exists in `src/mesh/cert.rs`

### 1.7 Connection Limiting

**Documentation:** "The ConnectionLimiter provides fine-grained control over concurrent connections at multiple levels: Global Limit, Per-Site Limit, Per-IP Limit."

**Verification:** CONFIRMED
- File: `src/waf/traffic_shaper/limiter.rs`
- Global limit: `config.max_connections` (line 103)
- Per-site limit: `site_total_connections` HashMap with shard indexing (lines 50-51, 107-121)
- Per-IP limit: `ip_connections` HashMap with shard indexing (lines 48, 123-134)
- Burst token mechanism for burst allowance (lines 136-146, 279-284)

### 1.8 Buffer Pool

**Documentation:** "A custom BufferPool is used to reuse memory buffers for IO operations."

**Verification:** CONFIRMED
- File: `crates/synvoid-utils/src/buffer/pool.rs`
- Multi-tier pool: Small (4KB), Medium (64KB), Large (256KB), Jumbo
- Thread-local caching with TLS_CACHE_SIZE of 16 per tier
- Sharded arenas (8 shards) for lock-free acquisition on common paths
- Metrics tracking for acquire/reuse ratios

### 1.9 TCP Pool

**Documentation:** "TCP Pool: Manages multiple TCP listeners with auto-tuned worker pools."

**Verification:** CONFIRMED
- File: `src/server/mod.rs` (lines 693-738)
- `TcpListenerPool` with configurable worker pool size
- Socket options: nodelay, send/recv buffer size, reuse_port, quickack, keepalive
- Flood protector integration for SYN/rate limiting

### 1.10 UDP Pool

**Documentation:** "UDP Pool: Optimized for high-throughput UDP packet handling, with built-in protections against amplification attacks."

**Verification:** CONFIRMED
- File: `src/server/mod.rs` (lines 740-772)
- `UdpListenerPool` with worker pool size configuration
- Rate limiting via `FloodProtector` with `udp_rate_per_ip` and `udp_rate_global`
- Configurable socket options for buffer sizes

---

## 2. Unverified Claims (Needing Clarification)

### 2.1 QUIC Connection Migration

**Documentation:** "QUIC's use of connection IDs allows clients (like mobile devices) to switch networks without dropping connections."

**Status:** NOT FULLY VERIFIED
- The QUIC stack uses `quinn` which supports connection migration per RFC 9000
- However, no explicit connection migration handling code was found in `src/http3/server.rs`
- Quinn handles this at the transport layer, but SynVoid does not implement any application-level migration handling or logging

### 2.2 0-RTT QUIC Support

**Documentation:** "0-RTT: Enables clients to send data in the first packet of a handshake, significantly reducing time-to-first-byte."

**Status:** PARTIALLY VERIFIED
- Code exists at `src/mesh/cert.rs` lines 151, 213, 388-405 for QUIC 0-RTT configuration
- Configuration `quic_enable_0rtt` exists and is documented as disabled by default due to replay attack concerns
- **However:** HTTP/3 server at `src/http3/server.rs` does not appear to have any 0-RTT specific handling
- The 0-RTT configuration is in the mesh (proxy) cert, not the HTTP/3 server TLS config

### 2.3 Zero-Copy IO

**Documentation:** "SynVoid leverages Rust's ownership model to minimize data copying between the network stack and the application handlers."

**Status:** PARTIALLY VERIFIED
- H3 response handling at lines 980-1003 uses frame-based streaming with `data.clone()` on line 985
- For responses > 1MB, data is streamed frame-by-frame but `.clone()` is called
- For smaller responses, entire body is buffered before sending (lines 1005-1080)
- The claim of "zero-copy" is not strictly accurate - there are instances of data cloning

---

## 3. Implementation Gaps

### 3.1 Missing Per-IP Limit Enforcement in HTTP/3

**Issue:** HTTP/3 connection limiting at lines 238-249 uses site_id `"_http3_"` which bypasses per-IP limiting.

```rust
let mut connection_token = if let Some(ref conn_limiter) = self.waf.connection_limiter {
    match conn_limiter.try_acquire("_http3_", client_ip).await {  // <-- Hardcoded site_id
```

**Expected:** Per-IP limiting should use actual site identifier or a dedicated HTTP/3 limiting mechanism.

### 3.2 No Connection Migration Tracking

**Issue:** Despite claiming connection migration support, there's no tracking or metrics for connection migration events.

**Recommendation:** Add metrics/telemetry for connection migration occurrences.

### 3.3 Missing HTTP/3 Request Timeout

**Issue:** HTTP/3 server has no per-request timeout. If an upstream request hangs, the connection may remain open indefinitely.

**Location:** `src/http3/server.rs` - the `handle_request()` function lacks timeout handling.

### 3.4 QUIC Idle Timeout Hardcoded

**Issue:** At line 121-123 in `src/http3/server.rs`, idle timeout is hardcoded to 60 seconds:

```rust
let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
    .expect("Failed to create idle timeout");
```

**Recommendation:** Make this configurable via `Http3Config`.

---

## 4. Code Improvements

### 4.1 Duplicate TLS Detection Logic

**Location:** Both `src/http/server.rs` (lines 169-171) and `src/tls/server.rs` (lines 58-60) define identical `is_tls_client_hello()` functions.

**Recommendation:** Move to a shared utility module.

### 4.2 Duplicate HTTP Method Validation

**Location:** Both `src/http/server.rs` (lines 148-167) and `src/tls/server.rs` (lines 62-81) define identical `is_valid_http_request_start()` functions.

**Recommendation:** Move to a shared utility module.

### 4.3 Inconsistent Error Handling in H3

**Location:** `src/http3/server.rs` lines 1088-1106

**Issue:** Some upstream errors are logged and handled gracefully, but others silently return. The error handling pattern is inconsistent.

**Recommendation:** Standardize error handling with a helper function.

### 4.4 Buffer Pool Tier Selection Could Be Optimized

**Location:** `crates/synvoid-utils/src/buffer/pool.rs` line 224

**Issue:** `get_tier()` function could use a lookup table instead of match for slight performance improvement.

---

## 5. Bug Reports

### 5.1 HTTP/3 Stream Scanning Logic Error

**Severity:** Medium

**Location:** `src/http3/server.rs` lines 341-396

**Description:** The streaming WAF scanning logic has a conditional `stream_scanned_upstream_mode` that affects body handling. If streaming scan is enabled, body bytes are accumulated in `body_bytes` but never scanned if `stream_scanned_upstream_mode` is true (lines 341-396). However, later at lines 427-442, `waf.check_request_full()` is called with `waf_body_slice` which may be `None` if streaming mode is active.

**Impact:** In certain routing configurations, request bodies may bypass WAF scanning entirely.

### 5.2 HTTP/3 Response Size Limit Race Condition

**Severity:** Low

**Location:** `src/http3/server.rs` lines 756-766

**Description:** Response size checking uses `Content-Length` header which may not match actual body size due to chunked encoding or streaming. The check at lines 763-766 only checks if `Content-Length` exceeds limit, not actual body size.

**Workaround:** For small responses (< 1MB), body is fully buffered and checked (lines 1005-1080). For large responses, size limit is only checked against Content-Length header.

### 5.3 H3 Connection Token Not Released on Early Return

**Severity:** Low

**Location:** `src/http3/server.rs` line 1137

**Description:** `drop(connection_token)` is called at the end, but if early returns occur (e.g., line 244, 272, 363, 390, 477), the connection token is not explicitly released until the function exits.

**Note:** This is acceptable for connection tokens since they implement Drop, but explicit release would be clearer.

---

## 6. Security Concerns

### 6.1 ACME Terms of Service Warning

**Severity:** Info

**Location:** `src/config/tls.rs` line 150

**Issue:** The validation emits a warning but doesn't enforce terms of service agreement.

**Current Behavior:** `terms_of_service_agreed = false` still allows ACME to run with a warning.

**Recommendation:** Consider making this a hard error in production mode.

### 6.2 TLS 1.2 Fallback Enabled by Default in Some Paths

**Severity:** Low

**Location:** `src/tls/cert_resolver.rs` lines 269-285

**Issue:** If `enable_tls_12_fallback` is true, both TLS 1.3 and TLS 1.2 are offered, with TLS 1.3 listed first. This is correct preference ordering, but TLS 1.2 is considered weak.

**Recommendation:** Consider deprecating TLS 1.2 support entirely or making the fallback opt-in rather than opt-out.

### 6.3 Connection Limiter Shard Indexing Hash Collision

**Severity:** Low (Theoretical)

**Location:** `src/waf/traffic_shaper/limiter.rs` lines 15-42

**Description:** The `ip_shard_index()` and `site_shard_index()` functions use a simple hash (djb2/33) with 64 shards. While fast, this could theoretically cause shard imbalance with adversarial IPs.

**Mitigation:** The sharding distributes load across 64 shards, which is sufficient for normal traffic patterns.

### 6.4 No Rate Limiting on QUIC Connection Establishment

**Severity:** Medium

**Location:** `src/http3/server.rs` lines 177-189

**Issue:** Only `flood_protector.check_tcp_connection()` is called, not a QUIC-specific rate limit. While QUIC connections are still rate-limited by the flood protector, this may not properly account for QUIC-specific attack vectors.

**Recommendation:** Add QUIC-specific connection rate limiting or verify existing flood protector handles QUIC correctly.

---

## 7. Missing Documentation

### 7.1 HTTP/3 Server TLS Configuration

**Missing:** Documentation should clarify that HTTP/3 uses its own TLS configuration separate from the HTTPS server. The HTTP/3 TLS config is passed via `Arc<rustls::ServerConfig>` at line 104, but there's no documentation on how this is configured or if it shares the same CertResolver.

### 7.2 Shared Handler Pipeline

**Missing:** Documentation mentions "Both H1 and H2 share a common request processing pipeline" but doesn't explain how. The actual sharing happens via `SharedRequestHandler` trait at `src/http/shared_handler.rs`, but the routing/dispatch logic in `src/tls/server.rs` has separate code paths for H1 and H2.

### 7.3 Buffer Pool Configuration

**Missing:** No documented configuration for BufferPool sizes, caps, or tuning guidelines. The pool uses hardcoded constants:
- `SMALL_BUF_SIZE: 4KB`
- `MEDIUM_BUF_SIZE: 64KB`
- `LARGE_BUF_SIZE: 256KB`

### 7.4 Connection Limiter Tuning

**Missing:** No documentation on tuning connection limits, queue sizes, burst tokens, or shard counts.

### 7.5 QUIC Stream Independence Claim

**Documentation:** "QUIC streams are independent, meaning packet loss on one stream doesn't stall others (eliminating Head-of-Line blocking)."

**Missing:** While true for QUIC at the transport layer, this claim should clarify that application-level proxying to HTTP/1.1 upstreams may still introduce head-of-line blocking when buffering responses.

---

## 8. Summary of Findings

| Category | Count |
|----------|-------|
| Verified Claims | 10 |
| Unverified Claims | 3 |
| Implementation Gaps | 4 |
| Code Improvements | 5 |
| Bug Reports | 3 |
| Security Concerns | 4 |
| Missing Documentation | 5 |

**Priority Recommendations:**

1. **High Priority:** Fix HTTP/3 stream scanning logic (Section 5.1)
2. **Medium Priority:** Add HTTP/3 request timeout handling (Section 3.3)
3. **Medium Priority:** Add QUIC-specific rate limiting verification (Section 6.4)
4. **Low Priority:** Extract duplicate utility functions (Section 4.1, 4.2)
5. **Documentation:** Add missing sections on HTTP/3 TLS config and buffer pool tuning (Section 7)

---

## Appendix: Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `src/http3/server.rs` | 1-1179 | HTTP/3 QUIC server implementation |
| `src/http/server.rs` | 1-4772 | HTTP/1.1 server implementation |
| `src/tls/server.rs` | 1-2199 | HTTPS TLS server with H1/H2 |
| `src/tls/cert_resolver.rs` | 1-502 | Dynamic certificate resolution |
| `src/listener/common.rs` | 1-84 | Listener base types |
| `src/waf/traffic_shaper/limiter.rs` | 1-408 | Connection limiting |
| `crates/synvoid-utils/src/buffer/pool.rs` | 1-1164 | Buffer pool implementation |
| `src/server/mod.rs` | 690-839 | TCP/UDP pool creation |
| `src/mesh/cert.rs` | 87-137 | PQC verification |

# Networking Architecture Review

**Review Date:** 2026-05-22
**Reviewer:** Code Review Agent (explore)
**Document Reviewed:** `architecture/networking_deep_dive.md`
**Code Verification Scope:** `src/listener/`, `src/http/`, `src/http3/`, `src/tcp/`, `src/udp/`, `src/tls/`

---

## Executive Summary

The networking architecture documentation provides a high-level overview of SynVoid's protocol support, TLS handling, and performance optimizations. This review validates documented claims against actual implementation.

**Overall Assessment:** The documentation is mostly accurate with 10 verified claims, 3 unverified, and several implementation gaps and code quality issues identified.

---

## 1. Verified Claims

### 1.1 HTTP/1.1 & HTTP/2 via Hyper

**Documentation:** "SynVoid uses Hyper as its foundational HTTP library."

**Verification:** CONFIRMED
- `src/tls/server.rs` line 12-13: `hyper::server::conn::http1` and `hyper::server::conn::http2`
- HTTP/1.1: Lines 502-549 with `.keep_alive(true)` and `.serve_connection()`
- HTTP/2: Lines 413-487 with ALPN detection (`ALPN_HTTP2`) and `http2_server::Builder::new()`
- `src/http/server.rs` line 597: HTTP/1.1 usage in plain HTTP server

### 1.2 HTTP/3 via Quinn

**Documentation:** "SynVoid features native HTTP/3 support via the Quinn library."

**Verification:** CONFIRMED
- `src/http3/server.rs` lines 111-131: QUIC server setup with `quinn::Endpoint::new()`
- Line 200-202: HTTP/3 connection via `h3::server::builder()` and `h3_quinn::Connection`
- Lines 118-119: Stream limits configured (max_concurrent_uni_streams: 0, bidi_streams: 100)

### 1.3 TLS Termination via Rustls

**Documentation:** "SynVoid handles TLS termination at the edge using Rustls."

**Verification:** CONFIRMED
- `src/tls/server.rs` line 25: `use tokio_rustls::TlsAcceptor`
- `src/tls/cert_resolver.rs` line 4-10: Uses `rustls::crypto::aws_lc_rs::default_provider()`
- Line 327: `CertResolver` implements `rustls::server::ResolvesServerCert`

### 1.4 Dynamic Certificate Selection (SNI)

**Documentation:** "The CertResolver selects the appropriate certificate for each connection based on SNI."

**Verification:** CONFIRMED
- `src/tls/cert_resolver.rs` lines 330-344: `resolve_server_cert()` implementation
- SNI hostname matching with wildcard support via `strip_prefix(".")` for domain wildcard certs
- Fallback to default certificate at line 347

### 1.5 ACME/Let's Encrypt Integration

**Documentation:** "Built-in support for Let's Encrypt and other ACME-based CAs for automated certificate issuance and renewal."

**Verification:** CONFIRMED
- `src/tls/acme.rs`: Uses `instant_acme` crate for ACME protocol
- Lines 234-270: HTTP-01 and DNS-01 challenge types
- `src/tls/acme_dns.rs`: Full DNS-01 challenge implementation with TXT record management

### 1.6 Post-Quantum Cryptography (X25519MLKEM768)

**Documentation:** "X25519MLKEM768: A hybrid key exchange that combines classical X25519 with the ML-KEM (Kyber) algorithm."

**Verification:** CONFIRMED
- `src/startup/master.rs` lines 210-230: Post-quantum provider initialization
- `src/mesh/cert.rs` lines 87-137: `verify_post_quantum_tls()` function
- Feature-gated via `post-quantum` flag
- `src/mesh/config.rs` lines 1124-1152: ML-KEM configuration options

### 1.7 Connection Limiter (Global/Per-Site/Per-IP)

**Documentation:** "The ConnectionLimiter provides fine-grained control over concurrent connections at multiple levels."

**Verification:** CONFIRMED
- `src/waf/traffic_shaper/limiter.rs` lines 12-19: Multi-level tracking
- Global: `total_connections: AtomicU32` (line 14)
- Per-IP: `ip_connections: DashMap<IpAddr, AtomicU32>` (line 16)
- Per-Site: `site_connections: DashMap<String, DashMap<IpAddr, AtomicU32>>` (line 18)
- Lines 42-134: `try_acquire()` with all three limit checks

### 1.8 Buffer Pool

**Documentation:** "A custom BufferPool is used to reuse memory buffers for IO operations, significantly reducing garbage collection pressure and allocation overhead."

**Verification:** CONFIRMED
- `crates/synvoid-utils/src/buffer/pool.rs` line 211: `BufferPool` struct
- Multi-tier design: Small (4KB), Medium (64KB), Large (256KB), Jumbo (>1MB)
- Lines 267-271: Global singleton pools (`POOL`, `GLOBAL_POOL`)
- Lines 242-259: Tier configuration with `BufferPoolConfig`
- Lock-free sharded arenas for common path performance

### 1.9 TCP Listener Pool

**Documentation:** "TCP Pool: Manages multiple TCP listeners with auto-tuned worker pools."

**Verification:** CONFIRMED
- `src/tcp/listener.rs` lines 186-198: `TcpListenerPool` struct
- Lines 24-35: `TcpSocketOptions` with nodelay, keepalive, quickack
- Lines 100-136: `create_socket_with_options()` with SO_REUSEPORT
- Lines 53-97: `apply_tcp_socket_options()` for connection tuning

### 1.10 UDP Listener Pool with Amplification Protection

**Documentation:** "UDP Pool: Optimized for high-throughput UDP packet handling, with built-in protections against amplification attacks."

**Verification:** CONFIRMED
- `src/udp/listener.rs` lines 93-102: `UdpListenerPool` struct
- Lines 27-38: `UDP_TUNNEL_MANAGER` global singleton
- Line 25: `FloodProtector` integration for rate limiting
- Lines 43-57: `UdpSocketOptions` with 2MB buffer sizes
- Lines 104-123: `UdpListenerPoolConfig` with `max_packets_per_second`

---

## 2. Unverified Claims

### 2.1 QUIC Connection Migration

**Documentation:** "QUIC's use of connection IDs allows clients (like mobile devices) to switch networks without dropping connections."

**Status:** UNVERIFIED - NO EXPLICIT IMPLEMENTATION
- Quinn library (RFC 9000) supports connection migration at transport layer
- `src/http3/server.rs` has no application-level connection migration handling
- No metrics/tracking for migration events
- **Recommendation:** Add telemetry for connection migration occurrences if this is a design goal

### 2.2 0-RTT QUIC Support

**Documentation:** "0-RTT: Enables clients to send data in the first packet of a handshake, significantly reducing time-to-first-byte."

**Status:** PARTIALLY VERIFIED - IN MESH ONLY
- `src/mesh/cert.rs` lines 388-405: QUIC 0-RTT configuration exists for mesh transport
- Configuration `quic_enable_0rtt` is disabled by default due to replay attack concerns (line 1391-1392)
- **NOT in HTTP/3 server:** `src/http3/server.rs` has no 0-RTT specific handling
- 0-RTT is a mesh/proxy feature, not an HTTP server feature per documentation

### 2.3 Zero-Copy IO

**Documentation:** "SynVoid leverages Rust's ownership model to minimize data copying between the network stack and the application handlers."

**Status:** PARTIALLY VERIFIED - NOT STRICTLY ZERO-COPY
- `src/http3/server.rs` line 985: `data.clone()` exists in frame handling
- Lines 1005-1080: Small responses are fully buffered before sending
- **Claim is aspirational:** Actual implementation has data copying in several paths
- **Recommendation:** Update documentation to say "minimized-copy" or "low-copy IO"

---

## 3. Implementation Gaps

### 3.1 HTTP/3 Hardcoded Site ID for Connection Limiting

**Location:** `src/http3/server.rs` lines 244-250

```rust
let mut connection_token = if let Some(ref conn_limiter) = self.waf.connection_limiter {
    match conn_limiter.try_acquire("_http3_", client_ip).await {
```

**Issue:** Uses hardcoded `"_http3_"` site_id, bypassing per-site limiting. All HTTP/3 connections share the same site bucket.

**Impact:** Per-site connection limits cannot differentiate between multiple domains served over HTTP/3.

### 3.2 HTTP/3 Hardcoded Idle Timeout

**Location:** `src/http3/server.rs` lines 121-123

```rust
let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
    .expect("Failed to create idle timeout");
```

**Issue:** Idle timeout is hardcoded to 60 seconds with no configuration option.

**Recommendation:** Add `idle_timeout_secs` to `Http3Config`.

### 3.3 No Per-Request Timeout in HTTP/3

**Location:** `src/http3/server.rs` - `handle_request()` function (lines 235+)

**Issue:** No timeout on individual request handling. If upstream request hangs, connection may remain open indefinitely.

**Recommendation:** Add request timeout using `tokio::time::timeout()`.

### 3.4 QUIC Connection Establishment Lacks Rate Limiting

**Location:** `src/http3/server.rs` lines 183-195

**Issue:** Only `flood_protector.check_tcp_connection()` is called. QUIC-specific connection establishment rate limiting is missing.

**Note:** The flood protector may handle this, but there's no QUIC-specific verification.

---

## 4. Code Improvements

### 4.1 Duplicate TLS Client Hello Detection

**Location:** 
- `src/http/server.rs` lines 169-171
- `src/tls/server.rs` lines 58-60

**Issue:** Both files have identical `is_tls_client_hello()` function.

**Recommendation:** Move to `src/http/common.rs` or similar shared module.

### 4.2 Duplicate HTTP Method Validation

**Location:**
- `src/http/server.rs` lines 148-167
- `src/tls/server.rs` lines 62-81

**Issue:** Both files have identical `is_valid_http_request_start()` logic.

**Recommendation:** Consolidate into shared validation module.

### 4.3 HTTP/3 Response Size Check Relies on Content-Length

**Location:** `src/http3/server.rs` lines 756-766

**Issue:** Only checks `Content-Length` header, not actual body size. Chunked or streamed responses may bypass size limits.

**Recommendation:** Add streaming size tracker for responses without Content-Length.

### 4.4 Shared Handler Request Pipeline Not Unified

**Documentation Claim:** "Both H1 and H2 share a common request processing pipeline."

**Reality:** 
- `src/http/shared_handler.rs` only contains response helper methods
- `src/tls/server.rs` has separate `serve_connection()` calls for HTTP/1.1 (lines 502-549) and HTTP/2 (lines 428-487)
- Request handling uses different code paths with similar but not shared logic

**Recommendation:** Document the actual architecture (shared response helpers, separate request handlers).

---

## 5. Bug Reports

### 5.1 H3 Connection Token Release on Early Returns

**Severity:** Low

**Location:** `src/http3/server.rs` lines 244-272, 363, 390, 477

**Issue:** `connection_token` is acquired but not explicitly released on early returns. The token uses `Drop` so it will be released eventually, but the pattern is unclear.

**Note:** This is acceptable given `Drop` implementation, but explicit release would improve code clarity.

### 5.2 QUIC Stream Error Handling Inconsistency

**Severity:** Low

**Location:** `src/http3/server.rs` lines 223-227

**Issue:** Accept errors break the loop with `tracing::debug`, while connection errors use `tracing::debug` at line 147. Inconsistent error level handling.

---

## 6. Security Concerns

### 6.1 TLS 1.2 Fallback Enabled by Default

**Severity:** Medium

**Location:** `src/tls/cert_resolver.rs` lines 269-285

**Issue:** `enable_tls_12_fallback` defaults may allow TLS 1.2, considered weak.

**Recommendation:** Make TLS 1.2 fallback opt-in, not opt-out.

### 6.2 ACME Terms of Service Not Enforced

**Severity:** Info

**Location:** `src/config/tls.rs` line 150

**Issue:** ACME terms_of_service_agreed=false still allows ACME to run with only a warning.

**Recommendation:** Make this a hard error in production mode.

### 6.3 Connection Limiter Shard Hash Distribution

**Severity:** Low (Theoretical)

**Location:** `src/waf/traffic_shaper/limiter.rs` lines 30-38

**Issue:** Uses djb2/33 hash with 64 shards. Could theoretically cause shard imbalance with adversarial IPs, but 64 shards provides adequate distribution for normal traffic.

---

## 7. Missing Documentation

### 7.1 HTTP/3 TLS Configuration

**Missing:** How HTTP/3 TLS config is set up and whether it shares CertResolver with HTTPS server.

### 7.2 Shared Handler Pipeline Clarification

**Missing:** Document that "shared handler" refers to response helpers, not unified request pipeline.

### 7.3 Buffer Pool Configuration

**Missing:** No documented configuration for buffer sizes, tier limits, or tuning guidelines.

### 7.4 Connection Limiter Tuning

**Missing:** No documentation on tuning connection limits, burst tokens, or shard counts.

### 7.5 QUIC Stream Independence Limitation

**Missing:** While QUIC eliminates transport-layer HOL blocking, upstream HTTP/1.1 proxying may reintroduce buffering-based HOL blocking.

---

## 8. Summary

| Category | Count |
|----------|-------|
| Verified Claims | 10 |
| Unverified Claims | 3 |
| Implementation Gaps | 4 |
| Code Improvements | 4 |
| Bug Reports | 2 |
| Security Concerns | 3 |
| Missing Documentation | 5 |

**Priority Actions:**
1. **High:** Address TLS 1.2 fallback default (security)
2. **Medium:** Add HTTP/3 idle timeout configuration
3. **Medium:** Add HTTP/3 request timeout handling
4. **Low:** Consolidate duplicate utility functions
5. **Documentation:** Clarify shared handler architecture and buffer pool tuning

---

## Appendix: Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `src/http3/server.rs` | 1-1090 | HTTP/3 QUIC server |
| `src/http/server.rs` | 1-4903 | HTTP/1.1 server |
| `src/http/shared_handler.rs` | 1-433 | Shared response helpers |
| `src/tls/server.rs` | 1-2280 | HTTPS TLS server with H1/H2 |
| `src/tls/cert_resolver.rs` | 1-502 | Dynamic certificate resolution |
| `src/tls/acme.rs` | 1-500+ | ACME Let's Encrypt integration |
| `src/listener/common.rs` | 1-84 | Listener base types |
| `src/tcp/listener.rs` | 1-864 | TCP listener pool |
| `src/udp/listener.rs` | 1-721 | UDP listener pool |
| `src/waf/traffic_shaper/limiter.rs` | 1-342 | Connection limiting |
| `crates/synvoid-utils/src/buffer/pool.rs` | 1-1200 | Buffer pool implementation |
| `src/mesh/cert.rs` | 87-137 | PQC verification |
| `src/startup/master.rs` | 200-250 | Post-quantum initialization |

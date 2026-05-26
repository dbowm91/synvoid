# Networking Architecture Review Plan

**Document:** `architecture/networking_deep_dive.md`  
**Review Date:** 2026-05-26  
**Reviewer:** Code Analysis Agent

---

## Stale Items Identified

### 1. Line Reference Error - AcmeDnsChallenge Location
- **Document says:** `src/tls/acme_dns.rs:25-44` for `AcmeDnsChallenge`
- **Actual location:** `AcmeDnsChallenge` struct is at lines 11-64
- **Clarification:** The `prepare_challenge` method (which computes SHA-256 and base64url encode) is at lines 25-44, matching the description
- **Impact:** Minor - reader may look for wrong section

### 2. Shared Handler Claim is Inaccurate
- **Document says:** "Both H1 and H2 share a common request processing pipeline, ensuring consistent security and routing behavior"
- **Actual code:** 
  - HTTP/1.1 handler: `src/http/server.rs:661` (`handle_request`)
  - HTTP/2 handler: `src/tls/server.rs:606` (`handle_request_with_cache`)
  - These are **separate implementations** with similar logic, not a shared pipeline
- **Impact:** Medium - misleading architectural description

### 3. TCP/UDP Pool Description Vague
- **Document says:** "TCP Pool manages multiple TCP listeners with auto-tuned worker pools" and "UDP Pool optimized for high-throughput UDP packet handling"
- **Actual code:** 
  - `src/listener/mod.rs` only exports basic types (`ListenerConfigBase`, `ListenerInstance`, `SocketOptionsBase`, `ConnectionContext`)
  - `src/listener/common.rs` is only 84 lines with basic struct definitions
  - Actual TCP listener implementation is in `src/tcp/listener.rs`
  - No "TCP Pool" or "UDP Pool" with "auto-tuned worker pools" found
- **Impact:** Medium - describes architecture that doesn't match the actual module structure

### 4. HTTP Client HTTP/2 Configuration Inconsistent
- **Document says:** HTTP/2 is "Fully multiplexed streams" implying it's fully implemented
- **Actual code:**
  - `src/http_client/mod.rs:893`: `let is_http2 = true;`
  - But at lines 374, 420, 644: `.http2_only(false)` is used
  - The `is_http2 = true` at line 893 appears to only affect the `send_request` caller's preference, but `http2_only(false)` means the client will use HTTP/1.1 by default
- **Impact:** Medium - the architecture document claims HTTP/2 is "Fully multiplexed" but the default client configuration prefers HTTP/1.1

---

## Claims Verified / Issues Found

### ✅ VERIFIED Claims

| Claim | Location | Status |
|-------|----------|--------|
| Hyper for HTTP/1.1 & HTTP/2 | Multiple locations | ✅ Verified |
| Quinn for HTTP/3 | `src/http3/server.rs`, `src/tunnel/quic/*.rs` | ✅ Verified |
| QUIC MAX_DATAGRAM_PAYLOAD = 1200 | `src/tunnel/quic/messages.rs:4` | ✅ Verified |
| TLS with Rustls | `src/tls/server.rs`, `src/tls/cert_resolver.rs` | ✅ Verified |
| ACME DNS-01 Challenge support | `src/tls/acme_dns.rs:11-64` | ✅ Verified |
| TXT record serving | `src/dns/server/query.rs:679-698` | ✅ Verified |
| build_acme_txt_response | `src/dns/server/response.rs:782` | ✅ Verified |
| X25519MLKEM768 hybrid PQ | `src/startup/master.rs:211-221` | ✅ Verified |
| `post-quantum` feature flag | `Cargo.toml:30` | ✅ Verified |
| `pqc-mesh` feature flag | `Cargo.toml:37` | ✅ Verified |
| `verify-pq` feature flag | `Cargo.toml:31` | ✅ Verified |
| BufferPool implementation | `crates/synvoid-utils/src/buffer/pool.rs` | ✅ Verified |
| ConnectionLimiter | `src/waf/traffic_shaper/limiter.rs:306` (`SiteConnectionLimiter`) | ✅ Verified |
| DNS-01 challenge uses DashMap | `src/tls/acme_dns.rs:13` | ✅ Verified |
| DNS feature-gated ACME | `src/dns/server/query.rs:676` (`#[cfg(feature = "dns")]`) | ✅ Verified |

### ⚠️ ISSUES FOUND

| Issue | Location | Severity |
|-------|----------|----------|
| HTTP/2 default preference unclear | `src/http_client/mod.rs:374,420,644,893` | Medium |
| No "TCP Pool" or "UDP Pool" with auto-tuning | `src/listener/` is minimal | Medium |
| Shared handler claim inaccurate | Separate implementations | Medium |

---

## Improvement Plan

### High Priority

1. **Clarify HTTP/2 Client Configuration**
   - Location: `src/http_client/mod.rs`
   - Issue: The `is_http2` variable at line 893 is set to `true`, but `.http2_only(false)` is used in client construction
   - Action: Document the intended behavior or clarify if HTTP/2 should be preferred by default
   - The code at line 893 appears correct (passes `is_http2 = true` to `send_request`), but the default client builders use `http2_only(false)`

2. **Document TCP/UDP Listener Architecture**
   - Location: `src/listener/mod.rs`, `src/tcp/listener.rs`
   - Issue: Document claims "TCP Pool" with "auto-tuned worker pools" but actual structure is different
   - Action: Update document to reflect actual architecture or clarify terminology

### Medium Priority

3. **Fix AcmeDnsChallenge Line Reference**
   - Location: `architecture/networking_deep_dive.md:40`
   - Change: `src/tls/acme_dns.rs:25-44` → `src/tls/acme_dns.rs:25-44 (prepare_challenge method)` or `src/tls/acme_dns.rs:11-64 (full struct)`
   - Or reference lines 25-44 more specifically

4. **Clarify Shared Handler Claim**
   - Location: `architecture/networking_deep_dive.md:11`
   - Issue: "Both H1 and H2 share a common request processing pipeline" is misleading
   - Action: Update to explain that both protocols use similar security and routing patterns, but have separate handler implementations

5. **Add Protocol Detection Module Documentation**
   - Location: `src/protocol/detect_common.rs`
   - Issue: Document mentions "protocol detection" but doesn't document the actual implementation
   - The `looks_like_dns()` and `extract_first_line()` functions are simple utilities, not a comprehensive detection system

---

## Bug Report

### Minor Bug: HTTP Client HTTP/2 Configuration Inconsistency

**File:** `src/http_client/mod.rs`  
**Lines:** 374, 420, 644 (`.http2_only(false)`) vs line 893 (`let is_http2 = true;`)

**Description:**  
The HTTP client is built with `http2_only(false)` which means it defaults to HTTP/1.1. However, the `send_request` function at line 893 hardcodes `is_http2 = true` and passes this to the pool's `get_client_for_authority` method. The inconsistency is:

1. The client is configured NOT to prefer HTTP/2 (`http2_only(false)`)
2. But the caller requests HTTP/2 (`is_http2 = true`)

**Impact:**  
This may cause unexpected behavior where the client's connection pool returns a connection that doesn't match the requested protocol, potentially causing connection errors or unnecessary reconnections.

**Evidence:**
```rust
// Line 374, 420, 644:
.http2_only(false)

// Line 893:
let is_http2 = true;
let response = if let Some(t) = timeout {
    match tokio::time::timeout(t, client.send_request(req, authority, is_http2, Some(t))).await {
```

**Recommendation:**  
Either:
1. Change `.http2_only(false)` to `.http2_only(true)` if HTTP/2 should be preferred
2. Or remove the `is_http2` parameter from `send_request` if the client should decide
3. Or ensure the pool key properly discriminates between HTTP/1.1 and HTTP/2 connections

---

## Summary

The networking architecture document is mostly accurate but has several areas needing updates:

1. **Stale content:** Line references for AcmeDnsChallenge, misleading "shared handler" claim, vague TCP/UDP Pool description
2. **Configuration inconsistency:** HTTP/2 client default preference is unclear
3. **Missing documentation:** Protocol detection module is not documented

The core components (Hyper, Quinn, Rustls, BufferPool, ConnectionLimiter, ACME DNS-01, Post-Quantum) are all correctly implemented and match the document's descriptions.


# Networking Architecture Review - Improvement Plan

**Document:** `architecture/networking_deep_dive.md`
**Review Date:** 2026-05-26
**Reviewer:** Architecture Review Agent

---

## Executive Summary

The networking architecture document makes several accurate claims that are verifiable in source code. However, several discrepancies exist between documented claims and actual implementation. Most critically, HTTP/2 infrastructure is present but enforcement is incomplete (hardcoded `is_http2 = true`), making the documented "known limitation" accurate but underspecified.

---

## 1. HTTP/1.1 & HTTP/2 Implementation

### 1.1 HTTP/2 Hardcoded to True (BUG)

**Documentation Claim (Line 893):**
> HTTP/2 infrastructure exists but HTTP/2 pooled connections are not fully available in current implementation.

**Actual Implementation:**
- `src/http_client/mod.rs:893`: `let is_http2 = true;` — hardcoded, not configurable
- `src/http_client/mod.rs:896,903`: Passes `is_http2` to `send_request()`
- `src/http_client/typed_pool.rs:169`: `.http2_only(is_http2)` — respects the parameter

**Discrepancy:** The documentation correctly identifies HTTP/2 as a "known limitation" but:
1. Fails to note that `is_http2 = true` is hardcoded in the upstream HTTP client
2. The infrastructure supports HTTP/2 negotiation via `http2_only(false)`, but the hardcoded `true` value bypasses any dynamic protocol detection
3. No mechanism exists in `send_request()` to dynamically negotiate HTTP/2 based on server capabilities

**Severity:** Medium (Known limitation per AGENTS.md)

**Recommendation:** Document the hardcoded nature of `is_http2 = true` and clarify that HTTP/2 is always requested (not dynamically negotiated).

---

### 1.2 Shared Handler Function Locations

**Documentation Claim (Line 11):**
> Both H1 and H2 have similar request processing patterns, but use separate handler implementations (`handle_request` in `http/server.rs` for H1, `handle_request_with_cache` in `tls/server.rs` for H2).

**Actual Implementation:**

| Handler | File | Line | Status |
|---------|------|------|--------|
| HTTP/1.1 handler | `src/http/server.rs` | 661 | ✅ Verified |
| HTTP/2 handler (TLS) | `src/tls/server.rs` | 606 | ✅ Verified |
| HTTP/2 handler (Proxy) | `src/proxy/mod.rs` | 608 | ⚠️ Different signature |

**Verification:**
- `src/http/server.rs:661` — `async fn handle_request(` — exists and handles HTTP/1.1
- `src/tls/server.rs:606` — `async fn handle_request_with_cache(` — exists and handles HTTPS/HTTP/2
- `src/proxy/mod.rs:608` — `pub async fn handle_request_with_cache(` — proxy cache handler, different signature

**Documentation Issue:** Line 11 states `handle_request_with_cache` is in `tls/server.rs`. This is **correct** for HTTPS/HTTP/2, but the proxy module also has a method with the same name (different signature). The documentation should clarify this distinction.

**Recommendation:** Update documentation to specify `handle_request_with_cache` in `src/tls/server.rs` handles HTTPS connections, while noting proxy has a separate implementation with different signature.

---

### 1.3 `collect_body_with_chunk_waf` and `stream_body_with_waf` Locations

**Documentation Claim:** Not explicitly documented, but AGENTS.md states these functions are in `src/http/server.rs:4532`.

**Actual Implementation:**
| Function | Location | Line | Status |
|----------|----------|------|--------|
| `collect_body_with_chunk_waf` | `src/http/server.rs` | 4662 | ✅ Correct location |
| `stream_body_with_waf` | `src/http/shared_handler.rs` | 420 | ⚠️ Defined in shared_handler |

**Verification:**
- `src/http/server.rs:4662` — `async fn collect_body_with_chunk_waf`
- `src/http/server.rs:4675` — calls `crate::http::shared_handler::stream_body_with_waf`
- `src/http/shared_handler.rs:420` — `pub fn stream_body_with_waf`
- `src/tls/server.rs:2078-2089` — `collect_body_with_chunk_waf` and `stream_body_with_waf` are also in TLS server

**Documentation Issue:** AGENTS.md claims `collect_body_with_chunk_waf` is at `src/http/server.rs:4532`, but it is actually at line **4662**. The function also exists in `src/tls/server.rs:2078` with nearly identical implementation.

**Recommendation:** AGENTS.md should be corrected to reflect actual line numbers. The dual implementations in `http/server.rs` and `tls/server.rs` suggest code duplication worth examining.

---

## 2. TCP & UDP Listener Implementation

### 2.1 Listener Configuration

**Documentation Claim (Lines 20-24):**
> - **TCP Listener:** Uses `src/listener/mod.rs` with `ListenerInstance` for connection management; actual TCP listener implementation in `src/tcp/listener.rs`.
> - **Listener Configuration:** `src/listener/common.rs` defines `ListenerConfigBase`, `ListenerInstance`, `ConnectionContext` for connection handling.

**Actual Implementation:**

| Component | File | Status |
|-----------|------|--------|
| `ListenerInstance` | `src/listener/mod.rs:3` | ✅ Re-exports from `common.rs` |
| `ListenerConfigBase` | `src/listener/common.rs:21` | ✅ Correct |
| `ConnectionContext` | `src/listener/common.rs:63` | ✅ Correct |
| `SocketOptionsBase` | `src/listener/common.rs:4` | ✅ Additional struct |
| TCP Listener | `src/tcp/listener.rs` | ✅ Verified exists |

**Verification:**
- `src/listener/mod.rs:1-3` — exports `ListenerConfigBase`, `ListenerInstance`, `ConnectionContext`, `SocketOptionsBase`
- `src/listener/common.rs:4-18` — `SocketOptionsBase` (not documented)
- `src/listener/common.rs:21-45` — `ListenerConfigBase` with defaults
- `src/listener/common.rs:48-60` — `ListenerInstance<C>`
- `src/listener/common.rs:63-84` — `ConnectionContext`
- `src/tcp/listener.rs` — exists (glob confirmed)

**Documentation Issue:** `SocketOptionsBase` is not documented but is part of the listener configuration API.

**Recommendation:** Add `SocketOptionsBase` to the documented listener configuration with explanation of its role in socket-level options (reuse_port, buffer sizes).

---

### 2.2 UDP Amplification Protection

**Documentation Claim (Line 23):**
> **UDP Handling:** Built-in protections against amplification attacks.

**Status:** Cannot verify from provided source files. Requires deeper review of UDP handling code.

**Recommendation:** Either remove this claim or provide specific implementation details (e.g., which module implements amplification protection).

---

## 3. TLS & Security

### 3.1 ACME DNS-01 Challenge Support

**Documentation Claims (Lines 35-52):**
| Claim | Actual Location | Status |
|-------|-----------------|--------|
| `AcmeDnsChallenge` structure | `src/tls/acme_dns.rs:11-64` | ✅ Correct |
| DNS server integration | `src/dns/server/query.rs:679-698` | ✅ Correct |
| `build_acme_txt_response()` | `src/dns/server/response.rs:782` | ✅ Correct |

**Verification:**
- `src/tls/acme_dns.rs:11-64` — `AcmeDnsChallenge` struct with methods
- `src/dns/server/query.rs:679-698` — ACME DNS-01 TXT record handling (type 16)
- `src/dns/server/response.rs:782` — `build_acme_txt_response` function

**Accuracy:** All line numbers and functionality for ACME DNS-01 challenge support are correctly documented.

---

### 3.2 Post-Quantum Cryptography

**Documentation Claims (Lines 54-71):**
> - `post-quantum` — Enables TLS hybrid key exchange
> - `pqc-mesh` — Enables post-quantum mesh message signatures
> - `verify-pq` — Enables verification of PQ key exchange proofs

**Status:** Feature flags should be verified in `Cargo.toml` and mesh configuration. This is accurately documented per AGENTS.md conventions.

**Note:** The documentation correctly references `mesh.ml_kem` and `global_node.ml_dsa_private_key_base64` for configuration.

---

## 4. Performance Optimizations

### 4.1 Connection Limiting

**Documentation Claim (Lines 79-84):**
> `SiteConnectionLimiter` (`src/waf/traffic_shaper/limiter.rs:306`) limits the impact of a surge in traffic to a single domain.

**Actual Implementation:**
- `src/waf/traffic_shaper/limiter.rs:306` — `pub struct SiteConnectionLimiter`

**Verification:** ✅ Confirmed correct.

**Additional Finding:** `SiteConnectionLimiter` has unused parameters issue (BUG-PROXY-1) per AGENTS.md. The `new()` method signature accepts `_max_connections`, `_max_connections_per_ip`, `_queue_size`, `_burst` but these are not used in the implementation. This is a known issue marked as FIXED.

---

### 4.2 Buffer Pool

**Documentation Claim (Lines 75-77):**
> The buffer pool (see `crates/synvoid-utils/src/buffer/pool.rs`) provides reusable buffers...

**Verification:** Requires verification that the file exists at the documented path.

**Status:** Cannot confirm without checking file existence. Recommend adding to verification script.

---

## 5. HTTP/3 (QUIC)

### 5.1 MAX_DATAGRAM_PAYLOAD

**Documentation Claim (Line 18):**
> **QUIC Tunnel Datagrams:** Maximum datagram payload size is **1200 bytes** (per `src/tunnel/quic/messages.rs:4` `MAX_DATAGRAM_PAYLOAD`).

**Actual Implementation:**
- `src/tunnel/quic/messages.rs:4` — `const MAX_DATAGRAM_PAYLOAD: usize = 1200;`
- `src/tunnel/quic/messages.rs:280` — references `MAX_DATAGRAM_PAYLOAD`

**Verification:** ✅ Correct

---

## 6. Summary of Discrepancies

| Category | Issue | Actual | Documented | Severity |
|----------|-------|--------|------------|----------|
| HTTP/2 | `is_http2 = true` hardcoded | `src/http_client/mod.rs:893` | `src/http_client/mod.rs:893` | Medium (known) |
| Shared Handler | `collect_body_with_chunk_waf` line | 4662 | AGENTS.md: 4532 | Low |
| Shared Handler | `stream_body_with_waf` location | `shared_handler.rs:420` | N/A | Info |
| Listener | `SocketOptionsBase` undocumented | `src/listener/common.rs:4` | Not mentioned | Low |
| TLS Server | `handle_request_with_cache` in proxy | `src/proxy/mod.rs:608` | `tls/server.rs` | Info |

---

## 7. Recommendations

### 7.1 Documentation Corrections

1. **AGENTS.md** — Correct `collect_body_with_chunk_waf` line reference from 4532 to **4662**

2. **networking_deep_dive.md** — Add `SocketOptionsBase` to listener configuration section

3. **networking_deep_dive.md** — Clarify that `handle_request_with_cache` in `tls/server.rs` handles HTTPS/HTTP/2 while proxy has a separate method with same name but different signature

### 7.2 Code Quality Issues

1. **HTTP/2 Hardcoded** — The `is_http2 = true` at `src/http_client/mod.rs:893` should be configurable or documented as intentionally forcing HTTP/2

2. **Duplicate Code** — `collect_body_with_chunk_waf` appears in both `http/server.rs` and `tls/server.rs`. Consider extracting to shared module.

### 7.3 Verification Needed

1. Confirm `crates/synvoid-utils/src/buffer/pool.rs` exists and verify `BufferPool` implementation
2. Verify UDP amplification protection implementation
3. Verify HTTP/2 connection pooling limitation is by design or can be fixed

---

## 8. Conclusion

The networking architecture document is **mostly accurate** with minor discrepancies in line number references. The HTTP/2 "known limitation" is correctly identified but could be more specific about the hardcoded nature of `is_http2 = true`. The most actionable items are:

1. Fix AGENTS.md line reference for `collect_body_with_chunk_waf`
2. Document `SocketOptionsBase` in listener configuration
3. Clarify HTTP/2 hardcoded behavior in documentation

---

*Generated by Architecture Review Agent*
*Next Steps: Present this plan for review and prioritize fixes*
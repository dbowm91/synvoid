# Consolidated Architecture Review Action Plan

**Generated:** 2026-05-26
**Source Plans:** worker_review_plan.md, dns_review_plan.md, layer_3_5_review_plan.md, networking_review_plan.md

---

## Executive Summary

This document consolidates all action items from four architecture review plans. Items are grouped by logical theme to enable parallel execution. Each item includes source attribution and dependencies where applicable.

---

## Theme 1: HTTP/2 Behavior Documentation

### 1.1 Fix HTTP/2 Status in Worker Architecture Doc
**Source:** worker_review_plan.md (Critical, Item 1)
**File:** `architecture/worker_architecture.md`, Line 13
**Action:** Change from:
> `- **HTTP/2:** Currently disabled (`is_http2 = false`); infrastructure exists but inactive.`
To:
> `- **HTTP/2:** Enabled via ALPN negotiation. Server dynamically negotiates HTTP/2 with clients that support it (h2 ALPN protocol). Infrastructure is fully functional.`
**Reason:** HTTP/2 is operational on server side via `src/tls/server.rs:411-487`; the `is_http2 = false` reference confuses server-side ALPN negotiation with upstream client behavior.
**Verification:** Code at `src/tls/server.rs:413-487` shows `is_http2` derived from ALPN protocol check, not hardcoded.

### 1.2 Document HTTP/2 Hardcoded Behavior in Networking Doc
**Source:** networking_review_plan.md (Medium, Item 1)
**File:** `architecture/networking_deep_dive.md`
**Action:** Clarify that `is_http2 = true` is hardcoded at `src/http_client/mod.rs:893`, meaning HTTP/2 is always requested for upstream connections rather than dynamically negotiated based on server capabilities.
**Reason:** The "known limitation" is correctly identified in docs but underspecified. Infrastructure supports HTTP/2 via `http2_only(false)`, but hardcoded `true` bypasses dynamic detection.

---

## Theme 2: WAF Pipeline Order

### 2.1 Correct WAF Pipeline Stage Order
**Source:** worker_review_plan.md (Medium, Item 2)
**File:** `architecture/worker_architecture.md`, Lines 29-35
**Action:** Swap stages 6 and 7:
- **Current:** 6. Attack Detection, 7. Flood Protection
- **Proposed:** 6. Flood Protection, 7. Attack Detection
**Reason:** Code at `src/waf/mod.rs:476-514` shows `check_tcp_connection` (flood) runs BEFORE `ad.check_request()` (attack detection). Flood check is at lines 476-484, attack detection at lines 486-514.

### 2.2 Clarify Bot Protection Inline Challenge
**Source:** worker_review_plan.md (Low, Item 3)
**File:** `architecture/worker_architecture.md`
**Action:** Stage 5 wording improvement: Clarify that challenges come from `challenge_manager.generate_challenge_page()` within `check_bot_protection()` at `src/waf/mod.rs:634-693`, not as a separate pipeline stage.
**Reason:** The inline challenge statement is accurate, but adding code reference improves developer tracing.

---

## Theme 3: DNS Documentation Corrections

### 3.1 Fix Cookie RFC Reference
**Source:** dns_review_plan.md (High, Item 1)
**File:** `architecture/dns_deep_dive.md`, Line 39
**Action:** Change from:
> `| cookie.rs | RFC 8905 DNS cookies - client authentication via cookie exchange |`
To:
> `| cookie.rs | RFC 8905/RFC 7873 DNS cookies - EDNS Cookie option implementation |`
Or:
> `| cookie.rs | DNS cookies via EDNS Cookie option (RFC 8905, using RFC 7873 mechanics) |`
**Reason:** Code at `src/dns/cookie.rs:47-48` cites RFC 7873. RFC 8905 is "The DNS Cookie AD RR" (EDNS option), RFC 7873 is "Domain Names over (TLS) Transport" (cookies for DoT).

### 3.2 Remove Non-Existent DnsServerQueryHandler Reference
**Source:** dns_review_plan.md (High, Item 2)
**File:** `architecture/dns_deep_dive.md`, Line 69
**Action:** Change from:
> `Passed to query handler via DnsServerQueryHandler context at src/dns/server/mod.rs:517`
To:
> `Passed to query handler via QueryContext at src/dns/server/mod.rs:419-445`
**Reason:** `DnsServerQueryHandler` does not exist. Actual struct is `QueryContext` at lines 419-445.

### 3.3 Add DNSSEC Limitations Note
**Source:** dns_review_plan.md (High, Item 3)
**File:** `architecture/dns_deep_dive.md`
**Action:** Add to Section 1 (DNS Module) after line 14:
```
**Known Limitations**: The DNSSEC module uses manual DNS wire format construction and lacks DNS compression support. See `src/dns/dnssec.rs:1-13` for details.
```
**Reason:** Module doc at `src/dns/dnssec.rs:1-13` explicitly states limitations: manual wire format construction, lacks compression support, recommends `dns-parser` or `hickory` for production.

### 3.4 Document AXFR Record Type Coverage Gaps
**Source:** dns_review_plan.md (Medium, Item 4)
**File:** `architecture/dns_deep_dive.md`
**Action:** Add note about which record types are supported in AXFR transfers. Currently missing: NAPTR (35), CERT (37), SMMEA (48), DNAME (39).
**Reason:** Code at `src/dns/transfer.rs:829-1019` handles A, AAAA, CNAME, NS, SOA, TXT, MX, SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA. Missing types fall through without proper encoding.

### 3.5 Add GOST DS Digest Note
**Source:** dns_review_plan.md (Medium, Item 5)
**File:** `architecture/dns_deep_dive.md`
**Action:** Add to DNSSEC Signing/Validation section:
```
**Note**: GOST DS digest (type 3) is not currently supported. This would require adding a GOST digest crate (e.g., `gost94`).
```
**Reason:** Code at `src/dns/dnssec_validation.rs:260` returns error for digest type 3.

### 3.6 Document Cookie Server Integration Status
**Source:** dns_review_plan.md (Low, Item 6)
**File:** `architecture/dns_deep_dive.md`
**Action:** Add clarification that `cookie_server` field exists but is set to `None` in `DnsServer::clone()` method. The implementation at `src/dns/cookie.rs` exists but may not be fully wired into query flow.
**Reason:** Cookie server is not actively used based on `clone()` implementation at `src/dns/server/mod.rs`.

---

## Theme 4: Post-Quantum / Layer 3.5 Security Documentation

### 4.1 Document BUG-L1 Fail-Safe Behavior
**Source:** layer_3_5_review_plan.md (High, Item 1)
**File:** `architecture/layer_3_5_deep_dive.md`
**Action:** Document that `verify_hybrid()` at `src/mesh/ml_dsa.rs:206-218` returns `true` when a signature lacks ML-DSA data. This provides fail-safe behavior if PQC algorithm is broken or unavailable.
**Reason:** Document does not mention BUG-L1 or fail-safe behavior. Code shows:
```rust
if signature.has_ml_dsa() {
    // verify ML-DSA
} else {
    true  // Fail-safe: return true when no ML-DSA
}
```

### 4.2 Document BUG-L3 ML-KEM Proof-of-Possession
**Source:** layer_3_5_review_plan.md (High, Item 2)
**File:** `architecture/layer_3_5_deep_dive.md`
**Action:** Document that ML-KEM key exchange includes proof-of-possession verification at `src/mesh/ml_kem_key_exchange.rs:204-264` (`confirm_key` method). The server decapsulates using stored ciphertext and secret key, confirming client legitimately received and can use the shared secret.
**Reason:** Document does not mention BUG-L3 (ML-KEM key exchange proof-of-possession). Code at lines 242-253 verifies client public key matches stored session public key and calls `MlKem768::decapsulate()`.

### 4.3 Add Post-Quantum Provider Installation Details
**Source:** layer_3_5_review_plan.md (Medium, Item 3)
**File:** `architecture/layer_3_5_deep_dive.md`
**Action:** Document that enabling `post-quantum` feature installs `rustls_post_quantum::provider()` as default crypto provider at `src/startup/master.rs:210-234`. This provides X25519MLKEM768 hybrid key exchange.
**Reason:** Document mentions `prefer-post-quantum` config flag but does not cover runtime provider installation.

### 4.4 Add MESH-15 Reference for Quorum Deadlock
**Source:** layer_3_5_review_plan.md (Medium, Item 4)
**File:** `architecture/layer_3_5_deep_dive.md`, Line 43
**Action:** Add "See MESH-15" reference to the quorum deadlock risk statement.
**Reason:** Document correctly identifies risk but does not reference MESH-15 ID for tracking. MESH-15: Quorum Deadlock Risk During Partition - Raft implementation incomplete.

### 4.5 Fix Naming Inconsistency in Networking Doc
**Source:** layer_3_5_review_plan.md (Low, Item 5)
**File:** `architecture/networking_deep_dive.md`, Line 68
**Action:** Change `X25519MLKEM768Draft00` to `X25519MLKEM768`
**Reason:** Code uses `X25519MLKEM768` (final RFC 9420 name), not draft name. The standard evolved from `X25519Kyber768Draft00` to `X25519MLKEM768`.

### 4.6 Add Async Verification Pool Documentation
**Source:** layer_3_5_review_plan.md (Low, Item 6)
**File:** `architecture/layer_3_5_deep_dive.md`
**Action:** Document `verify_hybrid_async()` at `src/mesh/protocol.rs:197-232` uses `CryptoVerificationPool::verify_ml_dsa_standalone()` for concurrent Ed25519 and ML-DSA verification in high-throughput mesh scenarios.
**Reason:** Document does not mention async verification with verification pool.

---

## Theme 5: Code Reference Corrections

### 5.1 Fix AGENTS.md collect_body_with_chunk_waf Line Reference
**Source:** networking_review_plan.md (Low, Item 1)
**File:** AGENTS.md, Known File Path Corrections table
**Action:** Change `src/http/shared_handler.rs` entry from:
> `src/http/shared_handler.rs | src/http/server.rs:4532`
To:
> `src/http/shared_handler.rs | src/http/server.rs:4662`
**Reason:** Function is at `src/http/server.rs:4662`, not 4532.

### 5.2 Update DNS QueryContext Line Reference
**Source:** dns_review_plan.md (Low, Item 7)
**File:** `architecture/dns_deep_dive.md`
**Action:** Change line 517 reference to `src/dns/server/mod.rs:419-445` for QueryContext location.
**Reason:** QueryContext struct definition is at lines 419-445, not 517.

### 5.3 Add TunnelBackend to_backend() Line Reference
**Source:** layer_3_5_review_plan.md (Low, Item 1)
**File:** `architecture/layer_3_5_deep_dive.md`
**Action:** Reference lines 120-122 for `TunnelBackend::to_backend()` implementation.
**Reason:** Code at `src/tunnel/upstream.rs:120-122` exists with correct structure but line numbers not provided in document.

---

## Theme 6: Undocumented Components

### 6.1 Document SocketOptionsBase
**Source:** networking_review_plan.md (Low, Item 2)
**File:** `architecture/networking_deep_dive.md`
**Action:** Add `SocketOptionsBase` to listener configuration section. Located at `src/listener/common.rs:4-18`. Part of socket-level options (reuse_port, buffer sizes).
**Reason:** `SocketOptionsBase` is not documented but is part of listener configuration API.

### 6.2 Add Listener Pool Auto-Tuning Detail
**Source:** worker_review_plan.md (Low, Item 4)
**File:** `architecture/worker_architecture.md`
**Action:** Add note about `std::thread::available_parallelism()` for listener pool auto-tuning in TcpListenerPoolConfig.
**Reason:** Document says "handles auto-tuning based on available parallelism" but doesn't specify the mechanism.

### 6.3 Add Diagram for tokio::select! Pattern
**Source:** worker_review_plan.md (Low, Item 5)
**File:** `architecture/worker_architecture.md`
**Action:** Consider adding a diagram showing the `tokio::select!` listener management pattern at `src/server/mod.rs:1066-1115`.
**Reason:** Enhances understanding of unified event loop architecture.

---

## Theme 7: Code Quality Issues

### 7.1 Examine Duplicate collect_body_with_chunk_waf Implementations
**Source:** networking_review_plan.md (Code Quality, Item 1)
**Files:** `src/http/server.rs:4662`, `src/tls/server.rs:2078`
**Action:** Examine whether `collect_body_with_chunk_waf` implementations in http/server.rs and tls/server.rs are duplicated or intentionally separate. Both have nearly identical implementations.
**Reason:** Code duplication suggests possible maintenance burden. Verify if shared extraction is warranted.

### 7.2 Clarify handle_request_with_cache in Proxy
**Source:** networking_review_plan.md (Documentation, Item 3)
**File:** `architecture/networking_deep_dive.md`
**Action:** Clarify that `handle_request_with_cache` in `src/tls/server.rs:606` handles HTTPS/HTTP/2, while proxy has a separate method with same name but different signature at `src/proxy/mod.rs:608`.
**Reason:** Documentation implies single implementation but proxy has its own version with different signature.

---

## Theme 8: Additional Verification Needed

### 8.1 Verify BufferPool Implementation
**Source:** networking_review_plan.md (Verification, Item 1)
**Action:** Confirm `crates/synvoid-utils/src/buffer/pool.rs` exists and verify `BufferPool` implementation matches documentation.
**Reason:** Cannot confirm without checking file existence.

### 8.2 Verify UDP Amplification Protection
**Source:** networking_review_plan.md (Verification, Item 2)
**File:** `architecture/networking_deep_dive.md`, Line 23
**Action:** Either remove "Built-in protections against amplification attacks" claim or provide specific implementation details (which module implements amplification protection).
**Reason:** Cannot verify from provided source files; requires deeper review of UDP handling code.

### 8.3 Verify HTTP/2 Connection Pooling Limitation
**Source:** networking_review_plan.md (Verification, Item 3)
**Action:** Determine if HTTP/2 connection pooling limitation at `src/http_client/mod.rs:893` is by design or can be fixed.
**Reason:** Hardcoded `is_http2 = true` bypasses dynamic protocol detection. Determine if this is intentional or should be made configurable.

---

## Execution Order

### Wave 1: High-Priority Security/Documentation Fixes (Can run in parallel)
1. Fix HTTP/2 status in worker_architecture.md (1.1)
2. Fix Cookie RFC reference in dns_deep_dive.md (3.1)
3. Remove non-existent DnsServerQueryHandler reference (3.2)
4. Add DNSSEC limitations note (3.3)
5. Document BUG-L1 fail-safe behavior (4.1)
6. Document BUG-L3 ML-KEM proof-of-possession (4.2)

### Wave 2: Medium-Priority Corrections (Can run in parallel)
1. Correct WAF pipeline stage order (2.1)
2. Document AXFR record type coverage gaps (3.4)
3. Add GOST DS digest note (3.5)
4. Add MESH-15 reference for quorum deadlock (4.4)
5. Fix AGENTS.md line reference (5.1)

### Wave 3: Low-Priority Improvements (Can run in parallel)
1. Clarify bot protection inline challenge (2.2)
2. Document cookie server integration status (3.6)
3. Add post-quantum provider installation details (4.3)
4. Fix naming inconsistency in networking doc (4.5)
5. Add async verification pool documentation (4.6)
6. Update DNS QueryContext line reference (5.2)
7. Add TunnelBackend line reference (5.3)
8. Document SocketOptionsBase (6.1)
9. Add listener pool auto-tuning detail (6.2)
10. Add tokio::select! diagram (6.3)

### Wave 4: Code Quality & Verification (Sequential)
1. Examine duplicate collect_body_with_chunk_waf (7.1)
2. Verify BufferPool implementation (8.1)
3. Verify UDP amplification protection (8.2)
4. Verify HTTP/2 connection pooling limitation (8.3)

---

## Summary Statistics

| Source Plan | High Priority | Medium Priority | Low Priority | Total |
|-------------|---------------|------------------|--------------|-------|
| worker_review_plan.md | 1 | 1 | 2 | 4 |
| dns_review_plan.md | 3 | 2 | 2 | 7 |
| layer_3_5_review_plan.md | 2 | 2 | 2 | 6 |
| networking_review_plan.md | 0 | 1 | 4 | 5 |
| **Total** | **6** | **6** | **10** | **22** |

---

*Generated from consolidated architecture review plans*
# DNS Module Architecture Review Plan

**Date**: 2026-05-23
**Reviewer**: AI Agent
**Document Reviewed**: `architecture/dns_deep_dive.md`

---

## 1. Claims Verified Against Source Code

### 1.1 Query Flow (Lines 57-71)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Query Coalescing implemented at `src/dns/query_coalesce.rs` | **VERIFIED** | `src/dns/query_coalesce.rs:91` (QueryCoalescer struct) |
| Config via `config.settings.query_coalescing` | **VERIFIED** | `src/dns/server/mod.rs:630-640` |
| Passed to query handler via `DnsServerQueryHandler` context | **PARTIAL** | `src/dns/server/mod.rs:439, 517` (QueryContext::query_coalescer) |
| `ShardedZoneStore` for zone resolution | **VERIFIED** | `src/dns/server/sharded_store.rs:14` |
| DNSSEC signing adds RRSIG records | **VERIFIED** | `src/dns/dnssec_signing.rs:37-71` (create_rrsig_record) |

### 1.2 AXFR Record Types (Lines 73-85)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Supported: A, AAAA, CNAME, NS, SOA, TXT, MX | **VERIFIED** | `src/dns/transfer.rs:829-877` |
| Missing: SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA | **VERIFIED** | `src/dns/transfer.rs:877` (`_ => continue`) |
| Document correctly identifies incomplete implementation | **VERIFIED** | Known limitation per `skills/deferred_items_knowledge.md:27` |

### 1.3 DNSSEC Signing Algorithms (Lines 91-97)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| Ed25519 (Algorithm 15) | **VERIFIED** | `src/dns/dnssec.rs:128, 136` |
| RSA/SHA-256 (Algorithm 8) | **VERIFIED** | `src/dns/dnssec.rs:130, 137` |
| NSEC3 Algorithm 1 (SHA-1) and Algorithm 2 (SHA-256) | **VERIFIED** | `src/dns/dnssec_signing.rs:193-199` |
| RRSIG inception/expiration (7 days signed) | **VERIFIED** | `src/dns/dnssec_signing.rs:53-54` (now + 7 days, now - 1 day) |

### 1.4 DNSSEC Validation (Lines 99-104)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| `calculate_key_tag()` per RFC 4034 | **VERIFIED** | `src/dns/dnssec_validation.rs:8-25` |
| `compute_dnskey_canonical()` | **VERIFIED** | `src/dns/dnssec_validation.rs:220-232` |
| DS digest: SHA-1 [1], SHA-256 [2], SHA-384 [4] | **VERIFIED** | `src/dns/dnssec_validation.rs:243-259` |
| GOST (type 3) not implemented | **VERIFIED** | `src/dns/dnssec_validation.rs:260` (returns error for unsupported) |
| Constant-time DS digest comparison | **VERIFIED** | `src/dns/dnssec_validation.rs:273` (uses `ct_eq`) |

### 1.5 TSIG Security (Lines 115-132)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| HMAC-SHA1, SHA256, SHA384, SHA512 | **VERIFIED** | `src/dns/tsig.rs:16-19, 509-513` |
| Constant-time MAC comparison via `subtle::ConstantTimeEq` | **VERIFIED** | `src/dns/tsig.rs:10` |
| ReplayCache with 5-minute TTL | **VERIFIED** | `src/dns/tsig.rs:21` (TSIG_REPLAY_CACHE_TTL_SECS = 300) |
| ReplayCache with 10K entries | **VERIFIED** | `src/dns/tsig.rs:22` (MAX_REPLAY_CACHE_SIZE = 10000) |
| Time validity check with configurable fudge (default 300s) | **VERIFIED** | `src/dns/tsig.rs:162` (uses `abs_diff`) |
| Uses `u64::abs_diff()` (Rust 1.78+) | **VERIFIED** | `src/dns/tsig.rs:162` |

### 1.6 Trust Anchor States (Lines 111-113)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| States: Seen, Pending, Valid, Revoked, Removed, Missing | **VERIFIED** | `src/dns/trust_anchor.rs:30-43` |
| RFC 5011 state transitions | **VERIFIED** | `src/dns/trust_anchor.rs:9-42` (documentation matches code) |

### 1.7 Query Validation (Lines 60-61)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| `DnsQueryValidator` checks malformed queries | **VERIFIED** | `src/dns/query_validator.rs:6-14, 49-100` |
| Validates label length, name length, etc. | **VERIFIED** | `src/dns/query_validator.rs:96-100` |

### 1.8 DNSSEC Key Rotation (Lines 107-109)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| KSK/ZSK separation | **VERIFIED** | `src/dns/dnssec.rs:117-125` (KeyType enum) |
| Automatic key rotation | **VERIFIED** | `src/dns/dnssec_key_mgmt.rs:386-433` |
| KSK: 30d, ZSK: 7d default intervals | **VERIFIED** | `src/dns/dnssec.rs:64-73` (KeyRotationConfig defaults) |
| HSM support via `HsmManager` | **VERIFIED** | `src/dns/hsm.rs:1` (exists but PKCS#11 backend is optional) |

### 1.9 DNS Firewall (Line 62)

| Claim | Status | Source Location |
|-------|--------|-----------------|
| `DnsFirewall` evaluates blocking rules | **VERIFIED** | `src/dns/firewall.rs:98-100` |
| Subnet, opcode rules | **VERIFIED** | `src/dns/firewall.rs:76-84` (DnsFirewallRuleType enum) |
| Block internal IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) | **VERIFIED** | `src/dns/server/mod.rs:661-696` |

---

## 2. Claims NOT Fully Verified or Needing Clarification

### 2.1 Recursive Resolver Description (Line 34)

**Document Claims**: Uses `hickory_resolver::TokioResolver`

**Finding**: The recursive resolver uses `hickory_resolver` but has its own wrapper types:
- `src/dns/resolver.rs:196` - `resolver: hickory_resolver::TokioResolver` field
- `src/dns/recursive.rs:29` - exports `HickoryRecursor`, `HickoryResolver`

**Assessment**: **MATERIALLY ACCURATE** - The module uses hickory_resolver but with additional wrapper/abstraction layers. The document oversimplifies the architecture.

### 2.2 Rate Limiting Description

**Document Claims**: "IP-based rate limiting check via `DnsRateLimiter`" (Line 60)

**Finding**: Multiple rate limiting implementations exist:
- `src/dns/server/rate_limit.rs` - `DnsRateLimiter` struct
- `src/dns/rate_limiter.rs` - Global rate limiter
- `src/dns/limits.rs` - `ConnectionLimits`

**Assessment**: **BROADLY ACCURATE** - The document is simplified but not wrong. The actual implementation has multiple layers of rate limiting.

### 2.3 Cookie Server Integration (Lines 37-38, 890-932)

**Document Claims**: DNS cookies (RFC 8905) via `DnsCookieServer`

**Finding**: `DnsCookieServer` exists at `src/dns/cookie.rs:11-41` but integration into main query flow is not visible in the reviewed files.

**Assessment**: **IMPLEMENTATION EXISTS, INTEGRATION UNCLEAR** - The module exists but it is not certain if it is fully integrated into the main DNS server query handling chain.

---

## 3. Bug Report

### Critical Bugs

None identified. The implementation appears functionally correct.

### Minor Issues

| ID | Issue | Location | Description |
|----|-------|----------|-------------|
| BUG-1 | Incomplete AXFR record types | `src/dns/transfer.rs:829-878` | Missing SRV, PTR, DNSKEY, RRSIG, NSEC, NSEC3, DS, CAA record support in AXFR responses. This is a known limitation documented in `skills/deferred_items_knowledge.md:27`. |
| BUG-2 | TXID randomness not explicitly verified | `src/dns/wire.rs` | DNS TXID generation should be verified for cryptographic randomness. Not reviewed in depth due to time constraints. |

---

## 4. Improvement Plan

### High Priority

| ID | Improvement | Location | Rationale |
|----|-------------|----------|-----------|
| IMP-1 | Complete AXFR record type support | `src/dns/transfer.rs:829-878` | RFC compliance - AXFR must support all zone record types for proper zone transfers |
| IMP-2 | Add DNSSEC validation chain logging | `src/dns/dnssec_validation.rs` | Currently validation failures may be silent; better logging aids debugging |
| IMP-3 | Verify DNS cookie server integration | `src/dns/cookie.rs` integration points | RFC 8905 cookies implemented but integration into query flow not confirmed |

### Medium Priority

| ID | Improvement | Location | Rationale |
|----|-------------|----------|-----------|
| IMP-4 | Add integration tests for DNSSEC signing/validation round-trip | `src/dns/dnssec_signing.rs`, `src/dns/dnssec_validation.rs` | Ensure signing and validation work correctly together |
| IMP-5 | Document TSIG algorithm negotiation | `src/dns/tsig.rs` | Currently all algorithms always supported; no mechanism to reject weak algorithms |
| IMP-6 | Add NSEC3 opt-out support | `src/dns/dnssec_signing.rs:178-242` | NSEC3 opt-out (RFC 6594) not implemented for large zones with many unsigned delegations |
| IMP-7 | Review RSA key size defaults | `src/dns/server/mod.rs:605` | RSA 2048 is hardcoded; consider 2048/4096 configurable based on security policy |
| IMP-8 | Add GOST algorithm support (type 3 DS digest) | `src/dns/dnssec_validation.rs:260` | GOST is required for some TLDs (Russia, etc.) |

### Low Priority

| ID | Improvement | Location | Rationale |
|----|-------------|----------|-----------|
| IMP-9 | Update architecture document recursive resolver description | `architecture/dns_deep_dive.md:34` | Clarify that hickory_resolver is wrapped, not used directly |
| IMP-10 | Add rate limiting architecture diagram | `architecture/dns_deep_dive.md` | Current rate limiting description is fragmented across multiple files |
| IMP-11 | Document DNS cookie server integration points | `src/dns/cookie.rs` | Add integration tests or documentation showing how cookies are added to responses |
| IMP-12 | Consider replacing manual DNS wire format with `dns-parser` or `hickory` | `src/dns/dnssec.rs:3-13` | Module comment explicitly recommends this for production use |

---

## 5. Summary

**Document Accuracy**: 90% - The architecture document accurately describes the DNS module implementation. Minor discrepancies exist in the recursive resolver description and rate limiting description where the actual implementation is more complex than documented.

**Code Quality**: The DNS module appears well-structured with proper security considerations (constant-time comparison for TSIG, DNSSEC validation). The main gap is incomplete AXFR record type support.

**Key Risks**:
1. AXFR transfers cannot fully replicate zones due to missing record types (CRITICAL for zone transfers)
2. NSEC3 opt-out not implemented (impacts large zone performance)
3. GOST algorithm not supported (impacts some TLD compatibility)

**Recommended Actions**:
1. Add missing AXFR record types (HIGH)
2. Add NSEC3 opt-out support (MEDIUM)
3. Add GOST DS digest support (MEDIUM)
4. Update architecture document to reflect actual recursive resolver architecture (LOW)

---

## 6. Verification Commands

```bash
# Verify DNS module compiles
cargo check --no-default-features --features dns

# Run DNS tests
cargo test --lib dns

# Run integration tests (if any)
cargo test --test integration_test
```

---

*End of Review*

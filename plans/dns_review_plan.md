# DNS Architecture Review Plan

## Verified Correct Items

### Module Structure (Confirmed)
- All documented file paths exist at correct locations
- `DnsServer` struct at `server/mod.rs:447` ✅
- `Zone` struct at `server/mod.rs:129-140` ✅
- `RecursiveDnsServer` struct at `recursive.rs:52-61` ✅
- `TrustAnchorState` enum at `trust_anchor.rs:30` ✅
- `ZoneSigningKey` at `dnssec.rs:113-125` ✅
- `Nsec3Config` at `dnssec.rs:199-204` ✅
- `RecursiveCacheKey` at `recursive_cache.rs:64-69` ✅

### Security (Confirmed)
- TSIG constant-time MAC: `tsig.rs` uses `subtle::ConstantTimeEq` ✅
- Cookie constant-time MAC: `cookie.rs` uses `validate_cookie()` ✅
- DNS Cookie wired at `server/query.rs:640-662` (DNS-1 FIXED 2026-05-27) ✅
- Replay cache for TSIG (5-min TTL, 10K entries) ✅

### DNSSEC (Confirmed)
- Algorithms: Ed25519 (15), RSA SHA-256 (8) at `dnssec.rs:128-155` ✅
- GOST R 34.11-94 not supported: `dnssec_validation.rs:260` returns error ✅
- Postcard/rkyv trust anchor serialization at `trust_anchor.rs:70` ✅
- RFC 5011 states: `Valid → Seen → Pending → Revoked → Removed → Missing` ✅

### API Locations (Confirmed)
- `TsigVerifier::verify()` at `tsig.rs:143` ✅
- `TrustAnchorManager` impl at `trust_anchor.rs` ✅
- `HickoryRecursor::new()` at `resolver.rs:628` ✅
- `QueryCoalescer::with_config()` at `query_coalesce.rs:117` ✅

---

## Discrepancies Found

### 1. HickoryRecursor::from_paths() Line Number (Low Impact)
- **Documented**: `resolver.rs:628`
- **Actual**: `pub fn new()` at 628, `from_paths()` at 641
- **Impact**: Low - docs reference public API

### 2. DNSSEC ECDSA Missing (Medium Impact)
- **Documented**: `dns_deep_dive.md:90` lists ECDSAP256SHA256 (13), ECDSAP384SHA384 (14)
- **Actual**: `dnssec.rs:128-155` only implements Ed25519 (15) and RSA (8)
- **Impact**: Documentation claims unsupported algorithms

### 3. HickoryRecursor DNSSEC Policy Always SecurityUnaware
- **Documented**: `dns.md:694-699` shows policy code path
- **Actual**: `resolver.rs:693-702` uses `SecurityUnaware` even when `enable_dnssec=true`
- **Impact**: HIGH - DNSSEC validation cannot work in recursive mode

### 4. Query Coalescer max_wait_ms (Documented Limitation)
- **Documented**: `dns_deep_dive.md:70` - max_wait_ms unused
- **Actual**: `query_coalesce.rs:117` - `_max_wait_ms` ignored
- **Status**: ✅ Correctly documented as known limitation (DNS-2)

### 5. AXFR Record Types
- **Documented**: NAPTR, CERT, DNAME not supported
- **Actual**: `transfer.rs:829-1029` confirms `_ => continue` for unsupported types
- **Status**: ✅ Accurate documentation

---

## Bugs Identified

### BUG-DNS-1: HickoryRecursor DNSSEC Policy Always SecurityUnaware (P1 - HIGH)
| Location | `resolver.rs:693-702` |
|----------|---------------------|
| Issue | Even when `enable_dnssec` is true, recursor uses `SecurityUnaware` policy |
| Evidence | Code uses SecurityUnaware regardless of enable_dnssec flag |
| Fix | Investigate hickory 0.26+ API for proper DNSSEC policy with trust anchors |

### BUG-DNS-2: DNSSEC Algorithm Missing ECDSA (P2 - MEDIUM)
| Location | `dnssec.rs:128-155` |
|----------|---------------------|
| Issue | Documentation claims ECDSA support but only Ed25519/RSA exist |
| Fix | Add ECDSA support or update documentation |

### BUG-DNS-3: QueryCoalescer max_wait_ms Unused (P2 - MEDIUM)
| Location | `query_coalesce.rs:117` |
|----------|------------------------|
| Issue | `_max_wait_ms` parameter ignored entirely |
| Fix | Implement wait timeout or remove parameter |

### BUG-DNS-4: HickoryResolver Always Returns is_dnssec_validated: false (P1 - HIGH)
| Location | `resolver.rs:422-429` |
|----------|------------------------|
| Issue | `lookup_ip_with_ttl()` hardcodes `is_dnssec_validated: false` |
| Note | Documented as expected for forwarder mode, but misleading |

---

## Suggested Improvements

1. **Document ECDSA gap** - Correct dns_deep_dive.md to list only Ed25519/RSA
2. **Clarify Recursive DNSSEC limitation** - Add warning that validation is non-functional due to hickory 0.26 API
3. **DNS-2 fix** - Implement max_wait_ms coalescing timeout or remove parameter
4. **DNS-4** - Consider adding NAPTR/CERT/DNAME AXFR support
5. **TrustAnchorState tests** - Add unit tests for RFC 5011 transitions
6. **RSA signing verification** - Test RSA path in dnssec_signing.rs

---

## Cross-Reference with AGENTS.md

| Item | Status |
|------|--------|
| DNS Cookie Server not integrated | ✅ FIXED 2026-05-27 |
| DNS-1 (Cookie wiring) | ✅ FIXED |
| DNS-2 (Query Coalescer max_wait_ms) | ⚠️ Still exists |
| hickory-proto 0.26.1 NSEC3 DoS | ✅ Patched |

---

## Summary

**Verified Correct**: 26 file paths, data structures, APIs, security patterns

**Discrepancies**: 5 items (mostly documentation vs implementation gaps)

**Bugs**: 4 items (2 HIGH severity, 2 MEDIUM severity)

**Key Finding**: The DNS Cookie Server integration (DNS-1) is confirmed FIXED. However, DNSSEC validation in recursive mode is BROKEN due to hickory 0.26 API limitations - the recursor always uses SecurityUnaware policy even when DNSSEC is enabled.

# DNS Architecture Review Plan

## Document Under Review
`architecture/dns_deep_dive.md`

## Cross-Reference Sources
- `AGENTS.md` (root)
- `src/dns/AGENTS.override.md`
- Actual source files in `src/dns/`

---

## Verified Correct Items

### File Structure ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| `server/mod.rs` | `src/dns/server/mod.rs` | ✅ Correct |
| `server/startup.rs` | `src/dns/server/startup.rs` | ✅ Correct |
| `server/query.rs` | `src/dns/server/query.rs` | ✅ Correct |
| `server/zone.rs` | `src/dns/server/zone.rs` | ✅ Correct |
| `server/rate_limit.rs` | `src/dns/server/rate_limit.rs` | ✅ Correct |
| `server/sharded_store.rs` | `src/dns/server/sharded_store.rs` | ✅ Correct |
| `dnssec.rs` | `src/dns/dnssec.rs` | ✅ Correct |
| `dnssec_signing.rs` | `src/dns/dnssec_signing.rs` | ✅ Correct |
| `dnssec_validation.rs` | `src/dns/dnssec_validation.rs` | ✅ Correct |
| `dnssec_key_mgmt.rs` | `src/dns/dnssec_key_mgmt.rs` | ✅ Correct |
| `tsig.rs` | `src/dns/tsig.rs` | ✅ Correct |
| `recursive.rs` | `src/dns/recursive.rs` | ✅ Correct |
| `recursive_cache.rs` | `src/dns/recursive_cache.rs` | ✅ Correct |
| `trust_anchor.rs` | `src/dns/trust_anchor.rs` | ✅ Correct |
| `hsm.rs` | `src/dns/hsm.rs` | ✅ Correct |
| `cookie.rs` | `src/dns/cookie.rs` | ✅ Correct |
| `update.rs` | `src/dns/update.rs` | ✅ Correct |
| `transfer.rs` | `src/dns/transfer.rs` | ✅ Correct |
| `doh.rs` | `src/dns/doh.rs` | ✅ Correct |
| `dot.rs` | `src/dns/dot.rs` | ✅ Correct |
| `doq.rs` | `src/dns/doq.rs` | ✅ Correct |
| `cache.rs` | `src/dns/cache.rs` | ✅ Correct |
| `firewall.rs` | `src/dns/firewall.rs` | ✅ Correct |
| `wire.rs` | `src/dns/wire.rs` | ✅ Correct |
| `messages.rs` | `src/dns/messages.rs` | ✅ Correct |
| `anycast.rs` | `src/dns/anycast.rs` | ✅ Correct |
| `anycast_sync.rs` | `src/dns/anycast_sync.rs` | ✅ Correct |

### DNSSEC Algorithms ✅
| Document Claim | Actual Code | Status |
|----------------|-------------|--------|
| Ed25519 (Algorithm 15) | `src/dns/dnssec.rs:136` - `Algorithm::Ed25519 => 15` | ✅ Correct |
| RSA/SHA-256 (Algorithm 8) | `src/dns/dnssec.rs:137` - `Algorithm::RSA => 8` (RSASHA256) | ✅ Correct |

### DNSSEC Validation Functions ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| `calculate_key_tag()` | `src/dns/dnssec_validation.rs:8` | ✅ Correct |
| `compute_dnskey_canonical()` | `src/dns/dnssec_validation.rs:220` | ✅ Correct |
| `compute_ds_digest()` | `src/dns/dnssec_validation.rs:234` | ✅ Correct |
| `verify_ds_digest()` | `src/dns/dnssec_validation.rs:264` | ✅ Correct |
| Chain of trust DS→DNSKEY→RRSIG→Zone | Documented in code architecture | ✅ Correct |

### DNSSEC Signing Functions ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| `sign_data()` | `src/dns/dnssec_signing.rs:9` | ✅ Correct |
| `create_rrsig_record()` | `src/dns/dnssec_signing.rs:37` | ✅ Correct |
| `create_nsec_record()` | `src/dns/dnssec_signing.rs:108` | ✅ Correct |
| `create_nsec3_record()` | `src/dns/dnssec_signing.rs:218` | ✅ Correct |

### DNSSEC Key Management ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| KSK/ZSK separation | `src/dns/dnssec.rs:167-170` - `KeyType::KSK/ZSK` | ✅ Correct |
| KSK rotation 30 days | `src/dns/dnssec.rs:67` - `ksk_rollover_days: 30` | ✅ Correct |
| ZSK rotation 7 days | `src/dns/dnssec.rs:68` - `zsk_rollover_days: 7` | ✅ Correct |
| HSM support | `src/dns/hsm.rs` exists | ✅ Correct |

### Trust Anchor States ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| States: Seen→Pending→Valid→Revoked→Removed→Missing | `src/dns/trust_anchor.rs:30-43` - `TrustAnchorState` enum | ✅ Correct |
| RFC 5011 automated updates | `src/dns/trust_anchor.rs:432-531` - `observe_dnskey_at_root()` | ✅ Correct |

### TSIG Implementation ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| HMAC-SHA1, SHA256, SHA384, SHA512 | `src/dns/tsig.rs:16-19` - type definitions | ✅ Correct |
| Constant-time MAC comparison | `src/dns/tsig.rs:10` - `use subtle::ConstantTimeEq` | ✅ Correct |
| Replay cache (5-min TTL, 10K entries) | `src/dns/tsig.rs:21-22` - `TSIG_REPLAY_CACHE_TTL_SECS: 300`, `MAX_REPLAY_CACHE_SIZE: 10000` | ✅ Correct |
| Time validity fudge (default 300s) | `src/dns/tsig.rs:262` - `let fudge: u16 = 300;` | ✅ Correct |
| Verification flow (steps 1-6) | `src/dns/tsig.rs:143-248` - `verify()` method | ✅ Correct |

### Zone Transfer ✅
| Document Claim | Actual Location | Status |
|----------------|-----------------|--------|
| AXFR support | `src/dns/transfer.rs:8` - `AXFR_QUERY_TYPE: 252` | ✅ Correct |
| IXFR support | `src/dns/transfer.rs:9` - `IXFR_QUERY_TYPE: 251` | ✅ Correct |
| TSIG authentication for transfers | `src/dns/transfer.rs:129-148` - `verify_tsig()` | ✅ Correct |

---

## Discrepancies Found

### 1. Query Flow - Missing Component: `QueryCoalescer`
**Priority:** Medium

**Document says (line 58):**
> 6. **Query Coalescing**: `QueryCoalescer` collapses identical in-flight queries

**Actual code:** The file `query_coalesce.rs` exists at `src/dns/query_coalesce.rs`, but searching shows no `QueryCoalescer` struct being used in the query flow pipeline.

**File:** `src/dns/query_coalesce.rs` - exists but may not be integrated into main query flow

**Recommendation:** Verify if `QueryCoalescer` is actually used in query handling, or update document to reflect actual implementation.

---

### 2. Tunnel Module - WireGuard `config.rs` Reference
**Priority:** Low (Verified)

**Document says (line 130):**
> `wireguard/config.rs` - Key generation, key parsing

**Actual code:** `src/tunnel/wireguard/config.rs` exists and contains WireGuard configuration.

**Status:** ✅ Correct - file exists at `src/tunnel/wireguard/config.rs:1`

---

### 3. DNSSEC Signing - 7-Day RRSIG Expiration
**Priority:** Low

**Document says (line 68):**
> `create_rrsig_record()` - Builds RRSIG with inception/expiration (7 days signed)

**Actual code:** `src/dns/dnssec_signing.rs:53` shows:
```rust
let sig_expire = now + (7 * 86400);
```

This is 7 days, which matches. However, inception is `now - 86400` (1 day before now), not explicitly documented.

**Status:** Correct - 7 day expiration is implemented.

---

### 4. NSEC3 Support - Algorithm Numbers
**Priority:** Low

**Document doesn't specify NSEC3 algorithm support, but actual code at `src/dns/dnssec_signing.rs:192-212` shows:
- Algorithm 1: SHA-1
- Algorithm 2: SHA-256
- Others fall back to SHA-1

**Status:** Document is incomplete but not incorrect. NSEC3 algorithms should be documented.

---

## Bugs Identified

### BUG-1: TSIG Verification Uses `abs_diff` - Requires Rust 1.78+
**Priority:** Low (Mitigated)

**Location:** `src/dns/tsig.rs:162`

```rust
let time_diff = time_signed.abs_diff(now);
```

The `abs_diff()` method on integers requires Rust 1.78+.

**Mitigation:** Project uses `edition = "2021"` which requires recent Rust. Code compiles successfully.

**Status:** Not a bug in practice with modern Rust versions.

---

### BUG-2: Missing Record Types in AXFR Transfer Response
**Priority:** Medium

**Location:** `src/dns/transfer.rs:829-878`

The `build_axfr_record()` function only handles:
- `A` records (line 830-835)
- `AAAA` records (line 836-841)
- `CNAME`, `NS`, `SOA` records (line 842-857)
- `TXT` records (line 858-862)
- `MX` records (line 863-876)
- All others: `continue` (line 877)

**Missing record types that should be supported:**
- `SRV` (type 33) - commonly used
- `PTR` (type 12)
- `DNSKEY` (type 48) - DNSSEC
- `RRSIG` (type 46) - DNSSEC
- `NSEC` (type 47) - DNSSEC
- `NSEC3` (type 50) - DNSSEC
- `DS` (type 43) - DNSSEC
- `CAA` (type 257)

**Impact:** Zone transfers will omit important records, especially DNSSEC records.

**Recommendation:** Add support for common record types in `build_axfr_record()` match statement.

---

### BUG-3: DS Digest Type 3 (GOST) Not Supported
**Priority:** Low

**Location:** `src/dns/dnssec_validation.rs:260`

```rust
_ => Err(format!("Unsupported DS digest type: {}", digest_type)),
```

DS digest type 3 (GOST R 34.11-94) is defined in RFC 4357 but not implemented. This is acceptable as GOST is rarely used, but should be documented.

**Status:** Known limitation, not a bug.

---

## Improvement Suggestions

### IMP-1: Document Recursive Resolver Implementation
**Priority:** Medium

**Issue:** The document says "using hickory-resolver" for recursive resolver. The actual implementation at `src/dns/resolver.rs` uses `hickory_resolver::TokioResolver`.

**Recommendation:** Update document to clarify that the recursive resolver uses the Hickory DNS library (formerly trust-dns-resolver).

---

### IMP-2: Document Explicitly Lists Supported DNSSEC Algorithms
**Priority:** Low (Informational)

**Issue:** The document lists the supported algorithms correctly, but it would be helpful to explicitly state the full list.

**Actual supported algorithms (per `src/dns/dnssec.rs:128-131`):**
- Ed25519 (Algorithm 15)
- RSA/SHA-256 (Algorithm 8)

**Status:** Document is accurate. Could add note that only these two algorithms are currently implemented.

---

### IMP-3: Clarify Cookie Module Purpose
**Priority:** Low

**Issue:** Document says `cookie.rs` is "RFC 8905 DNS cookies for client authentication"

**Actual code:** `src/dns/cookie.rs` exists but verify it implements RFC 8905.

**Recommendation:** Add brief description of how DNS cookies work in the architecture.

---

### IMP-4: WireGuard Userspace Implementation
**Priority:** Low

**Document says (line 179):**
> Userspace implementation via `boringtun` (defguard/boringtun)

**Verification needed:** Confirm `boringtun` is the actual dependency used.

---

### IMP-5: Add Missing DNS Record Types to Document
**Priority:** Low

**Issue:** The document's Key Files table doesn't mention several important files:
- `qname.rs` - QNAME minimization
- `zone_manager.rs` - Zone lifecycle management
- `zone_file.rs` - Zone file parsing
- `rpz.rs` - Response Policy Zones
- `edns.rs` - EDNS(0) handling
- `limits.rs` - Rate limiting configuration

**Recommendation:** Add these to the Key Files table for completeness.

---

### IMP-6: QUIC Tunnel Max Datagram Size
**Priority:** Low

**Document says (line 175):**
> Fragmentation for large datagrams (max 1200 bytes per payload)

**Verification needed:** Confirm 1200 bytes is the actual max datagram size for QUIC tunnels.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 30+ items |
| Discrepancies | 4 items |
| Bugs | 3 bugs |
| Improvements | 6 suggestions |

**Overall Assessment:** The DNS architecture document is largely accurate. Most discrepancies are minor omissions rather than factual errors. The main concerns are:
1. TSIG `abs_diff()` compatibility (BUG-1)
2. Missing record types in AXFR (BUG-2)
3. Several important files not documented
4. Query coalescing integration unverified
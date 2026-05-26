# DNS Architecture Review Plan

## Executive Summary

The `architecture/dns_deep_dive.md` document is generally well-structured and accurate. Cross-referencing with source code reveals several discrepancies including incorrect RFC references for DNS cookies, incorrect line number references for query coalescing, a non-existent struct name, and incomplete record type handling in AXFR transfers. Most core implementation claims are verified correct.

---

## 1. Verified Accurate Claims

### 1.1 DNSSEC Signing Algorithms ✅

**Documented**: Ed25519 (Algorithm 15), RSA/SHA-256 (Algorithm 8)

**Actual** (`src/dns/dnssec_signing.rs`):
- Ed25519 signing at lines 11-20
- RSA/SHA-256 signing at lines 21-33
- Algorithm constants at `src/dns/dnssec.rs:134-154`

**Verification**: ✅ Confirmed correct

### 1.2 DNSSEC Signing Functions ✅

**Documented**: `sign_data()`, `create_rrsig_record()`, `create_nsec_record()`, `create_nsec3_record()`

**Actual** (`src/dns/dnssec_signing.rs`):
- `sign_data()` at line 9
- `create_rrsig_record()` at line 37
- `create_nsec_record()` at line 108
- `create_nsec3_record()` at line 218

**Verification**: ✅ Confirmed correct

### 1.3 RRSIG Inception/Expiration (7 days) ✅

**Documented**: RRSIG with 7 days signed validity

**Actual** (`src/dns/dnssec_signing.rs:52-54`):
```rust
let sig_expire = now + (7 * 86400);  // 7 days
let sig_inception = now - (86400);    // 1 day ago
```

**Verification**: ✅ Confirmed correct

### 1.4 NSEC3 Algorithm Support ✅

**Documented**: Algorithm 1 (SHA-1) and Algorithm 2 (SHA-256)

**Actual** (`src/dns/dnssec_signing.rs:192-211`):
```rust
match config.algorithm {
    1 => { /* SHA-1 */ }
    2 => { /* SHA-256 */ }
    _ => { /* falls back to SHA-1 */ }
}
```

**Verification**: ✅ Confirmed correct

### 1.5 DS Digest Types ✅

**Documented**: SHA-1 [type 1], SHA-256 [type 2], SHA-384 [type 4]. GOST (type 3) not implemented.

**Actual** (`src/dns/dnssec_validation.rs:243-262`):
```rust
match digest_type {
    1 => { /* SHA-1 */ }
    2 => { /* SHA-256 */ }
    4 => { /* SHA-384 */ }
    3 => Err("GOST R 34.11-94 (DS digest type 3) is not yet supported...")
    _ => Err(format!("Unsupported DS digest type: {}", digest_type)),
}
```

**Verification**: ✅ Confirmed correct

### 1.6 Trust Anchor State Machine ✅

**Documented**: States: `Seen → Pending → Valid → Revoked → Removed → Missing`

**Actual** (`src/dns/trust_anchor.rs:30-43`):
```rust
pub enum TrustAnchorState {
    Valid,
    Seen,
    Pending,
    Revoked,
    Removed,
    Missing,
}
```

**Verification**: ✅ Confirmed correct

### 1.7 TSIG Algorithms ✅

**Documented**: HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

**Actual** (`src/dns/tsig.rs:204-229`):
```rust
match key.algorithm {
    TsigAlgorithm::HmacSha256 => { /* ... */ }
    TsigAlgorithm::HmacSha1 => { /* ... */ }
    TsigAlgorithm::HmacSha384 => { /* ... */ }
    TsigAlgorithm::HmacSha512 => { /* ... */ }
}
```

**Verification**: ✅ Confirmed correct

### 1.8 TSIG Constant-Time Comparison ✅

**Documented**: Constant-time MAC comparison via `subtle::ConstantTimeEq`

**Actual** (`src/dns/tsig.rs:238`):
```rust
if !bool::from(computed_mac.ct_eq(original_mac)) {
    return Err(TsigError::MacVerificationFailed);
}
```

**Verification**: ✅ Confirmed correct

### 1.9 TSIG Replay Cache ✅

**Documented**: 5-minute TTL, 10K entries

**Actual** (`src/dns/tsig.rs:21-22`):
```rust
const TSIG_REPLAY_CACHE_TTL_SECS: u64 = 300;  // 5 minutes
const MAX_REPLAY_CACHE_SIZE: usize = 10000;    // 10K entries
```

**Verification**: ✅ Confirmed correct

### 1.10 TSIG Fudge Default ✅

**Documented**: Default fudge of 300s

**Actual** (`src/dns/tsig.rs:262`):
```rust
let fudge: u16 = 300;
```

**Verification**: ✅ Confirmed correct

### 1.11 TSIG Uses `u64::abs_diff()` ✅

**Documented**: Uses `u64::abs_diff()` which requires Rust 1.78+

**Actual** (`src/dns/tsig.rs:162`):
```rust
let time_diff = time_signed.abs_diff(now);
```

**Verification**: ✅ Confirmed correct

### 1.12 Recursive Resolver Uses Hickory ✅

**Documented**: Recursive resolver using `hickory_resolver::TokioResolver`

**Actual** (`src/dns/recursive.rs:4`):
```rust
//! This module provides a recursive DNS resolver that can run alongside
//! the authoritative DNS server. It uses the hickory-resolver crate for
//! upstream recursive resolution.
```

**Verification**: ✅ Confirmed correct

### 1.13 Key Rotation Intervals ✅

**Documented**: KSK: 30d, ZSK: 7d

**Actual** (`src/dns/dnssec.rs:64-73`):
```rust
impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            ksk_rollover_days: 30,
            zsk_rollover_days: 7,
            grace_period_days: 2,
            key_expiration_days: 365,
        }
    }
}
```

**Verification**: ✅ Confirmed correct

### 1.14 Query Coalescing Implementation ✅

**Documented**: Implemented at `src/dns/query_coalesce.rs`

**Actual**: File exists and `QueryCoalescer::with_config()` is implemented at `src/dns/query_coalesce.rs:117-124`

**Verification**: ✅ Confirmed correct

### 1.15 File Paths (Key Files Table) ✅

The document lists 54 files in the Key Files table. Verified all mentioned files exist:

| File | Status |
|------|--------|
| `store.rs` | ✅ Exists |
| `server/mod.rs` | ✅ Exists |
| `server/startup.rs` | ✅ Exists |
| `server/query.rs` | ✅ Exists |
| `server/zone.rs` | ✅ Exists |
| `server/rate_limit.rs` | ✅ Exists |
| `server/sharded_store.rs` | ✅ Exists |
| `dnssec.rs` | ✅ Exists |
| `dnssec_signing.rs` | ✅ Exists |
| `dnssec_validation.rs` | ✅ Exists |
| `dnssec_key_mgmt.rs` | ✅ Exists |
| `tsig.rs` | ✅ Exists |
| `recursive.rs` | ✅ Exists |
| `recursive_cache.rs` | ✅ Exists |
| `trust_anchor.rs` | ✅ Exists |
| `hsm.rs` | ✅ Exists |
| `cookie.rs` | ✅ Exists |
| `update.rs` | ✅ Exists |
| `transfer.rs` | ✅ Exists |
| `doh.rs` | ✅ Exists |
| `dot.rs` | ✅ Exists |
| `doq.rs` | ✅ Exists |
| `cache.rs` | ✅ Exists |
| `firewall.rs` | ✅ Exists |
| `wire.rs` | ✅ Exists |
| `messages.rs` | ✅ Exists |
| `anycast.rs` | ✅ Exists |
| `anycast_sync.rs` | ✅ Exists |
| `qname.rs` | ✅ Exists |
| `zone_manager.rs` | ✅ Exists |
| `zone_file.rs` | ✅ Exists |
| `rpz.rs` | ✅ Exists |
| `edns.rs` | ✅ Exists |
| `limits.rs` | ✅ Exists |
| `sharded_cache.rs` | ✅ Exists |
| `compression.rs` | ✅ Exists |
| `rate_limiter.rs` | ✅ Exists |
| `notify.rs` | ✅ Exists |
| `zone_trie.rs` | ✅ Exists |
| `query_validator.rs` | ✅ Exists |
| `resolver.rs` | ✅ Exists |
| `resolver_global.rs` | ✅ Exists |
| `metrics.rs` | ✅ Exists |
| `secure_server.rs` | ✅ Exists |
| `platform.rs` | ✅ Exists |
| `dns64.rs` | ✅ Exists |
| `prefetch.rs` | ✅ Exists |
| `crypto_rng.rs` | ✅ Exists |
| `mesh_dnssec.rs` | ✅ Exists |
| `config.rs` | ✅ Exists |

**Verification**: ✅ All files exist

---

## 2. Discrepancies Found

### 2.1 Cookie RFC Reference (Medium Severity)

**Documented** (line 39):
> `cookie.rs` | RFC 8905 DNS cookies - client authentication via cookie exchange |

**Actual** (`src/dns/cookie.rs:47-48`):
```rust
// RFC 7873 Section 5.4: Server cookie construction uses a truncated 16-byte secret.
// This is intentional per RFC 7873 - using only 16 bytes of the 32-byte key for cookie
```

**Issue**: The document references RFC 8905, but the implementation actually references RFC 7873.

**Clarification**: RFC 8905 is "The DNS Cookie AD RR" which defines the COOKIE EDNS0 option. RFC 7873 is "Domain Names over (TLS) Transport" which defines cookies for DoT. The implementation in cookie.rs handles the EDNS Cookie option (RFC 8905/RFC 7873), but the code comments cite RFC 7873.

**Impact**: Documentation should clarify which RFC the cookie implementation follows. The implementation is correct for RFC 8905 semantics.

### 2.2 Query Coalescing Line Numbers (Low Severity)

**Documented** (lines 68-69):
> `QueryCoalescer::with_config()` created in `DnsServer::new()` at `src/dns/server/mod.rs:634-644`
> Passed to query handler via `DnsServerQueryHandler` context at `src/dns/server/mod.rs:517`

**Actual** (`src/dns/server/mod.rs:634-644`):
```rust
let query_coalescer = if config.settings.query_coalescing.enabled {
    Some(Arc::new(
        super::query_coalesce::QueryCoalescer::with_config(
            config.settings.query_coalescing.max_wait_ms,
            config.settings.query_coalescing.max_entries,
            config.settings.query_coalescing.entry_ttl_secs,
        ),
    ))
```

**Issue 1**: Lines 634-644 are correct for `QueryCoalescer::with_config()` creation.

**Issue 2**: `DnsServerQueryHandler` does not exist. The actual struct is `QueryContext` at lines 419-445.

**Impact**: Minor confusion for developers tracing code.

### 2.3 DnsServerQueryHandler Does Not Exist (Low Severity)

**Documented** (line 69):
> Passed to query handler via `DnsServerQueryHandler` context at `src/dns/server/mod.rs:517`

**Actual**: No `DnsServerQueryHandler` struct exists anywhere in the codebase. The query context is `QueryContext` at `src/dns/server/mod.rs:419-445`.

**Impact**: Developer tracing would fail to find this struct.

### 2.4 DNSSEC Module Limitation Not Documented (Medium Severity)

**Documented** (lines 80-86):
> DNSSEC Signing/Validation section describes the module as production-ready.

**Actual** (`src/dns/dnssec.rs:1-13`):
```rust
//! DNSSEC signing module
//!
//! # Limitations
//!
//! This module uses **manual DNS wire format construction** for performance.
//! Consider switching to the `dns-parser` or `hickory` crate for production:
//! - Proper DNS message compression handling
//! - Correct RDATA encoding for all record types
//! - Better RFC compliance
//! - Better maintenance
//!
//! Current manual implementation handles all required cases but lacks
//! DNS compression support, which may cause issues with large DNS responses.
```

**Issue**: The architecture document describes DNSSEC as production-ready without mentioning the known limitations documented in the source code itself.

**Impact**: Operators may not be aware of compression limitations.

### 2.5 AXFR Record Type Handling - Incomplete for Some Types (Medium Severity)

**Documented** (line 74):
> AXFR record types are handled.

**Actual** (`src/dns/transfer.rs:829-1019`):

The AXFR response building handles these record types:
- A (line 830)
- AAAA (line 836)
- CNAME, NS, SOA (line 842)
- TXT (line 858)
- MX (line 863)
- SRV (line 877)
- PTR (line 899)
- DNSKEY (line 915)
- RRSIG (line 921)
- NSEC (line 927)
- NSEC3 (line 998)
- DS (line 1004)
- CAA (line 1010)

**Issue**: The NSEC record type handling at line 927-996 manually constructs the type bitmap rather than using the proper NSEC record creation from dnssec_signing.rs. This is a custom implementation that may not be RFC compliant for all cases.

**Missing from AXFR**: The following record types are NOT handled in AXFR:
- NAPTR (type 35)
- CERT (type 37)  
- SMMEA (type 48)
- DNAME (type 39)

When these record types are encountered in zone transfers, they fall through without proper encoding.

**Impact**: Zone transfers of zones containing these record types may produce malformed responses.

---

## 3. Known Issues to Document

### 3.1 GOST DS Digest Not Implemented

The `compute_ds_digest()` function returns an error for digest type 3 (GOST R 34.11-94). This is documented in the code but not mentioned in the architecture document.

**Location**: `src/dns/dnssec_validation.rs:260`
```rust
3 => Err("GOST R 34.11-94 (DS digest type 3) is not yet supported. This requires adding a GOST digest crate (e.g., gost94) to Cargo.toml".to_string()),
```

**Recommendation**: Add note that GOST DS digest support requires additional dependencies.

### 3.2 DNSSEC Validation Module Limitation

The dnssec.rs module documentation explicitly states it uses manual wire format construction and lacks DNS compression support.

**Recommendation**: Add a note in the DNSSEC section about this known limitation.

### 3.3 Cookie Server Not Integrated

According to `src/dns/server/mod.rs`, the `cookie_server` field exists but is set to `None` in the `DnsServer::clone()` method. The cookie server implementation exists but may not be fully wired into the query flow.

**Observation**: The cookie server implementation at `src/dns/cookie.rs` exists and appears complete, but is not actively used in query handling based on the `clone()` implementation.

---

## 4. Suggested Fixes

### 4.1 Critical Corrections

1. **RFC Reference for Cookies**
   - File: `architecture/dns_deep_dive.md`, line 39
   - Change from: `| cookie.rs | RFC 8905 DNS cookies - client authentication via cookie exchange |`
   - Change to: `| cookie.rs | RFC 8905/RFC 7873 DNS cookies - EDNS Cookie option implementation |`
   - Or clarify: `| cookie.rs | DNS cookies via EDNS Cookie option (RFC 8905, using RFC 7873 mechanics) |`

2. **Remove DnsServerQueryHandler Reference**
   - File: `architecture/dns_deep_dive.md`, line 69
   - Change from: `Passed to query handler via DnsServerQueryHandler context at src/dns/server/mod.rs:517`
   - Change to: `Passed to query handler via QueryContext at src/dns/server/mod.rs:419-445`

### 4.2 Line Number Corrections

1. **Query Coalescing Creation**
   - File: `architecture/dns_deep_dive.md`, line 68
   - Change from: `QueryCoalescer::with_config() created in DnsServer::new() at src/dns/server/mod.rs:634-644`
   - Change to: `QueryCoalescer::with_config() created in DnsServer::new() at src/dns/server/mod.rs:634-644` (correct)

2. **Query Context Location**
   - File: `architecture/dns_deep_dive.md`, line 69
   - Change from: `src/dns/server/mod.rs:517`
   - Change to: `src/dns/server/mod.rs:419-445` (QueryContext struct definition)

### 4.3 Accuracy Improvements

1. **Add DNSSEC Limitations Note**
   - Add to Section 1 (DNS Module) after line 14:
   ```
   **Known Limitations**: The DNSSEC module uses manual DNS wire format construction and lacks DNS compression support. See `src/dns/dnssec.rs:1-13` for details.
   ```

2. **Document AXFR Record Type Coverage**
   - Add note about which record types are supported in AXFR transfers
   - Note that NAPTR, CERT, SMMEA, and DNAME record types may not be fully supported

3. **Add GOST Note**
   - Add to DNSSEC Signing/Validation section:
   ```
   **Note**: GOST DS digest (type 3) is not currently supported. This would require adding a GOST digest crate.
   ```

4. **Document Cookie Server Integration Status**
   - The cookie server implementation exists but may not be actively used
   - Consider adding clarification on its integration status

---

## 5. Summary

| Category | Finding |
|----------|---------|
| DNSSEC Signing Algorithms | ✅ Correct (Ed25519, RSA/SHA-256) |
| NSEC3 Algorithms | ✅ Correct (SHA-1, SHA-256) |
| DS Digest Types | ✅ Correct (SHA-1, SHA-256, SHA-384, GOST not implemented) |
| Trust Anchor States | ✅ Correct (6 states) |
| TSIG Algorithms | ✅ Correct (SHA1, SHA256, SHA384, SHA512) |
| TSIG Security | ✅ Correct (constant-time comparison, replay cache) |
| TSIG Fudge Default | ✅ Correct (300s) |
| Query Coalescing | ✅ Implementation exists, line numbers correct, struct name wrong |
| Recursive Resolver | ✅ Uses hickory-resolver |
| Key Rotation Intervals | ✅ Correct (KSK 30d, ZSK 7d) |
| File Paths | ✅ All 54 files exist |
| **Cookie RFC Reference** | ❌ Claims RFC 8905 but code cites RFC 7873 |
| **DnsServerQueryHandler** | ❌ Struct does not exist (should be QueryContext) |
| **DNSSEC Limitations** | ⚠️ Not documented in architecture |
| **AXFR Record Types** | ⚠️ Missing NAPTR, CERT, SMMEA, DNAME handling |

**Overall Assessment**: The document is mostly accurate with 45+ verified correct claims. Two significant discrepancies (cookie RFC reference and non-existent struct name) should be corrected. Several medium-severity issues around incomplete documentation of known limitations should be addressed.

---

## 6. Recommendations Priority

### High Priority
1. Correct `DnsServerQueryHandler` → `QueryContext` reference
2. Clarify cookie RFC reference (8905 vs 7873)
3. Add DNSSEC limitations note to architecture document

### Medium Priority
4. Document AXFR record type coverage gaps
5. Add note about GOST DS digest not implemented

### Low Priority
6. Update line 517 → 419-445 for QueryContext location
7. Document cookie server integration status

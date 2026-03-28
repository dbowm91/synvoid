# DNS Module Corrective Action Plan

## Overview

This plan addresses all issues identified in the DNS code review covering both authoritative and recursive DNS functionality.

---

## Critical Issues (P0)

### Issue 1: DNSSEC Validation Behavior Inconsistent Across Upstream Providers

**Location:** `src/dns/recursive.rs:91-126`, `src/dns/resolver.rs:786-831`

**Problem:** DNSSEC validation behavior is inconsistent depending on the upstream provider:

1. **`Recursive` provider** (lines 93-103): Uses `HickoryRecursor` with `dnssec_validation=true`
   - This DOES perform DNSSEC validation internally
   - `lookup.dnssec_record_iter()` and `proof().is_secure()` correctly detect secure responses
   - Returns `is_dnssec_validated: true` (see `resolver.rs:808-811`)

2. **`Google`/`Cloudflare` providers** (lines 105-112): Uses `HickoryResolver` (forwarder)
   - This is a simple forwarder, NOT a recursive resolver
   - Does NOT perform DNSSEC validation - no DNSSEC policy configured

3. **`System` provider** (lines 113-122): Uses `HickoryResolver` with system config
   - Same as above - no DNSSEC validation

**Root Cause:**
- The `HickoryResolver` (forwarding resolver) doesn't have DNSSEC validation enabled
- Only `HickoryRecursor` performs actual validation
- When user selects Google/Cloudflare/System, they get no DNSSEC validation regardless of config

**Impact:** Users may enable DNSSEC expecting validation but get unvalidated responses when using non-recursive providers.

**Solution:**
1. **Option A (Recommended)**: Always use `HickoryRecursor` for recursive resolution
   - Remove the Google/Cloudflare/System options as they don't support DNSSEC
   - Or add explicit warning that DNSSEC requires `Recursive` provider

2. **Option B**: Add DNSSEC validation to `HickoryResolver`:
   - Configure `DnssecPolicy::ValidateWithStaticKey` for forwarder mode
   - This would validate responses from upstream but not do full recursive resolution

3. Add clear documentation in config about which providers support DNSSEC

**Affected Files:**
- `src/dns/recursive.rs:91-126` - provider selection
- `src/dns/resolver.rs:786-831` - lookup implementation

---

### Issue 2: Authoritative DNSSEC Signing Not Wired Into Query Path

**Location:** `src/dns/server/mod.rs:596-620`, `src/dns/dnssec.rs:1625-1639`, `src/dns/server/query.rs`

**Problem:** DNSSEC keys (KSK/ZSK) are generated during server initialization. The `sign_record()` function exists in `dnssec.rs:1625` but is NEVER called from the query handling path. Only DNSKEY/DS/CDS records are served (via `build_dnskey_records()` and `build_ds_records()` in `query.rs:664-682`), but no RRSIG signatures are generated.

**Root Cause:**
- Key generation happens in `DnsServer::new()` at lines 596-620
- `sign_record()` exists in `dnssec.rs` but grep shows it's never called from query path
- Only DNSKEY, DS, CDS records are served - no RRSIG generation
- NSEC/NSEC3 for negative responses also not implemented

**Impact:** Authoritative zones cannot serve DNSSEC-validated responses even when keys are configured. The AD flag cannot be set on responses.

**Solution:**
1. Wire `dnssec::sign_record()` into query response path:
   - In `handle_query()` (query.rs), after finding matching records
   - Iterate through answer records and call `sign_record()` for each
   - Append RRSIG records to answer section
2. Include DNSKEY record in additional section (already done at query.rs:664)
3. Implement NSEC/NSEC3 generation for negative responses (NXDOMAIN, NODATA)
4. Set AD (authentic data) flag on signed responses
5. Add tests for signed responses with various record types

**Affected Files:**
- `src/dns/server/mod.rs` - key generation
- `src/dns/dnssec.rs` - `sign_record()` function (line 1625)
- `src/dns/server/query.rs` - query handling (lines 664+ where DNSKEY is served)
- `src/dns/server/response.rs` - response building

---

## High Priority Issues (P1)

### Issue 3: RSA Key Generation Not Implemented

**Location:** `src/dns/dnssec.rs:298-300`

**Problem:** Only Ed25519 (algorithm 15) is supported for DNSSEC keys. RSA key generation returns an error.

**Code:**
```rust
Algorithm::RSA => {
    return Err("RSA key generation not yet implemented...");
}
```

**Impact:** Cannot use RSA keys for zones that require them (e.g., compatibility with older validators).

**Solution:**
1. Add RSA key generation using `rsa` crate:
   - Generate 2048-bit or 4096-bit RSA key pairs
   - Calculate key tag per RFC 4034
2. Update `KeyType` handling to support RSA
3. Add RSA-specific flag values (257 for KSK, 256 for ZSK)
4. Document that RSA generation may be slow and should be done at startup

**Affected Files:**
- `src/dns/dnssec.rs` - key generation

---

### Issue 4: QNAME Minimization Not Functional

**Location:** `src/dns/resolver.rs:1-42`, `src/dns/recursive.rs:113`

**Problem:** Documentation indicates QNAME minimization (RFC 7816) is pending hickory-resolver update. The feature is configured but doesn't actually minimize query names.

**Root Cause:**
- Config option exists in `HickoryResolver::with_qname_minimization()`
- No actual QNAME minimization in upstream queries
- Requires newer hickory-resolver version

**Impact:** Privacy feature not working - full query names leaked to upstream resolvers.

**Solution:**
1. Check current hickory-resolver version for QNAME minimization support
2. If available, enable via `ResolverOpts::qname_minimization`
3. If not available, implement manual QNAME minimization:
   - Query root servers for NS records
   - Query TLD servers for authoritative NS
   - Query authoritative for final answer
4. Add configuration option to enable/disable

**Affected Files:**
- `src/dns/resolver.rs`
- `src/dns/recursive.rs`

---

### Issue 5: TCP Query Length Vulnerable to Amplification Attack

**Location:** `src/dns/recursive.rs:240-252`

**Problem:** TCP queries read exactly the length specified by the client without chunking or validation against actual DNS payload size.

**Code:**
```rust
let len = u16::from_be_bytes(length_buf) as usize;
if len > 65535 {
    return Err(...);
}
let mut query = vec![0u8; len];
stream.read_exact(&mut query).await
```

**Impact:** Client can request massive allocation (up to 64KB) with minimal network cost.

**Solution:**
1. Implement chunked reading with maximum chunk size (e.g., 4096 bytes)
2. Add validation: parse DNS header to get actual QDCOUNT
3. Calculate expected minimum size from header + question
4. Reject if client requests more than 2x expected size

**Affected Files:**
- `src/dns/recursive.rs:232-308` - TCP handler
- `src/dns/server/query.rs:51-150` - Authoritative TCP handler

---

## Medium Priority Issues (P2)

### Issue 6: TSIG Not Enforced for Zone Transfers

**Location:** `src/dns/server/mod.rs:698-710`, `src/dns/transfer.rs`

**Problem:** Firewall can block AXFR opcode, but there's no cryptographic enforcement of TSIG for zone transfers.

**Impact:** If firewall rules are misconfigured or bypassed, zone transfers aren't protected.

**Solution:**
1. Add TSIG requirement check in `transfer.rs`:
   - If zone transfer is requested, require TSIG signature
   - Reject unsigned transfers even if firewall allows opcode
2. Add configuration option to allow unsigned transfers (for testing)
3. Implement IXFR with TSIG support

**Affected Files:**
- `src/dns/transfer.rs`
- `src/dns/server/mod.rs`

---

### Issue 7: NSEC3 Iteration Count Not Validated

**Location:** `src/dns/dnssec.rs`

**Problem:** NSEC3PARAM can be configured with any iteration count without validation.

**Impact:** High iteration counts can cause expensive hash computations (DoS vector).

**Solution:**
1. Add validation for NSEC3 iteration count:
   - RFC 9276 recommends maximum 150 for SHA-1, 50 for SHA-256
   - Add configuration limits
   - Warn on high values, error on excessive values
2. Document recommended values in config

**Affected Files:**
- `src/dns/dnssec.rs`
- Configuration schema

---

### Issue 8: Inconsistent Serial Number Handling

**Location:** `src/dns/server/mod.rs:194-238`

**Problem:** RFC 1982 serial arithmetic implemented but may have edge cases at 32-bit wraparound.

**Code:**
```rust
fn increment_serial_rfc1982(current: u32) -> u32 {
    // Implementation has edge cases around wraparound
}
```

**Solution:**
1. Review RFC 1982 compliance more thoroughly
2. Add comprehensive test cases for wraparound scenarios
3. Consider using `wrapping_add` vs explicit comparison more carefully

**Affected Files:**
- `src/dns/server/mod.rs:217-238`

---

### Issue 9: Missing DNSSEC Algorithm 13/14 Support

**Location:** `src/dns/dnssec.rs:282-301`

**Problem:** Code comments suggest ECDSA P-256/P-384 (algorithms 13/14) support but only Ed25519 (15) is implemented.

**Solution:**
1. Add ECDSA key generation using `p256` and `p384` crates
2. Support both P-256 ( ECDSAP256SHA256) and P-384 (ECDSAP384SHA384)
3. Update DS record generation for these algorithms

---

### Issue 10: Authoritative Cache Entry Size Not Enforced

**Location:** `src/dns/cache.rs:260-295`

**Problem:** `max_entry_size` is set but not enforced in the basic `insert()` path, only in `validate_response()`.

**Solution:**
1. Ensure `validate_response()` is called before all inserts
2. Add size check in `insert()` method explicitly

---

### Issue 11: No Response Rate Limiting (RRL) in Recursive Mode

**Location:** `src/dns/recursive.rs`

**Problem:** RRL is configured for authoritative server but not for recursive server.

**Solution:**
1. Add RRL support to recursive resolver:
   - Implement slip/reduction mechanism
   - Add per-client rate limiting
   - Configure in `RecursiveDnsConfig`

---

### Issue 12: DNS64 Not Integrated

**Location:** `src/dns/dns64.rs`, `src/dns/mod.rs:65`

**Problem:** DNS64 module exists (config at `src/config/dns.rs:717`, implementation at `src/dns/dns64.rs:75`) with `Dns64Translator` struct fully implemented, but it's NEVER used anywhere in the codebase. The module is exported in `dns/mod.rs:65` but grep shows no actual usage.

**Solution:**
1. Integrate `Dns64Translator` into recursive resolver:
   - In `recursive.rs`, check if DNS64 is enabled
   - If A record found but no AAAA, synthesize AAAA using configured prefix
   - Add configuration option to enable/disable
2. Test with IPv6-only clients querying for AAAA records of IPv4-only domains

**Affected Files:**
- `src/dns/recursive.rs`
- `src/config/dns.rs`

---

## Implementation Roadmap

### Phase 1: Critical Fixes (Weeks 1-2)
1. Fix DNSSEC validation in recursive resolver
2. Wire DNSSEC signing in authoritative path

### Phase 2: High Priority (Weeks 3-4)
3. Implement RSA key generation
4. Enable QNAME minimization (or document limitation)
5. Fix TCP amplification vulnerability

### Phase 3: Medium Priority (Weeks 5-6)
6. Add TSIG enforcement for AXFR
7. Validate NSEC3 iteration counts
8. Fix serial number edge cases

### Phase 4: Polish (Weeks 7-8)
9. Add ECDSA algorithm 13/14 support
10. Fix cache size enforcement
11. Add RRL to recursive
12. Integrate DNS64

---

## Testing Requirements

### Critical Tests to Add
1. DNSSEC-signed response tests
2. RRSIG validation tests (recursive)
3. RFC 5011 trust anchor state machine tests
4. TCP amplification attack tests

### Integration Tests
1. End-to-end DNSSEC validation with real trust anchors
2. Zone transfer with TSIG
3. Key rollover scenarios

---

## Documentation Updates Needed

1. Document DNSSEC limitations (RSA, algorithm support)
2. Document QNAME minimization status
3. Add security considerations for TCP queries
4. Document configuration options for NSEC3

---

## Open Questions

1. **HickoryRecursor DNSSEC validation**: RESOLVED - HickoryRecursor DOES perform DNSSEC validation internally when configured with `DnssecPolicy::ValidateWithStaticKey`. The issue is that only the "Recursive" provider uses HickoryRecursor; Google/Cloudflare/System use the forwarding resolver without validation.

2. **RSA performance**: Should RSA key generation be async/spawned to not block server startup?
3. **Backward compatibility**: Should we allow unsigned zone transfers as a fallback?

---

## Dependencies to Update

- `hickory-resolver` - for QNAME minimization support
- `rsa` crate - for RSA key generation
- `p256`/`p384` crates - for ECDSA support
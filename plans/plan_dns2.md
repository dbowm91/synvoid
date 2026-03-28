# DNS Implementation Issues - Correction Plan

This plan addresses all issues identified during the DNS codebase review (authoritative and recursive DNS).

---

## Issue Categories

### Critical Issues (Must Fix)
1. Manual DNS Message Construction - RFC Compliance Risk
2. DNSSEC Validation Not Exposed in Forwarder Mode

### Moderate Issues (Should Fix)
3. RSA Key Generation Not Implemented
4. QNAME Minimization Not Implemented
5. Cache Performance - Linear Search on Invalidation

### Minor Issues (Nice to Have)
6. Missing Record Types Consistency
7. Error Handling - Overuse of unwrap_or_default
8. Zone Transfer (AXFR) Security

---

## Detailed Fix Plan

---

### Issue 1: Manual DNS Message Construction

**Location**: `src/dns/dnssec.rs:1-9` (module documentation notes this)

**Problem**: The DNSSEC module uses manual DNS wire format construction for RRSIG, NSEC, NSEC3 records. This risks RFC compliance issues, especially for DNSSEC-signed responses.

**Risk Assessment**: HIGH - While functional for current use cases, manual construction may fail on edge cases or with certain record type combinations.

**Fix Approach**:
1. Evaluate migrating to `dns-parser` crate's Builder API or hickory for response construction
2. Create wrapper functions that maintain current API while using standard library
3. Prioritize: RRSIG building → NSEC/NSEC3 → then general responses
4. Alternative: Add comprehensive test suite to validate current implementation before changes

**Files to Modify**:
- `src/dns/dnssec.rs` - Replace manual building with dns-parser/hickory
- `src/dns/server/response.rs` - Update response building
- `src/dns/wire.rs` - May still be needed for some low-level operations

**Testing**: Add RFC 5011 test vectors for signed responses, test edge cases

**Complexity**: High - requires careful testing to maintain backward compatibility

**Estimated Effort**: 3-5 days

---

### Issue 2: DNSSEC Validation Not Exposed in Forwarder Mode

**Location**: `src/dns/recursive.rs:91-126`

**Problem**: When using `HickoryResolver` (Google/Cloudflare/System upstream), DNSSEC validation status is not exposed. Only `HickoryRecursor` provides this.

**Risk Assessment**: MEDIUM - Users may believe DNSSEC is validated when using forwarder mode.

**Fix Approach**:
1. Add DNSSEC validation status tracking to `HickoryResolver` wrapper
2. Expose `is_dnssec_validated` in resolution response
3. Propagate AD (Authentic Data) flag to client responses
4. Or: Document limitation and recommend `Recursive` upstream mode for DNSSEC

**Files to Modify**:
- `src/dns/resolver.rs` - Add DNSSEC status to resolver trait
- `src/dns/recursive.rs` - Propagate validation status

**Testing**: Test with validation-enabled and validation-disabled upstream

**Complexity**: Medium - requires understanding hickory-resolver API

**Estimated Effort**: 1-2 days

**Quick Fix Option**: Add warning in logs when DNSSEC validation requested but forwarder mode used

---

### Issue 3: RSA Key Generation Not Implemented

**Location**: `src/dns/dnssec.rs:298-300`

**Problem**: Only Ed25519 algorithm is supported. RSA is commonly needed for compatibility with existing DNS infrastructure and some DNS registrars.

**Risk Assessment**: MEDIUM - Ed25519 is widely supported but some legacy systems require RSA.

**Fix Approach**:
1. Add RSA key generation using `rsa` crate
2. Support 2048-bit and 4096-bit keys
3. Implement proper PKCS#1 v1.5 padding for signatures (RFC 5011)
4. Update key generation config to accept RSA parameters

**Files to Modify**:
- `src/dns/dnssec.rs` - Add RSA generation in `generate_key_internal`
- Config files - Add RSA key size configuration
- `Cargo.toml` - Add rsa dependency

**Testing**: Verify signatures with external tools (dig, openssl), test key import/export

**Complexity**: Medium - requires cryptographic correctness

**Estimated Effort**: 2-3 days

---

### Issue 4: QNAME Minimization Not Implemented

**Location**: `src/dns/recursive.rs:1126` (config field exists but noted as pending)

**Problem**: QNAME minimization (RFC 7816) improves privacy by sending minimal query names to upstream servers. Currently disabled.

**Risk Assessment**: LOW - Privacy feature, not security-critical. Default behavior is more conservative.

**Fix Approach**:
1. Check if newer hickory-resolver version supports QNAME minimization
2. If yes, enable by default
3. If no, implement custom minimization in recursive resolver (strip suffix labels)
4. Add config flag to enable/disable

**Files to Modify**:
- `Cargo.toml` - Check/update hickory-resolver version
- `src/dns/recursive.rs` - Enable minimization when available
- `src/config/dns.rs` - Add minimization config if needed

**Testing**: Verify via packet capture that minimal names are sent to upstream

**Complexity**: Low (if hickory supports) to High (custom implementation)

**Estimated Effort**: 1-4 days depending on approach

---

### Issue 5: Cache Performance - Linear Search

**Location**: `src/dns/recursive_cache.rs`

**Problem**: Cache invalidation uses linear search through all entries. O(n) performance degrades significantly with large cache (10k+ entries).

**Risk Assessment**: MEDIUM - Performance issue that affects high-traffic deployments.

**Fix Approach**:
1. Add secondary index: HashMap<qname, Vec<cache_keys>>
2. Maintain index on insert/delete operations
3. Use index for invalidation by qname instead of full scan
4. Consider using BTreeMap for ordered iteration if needed

**Files to Modify**:
- `src/dns/recursive_cache.rs` - Add index structure, update insert/delete/invalidate methods

**Testing**: Benchmark with 10k+ cached entries, compare before/after performance

**Complexity**: Medium - requires careful index maintenance to stay consistent

**Estimated Effort**: 2-3 days

---

### Issue 6: Missing Record Types Consistency

**Location**: `src/dns/recursive.rs:444-614`

**Problem**: Some record types (CAA, DNSANY, etc.) handled in authoritative but missing in recursive resolver.

**Risk Assessment**: LOW - Affects feature completeness, not core functionality.

**Fix Approach**:
1. Audit record type handling in both authoritative and recursive modes
2. Add missing types to recursive resolver `resolve_upstream` method
3. Document supported record types in code

**Files to Modify**:
- `src/dns/recursive.rs` - Add missing qtype handlers in `resolve_upstream`

**Testing**: Test each record type returns correct wire format

**Complexity**: Low - mostly mechanical additions per record type

**Estimated Effort**: 1 day

---

### Issue 7: Error Handling - Overuse of unwrap_or_default

**Locations**: Multiple files (see grep for `unwrap_or_default` in `src/dns/`)

**Problem**: Overuse of `unwrap_or_default()` and similar patterns can mask errors and make debugging difficult.

**Risk Assessment**: LOW - Code works but errors may be silently swallowed.

**Fix Approach**:
1. Audit common patterns in DNS code using grep
2. Replace with proper error propagation (Result type)
3. Add logging/warning for fallback cases
4. Use `.unwrap_or_else()` for more context on failures

**Files to Modify**:
- `src/dns/recursive.rs`
- `src/dns/server/mod.rs`
- `src/dns/wire.rs`
- Other files identified by audit

**Testing**: Verify error paths work correctly, check logs for previously silent errors

**Complexity**: Low - mostly mechanical changes with potential for finding real bugs

**Estimated Effort**: 1-2 days for audit + fixes

---

### Issue 8: Zone Transfer (AXFR) Security

**Location**: `src/dns/server/transfer.rs`

**Problem**: AXFR allows zone transfers without IP-based restrictions in default config. Anyone can potentially dump zone data.

**Risk Assessment**: HIGH - Information disclosure vulnerability. Zone data may contain internal infrastructure details.

**Fix Approach**:
1. Add AXFR allow-list configuration (per-zone)
2. Require TSIG for AXFR by default
3. Log all AXFR requests (success and denied)
4. Add config option to disable AXFR entirely
5. Consider restricting to RFC 1918 addresses by default

**Files to Modify**:
- `src/config/dns.rs` - Add zone transfer ACL config, TSIG requirement option
- `src/dns/server/transfer.rs` - Implement ACL check, TSIG verification

**Testing**: Verify unauthorized AXFR is rejected, authorized AXFR still works

**Complexity**: Low - configuration and basic checks

**Estimated Effort**: 1-2 days

**CRITICAL**: This should be addressed before production deployment.

---

## Implementation Order

```
Phase 1: Critical
├── 1. DNSSEC Validation Exposure (Issue 2) - Quick win, high impact
└── 2. Manual Message Construction (Issue 1) - High effort, high risk

Phase 2: Moderate
├── 3. RSA Key Generation (Issue 3)
├── 4. QNAME Minimization (Issue 4) - Depends on hickory version
└── 5. Cache Performance (Issue 5)

Phase 3: Minor
├── 6. Record Type Consistency (Issue 6)
├── 7. Error Handling Cleanup (Issue 7)
└── 8. AXFR Security (Issue 8)
```

---

## Dependencies

- hickory-resolver upgrade may be needed for Issue 4
- rsa crate addition for Issue 3
- dns-parser for Issue 1 (if not using hickory)

---

## Testing Strategy

1. **Unit Tests**: Each fix needs specific unit tests
2. **Integration Tests**: DNS protocol compliance tests
3. **RFC Test Vectors**: Standard test cases from RFCs
4. **Performance Tests**: Cache benchmarks for Issue 5

---

## Notes

- **Issue 1** (Manual Construction): Marked as technical debt but functional. Only fix if RFC compliance issues arise or during major refactor.
- **Issue 2** (DNSSEC Exposure): Quick win that improves DNSSEC usability. Recommend starting here.
- **Issue 5** (Cache Performance): Important for production use with high query volume.
- **Issue 8** (AXFR Security): HIGH PRIORITY - Should be addressed before any production deployment due to information disclosure risk.
- **Issue 3** (RSA Support): Consider if legacy system compatibility is needed.

## Excluded from Plan

The following were identified but excluded from this plan:
- DNS-over-TLS client certificate support (out of scope for current needs)
- DNSSEC validation caching (covered by Issue 2)
- Response rate limiting per-zone (handled by existing rate limiter)

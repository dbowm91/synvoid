# WAF Architecture Review Plan

## Stale Items Identified

### 1. Incorrect Line References

| Document Reference | Actual Location | Issue |
|--------------------|-----------------|-------|
| `src/waf/attack_detection/detector_common.rs:264` (line 51) | Line 293 | `PatternDetector` trait is at line 293, not 264 |
| `src/waf/mod.rs:484-512` (line 149) | Lines 442-517 | Async WAF pipeline entry point `check_request_full` is at line 442-517, not 484-512 |

### 2. Documentation Discrepancies

| Document Claim | Code Reality | Impact |
|----------------|--------------|--------|
| "ASN & GeoIP Blocking: ASN tracking via `src/waf/asn_tracker.rs` (GeoIP blocking not fully implemented)" | `AsnTracker` exists and is functional; GeoIP is used for ASN lookups | GeoIP blocking claim is misleading - GeoIP is actively used for ASN resolution |
| "Site-level tracking: Per-site connection counting via `SiteConnectionLimiter`" | `SiteConnectionLimiter` exists but has significant dead code | Unused parameters `_max_connections`, `_max_connections_per_ip`, `_queue_size`, `_burst` at lines 315-318 |

### 3. Missing/Stale Content

- **Missing**: `Stall` action is listed in Decisions section (line 120) but never explained
- **Missing**: Behavioral Analysis section mentions "Mesh mode only" but behavioral engine (`src/waf/attack_detection/behavioral.rs`) runs independently
- **Stale**: BufferPool tiered description (line 133-135) mentions "Four buffer tiers" but actual implementation uses different tier sizing

---

## Claims Verified / Issues Found

### Verified Claims

| Section | Claim | Status | Code Location |
|---------|-------|--------|---------------|
| Connection Layer | `FloodProtector` exists with SYN flood, per-IP rate limiting | VERIFIED | `src/waf/flood/mod.rs:225-367` (SynFloodProtector starts at line 368) |
| Connection Layer | `ConnectionLimiter` with global/IP/site limits | VERIFIED | `src/waf/traffic_shaper/limiter.rs:12-363` |
| Connection Layer | `TokenBucket` rate limiting | VERIFIED | `src/waf/traffic_shaper/bucket.rs:6-143` |
| Connection Layer | UDP flood protection with per-IP/global limits | VERIFIED | `src/waf/flood/udp_flood.rs` |
| Protocol Layer | HTTP validation, header sanitization | VERIFIED | `src/waf/request_sanitization.rs:1-377` |
| Request Layer | `AttackDetector` with SQLi, XSS, Path Traversal, etc. | VERIFIED | `src/waf/attack_detection/mod.rs:64-86` |
| Bot Detection | CSS challenge via `CssManager` | VERIFIED | `src/challenge/css.rs:10-416` |
| Bot Detection | HTTP honeypot traps via `HoneypotTracker` | VERIFIED | `src/challenge/honeypot.rs:61-175` |
| Bot Detection | JS Challenge (WASM-based PoW) | VERIFIED | `src/wasm_pow/src/lib.rs`, `src/challenge/pow.rs` |
| Streaming WAF | `StreamingWafCore` with chunked processing, trailing window | VERIFIED | `src/waf/attack_detection/streaming.rs:1-515` |
| Streaming WAF | Multipart state machine | VERIFIED | Lines 24-30, 89-93 |
| Performance | Zero-copy via BufferPool | VERIFIED | `crates/synvoid-utils/src/buffer/pool.rs:211` |
| Performance | Async WAF pipeline | VERIFIED | `src/waf/mod.rs:442-517` (actual location) |
| eBPF | Linux-only eBPF flood protection | VERIFIED | `src/waf/flood/mod.rs:5-6` |
| PatternDetector | Aho-Corasick multi-pattern matching via `PatternDetector` trait | VERIFIED | `src/waf/attack_detection/detector_common.rs:293` (actual) |

### Code Issues Found

#### Issue 1: Wrong Default for Site Connection Limits
**Location**: `src/waf/traffic_shaper/limiter.rs:65`

```rust
let effective_max_per_site = max_per_site.unwrap_or(10000);
```

**Problem**: When `max_per_site` is `None`, defaults to 10000 instead of using `config.max_connections_per_ip` (which is 100 by default in `FloodConfig`). This inconsistency could allow 10000 connections per site when the config might expect a different default.

**Recommendation**: Use `config.max_connections_per_ip` or a site-specific config default.

#### Issue 2: SiteConnectionLimiter Dead Code
**Location**: `src/waf/traffic_shaper/limiter.rs:312-323`

```rust
pub fn new(
    site_id: String,
    global_limiter: Arc<ConnectionLimiter>,
    _max_connections: Option<u32>,    // UNUSED
    _max_connections_per_ip: Option<u32>,  // UNUSED
    _queue_size: Option<u32>,         // UNUSED
    _burst: Option<u32>,              // UNUSED
) -> Self {
```

**Problem**: Parameters are never used. The struct just wraps the global limiter without site-specific customization.

#### Issue 3: FloodConfig Default Inconsistency
**Location**: `src/waf/flood/mod.rs:40-56`

- `connection_rate_per_ip` default: 100 (line 45)
- `connection_rate_global` default: 20,000 (line 46)
- But `ConnectionLimiter` uses `config.max_connections_per_ip` which has no explicit default in `ConnectionLimitsConfig`

#### Issue 4: Async Pipeline Line Reference Wrong
**Document**: Line 149 states async pipeline at `src/waf/mod.rs:484-512`
**Actual**: `check_request_full` is at lines 442-517

---

## Improvement Plan

### High Priority

1. **Fix ConnectionLimiter default inconsistency** (`limiter.rs:65`)
   - Default to `config.max_connections_per_ip` instead of hardcoded 10000
   - Ensures consistency between flood config and connection limiting

2. **Update document line references**
   - Change 484-512 to 442-517 for async pipeline location
   - Change 264 to 293 for PatternDetector trait location

3. **Remove or implement SiteConnectionLimiter parameters**
   - Either remove unused parameters or implement site-specific limits

### Medium Priority

4. **Document Stall action** - Add explanation for what "Stall" decision does (silent stalling wastes attacker time)

5. **Clarify GeoIP blocking statement** - The current phrase "GeoIP blocking not fully implemented" is ambiguous. GeoIP IS used for ASN lookups. Either clarify what's missing or update the claim.

6. **Behavioral Analysis section** - Current doc says "(Mesh mode only)" but the engine is standalone. Either update docs or verify mesh-only requirement.

### Low Priority

7. **BufferPool tier documentation** - The document describes 4 tiers but implementation may differ. Verify and update if needed.

8. **Add cross-reference to StreamingWafCore test cases** - Document mentions split attack detection but doesn't reference the test at `streaming.rs:451-462` that validates this.

---

## Bug Report

### Minor Bugs

| Bug ID | Location | Description |
|--------|----------|-------------|
| BUG-WAF-1 | `limiter.rs:65` | Wrong default value (10000 vs config-based) |
| BUG-WAF-2 | `limiter.rs:312-323` | Unused parameters in SiteConnectionLimiter::new |
| BUG-WAF-3 | `mod.rs:786-799` | set_flood_protector has dead code with comment "For now, we'll use the Logging provider..." |
| BUG-WAF-4 | `mod.rs:355-383` | WafCore creates ChallengeManager with hardcoded `false` values for pow_enabled, css_enabled, mesh_pow_enabled |

### Not Bugs (Working As Intended)

1. **Async WAF Pipeline execution order** - Document says flood protection first, then attack detection. Code at `mod.rs:476-514` shows flood check happens BEFORE attack detection. VERIFIED CORRECT.

2. **Streaming WAF trailing window** - Document claims 512 bytes trailing window. Code at `streaming.rs:44` defines `TRAILING_WINDOW_SIZE = 512`. VERIFIED CORRECT.

3. **Multipart file skipping** - Document says file content scanning is skipped. Code at `streaming.rs:190` sets state to `SkippingFile` when `filename=` is present. VERIFIED CORRECT.

---

## Summary

The architecture document is largely accurate with only minor line reference discrepancies and one significant inconsistency in connection limiter defaults. The WAF implementation is well-structured with proper separation between flood protection, rate limiting, attack detection, and bot detection layers.

Key findings:
- All documented modules exist and are correctly located
- 4 line references need correction
- 1 configuration inconsistency (BUG-WAF-1) should be fixed for safety
- 1 dead code item (BUG-WAF-2) should be addressed
- 1 incomplete integration (ChallengeManager hardcoded values) at BUG-WAF-4

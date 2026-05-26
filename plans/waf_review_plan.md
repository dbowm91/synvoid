# WAF Module Review Plan

## Verified Correct Items

### Connection Layer (Flood Protection)
- **FloodProtector** - `src/waf/flood/mod.rs:225-367` - Location accurate
- **SynFloodProtector** - Implemented in `src/waf/flood/syn_flood.rs`
- **ConnectionLimiter** - `src/waf/traffic_shaper/limiter.rs` - Location accurate
- **TokenBucket** - `src/waf/traffic_shaper/bucket.rs` - Location accurate
- **UdpFloodProtector** - Implemented in `src/waf/flood/udp_flood.rs`
- **eBPF backend** - Conditional compilation `#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]` in `src/waf/flood/mod.rs:5-6` - Accurate
- **ebpf_flood.rs** - `src/waf/flood/ebpf_flood.rs` exists

### Connection Limiting Defaults
- Global limit: 20,000 (verified in `src/waf/flood/mod.rs:46`)
- Per-IP limit: 100 (verified in `src/waf/flood/mod.rs:45`)
- Burst tokens: Default 10 (verified in FloodConfig::default())
- Queue size: 1000 (verified in ConnectionLimitsConfig)
- Queue timeout: 5000ms (verified in ConnectionLimitsConfig)

### TokenBucket Rate Limiting
- **TokenBucket** struct exists in `src/waf/traffic_shaper/bucket.rs:6-14`
- AsyncTokenBucket exists in `src/waf/traffic_shaper/async_bucket.rs`
- GlobalTrafficShaper exists in `src/waf/traffic_shaper/global.rs:10`
- SiteTrafficShaper exists in `src/waf/traffic_shaper/global.rs:182`

### Request Layer (Attack Detection)
- **PatternDetector trait** at `src/waf/attack_detection/detector_common.rs:293-397` - Line 264 referenced in doc is the trait definition area, actual trait starts at 293
- PatternDetector implementations verified: SstiDetector, LdapInjectionDetector, XPathInjectionDetector, OpenRedirectDetector, XxeDetector, CmdInjectionDetector, PathTraversalDetector, RfiDetector, SsrfDetector, BasePatternDetector

### Bot Detection Layer
- **CssManager** at `src/challenge/css.rs`
- CSS challenge with @media (min-aspect-ratio:) and @media (aspect-ratio:) patterns - Verified in code lines 127-158
- **HoneypotTracker** at `src/challenge/honeypot.rs`
- `/_waf_hp_` prefix verified at `src/challenge/honeypot.rs:9`
- **PowManager** at `src/challenge/pow.rs`

### Streaming WAF
- **StreamingWafCore** at `src/waf/attack_detection/streaming.rs`
- Default chunk size 4096 bytes (streaming.rs:6)
- Trailing window 512 bytes (streaming.rs:44)
- max_buffered_bytes 2MB (streaming.rs:7)
- Multipart state machine: LookingForBoundary, ReadingHeaders, ReadingField, SkippingFile - Matches implementation
- check_body_fragments() method exists at `src/waf/attack_detection/mod.rs:932`

### Async WAF Pipeline
- **check_request_full()** at `src/waf/mod.rs:442-517` - Accurate
- Flood protection runs first via FloodProtector::check_tcp_connection()
- Attack detection via AttackDetector::check_request()

### BufferPool Architecture
- **BufferPool** and **PooledBuf** at `crates/synvoid-utils/src/buffer/pool.rs`
- Four buffer tiers: Small (4KB), Medium (64KB), Large (256KB), Jumbo (256KB+) - Verified lines 7-9
- 8 shards with per-shard arenas (line 16: NUM_SHARDS: usize = 8)
- Thread-local cache up to 16 buffers per tier (line 17: TLS_CACHE_SIZE: usize = 16)

### ASN & GeoIP Blocking
- **AsnTracker** at `src/waf/asn_tracker.rs`
- GeoIP used for ASN lookups in asn_tracker.rs

---

## Stale/Incorrect Items

### 1. PatternDetector Trait Location
**Document says:** PatternDetector trait (src/waf/attack_detection/detector_common.rs:264)
**Actual:** The trait definition is at detector_common.rs:293-397. Line 264 is within the trait documentation or implementation area.
**Correction:** Update line reference to 293 or clarify that the trait is defined starting at 293.

### 2. SiteConnectionLimiter Line Number
**Document says:** SiteConnectionLimiter (lines 20-24)
**Actual:** The SiteConnectionLimiter struct is at src/waf/traffic_shaper/limiter.rs:306-346.
**Correction:** Document describes functionality correctly but struct definition is at line 306.

### 3. GlobalTrafficShaper Module Location
**Document says:** TokenBucket provides rate-based limiting, then mentions GlobalTrafficShaper and SiteTrafficShaper
**Actual:** GlobalTrafficShaper is defined in src/waf/traffic_shaper/global.rs:10 and SiteTrafficShaper at global.rs:182
**Correction:** Add module path for GlobalTrafficShaper and SiteTrafficShaper.

---

## Bugs Found

### BUG-WAF-1: SiteConnectionLimiter Unused Parameters
**Location:** `src/waf/traffic_shaper/limiter.rs:312-323`
**Issue:** SiteConnectionLimiter::new() accepts parameters _max_connections, _max_connections_per_ip, _queue_size, _burst that are documented but never used.
**Status:** Known issue from AGENTS.md - SiteConnectionLimiter unused params
**Reference:** AGENTS.md "SiteConnectionLimiter unused params"

---

## Security Concerns

### 1. Threat Intelligence Feed Integration
**Reference:** Document mentions "threat feeds" but doesn't provide implementation details.
**Verification needed:** Feed signing and verification, update frequency, fallback behavior.

### 2. Distributed Intelligence Mesh Sharing
**Reference:** "WAF nodes share blocked IP addresses and threat signatures in real-time"
**Verification needed:** Confirm secure channels and no tenant data leakage.

---

## Document Update Recommendations

### High Priority Fixes

1. **Update PatternDetector trait line reference**
   - Change src/waf/attack_detection/detector_common.rs:264 to 293 (where pub trait PatternDetector begins)

2. **Clarify SiteConnectionLimiter description vs definition**
   - Description at lines 20-24 describes functionality but struct is at line 306

3. **Add GlobalTrafficShaper/SiteTrafficShaper module paths**
   - After line 30, clarify they are in src/waf/traffic_shaper/global.rs

### Medium Priority Fixes

4. **Verify honeypot CSS properties**
   - display:none;visibility:hidden;opacity:0;position:absolute;left:-9999px;width:0;height:0 should be verified

5. **Add missing AsyncTokenBucket path**
   - AsyncTokenBucket mentioned at line 32 but path not provided
   - Actual location: src/waf/traffic_shaper/async_bucket.rs

6. **Clarify behavioral analysis limitation**
   - Line 78 states "(Mesh mode only)" - should be emphasized as key architectural limitation

### Documentation Enhancements

7. **Add threat feed architecture section**
   - Document references threat feeds but doesn't explain format, signing, or update mechanism

8. **Document the fast_path_detector optimization**
   - In src/waf/attack_detection/mod.rs:161-200, there's a fast_path_detector regex set optimization

---

## Verification Checklist

| Item | Status | Notes |
|------|--------|-------|
| FloodProtector location | Verified | src/waf/flood/mod.rs:225-367 |
| ConnectionLimiter location | Verified | src/waf/traffic_shaper/limiter.rs |
| TokenBucket location | Verified | src/waf/traffic_shaper/bucket.rs |
| StreamingWafCore location | Verified | src/waf/attack_detection/streaming.rs |
| PatternDetector trait | Verified | src/waf/attack_detection/detector_common.rs:293 |
| CssManager location | Verified | src/challenge/css.rs |
| HoneypotTracker location | Verified | src/challenge/honeypot.rs |
| PowManager location | Verified | src/challenge/pow.rs |
| check_request_full() | Verified | src/waf/mod.rs:442-517 |
| BufferPool architecture | Verified | crates/synvoid-utils/src/buffer/pool.rs |
| SiteConnectionLimiter | Stale ref | Struct at line 306, not near description |
| GlobalTrafficShaper path | Missing | Should specify global.rs |
| AsyncTokenBucket path | Missing | Should specify async_bucket.rs |
| Trailing window mechanism | Verified | 512 bytes at streaming.rs:44 |
| Multipart state machine | Verified | States match implementation |

---

## Summary

The WAF architecture document is mostly accurate with only minor line number discrepancies and missing module paths. The core architecture is well-documented and the code matches the descriptions. The main recommendations are:
1. Fix line number references for PatternDetector trait
2. Add missing module paths for GlobalTrafficShaper, SiteTrafficShaper, and AsyncTokenBucket
3. Clarify the SiteConnectionLimiter description vs definition separation

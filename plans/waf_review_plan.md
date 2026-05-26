# WAF Architecture Review Plan

## Verified Correct

### File Paths and Line Numbers
- **FloodProtector**: `src/waf/flood/mod.rs:225-367` - Struct defined at line 225, file ends at line 367
- **ConnectionLimiter**: `src/waf/traffic_shaper/limiter.rs` - Struct defined at line 12
- **TokenBucket**: `src/waf/traffic_shaper/bucket.rs` - Struct defined at line 6
- **PatternDetector trait**: `src/waf/attack_detection/detector_common.rs:293` - Trait defined at line 293
- **BasePatternDetector**: `src/waf/attack_detection/detector_common.rs:399` - Struct defined at line 399
- **CssManager**: `src/challenge/css.rs` - Struct defined at line 10
- **HoneypotTracker**: `src/challenge/honeypot.rs` - Struct defined at line 61
- **PowManager (WASM-based PoW)**: `src/challenge/pow.rs` - Struct defined at line 21
- **StreamingWafCore**: `src/waf/attack_detection/streaming.rs` - Struct defined at line 16
- **eBPF feature gate**: `src/waf/flood/mod.rs:5-6` - Conditional compilation at lines 5-6
- **ebpf_flood.rs**: `src/waf/flood/ebpf_flood.rs` - File exists
- **check_body_fragments**: `src/waf/attack_detection/mod.rs:932` - Method defined at line 932
- **GlobalTrafficShaper**: `src/waf/traffic_shaper/global.rs:10` - Struct defined at line 10
- **SiteTrafficShaper**: `src/waf/traffic_shaper/global.rs:182` - Struct defined at line 182
- **AsyncTokenBucket**: `src/waf/traffic_shaper/async_bucket.rs:4` - Struct defined at line 4
- **WAF pipeline (check_request_full)**: `src/waf/mod.rs:442-517` - Method defined at line 442
- **BufferPool tiered architecture**: `crates/synvoid-utils/src/buffer/pool.rs` - 4 tiers (4KB, 64KB, 256KB, 256KB+), 8 shards, TLS cache size 16
- **BlockStore**: `src/block_store.rs` - Struct defined at line 78
- **AsnTracker**: `src/waf/asn_tracker.rs` - Struct defined at line 58

### Components Verified
- All Pattern Detectors exist: SstiDetector, LdapInjectionDetector, XPathInjectionDetector, OpenRedirectDetector, XxeDetector, CmdInjectionDetector, PathTraversalDetector, RfiDetector, SsrfDetector
- WafDecision enum has all documented variants: Pass, Block, Drop, Tarpit, Stall, Challenge, ChallengeWithCookie
- Multipart state machine states exist: None, LookingForBoundary, ReadingHeaders, ReadingField, SkippingFile
- StreamingWafCore trailing window logic at streaming.rs:127-146 with TRAILING_WINDOW_SIZE = 512 bytes
- BufferPool architecture matches: Small (4KB), Medium (64KB), Large (256KB), Jumbo (256KB+), 8 shards, TLS cache 16

### Known Issues Confirmed
- **SiteConnectionLimiter dead code**: `src/waf/traffic_shaper/limiter.rs:306-346` - Struct defined but never instantiated anywhere in codebase (confirmed via grep)
- **StreamingWafCore trailing window**: Listed in AGENTS.md as "Already Fixed" - verified correct sliding window implementation at lines 127-146

---

## Discrepancies Found

### 1. Connection Queue Defaults (Medium Severity)
**Doc says**: Queue system with default 1000 queue size, 5000ms timeout  
**Actual code** (`crates/synvoid-config/src/traffic.rs:172-173`):
- `connection_queue_size: 100`
- `connection_queue_timeout_ms: 60000`

### 2. Global Connection Limit (Medium Severity)
**Doc says**: Default 20,000 concurrent connections  
**Actual code** (`crates/synvoid-config/src/traffic.rs:170`):
- `max_connections: 1000`

### 3. Per-IP Connection Limit (Medium Severity)
**Doc says**: Default 100 connections per IP  
**Actual code** (`crates/synvoid-config/src/traffic.rs:171`):
- `max_connections_per_ip: 10`

### 4. Burst Token Default (Low Severity)
**Doc says**: Default 10 burst tokens  
**Actual code** (`crates/synvoid-config/src/traffic.rs:174`):
- `connection_burst: 5`

### 5. CSS Challenge Rule Format (Low Severity - Documentation Clarity)
**Doc says**: Valid CSS uses `@media (min-aspect-ratio: X/Y) and (max-aspect-ratio: X/Y)`  
**Actual code** (`src/challenge/css.rs:135`):
```rust
@media (aspect-ratio: {min_num}/{min_den} and {max_num}/{max_den}) ...
```
Note: The code uses `aspect-ratio: num/den and num/den` not separate min/max aspect-ratio properties.

### 6. Honeypot HTML Attributes (Low Severity - Documentation Incompleteness)
**Doc says**: Hidden links with `display:none;visibility:hidden;opacity:0;position:absolute;left:-9999px;width:0;height:0`  
**Actual code** (`src/challenge/honeypot.rs:137`):
```rust
style="display:none;visibility:hidden;opacity:0;position:absolute;left:-9999px;width:0;height:0;overflow:hidden;" tabindex="-1" aria-hidden="true"
```
Actual implementation includes additional attributes: `overflow:hidden`, `tabindex="-1"`, `aria-hidden="true"`

---

## Bugs Identified

### High Severity
None identified in this review.

### Medium Severity
1. **Documentation Mismatch - Connection Limits**: The architecture document significantly underestimates the connection limits. This could lead operators to misconfigure their deployment or misinterpret WAF behavior. The actual defaults (1000 global, 10 per-IP) are 20x and 10x lower than documented.

### Low Severity
1. **SiteConnectionLimiter Dead Code** (`src/waf/traffic_shaper/limiter.rs:306-346`): Struct never instantiated. While the comment in AGENTS.md says "limits work via direct try_acquire_with_limits() call", having dead code is a maintenance burden. Consider removing or integrating.

2. **Documentation Inconsistency - Queue Timeout**: The queue timeout is documented as 5000ms but defaults to 60000ms (60 seconds). This is a 12x difference.

---

## Suggested Improvements

### Documentation Improvements
1. **Update connection limit defaults** in `architecture/waf_deep_dive.md` to match actual code:
   - Global connection limit: 1,000 (not 20,000)
   - Per-IP connection limit: 10 (not 100)
   - Burst tokens: 5 (not 10)
   - Queue size: 100 (not 1000)
   - Queue timeout: 60,000ms (not 5,000ms)

2. **Clarify CSS challenge rule syntax** - Document the actual `aspect-ratio: min/max and min/max` format used in `css.rs:135`

3. **Document complete honeypot HTML attributes** - Include `overflow:hidden`, `tabindex="-1"`, and `aria-hidden="true"` in the description

### Code Improvements
1. **Consider removing SiteConnectionLimiter** or adding a unit test that instantiates it to prevent bitrot

2. **Extract magic numbers into constants** with documentation comments:
   - `src/waf/traffic_shaper/limiter.rs` - connection limits
   - `crates/synvoid-config/src/traffic.rs` - queue parameters

### Architecture Improvements
1. **Consider adding validation** that documented defaults match code defaults (could be a compile-time check or documentation CI test)

2. **Add metrics/observability** for queue timeout scenarios to help operators tune these values

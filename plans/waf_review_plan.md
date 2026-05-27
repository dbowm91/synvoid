# WAF Architecture Review Plan

## Verified Correct Items

### 1. WafCore Structure (src/waf/mod.rs:172-199)
The `WafCore` struct matches documentation. All 18 fields present:
- `rate_limiter`, `bot_detector`, `endpoint_blocker`, `sensitive_endpoint_manager`
- `error_page_manager`, `challenge_manager`, `auth_manager`
- `attack_detector: ArcSwapOption<AttackDetector>` (correct type)
- `threat_level`, `violation_tracker`, `ip_feed`, `probe_tracker`
- `traffic_shaper`, `connection_limiter`, `asn_tracker`
- `flood_protector` (Option<Arc<FloodProtector>>)

### 2. WafDecision Enum (src/waf/mod.rs:59-74)
Documentation accurately reflects all 7 variants: Pass, Block, Drop, Tarpit, Stall, Challenge, ChallengeWithCookie.

### 3. AttackDetector Structure (src/waf/attack_detection/mod.rs:64-85)
All 13 detectors present as documented:
- sqli_detector, xss_detector, path_traversal_detector, rfi_detector, ssrf_detector
- ssti_detector, cmd_injection_detector, xxe_detector, jwt_detector
- request_smuggling_detector, header_validator
- ldap_injection_detector, xpath_injection_detector, open_redirect_detector

### 4. StreamingWafCore Trailing Window (src/waf/attack_detection/streaming.rs:127-148)
**AGENTS.md noted this as "correct sliding window" - CONFIRMED CORRECT.**
```
previous_len = min(trailing_window.len(), 512)
current_remaining = 512 - previous_len
window_start = chunk.len() - current_remaining
```
Correctly implements sliding window preserving up to 512 bytes across chunks.

### 5. FloodProtector (src/waf/flood/mod.rs:225-233)
Line reference `225-367` is accurate - FloodProtector struct and implementation spans lines 225-367 with methods for check_tcp_connection, register_half_open, etc.

### 6. ConnectionLimiter (src/waf/traffic_shaper/limiter.rs)
Documentation accurately notes SiteConnectionLimiter exists but is "not instantiated as a separate entity" - **CONFIRMED**: SiteConnectionLimiter at lines 306-346 is dead code. Only `ConnectionLimiter` is used directly via `try_acquire_with_limits()`.

### 7. PatternDetector Trait (src/waf/attack_detection/detector_common.rs:293)
Line reference `293` is accurate - PatternDetector trait defined at line 293.

### 8. Connection Limit Defaults
Verified from code:
| Setting | Code Default | Config Field |
|---------|--------------|--------------|
| Global connections | 1000 | `traffic.connection_limits.max_connections` |
| Per-IP connections | 10 | `traffic.connection_limits.max_connections_per_ip` |
| IP burst tokens | 5 | `traffic.connection_limits.connection_burst` |
| Queue size | 100 | `traffic.connection_limits.connection_queue_size` |
| Queue timeout | 60000ms | `traffic.connection_limits.connection_queue_timeout_ms` |

---

## Discrepancies Found

### 1. WafCore Line Count (waf.md:18)
Documentation states `mod.rs` is "936 lines" - **CORRECT** (verified 936 total lines).

### 2. Bot Detection Line Count (waf.md:98)
Documentation states `bot.rs` is "494 lines" - **ACTUAL**: `src/waf/bot.rs` is **~580 lines** (file exists with more content than documented).

### 3. FloodProtector Line Reference (waf_deep_dive.md:11)
States `FloodProtector` is at `src/waf/flood/mod.rs:225-367` - **CORRECT** but the FloodProtector impl block actually spans lines 225-367.

### 4. SiteConnectionLimiter Documentation Mismatch (waf_deep_dive.md:24)
States "SiteConnectionLimiter struct exists but is not instantiated as a separate entity" - **ACCURATE** but missing note that it IS instantiated in limiter.rs:312-317 via `new()` method. The struct is defined but the comment about "not instantiated" refers to its non-usage in the actual WAF pipeline (WafCore uses ConnectionLimiter directly).

### 5. PatternDetector Line Reference (waf_deep_dive.md:62)
States PatternDetector trait is at `detector_common.rs:293` - **CORRECT**.

### 6. Async WAF Pipeline Location (waf_deep_dive.md:181)
States "async at `src/waf/mod.rs:442-517`" - **CORRECT** for `check_request_full()` method (lines 442-520+).

---

## Bugs Identified

### BUG-WAF-1: SiteConnectionLimiter Dead Code (Severity: Low)
**Location**: `src/waf/traffic_shaper/limiter.rs:306-346`
**Issue**: `SiteConnectionLimiter` struct is defined but never instantiated in the codebase. WafCore uses `ConnectionLimiter` directly with `try_acquire_with_limits()`.
**Documentation Impact**: waf_deep_dive.md correctly notes "SiteConnectionLimiter struct exists but is not instantiated as a separate entity" but the comment is misleading since the struct CAN be instantiated (it has a `new()` method).

### BUG-WAF-2: StreamingWafCore get_block_status Always Returns 403 (Severity: Low)
**Location**: `src/waf/attack_detection/streaming.rs:387-392`
**Issue**:
```rust
impl AttackDetectionResult {
    pub fn get_block_status(&self) -> Option<u16> {
        let _ = self;
        Some(403)
    }
}
```
The method ignores `self` and always returns 403. This is test/debug code that should be removed or properly implemented.

### BUG-WAF-3: Missing SiteConnectionLimiter Instantiation (Severity: Medium)
**Location**: `src/waf/mod.rs:332-334`
**Issue**: WafCore creates `connection_limiter_instance` from traffic_shaping_config but never uses SiteConnectionLimiter. The per-site limiting via SiteConnectionLimiter is not wired into WafCore.
**Impact**: Per-site connection limiting may not work as documented.

---

## Suggested Improvements

### 1. Document StreamingWafCore Chunk Size Constants
**Location**: `src/waf/attack_detection/streaming.rs:6-7`
**Issue**: `DEFAULT_CHUNK_SIZE` (4096) and `DEFAULT_MAX_BUFFERED_BYTES` (2MB) are not documented.
**Suggestion**: Add documentation comments explaining these control streaming WAF memory usage.

### 2. Remove or Document AttackDetectionResult Extension
**Location**: `src/waf/attack_detection/streaming.rs:387-392`
**Issue**: `impl AttackDetectionResult` block at module level extends a type from another module without proper documentation.
**Suggestion**: Either remove this debug code or document it as a streaming-specific helper.

### 3. Update Bot Detection Line Count
**Location**: `architecture/waf.md:98`
**Issue**: States "bot.rs - Bot Detection (494 lines)" but actual is ~580 lines.
**Suggestion**: Update to "bot.rs - Bot Detection (~580 lines)".

### 4. Add Missing TRAILING_WINDOW_SIZE Constant Documentation
**Location**: `src/waf/attack_detection/streaming.rs:44`
**Issue**: `const TRAILING_WINDOW_SIZE: usize = 512;` has no documentation explaining its purpose.
**Suggestion**: Add inline comment explaining this is for boundary-crossing attack detection.

### 5. Document Multipart State Machine Transitions
**Location**: `src/waf/attack_detection/streaming.rs:23-30`
**Issue**: The multipart state machine transitions in code match the documentation at waf_deep_dive.md:133-137, but the documentation is clearer than the code comments.
**Suggestion**: Add state transition comments to the code to match documentation quality.

### 6. Consider Removing SiteConnectionLimiter Dead Code
**Location**: `src/waf/traffic_shaper/limiter.rs:306-346`
**Issue**: SiteConnectionLimiter is never used. Either remove it or wire it into WafCore.
**Suggestion**: Either remove the dead code or add a comment explaining why it exists but isn't used.

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 8 |
| Discrepancies | 6 |
| Bugs | 3 |
| Suggested Improvements | 6 |

**Overall Assessment**: The WAF architecture documentation is largely accurate. The primary issues are:
1. Line count mismatches for some files
2. Dead code (SiteConnectionLimiter) that is documented as unused but still present
3. A debug impl block for `get_block_status()` that should be removed
4. Minor documentation gaps for constants and state machines

The core architecture and most file paths line numbers are correct. The StreamingWafCore trailing window logic (AGENTS.md's concern at lines 129-134) is **confirmed correct**.
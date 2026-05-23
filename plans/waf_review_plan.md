# WAF Architecture Review - Improvement Plan

**Document Reviewed:** `architecture/waf_deep_dive.md`
**Review Date:** 2026-05-23
**Cross-Reference:** `AGENTS.md`, `src/waf/AGENTS.override.md`

---

## 1. VERIFIED CORRECT ITEMS

### 1.1 Flood Protection Integration
**Status:** ✅ VERIFIED CORRECT

The document states flood protection is part of the WAF pipeline. Code confirms:
- `src/waf/mod.rs:474-482` — `flood_protector.check_tcp_connection(ip)` is called in `check_request_full()`
- AGENTS.md Lesson #9 confirms: "Flood protector existed but was NOT called during request pipeline. **FIXED**: Integrated into `check_request_full()` pipeline."

### 1.2 Request Smuggling Detection
**Status:** ✅ VERIFIED CORRECT

The document mentions detection of inconsistent `Content-Length` and `Transfer-Encoding` headers.
- `src/waf/attack_detection/request_smuggling.rs` — Comprehensive implementation with:
  - Duplicate CL/TE headers detection (lines 78-108)
  - CL+TE conflict detection (lines 113-133)
  - Obfuscated TE detection (lines 151-164)
  - Large CL detection (lines 168-198)
  - CRLF injection in headers (lines 200-224)
  - HTTP/2 smuggling detection (lines 229-556)

### 1.3 Fast-Path Bypass Fix
**Status:** ✅ VERIFIED CORRECT

AGENTS.md Lesson #8 states: "WAF fast-path bypass — `src/waf/attack_detection/mod.rs:425-435` had early return when fast-path was safe, but request smuggling patterns were NOT in fast_path_patterns. **FIXED**: Added smuggling indicators (`transfer-encoding`, `content-length`) to fast_path_patterns."

Code at `src/waf/attack_detection/mod.rs:195-196` confirms:
```rust
r#"transfer-encoding"#,       // Request smuggling
r#"content-length"#,          // Request smuggling
```

Fast-path patterns expanded from 13 to 38 patterns (lines 156-197).

### 1.4 Behavioral Analysis Mesh-Only
**Status:** ✅ VERIFIED CORRECT

Document states behavioral analysis is "Mesh mode only." Code confirms:
- `src/waf/attack_detection/mod.rs:218` — `#[cfg(feature = "mesh")]`
- `src/waf/AGENTS.override.md:53-57` — Documents the mesh-only limitation

---

## 2. DISCREPANCIES FOUND

### 2.1 Missing Rate Limiting / Flood Protection Description
**Priority:** MEDIUM

**Discrepancy:** The document lists "Rate Limiting" under Connection Layer (Section 1), but the implementation details are sparse.

**Actual Implementation:**
- `src/waf/flood/mod.rs:225-367` — `FloodProtector` struct handles SYN/UDP/connection flood
- `src/waf/ratelimit.rs` and `src/waf/ratelimit/core.rs` — Rate limiting for WAF decisions
- `src/waf/traffic_shaper/` — Traffic shaping with TokenBucket implementation

**Issue:** Document claims "Per-IP and global rate limits" but doesn't mention:
1. TokenBucket-based rate limiting with precise refill (IPC-4 fix in `src/process/ipc_rate_limit.rs:132-141`)
2. Per-IP connection limiting via `ConnectionLimiter`
3. SYN flood protection with half-open connection tracking

**Suggested Fix:** Add subsection describing the rate limiting architecture:
- SYN flood protection (half-open tracking)
- Per-IP connection rate limiting
- Global connection limits
- TokenBucket-based request rate limiting

### 2.2 Bot Detection - Missing CSS Honeypot
**Priority:** MEDIUM

**Discrepancy:** Document mentions "Honeypots: Hidden CSS links and trap endpoints that only bots will follow" (Section 3), but doesn't mention CSS-based honeypot challenges.

**Actual Implementation:**
- `src/http/server.rs:931` — `enable_css_honeypot` in site bot config
- `src/challenge/css.rs` — CSS challenge implementation
- Config field: `SiteBotConfig.enable_js_challenge` in `crates/synvoid-config/src/site/defensive.rs:13`

**Issue:** Document is missing CSS honeypot details and JS challenge integration.

**Suggested Fix:** Update Section 3 to mention:
- CSS honeypot challenges (hidden links that flag bots)
- JS challenge for browser verification
- CAPTCHAs and PoW as additional challenge options

---

## 3. BUGS IDENTIFIED

### 3.1 Document Lists Non-Existent Attack Types
**Priority:** LOW (Documentation Issue)

**Finding:** Document mentions "JWT & XXE Detection" as attack types. While XXE is implemented (`src/waf/attack_detection/xxe.rs`), JWT is not a standalone detector.

**Actual:**
- `src/waf/attack_detection/jwt.rs` exists but is NOT a detector—it's a JWT validation module
- No `JwtAttackDetector` exists in the codebase

**Issue:** The document implies JWT attacks are detected as attack types, but JWT handling is for validation (not attack detection).

**Suggested Fix:** Remove "JWT & XXE Detection" from attack detection list, or clarify that JWT module is for token validation.

### 3.2 Aho-Corasick Mentioned But Not Used
**Priority:** LOW (Documentation Accuracy)

**Finding:** Document states "Aho-Corasick & Regex: High-performance pattern matching engines are used for rule evaluation" (Section 4).

**Actual:**
- `src/waf/attack_detection/detector_common.rs:264` — Trait exists for Aho-Corasick
- However, no detector actually uses Aho-Corasick in the current codebase
- All detectors use regex or libinjection

**Issue:** Document overstates the use of Aho-Corasick.

**Suggested Fix:** Remove "Aho-Corasick" from the performance section, or implement Aho-Corasick for high-volume pattern matching.

---

## 4. IMPROVEMENT SUGGESTIONS

### 4.1 Add Streaming WAF Documentation
**Priority:** HIGH

**Finding:** Document doesn't mention streaming WAF capability.

**Actual:**
- `src/waf/attack_detection/streaming.rs` — Full streaming WAF implementation exists
- Handles chunked processing, multipart parsing, trailing window
- `StreamingWafCore` for true streaming attack detection

**Suggestion:** Add new section "Streaming WAF" documenting:
- Chunk-based processing for 1M+ RPS
- Multipart boundary detection
- Trailing window for cross-chunk attack detection
- Max buffered bytes limit (2MB default)

### 4.2 Document Zero-Copy Inspection Details
**Priority:** MEDIUM

**Finding:** Document mentions "Zero-Copy Inspection" but provides no details.

**Actual:**
- `src/waf/attack_detection/streaming.rs` uses `BufferPool` for zero-copy buffer management
- `PooledBuf` type for zero-copy buffer reuse

**Suggestion:** Add implementation details about buffer pooling and zero-copy semantics.

### 4.3 Add Parallel Processing Documentation
**Priority:** MEDIUM

**Finding:** Document mentions "Parallel Processing" but provides no details.

**Actual:** `src/waf/mod.rs:484-512` shows parallel attack detection via `ad.check_request()`.

**Suggestion:** Document that attack detection runs in parallel with other WAF checks and how the async pipeline works.

### 4.4 Missing eBPF Documentation
**Priority:** MEDIUM

**Finding:** Document mentions "eBPF Integration" for flood protection but doesn't detail availability.

**Actual:**
- `src/waf/flood/mod.rs:5-6` — Feature-gated: `#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]`
- `src/waf/flood/ebpf_flood.rs` — eBPF implementation (Linux only)

**Suggestion:** Add note about Linux-only eBPF availability and the fallback to userspace.

### 4.5 ASN & GeoIP Blocking Not Implemented
**Priority:** LOW

**Finding:** Document mentions "ASN & GeoIP Blocking" (Section 1).

**Actual:** `src/waf/asn_tracker.rs` exists for ASN tracking, but no GeoIP blocking in WAF.

**Suggestion:** Clarify current state or mark as planned feature.

---

## 5. UNVERIFIED CLAIMS (Need Code Investigation)

### 5.1 Distributed Intelligence
**Claim:** "In a Mesh deployment, WAF nodes share blocked IP addresses and threat signatures in real-time"

**Status:** UNVERIFIED — Requires mesh feature testing

**Files to verify:**
- `src/mesh/threat_intel.rs` — Threat intelligence sharing
- `src/waf/ip_feed.rs` — IP feed integration

### 5.2 Anomaly Scoring
**Claim:** "Anomaly Scoring: Optionally combines multiple low-severity signals to block sophisticated attacks"

**Status:** UNVERIFIED — Requires configuration investigation

**Files to verify:**
- `src/waf/threat_level/` — Threat level scoring system

---

## 6. SUMMARY TABLE

| Category | Item | Status | Priority |
|----------|------|--------|----------|
| Flood Protection | Integration in check_request_full | ✅ VERIFIED | - |
| Request Smuggling | CL/TE detection | ✅ VERIFIED | - |
| Fast-Path Bypass | Smuggling patterns added | ✅ VERIFIED | - |
| Behavioral Analysis | Mesh-only | ✅ VERIFIED | - |
| Rate Limiting | Missing detailed description | ⚠️ DISCREPANCY | MEDIUM |
| Bot Detection | CSS honeypot missing | ⚠️ DISCREPANCY | MEDIUM |
| JWT Detection | Not a detector | 🐛 BUG | LOW |
| Aho-Corasick | Not actually used | 🐛 BUG | LOW |
| Streaming WAF | Not documented | 📝 IMPROVEMENT | HIGH |
| Zero-Copy | Missing details | 📝 IMPROVEMENT | MEDIUM |
| Parallel Processing | Missing details | 📝 IMPROVEMENT | MEDIUM |
| eBPF | Linux-only note missing | 📝 IMPROVEMENT | MEDIUM |
| Distributed Intel | Unverified | ❓ UNVERIFIED | - |
| Anomaly Scoring | Unverified | ❓ UNVERIFIED | - |

---

## 7. RECOMMENDED ACTIONS

### HIGH PRIORITY
1. **Add Streaming WAF documentation** — Major feature missing from doc
2. **Clarify rate limiting architecture** — Section 1 is sparse on implementation details

### MEDIUM PRIORITY
3. **Document bot detection fully** — CSS honeypot and JS challenge missing
4. **Add eBPF availability note** — Linux-only feature should be documented
5. **Document parallel processing** — How async WAF pipeline works

### LOW PRIORITY
6. **Remove JWT from attack detection list** — It's validation, not detection
7. **Remove Aho-Corasick claim** — Not actually used in current implementation
8. **Add GeoIP clarification** — Feature not fully implemented
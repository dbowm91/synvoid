# WAF Architecture Review - Improvement Plan

**Date:** 2026-05-22  
**Reviewer:** Architecture Review Agent  
**Document Reference:** `architecture/waf_deep_dive.md`

---

## Executive Summary

The WAF module (`src/waf/`) is a well-implemented, multi-layered security system with attack detection, rate limiting, bot protection, and flood mitigation. Most documented features are implemented, but some discrepancies exist between documentation and implementation.

**Overall Implementation Status:** ~90% complete with minor gaps

---

## 1. Documented vs Implemented Comparison

### 1.1 Connection Layer (Flood Protection) ✅

| Documented Feature | Implementation | Status |
|--------------------|----------------|--------|
| Volumetric Mitigation (SYN floods) | `src/waf/flood/syn_flood.rs` | ✅ Implemented |
| UDP Flood Protection | `src/waf/flood/udp_flood.rs` | ✅ Implemented |
| Connection Limiting | `src/waf/flood/connection_limiter.rs` | ✅ Implemented |
| eBPF Integration (Linux) | `src/waf/flood/ebpf_flood.rs` | ✅ Conditional (`#[cfg(all(target_os = "linux", feature = "flood-ebpf"))]`) |
| Rate Limiting (per-IP/global) | `src/waf/ratelimit/` | ✅ Implemented |
| ASN & GeoIP Blocking | `src/waf/asn_tracker.rs`, `src/waf/ip_feed.rs` | ✅ Implemented |

**Issue Found:** `flood/mod.rs:66-72` - `FloodBackend::Ebpf` is conditionally compiled but `Display` impl only shows "userspace" for all cases. Missing proper display for Ebpf variant.

```rust
impl std::fmt::Display for FloodBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Userspace => write!(f, "userspace"),
            // Ebpf case missing - would always show "userspace" even when Ebpf is active
        }
    }
}
```

### 1.2 Protocol Layer ✅

| Documented Feature | Implementation | Status |
|--------------------|----------------|--------|
| HTTP Validation | `src/waf/attack_detection/header_validation.rs` | ✅ Implemented |
| Header Size Limits | `AttackDetectionConfig::max_header_size` (default 8192) | ✅ Implemented |
| URI Length Validation | `max_request_body_size` for body, headers for path | ✅ Implemented |
| Header Sanitization | `src/waf/request_sanitization.rs` | ✅ Implemented |
| Request Smuggling Detection | `src/waf/attack_detection/request_smuggling.rs` | ✅ Implemented |

### 1.3 Request Layer (Attack Detection) ✅

| Documented Feature | Implementation | Status |
|--------------------|----------------|--------|
| SQL Injection (libinjection) | `src/waf/attack_detection/sqli.rs:59` | ✅ Implemented |
| XSS Detection | `src/waf/attack_detection/xss.rs` | ✅ Implemented |
| Path Traversal | `src/waf/attack_detection/path_traversal.rs` | ✅ Implemented |
| SSRF/RFI | `src/waf/attack_detection/ssrf.rs`, `rfi.rs` | ✅ Implemented |
| Command Injection | `src/waf/attack_detection/cmd_injection.rs` | ✅ Implemented |
| JWT Detection | `src/waf/attack_detection/jwt.rs` | ✅ Implemented |
| XXE Detection | `src/waf/attack_detection/xxe.rs` | ✅ Implemented |
| Anomaly Scoring | `src/waf/attack_detection/config.rs:35-53` | ✅ Implemented |
| Input Normalization | `src/waf/attack_detection/normalizer.rs` | ✅ Implemented (excellent) |

### 1.4 Bot Detection Layer ⚠️

| Documented Feature | Implementation | Status |
|--------------------|----------------|--------|
| Honeypots (CSS links, trap endpoints) | `src/waf/endpoints.rs` | ✅ Implemented |
| JS Challenge | Challenge module | ✅ Implemented |
| CAPTCHA | Challenge module | ✅ Implemented |
| Proof of Work (PoW) | Challenge module | ✅ Implemented |
| Behavioral Analysis (Mesh mode) | `src/waf/attack_detection/behavioral.rs` | ⚠️ Partial - mesh-only feature |

**Issue Found:** `bot.rs:91` - `block_scrapers` is hardcoded to `true`, ignoring constructor parameter:

```rust
pub fn with_ja4(...) -> Self {
    BotDetector {
        // ...
        block_scrapers: true,  // Should use parameter or make configurable
    }
}
```

### 1.5 Performance Features ✅

| Documented Feature | Implementation | Status |
|--------------------|----------------|--------|
| Zero-Copy Inspection | Buffer pools in `src/buffer/` | ✅ Implemented |
| Parallel Processing | `tokio::task::JoinSet` in `mod.rs:358` | ✅ Implemented |
| Aho-Corasick Pattern Matching | `detector_common.rs:512-538` | ✅ Implemented |
| RegexSet Fast-Path | `mod.rs:156-171`, `is_fast_path_safe()` | ✅ Implemented |

---

## 2. Discrepancies Found

### 2.1 Fast-Path Pre-Screening Pattern Set is Incomplete

**Location:** `src/waf/attack_detection/mod.rs:156-170`

The fast-path `RegexSet` patterns are missing several attack signatures that can bypass heavy detectors:

**Missing Patterns:**
- Command injection: `;`, `|`, `&`, `$()`, backticks
- Encoding indicators: `%00` (null byte), `%2f` (encoded slash)
- SQL patterns: `UNION`, `SELECT`, `DROP`, `INSERT`

**Impact:** Fast-path may allow malicious requests through to pass, but heavy detectors will still catch them. No security vulnerability, just performance optimization opportunity.

**Recommendation:**
```rust
let fast_path_patterns = vec![
    r#"['";]--"#,           // SQL comment/injection
    r#"(?i)union\s+select"#, // SQL union
    r#"(?i)select\s+.*\s+from"#,
    r#"<script"#,            // XSS
    r#"javascript:"#,
    r#"onload="#"#,
    r#"onerror="#,
    r#"\.\./\.\./"#,         // Path traversal
    r#"/etc/passwd"#,
    r#"/windows/system32"#,
    r#"<\?php"#,             // PHP tags
    r#"\$\{"#,               // Expression injection
    r#"\{\{"#,               // Template injection
    // ADDITIONAL PATTERNS:
    r#";"#,                  // Command separator
    r#"\|"#,                 // Pipe command
    r#"\$?\([^)]\)"#,        // Command substitution
    r#"`[^`]+`"#,            // Backtick command
    r#"%00"#,                // Null byte injection
    r#"%2f%2f"#,             // Double encoded slash
    r#"(?i)drop\s+table"#,   // SQL DROP
    r#"(?i)insert\s+into"#,  // SQL INSERT
];
```

### 2.2 Streaming WAF File Upload Handling Incomplete

**Location:** `src/waf/attack_detection/streaming.rs:175-181`

The code skips file uploads based on presence of `filename=` in headers, but doesn't properly detect content-type or handle edge cases:

```rust
let header_str = String::from_utf8_lossy(self.state.multipart_header_buffer.as_slice())
    .to_lowercase();
if header_str.contains("filename=") {
    self.state.multipart_state = MultipartState::SkippingFile;
}
```

**Issue:** A file upload without `filename=` (rare but possible) would be scanned as a field, and binary file content could contain false positives.

**Recommendation:** Add proper content-type checking and consider adding a MIME type allowlist for file uploads.

### 2.3 Behavioral Analysis Requires Mesh Feature

**Location:** `src/waf/attack_detection/mod.rs:263-314`

The behavioral analysis depends on `crate::mesh::behavioral_intel::BehavioralIntelligenceManager` which requires the `mesh` feature. The documentation says "Mesh mode only" but the code always initializes `behavioral_engine` even without mesh:

```rust
behavioral_engine: Arc::new(BehavioralEngine::new()),  // Always created
#[cfg(feature = "mesh")]
behavioral_intel: Option<Arc<crate::mesh::behavioral_intel::BehavioralIntelligenceManager>>,  // Only with mesh
```

**Issue:** The standalone `BehavioralEngine` is always created but only used when mesh feature is enabled. Minor resource inefficiency.

### 2.4 WafCore Missing Flood Protector Initialization

**Location:** `src/waf/mod.rs:193`, `764-778`

The `flood_protector` field is declared but never properly initialized in `WafCore::new()`. The `set_flood_protector()` method exists but is a no-op:

```rust
pub fn set_flood_protector(&mut self, protector: Arc<FloodProtector>) {
    #[cfg(all(target_os = "linux", feature = "flood-ebpf"))]
    {
        // Code suggests ebpf integration was planned but incomplete
    }
    self.flood_protector = Some(protector);
}
```

**Issue:** The flood protector is never called in the request pipeline. Flood protection is not actually integrated into the WAF decision flow.

---

## 3. Specific Bugs Identified

### BUG-1: Streaming WAF get_block_status Always Returns 403

**Location:** `src/waf/attack_detection/streaming.rs:356-365`

```rust
impl AttackDetectionResult {
    pub fn get_block_status(&self) -> Option<u16> {
        Some(match self.attack_type {
            crate::waf::attack_detection::AttackType::Sqli => 403,
            crate::waf::attack_detection::AttackType::Xss => 403,
            crate::waf::attack_detection::AttackType::PathTraversal => 403,
            _ => 403,  // ALL attack types return 403
        })
    }
}
```

**Issue:** All attack types return 403 regardless of severity or config. Should use actual config-based block status.

**Fix:** Make block status configurable per attack type.

### BUG-2: Double UTF-8 Lossy Conversion in Body Handling

**Location:** `src/waf/attack_detection/mod.rs:890-892`

```rust
pub fn check_body_only(&self, body: &[u8]) -> Option<AttackDetectionResult> {
    self.check_body_fragments(&[body])
}

pub fn check_body_fragments(&self, fragments: &[&[u8]]) -> Option<AttackDetectionResult> {
    // ...
    let normalized = self.normalizer.normalize_fragments(fragments);
    // This calls String::from_utf8_lossy internally
    // Then SqliDetector calls detect() which does String::from_utf8_lossy AGAIN
```

**Issue:** Potential double conversion when fragments are checked.

### BUG-3: Request Smuggling Not Included in Parallel Checks

**Location:** `src/waf/attack_detection/mod.rs:360-369`

Request smuggling runs in parallel via `JoinSet`, but it checks headers separately before the heavy detectors:

```rust
if self.config.request_smuggling.enabled {
    let detector = self.request_smuggling_detector.clone();
    let headers = headers.clone();
    let body = body.map(|b| b.to_vec());
    join_set.spawn(async move {
        detector.check_headers(&headers)
            .or_else(|| detector.check_http2_smuggling(&headers, &[], body.as_deref()))
            .or_else(|| body.as_deref().and_then(|b| detector.check_body(b)))
            .map(|r| (r, 50))
    });
}
```

**Issue:** Smuggling check runs in parallel but with low score (50) and returns early on detection. Not integrated into fast-path check.

---

## 4. Recommended Improvements

### REC-1: Add Comprehensive Fast-Path Patterns

**Priority:** Medium  
**File:** `src/waf/attack_detection/mod.rs`  
**Lines:** 156-171

Add command injection and encoding patterns to reduce false negatives in fast-path bypass.

### REC-2: Fix Flood Protector Integration

**Priority:** High  
**File:** `src/waf/mod.rs`  
**Lines:** 438-508 (`check_request_full`)

Add flood protection checks to the request pipeline:

```rust
pub async fn check_request_full(...) -> WafDecision {
    // Add flood check
    if let Some(ref protector) = self.flood_protector {
        match protector.check_tcp_connection(ip) {
            FloodDecision::RateLimited => return WafDecision::Block(429, "Rate Limited"),
            FloodDecision::Blackholed => return WafDecision::Drop,
            FloodDecision::Allowed => {}
        }
    }
    // ... rest of checks
}
```

### REC-3: Fix Streaming WAF Block Status

**Priority:** Medium  
**File:** `src/waf/attack_detection/streaming.rs`  
**Lines:** 356-365

Make attack type block status configurable instead of hardcoded 403.

### REC-4: Document Behavioral Analysis Limitation

**Priority:** Low  
**File:** `architecture/waf_deep_dive.md`  
Add note that behavioral analysis requires mesh feature to be enabled.

### REC-5: Add Request Smuggling to Fast-Path

**Priority:** Medium  
**File:** `src/waf/attack_detection/mod.rs`  
**Lines:** 425-435

Consider adding request smuggling patterns to fast-path `RegexSet` since it's a common attack vector.

### REC-6: Fix FloodBackend Display Implementation

**Priority:** Low  
**File:** `src/waf/flood/mod.rs`  
**Lines:** 66-72

Add proper display for Ebpf variant when compiled.

### REC-7: Make block_scrapers Configurable

**Priority:** Low  
**File:** `src/waf/bot.rs`  
**Lines:** 91

Currently hardcoded to `true`. Should respect constructor parameter.

---

## 5. Code Quality Assessment

### Strengths

1. **Excellent Input Normalization** (`normalizer.rs`): Comprehensive handling of URL encoding, HTML entities, Unicode normalization, null bytes, and homoglyphs.

2. **Efficient Pattern Matching**: Aho-Corasick automaton used throughout for O(n) pattern matching.

3. **Good Test Coverage**: Each detector has comprehensive unit tests.

4. **Parallel Detection**: Heavy detectors run concurrently via `JoinSet`.

5. **Clean Architecture**: Clear separation between detection engines, normalizers, and patterns.

### Areas for Improvement

1. **Configuration Flexibility**: Some values hardcoded (e.g., `block_scrapers`).

2. **Documentation**: Some features mentioned in docs not fully implemented or vice versa.

3. **Error Handling**: Some edge cases not handled gracefully.

4. **Metrics**: Some areas lack proper metrics for monitoring.

---

## 6. Summary of Changes Required

| Priority | Item | File | Lines |
|----------|------|------|-------|
| High | Integrate flood protector into request pipeline | `src/waf/mod.rs` | 438-508 |
| Medium | Enhance fast-path patterns | `src/waf/attack_detection/mod.rs` | 156-171 |
| Medium | Fix streaming waf block status | `src/waf/attack_detection/streaming.rs` | 356-365 |
| Low | Fix FloodBackend Display | `src/waf/flood/mod.rs` | 66-72 |
| Low | Make block_scrapers configurable | `src/waf/bot.rs` | 91 |
| Low | Update documentation | `architecture/waf_deep_dive.md` | - |

---

## Appendix: File Index

Key WAF files and their purposes:

| File | Purpose |
|------|---------|
| `src/waf/mod.rs` | WafCore - main orchestrator |
| `src/waf/attack_detection/mod.rs` | AttackDetector - request inspection engine |
| `src/waf/attack_detection/normalizer.rs` | Input normalization |
| `src/waf/attack_detection/detector_common.rs` | Base pattern detector, Aho-Corasick |
| `src/waf/attack_detection/sqli.rs` | SQL injection detection (libinjection) |
| `src/waf/attack_detection/xss.rs` | XSS detection |
| `src/waf/attack_detection/path_traversal.rs` | Path traversal detection |
| `src/waf/attack_detection/ssrf.rs` | SSRF detection with private IP blocking |
| `src/waf/attack_detection/streaming.rs` | Streaming WAF for large bodies |
| `src/waf/bot.rs` | Bot detection |
| `src/waf/flood/mod.rs` | Flood protection |
| `src/waf/request_sanitization.rs` | Header sanitization, XFF handling |


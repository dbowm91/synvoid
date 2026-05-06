# WAF Architecture Review

**Document**: `architecture/waf_deep_dive.md`
**Review Date**: 2026-05-06
**Reviewer**: Code Review Agent

---

## Verified Claims

The following claims from the WAF architecture document are **confirmed** by the source code:

### 1. Connection Layer (Flood Protection)
- **Rate Limiting**: Implemented in `src/waf/ratelimit.rs` with per-IP and global rate limits
- **SYN/UDP Flood**: Implemented in `src/waf/flood/syn_flood.rs` and `src/waf/flood/udp_flood.rs`
- **eBPF Integration**: Linux eBPF backend exists under `src/waf/flood/ebpf_flood.rs` (feature-gated)
- **Connection Limiter**: `src/waf/flood/connection_limiter.rs` handles per-IP and global limits

### 2. Protocol Layer (Request Sanitization)
- **Header Validation**: `src/waf/attack_detection/header_validation.rs` validates header size and count
- **Request Smuggling**: `src/waf/attack_detection/request_smuggling.rs` detects CL/TE anomalies
- **Trusted Proxy Handling**: `src/waf/request_sanitization.rs` handles X-Forwarded-For, X-Forwarded-Proto properly

### 3. Request Layer (Attack Detection)
All documented attack detectors exist and are properly integrated:
- **SQLi**: `src/waf/attack_detection/sqli.rs` uses `libinjectionrs` + Aho-Corasick patterns
- **XSS**: `src/waf/attack_detection/xss.rs` uses `libinjectionrs` + Aho-Corasick patterns
- **Path Traversal**: `src/waf/attack_detection/path_traversal.rs` with URL decoding
- **SSRF**: `src/waf/attack_detection/ssrf.rs` with private IP detection, localhost, cloud metadata
- **RFI**: `src/waf/attack_detection/rfi.rs` with IP address detection in URLs
- **Command Injection**: `src/waf/attack_detection/cmd_injection.rs`
- **SSTI**: `src/waf/attack_detection/ssti.rs`
- **XXE**: `src/waf/attack_detection/xxe.rs`
- **JWT**: `src/waf/attack_detection/jwt.rs`
- **LDAP Injection**: `src/waf/attack_detection/ldap_injection.rs`
- **XPath Injection**: `src/waf/attack_detection/xpath_injection.rs`
- **Open Redirect**: `src/waf/attack_detection/open_redirect.rs`

### 4. Bot Detection Layer
- **Honeypots**: `src/challenge/honeypot.rs` implements hidden CSS links and trap endpoints
- **JS Challenge**: `src/challenge/pow.rs` provides PoW-based browser verification
- **CAPTCHA**: CSS challenge in `src/challenge/css.rs` with asset verification
- **PoW**: Proof-of-work challenge system with constant-time verification
- **Behavioral Analysis**: Mesh-only feature via `src/mesh/behavioral_intel.rs`

### 5. Decisions & Actions
All documented WAF decisions exist in `src/waf/mod.rs`:
- `WafDecision::Block`
- `WafDecision::Challenge` / `ChallengeWithCookie`
- `WafDecision::Tarpit`
- `WafDecision::Stall`
- `WafDecision::Drop`
- `WafDecision::Pass`

### 6. Input Normalization
- URL decoding (single and multi-pass)
- HTML entity decoding
- Unicode normalization (NFKC)
- Homoglyph normalization (Cyrillic, fullwidth, etc.)
- Null byte stripping

---

## Unverified Claims

### 1. "Aho-Corasick & Regex: High-performance pattern matching engines are used for rule evaluation"

**Status**: PARTIALLY VERIFIED
- Aho-Corasick is used for pattern matching in detectors
- However, the claim about "Regex" for rule evaluation is **unclear** - some detectors use regex (RFI uses `regex::Regex` for IP extraction), but this is not documented
- Default patterns use Aho-Corasick which is O(n) instead of regex which is O(n*m)

### 2. "Parallel Processing: Different layers of the WAF can execute concurrently where possible"

**Status**: UNVERIFIED
- No evidence of parallel/concurrent execution within a single request
- Attack detection runs sequentially (sqli, xss, ssti, etc. one after another)
- Could be a future optimization target

### 3. "Distributed Intelligence: In a Mesh deployment, WAF nodes share blocked IP addresses and threat signatures in real-time"

**Status**: PARTIALLY VERIFIED
- Threat intelligence exists via `src/mesh/threat_intel.rs`
- IP blocking can be announced to DHT via `announce_honeypot_indicator`
- Behavioral intelligence exists but appears incomplete (empty feature extraction in `attack_detection/mod.rs:521-534`)

---

## Implementation Gaps

### 1. Behavioral Analysis Incomplete (Mesh Mode)

**Location**: `src/waf/attack_detection/mod.rs:478-535`

```rust
fn extract_behavioral_features(...) -> Option<...> {
    // ...
    Some(crate::mesh::behavioral_intel::RequestFeatures {
        header_timing_variance_ms: 0,           // HARDCODED ZERO
        request_sequence_entropy: 0.5,          // HARDCODED VALUE
        byte_length_distribution: vec![...],   // DERIVED FROM BODY ONLY
        inter_request_timing_ms: 0,            // HARDCODED ZERO
        suspicious_header_count,               // ACTUAL VALUE
        url_entropy,                            // ACTUAL VALUE
        body_to_header_ratio,                  // ACTUAL VALUE
    })
}
```

**Issue**: Behavioral features for anomaly detection are mostly hardcoded/zeros. The feature extraction captures structural properties but **does not track timing, sequence patterns, or historical behavior per IP**.

### 2. Test Mode Doesn't Cover All Components

**Location**: `src/waf/mod.rs:232-254`

Test mode flags exist but don't cover all WAF components consistently:
- `test_mode.attack_off` disables attack detection
- `test_mode.bot_off` disables bot detection
- `test_mode.challenge_off` disables challenges

But there's no `flood_off` flag implementation in `check_request_full`.

### 3. Challenge Manager Rate Limit Uses HashMap with No Atomic Cleanup

**Location**: `src/challenge/mod.rs:64`

```rust
attempts: RwLock<HashMap<IpAddr, ChallengeAttempt>>,
```

The rate limiting in `ChallengeManager::record_attempt` uses a write lock and performs cleanup by rebuilding the HashMap, which could cause issues under high concurrent load. The max entries limit (10,000) could lead to rejection of new challenge attempts.

### 4. CSS Session Store Has Race Condition in Cleanup

**Location**: `src/challenge/css.rs:152-168`

```rust
pub fn start_session(&self, session_id: &str, data: &CssChallengeData) {
    let mut store = self.sessions.write();
    let now = current_timestamp();

    // Proactive cleanup: clean expired sessions when table is >50% full
    if store.sessions.len() >= store.max_sessions / 2 {
        store.sessions.retain(...);  // First cleanup
    }

    // If still full after cleanup, reject new session
    if store.sessions.len() >= store.max_sessions {
        tracing::warn("CSS session table full, rejecting new session");
        return;  // Session rejected without acquiring write lock again
    }
    // ... insert session
}
```

Under high concurrent load, between the cleanup and the check, new sessions could fill the table.

---

## Code Improvements

### 1. Streaming WAF State Machine Reset Incomplete

**Location**: `src/waf/attack_detection/streaming.rs:250-260`

```rust
pub fn reset(&mut self) {
    let state = &mut self.state;
    state.pending_chunks.clear();
    state.current_input.clear();
    state.chunks_processed = 0;
    state.last_result = None;
    state.bytes_seen = 0;
    state.boundary = None;
    state.multipart_state = MultipartState::None;
    // NOTE: trailing_window not reset!
    state.trailing_window = BufferPool::acquire(0);
}
```

The `trailing_window` is reset to a zero-length buffer. However, this is actually correct behavior - the reset creates a fresh buffer from the pool. **Not a bug.**

### 2. Duplicate Code in SSRF Detector

**Location**: `src/waf/attack_detection/ssrf.rs:45-161`

The SSRF detector has private IP checking duplicated from the main code in `check_is_private_ip`. This could be consolidated.

### 3. SqliDetector and XssDetector Use Identical Pattern

Both `SqliDetector` and `XssDetector` use the same detection pattern:
1. Pattern matching via Aho-Corasick (lowercase)
2. libinjection fallback

This is good for consistency but the normalization is redundant since libinjection handles its own normalization.

### 4. Request Smuggling Detection Gap

**Location**: `src/waf/attack_detection/request_smuggling.rs`

The request smuggling detector only checks headers and body but **doesn't detect HTTP/2 pseudo-header smuggling** which is a common bypass technique.

### 5. Path Traversal Has Double-Search Inefficiency

**Location**: `src/waf/attack_detection/path_traversal.rs:55-73`

```rust
if decoded != input_lower {
    if let Some(mat) = self.inner.patterns_ref().find(&input_lower) {
        // Re-searches the same patterns on original input
    }
}
```

When decoded differs from input, it re-searches patterns on the original input. This is redundant - patterns should only need to run on decoded input.

---

## Bug Reports

### BUG 1: Potential Panic in SSRF IP Extraction

**Location**: `src/waf/attack_detection/ssrf.rs:207-222`

```rust
if in_url && (bytes[current] == b':' || current == url_start) {
    let start = if bytes[current] == b':' && current > url_start {
        current + 1
    } else {
        current
    };
    let remaining = &input_lower[start..];  // Could panic if start > len

    if let Some(slash_pos) = remaining.find('/') {
        let potential_ip = &remaining[..slash_pos];
```

If `start > input_lower.len()`, this causes a panic. Should add bounds check.

### BUG 2: SSRF Octal Parsing Allows Invalid Octets

**Location**: `src/waf/attack_detection/ssrf.rs:95-122`

```rust
fn parse_ipv4_octal(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    // ...
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            let octal: u32 = u32::from_str_radix(part, 8).ok()?;  // Allows "08" "09"
            if octal > 255 {  // But then rejects > 255
                return None;
            }
```

Octal parsing allows `08` and `09` which are invalid octal but get rejected later. This creates confusing behavior.

### BUG 3: SqliDetector Doesn't Use Libinjection Fingerprint

**Location**: `src/waf/attack_detection/sqli.rs:52-69`

```rust
let result = libinjectionrs::detect_sqli(normalized.as_bytes());

if result.is_injection() {
    let fingerprint = result.fingerprint.map(|fp| fp.to_string());

    tracing::warn!(
        attack_type = "sqli",
        fingerprint = ?fingerprint,
        location = %location,
        "SQL injection detected (libinjection)"
    );

    Some(AttackDetectionResult {
        attack_type: AttackType::Sqli,
        fingerprint,  // Set but never used downstream
        matched_pattern: None,
        input_location: location,
    })
}
```

The fingerprint is captured but never used in the `AttackDetectionResult`. However, the result is passed to metrics but the fingerprint field itself is not utilized in blocking decisions.

---

## Security Concerns

### 1. SSRF Allowlist Bypass via Subdomain Confusion

**Location**: `src/waf/attack_detection/ssrf.rs:426-456`

```rust
if self.allowlist_only_mode {
    if Self::has_word_boundary(input_lower, dot_domain) {
        return true;
    }
}
```

The allowlist mode check for word boundaries could be bypassed with crafted domain names like `allowed.com.example.com` vs `allowed.com.attacker.com`. The logic checks for prefix and dot, but doesn't prevent sibling domains.

### 2. PoW Challenge Secret Key Generated Each Restart

**Location**: `src/challenge/pow.rs:31-43`

```rust
pub fn new(difficulty: u8, window_secs: u64, timeout_secs: u64, cookie_name: String) -> Self {
    let mut secret_key = [0u8; 32];
    rand::fill(&mut secret_key);  // Generated on each PowManager creation
```

The PoW secret key is regenerated each time the server restarts. This means:
- Clients cannot use cached challenges after restart
- Old challenge cookies become invalid

This is a **DoS vector** if legitimate clients have cached challenges.

### 3. CSS Challenge Assets Not Validated by Content

**Location**: `src/challenge/css.rs:181-240`

```rust
for valid_name in &session.valid_names {
    if asset_name.starts_with(valid_name) {
        session.requested_valid.insert(valid_name.clone());
```

The verification only checks if the requested asset name **starts with** a valid name. This allows:
- `waf-rnd-name12345.png` matches valid name `waf-rnd-name1`
- An attacker could enumerate valid names by checking which prefixes work

### 4. IP Feed Block Has Zero Duration Default

**Location**: `src/waf/mod.rs:1300`

```rust
self.block_ip_with_threat_intel(client_ip, "ip_feed", 0, "global");
```

When blocking from IP feed, the duration is `0`. This means the block might not persist or could be immediately expired.

---

## Missing Documentation

### 1. WAF Pipeline Order Not Documented

The architecture document lists protection layers but doesn't specify the actual execution order in `check_request_full`:
1. ASN check
2. Rate limit check
3. IP feed check
4. DHT threat lookup (mesh)
5. Endpoint block check
6. Suspicious word recording
7. Honeypot check
8. Bot protection
9. Attack pattern detection
10. Challenge check

### 2. Anomaly Scoring Thresholds Not Documented

The document mentions "Anomaly Scoring" but doesn't document:
- Default threshold (100 per `config.rs:43`)
- Score weights per attack type
- How scores are accumulated and compared

### 3. Threat Level Escalation Not Documented

The document mentions "Threat Level" but doesn't document:
- How threat levels are calculated
- What `escalation.violations_before_block` defaults to
- How `record_violation` and `maybe_escalate_and_block` work

### 4. PoW Difficulty Scaling Not Documented

The document mentions PoW challenges but doesn't document:
- Default difficulty (12)
- How difficulty is clamped (1-20)
- How difficulty scales with threat level

### 5. Streaming WAF Chunk Size Limits Not Documented

**Location**: `src/waf/attack_detection/streaming.rs:9-10`

```rust
const DEFAULT_CHUNK_SIZE: usize = 4096;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 2 * 1024 * 1024;
```

These constants are not documented and the chunk size cannot be configured via the AttackDetectionConfig.

---

## Summary

### Strengths
1. Comprehensive attack detection coverage (SQLi, XSS, SSRF, RFI, CMD, SSTI, XXE, etc.)
2. Multiple defense layers with fallback mechanisms
3. Good use of libinjection for SQLi/XSS detection
4. Input normalization is thorough (URL, HTML entities, Unicode, homoglyphs)
5. Bot detection with multiple strategies (UA, JA3/JA4 fingerprints, AI crawlers)
6. Challenge system with PoW, CSS, and Mesh-PoW options
7. Streaming WAF for large request body inspection

### Areas for Improvement
1. Behavioral analysis features are incomplete (hardcoded zeros)
2. No parallel processing despite document claiming it
3. Distributed threat intelligence underutilized
4. Some detection logic has redundant operations
5. Security concerns with allowlist bypass and challenge persistence

### Recommended Actions
1. Implement actual behavioral analysis tracking across requests
2. Document the actual pipeline execution order
3. Fix SSRF IP extraction bounds checking
4. Improve PoW secret key persistence
5. Add configuration options for streaming chunk sizes

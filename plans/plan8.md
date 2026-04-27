# Code Quality Improvement Plan

**Status**: Planned
**Last Updated**: 2026-04-27
**Priority**: P0-Critical, P1-High, P2-Medium, P3-Low

## Executive Summary

Following a comprehensive code quality review, 11 major issue categories have been identified requiring remediation. The highest priority items are test coverage gaps for critical hot paths and a mutex panic risk in `ConnectionTokenGuard`. This plan addresses issues in a stepped fashion, starting with P0 items.

---

## Priority Matrix

| Priority | Item | Impact | Effort | Risk if Not Fixed |
|----------|------|--------|--------|-------------------|
| **P0** | `ConnectionTokenGuard` std::Mutex panic risk | Critical | Low | Process crash on any WAF thread panic |
| **P0** | Hot path test gaps (mesh/proxy, http3, proxy) | High | High | Untested reliability at 500K RPS |
| **P0** | rule_feed test failures (global state) | Medium | Medium | CI instability, regressions undetected |
| **P1** | cloakrs MSRV 1.87 typo | High | Low | Builds fail on stable Rust |
| **P1** | Hot path allocations (format!, HashMap, to_lowercase) | High | Medium | Performance degradation at scale |
| **P1** | DashMap test hangs in sliding.rs | Medium | Medium | 3 tests never run |
| **P2** | ArcStr duplication | Low | Medium | Code confusion, maintenance burden |
| **P2** | Missing concurrency stress tests | Medium | High | Undetected race conditions |
| **P2** | 892 .unwrap() calls (error handling) | Low | High | Reliability issues in edge cases |
| **P3** | Document src/http/server.rs (4211 lines) | Medium | High | Maintainability |
| **P3** | Split god modules (http/server, mesh/transport) | Low | Very High | Maintainability - DEFERRED |

---

## P0-1: Critical and High Priority Issues

### P0-1.1: Fix ConnectionTokenGuard Mutex Panic Risk

**Issue**: Uses `std::sync::Mutex` with `.unwrap()` in `src/http/server.rs:53,62`. Any thread panic while holding the lock poisons it, causing subsequent requests to panic and crash the process.

**Files Affected**:
- `src/http/server.rs:39-66` (`ConnectionTokenGuard` struct)
- `src/http/server.rs:53` (`self.token.lock().unwrap()`)
- `src/http/server.rs:62` (`self.token.lock().unwrap()`)

**Root Cause**: `std::sync::Mutex` poisons on panic; `parking_lot::Mutex` does not.

**Fix Options**:

**Option A (Recommended)**: Switch to `parking_lot::Mutex`
```rust
// src/http/server.rs:39
// Change from:
token: Arc<Mutex<Option<ConnectionToken>>>,
// To:
token: Arc<parking_lot::Mutex<Option<ConnectionToken>>>,

// Lines 53, 62: Change from:
let mut guard = self.token.lock().unwrap();
// To:
let mut guard = self.token.lock();
// parking_lot::Mutex::lock() returns &mut T directly, not Result
```

**Option B**: Handle poison explicitly
```rust
let mut guard = match self.token.lock() {
    Ok(g) => g,
    Err(e) => {
        tracing::error!("ConnectionTokenGuard mutex poisoned, recovering");
        e.into_inner()
    }
};
```

**Verification**:
```bash
cargo test --lib --no-run
cargo test --test integration_test
```

**Effort**: 1-2 hours

---

### P0-1.2: Add Tests for Hot Paths

Critical hot path files have ZERO test coverage. These are the most reliability-critical components at 500K RPS.

#### P0-1.2A: Add Tests for `src/mesh/proxy.rs` (1757 lines)

**Current State**: No `#[cfg(test)]` block exists. The file handles:
- Policy resolution and caching (lines 460-581)
- Circuit breaker state machine (lines 112-218)
- Provider selection with weighted shuffle (lines 747-783)
- Response transformation (minification, image poisoning, compression) (lines 1256-1580)
- Tiered transform cache L1/L2 (lines 263-312)

**Critical Scenarios Needed**:

| Scenario | Lines | Risk at 500K rps |
|----------|-------|------------------|
| Circuit breaker opens after 5 failures | 147-194 | Post-failure |
| Circuit breaker half-open after 30s timeout | 147-194 | Post-failure |
| Circuit breaker closes after 3 successes | 147-194 | Post-recovery |
| `resolve_upstream` cache hit (healthy peer) | 466-481 | Every request |
| `resolve_upstream` stale cache fallback | 483-490 | Every 3600s |
| `resolve_upstream` all providers failed | 492-499 | Degraded mode |
| `proxy_to_peer_with_fallback` all providers fail | 1001-1097 | Degraded mode |
| Block broadcast after 5 consecutive failures | 1031-1047 | Post-threshold |
| Transform cache L1→L2 promotion | 289-292 | Per-transform |
| Weighted shuffle distribution (statistical) | 747-783 | Per-request |

**Test Pattern** (follow `src/upstream/pool.rs:654-1100+`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_mesh_proxy() -> MeshProxy { ... }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let mut stats = ProviderStats::new();
        for _ in 0..CIRCUIT_OPEN_THRESHOLD {
            stats.record_failure();
        }
        assert_eq!(stats.circuit_state, CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_half_open_on_timeout() { ... }
    #[test]
    fn test_circuit_breaker_closes_after_success_threshold() { ... }

    #[test]
    fn test_stale_cache_returns_for_failed_provider() { ... }

    #[test]
    fn test_weighted_shuffle_distribution() {
        // Statistical test: higher score selected more often
        let providers = vec![
            ProviderInfo { score: 1.0, .. },
            ProviderInfo { score: 0.5, .. },
            ProviderInfo { score: 0.25, .. },
        ];
        // Run 1000 times, verify high_score selected > 40% (random would be 25%)
    }

    #[test]
    fn test_transform_cache_l1_to_l2_promotion() { ... }
}
```

**Verification**:
```bash
cargo test --lib mesh::proxy::tests
```

**Effort**: 1 week

---

#### P0-1.2B: Add Tests for `src/http3/server.rs` (660 lines)

**Current State**: No `#[cfg(test)]` block exists. The file handles:
- QUIC connection acceptance and flood protection (lines 138-202)
- Streaming WAF chunk scanning (lines 263-299)
- WAF decision handling (Stall, Block, Challenge, Tarpit, Drop) (lines 333-468)
- Per-site connection limiting (lines 479-507)
- Response streaming (lines 567-590)

**Critical Scenarios Needed**:

| Scenario | Lines | Risk at 500K rps |
|----------|-------|------------------|
| Streaming WAF chunk scan (SQLi in chunk) | 276-296 | Every request |
| Streaming WAF buffer overflow (HTTP 413) | 266-269 | Malicious body |
| WAF decision: Stall (10s delay) | 334-341 | Post-check |
| WAF decision: Block (JSON error) | 342-365 | Post-check |
| WAF decision: Challenge (HTML) | 366-395 | Post-check |
| WAF decision: ChallengeWithCookie (with Set-Cookie) | 396-435 | Post-check |
| WAF decision: Tarpit (delayed response) | 436-462 | Post-check |
| WAF decision: Drop (silent) | 463-466 | Post-check |
| Per-site connection limiting | 479-507 | Per-site |
| Bandwidth limit exceeded | 226-230 | Per-check |
| Flood decision: Blackholed | 153-157 | Per-connection |
| Flood decision: RateLimited | 158-163 | Per-connection |

**Test Pattern**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_request_stall_decision() {
        // Create Http3Server with mock WAF returning Stall
        // Verify 10s delay before response
    }

    #[test]
    fn test_handle_request_block_decision() {
        // Verify 403 response with JSON error body
    }

    #[test]
    fn test_handle_request_challenge_with_cookie() {
        // Verify Set-Cookie header present in challenge response
    }

    #[test]
    fn test_streaming_waf_scans_chunks() {
        // Create streaming detector, feed chunks with attack pattern
        // Verify Block decision returned
    }

    #[test]
    fn test_body_size_limit_enforcement() {
        // Create with small max_request_size, send oversized body
        // Verify body_too_large counter incremented
    }

    #[test]
    fn test_connection_limit_per_ip() {
        // Simulate exceeding per-IP connection limit
        // Verify connection_limited counter
    }
}
```

**Verification**:
```bash
cargo test --lib http3::server::tests
```

**Effort**: 1 week

---

#### P0-1.2C: Add Tests for `src/proxy/mod.rs` (1039 lines)

**Current State**: No `#[cfg(test)]` block in `mod.rs`. The file handles:
- WAF decision handling (Drop, Stall, Block, Challenge, Tarpit) (lines 332-381)
- Upstream error tracking and probing detection (lines 397-449)
- Retry logic with exponential backoff (lines 880-920)
- Cache handling with PURGE and stale-while-revalidate (lines 503-620)
- Request sending with max response size enforcement (lines 964-1038)

**Critical Scenarios Needed**:

| Scenario | Lines | Risk at 500K rps |
|----------|-------|------------------|
| WAF decision: Drop (blackholed) | 332-336 | Per-attack |
| WAF decision: Stall (30s sleep) | 337-342 | Per-stall |
| WAF decision: Block (dropped) | 344-351 | Per-block |
| WAF decision: Challenge (with cookie) | 362-381 | Per-challenge |
| Retry on status code 502-504 | 880-894 | Per-retry |
| Retry on connection error | 903-920 | Per-retry |
| Retry backoff calculation | 886-891 | Per-retry |
| Cache purge (token auth required) | 638-709 | Per-purge |
| Cache stale-while-revalidate | 548-577 | Per-cache-hit |
| Upstream error 4xx tracking (probing) | 397-449 | Per-upstream-error |
| Response too large handling | 993-999 | Per-oversized |

**Test Pattern** (follow `src/proxy/headers.rs` and `src/upstream/pool.rs`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_proxy_server() -> ProxyServer { ... }

    #[tokio::test]
    async fn test_handle_request_drops_on_waf_drop() {
        let proxy = create_test_proxy_server_with_mock_waf(WafDecision::Drop);
        let result = proxy.handle_request(..).await;
        assert_eq!(err, "blackholed");
    }

    #[tokio::test]
    async fn test_forward_with_pool_retry_on_connection_error() {
        // First request fails, should retry
        // Second request also fails, give up after max_retries
    }

    #[test]
    fn test_retry_config_respects_max_retries() {
        // Verify only 3 total attempts (1 initial + 2 retries)
    }

    #[tokio::test]
    async fn test_upstream_error_tracking_probing_detection() {
        // Create 3 consecutive 404s from upstream
        // Verify ProbingDetected result
    }

    #[tokio::test]
    async fn test_handle_request_with_cache_purge_requires_token() {
        // PURGE without token -> 403
        // PURGE with wrong token -> 403
        // PURGE with correct token -> 200
    }

    #[tokio::test]
    async fn test_send_single_request_rejects_large_response() {
        // Mock upstream returns response > max_response_size
        // Verify Err("Response too large")
    }
}
```

**Verification**:
```bash
cargo test --lib proxy::mod::tests
```

**Effort**: 1 week

---

### P0-1.3: Fix rule_feed Test Failures (Global State Contamination)

**Issue**: Two tests in `src/waf/rule_feed.rs` fail intermittently due to global `RULE_PATTERN_STORE` state contamination between parallel tests.

**Failing Tests**:
- `test_get_merged_patterns` (line 888)
- `test_multi_category_pattern_merge` (line 945)

**Root Cause**:
```rust
// src/waf/rule_feed.rs:33-34
static RULE_PATTERN_STORE: LazyLock<RwLock<GlobalRulePatterns>> =
    LazyLock::new(|| RwLock::new(GlobalRulePatterns::default()));
```

When tests run in parallel (`--test-threads=0`):
1. Test A calls `clear_global_patterns()` → resets to empty
2. Test A sets `update_patterns_for_category("sqli", vec!["feed_pattern"])`
3. Test B (different thread) calls `clear_global_patterns()` → resets to empty
4. Test B sets `update_patterns_for_category("sqli", vec!["custom1"])`
5. Test A reads `get_custom_patterns_for_category("sqli")` → gets Test B's value → **FAIL**

**Recommended Fix (Instance-Based Pattern)**:

```rust
// src/waf/rule_feed.rs

// Create RulePatternStore struct that can be injected
pub struct RulePatternStore {
    patterns: RwLock<GlobalRulePatterns>,
}

impl RulePatternStore {
    pub fn new() -> Self {
        Self {
            patterns: RwLock::new(GlobalRulePatterns::default()),
        }
    }

    pub fn get_merged_patterns(&self, ...) -> Vec<String> { ... }
    pub fn update_patterns_for_category(&self, ...) { ... }
    pub fn clear_patterns(&self) { ... }
}

// Global singleton for production
static RULE_PATTERN_STORE: LazyLock<RulePatternStore> =
    LazyLock::new(|| RulePatternStore::new());

pub fn get_global_pattern_store() -> &'static RulePatternStore {
    &RULE_PATTERN_STORE
}

// Tests can use isolated instances
#[cfg(test)]
impl RulePatternStore {
    pub fn new_for_test() -> Self {
        Self::new()
    }
}
```

**Test Changes**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_merged_patterns() {
        let store = RulePatternStore::new_for_test();
        store.update_patterns_for_category("sqli", vec!["test_pattern".to_string()]);
        let patterns = store.get_merged_patterns("sqli", ...);
        assert_eq!(patterns, vec!["test_pattern"]);
    }

    #[test]
    fn test_multi_category_pattern_merge() {
        let store = RulePatternStore::new_for_test();
        store.update_patterns_for_category("sqli", vec!["sqli_pattern".to_string()]);
        store.update_patterns_for_category("xss", vec!["xss_pattern".to_string()]);
        // Verify isolation
    }
}
```

**Verification**:
```bash
cargo test --lib waf::rule_feed::tests
# Should pass even with --test-threads=0
```

**Effort**: 1 week

---

### P1-1.4: Fix cloakrs MSRV Typo

**Issue**: `cloak/Cargo.toml:5` specifies `rust-version = "1.87"` which is a future Rust version (current is 1.93). This will cause builds to fail.

**Fix**:
```toml
# cloak/Cargo.toml:5
# Change from:
rust-version = "1.87"
# To (based on dependencies supporting 1.63+):
rust-version = "1.81"
```

**Also Consider**: Add MSRV to main `maluwaf` Cargo.toml for workspace consistency:
```toml
[package]
rust-version = "1.81"  # Add to maluwaf Cargo.toml
```

**Verification**:
```bash
cargo check -p cloakrs
rustc --version | head -1
```

**Effort**: 10 minutes

---

### P1-1.5: Optimize Hot Path Allocations

At 500K RPS, even small per-request allocations compound significantly:
- 500K × 1 extra allocation/req = 500K allocations/sec
- 500K × 8 extra allocations/req = 4M allocations/sec

#### P1-1.5A: `format!("{}?{}", path, qs)` in mod.rs:358-361

```rust
// Current (allocation per request):
let url = if let Some(qs) = query_string {
    format!("{}?{}", path, qs)
} else {
    path.to_string()
};

// Fix: Use thread-local buffer
thread_local! {
    static BEHAVIORAL_URL_BUF: RefCell<String> = RefCell::new(String::with_capacity(8192));
}

fn extract_behavioral_features(...) -> Option<...> {
    let url = BEHAVIORAL_URL_BUF.with(|buf_cell| {
        let mut buf = buf_cell.borrow_mut();
        buf.clear();
        buf.push_str(path);
        if let Some(qs) = query_string {
            buf.push('?');
            buf.push_str(qs);
        }
        buf[..].to_string()  // Reuses capacity, single allocation
    });
    // ...
}
```

#### P1-1.5B: `HashMap::new()` for entropy in mod.rs:410

```rust
// Current (allocation per request):
fn calculate_string_entropy(s: &str) -> f32 {
    let mut char_counts: HashMap<char, usize> = HashMap::new();
    // ...
}

// Fix: Use stack-allocated array for ASCII-only
fn calculate_string_entropy(s: &str) -> f32 {
    let mut ascii_counts = [0u32; 128];
    let mut other_chars = 0;

    for c in s.chars() {
        if c as u32 < 128 {
            ascii_counts[c as usize] += 1;
        } else {
            other_chars += 1;
        }
    }

    if other_chars > 0 {
        // Fall back to HashMap only for non-ASCII
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        // ...
    }

    // Calculate entropy from stack array
    let len = s.len() as f32;
    ascii_counts.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum()
}
```

#### P1-1.5C: `normalize_input()` in cmd_injection.rs:64

**Issue**: `CmdInjectionDetector` has its own `normalize_input()` function that allocates. The codebase already has `InputNormalizer` with thread-local buffers.

**Fix**: Reuse `InputNormalizer`:
```rust
pub struct CmdInjectionDetector {
    inner: BasePatternDetector,
    normalizer: InputNormalizer,  // Add this field
}

impl CmdInjectionDetector {
    pub fn new(paranoia_level: u8, custom_patterns: &[String]) -> Self {
        Self {
            inner: BasePatternDetector::new(...),
            normalizer: InputNormalizer::new(),
        }
    }

    fn detect_with_normalization(&self, input: &str, location: InputLocation) -> Option<...> {
        // Use InputNormalizer's thread-local buffers
        let normalized = self.normalizer.normalize(input);
        // Use normalized.normalized instead of calling normalize_input()
        // ...
    }
}
```

#### P1-1.5D: `format!("http://{}:{}", host, port)` in proxy.rs:596

**Fix**: Use small key struct instead of String:
```rust
#[derive(Hash, PartialEq, Eq)]
struct UpstreamKey {
    host: Arc<str>,
    port: u16,
    scheme: &'static str,
}

fn extract_upstream_id(&self, req: &Request<Incoming>) -> Result<UpstreamKey, MeshProxyError> {
    let uri = req.uri();
    let host = uri.host()...;
    let port = uri.port_u16().unwrap_or(...);
    Ok(UpstreamKey {
        host: Arc::from(host),
        port,
        scheme: if uri.scheme_str() == Some("https") { "https" } else { "http" },
    })
}
```

#### P1-1.5E: `body.clone(), headers.clone()` in proxy.rs:941-970

**Current**: N clones for N providers in fallback loop

**Fix**:
```rust
// Pre-clone headers ONCE before loop (headers.clone() still allocates but once)
let headers = req.headers().clone();
let method = req.method().clone();
let uri = req.uri().clone();

// body_bytes.clone() is cheap (Bytes uses Arc internally)
// Only headers.clone() per provider is the concern

// For high-contention, consider pre-serializing:
let headers_bytes = {
    let mut buf = Vec::new();
    for (name, value) in headers.iter() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.push(b':');
        buf.extend_from_slice(value.as_bytes());
        buf.push(b'\r');
        buf.push(b'\n');
    }
    buf.push(b'\r');
    buf.push(b'\n');
    buf
};
```

**Verification**:
```bash
cargo test --lib waf::attack_detection::tests
cargo test --lib mesh::proxy::tests  # After tests are added
```

**Effort**: 1-2 weeks

---

### P1-1.6: Fix DashMap Test Hangs in sliding.rs

**Issue**: Three tests in `src/waf/ratelimit/sliding.rs` hang due to DashMap initialization issues with `LazyLock` and thread parking.

**Ignores** (lines 356, 372, 388):
- `test_sliding_window_limiter_ip`
- `test_sliding_window_limiter_limit`
- `test_sliding_window_different_keys`

**Root Cause**: DashMap uses `thread::park()` when shard locks are contended. There's an interaction issue with Rust's `LazyLock` and the parking lot implementation.

**Recommended Fix**: Replace `DashMap` with `RwLock<HashMap>`:

```rust
// src/waf/ratelimit/sliding.rs:169-174
// Change from:
pub struct SlidingWindowLimiter<K: Hash + Eq> {
    entries: dashmap::DashMap<K, SlidingWindowEntry>,
    configs: Vec<SlidingWindowConfig>,
    max_entries: usize,
    cleanup_threshold: f64,
}

// To:
use parking_lot::RwLock;
use std::collections::HashMap;

pub struct SlidingWindowLimiter<K: Hash + Eq + Clone> {
    entries: RwLock<HashMap<K, SlidingWindowEntry>>,
    configs: Vec<SlidingWindowConfig>,
    max_entries: usize,
    cleanup_threshold: f64,
}

// Update check_and_increment at lines 186-204:
pub fn check_and_increment(&self, key: &K) -> SlidingDecision {
    let entry = {
        let mut entries = self.entries.write();
        entries.entry(key.clone()).or_insert_with(|| SlidingWindowEntry::new(&self.configs)).clone()
    };
    // ... rest unchanged
}

// Update other methods that access self.entries
```

**Note**: This aligns with other rate limiting code in `src/waf/ratelimit.rs` which uses `RwLock<HashMap>`.

**Verification**:
```bash
cargo test --lib waf::ratelimit::sliding::tests
# Remove #[ignore] attributes after fix
```

**Effort**: 4-8 hours

---

## P2: Medium Priority Issues

### P2-1.7: ArcStr Duplication

**Issue**: `ArcStr` type defined in two places:
- `src/utils.rs:77-140` - Completely unused (0 references)
- `src/mesh/protocol.rs:15-73` - Used in 266+ places, has rkyv support

**Finding**: The `utils.rs` version is dead code. The `protocol.rs` version is canonical.

**Recommended Action**:
1. Keep `protocol.rs` version as canonical
2. Add deprecation note to `utils.rs` version:
```rust
// src/utils.rs:77
#[deprecated(since = "0.1.0", note = "Use crate::mesh::protocol::ArcStr instead")]
pub struct ArcStr(pub Arc<str>);
```
3. Add comment in `protocol.rs` noting this is the canonical version

**Verification**:
```bash
cargo check
# No functional changes
```

**Effort**: 2-3 hours (documentation/cleanup only)

---

### P2-1.8: Add Concurrency Stress Tests

**Issue**: 166+ DashMap uses, 632+ atomic operations, but no concurrency stress tests. Known race conditions exist but are untested.

**Known Race Conditions NOT Tested**:

| Location | Issue |
|----------|-------|
| `topology/types.rs:317-350` | `cleanup_inactive` releases locks between shard iterations |
| `behavioral_intel.rs:126-131` | `analyze_request` reads from two separate locks non-atomically |
| `sliding.rs:79-107` | `AtomicBucketWindow::rotate_and_get_bucket` can lose updates during rotation |
| `threat_intel.rs:1002-1016` | Sequential writes to `indicators` then `local_version` not atomic |

**Recommended Test File**: `tests/concurrency_stress_test.rs`

**Test Scenarios**:

```rust
// tests/concurrency_stress_test.rs
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_sharded_peer_store_concurrent_stress() {
    let store = Arc::new(ShardedPeerStore::new());
    let errors = Arc::new(AtomicUsize::new(0));

    // 32 concurrent writers hitting DIFFERENT shards
    let handles: Vec<_> = (0..32u32).map(|i| {
        let store = store.clone();
        std::thread::spawn(move || {
            let node_id = format!("node_{}", i);
            for iteration in 0..1000 {
                let peer = create_test_peer(&node_id);
                store.upsert_peer(peer);
                store.record_connection_success(&node_id);
                store.record_latency(&node_id, iteration);
                if iteration % 100 == 0 {
                    let active: HashSet<_> = vec![node_id.clone()].into_iter().collect();
                    store.cleanup_inactive(&active);
                }
            }
        })
    }).collect();

    // 32 concurrent readers
    let reader_handles: Vec<_> = (0..32u32).map(|i| {
        let store = store.clone();
        let errors = errors.clone();
        std::thread::spawn(move || {
            let node_id = format!("node_{}", i);
            for _ in 0..1000 {
                let peer = store.get_peer(&node_id);
                let score = store.get_peer_score(&node_id);
                if score.is_none() && i % 2 == 0 {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    }).collect();

    for h in handles { h.join().unwrap(); }
    for h in reader_handles { h.join().unwrap(); }
    assert_eq!(errors.load(Ordering::Relaxed), 0, "Inconsistent state detected");
}

#[test]
fn test_atomic_bucket_window_concurrent_rotation() {
    let window = Arc::new(AtomicBucketWindow::new(1, 10));
    let counts = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..100).map(|_| {
        let window = window.clone();
        let counts = counts.clone();
        std::thread::spawn(move || {
            for _ in 0..10000 {
                window.increment();
                counts.fetch_add(1, Ordering::Relaxed);
            }
        })
    }).collect();

    for h in handles { h.join().unwrap(); }

    // Due to rotation races, count may be less than expected
    let total = counts.load(Ordering::Relaxed);
    let actual = window.get_count();
    println!("Incremented: {}, In buckets: {}", total, actual);
    // Note: Some loss is expected due to rotation clearing, but should be < 1%
}

#[test]
fn test_threat_intel_concurrent_insert() {
    // Similar pattern - 50 threads, 100 insertions each
    // Verify version consistency at end
}
```

**Verification**:
```bash
cargo test --test concurrency_stress_test
```

**Effort**: 2 weeks

---

### P2-1.9: Clean Up .unwrap() Calls (Error Handling)

**Issue**: ~892 `.unwrap()` calls across codebase. Many are in hot paths and error handling paths that could panic.

**Top 5 Critical Hot Path Unwraps to Fix**:

| File | Line | Code | Severity |
|------|------|------|----------|
| `http/server.rs` | 53 | `self.token.lock().unwrap()` | **CRITICAL** (already in P0-1.1) |
| `http/server.rs` | 62 | `self.token.lock().unwrap()` | **CRITICAL** (already in P0-1.1) |
| `http3/server.rs` | 607 | `.body(body).unwrap()` | HIGH |
| `mesh/proxy.rs` | 1272 | `tm.unwrap()` | HIGH |
| `http/server.rs` | 737 | Response building `.unwrap()` | HIGH |

**Fix Pattern**:
```rust
// http3/server.rs:607
// Change from:
.body(body).unwrap()
// To:
.body(body).expect("Bad gateway response should always be valid")
// Or for graceful degradation:
.map_err(|e| format!("Bad gateway: {}", e))?
```

**Verification**:
```bash
cargo test --lib
cargo clippy -- -D warnings
```

**Effort**: 1-2 days for top 5, 2 weeks for all

---

## P3: Lower Priority Issues

### P3-1.10: Document src/http/server.rs

**Issue**: 4211 lines with no module-level documentation.

**Required Documentation Structure**:
```rust
//! HTTP/1.1 Server for MaluWAF
//!
//! This module implements the primary HTTP/1.1 server that handles incoming
//! requests in a MaluWAF worker process. It orchestrates request filtering,
//! routing, backend dispatch, and response handling.
//!
//! # Architecture
//!
//! The server is built on `hyper` and handles the full request lifecycle:
//!
//! - **Protocol Validation**: Detects and rejects non-HTTP connections on HTTP ports
//! - **Connection Management**: Semaphore-based global and per-site connection limiting
//! - **WAF Inspection**: Early and full body scanning via `WafCore`
//! - **Request Routing**: Host/path-based routing to backends via `Router`
//! - **Backend Dispatch**: Multiple backend types (upstream proxy, static files, WebSocket, serverless, etc.)
//! - **Response Transforms**: Minification, image poisoning, compression
//!
//! # Request Flow
//!
//! 1. TCP connection accepted, TLS/HTTP protocol detected
//! 2. Flood protection check (TCP-level)
//! 3. Internal endpoint handling (drain, health, ready)
//! 4. Connection limiting (global and per-site)
//! 5. Bandwidth limiting check
//! 6. WebSocket upgrade detection
//! 7. WAF early decision (challenge, block, drop)
//! 8. Full body collection (chunked for large bodies)
//! 9. WAF full body inspection
//! 10. Routing and site resolution
//! 11. Per-site connection limiting
//! 12. Backend dispatch
//! 13. WASM plugin filters
//! 14. Upstream proxying with response transforms
//! 15. Request logging
//!
//! # Backend Types
//!
//! The server dispatches to different backend types via `BackendType`:
//!
//! - **`Upstream`**: HTTP proxy to configured upstream
//! - **`FastCgi` / `Cgi` / `Php`**: CGI-based backends
//! - **`Static`**: Static file serving
//! - **`Serverless`**: WASM serverless functions
//! - **`AppServer`**: Granian Python ASGI server
//! - **`AxumDynamic`**: Plugin-based dynamic handlers
//! - **`WebSocket`**: WebSocket tunneling to backends
//! - **`QuicTunnel`**: QUIC tunnel proxying
//! - **`Mesh`**: Mesh-routed requests
//!
//! # Key Types
//!
//! - **`HttpServer`**: Main server struct with builder pattern
//! - **`HttpConnection`**: Per-connection state wrapper
//! - **`ConnectionTokenGuard`**: RAII guard for connection limiting
//! - **`ProtocolValidatingStream`**: Protocol detection wrapper
//! - **`RequestMetrics`**: Request-scoped metrics helper

pub struct HttpServer { ... }  // Document key fields
```

**Key Structs to Document**:
- `HttpServer` (line 323) - Main server struct
- `HttpConnection` (line 219) - Per-connection state
- `ConnectionTokenGuard` (line 39) - RAII guard for connection limiting
- `ProtocolValidatingStream` (line 163) - Protocol detection wrapper
- `DrainGuard` (line 250) - Worker drain state tracking
- `RequestMetrics` (line 277) - Per-request metrics helper

**Verification**:
```bash
cargo doc --no-deps --open 2>&1 | head -50
```

**Effort**: 1 week

---

### P3-1.11: Split God Modules

**Status**: DEFERRED - address after other issues are resolved

**Reason**: High effort (weeks per module), lower immediate impact than P0-P2 items.

**Recommended Order** (when deferred work begins):
1. **`src/metrics/mod.rs`** (2086 lines) - Easiest (pure functions, no complex interdependencies)
2. **`src/mesh/transport.rs`** (3291 lines) - Already documented as split in file header
3. **`src/http/server.rs`** (4211 lines) - Most complex, deferred

**Pattern to Follow**: `src/waf/attack_detection/` module structure (20+ files, each detector in own file).

---

## Implementation Order Summary

| Week | Items |
|------|-------|
| **Week 1** | P0-1.1 (ConnectionTokenGuard), P1-1.4 (cloakrs MSRV) |
| **Week 2** | P1-1.6 (DashMap test hangs), P3-1.10 (http/server.rs docs - header only) |
| **Week 3-4** | P0-1.2A (mesh/proxy tests) |
| **Week 5** | P0-1.2B (http3/server tests) |
| **Week 6** | P0-1.2C (proxy/mod tests), P0-1.3 (rule_feed test fixes) |
| **Week 7-8** | P1-1.5 (hot path allocations) |
| **Week 9-10** | P2-1.8 (concurrency stress tests) |
| **Week 11+** | P2-1.7 (ArcStr cleanup), P2-1.9 (unwrap cleanup), P3-1.11 (god module split - deferred) |

---

## Verification Commands

```bash
# Test compilation (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <module>::tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Documentation check
cargo doc --no-deps 2>&1 | head -20

# Specific fixes verification
cargo test --lib waf::ratelimit::sliding::tests  # After DashMap fix
cargo test --lib waf::rule_feed::tests  # After global state fix
```

---

## Files Affected Summary

| Issue | Files |
|-------|-------|
| P0-1.1: ConnectionTokenGuard | `src/http/server.rs:39-66,53,62` |
| P0-1.2A: mesh/proxy tests | `src/mesh/proxy.rs` (new tests) |
| P0-1.2B: http3/tests | `src/http3/server.rs` (new tests) |
| P0-1.2C: proxy tests | `src/proxy/mod.rs` (new tests) |
| P0-1.3: rule_feed | `src/waf/rule_feed.rs:33-34, test section` |
| P1-1.4: cloakrs MSRV | `cloak/Cargo.toml:5`, `Cargo.toml` (add MSRV) |
| P1-1.5: allocations | `src/waf/attack_detection/mod.rs:358-361,410`, `cmd_injection.rs:64`, `mesh/proxy.rs:596,941-970` |
| P1-1.6: DashMap hangs | `src/waf/ratelimit/sliding.rs:170,186-204` |
| P2-1.7: ArcStr | `src/utils.rs:77-140` (deprecated), `src/mesh/protocol.rs:15-73` (canonical) |
| P2-1.8: concurrency tests | `tests/concurrency_stress_test.rs` (new) |
| P2-1.9: unwrap cleanup | Multiple files (892 locations) |
| P3-1.10: http/server docs | `src/http/server.rs:1-68` (new module docs) |
| P3-1.11: god module split | `src/metrics/mod.rs`, `src/mesh/transport.rs`, `src/http/server.rs` (DEFERRED) |
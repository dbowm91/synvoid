# Test Coverage Improvement Plan

**Plan ID:** 6
**Project:** MaluWAF Test Coverage Enhancement
**Date:** 2026-04-27
**Status:** Draft
**Architecture:** Overseer/Master/Worker (3-level process hierarchy)

---

## 1. Executive Summary

This plan addresses test coverage gaps identified in a comprehensive codebase review. The codebase contains **2,184 tests** across unit and integration test suites, but critical gaps exist in hot-path functionality, process lifecycle management, and end-to-end request scanning.

### Key Findings

| Category | Current State | Gap Severity |
|----------|--------------|--------------|
| Test Infrastructure | 16 integration test files, 80+ unit test modules | Stable |
| **Compile Errors** | 1 test file (dht_integration_test) | **P0 - Blocking** |
| **Race Conditions** | 2 tests in rule_feed.rs | **P0 - Blocking** |
| WAF Core | Solid pattern matching, zero anomaly scoring tests | **P1 - Critical** |
| Worker HTTP Handling | No end-to-end tests | **P1 - Critical** |
| Process Lifecycle | State machine tested, actual process spawn NOT tested | **P2 - High** |
| Mesh Proxy | 0 unit tests for 1757-line module | **P2 - Medium** |
| DNS Recursive | Cache tested, real query path NOT tested | **P2 - Medium** |
| Plugin Execution | ~5% coverage, no real WASM execution tests | **P3 - Lower** |

### Recommended Priority

```
P0 (Immediate): Fix compile errors and race conditions
P1 (This Sprint): WAF core tests, Worker HTTP tests
P2 (Next Sprint): Process lifecycle, Mesh proxy tests
P3 (Backlog): Plugin execution, DNS recursive integration
```

---

## 2. Critical Issues - Immediate Action Required

### 2.1 DHT Integration Test Compile Error

**File:** `tests/dht_integration_test.rs`
**Problem:** `ThreatIntelligenceConfigInternal` and `ThreatIntelligenceConfig` were updated with 4 new fields for behavioral intelligence, but test instantiations were not updated.

**Missing Fields:**
```rust
behavioral_enabled: true,              // default: true
min_samples_for_fingerprint: 10,     // default: 10
fingerprint_ttl_secs: 3600,           // default: 3600
high_severity_threshold: 70,           // default: 70
```

**Locations requiring fixes:**
- Line 1377: `ThreatIntelligenceConfigInternal` in `create_test_manager()`
- Line 1451: `ThreatIntelligenceConfig` in test function
- Line 1802: `ThreatIntelligenceConfigInternal` in another test function
- Line 1839: Uses struct update syntax `..config_internal.clone()`, inherits missing fields

**Source reference:** `src/mesh/threat_intel.rs:140-159` defines `ThreatIntelligenceConfigInternal` with these fields.

**Action Required:**
1. Add the 4 missing fields to all `ThreatIntelligenceConfigInternal` instantiations
2. Add the 4 missing fields to all `ThreatIntelligenceConfig` instantiations
3. Use default values from the struct's Default impl (behavioral_enabled=true, min_samples=10, fingerprint_ttl=3600, high_severity=70)

**Effort:** 1-2 hours

---

### 2.2 Rule Feed Test Race Conditions

**File:** `src/waf/rule_feed.rs`
**Problem:** Global `RULE_PATTERN_STORE` static causes test interference when tests run in parallel.

**Root Cause:**
```rust
static RULE_PATTERN_STORE: LazyLock<RwLock<GlobalRulePatterns>> =
    LazyLock::new(|| RwLock::new(GlobalRulePatterns::default()));
```

When `test_get_merged_patterns` and `test_multi_category_pattern_merge` run in parallel:
1. Test A calls `clear_global_patterns()` → resets all patterns to `None`
2. Test A sets `update_patterns_for_category("sqli", vec!["feed_pattern"])`
3. Test B calls `clear_global_patterns()` → wipes Test A's patterns
4. Test A's assertion `merged.contains("feed_pattern")` fails

**Evidence:** Tests pass with `--test-threads=1` but fail with parallel execution.

**Recommended Fix Options:**

| Option | Approach | Pros | Cons |
|--------|----------|------|------|
| A | Thread-local storage | True isolation, no serialization | More code complexity |
| B | Mutex guard with `#[serial]` | Simple, guaranteed | Slower test execution |
| C | Arc-based test isolation | Clean API | Requires production refactor |

**Recommended: Option A - Thread-Local for Tests**

```rust
// Add to rule_feed.rs

#[cfg(test)]
thread_local! {
    static TEST_RULE_PATTERN_STORE: RwLock<GlobalRulePatterns> =
        RwLock::new(GlobalRulePatterns::default());
}

#[cfg(test)]
pub fn clear_global_patterns() {
    *RULE_PATTERN_STORE.write() = GlobalRulePatterns::default();
    TEST_RULE_PATTERN_STORE.with(|store| {
        *store.write() = GlobalRulePatterns::default();
    });
}

#[cfg(test)]
pub fn update_patterns_for_category(category: &str, patterns: Vec<String>) {
    // Update global (production)
    {
        let mut store = RULE_PATTERN_STORE.write();
        // ... macro-based category setting ...
    }
    // Update thread-local (tests)
    TEST_RULE_PATTERN_STORE.with(|store| {
        let mut s = store.write();
        // ... macro-based category setting ...
    });
}

#[cfg(test)]
pub fn get_custom_patterns_for_category(category: &str) -> Vec<String> {
    // Use thread-local for tests
    TEST_RULE_PATTERN_STORE.with(|store| {
        let patterns = store.read();
        // ... same macro pattern ...
    })
}
```

**Alternative Quick Fix (if thread-local is too complex):**
Add `#[serial]` attribute or manual Mutex to the two conflicting tests.

**Effort:** 2-4 hours

---

## 3. Critical Test Gaps - P1 Priority

### 3.1 WAF Core End-to-End Testing

**Files:** `src/waf/attack_detection/mod.rs`, `src/waf/attack_detection/streaming.rs`

**Current Coverage:**
- Unit-level pattern matching: Good (SQLi, XSS, SSTI, etc.)
- Input normalizer: Good
- Basic streaming: Minimal (4 tests)

**Critical Gaps:**

#### 3.1.1 Anomaly Scoring Tests (SECURITY-CRITICAL)

**Why Critical:** At 500K RPS, anomaly scoring determines blocking decisions. This code path has **zero test coverage** despite being security-critical.

**Location:** `src/waf/attack_detection/mod.rs` - `check_request_anomaly_scoring()` method

**Missing Tests:**
```rust
#[test]
fn test_anomaly_score_aggregates_from_all_detectors() {
    // Send request with multiple attack indicators
    // Verify anomaly score accumulates correctly
}

#[test]
fn test_anomaly_threshold_blocks_high_score() {
    // Configure threshold, send high-score request
    // Verify block response
}

#[test]
fn test_anomaly_threshold_passes_benign_request() {
    // Send legitimate request with no indicators
    // Verify pass-through
}
```

**Implementation Note:** Anomaly scoring aggregates scores from all detector categories. Tests need to verify:
- Score accumulation correctness
- Threshold boundary conditions
- Category-specific scoring weights

#### 3.1.2 False Positive Benchmarks (PRODUCTION-SAFETY-CRITICAL)

**Why Critical:** False positives block legitimate traffic, causing user-facing errors.

**Missing Tests:**
```rust
#[test]
fn test_benign_sql_keywords_not_blocked() {
    // "SELECT * FROM users WHERE id = 1"
    // "INSERT INTO table VALUES (1, 2)"
    // "UPDATE users SET name = 'John'"
    // Should NOT trigger SQLi detection
}

#[test]
fn test_benign_html_content_not_blocked() {
    // "<h1>Welcome</h1>" in body
    // "<script> is not an attack when in text content"
    // Should NOT trigger XSS detection
}

#[test]
fn test_benign_path_parameters_not_blocked() {
    // "/files/document.pdf"
    // "/users/johnnyBravo/profile"
    // Should NOT trigger path traversal
}
```

**Reference:** OWASP CRS (Core Rule Set) provides known false positive cases for benchmarking.

#### 3.1.3 Streaming Multi-Chunk Attack Detection

**Why Critical:** Attack vectors spanning chunk boundaries could bypass detection.

**Current:** Only basic single-chunk tests exist.

**Missing Tests:**
```rust
#[test]
fn test_streaming_sqli_spans_chunks() {
    let streaming = StreamingWafCore::new(Arc::new(detector));
    streaming.scan_chunk(b"1' OR '1'='1"); // benign start
    let result = streaming.scan_chunk(b" AND 1=1--"); // completes attack
    assert!(matches!(result, Block(..)));
}

#[test]
fn test_streaming_chunk_boundary_no_bypass() {
    // Split attack across chunk boundary
    // Verify detection cannot be bypassed
}

#[test]
fn test_streaming_buffer_overflow_blocks() {
    // EXCEEDS max_buffer_chunks configuration
    // Verify 413 response (buffer overflow)
}
```

**Implementation Location:** `src/waf/attack_detection/streaming.rs:70-102`

#### 3.1.4 Behavioral Intelligence Integration

**Why Critical:** Fingerprint-based detection is a key security layer added in Wave 3.1.

**Missing Tests:**
```rust
#[test]
fn test_behavioral_fingerprint_generation() {
    let manager = BehavioralIntelligenceManager::new(config);
    let features = BehavioralFeatures::from_request(&request);
    let fingerprint = manager.generate_fingerprint(&features);
    assert!(!fingerprint.is_empty());
}

#[test]
fn test_behavioral_intel_elevates_detection() {
    // Configure behavioral intelligence
    // Send suspicious request pattern
    // Verify elevated paranoia or block
}
```

**Reference:** `src/mesh/behavioral_intel.rs:709+` has unit tests for fingerprint generation, but integration with WAF detection is untested.

---

### 3.2 Worker HTTP Handling Tests

**Files:** `src/worker/unified_server.rs`, `src/http/server.rs`

**Current Coverage:** Zero end-to-end HTTP request tests in worker context.

**Critical Components Not Tested:**

| Component | Lines | Gap |
|-----------|-------|-----|
| Worker health endpoint | 605-620 in server.rs | No test for `/health` response |
| Connection limiting | Section 5 | No test for `try_acquire` behavior |
| Bandwidth limiting | Section 6 | No test for bandwidth enforcement |
| Site routing | `router.route_with_local_addr()` | No test for route resolution |
| Upstream proxy | Sections 13-17 | No test for actual proxy forwarding |
| WebSocket upgrade | Section 7 | No test for WS upgrade detection |
| Body collection | Section 10 | No test for large body handling |
| Honeypot detection | Section 11 | No test for honeypot paths |
| Challenge assets | Section 11 | No test for CSS challenge serving |

**Recommended Test Structure:**

Add to `tests/integration_test.rs` (new section around line 2840):

```rust
// Worker HTTP Handler Tests
#[cfg(test)]
mod worker_http_handler_tests {
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn create_test_waf_core() -> Arc<WafCore> {
        crate::worker::connection::create_waf(&MainConfig::default())
    }

    #[tokio::test]
    async fn test_worker_health_endpoint() {
        // Start worker with test config
        // Send HTTP request to /health
        // Verify 200 response with expected JSON
    }

    #[tokio::test]
    async fn test_connection_limit_returns_503() {
        // Configure connection_limit: 1
        // Send 2 concurrent requests
        // Verify second gets 503 Service Unavailable
    }

    #[tokio::test]
    async fn test_waf_block_on_malicious_request() {
        // Send request with SQL injection in path
        // Verify 403 Forbidden or challenge response
    }

    #[tokio::test]
    async fn test_bandwidth_limit_returns_413() {
        // Configure max_body_size: 1024
        // Send request with body > 1024 bytes
        // Verify 413 Payload Too Large
    }

    #[tokio::test]
    async fn test_proxy_to_mock_upstream() {
        // Start mock upstream on localhost
        // Send request through worker
        // Verify forwarded request headers, receive response
    }
}
```

**Pattern Reference:** Existing TCP socket mocking pattern at `tests/integration_test.rs:2587-2633` for HTTP client testing.

---

## 4. High Priority Test Gaps - P2

### 4.1 Overseer Lifecycle Tests

**File:** `src/overseer/process.rs`

**Current Coverage:**
- State machine transitions (UpgradeState, OverseerState): TESTED
- Config defaults/bounds: TESTED
- Restart delay calculations: TESTED

**Critical Gaps (No Actual Process Testing):**

| Component | Location | Gap |
|-----------|----------|-----|
| Process spawn | `spawn_master()` | No test that master actually starts |
| Health check loop | `run()` method | No test of main supervision loop |
| Auto-restart | `handle_master_restart()` | No test with actual crash/restart |
| Signal handling | Signal handler section | No SIGTERM/SIGINT handling test |
| Graceful shutdown | `stop_master()` | No test of 30s timeout behavior |
| IPC health check | `check_master_ipc_health()` | No test of socket failure handling |
| Dual-master upgrade | `dual_master_upgrade()` | No test of upgraded_master_child |
| Recovery logic | `attempt_recovery()` | No test from incomplete upgrade |

**Infrastructure Needed:**

```rust
// tests/test_utils.rs - New file

use tempfile::TempDir;
use tokio::process::{Child, Command};
use std::process::Stdio;

/// Mock master for health check testing
pub struct MockMaster {
    socket_path: PathBuf,
}

impl MockMaster {
    pub fn new(path: PathBuf) -> Self {
        Self { socket_path: path }
    }

    pub async fn spawn(&self) -> Result<Child, std::io::Error> {
        // Spawn a process that listens on socket_path
        // and responds to health checks appropriately
    }
}

/// Overseer test harness
pub struct OverseerHarness {
    pub overseer: OverseerProcess,
    pub temp_dir: TempDir,
    pub master_pid: Option<u32>,
}

impl OverseerHarness {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let temp_dir = TempDir::new()?;
        let config = OverseerConfig {
            auto_restart: true,
            health_check_interval_secs: 1,
            max_restart_attempts: 3,
            ..Default::default()
        };
        let overseer = OverseerProcess::new(config, temp_dir.path().into())?;
        Ok(Self { overseer, temp_dir, master_pid: None })
    }

    pub fn spawn_master(&mut self) -> Result<u32, Box<dyn Error>> {
        let pid = self.overseer.spawn_master()?;
        self.master_pid = Some(pid);
        Ok(pid)
    }
}
```

**Recommended Test Additions:**

```rust
// tests/overseer_lifecycle_test.rs - New file

#[tokio::test]
async fn test_health_check_loop_restarts_on_crash() {
    let mut harness = OverseerHarness::new().unwrap();
    harness.spawn_master().unwrap();

    // Kill master process externally
    kill(harness.master_pid.unwrap());

    // Verify auto-restart kicks in within health_check_interval_secs
    // Verify new master is spawned with different PID
}

#[tokio::test]
async fn test_auto_restart_respects_max_attempts() {
    let mut harness = OverseerHarness::new().unwrap();
    harness.overseer.config.max_restart_attempts = 3;

    // Have mock master die immediately on each restart
    // After 3 attempts, verify overseer stops
}

#[tokio::test]
async fn test_sigterm_triggers_graceful_shutdown() {
    let harness = OverseerHarness::new().unwrap();
    harness.spawn_master().unwrap();

    send_sigterm(harness.overseer.pid());

    // Verify master receives SIGTERM within 30s
    // Verify overseer exits cleanly
}
```

**Effort:** 3-4 days to add comprehensive overseer lifecycle tests

---

### 4.2 Master IPC Loop Tests

**Files:** `src/master/ipc.rs`, `src/process/manager.rs`

**Current Coverage:**
- Message parsing: Good
- Socket send/recv: Good (real sockets used)
- WorkerId operations: Good

**Critical Gaps:**

| Component | Location | Gap |
|-----------|----------|-----|
| Accept loop | Accept loop pattern in master | Not tested - loop behavior under rapid connections |
| Worker spawn | `ProcessManager::spawn_worker()` | No real child process spawn test |
| Zombie detection | `detect_dead_workers()` | No test with actual process termination |
| Health monitor | `start_health_monitor` | Not tested - heartbeat timeout detection |
| PID verification | `handle_worker_connection` | Not tested - PID spoofing detection |
| Rate limiting | Multi-worker scenarios | No concurrent connection test |

**Current Test Limitation:**
Tests use simulated workers (`tokio::spawn(async { ... })`), not real child processes. So `peer_pid()` returns `None` on most platforms, and PID verification is never exercised.

**Recommended Test Additions:**

```rust
// tests/ipc_loop_test.rs - New file

#[tokio::test]
async fn test_accept_loop_handles_multiple_workers() {
    // Start actual accept loop task
    let pm = Arc::new(ProcessManager::new(config, None));
    let listener = IpcListener::bind(&endpoint).await.unwrap();

    let accept_handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(ipc) => {
                    let pm = pm.clone();
                    tokio::spawn(handle_worker_connection(ipc, pm));
                }
                Err(_) => break,
            }
        }
    });

    // Spawn multiple workers
    // Verify all register correctly with ProcessManager
}

#[tokio::test]
async fn test_pid_spoofing_detection() {
    // Only works on Linux where peer_pid() returns actual PID
    // Send WorkerStarted with mismatched claimed_pid
    // Verify WorkerError with AuthenticationFailed
}

#[tokio::test]
async fn test_health_monitor_detects_dead_worker() {
    let (pm, _rx) = ProcessManager::new(config, None);
    pm.spawn_worker().unwrap();

    // Kill worker externally
    let pid = pm.get_worker_pid(&worker_id).unwrap();
    kill(pid);

    // Trigger health check
    pm.check_workers_health().await;

    // Verify worker marked as Failed
}
```

**Effort:** 2-3 days to add comprehensive IPC loop tests

---

### 4.3 Mesh Proxy Tests

**File:** `src/mesh/proxy.rs` (1757 lines)

**Current Coverage:** ZERO unit tests for MeshProxy

**What's Tested:** `UpstreamPool` in `src/upstream/pool.rs` (different from `MeshBackendPool`)

**Critical Components Without Tests:**

| Component | Method | Lines | Gap |
|-----------|--------|-------|-----|
| DHT route resolution | `resolve_upstream()` | 460 | No test for route query + provider filtering |
| Main routing | `route_request()` | 787 | No test for circuit breaker routing |
| Policy routing | `route_request_with_policy()` | 1126 | No test with WAF policy |
| Multi-provider fallback | `proxy_to_peer_with_fallback()` | 928 | No test with mocked providers |
| Provider selection | `weighted_shuffle_providers()` | 747 | No deterministic output test |
| Circuit breaker | State machine | 95-217 | No test for Closed→Open→HalfOpen |
| Transform cache | `TieredTransformCache` | 264-312 | No test for L1/L2 eviction |
| Provider stats | Tracking | 609-681 | No test for failure cooldown |

**Hot Path Concern (500K RPS):**
**Hot Path Concern (500K RPS):**
`provider_stats.write()` on every request for failure/success recording. No tests verify this doesn't become a bottleneck.

**Recommended Test Structure:**

```rust
// src/mesh/proxy.rs - Add #[cfg(test)] module

#[cfg(test)]
mod mesh_proxy_tests {
    use super::*;

    // Mock dependencies
    struct MockMeshTransport {
        route_query_result: RouteQueryResult,
    }

    struct MockTopology {
        peer_health: HashMap<String, bool>,
        upstream_blocked: HashSet<String>,
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let proxy = MeshProxy::new(/* mocked deps */);
        let provider = "provider-1";

        // Record failures up to threshold
        for _ in 0..5 {
            proxy.record_failure(provider);
        }

        // Verify circuit is Open
        assert!(proxy.is_circuit_open(provider));

        // Verify requests are rejected fast
        let result = proxy.route_request(&request, provider);
        assert!(matches!(result, Err(CircuitOpen)));
    }

    #[test]
    fn test_weighted_shuffle_providers_deterministic() {
        // Use seeded RNG for deterministic output
        let providers = vec!["p1", "p2", "p3"];
        let weights = vec![1.0, 2.0, 3.0];

        let result = weighted_shuffle_providers(&providers, &weights, Some(42));
        // Verify deterministic ordering with same seed
    }

    #[test]
    fn test_tiered_transform_cache_l1_l2_eviction() {
        let cache = TieredTransformCache::new(l1_size: 100, l2_size: 1000);

        // Fill L1
        for i in 0..150 {
            cache.insert(format!("key{}", i), value.clone());
        }

        // Verify L1 eviction moves to L2
        assert!(cache.get("key100").is_some()); // Evicted from L1 but in L2
    }
}
```

**Effort:** 2-3 days to add MeshProxy unit tests

---

## 5. Medium Priority Test Gaps - P3

### 5.1 DNS Recursive Resolver Tests

**File:** `src/dns/recursive.rs`

**Current Coverage:**
- Cache operations: Good
- Record type conversions: Good
- Wire format: Good

**Critical Gaps:**

| Component | Gap |
|-----------|-----|
| `resolve_upstream()` | No test for async resolution path |
| Real upstream queries | No actual recursive resolution |
| Upstream failure simulation | No timeout/SERVFAIL/REFUSED tests |
| Cache TTL expiration | No test for entry expiry |
| Stale serving (RFC 2308) | No test for serving stale on upstream fail |
| DNSSEC validation | No trust anchor, signature verification tests |
| All record type lookups | MX, TXT, NS, SOA, etc. NOT tested |
| Server lifecycle | start()/stop() NOT tested |
| UDP/TCP packet handling | No end-to-end packet flow tests |

**Pattern to Follow:** `NoopResolver` in `src/dns/resolver.rs:144-193`

**Recommended Implementation:**

```rust
// tests/dns/mock_resolver.rs - New file

pub struct MockDnsResolver {
    records: HashMap<String, MockRecordSet>,
    delay: Option<Duration>,
    failures: Vec<String>,
}

impl MockDnsResolver {
    pub fn with_answer(&mut self, name: &str, ip: IpAddr) {
        self.records.insert(name.to_string(), MockRecordSet::A(vec![ip]));
    }

    pub fn with_delay(&mut self, delay: Duration) {
        self.delay = Some(delay);
    }

    pub fn with_failure(&mut self, name: &str) {
        self.failures.push(name.to_string());
    }
}

#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn lookup_ip_with_ttl(&self, name: &str) -> ResolverResult<IpRecord> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        if self.failures.contains(&name) {
            return Err(ResolverError::QueryFailed("mock".to_string()));
        }
        // Return configured record or NXDOMAIN
    }
}
```

**Effort:** 2 days to add DNS recursive integration tests

---

### 5.2 Plugin Execution Tests

**Files:** `src/plugin/wasm_runtime.rs`, `src/plugin/instance_pool.rs`

**Current Coverage:** ~5% - only resource limits, manager creation, header serialization

**Critical Gaps:**

| Component | Gap |
|-----------|-----|
| `filter_request()` | No test with real/simulated WASM |
| `transform_response()` | No test |
| Instance pool under load | Only empty pool tested |
| Fuel exhaustion | No test |
| Memory growth limits | No test |
| Sandbox security | No test for DHT/threat access |

**What Requires Real WASM:**
- `Module::from_binary()` loading
- `instantiate()` with linker
- `filter_request()` end-to-end execution
- Fuel consumption tracking

**Available Test Fixtures:**
- `/static/pow.wasm` (263KB) - PoW challenge module (not filter plugin)
- `/static/mesh_pow.wasm` (263KB) - Mesh PoW (not filter plugin)

None export `filter_request`, `transform_response`, or `handle_request`.

**Recommended Approach - WAT (WebAssembly Text):**

Generate minimal embedded WASM modules for unit tests:

```rust
// Minimal filter_request module returning Pass (0)
const FILTER_PASS_WAT: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,  // WASM header
    // ... WAT compiled to bytes
];

#[test]
fn test_filter_request_passes_with_valid_plugin() {
    let runtime = WasmRuntime::load_from_bytes("test", FILTER_PASS_WAT,
                                               WasmResourceLimits::default()).unwrap();
    let result = runtime.filter_request(request, HashMap::new()).unwrap();
    assert!(matches!(result, WasmFilterResult::Pass));
}
```

**For Integration Tests:**
Create test fixture plugins in `tests/fixtures/plugins/`:
- `filter_pass.wasm` - Always returns Pass
- `filter_block.wasm` - Always returns Block
- `filter_challenge.wasm` - Always returns Challenge
- `memory_stress.wasm` - Tests memory limits
- `fuel_hog.wasm` - Tests fuel exhaustion

**Effort:** 2-3 days for comprehensive plugin tests

---

## 6. Implementation Roadmap

### Phase 1: Fix Critical Blockers (Week 1)

| Task | Effort | Owner | Status |
|------|--------|-------|--------|
| Fix DHT integration test compile error | 1-2 hrs | TBD | TODO |
| Fix rule_feed race conditions | 2-4 hrs | TBD | TODO |

**Verification:** `cargo test --test dht_integration_test` and parallel rule_feed tests pass.

---

### Phase 2: WAF Core Security Tests (Week 1-2)

| Task | Effort | Owner | Status |
|------|--------|-------|--------|
| Add anomaly scoring tests | 1 day | TBD | TODO |
| Add false positive benchmarks | 2 days | TBD | TODO |
| Add streaming multi-chunk tests | 0.5 day | TBD | TODO |
| Add behavioral intel integration tests | 0.5 day | TBD | TODO |

**Verification:** New tests in `src/waf/attack_detection/` with >90% coverage on anomaly scoring.

---

### Phase 3: Worker HTTP Handler Tests (Week 2-3)

| Task | Effort | Owner | Status |
|------|--------|-------|--------|
| Add worker health endpoint tests | 0.5 day | TBD | TODO |
| Add connection limiting tests | 0.5 day | TBD | TODO |
| Add bandwidth limiting tests | 0.5 day | TBD | TODO |
| Add upstream proxy integration tests | 1 day | TBD | TODO |
| Add WAF block/allow flow tests | 1 day | TBD | TODO |

**Verification:** New section in `tests/integration_test.rs` with >80% coverage of HTTP handler.

---

### Phase 4: Process Lifecycle Tests (Week 3-4)

| Task | Effort | Owner | Status |
|------|--------|-------|--------|
| Create test infrastructure (MockMaster, OverseerHarness) | 1 day | TBD | TODO |
| Add process spawn tests | 0.5 day | TBD | TODO |
| Add health check loop tests | 0.5 day | TBD | TODO |
| Add auto-restart tests | 0.5 day | TBD | TODO |
| Add signal handling tests | 0.5 day | TBD | TODO |
| Add IPC loop tests | 1 day | TBD | TODO |
| Add PID verification tests | 0.5 day | TBD | TODO |

**Verification:** New file `tests/overseer_lifecycle_test.rs` and `tests/ipc_loop_test.rs`.

---

### Phase 5: Mesh and DNS Tests (Week 4-5)

| Task | Effort | Owner | Status |
|------|--------|-------|--------|
| Add MeshProxy unit tests | 2 days | TBD | TODO |
| Add circuit breaker tests | 0.5 day | TBD | TODO |
| Add DNS mock resolver infrastructure | 0.5 day | TBD | TODO |
| Add DNS upstream query tests | 1 day | TBD | TODO |
| Add DNSSEC validation tests | 1 day | TBD | TODO |

**Verification:** New `#[cfg(test)]` modules in `src/mesh/proxy.rs` and `tests/dns_mock_test.rs`.

---

### Phase 6: Plugin Execution Tests (Week 5-6)

| Task | Effort | Owner | Status |
|------|--------|-------|--------|
| Generate WAT test modules | 1 day | TBD | TODO |
| Add filter_request execution tests | 1 day | TBD | TODO |
| Add instance pool concurrency tests | 0.5 day | TBD | TODO |
| Add resource limit tests | 0.5 day | TBD | TODO |
| Create test fixture plugins | 0.5 day | TBD | TODO |

**Verification:** New section in `tests/integration_test.rs` and `#[cfg(test)]` in `src/plugin/`.

---

## 7. Test Infrastructure Requirements

### 7.1 New Test Files

| File | Purpose |
|------|---------|
| `tests/test_utils.rs` | Shared test utilities (MockMaster, OverseerHarness, MockDnsResolver) |
| `tests/overseer_lifecycle_test.rs` | Overseer process lifecycle tests |
| `tests/ipc_loop_test.rs` | Master IPC accept loop tests |
| `tests/mesh_proxy_test.rs` | Mesh proxy routing/caching tests |
| `tests/dns_mock_test.rs` | DNS resolver with mock upstream |
| `tests/fixtures/plugins/` | Real WASM plugin test fixtures |
| `tests/waf_false_positive_test.rs` | False positive benchmarks |

### 7.2 New Dependencies

| Crate | Purpose |
|-------|---------|
| `wat` | WebAssembly Text parser for test WAT modules |
| `serial_test` | Serial test execution for tests needing isolation |

**Add to `[dev-dependencies]` in Cargo.toml:**
```toml
wat = "1.0"  # For WAT parsing in tests
```

---

## 8. Success Metrics

### 8.1 Coverage Targets

| Module | Current Coverage | Target |
|--------|-----------------|--------|
| WAF Core (anomaly scoring) | 0% | 90% |
| Worker HTTP handling | 0% | 80% |
| Overseer lifecycle | 30% (state machine only) | 70% |
| Master IPC loop | 40% (parsing only) | 80% |
| Mesh proxy | 0% | 60% |
| DNS recursive | 30% (cache only) | 60% |
| Plugin execution | 5% | 50% |

### 8.2 Test Execution Targets

| Metric | Current | Target |
|--------|---------|--------|
| Unit test execution time | ~3-5 min | < 5 min |
| Integration test execution time | ~5 sec | < 10 sec |
| Parallel test stability | Intermittent failures | 100% stable |
| Compile errors in tests | 1 | 0 |

### 8.3 Quality Gates

- All P0 issues resolved before Phase 2
- All P1 issues resolved before Phase 4
- No new test failures introduced
- Test execution passes in CI/CD

---

## 9. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rule feed thread-local refactor breaks production | HIGH | Use feature flags, extensive manual testing |
| WASM fixture generation adds complexity | MEDIUM | Start with WAT, minimize fixture count |
| Process lifecycle tests require real processes | MEDIUM | Use temporary directories, proper cleanup |
| DNS mock resolver diverges from real behavior | LOW | Follow NoopResolver pattern, verify with integration |
| Test maintenance burden increases | MEDIUM | Document patterns, review test coverage in code review |

---

## 10. Appendix

### A. Current Test Statistics

| Metric | Value |
|--------|-------|
| Total tests | 2,184 |
| Integration test files | 16 |
| Unit test modules | 80+ |
| Passing tests | 1,776 (1,534 unit + 242 integration) |
| Failing tests | 2 (race conditions) |
| Compile errors | 1 (dht_integration_test) |

### B. File Reference Map

| Component | Source File | Test File |
|-----------|------------|-----------|
| Overseer | `src/overseer/process.rs` | `tests/upgrade_flow_test.rs`, `tests/overseer_health_check_test.rs` |
| Master | `src/master/ipc.rs` | `tests/e2e_process_test.rs`, `tests/ipc_test.rs` |
| Worker | `src/worker/unified_server.rs` | `tests/drain_e2e_test.rs` |
| IPC | `src/process/ipc.rs` | `tests/ipc_test.rs` |
| WAF | `src/waf/attack_detection/mod.rs` | `tests/integration_test.rs:3676+` |
| Mesh | `src/mesh/proxy.rs` | None |
| DNS | `src/dns/recursive.rs` | `tests/dns_recursive_test.rs` |
| Plugin | `src/plugin/wasm_runtime.rs` | `src/plugin/wasm_runtime.rs:1376+` |

### C. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      OVERSEER (Supervisor)                  │
│  - Manages master process lifecycle                        │
│  - Handles upgrades, rollbacks, health monitoring           │
│  - Spawns the master process                               │
│  - Runs as the initial parent process                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ spawns / monitors
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        MASTER (Parent)                      │
│  - Manages worker processes                                │
│  - Handles IPC with workers                                │
│  - Owns the master socket for IPC                          │
│  - Runs as a child of overseer                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ spawns / manages
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────────┐  ┌─────────────────┐
│   UNIFIED       │  │   STATIC           │  │   REGULAR       │
│   SERVER        │  │   WORKER           │  │   WORKERS       │
│   WORKERS       │  │                    │  │                 │
│  (HTTP/WAF)     │  │ (Minification,     │  │ (Legacy HTTP    │
│                 │  │  Image Poisoning)  │  │  processing)    │
└─────────────────┘  └─────────────────────┘  └─────────────────┘
```

**IPC Message Flow (Tested):**
- Worker lifecycle: `WorkerStarted` → `WorkerReady` → `WorkerHeartbeat` → `WorkerShutdownComplete`
- Drain protocol: `DrainRequest` → `StopAccepting` → `DrainComplete`
- Health checks: `MasterHealthCheck` → `HealthCheckAck`

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-04-27 | AI Assistant | Initial draft from codebase review |

---

*End of Plan*
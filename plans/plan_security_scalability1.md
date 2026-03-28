# MaluWAF Security and Scalability Remediation Plan

**Generated**: March 27, 2026  
**Status**: Proposed  
**Priority**: High

---

## Executive Summary

This plan addresses critical security vulnerabilities and scalability bottlenecks identified in the MaluWAF codebase. The remediation is organized into three phases: **Immediate (P0)**, **Short-term (P1)**, and **Medium-term (P2)**.

| Phase | Timeline | Focus | Items |
|-------|----------|-------|-------|
| P0 | 1-2 weeks | Critical security fixes | 4 |
| P1 | 2-4 weeks | Core scalability improvements | 6 |
| P2 | 1-2 months | Technical debt & hardening | 5 |

---

## Phase 0: Immediate Security Fixes (P0)

### P0-1: Replace Unwrap/Expect in Critical Paths

**Risk**: High - DoS via panic-inducing inputs

**Affected Files** (Top 20 critical):
- `src/proxy.rs` - 15+ unwraps in request handling
- `src/tls/server.rs` - 10+ unwraps in TLS handshake
- `src/waf/mod.rs` - 8+ unwraps in WAF decisions
- `src/mesh/proxy.rs` - 20+ unwraps in mesh routing
- `src/main.rs` - 5+ unwraps in initialization

**Approach**:
1. Create wrapper enum `WafResult<T>` that propagates errors without panicking
2. Replace `.unwrap()` with `.map_err()?` or `.ok_or_else()`
3. Add `#[track_caller]` for debugging panic origins
4. Implement graceful degradation (block request on error)

**Example Transformation**:
```rust
// BEFORE
let path = uri.path();
let Some(host) = headers.get("host") else {
    return Err(Error::MissingHost);
};
let host = host.to_str().unwrap();

// AFTER
let path = uri.path();
let host = headers.get("host")
    .and_then(|h| h.to_str().ok())
    .ok_or_else(|| WafError::MissingHost)?;
```

**Testing**:
- Fuzz test critical paths with random/malformed inputs
- Add integration tests for edge cases

**Estimate**: 3-4 days

---

### P0-2: Fix Authentication Timing Attack

**Risk**: Medium - Username enumeration

**Location**: `src/auth/mod.rs:370-432` (`verify_login` function)

**Verified Current State** (via code inspection):
```rust
// When user NOT found (lines 381-387):
let user = match store.users.get_mut(&username_key) {
    Some(user) => user,
    None => {
        drop(store);
        verify_dummy_password(password).await;  // Called for non-existent users
        return Err(AuthError::InvalidCredentials);
    }
};

// When user exists but password WRONG (lines 410-432):
if !password_valid {
    user.failed_attempts += 1;
    // ... records failure ...
    // NO verify_dummy_password call here before returning error!
    return Err(AuthError::InvalidCredentials);
}
```

**Issue**: The code DOES call `verify_dummy_password` for non-existent users, BUT:
1. When user exists + wrong password: Returns immediately after failed verification (few ms)
2. When user doesn't exist: Calls verify_dummy_password (~200ms)
3. When user exists + correct password: Returns immediately after successful verification (few ms)

This creates a timing oracle: "valid username + wrong password" returns FASTER than "invalid username", allowing username enumeration.

**Fix**:
```rust
if !password_valid {
    user.failed_attempts += 1;
    
    // CRITICAL: Always run dummy password verification to prevent timing attack
    // regardless of whether password was wrong or user doesn't exist
    verify_dummy_password(password).await;
    
    // ... rest of failure handling ...
    return Err(AuthError::InvalidCredentials);
}
```

**Testing**:
- Benchmark response times for valid vs invalid usernames with wrong passwords
- Verify no timing difference between "valid user, wrong password" and "invalid user"

**Estimate**: 0.5 days

---

### P0-3: Verify Request Body Size Limits (ALREADY IMPLEMENTED)

**Status**: ✅ Already implemented

**Location**: `src/http/handler.rs:273-291`, `src/config/http.rs:19-20`

**Verification**: Code inspection confirms:
- `max_request_size` exists in `HttpConfig.security`
- Default is applied via `default_max_request_size()` (10MB)
- Early rejection happens BEFORE reading body (line 278-291)
- Returns 413 "Request Entity Too Large" when exceeded

```rust
// src/http/handler.rs:273-291
let max_body_size = self.main_config.security.max_request_size;
let content_length = parts.headers.get("content-length")
    .and_then(|v| v.to_str().ok())
    .and_then(|s| s.parse::<usize>().ok());

if let Some(size) = content_length {
    if size > max_body_size {
        tracing::warn!(
            "Request body too large: {} bytes (limit: {}) from {}",
            size, max_body_size, client_ip
        );
        counter!("maluwaf.requests.body_too_large").increment(1);
        return self.build_response(
            413,
            "Request Entity Too Large".to_string(),
            "text/plain",
        );
    }
}
```

**Recommendation**: Verify this config is properly exposed in admin UI and has reasonable defaults. Consider adding per-endpoint overrides.

**Estimate**: N/A - completed

---

### P0-4: Audit Mesh Network Message Handlers

**Risk**: High - Potential RCE/injection via mesh messages

**Location**: `src/mesh/transport_*.rs` (15+ handler files)

**Concerns**:
1. 90+ dead code warnings indicating unmaintained code
2. DHT, peer routing, org handlers may accept unsanitized input
3. No message size limits on incoming mesh packets

**Actions**:
1. **Audit**: Review each handler for input validation
2. **Limit**: Add max message size for incoming mesh frames
3. **Remove**: Delete unused dead code functions
4. **Test**: Fuzz mesh message handlers

**Prioritized Files**:
| File | Handler Count | Risk |
|------|---------------|------|
| `transport_peer.rs` | 20+ | High |
| `transport_dns.rs` | 15+ | High |
| `transport_org.rs` | 10+ | Medium |
| `transport_global.rs` | 10+ | Medium |

**Testing**:
- Generate malformed mesh messages
- Verify no panics or overflows

**Estimate**: 3-5 days

---

## Phase 1: Core Scalability Improvements (P1)

### P1-1: Replace HashMap with DashMap in Hot Paths

**Risk**: Medium - Lock contention under load

**Current**: 645+ instances of `Arc<RwLock<HashMap<...>>>`

**Issue**: RwLock on HashMap causes thread contention. Each read requires acquire-release semantics.

**Solution**: Use `dashmap` for lock-free concurrent maps where appropriate.

**Affected Hot Paths**:
1. Rate limiter IP tracking (`src/waf/ratelimit.rs`)
2. Connection tracking (`src/waf/flood/connection_limiter.rs`)
3. Block store (`src/block_store.rs`)

**Migration Example**:
```rust
// BEFORE
struct RateLimiterState {
    ip_requests: RwLock<HashMap<IpAddr, IpRateLimitState>>,
}

// AFTER  
struct RateLimiterState {
    ip_requests: DashMap<IpAddr, IpRateLimitState>,
}
```

**Risk**: DashMap has higher memory overhead; use selectively

**Estimate**: 3 days

---

### P1-2: Optimize Cache Lookup Performance

**Risk**: Medium - Latency spikes under cache load

**Current Issue** (per AGENTS.md):
- O(n) VecDeque operations for LRU eviction
- Write lock required on every cache hit for LRU update

**Location**: `src/proxy_cache/store.rs:241`

**Fix Options**:

**Option A: Use linked-hash-map with LRU**
```rust
use linked_hash_map::LinkedHashMap;

// Use LRU capacity for automatic eviction
struct Cache {
    entries: LruCache<String, CacheEntry>,
    max_size: usize,
}
```

**Option B: Two-tier cache (hot/cold)**
- Hot: Small in-memory LRU with quick access
- Cold: Larger backing store for persistence

**Recommendation**: Option A for simplicity; Option B for production scale

**Estimate**: 2 days

---

### P1-3: Implement Connection Payload Limits (PARTIALLY IMPLEMENTED)

**Status**: ⚠️ Partial implementation

**Location**: Multiple files - see below

**Verification** (via grep):
- `max_connections` - ✅ EXISTS in `src/config/traffic.rs`, `src/server/mod.rs`, `src/tcp/listener.rs`
- `max_connections_per_ip` - ✅ EXISTS in `src/config/traffic.rs`, `src/waf/flood/connection_limiter.rs`
- `max_request_size` - ✅ EXISTS (per P0-3 above)
- `max_response_size` - ❌ NOT FOUND - needs implementation
- `max_concurrent_requests_per_connection` - ❌ NOT FOUND - needs implementation

**Existing Configuration**:
```rust
// src/config/traffic.rs
pub struct TrafficShaperConfig {
    pub max_connections: u32,           // default: 1000
    pub max_connections_per_ip: u32,    // default: 10
    // ... other fields
}
```

**Recommended Additions**:
1. Add `max_response_size` for upstream response limiting
2. Add per-connection request streaming limits
3. Add bandwidth throttling per IP/connection

**Estimate**: 0.5 days (add missing limits)

---

### P1-4: Verify Session Cleanup (ALREADY IMPLEMENTED)

**Status**: ✅ Already implemented

**Location**: `src/auth/mod.rs:641-656`

**Verification** (via code inspection):
```rust
pub async fn cleanup_expired_sessions(&self) {
    let mut store = self.store.write().await;
    
    store.sessions.retain(|_, s| s.expires_at > Utc::now());
    
    for user in store.users.values_mut() {
        if let Some(locked_until) = user.locked_until {
            if locked_until < Utc::now() {
                user.locked_until = None;
                user.failed_attempts = 0;
            }
        }
    }
    
    self.save_store(&store).await;
}
```

**Recommendations**:
1. Verify cleanup is called periodically in background task loop
2. Consider adding metrics for cleanup effectiveness

**Estimate**: N/A - verify only

---

### P1-5: Add Per-Worker Metrics and Monitoring

**Current**: Global metrics; no per-worker breakdown

**Issue**: Cannot diagnose which worker is under load

**Fix**:
```rust
#[derive(Clone)]
pub struct WorkerMetrics {
    pub worker_id: WorkerId,
    pub requests_processed: Counter,
    pub requests_blocked: Counter,
    pub avg_latency_ms: Histogram,
    pub active_connections: Gauge,
    pub memory_usage_bytes: Gauge,
}
```

**Integration**:
- Add worker_id to all metrics labels
- Expose via Prometheus with worker dimension

**Estimate**: 1.5 days

---

### P1-6: Implement Graceful Degradation for Global Rate Limiter

**Risk**: Medium - Single point of failure

**Current**: GlobalRateLimiter is a single instance; if it fails, all requests fail

**Fix**:
1. Add circuit breaker pattern
2. Fallback to per-IP limiting if global fails
3. Add health check endpoint

```rust
pub struct GlobalRateLimiter {
    inner: GlobalRateLimiterInner,
    circuit_breaker: CircuitBreaker,
    fallback: FallbackLimiter,
}

impl GlobalRateLimiter {
    pub async fn check(&self, key: &str) -> RateLimitResult {
        // Try main limiter
        if !self.circuit_breaker.is_open() {
            match self.inner.check(key).await {
                Ok(result) => return result,
                Err(e) => {
                    // Record failure, maybe open circuit
                    self.circuit_breaker.record_failure();
                }
            }
        }
        
        // Fallback to per-IP limiter
        self.fallback.check(key).await
    }
}
```

**Estimate**: 2 days

---

## Phase 2: Technical Debt & Hardening (P2)

### P2-1: Remove Dead Code from Mesh Module

**Current**: 90+ dead code warnings in mesh

**Affected**: `transport_dht.rs`, `transport_org.rs`, `transport_dns.rs`, `transport_global.rs`, `transport_peer.rs`

**Action**: Delete unused functions and constants

**Automated Detection**:
```bash
cargo clippy -- -W unused > dead_code.txt
# Then manually review each item
```

**Estimate**: 2-3 days (manual review required)

---

### P2-2: Fix Failing DNS Integration Tests

**Current**: 4 tests failing
- `test_anycast_serial_wrap_around`
- `test_connection_limits_defaults`
- `test_dns_query_validator_limits`
- `test_dns_zone_get_previous_version`

**Fix**: Investigate and patch each test

**Estimate**: 1-2 days

---

### P2-3: Fix Unreachable Pattern Warning

**Location**: `src/process/ipc.rs:926`

**Current**:
```rust
Message::OverseerCommitUpgradeAck { error, .. } => Ok(()),
```

**Issue**: Pattern unreachable due to earlier catch-all

**Fix**: Remove redundant arm or restructure match

**Estimate**: 0.5 days

---

### P2-4: Implement Distributed Rate Limiting

**Current**: Global rate limiter is local only

**Future**: Support multiple WAF nodes sharing rate limit state

**Approach**:
1. Define distributed rate limit protocol
2. Add Redis or similar backend option
3. Implement consistent hashing for state distribution

**Timeline**: P2 (1 month)

---

### P2-5: Security Hardening Checklist

- [ ] Add CSP headers by default
- [ ] Implement request ID for tracing
- [ ] Add audit logging for admin actions
- [ ] Implement IP reputation scoring
- [ ] Add DDoS traffic pattern detection

**Timeline**: Ongoing

---

## Implementation Roadmap

```
Week 1-2 (P0):
├── P0-1: Replace unwraps (3-4 days)
├── P0-2: Auth timing fix (0.5 days) [verified issue: missing dummy call on wrong password]
└── P0-3: Body size limits (VERIFY - already exists!)

Week 3-4 (P1):
├── P0-4: Mesh audit (start) - 3-5 days
├── P1-1: DashMap migration (3 days)
├── P1-2: Cache optimization (2 days)
├── P1-3: Connection payload limits (0.5 days) [add missing: response size, streaming]
└── P1-4: Session cleanup (VERIFY - already exists!)

Week 5-8 (P2):
├── P1-5: Per-worker metrics (1.5 days)
├── P1-6: Graceful degradation (2 days)
├── P2-1: Remove dead code (2-3 days)
├── P2-2: Fix DNS tests (1-2 days)
└── P2-3: Fix unreachable pattern (0.5 days)
```

---

## Dependencies and Blockers

### Blockers
1. **P0-1**: Requires understanding of each error path's semantics
2. **P0-4**: Requires mesh protocol knowledge

### Dependencies
- P1-1 (DashMap) depends on testing of P0-1 (error handling)
- P1-6 (graceful degradation) benefits from P1-5 (metrics)

---

## Success Metrics

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Unwrap count in critical paths | 50+ | 0 | Not done |
| Auth timing delta (valid user + wrong pass vs invalid user) | ~200ms (oracle) | <5ms | P0-2 needed |
| Body size limits | ✅ Exists | N/A | Already done |
| Cache lookup worst-case | O(n) | O(1) | P1-2 needed |
| Connection limits (max_connections) | ✅ Exists | N/A | Already done |
| Connection limits (response size) | ❌ Missing | Add | P1-3 needed |
| Session cleanup | ✅ Exists | N/A | Already done |
| Dead code warnings | 90+ | <10 | P2-1 needed |
| DNS tests passing | 41/45 | 45/45 | P2-2 needed |

---

## Risk Assessment

| Item | Probability | Impact | Mitigation |
|------|-------------|--------|-------------|
| P0-1 introduces bugs | Medium | High | Extensive integration tests |
| P0-4 mesh audit incomplete | High | High | Prioritize high-risk handlers |
| P1-1 DashMap memory overhead | Low | Medium | Selective use only |
| P2-1 dead code removal breaks functionality | Medium | High | Full test suite before/after |

---

## Resources Required

- **Developer time**: ~18-22 days total (adjusted from corrections)
- **Testing infrastructure**: Fuzzer setup for mesh messages
- **Review**: Security audit for mesh handlers

### Revised Estimate by Phase

| Phase | Original | Revised | Change |
|-------|----------|---------|--------|
| P0 | ~5-7 days | ~4 days | -1.5 days (P0-3 already done) |
| P1 | ~9 days | ~7 days | -2 days (P1-3, P1-4 partially done) |
| P2 | ~6-8 days | ~6 days | No change |
| **Total** | **~20-25 days** | **~17-18 days** | **-3 days** |

## Verification Summary

This plan was verified via code inspection on March 27, 2026.

### Verification Methods Used:
1. **Direct code reading**: Read key source files to verify implementations
2. **Grep search**: Searched for patterns (e.g., `max_request_size`, `cleanup_expired_sessions`)
3. **Test execution**: Ran `cargo test --test integration_test` and DNS tests
4. **Clippy analysis**: Reviewed clippy warnings for dead code and issues

### Key Corrections Made:
1. **P0-2 (Auth timing)**: Original analysis was incorrect - the code DOES call `verify_dummy_password` for non-existent users, but the vulnerability is different: when user exists but password is wrong, NO dummy call is made (different from non-existent user case)

2. **P0-3 (Body size limits)**: ALREADY IMPLEMENTED - `max_request_size` exists in config and is enforced in HTTP handler before body read

3. **P1-3 (Connection limits)**: PARTIALLY IMPLEMENTED - `max_connections` and `max_connections_per_ip` exist, but `max_response_size` is missing

4. **P1-4 (Session cleanup)**: ALREADY IMPLEMENTED - `cleanup_expired_sessions()` function exists at line 641

### Items Confirmed as Needing Work:
- P0-1: Unwraps in critical paths (still an issue)
- P0-4: Mesh network audit (dead code, untested handlers)
- P1-1: DashMap migration (RwLock<HashMap> still used)
- P1-2: Cache O(n) operations (confirmed via code at store.rs:276-281)
- P2-1: Dead code warnings (confirmed 90+ warnings)
- P2-2: 4 failing DNS tests (confirmed)

---

## Appendix: Verified File Locations

| Issue | Verified Location | Status |
|-------|-------------------|--------|
| Unwraps | `src/proxy.rs`, `src/tls/server.rs`, `src/waf/mod.rs`, `src/mesh/proxy.rs` | Not done |
| Auth timing (P0-2) | `src/auth/mod.rs:370-432` (`verify_login`) | Fix needed |
| Body limits | `src/http/handler.rs:273-291` | ✅ Already exists |
| Session cleanup | `src/auth/mod.rs:641-656` | ✅ Already exists |
| Connection limits | `src/config/traffic.rs`, `src/waf/flood/connection_limiter.rs` | ✅ Exists |
| Rate limiter HashMap | `src/waf/ratelimit.rs:34` (256 shards with RwLock) | P1-1 candidate |
| Cache O(n) | `src/proxy_cache/store.rs:276-281` (`move_to_back`) | P1-2 needed |
| Mesh handlers | `src/mesh/transport_*.rs` (15+ files) | P0-4 audit |
| IPC unreachable | `src/process/ipc.rs:926-934` | P2-3 fix |
| DNS tests | `tests/dns_integration_test.rs` (4 failing) | P2-2 fix |

---

*End of Plan - Updated March 27, 2026*
# MaluWAF Codebase Improvement Plan

## Overview

This plan addresses the critical, major, and minor issues identified during the codebase review. The plan is organized into phases, prioritizing issues that can cause crashes or security vulnerabilities.

---

## Phase 1: Critical Fixes (Immediate)

### 1.1 Fix Panic in IPC Message Handling

**Issue**: Non-exhaustive `match` statements cause process crashes when unexpected message types are received.

**Locations** (9 in master IPC):
- `src/master/ipc.rs:50` - WorkerStarted
- `src/master/ipc.rs:64` - WorkerReady
- `src/master/ipc.rs:105` - WorkerHeartbeat
- `src/master/ipc.rs:125` - WorkerError
- `src/master/ipc.rs:139` - WorkerShutdownComplete
- `src/master/ipc.rs:155` - StaticWorkerStarted
- `src/master/ipc.rs:166` - StaticWorkerReady
- `src/master/ipc.rs:182` - BlocklistRequest
- `src/master/ipc.rs:197` - BlocklistResponse

**Additional panic locations** (23 total in codebase):
- `src/waf/endpoints.rs:587`
- `src/dns/trust_anchor.rs:1023,1105,1239,1376,1407`
- `src/tunnel/quic/messages.rs:348,362,437`
- `src/tunnel/wireguard/config.rs:524,534`
- `src/udp/filter.rs:379`
- `pqc/src/kem.rs:445,459`

**Solution**:
```rust
// BEFORE
match message {
    Message::WorkerStarted { id, pid, port, .. } => { ... }
    _ => panic!("Expected WorkerStarted message"),
}

// AFTER
match message {
    Message::WorkerStarted { id, pid, port, .. } => { ... }
    other => {
        tracing::warn!("Unexpected message type: {:?}", other);
        return Err(IpcError::UnexpectedMessage);
    }
}
```

**Estimated Effort**: 2-4 hours (IPC) + 2-3 hours (other locations)

---

### 1.2 Replace `.unwrap()` with Proper Error Handling

**Issue**: 573+ occurrences of `.unwrap()` and `.expect()` throughout the codebase can cause panics in production.

**Priority Locations** (hot paths):
1. `src/waf/mod.rs:744,866,926,1044` - `unwrap_or(1)` on threat_level (4 locations)
2. `src/waf/attack_detection/jwt.rs:26` - regex compilation
3. `src/proxy.rs:138,445` - UTF-8 conversion
4. `src/waf/attack_detection/open_redirect.rs:178` - pattern match

**Note**: `unwrap_or(1)` in waf/mod.rs are actually `unwrap_or(1)` not unwrap - lower risk but still should use proper error handling.

**Solution Pattern**:
```rust
// BEFORE
let value = self.map.get(&key).unwrap();

// AFTER
let value = self.map.get(&key).ok_or_else(|| Error::KeyNotFound(key))?;
```

**Estimated Effort**: 8-12 hours (systematic review of hot paths first)

---

### 1.3 Fix Bcrypt Security Issues

**Issue**: 
- Bcrypt cost factor is 4 (too low for production - should be 10-12)
- Plaintext fallback mechanism when hashing fails stores `__plaintext__:token`

**Location**: `src/admin/auth.rs:9` (BCRYPT_COST const), lines 15-28 (hash function), lines 30-36 (verify function)

**Current code**:
```rust
const BCRYPT_COST: u32 = 4;

pub fn hash_admin_token(token: &str) -> String {
    match bcrypt::hash(token, BCRYPT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(...);
            format!("__plaintext__:{}", token)
        }
    }
}
```

**Solution**:
```rust
const BCRYPT_COST: u32 = 12;

pub fn hash_admin_token(token: &str) -> Result<String, AuthError> {
    if token.len() < 32 {
        return Err(AuthError::InsufficientEntropy);
    }
    bcrypt::hash(token, BCRYPT_COST)
        .map_err(|e| AuthError::HashingFailed(e))
}
```

**Additional**: Add token entropy validation (minimum 32 characters)

**Estimated Effort**: 2 hours

---

## Phase 2: Major Fixes (High Priority)

### 2.1 Replace VecDeque with Proper LRU Cache

**Issue**: O(n) `VecDeque::position()` and `remove()` operations in proxy cache

**Location**: `src/proxy_cache/store.rs:118` (VecDeque field), lines 262-264 (position/remove calls)

**Current implementation**: Custom ring buffer with VecDeque, uses `iter().position()` which is O(n)

**Solution**: Use existing `lru_time_cache` crate (already in Cargo.toml at version 0.11):

```rust
// Already in Cargo.toml
lru_time_cache = "0.11"

// Replace VecDeque with LruCache
use lru_time_cache::LruCache;

struct Cache {
    inner: LruCache<CacheKey, CachedEntry>,
}
```

**Note**: There's already an `lru_time_cache` dependency in Cargo.toml (line 202). Verify it fits the use case before adding another crate.

**Estimated Effort**: 4 hours

---

### 2.2 Optimize Rate Limiting Cleanup

**Issue**: 6 sequential `retain()` calls on ring buffer (custom implementation, not std Vec) - the ring buffer is O(n) due to element shifting

**Location**: 
- `src/waf/ratelimit.rs:120-145` - Custom ring buffer `retain` implementation
- `src/waf/ratelimit.rs:411-416` - 6 sequential retain calls on different time buckets

**Current code** (lines 411-416):
```rust
ip_state.per_second.retain(|t| now.duration_since(*t) < Duration::from_secs(1));
ip_state.per_minute.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
ip_state.per_5min.retain(|t| now.duration_since(*t) < Duration::from_secs(300));
ip_state.per_10min.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
ip_state.per_hour.retain(|t| now.duration_since(*t) < Duration::from_secs(3600));
ip_state.per_day.retain(|t| now.duration_since(*t) < Duration::from_secs(86400));
```

**Solution**: Batch cleanup operations or use interval-based cleanup:

```rust
// Option 1: Interval-based (only cleanup every N calls)
fn maybe_cleanup(&mut self) {
    self.cleanup_counter += 1;
    if self.cleanup_counter > 1000 {
        self.cleanup_expired();
        self.cleanup_counter = 0;
    }
}

// Option 2: Single pass with all time windows
fn cleanup_all(&mut self, now: Instant) {
    ip_state.per_second.retain(|t| now.duration_since(*t) < Duration::from_secs(1));
    ip_state.per_minute.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
    // ... only when needed, not every call
}
```

**Estimated Effort**: 3 hours

---

### 2.3 Remove or Fix Dead Code

**Issue**: `src/http/handler.rs` and `src/http/range.rs` exist but cannot be compiled

**Solution**: Either:
1. Fix the compile error (`site_request_key` undefined) and integrate into module tree
2. Delete the files if not needed

**Estimated Effort**: 4-8 hours (if fixing) or 1 hour (if deleting)

---

### 2.4 Complete Image Poisoning Implementation

**Issue**: `src/worker/image_poisoning.rs:13` has unimplemented TODO - returns body unchanged

**Location**: `src/worker/image_poisoning.rs:1-16` (entire file is 16 lines)

**Current code**:
```rust
pub(super) fn poison_image_sync(...) -> Vec<u8> {
    // STUB - returns body unchanged
    // TODO: Implement actual image poisoning algorithm
    body
}
```

**Solution**: Either:
1. Implement actual image poisoning algorithm (requires research)
2. Mark as incomplete feature and disable in production
3. Remove the feature entirely if not needed

**Estimated Effort**: 4-8 hours (if implementing) or 1 hour (if marking incomplete)

---

### 2.5 Reduce Clone Usage in Hot Paths

**Issue**: 3,333 `.clone()` calls, particularly heavy in request handling

**Locations**:
- `src/http/server.rs`
- `src/tls/server.rs`
- `src/proxy.rs`

**Solution**: Use references, `Arc`, or interior mutability patterns where appropriate

**Estimated Effort**: 6-8 hours

---

## Phase 3: Minor Improvements (Medium Priority)

### 3.1 Optimize Path Sanitization

**Issue**: Allocates `Vec<u8>` on every request

**Location**: `src/proxy.rs:101-144`

**Solution**: Consider using `Cow<[u8]>` to avoid allocation when no sanitization needed

**Estimated Effort**: 2 hours

---

### 3.2 Optimize Response Header Filtering

**Issue**: Creates new `Vec` and clones headers on every response

**Location**: `src/proxy.rs:147-159`

**Solution**: Pre-allocate buffer or use iterators

**Estimated Effort**: 2 hours

---

### 3.3 Upgrade Dependencies

**Issue**: Older versions of some crates

**Current state** (from Cargo.toml):
- `rustls`: 0.23 (line 145)
- `bcrypt`: 0.15 (line 121)
- `lru_time_cache`: 0.11 (line 202)
- `quinn`: 0.11 (line 161)

**Changes to evaluate**:
- `rustls`: 0.23 → verify if 0.24 is compatible with existing TLS config
- Review `hickory-dns` updates (if using DNS feature)
- Review `lightningcss` stable release

**Note**: The quinn version has a security patch applied (CVE-2026-31812) - verify patch compatibility when upgrading.

**Estimated Effort**: 2-4 hours

---

## Phase 4: Testing Improvements (Ongoing)

### 4.1 Add Authentication Integration Tests

**Gap**: No tests for auth flow

**Solution**: Add tests for:
- Login/logout flow
- Rate limiter behavior
- Token entropy validation
- Plaintext fallback scenario

**Estimated Effort**: 4 hours

---

### 4.2 Add TLS Handshake Tests

**Gap**: No tests for certificate validation

**Solution**: Test:
- Valid certificate acceptance
- Invalid certificate rejection
- Client certificate authentication

**Estimated Effort**: 4 hours

---

### 4.3 Add Fuzzing Tests

**Gap**: No fuzzing for HTTP parsing

**Solution**: Use `cargo-fuzz` or ` AFL.rs` for:
- HTTP request parsing
- URL parsing
- Header parsing

**Estimated Effort**: 8 hours

---

### 4.4 Improve Test Quality

**Issue**: Many tests only verify serialization, not behavior

**Solution**: Rewrite tests to verify actual behavior:
- IPC message handling
- WAF detection logic
- Rate limiting decisions

**Estimated Effort**: 8-12 hours

---

## Summary

| Phase | Effort (Hours) | Priority |
|-------|----------------|----------|
| Phase 1: Critical | 14-21 | Immediate |
| Phase 2: Major | 20-30 | High |
| Phase 3: Minor | 6-10 | Medium |
| Phase 4: Testing | 24-32 | Ongoing |
| **Total** | **64-93** | |

---

## Files to Modify

### Phase 1 (Critical)
1. `src/master/ipc.rs` - Fix 9 panic locations
2. `src/waf/endpoints.rs:587` - Fix panic
3. `src/dns/trust_anchor.rs:1023,1105,1239,1376,1407` - Fix 5 panics
4. `src/tunnel/quic/messages.rs:348,362,437` - Fix 3 panics
5. `src/tunnel/wireguard/config.rs:524,534` - Fix 2 panics
6. `src/udp/filter.rs:379` - Fix panic
7. `pqc/src/kem.rs:445,459` - Fix 2 panics
8. `src/waf/mod.rs:744,866,926,1044` - Error handling
9. `src/waf/attack_detection/jwt.rs` - Error handling
10. `src/proxy.rs:138,445` - Error handling
11. `src/admin/auth.rs` - Fix bcrypt cost + plaintext fallback

### Phase 2 (Major)
1. `src/proxy_cache/store.rs` - Replace VecDeque
2. `src/waf/ratelimit.rs` - Optimize cleanup
3. `src/http/handler.rs` - Fix or delete
4. `src/http/range.rs` - Fix or delete
5. `src/worker/image_poisoning.rs` - Complete or mark incomplete

### Phase 3 (Minor)
1. `src/proxy.rs` - Optimize allocations
2. `Cargo.toml` - Upgrade dependencies

### Phase 4 (Testing)
1. `tests/` - Add integration tests
2. Add fuzzing infrastructure

---

## Notes

- Phase 1 fixes should be merged immediately as they can cause production crashes
- Consider creating tracking issues for each phase
- Test thoroughly after each change
- Run `cargo clippy` and `cargo fmt` after modifications

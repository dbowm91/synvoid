# MaluWAF Codebase Improvement Plan

This document outlines a comprehensive plan to address issues found during the codebase review.

## Summary of Findings

| Category | Critical Issues | Medium Issues | Low Priority |
|----------|-----------------|--------------|--------------|
| Tests | 14 compilation errors in mesh/config.rs | DNS feature tests need verification | Test coverage gaps |
| Security | BCrypt cost=4 too weak | CORS wildcard not rejected for sites | IPC key fallback |
| Performance | Multiple lowercase calls in hot path | O(n) cache lookup | Per-request allocations |
| Error Handling | get_block_store() can panic | Silent send failures | eprintln vs tracing |

**Integration tests: 40/40 PASSING** (but lib tests have compilation errors)

**Total tasks**: ~45 actionable items across 6 phases

## Table of Contents

1. [Critical Issues](#1-critical-issues)
2. [Security Hardening](#2-security-hardening)
3. [Performance Optimization](#3-performance-optimization)
4. [Error Handling](#4-error-handling)
5. [Test Coverage](#5-test-coverage)
6. [Code Quality](#6-code-quality)
7. [Implementation Order](#7-implementation-order)

---

## 1. Critical Issues

These issues cause test failures, compilation errors, or runtime panics.

### 1.1 Fix Broken Test Compilation

**Issue**: `src/mesh/config.rs` lines 1336-1443 contain a test module that calls private methods, causing 14 compilation errors.

**Impact**: Blocks entire test suite from running.

**Tasks**:
- [ ] Review `src/mesh/config.rs:1336-1443` test module
- [ ] Either make methods `pub(crate)` or refactor tests to use public API
- [ ] Verify test suite compiles

### 1.2 Verify DNS Feature Tests (when --features dns enabled)

**Issue**: The testing agent reported 4 failing tests, but these appear to be DNS feature-gated tests that run with `--features dns`.

**Tasks**:
- [ ] Run `cargo test --features dns` to verify test status
- [ ] Investigate any failures in DNS-specific integration tests
- [ ] Fix any issues found

### 1.3 Fix Panic Risk in BlockStore Access

**Issue**: `src/server/mod.rs:360` uses `.expect()` on BlockStore, which will panic if BlockStore isn't initialized.

**Tasks**:
- [ ] Change `get_block_store()` to return `Result<Arc<BlockStore>, Error>`
- [ ] Update all call sites to handle the Result
- [ ] Add proper error context to errors

---

## 2. Security Hardening

### 2.1 Increase BCrypt Cost

**Issue**: `src/admin/auth.rs:9` uses `BCRYPT_COST = 4`, which is too weak (only 16 iterations vs recommended 12+).

**Current**: `const BCRYPT_COST: u32 = 4;`

**Recommended**: Minimum 10, ideally 12.

**Tasks**:
- [ ] Update `BCRYPT_COST` to 10 (allows ~1s hashing on modern hardware)
- [ ] Add migration path for existing tokens if changing after deployment
- [ ] Document the cost in code

### 2.2 Extend CORS Wildcard Rejection to Site Config

**Issue**: Admin API rejects `allow_origin: "*"` in release builds, but site-level CORS in `src/http/headers.rs` doesn't enforce this.

**Tasks**:
- [ ] Add wildcard rejection check to site-level CORS configuration
- [ ] Add validation on config load
- [ ] Add tests for CORS validation

### 2.3 Audit IPC Key Fallback

**Issue**: `src/process/manager.rs:455-457` falls back to env var if temp file creation fails, potentially exposing IPC key.

**Tasks**:
- [ ] Log warning when falling back to env var
- [ ] Consider failing hard instead of falling back
- [ ] Document security implications

### 2.4 Review TLS skip_verify Usage

**Issue**: `src/http_client/mod.rs:201-211` allows disabling TLS verification.

**Tasks**:
- [ ] Audit all uses of `skip_verify`
- [ ] Add warning logs at initialization
- [ ] Consider deprecating the option

---

## 3. Performance Optimization

### 3.1 Cache Lowercase Results in Attack Detection

**Issue**: Multiple `.to_lowercase()` calls in hot path - SSRF detector calls it 4+ times on same input.

**Files**: 
- `src/waf/attack_detection/ssrf.rs:60,156,197,212`
- `src/waf/attack_detection/detector_common.rs`

**Tasks**:
- [ ] Refactor SSRF detector to compute lowercase once
- [ ] Cache normalized input in detector common
- [ ] Apply same pattern to other detectors
- [ ] Benchmark before/after

### 3.2 Optimize Rate Limiter Cleanup

**Issue**: `src/waf/ratelimit.rs` has 256 shards, each requiring a lock acquisition. The custom `retain` implementation is actually optimized (ring buffer pattern), but 6 sequential retain calls per cleanup cycle may add up.

**Current**: Custom ring buffer `retain` is efficient O(n) per shard.

**Tasks**:
- [ ] Benchmark current cleanup duration with realistic data
- [ ] Consider if 6 sequential retain passes can be combined
- [ ] Evaluate if parallel shard cleanup is worth the complexity

### 3.3 Optimize Cache Position Lookup

**Issue**: `src/proxy_cache/store.rs` uses O(n) `VecDeque::position()` on every cache operation.

**Tasks**:
- [ ] Add `HashMap<key, position>` to track entry positions
- [ ] Update position tracking on get/insert/invalidate
- [ ] Benchmark cache operations

### 3.4 Reduce Per-Request Allocations

**Issue**: Multiple allocations per request in hot paths.

**Tasks**:
- [ ] Cache base headers filter set (`src/proxy.rs:77-99`)
- [ ] Reuse HashMap for HTTP/TLS requests (`src/tls/server.rs:213,256`)
- [ ] Cache normalized inputs across detector checks
- [ ] Review and optimize `build_headers_to_filter`

### 3.5 Optimize LRU Eviction

**Issue**: `src/waf/ratelimit.rs` collects ALL entries into Vec before sorting for eviction.

**Tasks**:
- [ ] Use partial sort (top-k) instead of full sort
- [ ] Consider per-shard eviction instead of global
- [ ] Benchmark with realistic data

---

## 4. Error Handling

### 4.1 Log Silent Send Failures

**Issue**: `src/supervisor/supervisor.rs:145` and `src/process/manager.rs:950,961` silently drop WorkerFailed events.

**Tasks**:
- [ ] Add logging when send fails
- [ ] Consider retry queue for critical events
- [ ] Add metrics for dropped events

### 4.2 Replace eprintln with Tracing

**Issue**: `src/main.rs:632` uses `eprintln!` instead of `tracing::warn!`.

**Tasks**:
- [ ] Replace with `tracing::warn!`
- [ ] Audit for other direct stderr/stdout usage

### 4.3 Document Unwrap Patterns

**Issue**: Several places use `.unwrap()` after checking conditions.

**Tasks**:
- [ ] Add comments explaining why unwrap is safe
- [ ] Consider using `expect()` with explanation
- [ ] Clean up redundant None checks (e.g., `src/mesh/proxy.rs:963`)

---

## 5. Test Coverage

### 5.1 Add Missing Core Tests

**Priority tests for untested critical paths**:

**Worker/Master/Server Lifecycle**:
- [ ] `src/worker/mod.rs` - spawn, request handling, graceful shutdown
- [ ] `src/master/mod.rs` - master process lifecycle
- [ ] `src/server/mod.rs` - server initialization

**WAF Hot Path**:
- [ ] `src/waf/mod.rs` - detection engine with realistic payloads
- [ ] `src/waf/ratelimit.rs` - rate limiting with concurrent requests
- [ ] `src/proxy_cache/` - caching logic

**HTTP/TLS**:
- [ ] `src/tls/server.rs` - TLS termination
- [ ] `src/tls/cert_resolver.rs` - certificate handling
- [ ] `src/http/server.rs` - HTTP parsing

### 5.2 Add Integration Tests

**Tasks**:
- [ ] Admin API endpoints with auth
- [ ] End-to-end request flow (proxy → WAF → upstream)
- [ ] Graceful shutdown sequences
- [ ] Config reload without dropping connections

### 5.3 Improve Existing Tests

**Tasks**:
- [ ] Increase assertions in sparse tests
- [ ] Add negative test cases
- [ ] Add edge case coverage (empty strings, max lengths, etc.)

---

## 6. Code Quality

### 6.1 Add Documentation

**Issue**: 585 public functions lack doc comments.

**Tasks**:
- [ ] Prioritize high-traffic modules:
  - `src/http_client/mod.rs`
  - `src/admin/handlers/`
  - `src/mesh/passover_key_exchange.rs`
- [ ] Document public API with:
  - Function purpose
  - Parameters
  - Return values
  - Error conditions
  - Examples

### 6.2 Fix Clippy Warnings

**Issue**: 19 clippy warnings.

**Tasks**:
- [ ] Fix formatting issues in `src/mesh/transport.rs`
- [ ] Remove dead code (`src/process/ipc.rs:926`)
- [ ] Fix redundant field names
- [ ] Address unused methods

### 6.3 Address Code Duplication

**Tasks**:
- [ ] Extract DNS wire format construction in `dnssec.rs`
- [ ] Create shared helper for lowercase comparisons
- [ ] Consider deriving Clone implementations vs manual

### 6.4 Split Large Modules

**Issue**: 6 modules exceed 1500 lines.

**Tasks**:
- [ ] Split `src/dns/dnssec.rs` (2,152 lines) - already borderline
- [ ] Review if `src/mesh/topology.rs` needs splitting
- [ ] Document rationale for large modules that are kept

---

## 7. Implementation Order

### Phase 1: Unblock Development (Week 1)

1. Fix broken test compilation (`src/mesh/config.rs`)
2. Verify DNS feature tests (`cargo test --features dns`)
3. Fix `get_block_store()` panic risk

**Verification**: `cargo test --lib` compiles without errors

### Phase 2: Security Fixes (Week 1-2)

1. Increase BCrypt cost
2. Extend CORS wildcard rejection
3. Audit IPC key fallback
4. Review TLS skip_verify

**Verification**: Security audit complete

### Phase 3: Performance (Week 2-3)

1. Cache lowercase results in attack detection
2. Optimize rate limiter cleanup (benchmark first)
3. Optimize cache position lookup (O(n) → O(1))
4. Reduce per-request allocations

**Verification**: Benchmark suite shows improvement

### Phase 4: Error Handling (Week 3)

1. Log silent send failures
2. Replace eprintln with tracing
3. Document unwrap patterns

**Verification**: `cargo clippy -- -D warnings` passes

### Phase 5: Test Coverage (Week 3-4)

1. Add core lifecycle tests
2. Add WAF hot path tests
3. Add integration tests

**Verification**: Coverage report shows improvement

### Phase 6: Documentation (Week 4+)

1. Add doc comments to public API
2. Fix remaining clippy warnings
3. Address code duplication

**Verification**: `cargo doc` generates complete documentation

---

## Appendix: File Reference

| File | Lines | Primary Responsibility |
|------|-------|------------------------|
| `src/server/mod.rs` | 897 | Server initialization |
| `src/worker/mod.rs` | 786 | Worker process |
| `src/master/mod.rs` | 21+ | Master process |
| `src/process/manager.rs` | 1,697 | Process lifecycle |
| `src/waf/mod.rs` | 1,203 | WAF core |
| `src/waf/ratelimit.rs` | ~400 | Rate limiting |
| `src/proxy_cache/store.rs` | ~300 | Response cache |
| `src/proxy.rs` | 1,401 | Proxy functionality |
| `src/admin/auth.rs` | ~200 | Admin authentication |
| `src/http/headers.rs` | ~200 | HTTP header handling |
| `src/http_client/mod.rs` | 697 | HTTP client |
| `src/mesh/config.rs` | 1,450 | Mesh configuration |
| `src/dns/dnssec.rs` | 2,152 | DNSSEC validation |
| `src/dns/server/mod.rs` | 763 | DNS server |

---

## Appendix: Testing Commands

```bash
# Run integration tests (fast)
cargo test --test integration_test

# Run all tests
cargo test

# Run with DNS feature
cargo test --features dns

# Run clippy
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check documentation
cargo doc
```

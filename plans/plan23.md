# MaluWAF Performance Improvement Plan

**Plan ID**: 23
**Date**: 2026-04-23
**Status**: Draft
**Priority**: High (Performance)
**Target**: 500K+ requests/second throughput

---

## Executive Summary

This plan addresses 18 performance issues identified in deep-dive analysis targeting 500K+ req/sec throughput. Issues are categorized by severity and implementation complexity, with concrete code changes and estimated effort.

### Summary Table

| Priority | Count | Items |
|----------|-------|-------|
| CRITICAL | 4 | JSON in DHT hot paths, WAF header clone, WAF dead lowercase, Cache O(n) invalidation |
| HIGH | 6 | HTTP header lookups, Cookie format!, Proxy headers, DNS lowercases, DNS Zone clone, Rate limit rotation |
| MEDIUM | 4 | Cache lock contention, Mesh lock consolidation, Ratelimit cleanup, Seen messages |
| LOW | 4 | Trust anchor save, DNS dead scan, DNS Vec alloc, Research patterns |

---

## Performance Issues Inventory

### CRITICAL Priority

#### Issue C1: JSON Serialization in DHT Hot Paths

**Severity**: CRITICAL
**Location**: `src/mesh/dht/record_store_crud.rs:33-40`, `src/mesh/dht/record_store_message.rs:557-562,700-705`
**Type**: Allocation overhead
**Impact**: ~1M allocations/sec at 500K req/s

**Problem**: `serde_json` used for DHT record serialization in hot paths where `postcard` should be used.

**Fix Plan**:
1. Add `Serialize, Deserialize` derives to `DhtRecord` in `src/mesh/dht/store.rs:34`
2. Add `Serialize, Deserialize` derives to `RecordMetadata` in `src/mesh/dht/store.rs:8`
3. Replace inline JSON with `crate::serialization::serialize()` at identified locations
4. Add version byte prefix for signature compatibility (nodes must understand both formats)

**Files to modify**:
- `src/mesh/dht/store.rs` - Add 2 derives (~8 lines)
- `src/mesh/dht/record_store_crud.rs` - Replace JSON (~15 lines)
- `src/mesh/dht/record_store_message.rs` - Replace JSON at 2 locations (~24 lines)
- `src/mesh/yara_rules.rs` - Replace JSON (~30 lines)

**Est. lines**: 170-240
**Risk**: Medium (signature compatibility)

---

#### Issue C2: WAF Attack Detection - Per-Header `name.clone()`

**Severity**: CRITICAL
**Location**: `src/waf/attack_detection/mod.rs:302` (and 10 similar locations)
**Type**: Unnecessary Arc clone
**Impact**: ~110M Arc clones/sec at 500K req/s with 20 headers

**Problem**: Every header triggers `InputLocation::Header(name.clone())` where `name` is already `Arc<str>`. Clone is passed by value to `detect()` functions.

**Fix Plan**:
1. Change `PatternDetector::detect()` signatures to accept `&InputLocation` instead of `InputLocation`
2. Update all detector implementations (sqli, xss, ssrf, ssti, etc.)
3. Update call sites in `mod.rs` to pass references

**Files to modify**:
- `src/waf/attack_detection/detector_common.rs` - Trait signatures (~15 lines)
- `src/waf/attack_detection/sqli.rs` - Implementations (~30 lines)
- `src/waf/attack_detection/mod.rs` - Call sites (~11 lines)
- Tests in `tests/integration_test.rs` (~10 lines)

**Est. lines**: ~70
**Risk**: Low (simple borrowing change)

---

#### Issue C3: WAF Normalizer - Dead `lowercased` Field

**Severity**: CRITICAL
**Location**: `src/waf/probe_tracker/normalizer.rs:66`
**Type**: Dead allocation
**Impact**: ~50MB/sec at 500K rps with average 100-byte input

**Problem**: `Normalizer::normalize()` allocates `Cow::Owned(buffer.to_lowercase())` but this field is never used by any active code path. Verified via grep - `check_inputs()` is dead code.

**Fix Plan**:
1. Delete `lowercased` field from `NormalizedInput` struct (line 397)
2. Delete `as_lowercased()` method (lines 418-420)
3. Delete `to_lowercase()` allocation in `normalize()` (line 66)
4. Optionally delete `check_inputs()` and `detect_with_pre_normalized()` if confirmed unused

**Files to modify**:
- `src/waf/probe_tracker/normalizer.rs` - Remove field and method (~15 lines)
- `src/waf/attack_detection/detector_common.rs` - Remove dead functions (~50 lines)

**Est. lines**: ~65 (net negative - dead code removal)
**Risk**: Very Low (verified field is unused)

---

#### Issue C4: Proxy Cache O(n) Pattern Invalidation

**Severity**: CRITICAL
**Location**: `src/proxy_cache/store.rs:557-562`
**Type**: Algorithmic - O(n) instead of O(1)
**Impact**: Event loop blocking during cache invalidation at scale

**Problem**: `invalidate_by_pattern()` iterates entire cache entries with `.iter().filter()` on every call. Same for `cleanup_expired()` at lines 697-732.

**Fix Plan**:
1. Add `uri_prefix_index: RwLock<AHashMap<String, Vec<CacheKey>>>` to `ProxyCache` struct
2. Update `insert()` to index by URI prefix
3. Update `invalidate()` and `clear()` to maintain index
4. Replace O(n) iteration with O(1) index lookup in `invalidate_by_pattern()`

**Files to modify**:
- `src/proxy_cache/store.rs` - Add index field (~1 line)
- `src/proxy_cache/store.rs` - Initialize index (~2 lines)
- `src/proxy_cache/store.rs` - Maintain index on insert (~10 lines)
- `src/proxy_cache/store.rs` - Maintain index on invalidate (~5 lines)
- `src/proxy_cache/store.rs` - Use index for pattern lookup (~10 lines)

**Est. lines**: ~30
**Risk**: Low (additive index structure)

---

### HIGH Priority

#### Issue H1: HTTP/TLS Repeated Header Lookups

**Severity**: HIGH
**Location**: `src/http/server.rs:831-844`, `src/tls/server.rs:597-613`
**Type**: Redundant hash lookups
**Impact**: 3 lookups per request instead of 1

**Problem**: Headers `host`, `user-agent`, `cookie` are each looked up with separate `.get()` calls.

**Fix Plan**:
1. Use single-pass header iteration: `for (name, value) in parts.headers.iter()`
2. Match against `http::header::HOST`, `USER_AGENT`, `COOKIE` constants
3. Extract needed headers in one iteration

**Files to modify**:
- `src/http/server.rs` - Single-pass header extraction (~25 lines)
- `src/tls/server.rs` - Single-pass header extraction (~25 lines)

**Est. lines**: ~50
**Risk**: Low (pattern exists elsewhere in codebase)

---

#### Issue H2: Cookie Parsing `format!()` Allocation

**Severity**: HIGH
**Location**: `src/http/server.rs:1219`, `src/waf/mod.rs:818,825`
**Type**: Per-request allocation
**Impact**: 1.5M allocations/sec at 500K rps

**Problem**: `format!("{}=", cookie_name)` called on every cookie check. Cookie names are static config.

**Fix Plan**:
1. Add helper function:
```rust
fn cookie_name_matches(trimmed: &str, cookie_name: &str) -> bool {
    let name_len = cookie_name.len();
    trimmed.starts_with(cookie_name)
        && trimmed.len() > name_len
        && trimmed.as_bytes()[name_len] == b'='
}
```
2. Update 3 call sites to use helper

**Files to modify**:
- `src/challenge/mod.rs` - Add helper (~8 lines)
- `src/http/server.rs` - Update call site (~1 line)
- `src/waf/mod.rs` - Update 2 call sites (~2 lines)

**Est. lines**: ~12
**Risk**: Low

---

#### Issue H3: Proxy Headers Excessive Allocations

**Severity**: HIGH
**Location**: `src/proxy/headers.rs:360-398`
**Type**: Allocation overhead
**Impact**: 8+ allocations per forwarded request

**Problem**: `build_forward_headers()` allocates `Vec<(String, String)>` with `.to_string()` calls for each header.

**Fix Plan**:
1. Use `http::HeaderMap` instead of `Vec<(String, String)>`
2. Use `HeaderValue` types that avoid String allocation
3. Leverage existing `HeaderMap` insert pattern from `filter_response_headers_buf()`

**Files to modify**:
- `src/proxy/headers.rs` - Refactor `build_forward_headers()` (~50 lines)

**Est. lines**: ~50
**Risk**: Medium (type changes)

---

#### Issue H4: DNS Redundant `to_lowercase()` Calls

**Severity**: HIGH
**Location**: `src/dns/server/query.rs:670,716,719`, `src/dns/server/dnssec_impl.rs:324-325,390`
**Type**: Redundant allocation
**Impact**: 3-5 lowercases per query instead of 1

**Problem**: `qname.to_lowercase()` called multiple times; `find_zone()` re-lowercases already-lowercase input.

**Fix Plan**:
1. Pre-compute `qname_lower` once before loops in query.rs
2. Add fast-path in `zone_trie.rs` to skip re-lowercasing if already lowercase
3. Fix NSEC3 dead code scan in dnssec_impl.rs:384

**Files to modify**:
- `src/dns/server/query.rs` - Hoist lowercase before loop (~10 lines)
- `src/dns/server/zone_trie.rs` - Add fast-path (~8 lines)
- `src/dns/server/dnssec_impl.rs` - Pre-compute lowercase, remove dead code (~8 lines)

**Est. lines**: ~26
**Risk**: Low

---

#### Issue H5: DNS Zone Clone on Get

**Severity**: HIGH
**Location**: `src/dns/server/sharded_store.rs:67`
**Type**: Unnecessary copy
**Impact**: Full Zone clone on every DNS query

**Problem**: `get()` returns `Option<Zone>` which clones the entire Zone including all records.

**Fix Plan**:
1. Change `get()` to return `Option<Arc<Zone>>`
2. Store zones as `Arc<RwLock<Zone>>` internally
3. Update all call sites to handle `Arc<Zone>`

**Files to modify**:
- `src/dns/server/sharded_store.rs` - Change storage and get (~20 lines)
- Call sites in `src/dns/server/query.rs`, `src/dns/server/mod.rs` (~10 lines)

**Est. lines**: ~30
**Risk**: Medium (Arc propagation)

---

#### Issue H6: Rate Limiting O(bucket_count) Rotation

**Severity**: HIGH
**Location**: `src/waf/ratelimit/core.rs:176-180`
**Type**: Algorithmic
**Impact**: O(60) sum on every rotation blocks further increments

**Problem**: On bucket rotation, all 60 buckets are summed sequentially blocking new increments.

**Fix Plan**:
1. Maintain `running_sum` atomic counter
2. On bucket increment: `running_sum.fetch_add(count, Relaxed)`
3. On bucket expiration: `running_sum.fetch_sub(expired_count, Relaxed)`
4. Rotation becomes O(1) - just update slots

**Files to modify**:
- `src/waf/ratelimit/core.rs` - Add running_sum, update rotation logic (~30 lines)

**Est. lines**: ~30
**Risk**: Low

---

### MEDIUM Priority

#### Issue M1: Cache Write Lock Contention

**Severity**: MEDIUM
**Location**: `src/proxy_cache/store.rs:524`
**Type**: Lock contention
**Impact**: 500K+ write lock acquisitions/sec

**Problem**: `host_index.write()` acquired on every cache insert creates contention.

**Fix Plan**:
1. Replace `RwLock<AHashMap<String, Vec<CacheKey>>>` with `DashMap<String, Vec<CacheKey>>`
2. Remove all `.write()` calls on host_index

**Files to modify**:
- `src/proxy_cache/store.rs` - Change field type, remove lock calls (~15 lines)

**Est. lines**: ~15
**Risk**: Low (DashMap already used in codebase)

---

#### Issue M2: Mesh Multiple Sequential Read Locks

**Severity**: MEDIUM
**Location**: `src/mesh/dht/record_store_message.rs:518-546`
**Type**: Lock contention
**Impact**: 3 lock acquisitions instead of 1 per quorum operation

**Problem**: Triple lock pattern: quorum_manager, topology, transport each acquired separately.

**Fix Plan**:
1. Create combined `RoutingStateRef` struct holding all three
2. Single lock acquisition returns all data
3. Alternatively: use a higher-level lock protecting the compound operation

**Files to modify**:
- `src/mesh/dht/record_store_message.rs` - Consolidate locks (~20 lines)

**Est. lines**: ~20
**Risk**: Medium (deadlock analysis needed)

---

#### Issue M3: Ratelimit Cleanup Write Locks

**Severity**: MEDIUM
**Location**: `src/waf/ratelimit.rs:285-316`
**Type**: Lock contention
**Impact**: Sequential write locks on 64 shards blocking request handlers

**Problem**: Single cleanup task acquires write locks on all 64 shards sequentially.

**Fix Plan**:
1. Spawn 64 parallel async tasks (one per shard)
2. Each task acquires only its own shard's lock
3. Await all tasks to complete before logging totals

**Files to modify**:
- `src/waf/ratelimit.rs` - Parallelize cleanup loop (~40 lines)

**Est. lines**: ~40
**Risk**: Low (uses existing tokio::spawn pattern)

---

#### Issue M4: Mesh Seen Messages Locking

**Severity**: MEDIUM
**Location**: `src/mesh/transport.rs:961-968`
**Type**: Lock contention
**Impact**: 500K+ lock acquisitions/sec

**Problem**: `RwLock` on `seen_messages` HashMap for every message check+mark.

**Fix Plan**:
1. Replace `RwLock<LruCache>` with `DashMap`
2. Use `DashMap::contains_key()` (lock-free read)
3. Use `DashMap::insert()` (lock-free write)

**Files to modify**:
- `src/mesh/transport.rs` - Change field type, update methods (~20 lines)

**Est. lines**: ~20
**Risk**: Low (DashMap already in Cargo.toml)

---

### LOW Priority

#### Issue L1: Trust Anchor Full DB Save

**Severity**: LOW
**Location**: `src/dns/trust_anchor.rs:770`
**Type**: I/O inefficiency
**Impact**: Full database rewrite on single anchor change

**Fix Plan**:
1. Enable SQLite WAL mode in `init_db()` (1 line)
2. Add `upsert_single_anchor()` method
3. Update `add_anchor()` and `remove_anchor()` to use single-row upsert
4. Update `process_rfc5011_updates()` to do targeted updates

**Files to modify**:
- `src/dns/trust_anchor.rs` - Add upsert method, update callers (~60 lines)

**Est. lines**: ~60
**Risk**: Low

---

#### Issue L2: DNS NSEC3 Dead Code Scan

**Severity**: LOW
**Location**: `src/dns/server/dnssec_impl.rs:384`
**Type**: Wasted CPU
**Impact**: Full zone scan where result is discarded

**Problem**: `_types_exists` result is never read - dead code.

**Fix Plan**:
1. Remove the `.any()` call entirely
2. Or add `#[allow(dead_code)]` if it serves as documentation

**Files to modify**:
- `src/dns/server/dnssec_impl.rs` - Remove dead code (~10 lines)

**Est. lines**: ~10
**Risk**: Very Low

---

#### Issue L3: DNS Vec Allocations in Canonicalization

**Severity**: LOW
**Location**: `src/dns/dnssec_validation.rs:51-130,178-209`
**Type**: Allocation overhead
**Impact**: 3-6M allocations/sec

**Fix Plan**:
1. Add thread-local buffers like existing normalizer pattern:
```rust
thread_local! {
    static CANONICAL_RDATA_BUF: Cell<Option<Vec<u8>>> = Cell::new(None);
}
```
2. Refactor `canonical_name()`, `canonical_rdata()`, `canonical_dns_message()` to use buffers
3. Use `take()`/`put()` pattern for buffer reuse

**Files to modify**:
- `src/dns/dnssec_validation.rs` - Add buffers, refactor functions (~80 lines)

**Est. lines**: ~80
**Risk**: Low

---

#### Issue L4: Rust Allocation Patterns Research (Completed)

**Finding**: Codebase already has good patterns to leverage:
- `thread_local` buffers: `src/buffer/pool.rs:126-129`
- Lock-free DashMap: 158 usages
- Moka cache: 7 usages with TTL
- `Cow<str>`: 41 usages for zero-copy
- Pre-computed values at init: `SuspiciousWordTracker`

**No code changes needed** - this is reference documentation.

---

## Implementation Phases

### Phase 1: Dead Code & Quick Wins (Low Risk, High Impact)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| C3: Dead lowercase field | -65 (net) | Very Low | ~50MB/sec |
| H2: Cookie format! | 12 | Low | 1.5M alloc/sec |
| L2: NSEC3 dead scan | 10 | Very Low | CPU reduction |
| **Subtotal** | **~0** | **Very Low** | **High** |

### Phase 2: CRITICAL Infrastructure (Medium Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| C1: DHT JSON→postcard | 170-240 | Medium | 1M alloc/sec |
| C2: WAF header clone | 70 | Low | 110M clones/sec |
| C4: Cache O(n) invalidation | 30 | Low | Event loop unblock |
| **Subtotal** | **270-340** | **Medium** | **Very High** |

### Phase 3: HTTP/TLS & Rate Limiting (Low Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| H1: Header lookups | 50 | Low | 67% lookup reduction |
| H6: Rate limit rotation | 30 | Low | O(1) rotation |
| **Subtotal** | **80** | **Low** | **High** |

### Phase 4: DNS Optimizations (Low-Medium Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| H4: DNS lowercases | 26 | Low | 3→1 lowercases/query |
| H5: Zone Arc | 30 | Medium | Eliminate zone clone |
| L3: Vec reuse | 80 | Low | 3-6M alloc/sec |
| **Subtotal** | **136** | **Medium** | **High** |

### Phase 5: Lock Consolidations (Medium Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| M1: Cache DashMap | 15 | Low | Lock elimination |
| M2: Mesh lock consolidation | 20 | Medium | 3→1 lock |
| M3: Ratelimit cleanup parallel | 40 | Low | Parallel cleanup |
| M4: Seen messages DashMap | 20 | Low | Lock elimination |
| **Subtotal** | **95** | **Medium** | **High** |

### Phase 6: Remaining Items (Low Risk)

| Issue | Lines | Risk | Benefit |
|-------|-------|------|---------|
| H3: Proxy headers | 50 | Medium | 8 alloc/request |
| L1: Trust anchor | 60 | Low | Incremental saves |
| **Subtotal** | **110** | **Medium** | **Medium** |

---

## Total Estimated Effort

| Phase | Lines | Priority | Risk |
|-------|-------|----------|------|
| Phase 1 | ~0 (net negative) | CRITICAL | Very Low |
| Phase 2 | 270-340 | CRITICAL | Medium |
| Phase 3 | 80 | HIGH | Low |
| Phase 4 | 136 | HIGH | Medium |
| Phase 5 | 95 | MEDIUM | Medium |
| Phase 6 | 110 | MEDIUM | Medium |
| **Total** | **~691-771** | **-** | **-** |

---

## Known Patterns to Leverage

The codebase has proven patterns to follow:

| Pattern | Location | Usage |
|---------|----------|-------|
| `thread_local` buffers | `src/buffer/pool.rs:126-129` | 4-tier BufferPool |
| `thread_local` normalizer | `src/waf/attack_detection/normalizer.rs:8-11` | NORMALIZE_BUFFER |
| `DashMap` | 158 usages across codebase | Concurrent HashMap |
| `moka::sync::Cache` | 7 usages | TTL caches |
| `Cow<str>` | 41 usages | Zero-copy transforms |
| Pre-computed words | `src/waf/probe_tracker.rs:500-508` | words_lower at init |
| Lock-free rate limit | `src/waf/ratelimit/core.rs:66-81` | AtomicSlidingWindow |

---

## Testing Requirements

For each phase:

1. `cargo test --lib --no-run` - Verify test compilation
2. `cargo clippy --lib -- -D warnings` - Catch type errors
3. `cargo fmt` - Code formatting
4. Integration tests for changed paths

**Performance validation** (manual):
- k6 benchmark before/after for affected code paths
- `cargo bench` if benchmarks exist

---

## Backwards Compatibility Notes

| Issue | Compatibility Concern |
|-------|----------------------|
| C1: DHT postcard | Version prefix needed for signature compatibility |
| H5: Zone Arc | Call sites must handle Arc<Zone> |
| M2: Mesh locks | Must preserve deadlock safety |

---

## Risk Assessment Summary

| Risk Level | Issues | Mitigation |
|------------|--------|------------|
| Very Low | 3 (C3, H2, L2) | Dead code removal |
| Low | 9 (C2, C4, H1, H6, M1, M3, M4, L1, L3) | Proven patterns |
| Medium | 5 (C1, H3, H5, M2, L1) | Careful implementation, test |
| High | 0 | - |

---

## References

- AGENTS.md: Architecture and performance guidelines
- `skills/performance_patterns.md`: Detailed patterns
- `src/buffer/pool.rs`: Production-tested buffer pooling
- `src/waf/ratelimit/core.rs`: Lock-free rate limiting example
- `src/waf/probe_tracker.rs`: Pre-computation patterns

---

## Appendix: Issue Locations Quick Reference

| ID | File | Line(s) | Fix Complexity |
|----|------|---------|----------------|
| C1 | `src/mesh/dht/record_store_crud.rs` | 33-40 | Medium |
| C1 | `src/mesh/dht/record_store_message.rs` | 557-562, 700-705 | Medium |
| C2 | `src/waf/attack_detection/mod.rs` | 302, 336, 375, etc. | Low |
| C3 | `src/waf/probe_tracker/normalizer.rs` | 66, 397, 418-420 | Very Low |
| C4 | `src/proxy_cache/store.rs` | 557-562 | Low |
| H1 | `src/http/server.rs` | 831-844 | Low |
| H1 | `src/tls/server.rs` | 597-613 | Low |
| H2 | `src/http/server.rs` | 1219 | Low |
| H2 | `src/waf/mod.rs` | 818, 825 | Low |
| H3 | `src/proxy/headers.rs` | 360-398 | Medium |
| H4 | `src/dns/server/query.rs` | 670, 716, 719 | Low |
| H4 | `src/dns/server/dnssec_impl.rs` | 324-325, 390 | Low |
| H5 | `src/dns/server/sharded_store.rs` | 67 | Medium |
| H6 | `src/waf/ratelimit/core.rs` | 176-180 | Low |
| M1 | `src/proxy_cache/store.rs` | 524 | Low |
| M2 | `src/mesh/dht/record_store_message.rs` | 518-546 | Medium |
| M3 | `src/waf/ratelimit.rs` | 285-316 | Low |
| M4 | `src/mesh/transport.rs` | 961-968 | Low |
| L1 | `src/dns/trust_anchor.rs` | 770 | Low |
| L2 | `src/dns/server/dnssec_impl.rs` | 384 | Very Low |
| L3 | `src/dns/dnssec_validation.rs` | 51-130, 178-209 | Low |
# MaluWAF Performance Optimization Plan

**Last updated**: 2026-04-23
**Status**: 📋 PENDING IMPLEMENTATION

## Overview

This document details performance optimizations identified during a comprehensive performance review of the MaluWAF codebase. The goal is to reduce per-request allocations and lock contention to support 500K+ requests/second target.

**Total optimization categories**: 9
**Priority**: Critical → Medium

---

## Performance Review Summary

### Architecture Assessment

| Component | Status | Notes |
|-----------|--------|-------|
| Worker Model | ✅ GOOD | Single tokio async runtime, internal thread pool |
| DNS ZoneStore | ✅ GOOD | 64-shard implementation, lock-free reads |
| Rate Limiter | ✅ GOOD | Lock-free atomic sliding window, 16 shards |
| Moka Cache | ✅ GOOD | Thread-safe O(1) lookups |
| ViolationTracker | ⚠️ ISSUE | Global RwLock - contention under attack |
| HTTP Response Path | ⚠️ ISSUE | Multiple per-request allocations |
| WebSocket Path | ⚠️ ISSUE | HashMap::new() per message |

---

## Items Requiring Optimization

### Category 1: ViolationTracker Lock Contention

**Severity**: CRITICAL
**Impact**: Per-violation lock acquisition ~1ms; under attack becomes bottleneck
**Location**: `src/waf/violation_tracker.rs:152-180`

**Problem**: The `record_violation()` function acquires a global `RwLock<HashMap>` on every call. This is called from `src/waf/mod.rs:659` in `maybe_escalate_and_block()`, which only triggers on actual violations, not every request.

**Current behavior**:
```rust
// src/waf/violation_tracker.rs:152-180
pub fn record_violation(&self, ip: IpAddr, reason: &str, threat_level: u8) -> u32 {
    let key = ViolationEntry::key(&ip);
    let count = {
        let mut store = self.store.write();  // <-- LOCK ACQUISITION
        // ... hashmap operations
    };
    count
}
```

**Call frequency**: Only on WAF violations (~1-5% of requests under normal conditions, higher under attack)

**Recommended Fix**: Shard by IP prefix (last octet for IPv4, first byte for IPv6):

```rust
// Proposed: ShardedViolationTracker
const NUM_SHARDS: usize = 64;

struct ShardedViolationTracker {
    shards: Vec<RwLock<HashMap<String, ViolationEntry>>>,
}
```

**Implementation complexity**: Medium
**Risk**: Medium - requires careful handling of migration and persistence

---

### Category 2: Response Header Vec Allocations

**Severity**: HIGH
**Impact**: 10-20 allocations per proxied response; ~10M/sec at 500K rps
**Location**: `src/http/server.rs:2644, 2741`, `src/tls/server.rs:1449, 1599`

**Problem**: Creating new `Vec::new()` for response header filtering on each response:

```rust
// src/http/server.rs:2644
let mut filtered_headers_buf = Vec::new();
filter_response_headers_buf(
    &resp_parts.headers,
    &headers_to_filter,
    &mut filtered_headers_buf,
);
```

**Current allocation sites**:

| File | Line | Description |
|------|------|-------------|
| `http/server.rs` | 2644 | Proxy response headers |
| `http/server.rs` | 2741 | Cached response headers |
| `tls/server.rs` | 1449 | TLS proxy response |
| `tls/server.rs` | 1599 | TLS cached response |

**Recommended Fix**: Thread-local buffer reuse:

```rust
// src/http/server.rs
thread_local! {
    static RESPONSE_HEADER_BUF: RefCell<Vec<(HeaderName, HeaderValue)>> =
        RefCell::new(Vec::with_capacity(32));
}

// Usage:
RESPONSE_HEADER_BUF.with(|buf| {
    buf.borrow_mut().clear();
    filter_response_headers_buf(&headers, &to_filter, &mut *buf.borrow_mut());
    // use buf
});
```

**Implementation complexity**: Low
**Risk**: Low - thread-local ensures isolation
**Estimated allocations eliminated**: ~10M/sec at 500K rps

---

### Category 3: String Allocations in Hot Paths

**Severity**: HIGH
**Impact**: 10-15 allocations per request; ~7.5M/sec at 500K rps
**Location**: `src/http/server.rs`, `src/tls/server.rs`

**Problem**: Multiple `.to_string()` calls in request handling path:

| Line | Pattern | Current | Recommendation |
|------|---------|---------|--------------|
| `http/server.rs:829` | `pq.to_string()` | Cow → Good | Keep |
| `http/server.rs:1416` | `method.to_string()` | String | Use `method.as_str()` |
| `http/server.rs:1112` | `&method.to_string()` | String | Use `method.as_str()` |
| `http/server.rs:1140` | `&method.to_string()` | String | Use `method.as_str()` |
| `http/server.rs:1352` | `site_id.to_string()` | String | Cache per-request |
| `tls/server.rs:600` | `pq.to_string()` | String | Use Cow |
| `tls/server.rs:607` | `host.to_string()` | String | Use Cow |
| `tls/server.rs:780` | `method.to_string()` | String | Use `method.as_str()` |

**Worst offender - Duplicate regex allocation**:
```rust
// http/server.rs:2073-2080
let path_str = path.to_string();           // FIRST ALLOCATION
is_image = IMAGE_PROTECTION_REGEX.is_match(&path_str);
let path_str = path.to_string();           // SECOND ALLOCATION (SAME LINE!)
is_whitelisted = IMAGE_PROTECTION_WHITELIST.is_match(&path_str);
```

**Recommended Fix**: Reuse String variable:

```rust
let mut path_str = path.to_string();
is_image = IMAGE_PROTECTION_REGEX.is_match(&path_str);
is_whitelisted = IMAGE_PROTECTION_WHITELIST.is_match(&path_str);
```

**Implementation complexity**: Low (search/replace patterns)
**Risk**: Low
**Estimated allocations eliminated**: ~5M/sec at 500K rps

---

### Category 4: WebSocket HashMap Allocations

**Severity**: HIGH (for WebSocket traffic only)
**Impact**: 2 HashMap allocations per WebSocket message
**Location**: `src/http/server.rs:3337, 3340, 3412, 3415, 3547, 3550, 3618, 3625`

**Problem**: Creating empty HashMaps for every WebSocket frame:

```rust
// src/http/server.rs:3333-3341
let mut proto_request = ProtocolRequest {
    client_ip: SocketAddr::from((client_ip, 0)),
    method: method.to_string(),
    path: path_clone.clone(),
    headers: HashMap::new(),      // <-- ALLOCATION
    body: body_vec,
    protocol: ProtocolType::WebSocket,
    metadata: HashMap::new(),   // <-- ALLOCATION
};
```

**Usage analysis**: Looking at `src/protocol/types.rs:45-53`, these HashMaps store request metadata but are rarely populated in WebSocket flows.

**Recommended Fix**: Static empty map constant:

```rust
use std::collections::HashMap;
use std::sync::LazyLock;

static EMPTY_METADATA: LazyLock<HashMap<String, String>> = LazyLock::new(|| HashMap::new());

// Then use &EMPTY_METADATA for empty case
```

**Alternative**: Use a constant reference to an empty map for the "not populated" case

**Implementation complexity**: Low
**Risk**: Low
**Estimated allocations eliminated**: N/A (WebSocket-only path)

---

### Category 5: WASM Transform Empty HashMap

**Severity**: MEDIUM
**Impact**: 1-2 allocations per response when WASM filters enabled
**Location**: `src/http/server.rs:2033, 2038, 2336, 2339, 2772, 2777`

**Problem**: Creating empty HashMap to pass to WASM filters:

```rust
// http/server.rs:2336
pm.apply_wasm_filters(filter_req, std::collections::HashMap::new())
```

**Call frequency**: Only when WASM plugins enabled (rare)

**Recommended Fix**: Check if filters exist before calling:

```rust
if !filters.is_empty() {
    pm.apply_wasm_filters(filter_req, std::collections::HashMap::new())
}
```

**Or**: Accept Option parameter in filter functions:

```rust
pub fn apply_wasm_filters(&self, request: Request, metadata: Option<HashMap>)
```

**Implementation complexity**: Low
**Risk**: Low
**Estimated allocations eliminated**: Minimal (WASM is rare)

---

### Category 6: DNS ZoneStore Sharding

**Severity**: Already optimized
**Status**: ✅ GOOD

**Current implementation**: `src/dns/server/sharded_store.rs`

- 64 shards with independent RwLocks
- Single-shard O(1) reads via `shard_index()` hashing
- Suffix index for domain matching

**Potential improvements**:
- Consider `DashMap` for lock-free reads
- Pre-compute zone lookups for common zones

**Status**: No action needed - well implemented

---

### Category 7: Rate Limiter Lock-Free

**Severity**: Already optimized
**Status**: ✅ GOOD

**Current implementation**: `src/waf/ratelimit/core.rs`

- 16 shards with `AtomicSlidingWindow`
- Truly lock-free with atomic operations
- No contention issues

**Status**: No action needed - well implemented

---

### Category 8: Moka Cache Optimization

**Severity**: Already optimized
**Status**: ✅ GOOD

**Current implementation**: `src/proxy_cache/store.rs`

- O(1) lookups via Moka Cache
- Proper weigher function
- Inflight request deduplication via DashMap

**Potential minor improvements**:
- Remove duplicate tracking (local + global metrics)
- Consider `get_with` API for better concurrency

**Status**: No action needed - well implemented

---

### Category 9: Mesh DHT Lock Contention

**Severity**: MEDIUM
**Impact**: Background operations, not in request path
**Location**: `src/mesh/dht/record_store.rs`, `src/mesh/transport.rs`

**Current state**: 
- 64-shard implementation for DHT records
- Multiple RwLocks for metadata

**Problem areas**:
- `record_state`, `routing_state`, `metrics_state` compound locks
- Some operations hold multiple locks

**Recommended Fix**:
- Consider DashMap for peer_states
- Batch operations to reduce lock acquisitions

**Implementation complexity**: Medium
**Risk**: Medium - DHT is critical for mesh operation

**Note**: This is a background operation path, not in the HTTP request hot path. Can be deferred.

---

## Implementation Phases

### Phase 1: Critical Quick Fixes (Recommended First)

| # | Category | Effort | Risk | Est. Impact |
|---|----------|--------|------|-------------|
| 1.2 | Response Vec Allocation | Low | Low | High |
| 1.3 | String Allocations | Low | Low | High |
| 1.4 | WebSocket HashMap | Low | Low | Medium |
| 1.5 | WASM HashMap | Low | Low | Low |

### Phase 2: Medium Effort Fixes

| # | Category | Effort | Risk | Est. Impact |
|---|----------|--------|------|-------------|
| 2.1 | ViolationTracker Sharding | Medium | Medium | High |
| 2.9 | Mesh DHT Optimization | Medium | Medium | Low |

### Phase 3: Informational (No Action Needed)

- [x] DNS ZoneStore - Already optimal
- [x] Rate Limiter - Already optimal
- [x] Moka Cache - Already optimal

---

## Implementation Checklist

### Phase 1: Quick Wins

- [ ] **F1.1**: Add thread-local RESPONSE_HEADER_BUF to http/server.rs
- [ ] **F1.2**: Add thread-local RESPONSE_HEADER_BUF to tls/server.rs
- [ ] **F1.3**: Fix duplicate path_str allocation (lines 2073, 2826, 2901)
- [ ] **F1.4**: Replace method.to_string() with method.as_str() (8 locations)
- [ ] **F1.5**: Replace site_id.to_string() with site_id.as_str() (2 locations)
- [ ] **F1.6**: Use Cow for pq, host, user_agent in tls/server.rs
- [ ] **F1.7**: Change ProtocolRequest headers/metadata to Option or static empty
- [ ] **F1.8**: Check WASM filter existence before calling

### Phase 2: Medium Effort

- [ ] **F2.1**: Implement ShardedViolationTracker
- [ ] **F2.2**: Test under load (simulate attack conditions)
- [ ] **F2.3**: Consider DashMap for mesh peer_states

---

## Performance Impact Estimation

### At 500K RPS (with 20% cache hit rate, 80% proxied)

| Optimization | Allocations Saved/sec | Est. CPU Improvement |
|--------------|----------------------|-------------------|
| Response Vec | ~10M | ~2-3% |
| String fixes | ~5M | ~1-2% |
| WebSocket | N/A | N/A |
| WASM | Minimal | Minimal |
| ViolationTracker | N/A (under attack) | ~10-15% |
| **Total** | ~15M | ~3-5% |

---

## Testing Recommendations

1. **Load testing**: Run `cargo bench` or custom load test at 250K, 500K, 750K rps
2. **Profile**: Use `cargo flamegraph` to verify improvements
3. **Allocate tracking**: Add `RUSTFLAGS="-Z allocator=system"` and track allocations
4. **Lock contention**: Monitor with `tokio-console` under attack simulation

---

## References

- `AGENTS.md` - Scalability guidelines and patterns
- `src/waf/violation_tracker.rs` - Current implementation
- `src/http/server.rs` - HTTP hot path
- `src/tls/server.rs` - TLS hot path
- `src/proxy_cache/store.rs` - Cache implementation
- `src/dns/server/sharded_store.rs` - DNS zone store
- `src/waf/ratelimit/core.rs` - Rate limiter
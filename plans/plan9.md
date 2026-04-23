# Reverse Proxy & WAF Scalability Improvement Plan

## Overview

This plan addresses scalability improvements identified in the reverse proxy and WAF code review for supporting 100K+ proxied sites across the mesh network, targeting 500K requests/second.

## Review Context

- **Architecture**: Single unified server process handles all sites (not multiple worker processes)
- **Memory target**: < 1000MB default for the unified server process, configurable
- **Site discovery**: Edge nodes discover sites via DHT (origins advertise, global nodes authenticate)
- **Edge model**: Any edge can serve any site based on client proximity (stateless serving)

## Review Summary

| Area | Current State | Priority | Target |
|------|--------------|----------|--------|
| HTTP Client Pooling | ✅ Adequate | Low | Scale cache TTL |
| Upstream Pools | ⚠️ Per-site only | Medium | Global pool by backend URL |
| Rate Limiter | ⚠️ Global/shared | **HIGH** | Per-site isolation |
| Mesh Topology | ⚠️ Undersized caches | **HIGH** | 10-100x scale |
| Mesh Fallback | ❌ No graceful deg. | **HIGH** | DHT + cache fallback |
| Connection Limits | ⚠️ Hardcoded | Medium | Make configurable |
| WAF Checks | ✅ Correct | Low | Add metrics |
| IPC Serialization | ✅ Binary (postcard) | Done | - |
| Memory | ⚠️ Info only | Low | Document |

---

## Issue #1: Per-Site Rate Limiting (CRITICAL)

**Priority**: P0

### Problem

Current rate limiter (`src/waf/ratelimit/core.rs`) is global across all sites. One site undergoing a traffic surge (legitimate or attack) can cause all sites to hit rate limits, taking down the entire proxy.

Note: There's already a `GlobalRateLimiter` in `src/waf/ratelimit/core.rs:203` - this is used but provides per-connection limits only, not per-site limits. The issue is that IP-based rate limiting is shared.

**Current state**:
- `ShardedRateLimiter` uses 16 shards (hardcoded at `core.rs:10`)
- No site_id awareness in rate limit checks
- `SiteRateLimitConfig` exists but is not wired into `check_rate_limit()`

### Affected Files

1. `src/waf/ratelimit/core.rs` - Add site-aware sharding
2. `src/waf/mod.rs:949-1100` - Wire site_id into rate limit checks
3. `src/config/site/ratelimit.rs` - Configure per-site limits

### Implementation

Add site_id-aware rate limiting with separate buckets per site:

```rust
// New: Site-specific rate limiter
pub struct SiteRateLimiter {
    site_id: String,
    ip_limiter: Arc<ShardedRateLimiter>,    // Per-site IP limiting
    global_limiter: GlobalRateLimiter,        // Per-site global limiting  
}

// In WafCore check_request_full, add site_id parameter:
// pub async fn check_request_full(
//     &self,
//     client_ip: IpAddr,
//     site_id: &str,  // NEW PARAMETER
//     method: &str,
//     ...
// )
```

**Changes needed**:
1. Add `site_id: &str` parameter to `check_request_full()` and downstream checks
2. Create `SiteRateLimiter` per site (lazy initialization from config) - or better, use sub-shards keyed by site_id within the existing limiter
3. Use site_id hash for shard selection to avoid hot shards
4. Wire `SiteRateLimitConfig` overrides (per_second, per_minute)

**Alternative approach (simpler)**: Instead of creating per-site limiters, add site_id as part of the rate limiting key:
```rust
// In check_rate_limit, include site_id in the rate limit key:
fn rate_limit_key(&self, client_ip: IpAddr, site_id: &str) -> String {
    format!("{}:{}", site_id, client_ip)
}
```

### Effort

Medium - Requires API changes to WAF check calls.

---

## Issue #2: Mesh Topology Cache Scaling (CRITICAL)

**Priority**: P0

### Problem

At 100K sites, mesh topology caches are undersized by 10-100x:
- `route_cache`: 10K capacity → 90% eviction rate
- `verified_upstream_cache`: 1K capacity, 60s TTL → 99% miss rate

Location: `src/mesh/topology.rs:58-66`

### Affected Files

1. `src/mesh/topology.rs` - Scale cache sizes
2. `src/mesh/proxy.rs` - Scale policy caches
3. `src/mesh/topology.rs:739-842` - DHT query optimization

### Implementation

**Cache scaling**:
```rust
// topology.rs:58-66 - Scale UP
let route_cache = MokaCache::builder()
    .time_to_live(Duration::from_secs(3600))
    .max_capacity(100000)    // 10x for 100K sites
    .build();

let verified_upstream_cache = MokaCache::builder()
    .time_to_live(Duration::from_secs(60))
    .max_capacity(50000)    // 50x - matches active upstreams
    .build();

// proxy.rs:261-265 - Scale UP
let policy_cache = Cache::builder()
    .time_to_live(Duration::from_secs(3600))
    .max_capacity(50000)    // Up from defaults
    .build();
```

**DHT query optimization**:
Replace `get_all_records()` scan with indexed `get_by_prefix()`:
```rust
// Current (inefficient at line ~756):
let records = rs.get_all_records();
for record in records { 
    if record.key.starts_with("verified_upstream:") ... 
}

// Should be (indexed):
let records = rs.get_by_prefix("verified_upstream:", DEFAULT_GET_BY_PREFIX_LIMIT);
```

### Effort

Small - Configuration changes only.

---

## Issue #3: Mesh Graceful Degradation (HIGH)

**Priority**: P0

### Problem

When global nodes are unavailable, edge nodes have no fallback - they fail requests hard with 500/503 instead of using cached routes or querying peer-to-peer.

**Current state**:
- Edge sets `degraded=true` when `get_closest_global_node()` returns None
- No attempt to use cached routes or local upstreams
- Circuit breaker only triggers on upstream failures, not global node failures

### Affected Files

1. `src/mesh/proxy.rs` - Add fallback logic
2. `src/mesh/topology.rs` - Add peer-to-peer query
3. `src/mesh/discovery.rs` - Handle degraded mode

### Implementation

```rust
// In MeshProxy::resolve_upstream(), add fallback chain:
async fn resolve_upstream(&self, site: &str) -> Result<...> {
    // 1. Try cached route (existing)
    if let Some(cached) = self.policy_cache.get(&site) {
        return Ok(cached);
    }
    
    // 2. Try global nodes (existing)
    if let Some(route) = self.send_route_query(site).await? {
        return Ok(route);
    }
    
    // 3. NEW: Try peer-to-peer DHT if degraded
    if self.topology.is_degraded() {
        // Query peers directly
        if let Some(route) = self.query_peers_directly(site).await? {
            return Ok(route);
        }
    }
    
    // 4. NEW: Serve stale cached content
    if let Some(stale) = self.get_stale_policy(site) {
        // Return with warning header
        return Ok(stale.with_warning());
    }
    
    Err(MeshProxyError::NoRouteToUpstream)
}
```

### Effort

Medium - New code paths needed.

---

## Issue #4: Connection Limits Configurability (MEDIUM)

**Priority**: P1

### Problem

Several connection-related values are hardcoded:
- TCP backlog: 1024 (`tcp/listener.rs:357`)
- Max connections per worker: 10,000 (default)

This limits scalability for 500K rps target.

### Affected Files

1. `src/tcp/listener.rs:357` - Make backlog configurable
2. `src/config/network.rs` - Add backlog config
3. `src/config/http.rs` - Increase default max_connections

### Implementation

```rust
// config/network.rs - Add:
pub struct TcpConfig {
    pub backlog: usize,  // NEW: default 4096
    pub worker_pool_size: usize,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
}

// tcp/listener.rs:357 - Use config:
let backlog = self.config.backlog;
```

Also document OS-level tuning:
```bash
# /etc/sysctl.conf (Linux)
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
fs.file-max = 2097152

# /etc/security/limits.conf
* soft nofile 524288
* hard nofile 524288
```

### Effort

Small - Configuration changes.

---

## Issue #5: Global Upstream Connection Pooling (MEDIUM)

**Priority**: P1

### Problem

Each site creates its own `UpstreamPool`. Sites with identical backends don't share connections, leading to inefficiency.

**Current state**: `ProxyServer` owns `upstream_pool: Option<Arc<UpstreamPool>>` - per-site.

### Affected Files

1. `src/upstream/pool.rs` - Add global pool registry
2. `src/proxy/mod.rs` - Use global pool when backend matches

### Implementation

```rust
// New: Global upstream pool registry
static UPSTREAM_POOL_GLOBAL: LazyLock<DashMap<String, Arc<UpstreamPool>>> =
    LazyLock::new(DashMap::new);

// Get or create shared pool
fn get_global_upstream_pool(urls: &[String], algorithm: LoadBalanceAlgorithm) 
    -> Arc<UpstreamPool> {
    let key = urls.join(",");
    UPSTREAM_POOL_GLOBAL
        .entry(key)
        .or_insert_with(|| UpstreamPool::new(urls.to_vec(), algorithm))
        .clone()
}
```

### Effort

Medium - Add global registry.

---

## Issue #6: Per-Site Memory Limits (LOW)

**Priority**: P2

### Problem

Proxy cache at 100K sites could consume 100GB+ if caching enabled for all sites with average 1MB each. No per-site quotas.

### Affected Files

1. `src/proxy_cache/store.rs` - Add per-site limits
2. `src/config/site/cache.rs` - Configure quotas

### Implementation

```rust
// Add per-site memory quota
pub struct CacheQuota {
    pub site_id: String,
    pub max_memory_bytes: u64,
    pub max_entries: u64,
}

// Track memory per site in cache
struct SiteMemoryTracker {
    by_site: DashMap<String, u64>,  // bytes per site
    total: AtomicU64,
}

// Evict when site exceeds quota
```

### Effort

Low - Nice to have, not critical.

---

## Issue #7: Rate Limiter Shard Count (LOW)

**Priority**: P2

### Problem

Rate limiter uses 16 shards (hardcoded). At 500K rps, may see contention.

### Affected Files

1. `src/waf/ratelimit/core.rs:10` - Make configurable

### Implementation

Use CPU count × 2:
```rust
const SHARD_COUNT: usize = std::thread::available_parallelism()
    .map(|n| n.get() * 2)
    .unwrap_or(16)
    .max(16);
```

### Effort

Small - Configuration change.

---

## Issue #8: WAF Check Timing Metrics (LOW)

**Priority**: P2

### Problem

No visibility into which WAF check is slow. Sequential execution is correct, but need metrics to verify.

### Affected Files

1. `src/waf/mod.rs` - Add timing histograms

### Implementation

```rust
// In check_request_full:
let _timer = metrics::histogram!("waf.check.duration").start();
let result = self.check_rate_limit(...);
// Check-specific timers in each check_ function
```

### Effort

Small - Add metrics.

---

## Implementation Order

| Phase | Items | Priority | Estimate |
|-------|-------|----------|----------|
| 1 | Issue #2 (Mesh Caches) | P0 | 1 hour |
| 2 | Issue #1 (Per-Site Rate Limit) | P0 | 4 hours |
| 3 | Issue #3 (Graceful Degradation) | P0 | 3 hours |
| 4 | Issue #4 (Connection Config) | P1 | 1 hour |
| 5 | Issue #5 (Global Upstream Pool) | P1 | 2 hours |
| 6 | Issue #6 (Per-Site Cache) | P2 | 2 hours |
| 7 | Issue #7 (Shard Count) | P2 | 30 min |
| 8 | Issue #8 (WAF Metrics) | P2 | 30 min |

**Total**: ~14 hours

---

## Dependencies

- Issue #1 (Per-Site Rate) requires changes to `check_request_full()` signature
- Issue #3 (Graceful Degradation) depends on Issue #2 (Cache Scaling) for stale cache availability
- Issue #5 (Global Upstream) can be done independently

---

## Testing

```bash
# Integration tests
cargo test --test integration_test

# Rate limiter tests
cargo test --lib ratelimit

# Mesh tests (if available)
cargo test --test dht_integration_test
```

---

## Notes

- WAF check parallelization was investigated and is NOT recommended - sequential early-exit is correct pattern
- IPC uses binary (postcard) serialization - no change needed
- Memory should stay under 1000MB with these changes if proxy cache is disabled or disk-backed
- The single unified server process approach is correct for this scale
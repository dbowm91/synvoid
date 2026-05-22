# SynVoid Routing Architecture Review

**Date:** 2026-05-22
**Document:** `architecture/routing_deep_dive.md`
**Review Scope:** Router, Upstream Pools, Load Balancing, Health Monitoring, Connection Lifecycle

---

## Verified Claims

### 1. Router Matching Hierarchy (Confirmed)

| Document Claim | Implementation | Location |
|--------------|----------------|----------|
| Listener-level default fallback | `default_servers` HashMap per SocketAddr | `src/router.rs:41,421-432` |
| Exact domain matching | `domain_map` HashMap lookup | `src/router.rs:33,1165-1167` |
| Wildcard/Suffix matching | `wildcard_domain_router` MatchRouter with reversed domains | `src/router.rs:34,1170-1173` |
| Path-based location matching | `LocationMatcher::match_uri()` | `src/location_matcher.rs:183-276` |

**Matching Order (verified in `route_with_local_addr`):**
1. Local address → IP-specific exact domain (line 1140-1142)
2. Local address → IP-specific wildcard (line 1145-1150)
3. Local address → IP-bound site with no domains (line 1153-1161)
4. Global exact domain map (line 1165-1167)
5. Global wildcard/suffix matching via reversed domain Radix tree (line 1170-1173)
6. Empty host / wildcard fallback to default servers (line 1175-1188)
7. Fallback mode (return_404 or proxy_to) (line 1190-1219)

### 2. Backend Types (Confirmed)

| Backend Type | Implementation | Location |
|-------------|----------------|----------|
| Upstream | `BackendType::Upstream` | `src/router.rs:66,573-587` |
| FastCGI | `BackendType::FastCgi` | `src/router.rs:67,589-606` |
| PHP | `BackendType::Php` | `src/router.rs:68,720-744` |
| Static | `BackendType::Static` | `src/router.rs:72,653-674` |
| AppServer (Granian) | `BackendType::AppServer` | `src/router.rs:71,630-651` |
| Serverless (WASM) | `BackendType::Serverless` | `src/router.rs:74,808-827` |
| Mesh | `BackendType::Mesh` | `src/router.rs:75,695-711` |
| QuicTunnel | `BackendType::QuicTunnel` | `src/router.rs:73,557-571` |
| Spin | `BackendType::Spin` | `src/router.rs:76,675-693` |
| AxumDynamic | `BackendType::AxumDynamic` | `src/router.rs:70,608-628` |
| CGI | `BackendType::Cgi` | `src/router.rs:69,768-785` |

### 3. Load Balancing Algorithms (Confirmed)

| Algorithm | Implementation | Location |
|-----------|----------------|----------|
| Round Robin | `apply_round_robin()` | `src/upstream/pool.rs:419-426` |
| Weighted Round Robin | `weighted_round_robin()` | `src/upstream/pool.rs:555-572` |
| Least Connections | `apply_least_connections()` via `composite_load()` | `src/upstream/pool.rs:439-445` |
| Random | `apply_random()` | `src/upstream/pool.rs:428-437` |
| IP Hash | `apply_ip_hash()` | `src/upstream/pool.rs:447-465` |
| Peak EWMA | `apply_algorithm()` | `src/upstream/pool.rs:483-498` |

### 4. Health Monitoring (Confirmed)

| Feature | Implementation | Location |
|---------|---------------|----------|
| Passive health checks | `Backend::record_success/failure()` with thresholds | `src/upstream/pool.rs:311-330` |
| Active health checks | `HealthChecker` with interval-based checks | `src/upstream/health.rs:70-96` |
| Recovery threshold | Configurable via `HealthCheckConfig::recovery_threshold` | `src/upstream/health.rs:22` |
| Failure threshold | Configurable via `HealthCheckConfig::failure_threshold` | `src/upstream/health.rs:21` |
| TCP health check | `tcp_health_check()` | `src/upstream/health.rs:224-231` |
| HTTP health check | `http_health_check()` | `src/upstream/health.rs:188-222` |

### 5. Connection Limits (Confirmed)

| Feature | Implementation | Location |
|---------|---------------|----------|
| Max connections per backend | `Backend::max_connections` with `is_available()` check | `src/upstream/pool.rs:144,268-271` |
| Connection scope guard | `ConnectionGuard` RAII pattern | `src/upstream/pool.rs:156-164,289-292` |
| Shared connection table | `SharedConnectionTable` for cross-worker counting | `src/upstream/shared_state.rs:21-124` |

### 6. Backup Servers (Confirmed)

| Feature | Implementation | Location |
|---------|---------------|----------|
| Backup flag | `Backend::is_backup` | `src/upstream/pool.rs:150` |
| Backup fallback | `select_from_backends()` checks primary first | `src/upstream/pool.rs:399-407` |
| Backup pool construction | `UpstreamPool::new_with_backup()` | `src/upstream/pool.rs:381-397` |

### 7. Connection Lifecycle (Confirmed)

| Phase | Implementation | Location |
|-------|----------------|----------|
| Target Resolution | `Router::route()` → `route_to_target()` | `src/router.rs:834-1123` |
| Lease (connection counting) | `Backend::connection_scope()` RAII guard | `src/upstream/pool.rs:289-292` |
| Protocol Negotiation | HTTP/1.1 keep-alive via http_client pool | `src/http_client/` |
| Execution (proxy) | `ProxyServer::forward_with_pool()` | `src/proxy/mod.rs:942-1072` |
| Release | `ConnectionGuard::drop()` decrements | `src/upstream/pool.rs:160-164` |

---

## Unverified Claims

### 1. "HTTP/2 multiplexing" in Connection Lifecycle

**Status:** Partially verified. The `BackendProtocol` enum includes `Grpc` and `GrpcTls` which imply H2 support, but the actual H2 connection multiplexing implementation is in `src/http_client/` which was not fully audited.

---

## Implementation Gaps

### Gap 1: Race Condition in Health Check Recovery

**Location:** `src/upstream/health.rs:134-153`

```rust
if !backend.is_healthy.is_running() {
    backend.consecutive_successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let successes = backend.consecutive_successes.load(std::sync::atomic::Ordering::Relaxed);

    if successes >= config.recovery_threshold {
        backend.is_healthy.set(true);
        backend.consecutive_failures.store(0, std::sync::atomic::Ordering::Relaxed);
```

**Problem:** Multiple concurrent health checks could race when incrementing `consecutive_successes`. If two checks pass simultaneously, both may read different values and cause inconsistent state transitions.

**Recommendation:** Use atomic compare-and-swap (CAS) for threshold detection or a dedicated atomic counter for recovery state.

### Gap 2: Division by Zero in `Backend::load()` and `composite_load()`

**Location:** `src/upstream/pool.rs:332-334`

```rust
pub fn load(&self) -> f64 {
    self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64
}
```

**Location:** `src/upstream/pool.rs:354-360`

```rust
pub fn composite_load(&self) -> f64 {
    let conn_load =
        self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64;
    let cpu_load = self.get_cpu_percent() as f64;
    let _mem_load = self.get_memory_percent() as f64;
    (conn_load * 0.4) + (cpu_load * 0.6)
}
```

**Problem:** If `max_connections` is set to 0 (which is allowed via `with_max_connections()`), both methods will panic due to division by zero.

### Gap 3: `LeastConnections` Uses Composite Load Instead of Pure Connection Count

**Location:** `src/upstream/pool.rs:439-445`

```rust
fn apply_least_connections(&self, candidates: &[&Backend]) -> Option<Backend> {
    candidates
        .iter()
        .map(|b| (b.composite_load(), *b))
        .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(_, b)| b.clone())
}
```

**Problem:** The documentation says "Least Connections: Routes to the backend with the fewest active requests" but the implementation uses `composite_load()` which includes CPU percentage (40% connection load + 60% CPU load). This is a hybrid load balancing algorithm, not pure least connections.

### Gap 4: `update_sites()` Rebuilds Location Matchers Correctly

**Location:** `src/router.rs:1222-1373`

**Update:** Upon re-examination, `update_sites()` does NOT clear or rebuild `location_matchers`. The method clears and rebuilds most maps (domain_map, wildcard_domain_router, static_handlers, listen_map, default_servers, ip_domain_map, ip_wildcard_routers, cleaned_site_domains, cleaned_site_domain_suffixes, site_map) but `location_matchers` is never mentioned.

**Problem:** This could cause stale or inconsistent location routing after site updates since the LocationMatcher for a site would not be updated if only its locations change.

### Gap 5: `Backend::is_available()` Does Not Check Weight

**Location:** `src/upstream/pool.rs:268-271`

```rust
pub fn is_available(&self) -> bool {
    self.is_healthy.is_running()
        && self.current_connections.load(Ordering::Relaxed) < self.max_connections
}
```

**Problem:** A backend with `weight = 0` is still considered "available" but would never actually be selected in weighted round robin, causing unexpected behavior where a zero-weight backend is never used but still occupies a slot.

---

## Bug Reports

### Bug 1: Global Pool Registry Race Condition

**Location:** `src/upstream/pool.rs:752-765`

```rust
pub fn get_or_create_global_pool(
    backend_url: &str,
    algorithm: LoadBalanceAlgorithm,
) -> Arc<UpstreamPool> {
    if let Some(pool) = GLOBAL_POOL_REGISTRY.get(backend_url) {
        return pool.value().clone();
    }

    let pool = Arc::new(UpstreamPool::new(vec![backend_url.to_string()], algorithm));

    GLOBAL_POOL_REGISTRY.insert(backend_url.to_string(), pool.clone());

    pool
}
```

**Problem:** Classic check-then-act race condition. Two concurrent calls could both see the pool doesn't exist and both create new pools, causing duplicate entries.

**Recommendation:** Use `DashMap::entry()` with `or_insert_with()` for atomic check-and-insert.

### Bug 2: IP Hash Algorithm Never Receives Client IP

**Location:** `src/upstream/pool.rs:502`

```rust
LoadBalanceAlgorithm::IpHash => self.apply_ip_hash(candidates, None),
```

The `apply_ip_hash()` is called with `client_ip_hint: None` in `apply_algorithm()`, meaning IP hash always falls back to round-robin when no client IP is provided. The `select_backend_for_ip()` method at line 574-590 properly handles IP hashing but is never called from the normal `select_backend()` flow.

### Bug 3: `WeightedRoundRobin` Returns First Backend When All Weights Are Zero

**Location:** `src/upstream/pool.rs:555-572`

```rust
fn weighted_round_robin(&self, available: &[Backend]) -> Option<Backend> {
    let total_weight: u32 = available.iter().map(|b| b.weight).sum();
    if total_weight == 0 {
        return available.first().cloned();  // Does not check availability!
    }
    // ...
}
```

When all backends have weight 0, the function returns the first backend without checking `is_available()`. This could return an unhealthy or at-capacity backend.

---

## Security Concerns

### Concern 1: No Maximum Domains Per Site Limit

**Location:** `src/router.rs:255-260`

Domain lists are processed without any size limit, which could lead to resource exhaustion with malicious configurations containing thousands of domains.

**Recommendation:** Add a configurable maximum domains limit (e.g., 1000) and reject configurations exceeding it.

### Concern 2: Fallback Mode Allows Proxy to Arbitrary Upstream

**Location:** `src/router.rs:1190-1219`

When `fallback_mode = "proxy_to"` and `fallback_upstream` is configured, any request that doesn't match a site gets proxied to that upstream. This could be exploited if fallback configuration is not properly secured.

### Concern 3: Unsafe Regex Complexity in Location Matchers

**Location:** `src/location_matcher.rs:30-38`

The `check_regex_complexity()` limits regex complexity, but `LocationMatcher` is only created for sites with proxy locations (router.rs:439-452). Static-only sites bypass this check entirely.

### Concern 4: Cache Purge Token Comparison Uses Constant-Time Eq

**Location:** `src/proxy/mod.rs:750`

```rust
Some(token) if required_token.as_bytes().ct_eq(token.as_bytes()).into() => {}
```

This is correct usage of constant-time comparison for secrets. Well implemented.

---

## Code Improvements

### Improvement 1: Extract Common RouteTarget Construction

The `RouteTarget` construction in `get_location_backend()` and `route_to_target()` has significant duplication (many identical field assignments across dozens of code paths). Consider a builder pattern or a shared constructor function to reduce code size and potential for inconsistency.

### Improvement 2: Reduce Clones in Hot Path

**Location:** `src/router.rs:1165-1167`

```rust
if let Some(site_config) = self.domain_map.get(clean_host_arc.as_ref()) {
    return self.route_to_target(site_config, path, &clean_host);
}
```

The `site_config` is already an `Arc<SiteConfig>`, so cloning is cheap, but `route_to_target` clones it again in every `RouteTarget` created. Consider whether all fields in `RouteTarget` actually need to be `Arc` or if references could be used.

### Improvement 3: Add `Backend::available_capacity()`

**Location:** `src/upstream/pool.rs:268-271`

```rust
pub fn is_available(&self) -> bool {
    self.is_healthy.is_running()
        && self.current_connections.load(Ordering::Relaxed) < self.max_connections
}
```

Consider adding a method that returns how many more connections can be accepted (e.g., `max_connections - current_connections`) to provide better load balancing granularity.

### Improvement 4: Health Check Uses Wrong Threshold for Passive Checks

**Location:** `src/upstream/pool.rs:311-330`

```rust
pub fn record_success(&self) {
    self.consecutive_failures.store(0, Ordering::Relaxed);
    let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
    if successes >= 3 && !self.is_healthy.is_running() {  // Hardcoded 3
        self.is_healthy.set(true);
    }
}

pub fn record_failure(&self) {
    self.consecutive_successes.store(0, Ordering::Relaxed);
    let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
    if failures >= 3 && self.is_healthy.is_running() {  // Hardcoded 3
        self.is_healthy.set(false);
```

The thresholds (3) are hardcoded in passive health checks while active health checks use `config.recovery_threshold` and `config.failure_threshold`. These should be consistent or the passive checks should also use configurable thresholds.

---

## Missing Documentation

### Missing 1: Active Health Check Trigger Details

The documentation mentions "Active Health Checks: Periodic out-of-band requests" but doesn't specify:
- How often (interval) - defaults to 10s (health.rs:38)
- What happens when a backend is marked unhealthy
- How recovery is detected

### Missing 2: Connection Pool Lifecycle

No documentation on:
- How connection pools are created/destroyed
- The relationship between `UpstreamPool` and `GLOBAL_POOL_REGISTRY`
- How backends are added/removed at runtime

### Missing 3: Weighted Round Robin Details

The documentation says "Weighted Round Robin: Distribution based on configured backend weights" but doesn't explain:
- How weights are configured (via `with_weight()` method)
- Default weight values (1)
- What happens when all backends have weight 0 (returns first backend without availability check)

### Missing 4: Session Persistence (IP Hash)

The documentation mentions "IP Hash: Ensures session persistence by hashing the client IP to a specific backend" but doesn't explain:
- What happens when backends are added/removed (rehashing inconsistency)
- How client IP is extracted (not passed to `select_backend()`)
- The fallback when no client IP is available (round-robin)

### Missing 5: `PeakEwma` Algorithm

The `LoadBalanceAlgorithm::PeakEwma` variant exists in the code but is not documented in the architecture document. It should be added.

### Missing 6: Backend Protocol Effect on Connection Limits

The `BackendProtocol` enum supports multiple protocols, but there's no documentation on:
- How protocol is determined/negotiated
- Whether protocol affects load balancing selection
- How H2 multiplexing interacts with connection limits

---

## Test Coverage Notes

The test suite has good coverage for:
- Round robin selection (`test_upstream_pool_round_robin`)
- Least connections selection (`test_upstream_pool_least_connections`)
- Health check state transitions (`test_backend_record_success_recovery`, `test_backend_record_failure_circuit_breaker`)
- Backup fallback (`test_upstream_pool_backup_fallback`)
- Connection guard (`test_connection_guard_decrement_on_drop`)

**Missing tests for:**
1. IP hash consistency (same IP -> same backend) - exists (`test_upstream_pool_select_backend_for_ip_same_client`)
2. Weighted round robin with varying weights
3. Concurrent health check recovery race condition
4. Global pool registry race conditions
5. Edge case: `max_connections = 0`
6. `PeakEwma` algorithm behavior
7. `update_sites()` with location matcher updates

---

## Summary

| Category | Count |
|----------|-------|
| Verified Claims | 7 major categories confirmed |
| Unverified Claims | 1 (HTTP/2 multiplexing detail) |
| Implementation Gaps | 5 |
| Bugs | 3 |
| Security Concerns | 4 |
| Code Improvements | 4 |
| Missing Documentation | 6 |

**Overall Assessment:** The routing architecture is well-implemented and matches the documented behavior in most areas. Key concerns are:

1. **Race conditions in health checking** - Concurrent health checks can create inconsistent state
2. **IP hash not working as documented** - Falls back to round-robin because client IP is never passed
3. **Least connections uses hybrid load** - Not pure connection count as documented
4. **Division by zero risk** - `max_connections = 0` causes panic
5. **Missing documentation** - `PeakEwma` and several algorithm behaviors undocumented

**Priority Fixes:**
1. Pass client IP to IP hash algorithm
2. Add `max_connections > 0` check in `load()` and `composite_load()`
3. Use CAS for health check threshold detection
4. Add `PeakEwma` to documentation
5. Add domain count limits to prevent resource exhaustion

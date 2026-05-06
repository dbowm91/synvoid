# SynVoid Routing Architecture Review

**Date:** 2026-05-06
**Document:** `architecture/routing_deep_dive.md`
**Review Scope:** Router, Upstream Pools, Load Balancing, Health Monitoring

---

## Verified Claims

### 1. Router Matching Hierarchy (Confirmed)

| Document Claim | Implementation | Location |
|--------------|----------------|----------|
| Listener-level default fallback | `default_servers` HashMap per SocketAddr | `src/router.rs:40,339-349` |
| Exact domain matching | `domain_map` HashMap lookup | `src/router.rs:32,1077-1078` |
| Wildcard/suffix matching | `suffix_domain_map` Vec with `.ends_with()` | `src/router.rs:33,1081-1085` |
| Path-based location matching | `LocationMatcher::match_uri()` | `src/location_matcher.rs:132-188` |

**Matching Order (verified in `route_with_local_addr`):**
1. Local address → site mapping (line 1056-1074)
2. Exact domain map lookup (line 1077)
3. Suffix/wildcard domain check (line 1081-1085)
4. Empty host / wildcard fallback (line 1087-1099)
5. Fallback mode (return_404 or proxy_to) (line 1102-1131)

### 2. Backend Types (Confirmed)

| Backend Type | Implementation | Location |
|-------------|----------------|----------|
| Upstream | `BackendType::Upstream` | `src/router.rs:75-88` |
| FastCGI | `BackendType::FastCgi` | `src/router.rs:507-524` |
| PHP | `BackendType::Php` | `src/router.rs:638-663` |
| Static | `BackendType::Static` | `src/router.rs:571-592` |
| AppServer (Granian) | `BackendType::AppServer` | `src/router.rs:548-569` |
| Serverless (WASM) | `BackendType::Serverless` | `src/router.rs:726-746` |
| Mesh | `BackendType::Mesh` | `src/router.rs:613-634` |
| QuicTunnel | `BackendType::QuicTunnel` | `src/router.rs:475-489` |
| Spin | `BackendType::Spin` | `src/router.rs:593-612` |

### 3. Load Balancing Algorithms (Confirmed)

| Algorithm | Implementation | Location |
|-----------|----------------|----------|
| Round Robin | `apply_round_robin()` | `src/upstream/pool.rs:311-318` |
| Weighted Round Robin | `weighted_round_robin()` | `src/upstream/pool.rs:430-447` |
| Least Connections | `apply_least_connections()` via `composite_load()` | `src/upstream/pool.rs:331-337` |
| Random | `apply_random()` | `src/upstream/pool.rs:320-329` |
| IP Hash | `apply_ip_hash()` | `src/upstream/pool.rs:339-357` |

### 4. Health Monitoring (Confirmed)

| Feature | Implementation | Location |
|---------|---------------|----------|
| Passive health checks | `Backend::record_success/failure()` with thresholds | `src/upstream/pool.rs:203-222` |
| Active health checks | `HealthChecker` with interval-based checks | `src/upstream/health.rs:70-96` |
| Recovery threshold | Configurable via `HealthCheckConfig::recovery_threshold` | `src/upstream/health.rs:22` |
| Failure threshold | Configurable via `HealthCheckConfig::failure_threshold` | `src/upstream/health.rs:21` |

### 5. Connection Limits (Confirmed)

| Feature | Implementation | Location |
|---------|---------------|----------|
| Max connections per backend | `Backend::max_connections` with `is_available()` check | `src/upstream/pool.rs:89,177-180` |
| Connection scope guard | `ConnectionGuard` RAII pattern | `src/upstream/pool.rs:98-106,197-201` |

### 6. Backup Servers (Confirmed)

| Feature | Implementation | Location |
|---------|---------------|----------|
| Backup flag | `Backend::is_backup` | `src/upstream/pool.rs:93` |
| Backup fallback | `select_from_backends()` checks primary first | `src/upstream/pool.rs:381-388` |
| Backup pool construction | `UpstreamPool::new_with_backup()` | `src/upstream/pool.rs:273-289` |

---

## Unverified Claims

### 1. "Connection Lifecycle" - Protocol Negotiation

The documentation describes:
> **Protocol Negotiation:** The handler establishes or reuses a connection (HTTP/1.1 keep-alive, H2 multiplexing).

**Issue:** While the `BackendProtocol` enum includes `Http`, `Https`, `H2`, `Grpc`, etc., the actual connection reuse and keep-alive behavior is **not visible in the upstream pool code**. The pool merely selects backends; the actual connection management appears to happen elsewhere (likely in `src/http_client/` or proxy handler code).

**Verification needed:** Confirm HTTP/1.1 keep-alive and H2 connection reuse implementation.

---

## Implementation Gaps

### Gap 1: Race Condition in Health Check Recovery

**Location:** `src/upstream/health.rs:137-153`

```rust
if !backend.is_healthy.is_running() {
    backend.consecutive_successes.fetch_add(1, ...);
    let successes = backend.consecutive_successes.load(...);
    if successes >= config.recovery_threshold {
        backend.is_healthy.set(true);
```

**Problem:** Multiple concurrent health checks could race when incrementing `consecutive_successes`. If two checks pass simultaneously, both may see different values and cause inconsistent state transitions.

**Recommendation:** Use atomic compare-and-swap (CAS) for threshold detection.

### Gap 2: Division by Zero in `Backend::load()`

**Location:** `src/upstream/pool.rs:224-226`

```rust
pub fn load(&self) -> f64 {
    self.current_connections.load(Ordering::Relaxed) as f64 / self.max_connections as f64
}
```

**Problem:** If `max_connections` is set to 0 (which is allowed via `with_max_connections()`), this will cause a panic due to division by zero.

**Note:** The `is_available()` check at line 179 prevents selection of backends with full connections, but `load()` is still called for metrics.

### Gap 3: `LeastConnections` Uses Composite Load Instead of Pure Connection Count

**Location:** `src/upstream/pool.rs:331-337`

```rust
fn apply_least_connections(&self, candidates: &[&Backend]) -> Option<Backend> {
    candidates
        .iter()
        .map(|b| (b.composite_load(), *b))
        .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(_, b)| b.clone())
}
```

**Problem:** The documentation says "Least Connections: Routes to the backend with the fewest active requests" but the implementation uses `composite_load()` which includes CPU and memory percentages (line 246-252: `conn_load * 0.4 + cpu_load * 0.6`).

**Inconsistency:** This is a hybrid load balancing algorithm, not pure least connections.

### Gap 4: Health Check Threshold Hardcoded at 3

**Locations:**
- `src/upstream/pool.rs:206` - Passive health recovery
- `src/upstream/pool.rs:214` - Passive health failure

The thresholds (3 successes for recovery, 3 failures for failure) are hardcoded rather than using the configurable thresholds from `HealthCheckConfig`.

### Gap 5: `update_sites()` Does Not Rebuild Location Matchers

**Location:** `src/router.rs:1134-1244`

The `update_sites()` method rebuilds domain maps, static handlers, listen maps, etc., but does **not** rebuild `location_matchers`. This could cause stale or inconsistent location routing after site updates.

**Code:** Line 1134 clears maps but location_matchers is never mentioned in the update.

---

## Bug Reports

### Bug 1: Suffix Domain Matching Incorrect for Leading Dot Wildcards

**Location:** `src/router.rs:241-246`

```rust
for clean_domain in &cleaned {
    if clean_domain.starts_with('.') || clean_domain.contains('*') {
        suffix_domain_map.push((clean_domain.clone(), config_arc.clone()));
```

**Problem:** A domain like `.example.com` would match `foo.example.com` but **NOT** `example.com` itself (since `.example.com` does not end with `.example.com`). This may be intentional but is a subtle edge case.

The suffix matching at line 1082:
```rust
if clean_host.ends_with(domain.as_ref()) {
```

Would match `foo.example.com`.ends_with(".example.com") = true
But NOT `example.com`.ends_with(".example.com") = false

### Bug 2: IP Hash Algorithm Never Receives Client IP

**Location:** `src/upstream/pool.rs:377`

```rust
LoadBalanceAlgorithm::IpHash => self.apply_ip_hash(candidates, None),
```

The `apply_ip_hash()` is called with `client_ip_hint: None` in `apply_algorithm()`, meaning **IP hash always falls back to round-robin** when no client IP is provided. The `select_backend_for_ip()` method at line 449-465 properly handles IP hashing but is never called from the normal selection flow.

### Bug 3: Global Pool Registry Race Condition

**Location:** `src/upstream/pool.rs:621-639`

```rust
pub fn get_or_create_global_pool(...) -> Arc<UpstreamPool> {
    if let Some(pool) = GLOBAL_POOL_REGISTRY.get(backend_url) {
        return pool.value().clone();
    }

    let pool = Arc::new(UpstreamPool::new(...));
    GLOBAL_POOL_REGISTRY.insert(backend_url.to_string(), pool.clone());
    pool
}
```

**Problem:** Classic check-then-act race condition. Two concurrent calls could create duplicate pools. The `DashMap` is thread-safe but doesn't provide atomic check-and-insert.

**Recommendation:** Use `DashMap::entry()` with `or_insert_with()` or similar atomic approach.

---

## Security Concerns

### Concern 1: Unsafe Regex Complexity Not Enforced in Router

**Location:** `src/location_matcher.rs:30-38`

The `check_regex_complexity()` is called for regex patterns, but the router does not use location matchers for all routing paths. The `LocationMatcher` is only created for sites with proxy locations (line 360-368 in router.rs), but other routing paths bypass this.

### Concern 2: No Maximum Domains Per Site Limit

**Location:** `src/router.rs:232-250`

Domain lists are processed without any size limit, which could lead to resource exhaustion with malicious configurations.

### Concern 3: Fallback Mode Allows Proxy to Arbitrary Upstream

**Location:** `src/router.rs:1104-1128`

When `fallback_mode = "proxy_to"` and `fallback_upstream` is configured, any request that doesn't match a site gets proxied to that upstream. This could be exploited if fallback configuration is not properly secured.

---

## Code Improvements

### Improvement 1: Extract Common RouteTarget Construction

The `RouteTarget` construction in `get_location_backend()` and `route_to_target()` has significant duplication (many identical field assignments). Consider a builder pattern or a shared constructor function.

### Improvement 2: Reduce Clone in Hot Path

**Location:** `src/router.rs:1077-1078`

```rust
if let Some(site_config) = self.domain_map.get(clean_host_arc.as_ref()) {
    return self.route_to_target(site_config, path, &clean_host);
}
```

The `site_config` is already an `Arc<SiteConfig>`, so cloning is cheap, but the subsequent `route_to_target` clones it again in every `RouteTarget` created. Consider passing references where possible.

### Improvement 3: `WeightedRoundRobin` Can Return Wrong Backend

**Location:** `src/upstream/pool.rs:430-447`

```rust
fn weighted_round_robin(&self, available: &[Backend]) -> Option<Backend> {
    let total_weight: u32 = available.iter().map(|b| b.weight).sum();
    if total_weight == 0 {
        return available.first().cloned();
    }
    // ...
    for backend in available {
        if remainder < backend.weight {
            return Some(backend.clone());
        }
        remainder -= backend.weight;
    }

    available.first().cloned()  // Fallback - but never reached if weights > 0
}
```

The final fallback is dead code if all weights are positive, and if total_weight is 0, it returns the first backend without checking availability.

### Improvement 4: `Backend::is_available()` Should Also Check Weight > 0

**Location:** `src/upstream/pool.rs:177-180`

A backend with `weight = 0` would still be considered "available" but would never actually be selected in weighted round robin, causing unexpected behavior.

---

## Missing Documentation

### Missing 1: Active Health Check Trigger

The documentation mentions "Active Health Checks: Periodic out-of-band requests" but doesn't specify:
- How often (interval)
- What happens when a backend is marked unhealthy
- How recovery is detected

### Missing 2: Connection Pool Lifecycle

No documentation on:
- How connection pools are created/destroyed
- The relationship between `UpstreamPool` and `GLOBAL_POOL_REGISTRY`
- How backends are added/removed at runtime

### Missing 3: Weighted Round Robin Details

The documentation says "Weighted Round Robin: Distribution based on configured backend weights" but doesn't explain:
- How weights are configured
- Default weight values
- What happens when all backends have weight 0

### Missing 4: Session Persistence (IP Hash)

The documentation mentions "IP Hash: Ensures session persistence by hashing the client IP to a specific backend" but doesn't explain:
- What happens when backends are added/removed (rehashing)
- How client IP is extracted
- The fallback when no client IP is available

### Missing 5: Backend Protocol Selection

The `BackendProtocol` enum supports multiple protocols, but there's no documentation on:
- How protocol is determined/negotiated
- Whether protocol affects load balancing selection
- How H2 multiplexing interacts with connection limits

---

## Test Coverage Notes

The test suite has good coverage for:
- Round robin selection
- Least connections selection
- Health check state transitions
- Backup fallback

**Missing tests for:**
1. IP hash consistency (same IP -> same backend)
2. Weighted round robin with varying weights
3. Concurrent health check recovery
4. Global pool registry race conditions
5. Edge case: max_connections = 0

---

## Summary

| Category | Count |
|----------|-------|
| Verified Claims | 6 major categories confirmed |
| Unverified Claims | 1 (protocol negotiation) |
| Implementation Gaps | 5 |
| Bugs | 3 |
| Security Concerns | 3 |
| Code Improvements | 4 |
| Missing Documentation | 5 |

**Overall Assessment:** The routing architecture is well-implemented and matches the documented behavior in most areas. Key concerns are:
1. Race conditions in health checking
2. IP hash not working as documented (always falls back)
3. Missing documentation on critical paths
4. Potential division by zero edge case

# Reverse Proxy & WAF Architecture Improvement Plan

**Status**: Planning - Not Started
**Last Updated**: 2026-04-27
**Target**: MaluWAF Reverse Proxy and WAF Scalability Improvements
**Scale Target**: 500K+ requests/second with high-traffic sites

---

## Executive Summary

This plan addresses critical and high-priority issues discovered during architecture review of MaluWAF's reverse proxy and WAF components. The goal is to enable proper mesh routing for proxied sites, improve scalability for high-traffic sites in non-mesh mode, and fix performance/security issues in the request handling pipeline.

**Key findings**:
- `BackendType::Mesh` is defined but never dispatched - mesh routing is non-functional
- HTTP client cache (100 entries) is undersized for 500K rps target
- UpstreamPool exists with load balancing but site config only exposes single upstream
- Header filtering gaps in QUIC tunnel path
- Circuit breaker constants are hardcoded
- Potential deadlock from await-holding-lock pattern
- O(n) wildcard domain lookup needs optimization

---

## Issue #1: BackendType::Mesh Not Integrated (CRITICAL)

**Priority**: Critical
**Status**: Non-functional - mesh routing code paths exist but are never executed
**Risk Assessment**: High impact on mesh networking functionality, medium implementation risk

### Problem Analysis

The `BackendType::Mesh` enum variant exists in `src/router.rs:65` but is **never created** in the router and **never dispatched** in the HTTP server. The `MeshBackendPool` exists in `UnifiedServer` but is never used during request handling.

**Current state**:
- `BackendType::Mesh` enum variant: defined at `router.rs:55-66`
- `MeshBackendPool` field in `UnifiedServer`: `server/mod.rs:66`
- Builder method `with_mesh_backend_pool()`: `server/mod.rs:460-467` - exists but **NEVER called**
- `mesh_backend_pool` not passed to `handle_request()` shared state
- No dispatch case in HTTP server for `BackendType::Mesh`

**Architecture gap**: The `mesh_backend_pool` is stored on `UnifiedServer` but the HTTP request handling happens in `handle_request()` which receives `ServerSharedState`. The pool needs to be passed through or made accessible.

### Required Changes

**1. Site Configuration (`src/config/site/mod.rs`)**
```rust
// Add to SiteConfig struct (~line 67-127):
#[serde(default)]
pub mesh_routing: bool,
```

**2. BackendConfig Enum (`src/config/site/backend.rs`)**
```rust
// Add to BackendConfig enum (~line 111-142):
Mesh {
    #[serde(default)]
    upstream_id: Option<String>,
}
```

**3. Router - Location Backend (`src/router.rs:435-472`)**
```rust
// Add case in get_location_backend() for location.backend:
BackendConfig::Mesh { upstream_id } => {
    let upstream = upstream_id.unwrap_or_else(|| site_config.site.upstream.default.clone());
    RouteResult::Found(RouteTarget {
        site_id: Arc::from(site_id.as_str()),
        upstream: Arc::from(upstream.as_str()),
        site_config: site_config.clone(),
        static_handler: None,
        backend_type: BackendType::Mesh,
        backend_socket: None,
        backend_plugin: None,
        tunnel_peer: None,
        tunnel_port: None,
        serverless_function: None,
        php_location_config: None,
    })
}
```

**4. Router - Site-Level Backend (`src/router.rs:888-903`)**
```rust
// Add in route_to_target() before default Upstream fallback:
if site_config.mesh_routing {
    return RouteResult::Found(RouteTarget {
        site_id: Arc::from(site_id.as_str()),
        upstream: Arc::from(upstream.as_str()),
        site_config: site_config.clone(),
        static_handler: None,
        backend_type: BackendType::Mesh,
        backend_socket: None,
        backend_plugin: None,
        tunnel_peer: None,
        tunnel_port: None,
        serverless_function: None,
        php_location_config: None,
    });
}
```

**5. UnifiedServer Wiring (`src/server/mod.rs:894`)**
```rust
// Add mesh_backend_pool to ServerSharedState:
mesh_backend_pool: self.mesh_backend_pool.clone(),
```

**CRITICAL NOTE**: The `handle_request()` function at `http/server.rs:617` receives `ServerSharedState`. Currently `mesh_backend_pool` is NOT passed through this shared state. Options:
1. Add `mesh_backend_pool` to `ServerSharedState` (preferred - single point of access)
2. Access via `UnifiedServer::get_mesh_backend_pool()` during request handling

**6. HTTP Server Dispatch (`src/http/server.rs:2263-2313`)**
```rust
// Add in WafDecision::Pass section after AppServer dispatch (line ~2313):
if matches!(target.backend_type, crate::router::BackendType::Mesh) {
    if let Some(ref mesh_pool) = mesh_backend_pool {
        let upstream_id = target.upstream.to_string();
        if let Some(backend) = mesh_pool.select_backend(&upstream_id).await {
            let body_bytes_for_mesh: Bytes = full_body_arc.as_ref().clone();

            let mut req_builder = http::Request::builder()
                .method(method.clone())
                .uri(parts.uri.clone());
            for (name, value) in parts.headers.iter() {
                req_builder = req_builder.header(name, value);
            }
            let req = req_builder
                .body(http_body_util::Full::new(body_bytes_for_mesh))
                .unwrap_or_else(|_| http::Request::new(http_body_util::Full::new(Bytes::new())));

            match backend.proxy_request(req).await {
                Ok(response) => return Ok(response.map(|b| Full::new(b).boxed())),
                Err(e) => {
                    tracing::warn!("Mesh backend error for site {} path {}: {}", site_id, path, e);
                }
            }
        }
    }
    // Fall through to generic upstream proxy if mesh fails
}
```

**Fallback behavior**: On mesh failure, request should fall through to standard upstream proxy (treat as `BackendType::Upstream`)

### Configuration Example
```toml
# Simple approach - enables mesh routing using site upstream
[sites.my-site]
mesh_routing = true
upstream.default = "http://my-service:8000"

# Explicit approach - specific upstream ID
[sites.my-site.proxy]
backend = { type = "mesh", upstream_id = "my-service-id" }
```

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/config/site/mod.rs` | ~67-127 | Add `mesh_routing: bool` field |
| `src/config/site/backend.rs` | ~111-142 | Add `Mesh` variant |
| `src/router.rs` | ~435-472, ~888-903 | Add BackendType::Mesh creation |
| `src/server/mod.rs` | ~894 | Wire mesh_backend_pool to shared state |
| `src/http/server.rs` | ~617, ~2263-2313 | Add mesh_backend_pool param, BackendType::Mesh dispatch |

### Dependencies
- Requires `mesh_backend_pool` to be initialized and passed to UnifiedServer (currently done via `with_mesh_backend_pool()` but never called)
- Mesh transport must be initialized before mesh backend pool can function
- Verify `MeshTransportManager` initialization order in server startup

### Verification
1. Add integration test with mesh backend pool (test in `tests/integration_test.rs`)
2. Verify `BackendType::Mesh` routes correctly through mesh using `MeshBackend::proxy_request()`
3. Verify fallback to direct upstream on mesh failure
4. Test mesh backend pool selection with multiple healthy backends
5. Test circuit breaker behavior during provider failures

---

## Issue #2: HTTP Client Cache Undersized (HIGH)

**Priority**: High
**Status**: Hardcoded 100 entry cache insufficient for 500K rps target

### Problem Analysis

**Current implementation** (`src/http_client/mod.rs:55-66`):
```rust
const MAX_UPSTREAM_CLIENT_CACHE_SIZE: u64 = 100;
const UPSTREAM_CLIENT_CACHE_TTL_SECS: u64 = 300;
```

**Issues**:
1. 100 entries with potentially thousands of site/TLS combinations = cache thrashing
2. Cache key (`UpstreamClientKey`) doesn't include site/upstream ID - different sites with same TLS config share entries
3. 300s TTL causes active client eviction
4. Site config has `keepalive`, timeout fields that are defined but never used

**Impact at 500K rps**: Cache miss rate compounds - each miss may create new TCP/TLS connection

### Required Changes

**1. Increase Cache Size (`src/http_client/mod.rs:55-56`)**
```rust
const MAX_UPSTREAM_CLIENT_CACHE_SIZE: u64 = 1000;  // 10x increase
const UPSTREAM_CLIENT_CACHE_TTL_SECS: u64 = 600;  // 10 minutes
```

**2. Extend UpstreamClientKey (`src/http_client/mod.rs:27-41`)**
```rust
#[derive(Hash, PartialEq, Eq)]
struct UpstreamClientKey {
    site_id: Option<String>,           // ADD: distinguish sites
    upstream_host: Option<String>,      // ADD: distinguish upstreams
    tls_config: UpstreamTlsConfigHashable,
    pool_max_idle: usize,
    pool_idle_secs: u64,
}
```

**3. Site Config Pool Settings (`src/config/site/proxy.rs:85-125`)**
```rust
pub struct ProxyUpstreamConfig {
    pub keepalive: Option<usize>,           // IMPLEMENT: pass to create_upstream_client
    pub connect_timeout: Option<String>,   // IMPLEMENT
    pub send_timeout: Option<String>,      // IMPLEMENT
    pub read_timeout: Option<String>,      // IMPLEMENT
    pub pool_max_idle: Option<usize>,      // ADD: expose pool size
    pub pool_idle_timeout_secs: Option<u64>, // ADD: expose idle timeout
    // ... existing fields ...
}
```

**4. HTTP Server Usage (`src/http/server.rs:2562-2569`)**
```rust
let forwarding_client = site_client.as_ref().unwrap_or(&client);
let target_url = format!("{}{}", target.upstream, path);
// Use site-configured pool settings instead of hardcoded 100
```

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/http_client/mod.rs` | 55-66, 27-41 | Increase cache, extend key |
| `src/config/site/proxy.rs` | 85-125 | Implement pool config fields |
| `src/http/server.rs` | 2562-2569 | Use site pool settings |

### Verification
1. Monitor cache hit/miss rates with increased size
2. Verify connection reuse increases under load

---

## Issue #3: No Upstream Load Balancing (HIGH)

**Priority**: High
**Status**: UpstreamPool with algorithms exists but site config only exposes single URL

### Problem Analysis

**Existing infrastructure**:
- `UpstreamPool` at `src/upstream/pool.rs:256-610` - fully implemented
- Algorithms: RoundRobin, Random, LeastConnections, WeightedRoundRobin, IpHash
- Health checking, backup servers, circuit breaker
- **Note**: This is in a **separate `upstream` module**, not wired to site-level config

**Gap**: Site config (`UpstreamConfig` at `listen.rs:75-86`) only has:
```rust
pub struct UpstreamConfig {
    pub default: String,           // SINGLE URL
    pub routes: HashMap<String, String>,  // path -> single URL
    pub tunnel_mappings: HashMap<String, u16>,
}
```

**Missing**: Multiple upstream support with load balancing at site level

### Required Changes

**1. UpstreamConfig Extension (`src/config/site/listen.rs:75-86`)**
```rust
pub struct UpstreamConfig {
    #[serde(default = "default_upstream")]
    pub default: String,
    #[serde(default)]
    pub routes: HashMap<String, String>,
    #[serde(default)]
    pub servers: Vec<String>,                    // ADD: multiple upstreams
    #[serde(default)]
    pub backup_servers: Vec<String>,             // ADD: failover
    #[serde(default)]
    pub load_balance_algorithm: Option<String>,  // ADD: algorithm selection
    #[serde(default)]
    pub tunnel_mappings: HashMap<String, u16>,
}
```

**2. BackendConfig Update (`src/config/site/backend.rs:113-115`)**
```rust
pub enum BackendConfig {
    Upstream { url: Option<String> },      // KEEP: single upstream (backward compat)
    UpstreamPool {                        // ADD: multi-upstream
        urls: Vec<String>,
        backup_urls: Vec<String>,
        algorithm: Option<String>,
    },
    // ... existing variants ...
}
```

**3. Router Integration (`src/router.rs:681-717`)**
```rust
// In route_to_target() for BackendConfig::UpstreamPool:
BackendConfig::UpstreamPool { urls, backup_urls, algorithm } => {
    return RouteResult::Found(RouteTarget {
        site_id: Arc::from(site_id.as_str()),
        upstream: Arc::from(urls.first().unwrap_or(&site_config.site.upstream.default).as_str()),
        site_config: site_config.clone(),
        static_handler: None,
        backend_type: BackendType::Upstream,  // Uses UpstreamPool in proxy
        backend_socket: None,
        // ... carry pool config in site_config for proxy layer
    });
}
```

**4. ProxyServer Wiring (`src/proxy/mod.rs:226-234`)**
```rust
// Already correctly creates UpstreamPool - wire site config to it:
ProxyServer::from_config(
    &site_config.site_id(),
    servers,
    backup_servers,
    algorithm,
    // ...
)
```

### Configuration Example
```toml
[sites.my-site.upstream]
default = "http://primary:8000"  # Fallback when servers list not configured
servers = ["http://primary:8000", "http://secondary:8000", "http://tertiary:8000"]
backup_servers = ["http://backup:8000"]
load_balance_algorithm = "least_connections"  # round_robin, random, ip_hash (default: round_robin)
```

**Note**: When `servers` is empty/not specified, falls back to `default` (single upstream - backward compatible)

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/config/site/listen.rs` | 75-86 | Add servers, backup_servers, algorithm |
| `src/config/site/backend.rs` | 113-115 | Add UpstreamPool variant |
| `src/router.rs` | ~681-717 | Handle UpstreamPool backend |
| `src/proxy/mod.rs` | 226-234 | Wire pool config |
| `src/upstream/pool.rs` | 256-610 | Reference for LoadBalanceAlgorithm enum |

**Integration approach**: When `servers` list has multiple entries, proxy layer should create `UpstreamPool` and use it for request distribution. Single upstream (current behavior) works via `ProxyServer` with direct backend.

### Verification
1. Test load balancing with multiple upstreams
2. Verify health checking and failover
3. Test sticky sessions (ip_hash)

---

## Issue #4: Header Filtering Gap in QUIC Tunnel (MEDIUM - SECURITY)

**Priority**: Medium (Security Issue - should be prioritized higher due to security impact)
**Status**: QUIC tunnel path leaks Authorization, Cookie headers to upstream

### Problem Analysis

**Location**: `src/http/server.rs:2701-2709`
```rust
crate::http_client::send_request_via_quic_tunnel(
    method,
    &target_url,
    Some(&parts.headers),  // LEAKS all headers including Authorization, Cookie
    // ...
)
```

**Headers leaked**: `Authorization`, `Cookie`, `Proxy-Authorization`, custom auth tokens

### Required Changes

**1. Filter Headers Before QUIC Tunnel Call (`src/http/server.rs:2701-2709`)**
```rust
let filtered_headers = {
    let to_filter = build_headers_to_filter(
        &main_config.security.more_clear_headers,
        &target.site_config.security.more_clear_headers.iter()
            .chain(target.site_config.security_headers.more_clear_headers.iter())
            .cloned()
            .collect::<Vec<_>>(),
    );
    let mut filtered = Parts::default();
    for (name, value) in parts.headers.iter() {
        if !to_filter.contains(name) {
            filtered.insert(name, value);
        }
    }
    filtered
};

let resp = crate::http_client::send_request_via_quic_tunnel(
    method,
    &target_url,
    Some(&filtered_headers.into()),
    // ...
)
```

**2. Update QUIC Tunnel Header Filtering (`src/http_client/mod.rs:788-794`)**
```rust
// Extend to use more_clear_headers list, not just HOST/CONNECTION
```

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/http/server.rs` | 2701-2709 | Filter headers before QUIC tunnel |
| `src/http_client/mod.rs` | 788-794 | Extend QUIC header filtering |

### Verification
1. Verify Authorization header not forwarded in QUIC tunnel path
2. Verify Cookie header filtering when configured

---

## Issue #5: Circuit Breaker Constants Hardcoded (MEDIUM)

**Priority**: Medium
**Status**: Circuit breaker thresholds cannot be tuned per site/upstream

### Problem Analysis

**Location**: `src/mesh/proxy.rs:96-102`
```rust
const CIRCUIT_OPEN_THRESHOLD: u32 = 5;
const CIRCUIT_OPEN_TIMEOUT_SECS: u64 = 30;
const HALF_OPEN_MAX_REQUESTS: u32 = 3;
const CIRCUIT_CLOSE_THRESHOLD: u32 = 3;
const HEALTH_METRICS_WINDOW_SECS: u64 = 300;
const BLOCK_BROADCAST_FAILURE_THRESHOLD: u32 = 5;
const BLOCK_DURATION_SECS: u64 = 300;
```

**Industry patterns** (Envoy, Istio):
- Per-upstream override capability
- Outlier detection configuration
- Percentage-based ejection

### Required Changes

**1. CircuitBreakerConfig Struct (`src/mesh/config.rs`)**
```rust
pub struct CircuitBreakerConfig {
    #[serde(default = "default_open_threshold")]
    pub open_threshold: u32,
    #[serde(default = "default_open_timeout_secs")]
    pub open_timeout_secs: u64,
    #[serde(default = "default_half_open_max_requests")]
    pub half_open_max_requests: u32,
    #[serde(default = "default_close_threshold")]
    pub close_threshold: u32,
    #[serde(default = "default_health_metrics_window_secs")]
    pub health_metrics_window_secs: u64,
}

fn default_open_threshold() -> u32 { 5 }
fn default_open_timeout_secs() -> u64 { 30 }
// ... etc
```

**2. Wire Into MeshUpstreamConfig (`src/mesh/config.rs:639-662`)**
```rust
pub struct MeshUpstreamConfig {
    // ... existing fields ...
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}
```

**3. Wire Into ProxyUpstreamConfig (`src/config/site/proxy.rs:85-125`)**
```rust
pub struct ProxyUpstreamConfig {
    // ... existing fields ...
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}
```

**4. Update ProviderStats (`src/mesh/proxy.rs:111-218`)**
```rust
impl ProviderStats {
    fn new(config: &CircuitBreakerConfig) -> Self { ... }
    fn record_success(&mut self, config: &CircuitBreakerConfig) { ... }
    fn record_failure(&mut self, config: &CircuitBreakerConfig) { ... }
}
```

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/mesh/config.rs` | ~721-812 | Add CircuitBreakerConfig |
| `src/config/site/proxy.rs` | 85-125 | Add circuit_breaker field |
| `src/mesh/proxy.rs` | 96-218 | Accept config in ProviderStats |

### Verification
1. Test circuit opens/closes with custom thresholds
2. Verify per-upstream overrides work

---

## Issue #6: Await-Holding-Lock Potential Deadlock (MEDIUM)

**Priority**: Medium
**Status**: `parking_lot::RwLock` held during `.await` can block Tokio thread pool

### Problem Analysis

**Location**: `src/mesh/backend.rs:240-280`
```rust
#[allow(clippy::await_holding_lock)]  // Issue acknowledged but not fixed
pub async fn select_backend(&self, upstream_id: &str) -> Option<Arc<MeshBackend>> {
    let backends = self.backends.read();  // parking_lot lock acquired

    for backend in &available {
        if let Some(peer_id) = self.topology.get_best_peer_for_upstream(upstream_id).await {
            let scores = self.topology.peer_scores().read().await;  // Await while holding lock!
        }
    }
}
```

**Risk**: At 500K rps, this compounds - Tokio threads blocked by parking_lot operations

### Required Changes

**1. Refactor select_backend (`src/mesh/backend.rs:240-281`)**
```rust
pub async fn select_backend(&self, upstream_id: &str) -> Option<Arc<MeshBackend>> {
    if self.topology.is_upstream_blocked(upstream_id).await {
        return None;
    }

    // Collect data under lock, release BEFORE await
    let backend_info: Vec<(String, Arc<MeshBackend>)> = {
        let backends = self.backends.read();
        backends
            .iter()
            .filter(|b| b.is_healthy())
            .map(|b| (b.upstream_id().to_string(), b.clone()))
            .collect()
    };  // Lock dropped here

    if backend_info.is_empty() {
        return None;
    }

    let mut best: Option<(Arc<MeshBackend>, f64)> = None;

    for (upstream_id, backend) in backend_info {
        if let Some(peer_id) = self.topology.get_best_peer_for_upstream(&upstream_id).await {
            let scores = self.topology.peer_scores().read().await;  // No backends lock held
            // ... scoring logic
        }
    }
    best.map(|(b, _)| b)
}
```

**2. Fix route_request (`src/mesh/proxy.rs:786-821`)**
Same pattern - drop lock before await

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/mesh/backend.rs` | 240-281 | Drop lock before await |
| `src/mesh/proxy.rs` | 786-821 | Same fix for route_request |

### Verification
1. Remove `#[allow(clippy::await_holding_lock)]` after fix
2. Load test to verify no thread pool starvation

---

## Issue #7: Wildcard Domain O(n) Lookup (LOW)

**Priority**: Low (optimization - lower priority due to typical site count being small)
**Status**: Suffix domain matching uses linear Vec scan - inefficient at scale

### Problem Analysis

**Location**: `src/router.rs:945-949`
```rust
for (domain, site_config) in &self.suffix_domain_map {
    if clean_host.ends_with(domain.as_ref()) {
        return self.route_to_target(site_config, path);
    }
}
```

**Complexity**: O(n) where n = number of wildcard domains

**Better approach**: Label-based HashMap index (O(k) where k = labels in domain)

### Required Changes

**1. Add Label Index (`src/router.rs:29-43`)**
```rust
pub struct Router {
    // ... existing fields ...
    suffix_label_map: HashMap<Arc<str>, Vec<Arc<SiteConfig>>>,  // ADD
}
```

**2. Build Index (`src/router.rs:149-203`)**
```rust
// In build_all_maps(), populate suffix_label_map:
// For *.example.com, *.com:
// "com" -> [config1, config2]
// "example.com" -> [config1]
```

**3. O(k) Lookup (`src/router.rs:945-949`)**
```rust
fn lookup_by_suffix(&self, clean_host: &str) -> Option<Arc<SiteConfig>> {
    let labels: Vec<&str> = clean_host.split('.').collect();
    let mut suffix = String::new();
    for (i, label) in labels.iter().enumerate().rev() {
        if !suffix.is_empty() { suffix.insert(0, '.'); }
        suffix.insert_str(0, label);
        if let Some(configs) = self.suffix_label_map.get(suffix.as_str()) {
            for config in configs {
                if clean_host.ends_with(suffix.as_str()) {
                    return Some(config.clone());
                }
            }
        }
    }
    None
}
```

### Files to Modify
| File | Lines | Change |
|------|-------|--------|
| `src/router.rs` | 29-43, 149-203, 945-949 | Add label index, O(k) lookup |

### Verification
1. Benchmark lookup with many wildcard domains
2. Verify same behavior as current implementation

---

## Summary Table

| # | Issue | Priority | Files | Est. Complexity | Notes |
|---|-------|----------|-------|------------------|-------|
| 1 | BackendType::Mesh not integrated | Critical | 5 | High | Mesh routing non-functional |
| 2 | Client cache limit 100 (too small) | High | 3 | Medium | Under-sized for 500K rps |
| 3 | No upstream load balancing | High | 4 | Medium | UpstreamPool exists but unwired |
| 4 | Header filtering on slow path only | Medium-High | 2 | Low | **Security issue - elevate** |
| 5 | Circuit breaker not configurable | Medium | 3 | Medium | Hardcoded constants |
| 6 | Await-holding-lock potential deadlock | Medium | 2 | Low | Could cause thread pool issues |
| 7 | Wildcard domain O(n) lookup | Low | 1 | Medium | Optimization |

**Priority Revision Recommendation**:
- Issue 4 (Header filtering): Consider elevating to **High** due to security implications
- Implementation order (revised):
  1. Issues 1, 3 (mesh routing, load balancing) - core infrastructure
  2. Issue 4 (header filtering) - **move up due to security**
  3. Issues 2, 6 (cache sizing, await-lock) - performance
  4. Issues 5, 7 (circuit breaker, wildcard lookup) - reliability/optimization

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

---

## Relationship to Existing Plan

This plan complements the existing `plan.md` which tracks completed waves. These improvements are **deferred items** identified during architecture review that were not part of previously completed waves.

The implementation of this plan does **not** require changes to:
- Overseer/Master/Worker process architecture (already correct)
- IPC message types (already defined)
- DHT storage schema (already stable)

Focus areas:
- **Router/Proxy**: Issues 1, 3, 7
- **HTTP Server/Client**: Issues 2, 4
- **Mesh**: Issues 5, 6

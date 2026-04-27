# Edge Node Caching & Image Poison - Improvement Plan

**Status**: Planning
**Plan Number**: 17
**Last Updated**: 2026-04-27
**Implementation Phase**: To Be Scheduled

---

## Executive Summary

This plan addresses 5 issues discovered during a deep-dive review of the edge node caching and image poison capability in mesh mode. The primary goal is to ensure proper HTTP response caching with minification is functional at the edge, along with fixing several correctness and performance issues.

### Issues Addressed

| # | Issue | Severity | Action |
|---|-------|----------|--------|
| 1 | `edge_only` flag is defined but never enforced | High | Implement role check before poisoning |
| 2 | HTTP response caching incomplete - `proxy_cache` not wired up | High | Wire up `proxy_cache` in `MeshProxy` |
| 3 | Direct DHT lookup in `transform_response()` bypasses cache | Medium | Use `tm.get_proxy_cache_preferences_for_site()` |
| 4 | Non-mesh mode uses static config (expected behavior) | N/A | Document as intended design |
| 5 | `MeshTransportManager` caches not invalidated on updates | Medium | Add invalidation methods |

---

## Architecture Overview

### Current Caching Architecture

```
MeshProxy (src/mesh/proxy.rs)
├── policy_cache: Cache<String, CachedPolicy>     # Routing policy (provider selection)
├── transform_cache: TieredTransformCache          # Body transforms (minified/compressed/poisoned)
├── proxy_cache: Arc<RwLock<Option<ProxyCache>>>   # Full HTTP response caching (NOT WIRED)
└── record_store: Arc<RwLock<Option<RecordStoreManager>>>  # DHT access

ProxyServer (src/proxy/mod.rs) - Reference Implementation
├── cache: Option<Arc<ProxyCache>>                 # Full HTTP response caching (FUNCTIONAL)
├── cache_key_builder: Option<CacheKeyBuilder>      # Cache key construction
└── Uses: cache.get() before request, cache.insert() after response
```

### Target Architecture

```
MeshProxy (src/mesh/proxy.rs)
├── policy_cache: Cache<String, CachedPolicy>        # Routing policy (existing)
├── transform_cache: TieredTransformCache           # Body transforms (existing, works correctly)
├── proxy_cache: Arc<RwLock<Option<ProxyCache>>>    # Full HTTP response caching (TO WIRE)
├── cache_key_builder: Option<CacheKeyBuilder>      # Cache key construction (TO ADD)
└── record_store: Arc<RwLock<Option<RecordStoreManager>>>  # DHT access (existing)
```

---

## Detailed Implementation

### Phase 1: Critical Fixes

#### Issue 1: `edge_only` Flag Enforcement

**Problem**: The `edge_only` flag in `SiteImagePoisonConfig` is defined, published to DHT, and retrieved - but **never checked** before applying image poisoning.

**Location**: `src/mesh/proxy.rs:1469-1497`

**Current Code** (line 1485-1493):
```rust
if !whitelisted {
    transformed = self
        .apply_image_poisoning(
            transformed,
            upstream_id,
            last_modified.clone(),
            image_poison_config.as_ref(),
        )
        .await;
}
```

**Fix Required**: Add role check before line 1485:
```rust
if !whitelisted {
    // Check edge_only flag combined with current node role
    let should_poison = image_poison_config
        .as_ref()
        .and_then(|c| c.edge_only)
        .map(|edge_only| {
            // If edge_only=true, only apply if current node is edge
            // If edge_only=false/unset, apply on all nodes
            !edge_only || self.config.role.is_edge()
        })
        .unwrap_or(true);  // Default: apply poisoning

    if should_poison {
        transformed = self
            .apply_image_poisoning(
                transformed,
                upstream_id,
                last_modified.clone(),
                image_poison_config.as_ref(),
            )
            .await;
    }
}
```

**Files to Modify**:
- `src/mesh/proxy.rs` - Add role check in `transform_response()` around line 1485

---

#### Issue 2: Wire Up `proxy_cache` in `MeshProxy`

**Problem**: `MeshProxy.proxy_cache` is initialized (line 333, 347) and preferences are applied via `set_proxy_cache_preferences()` (line 356-390), but **never used** for actual caching. No `.get()` or `.insert()` calls exist in the request path.

**Reference Implementation**: `src/proxy/mod.rs:529-619` shows how `ProxyServer` uses `ProxyCache`:
1. Build cache key from request (method, URI, headers, site_id)
2. Call `cache.get(&cache_key).await` before forwarding
3. On cache miss, forward request
4. Call `cache.insert(cache_key, body, status, headers, max_age)` if response is cacheable

**Implementation Steps**:

**Step 2.1**: Add `cache_key_builder` field to `MeshProxy` struct

**Location**: `src/mesh/proxy.rs:58-73`

**Change**:
```rust
#[derive(Clone)]
pub struct MeshProxy {
    // ... existing fields ...
    transform_cache: TieredTransformCache,
    proxy_cache: Arc<RwLock<Option<ProxyCache>>>,
    cache_key_builder: Arc<RwLock<Option<CacheKeyBuilder>>>,  // ADD THIS
}
```

**Step 2.2**: Initialize `cache_key_builder` in `MeshProxy::new()`

**Location**: `src/mesh/proxy.rs:314-349`

**Change**: After initialization, if `cache_config` exists, create `CacheKeyBuilder`:
```rust
let cache_key_builder = cache_config.as_ref().map(|cc| {
    // Use ProxyCacheSettings default pattern: "$scheme$request_method$host$request_uri"
    let pattern = cc.key.clone().unwrap_or_else(|| "$scheme$request_method$host$request_uri".to_string());
    let vary_by = cc.vary_by.clone().unwrap_or_else(|| vec!["Accept-Encoding".to_string()]);
    Arc::new(RwLock::new(Some(CacheKeyBuilder::new(pattern, vary_by))))
}).unwrap_or_else(|| Arc::new(RwLock::new(None)));

Self {
    // ... existing fields ...
    cache_key_builder,
}
```

**Step 2.3**: Add caching logic in `route_request()` (not `proxy_to_peer_with_fallback()`)

**Important Realization**: Cache lookup must happen in `route_request()` (line 787), NOT in `proxy_to_peer_with_fallback()` (line 928). This is because:
- `route_request()` is the main entry point that handles both cached and uncached provider paths
- `proxy_to_peer_with_fallback()` handles multiple providers but doesn't return until a success
- We need to check cache BEFORE any proxying happens

**Location**: `src/mesh/proxy.rs:787-925`

**Logic Flow** in `route_request()`:
1. After line 791 (timeout setup), check `proxy_cache` for hit
2. If hit, return cached response immediately (skip all provider logic)
3. If miss, proceed with existing flow (get cached/uncached provider, call proxy_to_peer_with_fallback)
4. On successful response (needs new code path), call `cache.insert()` if cacheable

**Key Code Locations**:
- Cache lookup: After line 793, before line 795 (the loop)
- Cache insert: After `transform_response()` in `route_request()` return path (around line 925)

**Critical observation**: `route_request()` returns at multiple points:
- Line 802: Request timeout
- Line 827: Upstream blocked
- Line 867, 874: Tier claim validation failed
- Line 878: Cached provider path - goes to `proxy_to_peer_with_fallback()`
- Line 925: Uncached provider path - goes to `proxy_to_peer_with_fallback()`

For proper caching, we need to intercept the response after `proxy_to_peer_with_fallback()` returns. This means wrapping the call around line 878 and 925.

**Important**: `proxy_cache` is `Arc<RwLock<Option<ProxyCache>>>` - uses **sync** `.read()`/`.write()`, not async. See `set_proxy_cache_preferences()` at line 360 which uses `self.proxy_cache.write()` synchronously.

**Recommended structure**:
```rust
pub async fn route_request(...) -> Result<...> {
    // 1. Cache check (early return on hit)
    {
        let cache_guard = self.proxy_cache.read().unwrap();
        if let Some(cache) = cache_guard.as_ref() {
            if let Some(cache_key) = self.build_proxy_cache_key(...) {
                if let Some(cached) = cache.get(&cache_key).await {
                    // Return cached response, preserving status code
                    return Ok(self.build_cached_response(cached));
                }
            }
        }
    }

    // 2. Existing provider selection logic
    let req = ...;

    // 3. Proxy with fallback
    let resp = self.proxy_to_peer_with_fallback(upstream_id, providers, req).await?;

    // 4. Check if response is cacheable, insert if so
    {
        let cache_guard = self.proxy_cache.read().unwrap();
        if let Some(cache) = cache_guard.as_ref() {
            if self.should_cache_response(&resp) {
                cache.insert(cache_key, body, status, headers, max_age).await;
            }
        }
    }

    Ok(resp)
}
```

**Cache Key Construction** (needs new helper):
```rust
fn build_proxy_cache_key(
    &self,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    upstream_id: &str,
) -> Option<CacheKey> {
    let builder = self.cache_key_builder.read().unwrap();
    builder.as_ref().map(|b| {
        b.build(
            "http",  // or from request
            method,
            upstream_id,  // or from headers
            uri,
            headers,
            upstream_id,
        )
    })
}
```

**Step 2.4**: Add `should_cache_response()` and `build_cached_response()` helpers

**References**:
- `src/proxy/mod.rs:782` - `build_cached_response()` returns `Response<bytes::Bytes>` (not hyper type)
- `src/proxy/cache.rs:44` - `build_cached_response_impl()` is the implementation
- `src/proxy/mod.rs:596` - `is_response_cacheable()` checks status, method, headers

**Important Type Difference**: `ProxyCacheEntry` stores `Response<bytes::Bytes>` but `MeshProxy.route_request()` returns `Response<BoxBody<Bytes, Infallible>>`. Need to convert between these types.

```rust
// Helper to build cached response with proper hyper types
fn build_cached_response(&self, entry: &ProxyCacheEntry) -> Response<BoxBody<Bytes, Infallible>> {
    use http_body_util::Full;
    use bytes::Bytes;

    let mut builder = http::Response::builder().status(entry.status);
    for (name, value) in entry.headers.iter() {
        builder = builder.header(name, value);
    }
    // Add Cache-Control header based on entry freshness
    let body = Full::new(Bytes::from(entry.content.clone())).boxed();
    builder.body(body).unwrap_or_else(|_| {
        Response::new(http_body_util::Full::new(Bytes::new()).boxed())
    })
}
```

Similar logic needed in `MeshProxy` to determine if response should be cached based on:
- Status code (200, 203, 204, 300, 301, 404, etc.)
- Request method (GET, HEAD only by default)
- Response headers (no Cache-Control: no-store, etc.)

**Step 2.5**: Update `set_proxy_cache_preferences()` signature (no changes needed)

**Observation**: `ProxyCachePreferences` (line 1129-1138) does NOT include `key_pattern` or `vary_by` fields - only settings like `enable`, `inactive`, `valid_status`, etc. The `CacheKeyBuilder` pattern is set at initialization from `ProxyCacheConfig.key` (site config) and is not updated via DHT preference sync.

**Files to Modify**:
- `src/mesh/proxy.rs` - Add field, initialization, cache get/insert logic

---

### Phase 2: Performance Fixes

#### Issue 3: Use Cached Config Lookup for Preferences

**Problem**: `transform_response()` at lines 1279-1289 does direct DHT lookup for proxy_cache_preferences, bypassing the LRU cache in `MeshTransportManager`.

**Current Code** (lines 1279-1289):
```rust
if let Some(ref record_store) = tm.get_record_store() {
    let prefs_key =
        crate::mesh::dht::keys::DhtKey::upstream_proxy_cache_preferences(upstream_id);
    if let Some(record) = record_store.get_record(&prefs_key.as_str()) {
        if let Ok(prefs) = serde_json::from_slice::<
            crate::mesh::protocol::ProxyCachePreferences,
        >(&record.value)
        {
            self.set_proxy_cache_preferences(&prefs);
        }
    }
}
```

**Fix Required**: Replace with cached lookup:
```rust
if let Some(prefs) = tm.get_proxy_cache_preferences_for_site(upstream_id).await {
    self.set_proxy_cache_preferences(&prefs);
}
```

This uses:
- LRU cache with 300s TTL
- Stampede protection via inflight mutex
- Metrics tracking (cache hits/misses)

**Files to Modify**:
- `src/mesh/proxy.rs:1279-1289` - Replace direct DHT lookup

---

#### Issue 5: Add Cache Invalidation to `MeshTransportManager`

**Problem**: 5 caches in `MeshTransportManager` are never invalidated on config updates, serving stale data for up to 5 minutes.

**Affected Caches**:
| Cache | Type | TTL |
|-------|------|-----|
| `image_poison_cache` | LruCache | 300s |
| `image_protection_cache` | LruCache | 300s |
| `compression_cache` | LruCache | 300s |
| `minification_cache` | LruCache | 300s |
| `proxy_cache_preferences_cache` | LruCache | 300s |

**Implementation**: Add invalidation methods to `MeshTransportManager`

**Location**: `src/mesh/transports/manager.rs`

**New Methods**:
```rust
impl MeshTransportManager {
    pub fn invalidate_image_poison_config(&self, site_id: &str) {
        let mut cache = self.image_poison_cache.write();
        cache.remove(&site_id.to_string());  // Note: verify LruCache API (remove vs pop)
    }

    pub fn invalidate_image_protection_config(&self, site_id: &str) {
        let mut cache = self.image_protection_cache.write();
        cache.remove(&site_id.to_string());
    }

    pub fn invalidate_compression_config(&self, site_id: &str) {
        let mut cache = self.compression_cache.write();
        cache.remove(&site_id.to_string());
    }

    pub fn invalidate_minification_config(&self, site_id: &str) {
        let mut cache = self.minification_cache.write();
        cache.remove(&site_id.to_string());
    }

    pub fn invalidate_proxy_cache_preferences(&self, site_id: &str) {
        let mut cache = self.proxy_cache_preferences_cache.write();
        cache.remove(&site_id.to_string());
    }

    pub fn invalidate_all_for_site(&self, site_id: &str) {
        self.invalidate_image_poison_config(site_id);
        self.invalidate_image_protection_config(site_id);
        self.invalidate_compression_config(site_id);
        self.invalidate_minification_config(site_id);
        self.invalidate_proxy_cache_preferences(site_id);
    }
}
```

**Note**: LRU cache API uses `remove()` not `pop()`. Verify during implementation.

**Call Sites**: In `src/admin/state.rs:557`, add call to `MeshTransportManager::invalidate_all_for_site()` when site config updates.

**Files to Modify**:
- `src/mesh/transports/manager.rs` - Add invalidation methods
- `src/admin/state.rs:557` - Call invalidation on config sync

---

### Phase 3: Documentation

#### Issue 4: Document Non-Mesh Mode Behavior

**Finding**: When not in mesh mode, the origin acts as its own edge. Static `site_config` is used directly instead of DHT-based preference forwarding. This is **correct intended behavior**.

**Documentation Required**: Add comments to relevant code paths and update plan.md.

**Comment Location**: `src/http/server.rs:2878` (start of non-mesh response transform)
```rust
// Non-mesh mode: Origin acts as its own edge.
// Static site_config is used directly - no DHT-based preference forwarding.
// Cache preferences from site_config.proxy.cache are applied at startup.
// Dynamic preference updates via DHT are mesh-only features.
```

---

## Implementation Order

| Phase | Issue | Description | Complexity |
|-------|-------|-------------|------------|
| 1.1 | Issue 1 | Fix `edge_only` enforcement | Low |
| 1.2 | Issue 2 | Wire up `proxy_cache` in MeshProxy | High |
| 2.1 | Issue 3 | Use cached config lookup | Low |
| 2.2 | Issue 5 | Add cache invalidation | Medium |
| 3.1 | Issue 4 | Document non-mesh mode | Low |

---

## Files Requiring Changes

| File | Changes |
|------|---------|
| `src/mesh/proxy.rs` | Issue 1: Add edge_only role check; Issue 2: Add cache_key_builder field, initialization, cache get/insert; Issue 3: Use cached config lookup |
| `src/mesh/transports/manager.rs` | Issue 5: Add invalidation methods |
| `src/admin/state.rs` | Issue 5: Call invalidation on config sync |
| `src/http/server.rs` | Issue 4: Add non-mesh mode documentation comment |

---

## Testing Requirements

### Issue 1: `edge_only` Enforcement
- Unit test: Verify poisoning skipped when `edge_only=true` and node is not edge
- Unit test: Verify poisoning happens when `edge_only=true` and node is edge
- Unit test: Verify poisoning happens when `edge_only=false/unset` on any node

### Issue 2: `proxy_cache` Wiring
- Integration test: Cache hit returns correct status code (not always 200)
- Integration test: Cache miss inserts into proxy_cache
- Integration test: Stale-while-revalidate triggers correctly
- Integration test: Cache key varies correctly by method, URI, vary headers

### Issue 3: Cached Config Lookup
- Verify `transform_response()` uses cached lookup
- Verify cache metrics (hits/misses) are updated

### Issue 5: Cache Invalidation
- Unit test: `invalidate_all_for_site()` clears all 5 caches
- Integration test: Config update reflects immediately (no 5min TTL delay)

---

## Verification Commands

```bash
# Verify tests compile (not just cargo check)
cargo test --lib --no-run

# Run targeted tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Check specific module compiles
cargo check --lib -p maluwaf
```

---

## Dependencies

- `ProxyCache` and `CacheKeyBuilder` from `src/proxy_cache/` module
- `MeshTransportManager::get_proxy_cache_preferences_for_site()` (existing)
- `SiteImagePoisonConfig.edge_only` field (existing)

---

## Risk Assessment

| Issue | Risk | Mitigation |
|-------|------|------------|
| Issue 1 | Low - Simple role check | Add unit tests |
| Issue 2 | Medium - New cache path may have bugs | Extensive integration testing |
| Issue 3 | Low - Simple refactor | Verify metrics still work |
| Issue 5 | Low - Simple invalidation methods | Add unit tests |

---

## Open Questions

1. **Cache key pattern for mesh**: Should `CacheKeyBuilder` use the same default pattern as `ProxyServer` (`{method}:{uri}`) or a mesh-specific pattern including `upstream_id`?

2. **DHT caching of full responses**: The `transform_cache` stores transformed content in DHT. Should `proxy_cache` also store in DHT for distributed caching, or stay local-only like `ProxyServer`?

3. **Interaction between caches**: When `proxy_cache` has a hit, should `transform_cache` still be checked? Or vice versa? What's the expected cache hierarchy?
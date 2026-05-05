# Edge Node Caching & Image Poison Review - Improvement Plan

**Status**: Under Review
**Last Updated**: 2026-04-27
**Review Source**: `src/mesh/proxy.rs`, `src/http/server.rs`, `src/mesh/transports/manager.rs`

---

## Executive Summary

After deep investigation, 5 significant issues were identified in the edge node caching and image poison capability:

| # | Issue | Severity | Impact |
|---|-------|----------|--------|
| 1 | `edge_only` flag is defined but never enforced | High | Image poisoning applied when it shouldn't be |
| 2 | `MeshProxy.proxy_cache` is populated but never used | High | Dynamic cache preferences are stored but have no effect |
| 3 | Direct DHT lookup in `transform_response()` bypasses cache | Medium | Performance degradation at scale (1000K req/sec) |
| 4 | Non-mesh mode completely bypasses preference forwarding | Medium | Origin-as-edge lacks dynamic config updates |
| 5 | `MeshTransportManager` caches not invalidated on config updates | Medium | Stale config served for up to 5 minutes |

---

## Detailed Findings

### Issue 1: `edge_only` Flag Never Enforced

**Location**: `src/mesh/proxy.rs:1469-1497`

**Problem**: The `edge_only` flag in `SiteImagePoisonConfig` is:
- Defined at `src/config/site/misc.rs:37`
- Published to DHT at `src/mesh/transport.rs:986`
- Retrieved from DHT at `src/mesh/transports/manager.rs:1056`

But it is **never checked** in the poisoning decision logic.

**Current behavior**:
```rust
// src/mesh/proxy.rs:1469
if let Some(ref config) = image_protection {
    if config.enabled.unwrap_or(false) && content_type.starts_with("image/") {
        // ... size check, whitelist check ...
        if !whitelisted {
            transformed = self.apply_image_poisoning(...).await;  // edge_only NOT checked!
        }
    }
}
```

**Expected behavior**: When `edge_only=true`, only edge nodes should apply poisoning. Global/origin nodes should skip.

**Fix required**: Check `image_poison_config.edge_only` combined with current node role (`self.config.role.is_edge()`) before line 1485.

---

### Issue 2: `MeshProxy.proxy_cache` is Dead Storage

**Location**: `src/mesh/proxy.rs:72`, `src/mesh/proxy.rs:356-390`

**Problem**: `MeshProxy` has a `proxy_cache: Arc<RwLock<Option<ProxyCache>>>` field that:
1. Gets populated via `set_proxy_cache_preferences()` (line 1287)
2. Is **never read** for any caching decision

**Evidence**:
- `set_proxy_cache_preferences()` writes to `proxy_cache` (line 360)
- No code path calls `.get()` or any lookup on this cache
- Compare to `ProxyServer` (`src/proxy/mod.rs:542`) which does `cache.get(&cache_key).await`

**Current architecture**:
```
MeshProxy.proxy_cache --written via set_proxy_cache_preferences()--> NEVER READ
```

**Actual caching in MeshProxy**:
| Cache | Type | Used? |
|-------|------|-------|
| `policy_cache` | `Cache<String, CachedPolicy>` | YES - for routing |
| `transform_cache` | `TieredTransformCache` | YES - for body transforms |

**Missing**: Full HTTP response caching with headers, status codes, stale-while-revalidate, etc.

**Fix required**: Either:
1. Implement actual cache lookups in `MeshProxy` using `proxy_cache`, OR
2. Remove the dead `proxy_cache` field if full caching isn't needed in mesh mode

---

### Issue 3: Redundant DHT Lookup Bypassing Cache

**Location**: `src/mesh/proxy.rs:1279-1289`

**Problem**: `transform_response()` fetches proxy_cache_preferences via direct DHT lookup:

```rust
if let Some(ref record_store) = tm.get_record_store() {
    let prefs_key = crate::mesh::dht::keys::DhtKey::upstream_proxy_cache_preferences(upstream_id);
    if let Some(record) = record_store.get_record(&prefs_key.as_str()) {  // Direct DHT!
        // ...
    }
}
```

**But** `MeshTransportManager` has a dedicated LRU cache at line 127:
```rust
let proxy_cache_preferences_cache =
    LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 1000);
```

**This cache is never used** - the direct DHT lookup bypasses it.

**Contrast with other 4 configs** at lines 1274-1277:
```rust
let image_protection = tm.get_image_protection_for_site(upstream_id).await;  // Uses cache
let image_poison_config = tm.get_image_poison_config_for_site(upstream_id).await;  // Uses cache
let compression = tm.get_compression_for_site(upstream_id).await;  // Uses cache
let minification = tm.get_minification_for_site(upstream_id).await;  // Uses cache
// But proxy_cache_preferences uses direct DHT lookup!
```

**Performance impact at 1000K req/sec**:
- Every response triggers synchronous DHT `get_record()` call
- No caching benefit - O(n) per request
- At 1000K req/sec, even 1-2μs per lookup = 1000K-2M ops/sec with no amortization

**Fix required**: Use `tm.get_proxy_cache_preferences_for_site(upstream_id).await` instead of direct DHT lookup.

---

### Issue 4: Non-Mesh Mode Bypasses Preference Forwarding

**Location**: `src/http/server.rs:2878-2934` vs `src/mesh/proxy.rs:1256-1290`

**Problem**: When NOT in mesh mode (origin acts as its own edge):

| Aspect | Mesh Mode | Non-Mesh Mode |
|--------|-----------|---------------|
| Image poison config source | DHT via `mt.get_image_poison_config_for_site()` | `site_config.image_poison` directly |
| Poisoned image caching | DHT-based (`PoisonedImage{site_id, hash}`) | In-memory `IMAGE_POISON_CACHE` |
| Minification/Compression | DHT via `mt.get_*()` methods | `site_config.r#static` directly |
| Proxy cache preferences | Dynamic DHT-based `set_proxy_cache_preferences()` | **MISSING** - static config only |
| `edge_only` check | Yes (but broken - see Issue 1) | No (not checked) |

**In mesh mode** (`src/mesh/proxy.rs:1279-1290`):
```rust
// Dynamic preference update from DHT
if let Some(record) = record_store.get_record(&prefs_key.as_str()) {
    if let Ok(prefs) = serde_json::from_slice::<ProxyCachePreferences>(&record.value) {
        self.set_proxy_cache_preferences(&prefs);  // <-- Dynamic update works
    }
}
```

**In non-mesh mode**: No equivalent mechanism exists.

**Fix required**: Implement similar preference forwarding for non-mesh mode, or document that mesh mode is required for dynamic cache preference updates.

---

### Issue 5: MeshTransportManager Caches Not Invalidated

**Location**: `src/http/server.rs:92`, `src/mesh/transports/manager.rs:90-91`

**Problem**: Two separate caches exist for image poisoning:

| Cache | Type | TTL | Invalidated? |
|-------|------|-----|--------------|
| `IMAGE_POISON_CACHE` (`http/server.rs:85`) | moka `Cache<String, Vec<u8>>` | 1 hour | Yes - via `invalidate_image_poison_cache_for_site()` |
| `image_poison_cache` (`transports/manager.rs:90`) | LruCache `SiteImagePoisonConfig` | 5 min | **NO** |

**When site config updates** (`admin/state.rs:557`):
```rust
crate::http::server::invalidate_image_poison_cache_for_site(&site_id);
```

This only clears HTTP server's cache. `MeshTransportManager`'s caches are **never invalidated**.

**All 5 MeshTransportManager caches have this gap**:

| Cache | Invalidated? | TTL |
|-------|-------------|-----|
| `image_poison_cache` | **NO** | 300s |
| `image_protection_cache` | **NO** | 300s |
| `compression_cache` | **NO** | 300s |
| `minification_cache` | **NO** | 300s |
| `proxy_cache_preferences_cache` | **NO** | 300s |

**Stale data scenario**:
1. Site config updated (poison level changes)
2. HTTP server cache cleared
3. New requests hit `MeshTransportManager.get_image_poison_config_for_site()`
4. DHT is updated, but local LruCache serves **old config for up to 300 seconds**

**Fix required**: Add invalidation method to `MeshTransportManager` and call it when site config updates.

---

## Recommended Implementation Order

### Phase 1: Critical Fixes

1. **Issue 1 - Fix `edge_only` enforcement** (High priority - security correctness)
   - Location: `src/mesh/proxy.rs:1485`
   - Add role check before applying image poisoning

2. **Issue 2 - Investigate `proxy_cache` intent** (High priority - architectural clarity)
   - Determine if mesh proxy caching was intended but never completed
   - Either implement proper caching or remove dead code

### Phase 2: Performance Fixes

3. **Issue 3 - Use cached config lookup** (Medium priority - performance at scale)
   - Location: `src/mesh/proxy.rs:1279-1289`
   - Replace direct DHT with `tm.get_proxy_cache_preferences_for_site()`

4. **Issue 5 - Add cache invalidation** (Medium priority - config freshness)
   - Add `invalidate_*()` methods to `MeshTransportManager`
   - Call on site config updates

### Phase 3: Architecture Improvements

5. **Issue 4 - Document non-mesh mode limitations** (Medium priority)
   - Either implement missing preference forwarding in non-mesh mode
   - Or clearly document mesh mode is required for dynamic preferences

---

## Verification Commands

```bash
# Verify tests compile
cargo test --lib --no-run

# Run targeted tests
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Check specific module compiles
cargo check --lib -p synvoid
```

---

## Files Requiring Changes

| File | Changes |
|------|---------|
| `src/mesh/proxy.rs` | Fix edge_only check, use cached config lookup, investigate proxy_cache usage |
| `src/mesh/transports/manager.rs` | Add cache invalidation methods |
| `src/admin/state.rs` | Call MeshTransportManager invalidation on config sync |
| `src/http/server.rs` | Consider unified invalidation across both cache types |
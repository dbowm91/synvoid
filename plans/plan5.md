# MaluWAF Edge Node Caching and Image Poison Implementation Plan

**Last updated**: 2026-04-19
**Status**: PLANNING

---

## Overview

This plan enables edge nodes to receive and apply caching preferences and image poison configuration from origin nodes, and to cache responses locally.

**Target Architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Mesh Mode                              │
├─────────────────────────────────────────────────────────────┤
│                                                      │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐        │
│  │ Edge 1 │     │ Edge 2 │     │ Edge N │        │
│  │        │     │        │     │        │        │
│  │ Cache: │     │ Cache: │     │ Cache: │        │
│  │ - HTTP │     │ - HTTP │     │ - HTTP │        │
│  │ - Static│     │ - Static│     │ - Static│        │
│  │ - Img  │     │ - Img  │     │ - Img  │        │
│  │   Poison   │     │   Poison   │     │   Poison   │        │
│  └────┬────┘     └────┬────┘     └────┬────┘        │
│       │               │               │             │
│       │   SiteConfigSync (prefs + cache_ttl)            │
│       │   + DHT image_poison config                    │
│       ▼               ▼               ▼             │
│  ┌─────────────────────────────────┐                │
│  │         Origin Node(s)           │                │
│  │  (static files, image poison)  │                │
│  └───────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│               Non-Mesh (Standalone) Mode                    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐                │
│  │         Origin Node                 │                │
│  │  (acts as its own edge)          │                │
│  │                               │                │
│  │  - Local static files cache     │                │
│  │  - Local image poison          │                │
│  │  - Local proxy cache          │                │
│  └───────────────────────────────┘                │
│                                                     │
│  Simplification: Uses local config directly            │
└─────────────────────────────────────────────────────────────┘
```

---

## Current State Analysis

### What's Implemented

| Component | Location | Status | Notes |
|-----------|----------|--------|-------|
| `ProxyCachePreferences` message | `src/mesh/protocol.rs:1037-1061` | ✅ Defined | In `SiteConfigSync` message |
| `SiteConfigSync` broadcast | `src/mesh/transport.rs:1027-1126` | ✅ Implemented | Sends to origins only |
| `ImagePoisonConfig` DHT | `src/mesh/transports/manager.rs:979-1022` | ✅ Working | Edges fetch from DHT |
| Image poison application | `src/mesh/proxy.rs:1297-1303` | ✅ Working | Applied to proxied images |
| Static file TTL | `src/static_files/mod.rs:534-541` | ✅ Local | Uses local config |
| Proxy cache | `src/proxy/mod.rs:515-591` | ✅ Local | Uses local config |

### Current Gaps

| Gap | Location | Impact | Priority |
|-----|----------|--------|----------|
| **Config targets origins only** | `src/mesh/transport.rs:1055-1058` | Edges never receive preferences | HIGH |
| **Preferences discarded** | `src/admin/state.rs:500` | Received prefs not applied | HIGH |
| **No edge HTTP caching** | N/A | All requests proxy to origin | HIGH |
| **No edge static caching** | N/A | Static files proxied, not cached | MEDIUM |
| **Static cache TTL not synced** | N/A | No TTL forwarded to edges | MEDIUM |

### Current Flow

```
Admin updates site config
         │
         ▼
broadcast_site_config_to_origins() [transport.rs:1027]
         │    (filters to origins only!)
         ▼
SiteConfigSync sent to origins
         │
         ▼
state.rs receives but discards _proxy_cache_preferences [line 500]
         │
         ▼
Config written to disk, preferences lost
```

---

## Status Legend

- 📋 PLANNING - Not yet started
- 🔄 IN PROGRESS - Actively being implemented
- ✅ COMPLETED - Fully implemented and verified
- ⚠️ PARTIAL - Some features added, gap remains
- ❌ BLOCKED - Requires external dependency

---

## Phase 1: Core Infrastructure Fixes

**Goal**: Fix the fundamental config forwarding to edges and apply received preferences.

**Status**: 📋 PLANNING

### 1.1 Add Edge-Targeted Config Broadcast

Add a new function to broadcast site config to edge nodes:

```rust
// In src/mesh/transport.rs
pub async fn broadcast_site_config_to_edges(
    &self,
    site_id: &str,
    config_json: &str,
    config_version: u64,
    cache_preferences: Option<ProxyCachePreferences>,
    static_cache_ttl: Option<u64>,
    image_poison_config: Option<SiteImagePoisonConfig>,
) -> Result<(usize, usize), String> {
    // Find all edge nodes for this site
    let edges = self.topology.find_all_edges_for_site(site_id).await;
    
    // Broadcast SiteConfigSync with preferences to each edge
    for edge_node_id in edges {
        let message = MeshMessage::SiteConfigSync {
            site_id: site_id.into(),
            config_version,
            config_json: config_json.into(),
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id().into(),
            signature: sign_message(...),
            signer_public_key: get_public_key(),
            proxy_cache_preferences: cache_preferences.clone(),
            static_cache_ttl,          // NEW
            image_poison_config: ..., // NEW
        };
        self.send_datagram_to_peer(&edge_node_id, &message).await;
    }
}
```

**File Changes**:
- `src/mesh/transport.rs` - Add `broadcast_site_config_to_edges()`
- `src/mesh/topology.rs` - Add `find_all_edges_for_site()`
- `src/mesh/protocol.rs` - Add `static_cache_ttl`, `image_poison_config` to `SiteConfigSync`

**Estimated effort**: 4-6 hours

### 1.2 Apply Received Preferences

Fix the discard of received preferences in state.rs:

```rust
// In src/admin/state.rs
tokio::spawn(async move {
    while let Some((site_id, config_json, proxy_cache_preferences, static_cache_ttl, image_poison_config)) = rx.recv().await {
        // Write config to disk
        tokio::fs::write(&config_path, &config_json).await;
        
        // NEW: Apply preferences to cache state
        if let Some(prefs) = proxy_cache_preferences {
            let mut cache_settings = state.proxy_cache_settings.write();
            *cache_settings = Some(prefs);
        }
        
        // NEW: Apply static cache TTL
        if let Some(ttl) = static_cache_ttl {
            let mut static_ttl = state.static_cache_ttl.write();
            *static_ttl = Some(ttl);
        }
        
        // NEW: Apply image poison config
        if let Some(cfg) = image_poison_config {
            let mut img_poison = state.image_poison_config.write();
            *img_poison = Some(cfg);
        }
        
        // Reload site config
        config.load_site(config_path).await;
    }
});
```

**File Changes**:
- `src/admin/state.rs` - Apply received preferences to state
- Add new fields to `AdminState`: `proxy_cache_settings`, `static_cache_ttl`, `image_poison_config`

**Estimated effort**: 2-3 hours

### 1.3 Protocol Message Update

Update the `SiteConfigSync` message to include new fields:

```rust
// In src/mesh/protocol.rs
pub struct SiteConfigSync {
    pub request_id: String,
    pub site_id: String,
    pub config_version: u64,
    pub config_json: String,
    pub timestamp: i64,
    pub source_node_id: String,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub proxy_cache_preferences: Option<ProxyCachePreferences>,  // EXISTS
    // NEW FIELDS:
    pub static_cache_ttl: Option<u64>,                         // NEW
    pub image_poison_config: Option<SiteImagePoisonConfig>,       // NEW (from config/site/misc.rs)
}
```

**File Changes**:
- `src/mesh/protocol.rs` - Add new fields to `SiteConfigSync`

**Estimated effort**: 1-2 hours

---

## Phase 2: Edge HTTP Response Caching

**Goal**: Edge nodes cache HTTP responses from origin with configurable TTL.

**Status**: 📋 PLANNING

### 2.1 Edge Cache Implementation

Create a new edge cache for HTTP responses:

```rust
// New file: src/mesh/edge_cache.rs

pub struct EdgeCache {
    cache: moka::sync::Cache<String, EdgeCacheEntry>,
    max_capacity: u64,
    default_ttl_secs: u64,
}

pub struct EdgeCacheEntry {
    pub body: Bytes,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_encoding: Option<String>,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub cached_at: i64,
}

impl EdgeCache {
    pub fn get(&self, key: &str) -> Option<EdgeCacheEntry> {
        self.cache.get(key)
    }
    
    pub fn insert(&self, key: String, entry: EdgeCacheEntry, ttl_secs: Option<u64>) {
        let ttl = Duration::from_secs(ttl_secs.unwrap_or(self.default_ttl_secs));
        self.cache.insert(key, entry, ttl, ttl);
    }
    
    pub fn compute_key(&self, request: &Request<()>, upstream_id: &str) -> String {
        // Content-addressable: upstream_id + method + path + query + content_hash
        let mut hasher = Sha256::new();
        hasher.update(upstream_id);
        hasher.update(request.uri().path());
        hasher.update(request.uri().query().unwrap_or(""));
        hex::encode(hasher.finalize())
    }
    
    pub fn should_cache(&self, response: &Response<()>) -> bool {
        // Only cache GET responses with 2xx status
        // Respect Cache-Control: no-cache, private
        // Use max-age if present
    }
}
```

**File Changes**:
- `src/mesh/edge_cache.rs` - NEW file

**Estimated effort**: 4-6 hours

### 2.2 Cache Key Computation

Use content-addressable cache keys:

```rust
// Cache key format: {upstream_id}:{method}:{path}:{query}:{content_hash}
// Example: "http://example.com:80:GET:/images/logo.png::{sha256}"
```

**Implementation**:
- Include `ETag`/`Last-Modified` for validation
- Support `Cache-Control: max-age` from origin
- Support `Stale-While-Revalidate`

### 2.3 Integration with MeshProxy

Integrate edge cache into `MeshProxy`:

```rust
// In src/mesh/proxy.rs
pub struct MeshProxy {
    // ... existing fields
    edge_cache: Option<Arc<EdgeCache>>,  // NEW
}

impl MeshProxy {
    pub async fn fetch(&self, upstream_id: &str, request: Request<()>) -> Result<Response<()>, Error> {
        // Check edge cache first
        let cache_key = self.edge_cache.as_ref()
            .map(|c| c.compute_key(&request, upstream_id));
        
        if let Some(cache) = self.edge_cache.as_ref() {
            if let Some(key) = cache_key {
                if let Some(entry) = cache.get(&key) {
                    // Return cached response
                    return self.build_cached_response(entry);
                }
            }
        }
        
        // Fetch from origin (existing code)
        let response = self.fetch_from_origin(upstream_id, request).await?;
        
        // Cache if cacheable
        if let Some(cache) = self.edge_cache.as_ref() {
            if cache.should_cache(&response) {
                let ttl = extract_cache_ttl(&response);
                cache.insert(cache_key.unwrap(), entry, ttl);
            }
        }
        
        Ok(response)
    }
}
```

**File Changes**:
- `src/mesh/proxy.rs` - Integrate edge cache

**Estimated effort**: 2-3 hours

---

## Phase 3: Edge Static File Caching

**Goal**: Edge nodes cache static files from origin with TTL.

**Status**: 📋 PLANNING

### 3.1 Static Cache Implementation

Extend existing static file system for edge caching:

```rust
// In src/static_files/mod.rs

pub struct FileManager {
    // ... existing fields
    edge_cache: Option<Arc<EdgeFileCache>>,  // NEW
}

// New file: src/static_files/edge_cache.rs
pub struct EdgeFileCache {
    cache: moka::sync::Cache<String, StaticCacheEntry>,
}

pub struct StaticCacheEntry {
    pub body: Bytes,
    pub mime_type: String,
    pub etag: String,
    pub last_modified: i64,
    pub cached_at: i64,
}
```

**File Changes**:
- `src/static_files/edge_cache.rs` - NEW file
- `src/static_files/mod.rs` - Integrate edge cache

**Estimated effort**: 3-4 hours

### 3.2 Cache Invalidation

Support cache invalidation:

```rust
// When origin updates static file, broadcast invalidation
pub async fn invalidate_edge_cache(site_id: &str, path_pattern: &str) {
    // Send cache invalidation message to all edges
    let message = MeshMessage::EdgeCacheInvalidate {
        site_id: site_id.into(),
        path_pattern: path_pattern.into(),
    };
    broadcast_to_edges(&message).await;
}
```

---

## Phase 4: DHT Image Poison Fallback Preservation

**Goal**: Maintain DHT-based image poison config as required fallback.

**Status**: 📋 PLANNING

### 4.1 DHT Fetch Remains Primary

The existing DHT-based image poison config fetch must remain as the primary mechanism:

```rust
// In src/mesh/proxy.rs applied_image_poisoning()
pub async fn apply_image_poisoning(
    &self,
    body: Bytes,
    upstream_id: &str,
    last_modified: Option<String>,
    config: Option<&SiteImagePoisonConfig>,
) -> Result<Bytes, Error> {
    // 1. First, try DHT-based config (required fallback)
    let dht_config = tm.get_image_poison_config_for_site(upstream_id).await;
    
    // 2. Use site config if DHT returns nothing
    let effective_config = dht_config.or(config);
    
    if effective_config.is_none() || !effective_config.unwrap().enabled.unwrap_or(false) {
        return Ok(body);
    }
    
    // Apply poisoning
    // ...
}
```

**Key Requirement**: DHT-based config fetch MUST remain as primary. Site config sync is a supplement, not replacement.

**File Changes**:
- `src/mesh/proxy.rs` - Ensure DHT fetch remains

### 4.2 Dual Config Priority

Configuration priority (highest to lowest):

1. **DHT-based config** (required fallback) - `get_image_poison_config_for_site()`
2. **Site config sync** (from origin) - received via `SiteConfigSync`
3. **Local config** - TOML configuration

---

## Phase 5: Non-Mesh Mode Simplification

**Goal**: Standalone origin uses local config directly (no forwarding needed).

**Status**: 📋 PLANNING

### 5.1 Detect Non-Mesh Mode

When not in mesh mode, origin uses local config:

```rust
// In src/worker/unified_server.rs
let is_mesh_mode = {
    let config = self.process.config.read().await;
    config.mesh.enabled && config.mesh.role.is_edge()
};

if !is_mesh_mode {
    // Non-mesh mode: origin acts as its own edge
    // Use local config directly
    let static_ttl = site_config.static.cache_ttl_seconds.unwrap_or(3600);
    let image_poison = site_config.image_poison.clone();
    let proxy_cache = site_config.proxy.cache.clone();
}
```

### 5.2 Apply Local Config Directly

In non-mesh mode:

```rust
// Local config already works:
// - Static files: src/static_files/mod.rs uses local cache_ttl
// - Image poison: src/worker/image_poisoning.rs uses local config
// - Proxy cache: src/proxy/mod.rs uses local config
```

**Verification**: Non-mesh mode should require no changes - existing implementation already works correctly.

---

## Implementation Order

### Phase Dependencies

```
Phase 1 (Infra) ──► Phase 2 (Edge HTTP Cache)
       │                     │
       │                     ▼
       │              Phase 3 (Static Cache)
       │                     │
       ▼                     ▼
Phase 4 (DHT Fallback) ◄──────┘
       │
       ▼
Phase 5 (Non-Mesh Simplification)
```

### Suggested Execution

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1 | 1-2 days | None |
| Phase 2 | 2 days | Phase 1 |
| Phase 3 | 1-2 days | Phase 1, 2 |
| Phase 4 | 0.5 day | Phase 1 |
| Phase 5 | 0.5 day | None |

**Total Estimated**: 5-7 days

---

## File Changes Summary

### New Files

| File | Purpose |
|------|---------|
| `src/mesh/edge_cache.rs` | Edge HTTP response caching |
| `src/static_files/edge_cache.rs` | Edge static file caching |

### Modified Files

| File | Changes |
|------|---------|
| `src/mesh/transport.rs` | Add `broadcast_site_config_to_edges()` |
| `src/mesh/topology.rs` | Add `find_all_edges_for_site()` |
| `src/mesh/protocol.rs` | Add fields to `SiteConfigSync` |
| `src/admin/state.rs` | Apply received preferences |
| `src/mesh/proxy.rs` | Integrate edge cache |
| `src/static_files/mod.rs` | Edge caching support |
| `src/worker/unified_server.rs` | Mesh mode detection |

### Key Tests to Add

| Test | Description |
|------|-------------|
| `test_edge_cache_basic` | Edge caches response |
| `test_edge_cache_ttl` | Respects origin TTL |
| `test_config_sync_to_edges` | Edges receive config |
| `test_image_poison_dht_fallback` | DHT preferred over sync |
| `test_non_mesh_uses_local` | Standalone uses local config |

---

## Configuration Examples

### Origin Node Config

```toml
[mesh]
role = "origin"

[site.static]
enabled = true
cache_ttl_seconds = 3600

[site.image_poison]
enabled = true
level = "standard"
intensity = 0.3

[site.proxy.cache]
enabled = true
max_size = "100MB"
valid_status = [200, 301, 302]
methods = ["GET", "HEAD"]
inactive = 3600
```

### Edge Node Config

```toml
[mesh]
role = "edge"

# Receives config from origin via SiteConfigSync
# No explicit cache config needed
```

### Standalone Config (Non-Mesh)

```toml
[mesh]
enabled = false

[site.static]
enabled = true
cache_ttl_seconds = 3600

[site.image_poison]
enabled = true

# Non-mesh: uses local config directly
```

---

## Verification Checklist

After implementation:

- [ ] `cargo test --test integration_test` - All tests pass
- [ ] Edge receives config via `SiteConfigSync`
- [ ] Edge caches HTTP responses with TTL
- [ ] Edge caches static files
- [ ] DHT image poison config remains primary
- [ ] Non-mesh mode uses local config
- [ ] `cargo clippy --lib -- -D warnings` passes
- [ ] `cargo fmt` passes

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Cache inconsistency | Medium | Medium | Use content-addressable keys |
| Stale cache | Medium | Medium | Proper TTL + invalidation |
| Memory pressure | Medium | Medium | Bounded cache size |
| Concurrent invalidation | Low | Low | Use atomic operations |
| Missing DHT fallback | High | High | Keep DHT as primary |

---

## Backward Compatibility

- Existing TOML config continues to work
- DHT-based image poison remains primary
- Non-mesh mode unchanged
- Breaking changes require major version
- Cache invalidation for config updates

---

## Reference Commands

```bash
# Run integration tests
cargo test --test integration_test

# Verify test compilation
cargo test --lib --no-run

# Run clippy
cargo clippy --lib -- -D warnings

# Format
cargo fmt
```

---

## Notes

- Edge cache uses content-addressable keys (SHA256 of request)
- DHT-based config fetch MUST remain as primary
- Site config sync is a supplement, not replacement
- Non-mesh mode simplifies: origin = own edge
- Consider adding cache invalidation messages
- Use consistent hashing for cache key distribution
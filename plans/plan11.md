# Edge Node Caching & Image Poison Capability - Implementation Plan

## Update: Proxy Cache Preferences Status

**IMPORTANT**: After deeper investigation, proxy cache preferences ARE already applied in the mesh proxy path at `src/mesh/proxy.rs:1209-1219`:

```rust
if let Some(ref record_store) = tm.get_record_store() {
    let prefs_key = crate::mesh::dht::keys::DhtKey::upstream_proxy_cache_preferences(upstream_id);
    if let Some(record) = record_store.get_record(&prefs_key.as_str()) {
        if let Ok(prefs) = serde_json::from_slice::<ProxyCachePreferences>(&record.value) {
            self.set_proxy_cache_preferences(&prefs);  // ← APPLIED HERE
        }
    }
}
```

This means the real issue is:
1. Origin publishes preferences to DHT
2. MeshProxy reads from DHT when transforming response - APPLIES preferences
3. BUT: When EDGE serves response DIRECTLY to client (not via proxy), we're in `http/server.rs` not `mesh/proxy.rs`
4. Edge's HTTP server doesn't check/apply preferences

**The proxy cache issue is now LOWER priority** - it works in the mesh proxy path. The remaining question is whether edge needs preferences when serving directly.

---

## Overview

This plan addresses fixing the edge node caching and image poison capability in mesh mode. In mesh topology, origin nodes should forward caching/preferences through to edge nodes, and edge nodes should apply and cache responses accordingly. This is simpler when not in mesh mode as the origin acts as its own edge node (direct config access).

## Problem Statement

Two critical issues were identified:

1. **Image Poison Config Not Applied in Mesh Mode**: Edge nodes fetch the full `SiteImagePoisonConfig` from origin but fail to convert it properly for use in the response transform pipeline
2. **Proxy Cache Preferences Not Applied at Edge**: Edge nodes retrieve proxy cache preferences from origin but never apply them to the local proxy cache

---

## Issue Analysis

### Issue 1: Image Poison Config Type Mismatch

#### Field Comparison

| Field | SiteImagePoisonConfig | MeshImageProtectionConfig | Status |
|-------|---------------------|-------------------------|--------|
| `enabled` | `Option<bool>` | `Option<bool>` | ✅ Present |
| `level` | `Option<String>` | ❌ Missing | **LOST** |
| `intensity` | `Option<f32>` | ❌ Missing | **LOST** |
| `seed` | `Option<u64>` | ❌ Missing | **LOST** |
| `max_dimension` | `Option<u32>` | `Option<usize>` | Similar (renamed) |
| `jpeg_quality` | `Option<u8>` | ❌ Missing | **LOST** |
| `whitelist_patterns` | `Option<Vec<String>>` | `Option<Vec<String>>` | ✅ Present |

#### Root Cause

In `src/http/server.rs:2805-2809`:

```rust
let config = crate::http::response_transform::ResponseTransformConfig::from_mesh_config(
    minification.as_ref(),
    image_protection.as_ref(),  // Uses MeshImageProtectionConfig only
    compression.as_ref(),
);
```

The code:
1. Fetches `image_protection` (`MeshImageProtectionConfig` - basic fields only)
2. Fetches `image_poison_config` (`SiteImagePoisonConfig` - full fields) but DISCARDS it
3. Builds `ResponseTransformConfig` using only `image_protection`
4. The `img_settings` check at lines 2820-2858 uses only `image_protection.min_size` and `whitelist_patterns`
5. At line 2852, `image_poison_config` is passed directly to `apply_image_poisoning()` - this DOES have full fields

**Why it's partially broken**: The detection check (`is_image && in_range`) uses simpler config from `image_protection`. The actual poisoning uses full config, but the decision to poison is based on reduced config.

### Issue 2: Proxy Cache Preferences Not Applied

#### Where Published (Origin)

`src/mesh/transport.rs:902-909`:

```rust
if let Some(ref cache_config) = site_config.proxy.cache {
    let proxy_cache_prefs = crate::mesh::protocol::ProxyCachePreferences::from(cache_config);
    if let Ok(bytes) = serde_json::to_vec(&proxy_cache_prefs) {
        let key = format!("upstream_proxy_cache_preferences:{}", site_id);
        record_store.store_and_announce(key, bytes, 3600);
    }
}
```

Fields published:
- `enable: bool`
- `inactive: u64`
- `valid_status: Vec<u32>`
- `methods: Vec<String>`
- `use_stale: Vec<String>`
- `min_uses: u32`
- `stale_while_revalidate: u64`
- `stale_if_error: u64`

#### Where Retrieved (Edge)

`src/mesh/transports/manager.rs:1134-1194`:

```rust
pub async fn get_proxy_cache_preferences_for_site(
    &self,
    upstream_id: &str,
) -> Option<crate::mesh::protocol::ProxyCachePreferences>
```

#### Missing: Application at Edge

The edge retrieves `ProxyCachePreferences` but **never calls** `set_proxy_cache_preferences()` to apply them.

Compare to origin mode at `src/mesh/proxy.rs:1217` where preferences ARE applied:

```rust
self.set_proxy_cache_preferences(&prefs);
```

---

## Non-Mesh Mode: Baseline (Working Correctly)

For origin nodes that serve as their own edge (non-mesh mode), the code uses `from_static_config()`:

`src/http/server.rs:2881-2884`:

```rust
let config = crate::http::response_transform::ResponseTransformConfig::from_static_config(
    static_config,
    image_poison_config,
);
```

This correctly reads all fields from `site_config.image_poison` and works as expected.

---

## Implementation Plan: Option A (Minimal Fix)

### Strategy

1. **Fix image poison**: Pass `image_poison_config` directly to the settings check instead of using only `image_protection`
2. **Fix proxy cache**: Add call to apply preferences after retrieval at edge
3. **No struct changes**: Avoid renaming or creating new config types

### Files to Modify

| File | Changes |
|------|---------|
| `src/http/server.rs` | Fix image poison settings check, add proxy cache apply call |
| `src/http/response_transform.rs` | Add new method or extend existing to accept image_poison |

### Step 1: Fix Image Poison Settings Check

**Location**: `src/http/server.rs:2805-2858`

**Current code** (broken at 2805-2809, 2820-2858):
```rust
let config = crate::http::response_transform::ResponseTransformConfig::from_mesh_config(
    minification.as_ref(),
    image_protection.as_ref(),
    compression.as_ref(),
);

// Later at 2820-2829 - uses img_settings from config (wrong)
if let Some(ref img_settings) = config.image_poisoning {
    let mut is_image = ...
    let in_range = body_len >= img_settings.min_size;  // Uses image_protection.min_size_bytes, not image_poison_config.max_dimension
```

**Fix approach A1a**: Modify the detection check to use `image_poison_config` directly

Option A1a would change lines 2820-2858 to:
```rust
// Use image_poison_config from mesh for the decision, not image_protection
if let Some(ref img_settings) = image_poison_config {
    let enabled = img_settings.enabled.unwrap_or(false);
    if !enabled {
        // Skip checks entirely
    }
    // Use img_settings fields directly
    let min_size = img_settings.max_dimension.unwrap_or(4096) as u64;
    let in_range = body_len >= min_size;
    // ... rest of check
```

**Fix approach A1b**: Add new `from_mesh_config_with_poison()` method

Add a new method to `ResponseTransformConfig`:

```rust
pub fn from_mesh_config_with_poison(
    minification: Option<&'a MeshMinificationConfig>,
    image_protection: Option<&'a MeshImageProtectionConfig>,
    image_poison: Option<&'a SiteImagePoisonConfig>,  // NEW
    compression: Option<&'a MeshCompressionConfig>,
) -> Self
```

This maintains backward compatibility while adding full image poison support.

**Recommendation**: A1a - Direct fix in http/server.rs is simpler than adding new methods.

### Step 2: Fix Proxy Cache Preferences Application

**Location**: `src/http/server.rs:2797-2803` (mesh transport block)

**Add after retrieval**:
```rust
if let Some(ref mt) = mesh_transport {
    let (minification, image_protection, image_poison_config, compression, proxy_prefs) = tokio::join!(
        mt.get_minification_for_site(&site_id),
        mt.get_image_protection_for_site(&site_id),
        mt.get_image_poison_config_for_site(&site_id),
        mt.get_compression_for_site(&site_id),
        mt.get_proxy_cache_preferences_for_site(&site_id),  // NEW
    );
    
    // Apply proxy cache preferences to local cache
    if let Some(ref prefs) = proxy_prefs {
        if let Some(ref cache) = target.proxy_cache.as_ref() {
            cache.apply_preferences(prefs);
        }
    }
}
```

Wait - we need to verify where `proxy_cache` is accessible. Let me check...

Actually, the proxy cache preferences need to be applied to the PROXY CACHE (in proxy.rs), not to the site target. Looking at how origin applies preferences in `src/mesh/proxy.rs:1217`:

```rust
self.set_proxy_cache_preferences(&prefs);
```

At the edge HTTP layer, we don't have direct access to `MeshProxy`. We need to either:
- Store preferences in the mesh transport manager for later use
- Apply during proxy phase (not HTTP response phase)

**Alternative**: The proxy cache preferences should be applied when the edge PROXIES requests to origin, not during response handling. Let me trace through more...

Actually, the preferences are for caching RESPONSE from origin. So applying them at response time doesn't make sense - the edge isn't caching at that point. The preferences should be applied to the edge's proxy CACHE that stores upstream responses.

Let me verify: Does the edge have a `proxy_cache` that would use these preferences?

Looking at `src/mesh/transports/manager.rs` - there's no `proxy_cache` here. The preferences are retrieved but not stored for later application.

**Correct location**: These preferences should be applied at the edge's PROXY layer (mesh proxy), not the HTTP response layer. The edge needs to apply preferences when SETTING UP its proxy cache for an upstream.

This requires examining where proxy_cache is initialized at the edge. Let me check...

Actually, finding: The edge doesn't set up proxy cache the same way origin does. The edge uses the mesh transport to proxy to origin. The preferences need to flow through the transport somehow.

**Alternative fix**: Store the preferences in `MeshTransportManager` and apply them when creating proxy cache for an upstream.

```rust
// In MeshTransportManager - add field
proxy_cache_preferences: Arc<RwLock<HashMap<String, ProxyCachePreferences>>,

// When retrieving, also store
if let Some(ref prefs) = proxy_prefs {
    self.proxy_cache_preferences.write().insert(upstream_id.to_string(), prefs);
}
```

Then when edge creates proxy cache for upstream, it reads preferences from manager.

**Recommendation**: This fix is more involved and may require finding where proxy cache is created at edge. Let's trace through to confirm correct location.

### Implementation Estimate

| Task | Complexity | Files |
|------|-----------|-------|
| Fix image poison detection | LOW | 1 |
| Verify proxy cache (now LOWER priority) | LOW | 1 |

**Total estimated time**: 1-2 hours

**NOTE**: Proxy cache preferences ARE applied in mesh proxy path. Main issue is image poison.

---

## Alternative: Option B (Full Unification)

### Strategy

1. Create unified `MeshImagePoisonConfig` with all fields
2. Restructure origin→edge publishing to use unified type
3. Restructure edge retrieval and config building
4. Add proper proxy cache preference flow

### Files to Modify (5-7)

| File | Changes |
|------|---------|
| `src/mesh/config.rs` | Add `MeshImagePoisonConfig` |
| `src/mesh/transport.rs` | Publish unified type |
| `src/mesh/transports/manager.rs` | Retrieve unified type |
| `src/http/server.rs` | Use unified type |
| `src/http/response_transform.rs` | Accept unified type |
| `src/mesh/proxy.rs` | Proper proxy cache preference flow |

### Pros/Cons

| + | - |
|----|---|
| Clean design | 4-6 hours |
| Future-proof | Breaking changes |
| Single config type | More testing |

---

## Recommendation

**Proceed with Option A** (Minimal Fix):

1. Fix image poison detection in http/server.rs (2-3 lines change) - LOW risk
2. Proxy cache preferences: Already works in mesh proxy path - verify only

The image poison fix is straightforward. Proxy cache already applies preferences during mesh proxy response transform.

---

## Testing Plan

### Issue 1: Image Poison (PRIMARY)

1. Enable image poison with custom level/intensity on origin site config
2. Make request through edge node (mesh mode)
3. Verify edge uses correct level/intensity for poisoning
4. Compare with direct request to origin (non-mesh mode) - should be identical

### Issue 2: Proxy Cache Preferences (SECONDARY - VERIFY ONLY)

1. Configure custom proxy cache preferences on origin
2. Make multiple requests through edge
3. Check edge's cache behavior (inactive, stale-while-revalidate, etc.)

---

## Open Questions

These are now RESOLVED:

1. **Where does edge create/configure its proxy cache?** - Found at `src/mesh/proxy.rs:1209-1219` - The `MeshProxy` already reads preferences from DHT directly in the response transform method! The issue is that this code path is for when origin proxies TO another origin, not when edge serves response to client.

2. **Should preferences be stored in MeshTransportManager?** - Actually not needed - the proxy already reads from DHT during response transform. The REAL issue is different: When EDGE serves response to CLIENT (not proxying), the HTTP server doesn't apply these preferences.

The correct fix for proxy cache: The edge HTTP server (`http/server.rs`) needs to apply the preferences when SETTING UP the proxy cache, not during response handling. But wait - does edge even USE proxy cache when serving client requests?

**Actually the issue is simpler**: When edge proxies to origin, it uses MeshProxy which DOES read preferences from DHT at line 1217. But when origin configures proxy_cache at startup (not via mesh), it uses local config. So the "preferences not applied" is primarily about origin→edge publishing vs edge applying.

Let me re-verify: The mesh proxy already reads preferences at line 1217. So maybe this works? The concern was whether edge retrieves AND applies it - yes it does read from DHT, not from transport manager.Wait let me re-check the line numbers - in my earlier search I found the apply at line 1217 yes. Let me verify this is actually in the flow...

Actually I see now - the code at 1209-1219 directly reads from record_store in MeshProxy:
```rust
if let Some(ref record_store) = tm.get_record_store() {
    let prefs_key = ...
    if let Some(record) = record_store.get_record(&prefs_key.as_str()) {
        ...self.set_proxy_cache_preferences(&prefs);
    }
}
```

This DOES apply preferences when transforming response. So proxy cache preferences ARE applied (at least in the mesh proxy path). The "missing" might be specific scenarios. But for completeness, we should verify this works and fix if needed.

**Conclusion**: The plan should note that proxy cache application IS present in the mesh proxy path, but needs verification.
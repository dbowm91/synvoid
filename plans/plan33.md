# Plan 33: Edge Caching & Image Poison Capability

## Context

A code review of the edge node caching and image poison capability revealed several architectural issues that must be addressed to achieve the scalability target of 500K+ sites mesh-wide.

**Architecture Impact**: ⚠️ **Architecture changes required** - This plan modifies how origin and edge nodes handle transforms, caching, and image poisoning.

---

## Executive Summary

### Current Issues Found

| # | Issue | Severity | Impact |
|---|-------|----------|--------|
| 1 | Image poisoning happens at both origin and edge | **Critical Bug** | Double-poisoning corrupts images |
| 2 | HTTP server has separate `IMAGE_POISON_CACHE` from MeshProxy | Medium | Duplication, no DHT distribution |
| 3 | `proxy_cache` in MeshProxy is dead code | Low | Confusion, unused code |
| 4 | Origin's `apply_response_transforms()` only does minification | High | Missing image poisoning and compression |
| 5 | No `X-MaluWaf-Transformed` header | Medium | Edge can't skip idempotent transforms |
| 6 | Single-tier 300s cache TTL causes DHT hammering | Medium | 500K sites × 300s expiry = potential stampede |

### Design Decisions (confirmed with user)

1. **Image poison edge-only**: Origin NEVER applies image poisoning. Edge ALWAYS applies it. Prevents double-poisoning.

2. **Origin may transform idempotent operations**: Origin may apply minification and compression, but MUST signal via header. Edge skips already-applied transforms.

3. **Tiered caching**: Both combined approach - time-based tiers (L1/L2) with popularity-based promotion.

4. **HTTP server uses MeshProxy**: Option A - HTTP server routes through MeshProxy for all transforms.

5. **Full RFC 7234 Vary handling**: Proper HTTP response caching with Vary header support.

---

## Architecture: Target State

```
┌─────────────────────────────────────────────────────────────────┐
│                         Origin Node                              │
│                                                                  │
│  Backend ──► [minification + compression if enabled]            │
│                    │                                             │
│                    ├── Caches locally (L1/L2 tiered cache)        │
│                    └── Serves to edge via mesh                   │
│                                                                  │
│  Adds header: X-MaluWaf-Transformed: min,gzip (if applied)     │
│                                                                  │
│  ❌ NEVER applies image poisoning                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ RAW content (poison never applied)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Edge Node                                │
│                                                                  │
│  1. Read transform config from DHT (with local L1/L2 cache)      │
│  2. Check X-MaluWaf-Transformed header from origin              │
│  3. Apply transforms client-side if needed:                      │
│     ├── Minification (skip if already done by origin)            │
│     ├── Image Poisoning (ALWAYS at edge, never by origin)        │
│     └── Compression (skip if already done by origin)             │
│  4. Cache transformed result (tiered: L1 → L2 promotion)        │
│  5. Serve to client                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Image Poisoning - Edge Only

**Goal**: Make image poisoning exclusively an edge operation. Origin NEVER poisons images.

### Step 1.1: Add `edge_only` to SiteImagePoisonConfig

**File**: `src/config/site/misc.rs`

**Current** (lines 21-36):
```rust
pub struct SiteImagePoisonConfig {
    pub enabled: Option<bool>,
    pub level: Option<String>,
    pub intensity: Option<f32>,
    pub seed: Option<u64>,
    pub max_dimension: Option<u32>,
    pub jpeg_quality: Option<u8>,
    pub whitelist_patterns: Option<Vec<String>>,
}
```

**Change to:**
```rust
pub struct SiteImagePoisonConfig {
    pub enabled: Option<bool>,
    pub level: Option<String>,
    pub intensity: Option<f32>,
    pub seed: Option<u64>,
    pub max_dimension: Option<u32>,
    pub jpeg_quality: Option<u8>,
    pub whitelist_patterns: Option<Vec<String>>,
    pub edge_only: Option<bool>,  // NEW: If true, origin never poisons
}
```

### Step 1.2: Publish `edge_only` to DHT

**File**: `src/mesh/transport.rs` (lines 864-875)

**Add to site_image_poison_json:**
```rust
let site_image_poison_json = serde_json::json!({
    "enabled": image_poison_config.enabled,
    "level": image_poison_config.level,
    "intensity": image_poison_config.intensity,
    "seed": image_poison_config.seed,
    "max_dimension": image_poison_config.max_dimension,
    "jpeg_quality": image_poison_config.jpeg_quality,
    "edge_only": image_poison_config.edge_only.unwrap_or(true),  // NEW: Default true
});
```

### Step 1.3: Parse `edge_only` in MeshTransportManager

**File**: `src/mesh/transports/manager.rs` (lines 1022-1065)

**Add to the config parsing closure:**
```rust
edge_only: parsed
    .get("edge_only")
    .and_then(|v| v.as_bool())
    .unwrap_or(true),  // Default to true for safety
```

### Step 1.4: Clarify image poisoning behavior

**Key insight**: Since origin NEVER poisons images (per design decision), the `transform_response()` in MeshProxy running on the EDGE should ALWAYS poison when `image_poison_config.enabled=true`.

The `edge_only` field is therefore a safety/clarification flag rather than a runtime guard. Its presence documents the intent that poisoning only happens at edge.

**No code change needed in MeshProxy** - it already assumes origin didn't poison (because we removed that code in Steps 1.5 and 1.6).

### Step 1.5: Remove image poisoning from origin path

**File**: `src/mesh/transport_peer.rs` (lines 2753-2868)

**Function**: `apply_response_transforms()`

Currently handles only minification. Image poisoning must NEVER be added here.

**Verify** that no image poisoning code exists in this function.

### Step 1.6: Verify HTTP server origin path doesn't poison

**File**: `src/http/server.rs`

**Search for** any `apply_image_poisoning` calls in code paths where the server is acting as origin (not edge proxying through mesh).

**Key insight**: When `mesh_transport.is_none()` at line 2877, the HTTP server is acting as origin. It should NOT poison images in this path - it should only do minification and compression.

---

## Phase 2: X-MaluWaf-Transformed Header

**Goal**: Allow origin to signal which idempotent transforms it applied, so edge can skip redundant work.

### Step 2.1: Define header format

**Header**: `X-MaluWaf-Transformed`
**Values**: Comma-separated list, e.g., `min,gzip` or `min,br,gzip`

**Transform tokens:**
- `min` - HTML/CSS/JS minification applied
- `gzip` - gzip compression applied
- `br` - brotli compression applied

### Step 2.2: Add header on origin outgoing responses

**File**: `src/mesh/transport_peer.rs`

**In `apply_response_transforms()` or wherever responses are sent to edge:**

After applying idempotent transforms (minification, compression), add the header:

```rust
// Build transformed header
let mut applied = Vec::new();
if minification_applied {
    applied.push("min");
}
if gzip_applied {
    applied.push("gzip");
}
if brotli_applied {
    applied.push("br");
}

if !applied.is_empty() {
    response.headers_mut().insert(
        "X-MaluWaf-Transformed",
        HeaderValue::from_str(&applied.join(",")).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
}
```

### Step 2.3: Parse header in MeshProxy

**File**: `src/mesh/proxy.rs` (in `transform_response()`)

**At start of function**, parse the header:

```rust
let upstream_transforms = response
    .headers()
    .get("X-MaluWaf-Transformed")
    .and_then(|v| v.to_str().ok())
    .map(|s| s.split(',').collect::<HashSet<_>>())
    .unwrap_or_default();
```

**When deciding which transforms to apply:**

```rust
// Minification - skip if origin already did it
let needs_minification = minification
    .as_ref()
    .and_then(|c| c.enabled)
    .unwrap_or(false)
    && !upstream_transforms.contains("min");

// Compression - skip if origin already did it (check both gzip and br)
let needs_gzip = gzip_enabled && !upstream_transforms.contains("gzip");
let needs_brotli = brotli_enabled && !upstream_transforms.contains("br");

// Image poisoning - ALWAYS needed (origin never does this)
let needs_poison = image_poison_config
    .as_ref()
    .and_then(|c| c.enabled)
    .unwrap_or(false);
```

### Step 2.4: Add header in HTTP server origin path

**File**: `src/http/server.rs`

When acting as origin (`mesh_transport.is_none()` path at line 2877), set the header after applying idempotent transforms.

---

## Phase 3: Tiered Transform Caching

**Goal**: Prevent DHT hammering at scale with 500K sites by using L1/L2 tiered caching with popularity-based promotion.

### Step 3.1: Define TieredTransformCache struct

**File**: `src/mesh/proxy.rs` (new section, before `MeshProxy` struct)

```rust
/// Tiered transform cache with L1 (hot) and L2 (warm) tiers.
/// L1: 5min TTL, 10K entries - fast access for popular content
/// L2: 1hr TTL, 100K entries - for content accessed multiple times
/// Promotion: Entries accessed >3 times in L1 get promoted to L2
struct TieredTransformCache {
    l1: Cache<String, TieredCacheEntry>,
    l2: Cache<String, TieredCacheEntry>,
}

struct TieredCacheEntry {
    body: Bytes,
    content_encoding: Option<String>,
    content_type: Option<String>,
    access_count: AtomicU32,
    created_at: Instant,
}

impl TieredTransformCache {
    const L1_SIZE: u64 = 10_000;
    const L1_TTL_secs: u64 = 300;  // 5 minutes

    const L2_SIZE: u64 = 100_000;
    const L2_TTL_secs: u64 = 3600;  // 1 hour

    const PROMOTION_THRESHOLD: u32 = 3;

    pub fn new() -> Self {
        let l1 = Cache::builder()
            .max_capacity(Self::L1_SIZE)
            .time_to_live(Duration::from_secs(Self::L1_TTL_secs))
            .weigher(|_key: &String, value: &TieredCacheEntry| {
                value.body.len() as u32
            })
            .build();

        let l2 = Cache::builder()
            .max_capacity(Self::L2_SIZE)
            .time_to_live(Duration::from_secs(Self::L2_TTL_secs))
            .build();

        Self { l1, l2 }
    }

    pub fn get(&self, key: &str) -> Option<Arc<TieredCacheEntry>> {
        // Try L1 first
        if let Some(entry) = self.l1.get(key) {
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            // Check if should promote to L2
            if entry.access_count.load(Ordering::Relaxed) > Self::PROMOTION_THRESHOLD {
                self.promote_to_l2(key, entry);
            }
            return Some(entry);
        }

        // Try L2
        self.l2.get(key).map(|entry| {
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            entry
        })
    }

    pub fn insert(&self, key: String, value: TieredCacheEntry) {
        self.l1.insert(key, Arc::new(value));
    }

    fn promote_to_l2(&self, key: &str, entry: Arc<TieredCacheEntry>) {
        // Remove from L1 and insert into L2
        self.l1.invalidate(key);
        self.l2.insert(key.to_string(), entry);
    }
}
```

### Step 3.2: Replace transform_cache usage

**File**: `src/mesh/proxy.rs`

**Current** (lines 70, 1301-1325, 1478-1487):
```rust
transform_cache: Arc<Cache<String, TransformCacheEntry>>,
// ...
if let Some(entry) = self.transform_cache.get(&cache_key) { ... }
// ...
self.transform_cache.insert(cache_key.clone(), TransformCacheEntry { ... });
```

**Change to** use `TieredTransformCache`:
```rust
transform_cache: Arc<TieredTransformCache>,
// ...
if let Some(entry) = self.transform_cache.get(&cache_key) {
    // Return cached response
    let mut new_response = Response::builder().status(200);
    if let Some(ref enc) = entry.content_encoding {
        new_response = new_response.header("Content-Encoding", enc.as_str());
    }
    if let Some(ref ct) = entry.content_type {
        new_response = new_response.header("Content-Type", ct.as_str());
    }
    let body = http_body_util::Full::new(entry.body.clone()).boxed();
    return new_response.body(body).unwrap_or_else(|_| ...);
}
// ...
self.transform_cache.insert(
    cache_key.clone(),
    TieredCacheEntry {
        body: transformed.clone(),
        content_encoding: cached_content_encoding,
        content_type: content_type_header,
        access_count: AtomicU32::new(0),
        created_at: Instant::now(),
    },
);
```

### Step 3.3: Update TransformCacheEntry to TieredCacheEntry

**Remove** the old `TransformCacheEntry` struct and `DhtTransformEntry` conversions if no longer needed.

### Step 3.4: Add metrics

**File**: `src/metrics/mod.rs`

Add new metrics:
```rust
pub static TRANSFORM_CACHE_L1_HITS: AtomicU64 = AtomicU64::new(0);
pub static TRANSFORM_CACHE_L2_HITS: AtomicU64 = AtomicU64::new(0);
pub static TRANSFORM_CACHE_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
pub static TRANSFORM_CACHE_L1_MISSES: AtomicU64 = AtomicU64::new(0);
```

Update `TieredTransformCache` to increment these.

### Step 3.5: Update cache initialization

**File**: `src/mesh/proxy.rs` (new() constructor)

**Current** (line 271):
```rust
let transform_cache = Cache::builder()
    .max_capacity(DEFAULT_TRANSFORM_CACHE_SIZE)
    .time_to_live(Duration::from_secs(DEFAULT_TRANSFORM_CACHE_TTL_SECS))
    .weigher(|_key: &String, value: &TransformCacheEntry| {
        value.body.len() as u32
    })
    .build();
```

**Change to:**
```rust
let transform_cache = Arc::new(TieredTransformCache::new());
```

---

## Phase 4: HTTP Server Uses MeshProxy Transform Caching

**Goal**: Eliminate duplicate `IMAGE_POISON_CACHE` by having HTTP server route through MeshProxy for all transforms.

### Step 4.1: Remove IMAGE_POISON_CACHE and related code

**File**: `src/http/server.rs`

**Remove** (lines 82-101):
```rust
static IMAGE_POISON_CACHE: LazyLock<Cache<String, Vec<u8>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(1000)
        .time_to_live(Duration::from_secs(3600))
        .build()
});

pub fn invalidate_image_poison_cache_for_site(site_id: &str) {
    // Invalidate entries matching site_id prefix...
}
```

**Remove** `apply_image_poisoning()` function (lines 3894-3961) - MeshProxy's version will be used instead.

### Step 4.2: Add MeshProxy reference to HTTP server state

**File**: `src/http/server.rs` (around line 335)

**Current:**
```rust
mesh_transport: Option<Arc<MeshTransportManager>>,
```

**Add:**
```rust
mesh_proxy: Option<Arc<MeshProxy>>,  // NEW: For transform caching
```

**Update** the handler function signature to accept and store `mesh_proxy`.

### Step 4.3: Wire up MeshProxy in unified_server.rs

**File**: `src/worker/unified_server.rs`

**Find where** HTTP server is created and wire in the MeshProxy:

```rust
let http_state = HttpServerState::new(
    // ... existing params ...
    mesh_transport: transport_manager.clone(),
    mesh_proxy: proxy.clone(),  // NEW: Wire in MeshProxy
);
```

### Step 4.4: Update HTTP server to use MeshProxy.transform_response()

**File**: `src/http/server.rs`

**In the request handling path** (around line 2797), when `mesh_proxy.is_some()`:

Instead of inline transforms:
```rust
// CURRENT (inline transforms):
let (minification, image_protection, image_poison_config, compression) = tokio::join!(
    mt.get_minification_for_site(&site_id),
    mt.get_image_protection_for_site(&site_id),
    mt.get_image_poison_config_for_site(&site_id),
    mt.get_compression_for_site(&site_id),
);
// ... inline transform logic
```

**Change to** use MeshProxy's transform_response:
```rust
// Use MeshProxy.transform_response() for all transforms including caching
if let Some(ref proxy) = mesh_proxy {
    response = proxy
        .transform_response(response, &site_id, request_path)
        .await;
} else {
    // Fallback to inline transforms if proxy unavailable
    let (minification, image_protection, image_poison_config, compression) = tokio::join!(...);
    // ... inline transform logic
}
```

**Note**: `transform_response()` signature is:
```rust
async fn transform_response(
    &self,
    mut response: Response<BoxBody<Bytes, Infallible>>,
    upstream_id: &str,
    request_path: &str,
) -> Response<BoxBody<Bytes, Infallible>>
```

The `upstream_id` should be the `site_id`. The `transport_manager` inside MeshProxy is already set via `proxy.set_transport_manager()` in `backend.rs`.

### Step 4.5: Ensure MeshProxy works with site_id as upstream_id

**File**: `src/mesh/proxy.rs`

**In `transform_response()`**, `upstream_id` is used to:
1. Look up transform config in DHT via `MeshTransportManager.get_*_for_site()`
2. Build cache key

If we pass `site_id` as `upstream_id`, it should work correctly because:
- `get_image_poison_config_for_site(upstream_id)` queries `site_image_poison_config:{site_id}`
- Cache key `"{upstream_id}:{content_hash}:{transform_flags}"` becomes `"{site_id}:{content_hash}:{transform_flags}"`

---

## Phase 5: Implement RFC 7234 ProxyCache

**Goal**: Implement proper HTTP response caching with Vary header handling, stale-while-revalidate, stale-if-error.

### Step 5.1: Define CacheKey for RFC 7234 compliance

**File**: `src/proxy_cache/key.rs`

**Current**: Basic key definition exists.

**Expand to**:
```rust
pub struct CacheKey {
    pub method: http::Method,
    pub scheme: String,       // "http" or "https"
    pub authority: String,    // host:port
    pub path: String,
    pub vary_headers: HashMap<String, String>,  // normalized Vary header values
}

impl CacheKey {
    pub fn from_request(
        method: &http::Method,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &http::HeaderMap,
        vary: &str,  // Vary header value, e.g., "Accept-Encoding, Accept-Language"
    ) -> Self {
        let mut vary_values = HashMap::new();
        for header_name in vary.split(',') {
            let name = header_name.trim().to_lowercase();
            if let Some(value) = headers.get(&name) {
                if let Ok(v) = value.to_str() {
                    vary_values.insert(name, v.to_string());
                }
            }
        }

        Self {
            method: method.clone(),
            scheme: scheme.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            vary_headers: vary_values,
        }
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.method.hash(state);
        self.scheme.hash(state);
        self.authority.hash(state);
        self.path.hash(state);
        // Hash Vary headers in sorted order for consistency
        let mut sorted: Vec<_> = self.vary_headers.iter().collect();
        sorted.sort_by_key(|k| k.0);
        for (k, v) in sorted {
            k.hash(state);
            v.hash(state);
        }
    }
}
```

### Step 5.2: Update ProxyCacheEntry with RFC 7234 fields

**File**: `src/proxy_cache/store.rs`

**Current** (lines 33-45):
```rust
pub struct ProxyCacheEntry {
    pub content: Bytes,
    pub status: u16,
    pub headers: HeaderMap,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub expires_at: Option<Instant>,
    pub stale_while_revalidate: Option<Instant>,
    pub stale_if_error: Option<Instant>,
    pub content_length: Option<usize>,
    pub is_fresh: bool,
}
```

**Add**:
```rust
pub struct ProxyCacheEntry {
    pub content: Bytes,
    pub status: u16,
    pub headers: HeaderMap,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub expires_at: Option<Instant>,
    pub stale_while_revalidate: Option<Instant>,
    pub stale_if_error: Option<Instant>,
    pub content_length: Option<usize>,
    pub is_fresh: bool,

    // RFC 7234 fields
    pub max_age: Option<Duration>,
    pub vary: Option<String>,  // Original Vary header value
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl ProxyCacheEntry {
    pub fn is_fresh(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            return Instant::now() < expires_at;
        }
        false
    }

    pub fn is_stale_while_revalidate(&self) -> bool {
        if let Some(swr) = self.stale_while_revalidate {
            return Instant::now() <= swr && self.is_expired();
        }
        false
    }

    pub fn is_stale_if_error(&self) -> bool {
        if let Some(sie) = self.stale_if_error {
            return Instant::now() <= sie && self.is_expired();
        }
        false
    }
}
```

### Step 5.3: Implement proper get() with Vary handling

**File**: `src/proxy_cache/store.rs`

**Current `get()`** (line 269) - simple key lookup.

**Update to**:
```rust
pub async fn get(&self, key: &CacheKey) -> Option<Arc<ProxyCacheEntry>> {
    if !self.settings.read().enabled {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let inner = self.entries.get(key)?;

    // Check freshness
    if inner.entry.is_fresh() {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        inner.entry.update_access();
        return Some(inner.entry.clone());
    }

    // Handle stale scenarios
    if inner.entry.is_stale_while_revalidate() {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        let mut entry = (*inner.entry).clone();
        entry.is_fresh = false;
        entry.update_access();
        // Trigger background revalidation
        self.revalidate(key, inner).await;
        return Some(Arc::new(entry));
    }

    if inner.entry.is_stale_if_error() {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        let mut entry = (*inner.entry).clone();
        entry.is_fresh = false;
        entry.update_access();
        return Some(Arc::new(entry));
    }

    // Fully expired
    None
}

async fn revalidate(&self, key: &CacheKey, inner: &CacheEntryInner) {
    // Spawn background task to revalidate with origin
    // Uses If-None-Match / If-Modified-Since headers
}
```

### Step 5.4: Implement proper insert() with RFC 7234 headers

**File**: `src/proxy_cache/store.rs`

**Current `insert()`** - basic insert.

**Update to** parse and store:
```rust
pub async fn insert(
    &self,
    key: CacheKey,
    response: &http::Response<Bytes>,
    settings: &ProxyCacheSettings,
) -> Result<(), CacheError> {
    let status = response.status().as_u16();

    // Check if status is cacheable
    if !settings.valid_status.contains(&status) {
        return Err(CacheError::NotCacheable);
    }

    // Parse headers
    let headers = response.headers().clone();
    let content_length = headers.get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Parse cache control
    let (max_age, stale_while_revalidate, stale_if_error, vary) =
        parse_cache_control_headers(&headers);

    // Calculate expiry
    let now = Instant::now();
    let expires_at = max_age.map(|age| now + age);

    let swr = stale_while_revalidate.and_then(|d| expires_at.map(|e| e + d));
    let sie = stale_if_error.and_then(|d| expires_at.map(|e| e + d));

    let entry = ProxyCacheEntry {
        content: response.body().clone(),
        status,
        headers,
        created_at: now,
        last_accessed: now,
        expires_at,
        stale_while_revalidate: swr,
        stale_if_error: sie,
        content_length,
        is_fresh: true,
        max_age,
        vary,
        etag: None,  // Extract from headers
        last_modified: None,
    };

    // ... rest of insert logic
}

fn parse_cache_control_headers(headers: &http::HeaderMap) -> (Option<Duration>, Option<Duration>, Option<Duration>, Option<String>) {
    let cache_control = headers.get("cache-control")
        .and_then(|v| v.to_str().ok());

    let mut max_age = None;
    let mut stale_while_revalidate = None;
    let mut stale_if_error = None;

    if let Some(cc) = cache_control {
        for directive in cc.split(',') {
            let directive = directive.trim();
            if directive.starts_with("max-age=") {
                if let Ok(secs) = directive[8..].parse::<u64>() {
                    max_age = Some(Duration::from_secs(secs));
                }
            }
            if directive.starts_with("stale-while-revalidate=") {
                if let Ok(secs) = directive[24..].parse::<u64>() {
                    stale_while_revalidate = Some(Duration::from_secs(secs));
                }
            }
            if directive.starts_with("stale-if-error=") {
                if let Ok(secs) = directive[15..].parse::<u64>() {
                    stale_if_error = Some(Duration::from_secs(secs));
                }
            }
        }
    }

    let vary = headers.get("vary")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    (max_age, stale_while_revalidate, stale_if_error, vary)
}
```

### Step 5.5: Wire proxy_cache into MeshProxy.transform_response()

**File**: `src/mesh/proxy.rs`

**In `transform_response()`**, after transforms are applied but before caching in transform_cache:

```rust
// Check proxy_cache for existing cached response (before transforms)
let proxy_cache_key = CacheKey::from_request(
    http::Method::GET,  // transform_response handles GET responses
    "https",  // or "http" based on request
    upstream_id,  // use upstream_id as authority
    request_path,
    response.headers(),  // need to pass original request headers
    "",  // Vary - get from response headers
);

if let Some(ref proxy_cache) = *self.proxy_cache.read() {
    if let Some(cached) = proxy_cache.get(&proxy_cache_key).await {
        tracing::debug!("Proxy cache hit for {}", proxy_cache_key);
        // Return cached response
        return cached.to_response();
    }
}

// ... apply transforms ...

// After applying transforms, store in proxy_cache
if let Some(ref proxy_cache) = *self.proxy_cache.read() {
    if let Err(e) = proxy_cache.insert(proxy_cache_key, &response, &settings).await {
        tracing::warn!("Failed to insert into proxy cache: {}", e);
    }
}
```

**Note**: This adds RFC 7234 proxy caching as a LAYER BEFORE transform caching. The proxy cache stores the ORIGINAL response from origin, and transform caching stores the TRANSFORMED response. This is correct because:
1. Proxy cache handles HTTP caching semantics (freshness, Vary, etc.)
2. Transform cache stores already-transformed content

### Step 5.6: Remove dead proxy_cache field usage

**File**: `src/mesh/proxy.rs`

**Current** (lines 71, 302-336): `proxy_cache` is configured but never used.

**After implementing Step 5.5**, this should be resolved.

---

## Phase Dependencies

```
Phase 1 ───────────────────────────────────────────────────────────┐
                                                                  │
Phase 2 ─────────────────────────────────────────────────────────┤
                                                                  │
Phase 3 ─────────────────────────────────────────────────────────┤
                                                                  │ All feed into Phase 4
Phase 4 ─────────────────────────────────────────────────────────┤
                                                                  │
Phase 5 ─────────────────────────────────────────────────────────┘
```

---

## Files to Modify

| File | Phase(s) | Changes |
|------|----------|---------|
| `src/config/site/misc.rs` | 1 | Add `edge_only` field |
| `src/mesh/transport.rs` | 1 | Publish `edge_only` to DHT |
| `src/mesh/transports/manager.rs` | 1, 3 | Parse `edge_only`, TieredTransformCache |
| `src/mesh/proxy.rs` | 1, 3, 4, 5 | TieredTransformCache, use proxy_cache |
| `src/mesh/transport_peer.rs` | 2 | Add X-MaluWaf-Transformed header |
| `src/http/server.rs` | 2, 4 | Remove IMAGE_POISON_CACHE, use MeshProxy |
| `src/proxy_cache/key.rs` | 5 | RFC 7234 CacheKey with Vary |
| `src/proxy_cache/store.rs` | 5 | RFC 7234 ProxyCacheEntry |
| `src/metrics/mod.rs` | 3 | Add tiered cache metrics |

---

## Verification Steps

### After Phase 1 (Edge Only Poison)

```bash
# Verify origin never poisons
cargo build 2>&1 | grep -i "poison"  # Should only show edge-side poisoning

# Test double-poisoning prevention
# 1. Set edge_only=true on site
# 2. Request image through origin -> edge
# 3. Verify image is only poisoned once
```

### After Phase 2 (X-MaluWaf-Transformed)

```bash
# Verify header is set when origin transforms
# Check response headers contain X-MaluWaf-Transformed when minification/compression applied

# Verify edge skips already-applied transforms
# Request same content twice - second request should hit cache
```

### After Phase 3 (Tiered Caching)

```bash
# Verify L1/L2 promotion works
# 1. Request same content 4+ times
# 2. Check metrics for L1 hits, promotions

cargo test --test integration_test  # Should pass
```

### After Phase 4 (HTTP Uses MeshProxy)

```bash
# Verify single image poison cache
# HTTP server and MeshProxy should share same caching

cargo clippy --lib -- -D warnings  # Should pass
```

### After Phase 5 (RFC 7234 Cache)

```bash
# Test Vary header handling
# Test stale-while-revalidate
# Test stale-if-error

cargo test --test integration_test  # Should pass
```

---

## Rollback Plan

If issues arise during implementation:

1. **Phase 1-2**: Revert `edge_only` to false, remove X-MaluWaf-Transformed header - system falls back to original behavior
2. **Phase 3**: Replace TieredTransformCache with original single-tier Cache
3. **Phase 4**: Restore HTTP server's inline transform code and IMAGE_POISON_CACHE
4. **Phase 5**: Restore proxy_cache dead code state

---

## Performance Considerations

| Aspect | Current | After Phase 3 |
|--------|---------|----------------|
| Cache hit latency | O(1) Moka | O(1) Moka (L1), O(1) Moka (L2) |
| Memory for 500K sites | ~1MB per 1K entries | L1: 10K × avg_entry, L2: 100K × avg_entry |
| DHT queries at steady state | 500K / 300s = 1.7K/s | 500K / 3600s = 139/s (L2 fallback) |
| Cache stampede risk | High (300s TTL) | Low (L1 catches hot content) |

---

## References

- [RFC 7234](https://tools.ietf.org/html/rfc7234) - HTTP/1.1 Caching
- [MDN Vary Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary) - Vary header semantics
- [stale-while-Revalidate](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#stale-while-revalidate) - SWR semantics
- [stale-If-Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#stale-if-error) - SIE semantics

# Proxy Cache Architecture

## 1. Purpose and Responsibility

The Proxy Cache module (`crates/synvoid-proxy-cache/`) provides an **LRU cache for proxied HTTP responses** with disk persistence, cache key generation, TTL-based expiration, stale-while-revalidate, and circuit breaker for revalidation.

**Core Responsibilities:**
- In-memory (moka) + disk response caching
- Configurable cache key generation with hash-prefixed URIs
- TTL-based expiration with `Instant`-based timing
- Stale-while-revalidate and stale-if-error support
- Circuit breaker for backend failures during revalidation
- Vary-by header support
- Per-site memory tracking

---

## 2. Key Data Structures

### ProxyCacheEntry (`crates/synvoid-proxy-cache/src/store.rs:32-43`)

```rust
pub struct ProxyCacheEntry {
    pub content: Bytes,
    pub status: u16,
    pub headers: HeaderMap,           // NOT HashMap<String, String>
    pub created_at: Instant,          // NOT u64
    pub last_accessed: Instant,
    pub expires_at: Option<Instant>,  // None = no TTL
    pub stale_while_revalidate: Option<Instant>,
    pub stale_if_error: Option<Instant>,
    pub content_length: Option<usize>,
    pub is_fresh: bool,
}
```

### CacheKey (`crates/synvoid-proxy-cache/src/key.rs:4-12`)

```rust
pub struct CacheKey {
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub uri: String,      // Contains hash-prefixed value: "format!("{}:{}", hash, uri_str)"
    pub vary: String,
    pub site_id: String,  // NOT Option<String>
}
```

**Important**: The `uri` field is NOT the raw URI. It contains a hash-prefixed value
(`"<ahash_hex>:<path_and_query>"`) to ensure uniqueness when the same path has different
pattern or vary values.

### CacheHit (`crates/synvoid-proxy-cache/src/store.rs:110-117`)

```rust
pub enum CacheHit {
    Hit,
    Miss,
    Expired,
    Stale,
    StaleWhileRevalidate,
}
```

Note: `CacheHit` variants do NOT carry `ProxyCacheEntry` data. They are status-only enums.

### ProxyCacheSettings (`crates/synvoid-proxy-cache/src/config.rs:4-24`)

```rust
pub struct ProxyCacheSettings {
    pub enabled: bool,
    pub path: PathBuf,
    pub max_memory_size: usize,
    pub max_disk_size: usize,
    pub inactive: Duration,
    pub use_temp_file: bool,
    pub valid_status: Vec<u16>,
    pub methods: Vec<String>,
    pub use_stale: Vec<String>,
    pub stale_while_revalidate: Option<Duration>,
    pub stale_if_error: Option<Duration>,
    pub min_uses: u32,
    pub key_pattern: String,
    pub vary_by: Vec<String>,
    pub max_concurrent_revalidations: usize,  // Default: 100
    pub revalidation_failure_threshold: u32,   // Default: 10
    pub revalidation_circuit_breaker_cooldown_secs: u64,  // Default: 30
    pub allowed_headers: Vec<String>,
}
```

### ProxyCache (`crates/synvoid-proxy-cache/src/store.rs:138-155`)

```rust
pub struct ProxyCache {
    entries: Cache<CacheKey, CacheEntryInner>,     // moka cache
    settings: RwLock<ProxyCacheSettings>,
    disk_path: PathBuf,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    current_memory_size: AtomicU64,
    cleanup_shutdown_tx: Arc<tokio::sync::watch::Sender<()>>,
    host_index: DashMap<String, Vec<CacheKey>>,
    inflight_requests: InflightRequestsMap,
    inflight_revalidations: Arc<DashMap<CacheKey, ()>>,
    site_memory_usage: DashMap<String, AtomicU64>,
    revalidation_semaphore: Arc<tokio::sync::Semaphore>,
    revalidation_active: AtomicU64,
    revalidation_queued: AtomicU64,
    revalidation_failures: AtomicU32,
    circuit_open: AtomicBool,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ProxyCache::new(settings)` | Create cache with moka + disk backend |
| `ProxyCacheSettings::from_config(...)` | Construct from site config |
| `CacheKey::new(scheme, method, host, uri, headers, pattern, vary_by, site_id)` | Build cache key with hash-prefixed URI |
| `CacheKeyBuilder::new(pattern, vary_by).build(...)` | Pattern-based key builder |
| `CacheKey::to_cache_string()` | Serialize key to string |
| `CacheKey::from_cache_string(s)` | Deserialize key from string |
| `cache.get(key).await` | Lookup entry (handles SWR/SIE stale logic) |
| `cache.insert(key, content, status, headers, max_age)` | Insert with TTL |
| `cache.invalidate(key)` | Remove single entry |
| `cache.invalidate_by_pattern(pattern)` | Remove entries matching URI pattern |
| `cache.invalidate_by_host(host)` | Remove all entries for a host |
| `cache.stats()` | Get cache statistics |
| `cache.get_hit_status(key)` | Check hit/miss/expired/stale status |

---

## 4. Cache Key Construction

```rust
// Pattern expansion with single-pass replacement
let key = replace_pattern_single_pass(key_pattern, &[
    ("$scheme", scheme),
    ("$request_method", method.as_str()),
    ("$host", host),
    ("$request_uri", &uri_str),
    ("$site_id", site_id),
]);

// Hash computed from expanded key + vary string
let mut hasher = AHasher::default();
Hash::hash(&key, &mut hasher);
Hash::hash(&vary, &mut hasher);
let hash = Hasher::finish(&hasher);

// URI becomes hash-prefixed
uri: format!("{}:{}", hash, uri_str)
```

Default pattern: `"$scheme$request_method$host$site_id$request_uri"`

---

## 5. Integration Points

- **Proxy**: Response caching in proxy pipeline via `handle_request_with_cache()`
- **Config**: Per-site `ProxyCacheSettings` from `SiteConfig.proxy.cache`
- **Metrics**: Cache hit/miss counters (`synvoid.proxy.cache.hit`/`miss`)
- **Circuit Breaker**: Stops revalidation attempts during backend outages
- **Mesh**: `apply_preferences()` for mesh-driven cache configuration

---

## 6. Key Implementation Details

- **Two-tier Cache**: In-memory (moka) + optional disk persistence for large entries
- **LRU Eviction**: moka `weigher` function; disk entries have weight 1, memory entries use byte size
- **Stale-While-Revalidate**: Serve stale content while refreshing in background
- **Stale-If-Error**: Serve stale content when backend is unavailable
- **Circuit Breaker**: Opens after `revalidation_failure_threshold` failures, closes after cooldown
- **Vary Support**: Cache varies by selected headers via `build_vary_key()`
- **Inflight Deduplication**: Concurrent requests for the same key are coalesced via `inflight_requests`
- **Disk Checksums**: `AHasher`-based checksums detect disk corruption
- **Per-Site Memory**: `site_memory_usage` tracks memory consumption per host

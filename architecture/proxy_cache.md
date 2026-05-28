# Proxy Cache Architecture

## 1. Purpose and Responsibility

The Proxy Cache module (`src/proxy_cache/`) provides an **LRU cache for proxied HTTP responses** with disk persistence, cache key generation, TTL-based expiration, stale-while-revalidate, and circuit breaker for revalidation.

**Core Responsibilities:**
- In-memory (moka) + disk response caching
- Configurable cache key generation
- TTL-based expiration
- Stale-while-revalidate support
- Circuit breaker for backend failures
- Vary-by header support

---

## 2. Key Data Structures

```rust
pub struct ProxyCache {
    memory_cache: moka::sync::Cache<String, ProxyCacheEntry>,
    disk_cache: Option<DiskCache>,
}

pub struct ProxyCacheEntry {
    pub content: Bytes,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub stale: bool,
}

pub struct CacheKey {
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub vary: String,
    pub site_id: Option<String>,
}

pub enum CacheHit {
    Hit(ProxyCacheEntry),
    Miss,
    Stale(ProxyCacheEntry),
}

pub struct ProxyCacheSettings {
    pub max_memory_entries: usize,
    pub max_disk_size: usize,
    pub default_ttl: u64,
    pub stale_while_revalidate: u64,
    pub valid_status_codes: Vec<u16>,
    pub valid_methods: Vec<String>,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ProxyCacheSettings::from_config(...)` | Construct from site config |
| `CacheKey::new(scheme, method, host, uri, headers, pattern, vary_by, site_id)` | Build cache key |
| `CacheKeyBuilder::new(pattern, vary_by).build(...)` | Pattern-based key builder |
| `CacheKey::to_cache_string()` | Serialize key |
| `CacheKey::from_cache_string(s)` | Deserialize key |

---

## 4. Integration Points

- **Proxy**: Response caching in proxy pipeline
- **Config**: Per-site cache configuration
- **Metrics**: Cache hit/miss counters
- **Circuit Breaker**: Prevents cache stampede on backend failure

---

## 5. Key Implementation Details

- **Two-tier Cache**: In-memory (moka) + optional disk persistence
- **LRU Eviction**: Least-recently-used entries evicted first
- **Stale-While-Revalidate**: Serve stale content while refreshing
- **Circuit Breaker**: Stops revalidation attempts during backend outages
- **Vary Support**: Cache varies by selected headers

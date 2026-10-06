# Proxy Cache

SynVoid includes a built-in HTTP response cache to reduce upstream load, improve response times, and handle traffic spikes more effectively.

## Overview

The proxy cache:
- **Stores** responses from upstream servers
- **Serves** cached responses for matching requests
- **Invalidates** based on configurable rules
- **Optimizes** with Vary header support

## Configuration

### Basic Configuration

The cache is configured under `[site.proxy.cache]`. There are no `proxy_cache_*` keys
directly in `[site.proxy]` — the implementation is the `synvoid-proxy-cache` crate.

```toml
[site.proxy.cache]
enable = true
```

### Full Configuration

```toml
[site.proxy.cache]
enable = true

# Storage
path = "/var/cache/synvoid/proxy"
max_size = "1G"
memory_max = "256M"
disk_max = "1G"

# Time-to-live
inactive = 3600
valid_status = [200, 301, 302, 304]
methods = ["GET", "HEAD"]
min_uses = 1

# Cache key
key = "$scheme$request_method$host$uri"
vary_by = ["Accept-Encoding", "Accept-Language"]

# Stale-while-revalidate
stale_while_revalidate = 60
stale_if_error = 60

# Options
use_temp_file = true
use_stale = ["error", "timeout", "updating"]
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enable` | - | Enable proxy cache (off unless set) |
| `path` | - | Cache directory path |
| `max_size` | - | Maximum cache size (e.g., "1G") |
| `inactive` | `3600` | Time to keep inactive cache entries |
| `valid_status` | `[200, 301, 302, 304]` | Status codes to cache |
| `methods` | `["GET", "HEAD"]` | HTTP methods to cache |
| `min_uses` | `1` | Minimum requests before caching |
| `key` | - | Custom cache key format |
| `vary_by` | `[]` | Headers to vary on |
| `stale_while_revalidate` | - | Serve stale while revalidating |
| `stale_if_error` | - | Serve stale on upstream errors |
| `memory_max` | - | In-memory size limit |
| `disk_max` | - | On-disk size limit |
| `use_temp_file` | - | Write entries through a temp file |
| `use_stale` | `[]` | Conditions under which a stale entry is served |

## How It Works

### Request Flow

```
Client Request
      │
      ├─ Cache Key Generated
      │
      ├─► Cache Lookup
      │      │
      │   ┌──┴──┐
      │   │     │
      │ HIT   MISS
      │   │     │
      │   │     ▼
      │   │   Upstream Request
      │   │     │
      │   │   Response
      │   │     │
      │   │   ┌──┴──┐
      │   │   │     │
      │   │ CACHEABLE  NOT CACHEABLE
      │   │   │         │
      │   │   ▼         ▼
      │   │ Store     Pass Through
      │   │
      └─ Response
```

### Cache Key Generation

Default cache key uses the full request URL. Custom keys can be configured using variables:

```
$scheme, $request_method, $host, $uri, $args
```

Example:
```
[site.proxy.cache]
key = "$scheme$host$uri$args";
```

## Vary Header Support

When Vary is enabled, SynVoid stores separate cache entries for different header combinations:

```toml
[site.proxy.cache]
vary_by = ["Accept-Encoding", "Accept-Language"]
```

```
GET /api/data
Accept-Encoding: gzip
-> Cache key: ...:gzip

GET /api/data
Accept-Encoding: br
-> Cache key: ...:br (separate entry)
```

## Cache Invalidation

### Automatic Invalidation

Based on response headers:
- `Cache-Control: no-cache`
- `Cache-Control: private`
- `Expires` past
- `Set-Cookie` present

### Manual Invalidation

Cache invalidation is handled via configuration reload or site restart.

## Admin API

Cache statistics are available through the admin metrics API:

```bash
# View cache metrics
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/metrics
```

### Cache Metrics

There is no `synvoid_cache*` Prometheus metric family. Cache counters are exposed as
fields of the admin metrics payload (`crates/synvoid-metrics/src/payloads.rs`):

| Field | Description |
|-------|-------------|
| `proxy_cache_hits` | Cache hits |
| `proxy_cache_misses` | Cache misses |
| `cache_hit_rate` | Derived hit ratio |

Cache-level queueing/revalidation counters are reported per cache in the `CacheStats`
structure (`cpu_offload_queued_minify`, `cpu_offload_active_minify`,
`cpu_offload_completed_minify` and peers).

## Use Cases

### Static Content

Cache static assets aggressively:

```toml
[site.proxy.cache]
enable = true
inactive = 86400
valid_status = [200, 304]
```

### API Responses

Cache API responses with shorter TTL:

```toml
[site.proxy.cache]
enable = true
inactive = 60
valid_status = [200]
min_uses = 3
```

### User-Specific Content

Use Vary for user-specific caching:

```toml
[site.proxy.cache]
enable = true
vary_by = ["Accept-Language"]
valid_status = [200]
```

## Performance Considerations

### Memory vs Disk

The cache can use both memory and disk:
- **Memory**: Faster but limited by `memory_max`
- **Disk**: Larger storage via `disk_max`

### Hit Rate Optimization

1. **Use appropriate TTLs** - Static = long TTL, Dynamic = short
2. **Minimize Vary headers** - Each header creates separate entries
3. **Set `min_uses`** - Avoid caching one-off requests
4. **Monitor eviction rate** - Adjust `max_size` if too high

## Best Practices

1. **Know Your Content** - Static = long TTL, Dynamic = short
2. **Monitor Hit Rate** - Target 70%+ for good performance
3. **Set Appropriate Limits** - Balance memory vs performance
4. **Use Vary Carefully** - Too many variants hurts cache
5. **Invalidate Strategically** - Clear cache on deployments

## See Also

- [STATIC_FILES.md](./STATIC_FILES.md) - Static file serving
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance optimization
- [CONFIGURATION.md](./CONFIGURATION.md) - Cache configuration

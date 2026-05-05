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

```toml
[site.proxy]
proxy_cache_enable = true
```

### Full Configuration

```toml
[site.proxy]
proxy_cache_enable = true

# Storage
proxy_cache_path = "/var/cache/synvoid/proxy"
proxy_cache_max_size = "1G"
proxy_cache_memory_max = "256M"
proxy_cache_disk_max = "1G"

# Time-to-live
proxy_cache_inactive = 3600
proxy_cache_valid_status = [200, 301, 302, 304]
proxy_cache_methods = ["GET", "HEAD"]
proxy_cache_min_uses = 1

# Cache key
proxy_cache_key = "$scheme$request_method$host$uri"
proxy_cache_vary_by = ["Accept-Encoding", "Accept-Language"]

# Stale-while-revalidate
proxy_cache_stale_while_revalidate = 60
proxy_cache_stale_if_error = 60

# Options
proxy_cache_use_temp_file = true
proxy_cache_use_stale = ["error", "timeout", "updating"]
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `proxy_cache_enable` | `false` | Enable proxy cache |
| `proxy_cache_path` | - | Cache directory path |
| `proxy_cache_max_size` | - | Maximum cache size (e.g., "1G") |
| `proxy_cache_inactive` | `3600` | Time to keep inactive cache entries |
| `proxy_cache_valid_status` | `[200, 301, 302, 304]` | Status codes to cache |
| `proxy_cache_methods` | `["GET", "HEAD"]` | HTTP methods to cache |
| `proxy_cache_min_uses` | `1` | Minimum requests before caching |
| `proxy_cache_key` | - | Custom cache key format |
| `proxy_cache_vary_by` | `[]` | Headers to vary on |
| `proxy_cache_stale_while_revalidate` | - | Serve stale while revalidating |
| `proxy_cache_stale_if_error` | - | Serve stale on upstream errors |

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
proxy_cache_key = "$scheme$host$uri$args";
```

## Vary Header Support

When Vary is enabled, SynVoid stores separate cache entries for different header combinations:

```toml
proxy_cache_vary_by = ["Accept-Encoding", "Accept-Language"]
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

Cache statistics are available through Prometheus metrics:

```bash
# View cache metrics
curl http://localhost:9090/metrics | grep synvoid_cache
```

### Prometheus Metrics

```bash
synvoid.proxy.cache.hit                   # Cache hits
synvoid.proxy.cache.miss                  # Cache misses
synvoid.proxy.cache.stale_while_revalidate # Stale-while-revalidate served
```

## Use Cases

### Static Content

Cache static assets aggressively:

```toml
[site.proxy]
proxy_cache_enable = true
proxy_cache_inactive = 86400
proxy_cache_valid_status = [200, 304]
```

### API Responses

Cache API responses with shorter TTL:

```toml
[site.proxy]
proxy_cache_enable = true
proxy_cache_inactive = 60
proxy_cache_valid_status = [200]
proxy_cache_min_uses = 3
```

### User-Specific Content

Use Vary for user-specific caching:

```toml
[site.proxy]
proxy_cache_enable = true
proxy_cache_vary_by = ["Accept-Language"]
proxy_cache_valid_status = [200]
```

## Performance Considerations

### Memory vs Disk

The cache can use both memory and disk:
- **Memory**: Faster but limited by `proxy_cache_memory_max`
- **Disk**: Larger storage via `proxy_cache_disk_max`

### Hit Rate Optimization

1. **Use appropriate TTLs** - Static = long TTL, Dynamic = short
2. **Minimize Vary headers** - Each header creates separate entries
3. **Set `proxy_cache_min_uses`** - Avoid caching one-off requests
4. **Monitor eviction rate** - Adjust max_size if too high

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

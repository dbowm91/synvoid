# Proxy Cache

MaluWAF includes a built-in HTTP response cache to reduce upstream load, improve response times, and handle traffic spikes more effectively.

## Overview

The proxy cache:
- **Stores** responses from upstream servers
- **Serves** cached responses for matching requests
- **Invalidates** based on configurable rules
- **Optimizes** with vary header support

## Configuration

### Basic Configuration

```toml
[defaults.proxy_cache]
enabled = true
max_entries = 10000
max_size_mb = 512
ttl_secs = 300
```

### Full Configuration

```toml
[defaults.proxy_cache]
enabled = true

# Storage limits
max_entries = 10000
max_size_mb = 512

# Time-to-live
ttl_secs = 300           # Default TTL
min_ttl_secs = 60        # Minimum TTL
max_ttl_secs = 3600      # Maximum TTL

# Response matching
[defaults.proxy_cache.match]
status_codes = [200, 201, 301, 302]
methods = ["GET", "HEAD"]
headers = ["Accept-Encoding"]

# Vary header support
[defaults.proxy_cache.vary]
enabled = true
headers = ["Accept-Encoding", "Accept-Language", "Cookie"]

# Cache key
[defaults.proxy_cache.key]
include_query = true
include_method = true
include_headers = ["Accept-Encoding"]
```

### Per-Site Configuration

```toml
# config/sites/example.com.toml
[site.proxy_cache]
enabled = true
max_entries = 5000
ttl_secs = 600  # Longer TTL for static content
```

## Configuration Options

### Basic Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable proxy cache |
| `max_entries` | `10000` | Maximum cached entries |
| `max_size_mb` | `512` | Maximum cache size in MB |
| `ttl_secs` | `300` | Default TTL in seconds |

### TTL Options

| Option | Default | Description |
|--------|---------|-------------|
| `ttl_secs` | `300` | Default time-to-live |
| `min_ttl_secs` | `0` | Minimum TTL |
| `max_ttl_secs` | `86400` | Maximum TTL |

### Match Options

| Option | Default | Description |
|--------|---------|-------------|
| `status_codes` | `[200]` | Status codes to cache |
| `methods` | `["GET"]` | Methods to cache |
| `headers` | `[]` | Headers that trigger no-cache |

### Vary Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable Vary header support |
| `headers` | `[]` | Headers to vary on |

### Cache Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `include_query` | `true` | Include query string |
| `include_method` | `false` | Include HTTP method |
| `include_headers` | `[]` | Include headers in key |

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

Default cache key format:
```
{METHOD}:{URL}?{QUERY}:{ACCEPT_ENCODING}
```

Example:
```
GET:/api/users:application/json,gzip
```

## Cache Invalidation

### By URL Pattern

```toml
[site.proxy_cache.invalidate]
patterns = [
    "/api/cache/*",
    "/static/*"
]
```

### On Demand

```bash
# Invalidate specific URL
curl -X POST -H "Authorization: Bearer <token>" \
  -d '{"url": "/api/users/123"}' \
  http://localhost:8081/api/cache/invalidate

# Invalidate by pattern
curl -X POST -H "Authorization: Bearer <token>" \
  -d '{"pattern": "/api/cache/*"}' \
  http://localhost:8081/api/cache/invalidate
```

### Automatic Invalidation

Based on response headers:

- `Cache-Control: no-cache`
- `Cache-Control: private`
- `Expires` past
- `Set-Cookie` present (when configured)

## Vary Header Support

When Vary is enabled, MaluWAF stores separate cache entries for different header combinations:

```
GET /api/data
Accept-Encoding: gzip
-> Cache key: ...:gzip

GET /api/data  
Accept-Encoding: br
-> Cache key: ...:br (separate entry)
```

### Configuration

```toml
[defaults.proxy_cache.vary]
enabled = true
headers = [
    "Accept-Encoding",
    "Accept-Language", 
    "Accept"
]
```

## Admin API

Cache management endpoints are currently not exposed via the Admin API. Cache behavior can be configured through:

1. **Configuration files** - Set cache parameters in `main.toml` or site configs
2. **Cache-Control headers** - Upstream responses with appropriate headers control caching
3. **Configuration reload** - Use `POST /api/config/reload` after config changes

### Monitoring Cache via Metrics

Cache statistics are available through Prometheus metrics on port 9090:

```bash
# View cache metrics
curl http://localhost:9090/metrics | grep maluwaf_cache
```

## Prometheus Metrics

```bash
maluwaf.proxy.cache.hit                   # Cache hits
maluwaf.proxy.cache.miss                  # Cache misses
maluwaf.proxy.cache.stale_while_revalidate # Stale-while-revalidate served
```

## Use Cases

### Static Content

Cache static assets aggressively:

```toml
# config/sites/static.example.com.toml
[site.proxy_cache]
enabled = true
ttl_secs = 86400  # 24 hours
max_size_mb = 2048

[site.proxy_cache.match]
status_codes = [200, 304]
methods = ["GET", "HEAD"]
```

### API Responses

Cache API responses with shorter TTL:

```toml
# config/sites/api.example.com.toml
[site.proxy_cache]
enabled = true
ttl_secs = 60   # 1 minute
max_entries = 1000

[site.proxy_cache.match]
status_codes = [200]
methods = ["GET"]
```

### User-Specific Content

Use vary for user-specific caching:

```toml
[site.proxy_cache]
enabled = true

[site.proxy_cache.vary]
enabled = true
headers = ["Accept-Language"]

# Exclude private responses
[site.proxy_cache.match]
headers = ["Cookie"]  # If present, don't cache
```

## Performance Considerations

### Memory Usage

Approximate cache size:
- Each entry: ~1KB metadata + response size
- 10,000 entries at 50KB avg: ~500MB

### Disk vs Memory

Currently memory-only. For larger caches:
- Reduce TTL
- Increase eviction
- Use CDN upstream

## Troubleshooting

### Cache Not Working

1. Check cache is enabled
2. Verify method is GET/HEAD
3. Check status code is cacheable
4. Look for no-cache headers

### Low Hit Rate

1. Too many unique URLs
2. TTL too short
3. Query strings vary too much
4. Vary headers too broad

### Memory Growth

1. Reduce max_entries
2. Reduce TTL
3. Monitor eviction rate

### Stale Data

1. Check TTL settings
2. Verify upstream sends proper headers
3. Implement manual invalidation

## Integration

### With Traffic Shaping

```toml
[proxy_cache]
enabled = true
ttl_secs = 300

[traffic_shaping]
enabled = true
max_rate_mbps = 100
```

Cached responses bypass traffic shaping limits.

### With Rate Limiting

```toml
[proxy_cache]
enabled = true
ttl_secs = 300

[ratelimit]
enabled = true
per_second = 10
```

Cached responses still count against rate limits.

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
- [RATE_LIMITING.md](./RATE_LIMITING.md) - Rate limiting with caching

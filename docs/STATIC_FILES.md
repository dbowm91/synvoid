# Static Files & Optimization

MaluWAF provides built-in static file serving with automatic optimization features including minification, compression, and caching.

## Overview

MaluWAF can serve static files directly with the following optimizations:

- **Minification** - Remove whitespace and comments from HTML, CSS, and JavaScript
- **Compression** - Serve pre-compressed versions (gzip, Brotli) or compress on-the-fly
- **Caching** - Efficient caching with ETags and Last-Modified headers
- **Security** - Prevent directory traversal and unauthorized access

## Configuration

### Basic Static File Configuration

```toml
[site.static]
enabled = true
root = "/var/www/static"
```

### Full Configuration

```toml
[site.static]
enabled = true
root = "/var/www/static"

# Minification
enable_minification = true
enable_html_minification = true
enable_css_minification = true
enable_js_minification = true

# Compression
enable_compression = true
compression_min_size = 1024  # Only compress files larger than 1KB

# Caching
cache_enabled = true
cache_ttl_secs = 3600
cache_max_size_mb = 512

# Directories
index_files = ["index.html", "index.htm"]
```

## Minification

### How It Works

When minification is enabled, MaluWAF automatically minifies static files before serving:

| Type | What It Does | Savings |
|------|-------------|---------|
| HTML | Removes comments, whitespace, optional tags | 20-30% |
| CSS | Removes comments, whitespace, shortens colors | 20-30% |
| JavaScript | Removes comments, whitespace, shortens variables | 20-40% |

### Configuration

```toml
[site.static]
enable_minification = true
enable_html_minification = true
enable_css_minification = true
enable_js_minification = true

# Cache minified files
minified_dir = "/var/cache/maluwaf/minified"
```

### Performance

Minification is performed:
- **First request**: On-the-fly, may add latency
- **Subsequent requests**: Served from cache

For best performance, pre-minify during build:

```bash
# Pre-minify your static files
npx minify-html index.html > index.min.html
npx minify-css styles.css > styles.min.css
npx minify-js app.js > app.min.js
```

## Compression

### Pre-Compressed Files

MaluWAF automatically serves pre-compressed files if they exist:

```
/var/www/static/
├── index.html
├── index.html.gz      # gzip version
├── index.html.br      # Brotli version
├── styles.css
├── styles.css.gz
└── app.js
```

When a client sends `Accept-Encoding: br, gzip`, MaluWAF checks for pre-compressed versions first.

### Compression Priority

1. **Pre-compressed Brotli** (`.br`) - Best compression
2. **Pre-compressed gzip** (`.gz`) - Good compression
3. **On-the-fly compression** - Uses CPU, slower
4. **Uncompressed** - Fallback

### Creating Pre-Compressed Files

```bash
# Gzip compression
gzip -k -f index.html styles.css app.js

# Brotli compression (better compression)
brotli -k -f index.html styles.css app.js
```

### On-the-Fly Compression

If pre-compressed files aren't available, MaluWAF can compress on-the-fly:

```toml
[site.static]
enable_compression = true
compression_min_size = 1024  # Minimum size to compress
```

**Note**: On-the-fly compression uses CPU. Pre-compressed files are recommended for production.

## Caching

### Cache Configuration

```toml
[site.static]
cache_enabled = true
cache_ttl_secs = 3600  # 1 hour default
cache_max_size_mb = 512
```

### Cache Headers

MaluWAF automatically sets appropriate cache headers:

| Header | Value |
|--------|-------|
| `Cache-Control` | `public, max-age=3600` |
| `ETag` | File hash |
| `Last-Modified` | File modification time |

### Cache Invalidation

```bash
# Clear all static cache
curl -X POST -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/cache/clear

# Clear specific site cache
curl -X POST -H "Authorization: Bearer <token>" \
  -d '{"site": "example.com"}' \
  http://localhost:8081/api/cache/clear
```

## Security

### Path Traversal Protection

MaluWAF automatically blocks path traversal attempts:

```bash
# This will be blocked
curl "http://localhost/../../etc/passwd"
# Returns: 403 Forbidden
```

### Forbidden Files

Block access to sensitive files:

```toml
[site.static]
forbidden_files = [".htaccess", ".git", ".env"]
```

### Example: Complete Static Site Configuration

```toml
[site.static]
enabled = true
root = "/var/www/static"

# Optimization
enable_minification = true
enable_html_minification = true
enable_css_minification = true
enable_js_minification = true
enable_compression = true

# Performance
cache_enabled = true
cache_ttl_secs = 86400  # 24 hours

# Security
forbidden_files = [".git", ".svn", ".env", "wp-config.php"]

# Index
index_files = ["index.html"]
```

## Monitoring

### Metrics

```bash
# View static file metrics
curl http://localhost:9090/metrics | grep maluwaf_static

# Key metrics
maluwaf_static_requests_total    # Total requests
maluwaf_static_bytes_served      # Bytes served
maluwaf_static_cache_hits       # Cache hits
maluwaf_static_cache_misses      # Cache misses
maluwaf_static_compression_saved # Bytes saved by compression
```

### Logs

Static file access is logged in the access log:

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "method": "GET",
  "path": "/static/styles.css",
  "status": 200,
  "size": 12345,
  "compressed": true,
  "minified": true,
  "cached": true
}
```

## Performance Tuning

### Recommended Settings

**High Traffic Site:**
```toml
[site.static]
enable_minification = true
enable_compression = true
cache_enabled = true
cache_ttl_secs = 86400  # 24 hours

# Pre-compress during build, don't compress on-the-fly
```

**Low Traffic Site:**
```toml
[site.static]
enable_minification = true
enable_compression = true
cache_enabled = true
cache_ttl_secs = 3600
```

**Development:**
```toml
[site.static]
enable_minification = false
enable_compression = false
cache_enabled = false
```

## Troubleshooting

### Files Not Being Served

1. Check static is enabled: `enable_static = true`
2. Verify root path exists and is readable
3. Check file permissions

```bash
# Verify path
ls -la /var/www/static

# Check logs
tail -f /var/log/maluwaf/access.log | grep static
```

### Minification Not Working

1. Ensure minification is enabled
2. Check file types (HTML, CSS, JS only)
3. Verify cache directory is writable

```toml
[site.static]
enable_minification = true
minified_dir = "/var/cache/maluwaf/minified"
```

### Compression Not Working

1. Check client sends `Accept-Encoding` header
2. Verify pre-compressed files exist or on-the-fly compression is enabled
3. Check file isn't already compressed (e.g., .zip)

```bash
# Test with compression
curl -H "Accept-Encoding: gzip" -I http://localhost/static/app.js

# Should show:
# Content-Encoding: gzip
```

### Cache Not Working

1. Verify cache is enabled
2. Check cache directory is writable
3. Ensure TTL is appropriate

```bash
# Check cache directory
ls -la /var/cache/maluwaf/

# Clear cache
curl -X POST -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/cache/clear
```

## Integration with Build Process

### Example: Build Script

```bash
#!/bin/bash
STATIC_DIR="/var/www/static"

# Minify HTML
for f in $(find $STATIC_DIR -name "*.html"); do
    minify-html -o "${f%.html}.min.html" "$f"
    mv "${f%.html}.min.html" "$f"
done

# Minify and compress CSS
for f in $(find $STATIC_DIR -name "*.css"); do
    minify-css -o "$f.min" "$f"
    gzip -k -f "$f.min"
    brotli -k -f "$f.min"
    mv "$f.min" "$f"
done

# Minify and compress JS
for f in $(find $STATIC_DIR -name "*.js"); do
    minify-js -o "$f.min" "$f"
    gzip -k -f "$f.min"
    brotli -k -f "$f.min"
    mv "$f.min" "$f"
done
```

### Example: Nginx Comparison

If you're migrating from Nginx:

| Nginx Directive | MaluWAF Equivalent |
|-----------------|-------------------|
| `gzip on` | `enable_compression = true` |
| `gzip_types text/html` | Automatic |
| `expires 24h` | `cache_ttl_secs = 86400` |
| `add_header Cache-Control` | Automatic |
| `minify on` | `enable_minification = true` |

## See Also

- [PROXY_CACHE.md](./PROXY_CACHE.md) - Response caching configuration
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance optimization tips
- [CONFIGURATION.md](./CONFIGURATION.md) - Static file serving options

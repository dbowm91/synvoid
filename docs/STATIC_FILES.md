# Static Files & Optimization

MaluWAF provides built-in static file serving with automatic optimization features including minification, compression, and caching.

## Overview

MaluWAF can serve static files directly with the following optimizations:

- **Minification** - Remove whitespace and comments from HTML, CSS, and JavaScript
- **Compression** - Serve pre-compressed versions (gzip, Brotli) or compress on-the-fly
- **Caching** - Efficient caching with ETags and Last-Modified headers
- **Security** - Prevent directory traversal and unauthorized access
- **Directory Listing** - Customizable file browser with themes

## Configuration

### Basic Static File Configuration

```toml
[site.static]
enabled = true
default_root = "/var/www/static"
```

### Full Configuration

```toml
[site.static]
enabled = true
default_root = "/var/www/static"

# File handling
max_file_size = "100M"
allow_symlinks = false
block_hidden_files = true

# Compression
enable_compression = true
compression_min_size = 256
gzip_on_the_fly = true
gzip_level = 5
gzip_min_size = 256
gzip_types = ["text/html", "text/css", "application/javascript", ...]
enable_brotli = true
brotli_level = 11
enable_svg_compression = true

# Caching
enable_file_cache = true
cache_max_entries = 10000
cache_ttl_seconds = 3600

# Minification
enable_minification = true
enable_html_minification = true
enable_css_minification = true
enable_js_minification = true

# Directory listing
directory_listing = true
directory_listing_format = "json"

# File watching (for development)
enable_file_watching = true
watch_interval_ms = 5000

# Preload on startup
preload_on_startup = true

# Locations (per-path overrides)
[[site.static.locations]]
path = "/assets"
root = "/var/www/assets"
index = "index.html"
cache_ttl = 86400
```

### Per-Location Configuration

```toml
[[site.static.locations]]
path = "/api/static"
root = "/var/www/api_static"
index = "index.html"
try_files = ["{path}", "{path}/index.html", "/404.html"]
cache_ttl = 3600

[[site.static.locations]]
path = "/images"
root = "/var/www/images"
cache_ttl = 86400

[site.static.locations[0].theme]
preset = "dark"
```

## Directory Listing Theme

MaluWAF supports customizable directory listing with themes:

```toml
[site.static.theme]
preset = "dark"  # or "light"

# Or use custom template
directory_template_path = "/etc/maluwaf/templates/directory.html"
```

**Available presets:** `dark`, `light`

**Template placeholders:**
- `{{url_path}}` - current URL path
- `{{parent_link}}` - parent directory link
- `{{rows}}` - file/folder entries
- `{{site_name}}` - site name (RustWAF)
- `{{title}}` - page title ("Index of {url_path}")

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

## Caching

### Cache Configuration

```toml
[site.static]
enable_file_cache = true
cache_max_entries = 10000
cache_ttl_seconds = 3600
```

### Cache Headers

MaluWAF automatically sets appropriate cache headers:

| Header | Value |
|--------|-------|
| `Cache-Control` | `public, max-age=<ttl>` |
| `ETag` | File hash |
| `Last-Modified` | File modification time |

## Security

### Path Traversal Protection

MaluWAF automatically blocks path traversal attempts:

```bash
# This will be blocked
curl "http://localhost/../../etc/passwd"
# Returns: 403 Forbidden
```

### Forbidden Files

Block access to sensitive files by not placing them in the static root, or use `block_hidden_files`:

```toml
[site.static]
block_hidden_files = true  # Blocks .htaccess, .git, .env, etc.
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

## Performance Tuning

### Recommended Settings

**High Traffic Site:**
```toml
[site.static]
enable_file_cache = true
cache_ttl_seconds = 86400
enable_compression = true
gzip_on_the_fly = false  # Pre-compress instead
```

**Development:**
```toml
[site.static]
enable_file_cache = false
enable_minification = false
enable_compression = false
enable_file_watching = true
```

## Integration with Build Process

### Example: Build Script

```bash
#!/bin/bash
STATIC_DIR="/var/www/static"

# Compress CSS
for f in $(find $STATIC_DIR -name "*.css"); do
    gzip -k -f "$f"
    brotli -k -f "$f"
done

# Compress JS
for f in $(find $STATIC_DIR -name "*.js"); do
    gzip -k -f "$f"
    brotli -k -f "$f"
done
```

### Example: Nginx Comparison

If you're migrating from Nginx:

| Nginx Directive | MaluWAF Equivalent |
|-----------------|-------------------|
| `gzip on` | `enable_compression = true` |
| `gzip_types text/html` | Automatic |
| `expires 24h` | `cache_ttl_seconds = 86400` |
| `add_header Cache-Control` | Automatic |
| `autoindex on` | `directory_listing = true` |

## See Also

- [PROXY_CACHE.md](./PROXY_CACHE.md) - Response caching configuration
- [PERFORMANCE.md](./PERFORMANCE.md) - Performance optimization tips
- [CONFIGURATION.md](./CONFIGURATION.md) - Static file serving options

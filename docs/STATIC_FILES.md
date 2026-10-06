# Static Files & Optimization

SynVoid provides built-in static file serving with automatic optimization features including minification, compression, and caching.

## Overview

SynVoid can serve static files directly with the following optimizations:

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
gzip_types = ["text/html", "text/css", "application/javascript", "application/json"]
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

Per-location theme settings go **inside** the `[[site.static.locations]]` element as an inline
table.

> The array-index sub-table form (`[site.static.locations[0].theme]`) is **rejected by
> SynVoid's TOML parser**.

```toml
[[site.static.locations]]
path = "/api/static"
root = "/var/www/api_static"
index = "index.html"
try_files = ["{path}", "{path}/index.html", "/404.html"]
cache_ttl = 3600
theme = { preset = "dark" }

[[site.static.locations]]
path = "/images"
root = "/var/www/images"
cache_ttl = 86400
```

## Directory Listing Theme

SynVoid supports customizable directory listing with themes:

```toml
[site.static.theme]
preset = "dark"  # or "light"

# Or use custom template
directory_template_path = "/etc/synvoid/templates/directory.html"
```

**Available presets:** `dark`, `light`

**Template placeholders:**
- `{{url_path}}` - current URL path
- `{{parent_link}}` - parent directory link
- `{{rows}}` - file/folder entries
- `{{title}}` - page title ("Index of {url_path}")

## Minification

### Worker Architecture

Minification is CPU-bound, so it is offloaded to the CPU worker process
(`--cpu-worker`) rather than executed on the unified worker's event loop. The
minifier itself lives in the `synvoid-static-files` crate (`src/static_files/`
re-exports it as a facade):

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNIFIED WORKER (HTTP/HTTPS)                    │
│  - Handles incoming requests                                      │
│  - Serves minified files from the file cache                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ IPC (CPU task offload)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CPU WORKER                                     │
│  - Runs minification off the request event loop                   │
│  - Returns minified content to the unified worker                │
│  - The unified worker owns the in-process file cache              │
└─────────────────────────────────────────────────────────────────┘
```

**Why it is offloaded:**
- Minification (HTML, CSS, JS) is CPU-intensive and would block the main event loop
- The CPU worker keeps the HTTP worker responsive under load
- Results are returned to the unified worker, which owns the file cache

Note: there is **no** separate "static file worker" process, and the minified content
is not held in a cross-process shared-memory cache. Offload progress is visible as the
`cpu_offload_queued_minify` / `cpu_offload_active_minify` / `cpu_offload_completed_minify`
counters in `CacheStats`.

### How It Works

1. When a static file is first requested, the unified worker checks if minification is enabled
2. If enabled and the file type matches (`text/html`, `text/css`, `application/javascript`), the worker:
   - Offloads the file content to the CPU worker
   - The CPU worker minifies the content
   - The unified worker stores the result in its file cache
3. Subsequent requests serve directly from cache (no offload round-trip)

### Cache Behavior

- Minified content is cached per-file based on file path + modification time
- If the source file changes, the cache is invalidated automatically
- Cache TTL matches the static file cache TTL (`cache_ttl_seconds`)

### Performance Notes

- **First request**: Slight delay (one CPU offload round-trip) for minification
- **Subsequent requests**: No overhead (served from cache)
- **File changes**: Next request triggers re-minification, then cached again
- For highest traffic files, consider pre-minifying at build time instead
- `minified_dir` (site) / `minified_base_dir` (main `[static]`) set where minified
  artifacts are written

## Compression

### Pre-Compressed Files

SynVoid automatically serves pre-compressed files if they exist:

```
/var/www/static/
├── index.html
├── index.html.gz      # gzip version
├── index.html.br      # Brotli version
├── styles.css
├── styles.css.gz
└── app.js
```

When a client sends `Accept-Encoding: br, gzip`, SynVoid checks for pre-compressed versions first.

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

SynVoid automatically sets appropriate cache headers:

| Header | Value |
|--------|-------|
| `Cache-Control` | `public, max-age=<ttl>` |
| `ETag` | File hash |
| `Last-Modified` | File modification time |

## Security

### Path Traversal Protection

Traversal attempts are blocked by the WAF path-traversal detector, not by a static-handler
check. With `[attack_detection] action = "block"` the response is HTTP 403 with the body
`Attack Detected`. Send a browser-like `User-Agent` — a default curl request is matched by
the bot scraper patterns and TARPITTED first (HTTP 200, body `Tarpit active`):

```bash
# This will be blocked by [attack_detection.path_traversal]
curl -A "Mozilla/5.0" "http://localhost/../../etc/passwd"
# Returns: 403 Forbidden, body "Attack Detected"
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
# View static file metrics via the admin metrics API
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8081/api/metrics

# Prometheus scrape (metrics listener, port 9090 in config/main.toml)
curl http://localhost:9090/metrics | grep -i static
```

There is no `synvoid_static_*` Prometheus metric family. Static counters are fields of
the admin metrics payload (`crates/synvoid-metrics/src/payloads.rs`):

| Field | Description |
|-------|-------------|
| `static_cache_hits` | File cache hits |
| `static_cache_misses` | File cache misses |
| `bytes_sent` | Bytes served |

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

| Nginx Directive | SynVoid Equivalent |
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

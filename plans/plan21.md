# Web App Stack Enhancement Plan - MaluWAF

**Last updated**: 2026-04-23
**Status**: PENDING

## Overview

This plan addresses enhancing the built-in web app stack for serving backend applications. The goal is to provide configurable, production-ready backends for static websites (with directory viewer), PHP-FPM, FastCGI, WASM serverless functions, and Python ASGI applications via Granian.

**Key findings**:
- All backends are implemented and functional
- Directory listing has two code paths (simple vs theme-aware) - decision: keep both, opt-in to theme
- Granian workers are not per-site configurable
- FastCGI pool timeouts are not configurable via TOML

---

## Current State Analysis

### Backend Implementation Status

| Backend | Status | Location | Config File |
|---------|--------|----------|-------------|
| **Static Files** | ✅ Implemented | `src/static_files/mod.rs` | `src/config/site/static_files.rs` |
| **Directory Listing** | ⚠️ Two implementations | `src/static_files/directory.rs` + `src/theme/dir_listing.rs` | Inherits theme from `SiteStaticThemeConfig` |
| **PHP-FPM** | ✅ Full | `src/php/mod.rs` | `src/config/site/backend.rs` |
| **FastCGI** | ✅ Pooled | `src/fastcgi/mod.rs`, `pool.rs` | `src/config/site/backend.rs` |
| **WASM/Serverless** | ✅ Full | `src/serverless/manager.rs` | `src/config/serverless.rs` |
| **Granian** | ✅ Implemented | `src/app_server/granian.rs` | `src/config/site/app_server.rs` |

### Directory Listing: Two Code Paths

| Implementation | File | Features |
|---------------|------|----------|
| **Simple** | `src/static_files/directory.rs` | Template placeholders, file icons, basic HTML/JSON |
| **Theme-aware** | `src/theme/dir_listing.rs` | Full pagination, sorting, filtering, ThemeRenderer CSS |

**Decision**: Keep both implementations. Simple version for minimal use cases; theme-aware version when `SiteStaticThemeConfig` is configured.

---

## Theme System Integration

### Theme Architecture

**Location**: `src/theme/`

| Component | File | Purpose |
|-----------|------|---------|
| ThemeConfig | `config.rs` | Colors, presets, spacing, effects, branding |
| ThemeRenderer | `renderer.rs` | CSS generation, SVG icons, theme toggle |
| DirectoryListingTemplate | `dir_listing.rs` | Theme-aware directory listing with sorting/pagination |

### Theme Presets

| Preset | Dark BG | Primary | Description |
|--------|---------|---------|-------------|
| `default` | #0a0a0f | #e94560 | Red accent (same as dark) |
| `dark` | #0a0a0f | #e94560 | Dark theme |
| `light` | #f8fafc | #c41e3a | Light theme |
| `ocean` | #0c1929 | #0ea5e9 | Blue tones |
| `forest` | #0a1a0f | #22c55e | Green tones |
| `sunset` | #1a0f0a | #f97316 | Orange tones |

### Theme Configuration Levels

| Level | Config Location | Scope |
|-------|-----------------|-------|
| Global | `config/main.toml` → `[defaults.theme]` | All sites |
| Per-Site | `[site.theme]` | Single site |
| Per-Location | `[site.static.locations[0].theme]` | Specific path |

### Directory Listing Placeholders

**For custom templates** (`src/static_files/directory.rs`):
```toml
{{url_path}}     # Current path (e.g., "/images/")
{{parent_link}}  # HTML link to parent directory
{{rows}}         # File/folder entries as HTML <tr> elements
{{site_name}}    # Site identifier (default: "MaluWAF")
{{title}}        # Page title (e.g., "Index of /images/")
```

**For CSS theme integration** (`src/theme/dir_listing.rs`):
- Uses `ThemeRenderer::generate_css()` which produces CSS custom properties
- All directory listings get `--waf-*` CSS variables automatically

---

## Investigation Summary

### 1. Static Files Handler

**Location**: `src/static_files/mod.rs`

Key components:
- `StaticFileHandler` - main handler with path resolution
- `NormalizedLocation` - per-location config
- `RangeState` - byte range request state

Features:
- Path traversal protection (canonicalization)
- Hidden file blocking (default: true)
- Symlink support (configurable)
- Pre-compressed file serving (.br, .gz)
- On-the-fly gzip compression
- ETag/Last-Modified caching
- Range request support
- Zero-copy file serving (>4KB on Unix)

### 2. Directory Listing Integration

**Simple path** (`src/static_files/directory.rs`):
```rust
pub fn render_custom_template(
    template: &str,
    url_path: &str,
    entries: &[DirectoryEntry],
) -> Result<String, StaticError>
```

**Theme-aware path** (`src/static_files/mod.rs:385-415`):
```rust
pub fn render_directory_listing(
    &self,
    path: &Path,
    url_path: &str,
    request: &parts::Request,
) -> Result<Response, StaticError>
```

Currently, `render_directory_listing()` uses the simple template renderer when `self.config.directory_template` is set. The theme-aware version is in `src/theme/dir_listing.rs` but not integrated.

### 3. PHP-FPM Implementation

**Location**: `src/php/mod.rs`

Key types:
- `PhpClient` - core execution struct
- `PhpLocationConfig` - per-location overrides
- `COMMON_PHP_SOCKETS` - auto-detection of PHP-FPM sockets

**Pooled via FastCGI**:
```rust
fastcgi::get_pool(socket, config)
```

Security settings passed via FastCGI params:
- `PHP_ADMIN_VALUE`: `disable_functions`, `open_basedir` (cannot be overridden)
- `PHP_VALUE`: `allow_url_fopen`, `max_execution_time`, `memory_limit`, etc.

### 4. FastCGI Pool Configuration

**Location**: `src/fastcgi/pool.rs`

```rust
pub struct FastCgiPoolConfig {
    pub max_connections: usize,           // Default: 10
    pub connection_timeout: Duration,     // Default: 5s
    pub health_check_interval: Duration, // Default: 30s (NOT CONFIGURABLE)
    pub health_check_timeout: Duration,   // Default: 3s (NOT CONFIGURABLE)
    pub max_idle_time: Duration,          // Default: 300s (NOT CONFIGURABLE)
    pub socket: String,
}
```

**Gap**: Only `max_connections` and `connection_timeout` are configurable via `FastCgiConfig`. The other timeouts are hardcoded.

### 5. Granian Worker Configuration

**Location**: `src/app_server/granian.rs`

```rust
pub struct GranianConfig {
    pub app_path: String,
    pub interface: String,         // "asgi" | "rsgi" | "wsgi"
    pub workers: u32,              // Default: 1
    pub blocking_threads: u32,     // Default: 4
    pub socket_path: Option<String>,
    pub host: String,
    pub port: u16,
    // ...
}
```

**Status**: ✅ Already implemented - `workers` and `blocking_threads` are configurable via `SiteAppServerConfig`

---

## Implementation Plan

### Phase 1: FastCGI Pool Timeout Configuration

Make pool timeouts configurable via TOML.

#### Task 1.1: Add Timeout Fields to FastCgiConfig

**File**: `src/config/site/backend.rs`

Add to `FastCgiConfig`:
```rust
#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct FastCgiConfig {
    // ... existing fields ...

    // NEW: Pool timeout configuration
    #[serde(default)]
    pub health_check_interval_secs: Option<u64>,

    #[serde(default)]
    pub max_idle_time_secs: Option<u64>,
}
```

#### Task 1.2: Update FastCgiPoolConfig Builder

**File**: `src/fastcgi/pool.rs`

```rust
impl FastCgiPoolConfig {
    pub fn from_fastcgi_config(config: &FastCgiConfig, socket: &str) -> Self {
        Self {
            max_connections: config.max_connections.unwrap_or(10),
            connection_timeout: Duration::from_secs(
                config.connect_timeout.unwrap_or(5)
            ),
            // NEW: Use config values or fall back to defaults
            health_check_interval: Duration::from_secs(
                config.health_check_interval_secs.unwrap_or(30)
            ),
            max_idle_time: Duration::from_secs(
                config.max_idle_time_secs.unwrap_or(300)
            ),
            socket: socket.to_string(),
        }
    }
}
```

#### Task 1.3: Add utoipa Documentation

**File**: `src/config/site/backend.rs`

Add OpenAPI schema annotations for new fields.

---

### Phase 2: Granian Per-Site Worker Configuration

**Status**: ✅ ALREADY IMPLEMENTED

Worker count and blocking threads are already configurable per-site via TOML.

#### Current Implementation

**SiteAppServerConfig** (`src/config/site/app_server.rs:13-15`):
```rust
#[serde(default)]
pub workers: Option<u32>,

#[serde(default)]
pub blocking_threads: Option<u32>,
```

**Conversion** (`src/config/site/mod.rs:165-177`):
```rust
pub fn app_server_config(&self) -> crate::app_server::AppServerConfig {
    let site_config = &self.app_server;
    crate::app_server::AppServerConfig {
        // ...
        workers: site_config.workers.unwrap_or(1),
        blocking_threads: site_config.blocking_threads.unwrap_or(4),
        // ...
    }
}
```

#### Usage

```toml
[site.app_server]
enabled = true
app_path = "main:app"
interface = "asgi"
workers = 4
blocking_threads = 2
socket_path = "/run/maluwaf-app.sock"
```

**Note**: Default workers is 1 (not CPU cores). If auto-detection based on CPU cores is desired, this could be enhanced with a special value like `"auto"`.

---

### Phase 3: Directory Listing Theme Integration

Enhance directory listing to optionally use theme-aware rendering when theme is configured.

#### Task 3.1: Add Directory Listing Options to StaticLocation

**File**: `src/config/site/static_files.rs`

```rust
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct StaticLocation {
    pub path: String,
    pub root: String,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub try_files: Option<Vec<String>>,
    #[serde(default)]
    pub cache_ttl: Option<u64>,
    #[serde(default)]
    pub theme: Option<SiteStaticThemeConfig>,
    // NEW: Per-location directory listing options
    #[serde(default)]
    pub directory_listing: Option<bool>,
    #[serde(default)]
    pub directory_sort_default: Option<String>,  // "name" | "date" | "size"
    #[serde(default)]
    pub directory_sort_order: Option<String>,    // "asc" | "desc"
    #[serde(default)]
    pub directory_filter: Option<String>,        // e.g., "jpg,png,gif"
    #[serde(default)]
    pub directory_page_size: Option<usize>,      // Default: 100
}
```

#### Task 3.2: Add UseThemeListing Flag

**File**: `src/config/site/static_files.rs`

```rust
pub struct SiteStaticThemeConfig {
    #[serde(flatten)]
    pub theme: SiteThemeConfig,
    #[serde(default)]
    pub directory_template_path: Option<String>,
    // NEW: Use theme-aware directory listing (pagination, sorting)
    #[serde(default)]
    pub use_theme_directory_listing: Option<bool>,  // Default: false
}
```

#### Task 3.3: Integrate ThemeRenderer into StaticFileHandler

**File**: `src/static_files/mod.rs`

```rust
pub struct StaticFileHandler {
    // ... existing fields ...
    pub directory_template: Option<String>,
    // NEW: Theme renderer for directory listing
    pub theme_renderer: Option<ThemeRenderer>,
    pub theme_config: Option<ThemeConfig>,
    pub use_theme_directory_listing: bool,
}
```

When `use_theme_directory_listing = true` and theme config exists, delegate to `DirectoryListingTemplate` from `src/theme/dir_listing.rs`.

#### Task 3.4: Update StaticFileHandler::new()

**File**: `src/static_files/mod.rs`

Parse `use_theme_directory_listing` from config and initialize `ThemeRenderer` when enabled.

---

### Phase 4: Documentation & Examples

#### Task 4.1: Add Web App Stack Documentation

**File**: `docs/WEB_APP_STACK.md`

Document all backend types with examples:
- Static files with directory listing
- PHP-FPM configuration
- FastCGI setup
- WASM serverless functions
- Granian Python ASGI

#### Task 4.2: Add Configuration Examples

**File**: `docs/examples/web_app_stack/` (new directory)

```
docs/examples/web_app_stack/
├── static_with_directory.toml
├── php_fpm_basic.toml
├── php_fpm_advanced.toml
├── fastcgi_python.toml
├── serverless_wasm.toml
└── granian_asgi.toml
```

---

## File Changes Summary

### Files to Modify

| File | Changes |
|------|---------|
| `src/config/site/backend.rs` | Add `health_check_interval_secs`, `max_idle_time_secs` to `FastCgiConfig` |
| `src/config/site/static_files.rs` | Add directory listing options to `StaticLocation`, add `use_theme_directory_listing` |
| `src/fastcgi/pool.rs` | Use config values for timeouts in `FastCgiPoolConfig::from_fastcgi_config()` |
| `src/static_files/mod.rs` | Add theme integration for directory listing |
| `src/theme/mod.rs` | Export `DirectoryListingTemplate` if needed |

### Files to Create

| File | Purpose |
|------|---------|
| `docs/WEB_APP_STACK.md` | Web app stack documentation |
| `docs/examples/web_app_stack/*.toml` | Configuration examples |

### Already Implemented (No Changes Needed)

| File | Status |
|------|--------|
| `src/config/site/app_server.rs` | `workers` and `blocking_threads` fields already exist |
| `src/app_server/granian.rs` | Properly uses `workers` and `blocking_threads` from site config |

### Files to Update (Documentation)

| File | Changes |
|------|---------|
| `docs/RFC5011_TRUST_ANCHOR.md` | No change needed |
| `docs/THREAT_INTEL.md` | No change needed |

---

## Testing Checklist

- [ ] `cargo check` passes after each phase
- [ ] `cargo clippy --lib -- -D warnings` passes
- [ ] `cargo test --lib --no-run` compiles test code
- [ ] FastCGI pool uses configured timeouts (unit test)
- [ ] Granian starts with configured worker count (integration test) - **Already implemented, verify works**
- [ ] Directory listing respects theme when `use_theme_directory_listing = true`
- [ ] Custom directory template still works when `directory_template_path` set
- [ ] Per-location directory listing settings override site-level defaults
- [ ] Theme CSS variables apply correctly to directory listing

---

## Architecture Compliance

**Key principle**: All backends are invoked from worker process. Configuration flows:

```
config/main.toml / sites/{site_id}.toml
         │
         ▼
  ConfigManager (master process)
         │
         │ IPC broadcast on config change
         ▼
  WorkerProcess receives updated config
         │
         ▼
  UnifiedServer initializes backends with config
```

**No architectural changes required** - all enhancements are configuration-level.

---

## Dependencies

| Component | Dependency | Notes |
|-----------|------------|-------|
| Theme integration | `ThemeRenderer` | Already in `src/theme/renderer.rs` |
| Directory listing | `DirectoryListingTemplate` | Already in `src/theme/dir_listing.rs` |
| Pool management | `FastCgiPoolManager` | Already in `src/fastcgi/pool.rs` |
| Granian supervisor | `GranianSupervisor` | Already in `src/app_server/granian.rs` |

**No new external dependencies required.**

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Breaking existing static file serving | Only add optional fields with defaults |
| Theme directory listing regression | Keep simple path as default; opt-in to theme |
| FastCGI pool misconfiguration | Validate timeout values (min/max bounds) |
| Granian worker over-allocation | Document best practices; warn on high counts |

---

## Priority Ordering

### Phase 1 (Quick Wins)
1. FastCGI pool timeout configuration - Low effort, enables tuning

### Phase 2 (Per-Site Control)
2. Granian per-site worker configuration - ✅ ALREADY IMPLEMENTED

### Phase 3 (UX Enhancement)
3. Directory listing theme integration - Medium effort, improves consistency

### Phase 4 (Documentation)
4. Web app stack documentation - Low effort, high value

---

## Defer to Future Plans

The following are out of scope for this plan:

1. **CGI support** - Generic CGI handler for Perl/Ruby/etc. (low demand)
2. **Node.js backend** - Separate server (not embedded)
3. **Database pooling** - External service integration
4. **Metrics dashboard for backends** - Separate admin UI enhancement
5. **Automatic HTTPS certificate management** - ACME already implemented

---

## Configuration Reference

### Static Files with Theme-Aware Directory Listing

```toml
[site.static]
enabled = true
default_root = "/var/www/html"
directory_listing = true

[site.static.theme]
preset = "dark"
mode = "auto"
use_theme_directory_listing = true  # Enable pagination/sorting

[[site.static.locations]]
path = "/files"
root = "/var/www/files"
directory_listing = true
directory_sort_default = "date"
directory_sort_order = "desc"
directory_filter = "jpg,png,gif,pdf"
directory_page_size = 50
```

### PHP-FPM with Security Settings

```toml
[site.php]
socket = "/run/php/php-fpm.sock"
root = "/var/www/html"
disable_functions = ["exec", "passthru", "shell_exec", "system", "proc_open"]
open_basedir = "/var/www/html:/tmp"
allow_url_fopen = false
max_execution_time = 30
memory_limit = "128M"
upload_max_filesize = "10M"
post_max_size = "50M"

[[site.php.locations]]
path = "/api"
disable_functions = ["exec", "passthru", "shell_exec"]  # Override for /api
max_execution_time = 60
```

### Granian ASGI with Custom Workers

```toml
[site.app_server]
enabled = true
app_path = "main:app"
interface = "asgi"
workers = 4
blocking_threads = 2
socket_path = "/run/maluwaf-app.sock"
auto_install_requirements = true
health_check_path = "/health"
```

### FastCGI with Custom Pool Settings

```toml
[site.fastcgi]
socket = "/run/myapp.sock"
max_connections = 20
connect_timeout = 10
health_check_interval_secs = 60
max_idle_time_secs = 600
```

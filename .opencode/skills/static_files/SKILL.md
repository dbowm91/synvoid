---
name: static_files
description: Static file serving, directory listing templates, and filesystem content delivery.
---

# Static Files and Directory Listing Skill

## Overview

The static files subsystem (canonical: `crates/synvoid-static-files/`) serves static content from the filesystem with optional custom directory listing templates, plus the canonical `FileManager` for filesystem mutations. Root `src/static_files/mod.rs` is a pure re-export facade — do not add implementation there.

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-static-files/src/lib.rs` | `StaticFileHandler` + main serving logic |
| `crates/synvoid-static-files/src/directory.rs` | Directory listing: `load_directory_template`, `collect_directory_entries`, `render_custom_template`, `render_directory_listing` |
| `crates/synvoid-static-files/src/file_manager.rs` | Canonical `FileManager` + `FileManagerSecurityBackend` trait |
| `src/static_files/mod.rs` | Pure re-export facade (no implementation) |
| `src/http/file_manager.rs` | Root HTTP adapter + production `UploadFileManagerBackend` |
| `src/http/webdav.rs` | Root WebDAV adapter over canonical `FileManager` |
| `crates/synvoid-config/src/site/static_files.rs` | `SiteStaticConfig`, `SiteStaticThemeConfig`, `StaticLocation` |

## StaticFileHandler

`StaticFileHandler` is **multi-location**, not single-root. It holds a
normalized snapshot of the site config, so all behavior is config-driven:

```rust
pub struct StaticFileHandler {
    config: Arc<SiteStaticConfig>,
    locations: Vec<NormalizedLocation>,
    gzip_types: Vec<String>,
    max_file_size: u64,
    gzip_level: u32,
    gzip_min_size: usize,
    allow_symlinks: bool,
    block_hidden_files: bool,
    enable_compression: bool,
    gzip_on_the_fly: bool,
    directory_listing: bool,
    default_cache_ttl: Option<u64>,
    // ...
}
```
There is no per-handler `root`, `index_file`, `site_name`, or
`directory_template_path` field — those live in the site config
(`SiteStaticConfig` / `StaticLocation`) and the theme config.

## Directory Listing

Directory listing is controlled by `directory_listing: Option<bool>` (and
`directory_listing_format`) on the site static config — the field is **not**
named `show_directory_index`.

### Built-in Template

The built-in template renders:
- Directory path
- Parent link (if not at root)
- File/folder entries with name, size, modified date
- Site name and title

### Custom Template Support

Custom templates can be specified via `SiteStaticThemeConfig`:

```rust
pub struct SiteStaticThemeConfig {
    pub theme: SiteThemeConfig,
    pub directory_template_path: Option<String>,
}
```

Template path in TOML config:
```toml
[site.static.theme]
directory_template_path = "/etc/synvoid/templates/directory.html"
preset = "dark"
```

## Template Placeholders

Custom templates support these placeholders (similar to Handlebars):

| Placeholder | Description |
|-------------|-------------|
| `{{url_path}}` | Current URL path, HTML-escaped (e.g., `/images/`) |
| `{{parent_link}}` | HTML `<tr><td colspan="3">` parent link, or empty at root |
| `{{rows}}` | File/folder entries as HTML `<tr>` elements |
| `{{site_name}}` | Substituted with the literal `"SynVoid"` — always, unconditionally |
| `{{title}}` | `"Index of <url_path>"` |

### Example Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{title}}</title>
    <style>
        body { font-family: sans-serif; margin: 40px; }
        table { border-collapse: collapse; }
        th, td { padding: 8px 12px; text-align: left; }
        a { text-decoration: none; color: #0066cc; }
    </style>
</head>
<body>
    <h1>{{site_name}}</h1>
    <table>
        {{parent_link}}
        <tbody>
            {{rows}}
        </tbody>
    </table>
</body>
</html>
```

## DirectoryEntry

Files and subdirectories are represented as `DirectoryEntry`. It is owned by
the theme crate, not this one (`crates/synvoid-theme/src/dir_listing.rs`), and
carries pre-formatted display strings alongside raw values:

```rust
pub struct DirectoryEntry {
    pub name: String,
    pub href: String,          // relative link, already percent-decoded/escaped upstream
    pub is_dir: bool,
    pub modified: String,      // display-formatted
    pub size: String,          // display-formatted
    pub modified_timestamp: u64,
    pub size_bytes: u64,
}
```
There is no `path: PathBuf` field and no `Option<DateTime<Utc>>` — sorting
and paging use the raw `modified_timestamp` / `size_bytes`, while
`render_custom_template` emits the formatted `modified` / `size`.

## Template Loading Flow

1. `serve_directory()` (in `crates/synvoid-static-files/src/lib.rs`) handles a directory request
2. `directory::load_directory_template()` reads the template from the filesystem
   when `directory_template_path` is set on the resolved theme config
3. `directory::collect_directory_entries()` reads directory contents into `Vec<DirectoryEntry>`
4. `directory::render_custom_template()` substitutes the `{{...}}` placeholders
5. Without a custom template: `directory::render_directory_listing()` renders the
   built-in listing (with JSON output available via `render_json`)

## Adding Custom Themes

1. Create `SiteStaticThemeConfig` with `directory_template_path`
2. The `StaticFileHandler` extracts template path from config
3. On directory request, template is loaded and rendered

## Per-Location Themes

Each `StaticLocation` can have its own `theme` field, allowing different themes per URL path:

```rust
pub struct StaticLocation {
    pub path: String,
    pub root: String,
    pub index: Option<String>,
    pub try_files: Option<Vec<String>>,
    pub cache_ttl: Option<u64>,
    pub theme: Option<SiteStaticThemeConfig>,  // per-location theme
}
```

**Config example**:
```toml
[site.static]
locations = [
    { path = "/public", root = "/var/www/public", theme = { preset = "dark" } },
    { path = "/docs", root = "/var/www/docs", theme = { preset = "light", directory_template_path = "/etc/synvoid/docs-template.html" } }
]
```

When serving a directory, the location's theme takes precedence over the site-wide theme.

## FileManager

The canonical `FileManager` (`crates/synvoid-static-files/src/file_manager.rs`) owns filesystem validation, directory listing/mutations, upload restrictions (hidden files, blocked/allowed extensions, size limits, depth bound, archive policy), and path-traversal/symlink safety.

Upload security (malware scanning, rate limiting, content MIME detection) is injected through the narrow `FileManagerSecurityBackend` trait — never import `synvoid-upload` or root `synvoid::` paths from the crate (dependency cycle via mesh → proxy). The production `UploadFileManagerBackend` adapter lives in `src/http/file_manager.rs`.

There is no periodic YARA-refresh background task. The backend owns its scanner generation; `FileManager::yara_rule_version()` exposes the observable version. To pick up new rules, construct a new backend + manager (mesh feeds stay owned by `UploadValidator`).

```rust
let manager = FileManager::new(config, security_backend);
```

## Testing

```bash
# Whole crate (path safety, upload policy, directory rendering)
cargo nextest run -p synvoid-static-files --cargo-profile ci --profile ci

# Ownership guard (root integration test)
cargo test --test static_file_manager_ownership_guard --profile ci

# Check compilation
cargo check --lib
```

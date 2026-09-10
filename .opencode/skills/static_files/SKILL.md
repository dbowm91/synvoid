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
| `crates/synvoid-static-files/src/lib.rs` | StaticFileHandler, main serving logic, directory listing rendering |
| `crates/synvoid-static-files/src/file_manager.rs` | Canonical `FileManager` + `FileManagerSecurityBackend` trait |
| `src/static_files/mod.rs` | Pure re-export facade (no implementation) |
| `src/http/file_manager.rs` | Root HTTP adapter + production `UploadFileManagerBackend` |
| `src/http/webdav.rs` | Root WebDAV adapter over canonical `FileManager` |
| `crates/synvoid-config/src/site/static_files.rs` | SiteStaticThemeConfig |

## StaticFileHandler

The `StaticFileHandler` serves files from a configured root directory:

```rust
pub struct StaticFileHandler {
    root: PathBuf,
    index_file: Option<String>,
    show_directory_index: bool,
    site_name: String,
    directory_template_path: Option<String>,  // Custom template
}
```

## Directory Listing

When `show_directory_index` is true and no index file exists, directory listing is shown.

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
| `{{url_path}}` | Current URL path (e.g., `/images/`) |
| `{{parent_link}}` | HTML link to parent directory (tr with colspan=3) |
| `{{rows}}` | File/folder entries as HTML tr elements |
| `{{site_name}}` | Site name (defaults to "synvoid") |
| `{{title}}` | Page title (e.g., "Index of /images/") |

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

Files and subdirectories are represented as `DirectoryEntry`:

```rust
pub struct DirectoryEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}
```

## Template Loading Flow

1. `serve_directory()` is called for a directory request
2. Check if `directory_template_path` is set in config
3. If set and format is "html":
   - `load_directory_template()` reads template from filesystem
   - `collect_directory_entries()` reads directory contents
   - `render_custom_template()` substitutes placeholders
4. If no custom template:
   - Use built-in `render_directory_listing()`

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
# File-manager unit tests (path safety, upload policy)
cargo test -p synvoid-static-files --profile ci file_manager

# HTTP adapter tests
cargo test --lib --profile ci file_manager
cargo test --lib --profile ci webdav

# Ownership guard
cargo test --test static_file_manager_ownership_guard --profile ci

# Check compilation
cargo check --lib
```

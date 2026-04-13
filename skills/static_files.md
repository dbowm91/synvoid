# Static Files and Directory Listing Skill

## Overview

The static files module (`src/static_files/`) serves static content from the filesystem with optional custom directory listing templates.

## Key Files

| File | Purpose |
|------|---------|
| `src/static_files/mod.rs` | StaticFileHandler, main serving logic |
| `src/static_files/directory.rs` | Directory listing rendering |
| `src/config/site/static_files.rs` | SiteStaticThemeConfig |

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
directory_template_path = "/etc/maluwaf/templates/directory.html"
preset = "dark"
```

## Template Placeholders

Custom templates support these placeholders (similar to Handlebars):

| Placeholder | Description |
|-------------|-------------|
| `{{url_path}}` | Current URL path (e.g., `/images/`) |
| `{{parent_link}}` | HTML link to parent directory (tr with colspan=3) |
| `{{rows}}` | File/folder entries as HTML tr elements |
| `{{site_name}}` | Site name (defaults to "RustWAF") |
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

## Testing

```bash
# Run integration tests
cargo test --test integration_test

# Check compilation
cargo check --lib
```

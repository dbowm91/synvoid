# MIME Architecture

## 1. Purpose and Responsibility

The MIME module (`src/mime/`) provides a **comprehensive MIME type registry** with extension-to-MIME mapping, file category classification, nginx-format MIME file parsing, and a global registry singleton.

**Core Responsibilities:**
- Bidirectional extension ↔ MIME mapping
- File category classification (Image, Video, Audio, etc.)
- Content-type detection from file bytes
- Nginx-format MIME file parsing
- Wildcard pattern matching

---

## 2. Key Data Structures

```rust
pub struct MimeRegistry {
    extension_to_mime: HashMap<String, MimeTypeInfo>,
    mime_to_extensions: HashMap<String, Vec<String>>,
}

pub struct MimeTypeInfo {
    pub mime_type: String,
    pub extensions: Vec<String>,
    pub category: FileCategory,
}

pub enum FileCategory {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    Font,
    Code,
    Executable,
    Unknown,
}

// Global singleton
static MIME_REGISTRY: LazyLock<RwLock<MimeRegistry>> = LazyLock::new(|| {
    RwLock::new(MimeRegistry::with_defaults())
});
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `MimeRegistry::new()`, `with_defaults()` | Constructors |
| `register(mime_type, extensions)` | Register new type |
| `get_mime_for_extension(ext)` | Extension → MIME lookup |
| `get_extensions_for_mime(mime)` | MIME → extensions lookup |
| `get_category(mime) -> Option<FileCategory>` | Category lookup |
| `get_info(mime) -> Option<MimeTypeInfo>` | Full info lookup |
| `normalize_mime(mime) -> String` | Normalize MIME string |
| `is_mime_allowed(mime, patterns)` | Check against allowlist |
| `mime_matches_pattern(mime, pattern)` | Wildcard matching |
| `detect_from_bytes(data)` | Content-type detection |
| `detect_from_bytes_with_fallback(data, fallback_ext)` | Detection with fallback |
| `init_mimes_from_file(path)` | Load from nginx-format file |
| `reload_mimes_from_file(path)` | Reload from file |

---

## 4. Integration Points

- **Static Files**: Content-type detection for served files
- **Upload**: MIME validation for uploaded files
- **HTTP Server**: Content-type header generation
- **Proxy Cache**: Vary-by content-type support
- **WAF**: MIME-based filtering rules

---

## 5. Key Implementation Details

- **Global Singleton**: Thread-safe `RwLock<MimeRegistry>`
- **Content Detection**: Uses `infer` crate for magic-byte detection
- **Nginx Compatible**: Parses standard nginx mime.types format
- **Wildcard Support**: Pattern matching with `*/*` style globs
- **Default Registry**: Pre-populated with common MIME types

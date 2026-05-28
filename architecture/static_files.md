# Static Files Architecture

## 1. Purpose and Responsibility

The Static Files module (`src/static_files/`) provides **full-featured static file serving** with path traversal protection, ETag/Last-Modified caching, range requests, pre-compressed file support, on-the-fly compression, minification, directory listing, and zero-copy support.

**Core Responsibilities:**
- Secure static file serving with path traversal prevention
- ETag and Last-Modified conditional requests
- Range request support (partial content)
- Pre-compressed file serving (brotli, gzip)
- On-the-fly gzip compression
- CSS/JS minification integration
- Directory listing with sorting/pagination
- Zero-copy file-to-socket transfer

---

## 2. Key Data Structures

```rust
pub struct StaticFileHandler {
    locations: Vec<NormalizedLocation>,
    compression: CompressionConfig,
    minification: MinificationConfig,
    mesh_config: Option<MeshConfig>,
    theme: Option<ThemeConfig>,
}

pub struct NormalizedLocation {
    pub url_prefix: String,
    pub fs_root: PathBuf,
    pub index: Vec<String>,
    pub try_files: Vec<String>,
    pub cache_ttl: u64,
}

pub enum StaticResponse {
    InMemory { content: Bytes, headers: Headers },
    Buffered { path: PathBuf, headers: Headers },
}

pub enum StaticError {
    NotFound,
    Forbidden,
    DirectoryListingDisabled,
    BadRequest,
    FileTooLarge,
    Internal,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `StaticFileHandler::new(config, theme_config)` | Constructor |
| `new_with_minifier(...)` | With minifier client |
| `serve(path, method, accept_encoding, if_none_match, if_modified_since, range)` | Serve file |
| `into_response(result) -> Response` | Convert to HTTP response |
| `get_matching_location(path)` | Find matching location |
| `with_mesh_config(protection, compression, minification)` | Mesh configuration |

---

## 4. Integration Points

- **HTTP Server**: Static file serving in request pipeline
- **MIME**: Content-type detection
- **Zero Copy**: Kernel-level file transfer
- **Theme**: Directory listing rendering
- **Minification**: CSS/JS minification
- **Mesh**: Image protection and compression config

---

## 5. Key Implementation Details

- **Path Traversal Prevention**: Canonicalize + prefix validation
- **Pre-compressed**: Serves `.br` and `.gz` variants when available
- **ETag/Last-Modified**: Full conditional request support
- **Range Requests**: HTTP 206 partial content support
- **Zero-Copy**: sendfile(2) on Linux/macOS for large files
- **Directory Listing**: Sortable, paginated, filterable listings

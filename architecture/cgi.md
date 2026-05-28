# CGI Architecture

## 1. Purpose and Responsibility

The CGI module (`src/cgi/`) provides **classic CGI script execution** with path traversal protection, extension validation, and CGI/1.1 response parsing.

**Core Responsibilities:**
- CGI script execution with environment setup
- Path traversal prevention
- Extension-based script validation
- CGI/1.1 response parsing
- Timeout enforcement

---

## 2. Key Data Structures

```rust
pub struct CgiHandler {
    root: PathBuf,
    index: Vec<String>,
    timeout: Duration,
    allowed_extensions: Vec<String>,
}

pub struct CgiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
}

pub enum CgiError {
    NotFound,
    Forbidden,
    ExecutionFailed(String),
    Timeout,
    InvalidResponse,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `CgiHandler::new(config)` | Constructor with root validation |
| `execute(method, uri, headers, body, client_ip).await` | Execute CGI script |
| `CgiResponse::into_http_response()` | Convert to HTTP response |
| `sanitize_cgi_path(path)` | Remove `.` and `..` components |

---

## 4. Integration Points

- **HTTP Server**: CGI backend routing
- **Config**: `CgiConfig` per-site settings
- **Theme**: Error page rendering

---

## 5. Security Considerations

- **Path Traversal**: Canonicalize + prefix check prevents `../` attacks
- **Extension Validation**: Only allowed script extensions execute
- **Timeout**: Scripts killed after configurable timeout
- **Environment Sanitization**: Clean environment for CGI processes

# Upload Architecture

## 1. Purpose and Responsibility

The Upload module (`src/upload/`) provides a **comprehensive upload validation pipeline** with MIME type checking, YARA malware scanning, sandbox quarantine, file signature verification, rate limiting, and multipart parsing.

**Core Responsibilities:**
- File upload validation (size, type, content)
- YARA-based malware scanning
- Sandbox quarantine for suspicious files
- MIME type verification (magic bytes)
- Multipart form data parsing
- Per-path upload configuration

---

## 2. Key Data Structures

```rust
pub struct UploadValidator {
    config: UploadConfig,
    yara_scanner: Option<YaraScanner>,
    sandbox: Option<Sandbox>,
}

pub struct UploadConfig {
    pub max_size: usize,
    pub allowed_types: Vec<String>,
    pub yara_enabled: bool,
    pub sandbox_enabled: bool,
    pub rate_limit_per_minute: u32,
}

pub struct EffectiveUploadConfig {
    pub max_size: usize,
    pub allowed_types: Vec<String>,
    pub yara_scan: bool,
    pub sandbox: bool,
}

pub struct ValidationResult {
    pub mime_type: Option<String>,
    pub size: usize,
    pub scanned: bool,
    pub yara_matches: Vec<String>,
}

pub struct MultipartPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Bytes,
}

pub enum UploadValidationError {
    SizeExceeded,
    TypeNotAllowed,
    MalwareDetected,
    MimeMismatch,
    InvalidFilename,
    RateLimited,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `UploadValidator::new(config)` | Constructor |
| `validate_bytes(data, path).await` | Validate upload bytes |
| `validate_with_sandbox(data, path, filename).await` | Validate with quarantine |
| `validate_large_file(sandbox_handle, path, filename).await` | Large file handling |
| `validate_filename(filename)` | Check for traversal/null bytes |
| `parse_multipart(body, content_type)` | Parse multipart data |
| `parse_content_disposition_filename(header)` | RFC 5987 filename parsing |
| `should_validate_upload(content_type, content_length, config)` | Check if validation needed |

---

## 4. Submodules

### `config.rs` — Upload Configuration
- Global and per-path settings
- Regex pattern matching for paths
- Configuration resolution

### `metrics.rs` — Upload Metrics
- Upload counting
- Malware detection tracking
- Size distribution

---

## 5. Integration Points

- **HTTP Server**: Upload handling in request pipeline
- **MIME**: Content-type detection for uploaded files
- **YARA**: Malware pattern matching
- **Sandbox**: File quarantine system
- **WAF**: Upload-based attack detection

---

## 6. Security Considerations

- **Path Traversal**: Filename sanitization for `../` and null bytes
- **MIME Mismatch**: Magic-byte detection vs declared content-type
- **Malware Scanning**: YARA rules for known malicious patterns
- **Quarantine**: Suspicious files isolated before processing
- **Rate Limiting**: Per-IP upload rate limits

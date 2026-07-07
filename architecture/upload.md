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
    sandbox: Arc<Sandbox>,
    malware_scanner: Option<Arc<MalwareScanner>>,
    config: UploadConfig,
    reload_lock: parking_lot::RwLock<()>,
    #[cfg(feature = "mesh")]
    yara_rules: Option<Arc<crate::mesh::yara_rules::YaraRulesManager>>,
}

pub struct UploadConfig {
    pub enabled: bool,
    pub max_size: String,
    pub memory_threshold: String,
    pub scan_with_yara: bool,
    pub yara_failure_policy: UploadScanFailurePolicy,
    pub sandbox_enabled: bool,
    pub sandbox_dir: String,
    pub quarantine_dir: String,
    pub yara_rules_dir: Option<String>,
    pub yara_timeout_ms: u64,
    pub yara_large_file_scan_mode: YaraLargeFileScanMode,
    pub yara_window_size_bytes: u64,
    pub yara_max_window_count: u32,
    pub yara_magic_scan_limit_bytes: u64,
    pub yara_max_concurrent_scans: u32,
    pub yara_max_queued_scans: u32,
    pub yara_queue_timeout_ms: u64,
    pub verify_signature: bool,
    pub signature_strict_mode: bool,
    pub rate_limit_enabled: bool,
    pub max_uploads_per_minute: u32,
    pub max_uploads_per_hour: u32,
    pub max_bytes_per_minute: String,
    pub burst_allowance: u32,
    pub allowed_types: AllowedTypesConfig,
    pub paths: Vec<PathUploadConfig>,
    pub reject_mime_mismatch: bool,
}

pub struct EffectiveUploadConfig {
    pub max_size: usize,
    pub allowed_types: Vec<String>,
    pub yara_scan: bool,
    pub sandbox: bool,
}

pub struct ValidationResult {
    pub mime_type: String,
    pub size: u64,
    pub scanned: bool,
    pub scan_status: UploadScanStatus,
    pub scan_error: Option<String>,
    pub yara_matches: Vec<String>,
    pub scanned_bytes: u64,
    pub total_bytes: u64,
    pub scan_mode: YaraLargeFileScanMode,
    pub coverage_ratio: f64,
    pub window_count: u32,
    pub duration_ms: u64,
}

pub enum UploadScanStatus {
    Clean,
    Malicious,
    Disabled,
    Unavailable,
    Indeterminate,
}

pub enum UploadScanFailurePolicy {
    FailClosed,
    QuarantineOnError,  // default
    FailOpen,
}

pub enum YaraLargeFileScanMode {
    Full,       // scan entire file
    Windowed,   // scan strategic windows (header, footer, middle)
    HeaderOnly, // scan only first 8KB (legacy behavior)
}

pub struct MultipartPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Bytes,
}

pub enum UploadValidationError {
    SizeExceeded { max: u64, actual: u64 },
    TypeNotAllowed { detected: String, allowed: Vec<String> },
    MalwareDetected { matches: Vec<String> },
    ScanIndeterminate { reason: String },
    ScannerUnavailable,
    IoError(#[from] std::io::Error),
    YaraError(#[from] YaraError),
    SandboxError(#[from] SandboxError),
    InvalidMultipart,
    NoData,
    InvalidFilename { reason: String },
    EmptyFilename,
    MimeMismatch { declared: String, detected: String },
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
- **Scan Failure Semantics**: Scanner errors never silently treated as clean

## 7. Scan Failure Semantics

YARA scan errors (timeout, panic, rule deserialization failure, scanner unavailable) are **never** silently treated as clean uploads under production defaults. The `yara_failure_policy` config field controls behavior:

| Policy | Behavior on scan error |
|--------|----------------------|
| `quarantine_on_error` (default) | Quarantine if possible, reject with `ScanIndeterminate` |
| `fail_closed` | Reject immediately with `ScanIndeterminate` |
| `fail_open` | Allow upload, mark `Indeterminate`, emit warning metrics (opt-in only) |

Scan statuses are reported in `ValidationResult.scan_status` and tracked via metrics (`UPLOAD_SCAN_CLEAN`, `UPLOAD_SCAN_MALICIOUS`, `UPLOAD_SCAN_DISABLED`, `UPLOAD_SCAN_UNAVAILABLE`, `UPLOAD_SCAN_INDETERMINATE`, `UPLOAD_SCAN_FAIL_OPEN_ALLOWED`, `UPLOAD_SCAN_QUARANTINE_ON_ERROR`).

## 8. Large File Scanning

For sandbox-backed streaming uploads (`validate_large_file`), the scan mode determines how much of the file is examined:

| Mode | Behavior | Coverage | Use Case |
|------|----------|----------|----------|
| `full` (default) | Read entire file, scan all bytes | 100% | Maximum security; memory-intensive for large files |
| `windowed` | Scan strategic windows (header, footer, middle) | ~20-40% | Balance between coverage and memory usage |
| `header_only` | Scan first 8KB only | <1% | Legacy behavior; only detects header-embedded malware |

### Windowed Scan Strategy

The windowed mode computes up to `yara_max_window_count` (default: 8) windows:

1. **Header window**: First `yara_window_size_bytes` (default: 1MB) — catches header-embedded payloads
2. **Footer window**: Last `yara_window_size_bytes` — catches appended payloads (polyglots, appended shells)
3. **Magic scan region**: Scans up to `yara_magic_scan_limit_bytes` (default: 16MB) for files with complex magic byte patterns
4. **Middle windows**: Evenly spaced across remaining bytes — catches payload injection in large files

Windows are deduplicated by YARA rule name across all scanned regions.

### Configuration

```toml
[defaults.upload]
yara_large_file_scan_mode = "windowed"  # "full", "windowed", or "header_only"
yara_window_size_bytes = 1048576        # 1MB per window
yara_max_window_count = 8               # Maximum windows to scan
yara_magic_scan_limit_bytes = 16777216  # 16MB magic scan region
yara_max_concurrent_scans = 4           # Max simultaneous YARA scan tasks
yara_max_queued_scans = 64              # Max queued scan requests
yara_queue_timeout_ms = 1000            # Timeout waiting for a scan slot (ms)
```

### Coverage Metadata

`ValidationResult` includes coverage metadata for audit trails:

- `scanned_bytes`: Total bytes actually scanned
- `total_bytes`: Total file size
- `scan_mode`: Which mode was used
- `coverage_ratio`: `scanned_bytes / total_bytes` (1.0 = full coverage)
- `window_count`: Number of windows scanned (0 for full/header_only)
- `duration_ms`: Scan wall-clock time

## 9. Bounded YARA Execution

The scan executor uses a semaphore-based bounded admission model to prevent hostile load from exhausting CPU/memory:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `yara_max_concurrent_scans` | 4 | Maximum simultaneously executing scan tasks |
| `yara_max_queued_scans` | 64 | Maximum requests waiting for a scan slot |
| `yara_queue_timeout_ms` | 1000 | Timeout (ms) to wait for a scan permit before rejecting |

When all scan slots are occupied and the queue is full, new scans are rejected with `YaraError::QueueFull`. When a scan waits longer than `queue_timeout_ms`, it is rejected with `YaraError::QueueTimeout`. Both flow through the standard failure policy (`yara_failure_policy`).

### Admission Flow

```
scan_bytes() / scan_file_windows()
  → acquire_scan_permit()  // semaphore + timeout
  → clone input data       // AFTER admission, not before
  → load generation Arc    // lock-free via ArcSwap
  → spawn_blocking(scan)   // YARA runs outside tokio runtime
  → drop permit            // releases slot
```

Key properties:
- **No global lock held during scan**: `ArcSwap` provides lock-free generation loading; the `Rules` object is immutable within a generation
- **Input cloned after admission**: Large buffers are only cloned when a scan slot is available, preventing memory amplification under pressure
- **Permit dropped on timeout**: Timed-out scans do not hold permits; the permit is dropped when the scan completes or errors

## 10. Atomic Rule Reloads

Rule reloads use a prepare-then-swap pattern via `ArcSwap<YaraRuleGeneration>`:

1. **Compile off-path**: New rules are compiled on a dedicated thread (not holding any shared state)
2. **Atomic store**: `generation.store(Arc::new(new_generation))` makes the new rules visible to all concurrent scanners instantly
3. **Last-known-good**: If compilation fails, the previous generation continues serving scans unchanged
4. **Metrics**: Reload success/failure counts tracked via `YARA_RELOAD_SUCCESS` / `YARA_RELOAD_FAILURE`

### Generation Lifecycle

```rust
struct YaraRuleGeneration {
    rules: Rules,              // compiled YARA rules (immutable)
    version: Option<String>,   // human-readable version tag
    hash: String,              // SHA-256 of source rules text
    loaded_at: DateTime<Utc>,  // timestamp for diagnostics
}
```

Scanners hold an `Arc` to the current generation, so reloads never block in-flight scans.

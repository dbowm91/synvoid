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

YARA scan errors (timeout, panic, rule deserialization failure, scanner unavailable) are **never** silently treated as clean uploads under production defaults. Errors propagate through `MalwareError::YaraScanError`, which is surfaced to the caller and classified by the failure policy. The `yara_failure_policy` config field controls behavior:

| Policy | Behavior on scan error |
|--------|----------------------|
| `quarantine_on_error` (default) | Quarantine if possible, reject with `ScanIndeterminate` |
| `fail_closed` | Reject immediately with `ScanIndeterminate` |
| `fail_open` | Allow upload, mark `Indeterminate`, emit warning metrics (opt-in only) |

Under production defaults (`quarantine_on_error`), a YARA error produces `UploadScanStatus::Indeterminate` and the upload is quarantined/rejected per the failure policy. Previously, some YARA errors were silently consumed; they now always surface as `MalwareError::YaraScanError`.

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
    provenance: YaraRuleProvenance,  // source tracking and verification state
}
```

Scanners hold an `Arc` to the current generation, so reloads never block in-flight scans.

## 11. YARA Rule Provenance (Phase 4)

Every rule generation carries `YaraRuleProvenance` metadata:

```rust
struct YaraRuleProvenance {
    source_type: YaraRuleSourceType,  // Bundled/Directory/Inline/Mesh/CompiledBundle
    version: Option<String>,          // human-readable version tag
    content_sha256: String,           // SHA-256 of combined source text
    manifest_sha256: Option<String>,  // SHA-256 of signed manifest (if available)
    signer: Option<String>,           // signer identity (if signed)
    verified: bool,                   // whether signature was verified
    loaded_at: DateTime<Utc>,         // when this generation was loaded
    source_count: usize,              // number of rule files merged
    source_bytes: u64,                // total source bytes
}
```

### Source Types

| Type | Trust | Description |
|------|-------|-------------|
| `Bundled` | Low | Default rules shipped with binary |
| `Directory` | Operator | Loaded from local directory (strict mode) |
| `Inline` | High | Provided directly via config/admin |
| `Mesh` | Network | Ed25519-verified mesh peer delivery |
| `CompiledBundle` | Operator | Pre-compiled YARA-X binary |

### Directory Loading Hardening

`load_rules_from_directory_with_limits()` replaces the old `load_rules_from_directory()`:

- **Canonicalized paths**: Directory must resolve to a real path
- **Sorted file order**: Files sorted alphabetically for deterministic compilation
- **Symlink control**: Symlinks rejected by default (`yara_allow_rule_symlinks = false`)
- **File count limit**: Rejects directories with more than `yara_max_rule_files` (default 256) files
- **Aggregate size limit**: Rejects directories exceeding `yara_max_rule_source_bytes` (default 8MB)
- **Strict mode**: `Directory` returns `NoRules` when empty; `DirectoryWithFallback` falls back to bundled

### Signed Bundle Verification

`YaraRuleManifest` provides Ed25519 signature verification for rule bundles:

```rust
struct YaraRuleManifest {
    version: String,
    created_at: String,
    source_id: String,
    rule_source_sha256: String,      // SHA-256 of source text
    compiled_rules_sha256: String,   // SHA-256 of compiled binary
    min_synvoid_version: String,
    format_version: u32,
    signature_scheme: Option<String>, // "ed25519"
    signature: Option<String>,        // base64-encoded Ed25519 signature
}
```

Signing payload: `"{source_sha256}:{compiled_sha256}"`. Verification via `manifest.verify()` (key check) and `manifest.verify_content()` (content integrity).

### Operator Inspection

```rust
let provenance = scanner.get_rule_provenance();  // current provenance
let error = scanner.get_last_reload_error();     // last error (None if clean)
```

### Directory Config Fields

| Field | Default | Description |
|-------|---------|-------------|
| `yara_max_rule_files` | 256 | Maximum rule files per directory |
| `yara_max_rule_source_bytes` | 8388608 (8MB) | Maximum aggregate source bytes |
| `yara_allow_rule_symlinks` | false | Whether to follow symlinks |

## 12. Native Malware Detector

The native malware detector is a **fallback/defense-in-depth layer**, not a replacement for YARA-X. It provides lightweight heuristic scanning without requiring YARA rule compilation or loading.

### Two-Layer Scanning

Uploads are scanned in two layers:

1. **Native heuristics first**: Fast pattern-based detection using built-in rules
2. **YARA-X second**: Full YARA rule matching (if enabled and rules are loaded)

Both layers run independently. A match from either layer flags the upload. Native detection never disables or replaces YARA scanning.

### YARA Error Propagation

YARA errors now propagate as `MalwareError::YaraScanError` instead of being silently consumed. Under production defaults (`quarantine_on_error`), this results in `UploadScanStatus::Indeterminate` and the upload is quarantined/rejected per the failure policy. This ensures scan failures are never treated as clean.

### Match Metadata Normalization

`MalwareMatch` now carries normalized metadata:

```rust
pub struct MalwareMatch {
    pub rule_name: String,
    pub category: String,
    pub description: String,
    pub source: MatchSource,       // Native | Yara
    pub confidence: MatchConfidence, // Low | Medium | High
}

pub enum MatchSource {
    Native,
    Yara,
}

pub enum MatchConfidence {
    Low,
    Medium,
    High,
}
```

### Filename-Aware Detection

Some detections depend on the uploaded filename (e.g., `DoubleExtension`). These require a `ScanContext` with a filename:

```rust
pub struct ScanContext {
    pub filename: Option<String>,
    pub declared_mime: Option<String>,
    pub detected_mime: Option<String>,
    pub size: Option<u64>,
}
```

Byte-only scans (without context) do **not** emit filename-dependent matches. Use `scan_bytes_with_context()` for filename-aware scanning:

```rust
let context = ScanContext {
    filename: Some("report.pdf.exe".to_string()),
    declared_mime: None,
    detected_mime: None,
    size: Some(data.len() as u64),
};
let matches = scanner.scan_bytes_with_context(data, &context);
```

### PE/ZIP Polyglot Detection

The `suspicious_polyglot` rule correctly searches for the ZIP magic bytes (`PK`) **after** the PE header (offset 4+), not at offset 0. The search is bounded to the first 1MB to prevent CPU exhaustion on large files.

### Native Rule Table

| Native Rule | Category | Confidence | Detection Method |
|-------------|----------|------------|------------------|
| executable_pe | executable | High | MZ magic at offset 0 |
| executable_elf | executable | High | ELF magic (`\x7FELF`) |
| executable_macho | executable | High | Mach-O magic (`0xFEEDFACE`/`0xFEEDFACF`/`0xBEBAFECA`) |
| suspicious_polyglot | evasion | High | MZ at offset 0 + PK signature after offset 4 (bounded 1MB) |
| suspicious_office_macro_autoopen | macro | Medium | Heuristic: auto-trigger keywords + shell execution patterns |
| suspicious_script_obfuscation | script | Medium | Heuristic: `eval`, `fromCharCode`, `unescape` patterns |
| suspicious_php_webshell | webshell | Medium | Heuristic: PHP exec function + user input access |
| suspicious_jsp_webshell | webshell | Medium | Heuristic: `Runtime.exec` + parameter access |
| suspicious_asp_webshell | webshell | Medium | Heuristic: shell execute + request object |
| suspicious_archive_bomb | archive | Medium | High density of archive signatures (nested headers) |
| suspicious_embedded_exe | embedded | Medium | MZ+PE in first 64 bytes of a non-PE file |
| suspicious_double_extension | social_engineering | Low | Filename context: `.pdf.exe`, `.doc.exe`, `.jpg.exe`, etc. |
| suspicious_hta_script | script | Medium | HTA tag + suspicious shell keywords |
| suspicious_shortcut_exploit | exploit | Medium | LNK magic + shell keywords |
| high_entropy_binary | entropy | Low | Shannon entropy > 7.5 (binary packing indicator) |

### Deduplication and Ordering

Matches are deduplicated by `(rule_name, category)` — only the first occurrence is kept. Results are sorted by:

1. **Severity**: critical > high > medium > low
2. **Category**: alphabetical
3. **Rule name**: alphabetical
4. **Source**: Native before Yara (within same severity/category/rule)

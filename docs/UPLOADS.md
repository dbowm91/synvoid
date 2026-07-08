# Upload Validation & Malware Scanning

SynVoid provides comprehensive file upload validation with optional YARA-based malware scanning to protect against malicious file uploads.

## Features

- **MIME Type Validation** - Verify file types before processing
- **File Size Limits** - Prevent resource exhaustion
- **YARA Scanning** - Detect malware using YARA rules
- **Quarantine** - Isolate suspicious files for review
- **Multi-part Handling** - Full support for multipart form uploads

## Configuration

### Basic Upload Configuration

```toml
[defaults.upload]
enabled = true
max_size_mb = 10

# Allowed MIME types (whitelist mode)
[defaults.upload.allowed_types]
mode = "whitelist"  # or "blacklist"
types = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/pdf",
    "application/zip",
]
```

### YARA Malware Scanning

```toml
[defaults.upload]
scan_with_yara = true
yara_failure_policy = "quarantine_on_error"  # default
# Other options: "fail_closed", "fail_open" (unsafe, opt-in only)

yara_rules_dir = "rules/"
quarantine_dir = "/var/lib/synvoid/quarantine"
yara_timeout_ms = 30000

# Large file scanning (for sandbox-backed streaming uploads)
yara_large_file_scan_mode = "windowed"  # "full", "windowed", or "header_only"
yara_window_size_bytes = 1048576        # 1MB per window
yara_max_window_count = 8               # Maximum windows to scan
yara_magic_scan_limit_bytes = 16777216  # 16MB magic scan region

# Directory rule loading hardening (Phase 4)
yara_max_rule_files = 256               # Maximum rule files per directory
yara_max_rule_source_bytes = 8388608    # Maximum aggregate source bytes (8MB)
yara_allow_rule_symlinks = false        # Reject symlinks by default
```

### Per-Site Configuration

```toml
# config/sites/example.com.toml
[site.upload]
enabled = true
max_size_mb = 25  # Override default for this site

[site.upload.allowed_types]
mode = "whitelist"
types = [
    "image/jpeg",
    "image/png",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
]
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable upload validation |
| `max_size_mb` | `10` | Maximum upload size in MB |

### Allowed Types Options

| Option | Default | Description |
|--------|---------|-------------|
| `mode` | `"whitelist"` | `"whitelist"` or `"blacklist"` |
| `types` | `[]` | List of allowed/blocked MIME types |

### YARA Scanning Options

| Option | Default | Description |
|--------|---------|-------------|
| `scan_with_yara` | `true` | Enable YARA scanning |
| `yara_failure_policy` | `"quarantine_on_error"` | How to handle scan errors: `quarantine_on_error`, `fail_closed`, or `fail_open` |
| `yara_rules_dir` | - | Directory containing YARA rules |
| `quarantine_dir` | - | Directory for quarantined files |
| `yara_timeout_ms` | `30000` | Scan timeout in milliseconds |

### Large File Scanning Options

| Option | Default | Description |
|--------|---------|-------------|
| `yara_large_file_scan_mode` | `"full"` | Scan mode for large files: `full`, `windowed`, or `header_only` |
| `yara_window_size_bytes` | `1048576` | Size of each scan window in bytes (1MB) |
| `yara_max_window_count` | `8` | Maximum number of windows to scan |
| `yara_magic_scan_limit_bytes` | `16777216` | Maximum bytes to scan for magic byte patterns (16MB) |

### Directory Rule Loading Options

| Option | Default | Description |
|--------|---------|-------------|
| `yara_max_rule_files` | `256` | Maximum number of rule files per directory |
| `yara_max_rule_source_bytes` | `8388608` | Maximum aggregate source bytes (8MB) |
| `yara_allow_rule_symlinks` | `false` | Whether to follow symlinks (rejected by default) |

### Scan Failure Policies

| Policy | Production Safe | Description |
|--------|----------------|-------------|
| `quarantine_on_error` | Yes | Quarantine file and reject upload on scan error (default) |
| `fail_closed` | Yes | Reject upload immediately on scan error |
| `fail_open` | **No** | Allow upload on scan error, mark as indeterminate. Opt-in only — never use on public upload endpoints. |

## YARA Rules Setup

### Installing YARA Rules

Place YARA rule files (`.yar` or `.yara`) in the rules directory:

```
rules/
├── malware.yar
├── exploits.yar
├── ransomware.yar
└── PUA.yar
```

### Example YARA Rule

```yara
rule Suspicious_Javascript {
    meta:
        description = "Detects suspicious JavaScript"
        author = "SynVoid"
        severity = 50
    
    strings:
        $eval = /eval\s*\(/i
        $document_write = /document\.write/i
        $inner_html = /innerHTML\s*=/i
    
    condition:
        any of them
}
```

### Recommended Rules Sources

- [YARA Rules Project](https://github.com/Yara-Rules/rules)
- [APT & Malware Rules](https://github.com/tennc/webshell)
- [ClamAV Signatures](https://github.com/Cisco-Talos/clamav-bytecode)

## How It Works

```
Client Upload Request
        |
        v
   Size Check -----> [Fail: 413 Payload Too Large]
        |
        v
   MIME Type Check ---> [Fail: 415 Unsupported Media Type]
        |
        v
   [YARA Scan] (if enabled)
        |
        +--> Clean ---------> Allow Upload
        |
        +--> Malicious -----> Quarantine + Block (403)
        |
        +--> Scan Error ----> Apply yara_failure_policy:
        |       |
        |       +--> quarantine_on_error (default): Quarantine + Block (403)
        |       +--> fail_closed: Block (403)
        |       +--> fail_open: Allow + Log Warning (opt-in only)
        |
        +--> Scanner Unavailable --> Block (403)
```

## Large File Scanning

For large file uploads (sandbox-backed streaming), SynVoid supports three scan modes to balance security and performance:

| Mode | Description | Security | Performance |
|------|-------------|----------|-------------|
| `full` | Scan entire file | Maximum | Memory-intensive |
| `windowed` | Scan strategic windows | High | Balanced |
| `header_only` | Scan first 8KB only | Low | Fast |

### Windowed Mode

The default `windowed` mode scans up to 8 strategic regions of the file:

1. **Header**: First 1MB — catches header-embedded malware
2. **Footer**: Last 1MB — catches appended payloads
3. **Magic region**: Up to 16MB — catches complex magic byte patterns
4. **Middle windows**: Evenly spaced — catches payload injection in large files

### Coverage Metadata

Each validation result includes coverage metadata for audit trails:

```json
{
  "scanned_bytes": 4194304,
  "total_bytes": 52428800,
  "scan_mode": "windowed",
  "coverage_ratio": 0.08,
  "window_count": 4,
  "duration_ms": 127
}
```

### Per-Path Configuration

Override scan mode per path pattern:

```toml
[defaults.upload.paths]
pattern = "^/api/uploads/documents/.*"
yara_large_file_scan_mode = "full"
yara_max_window_count = 12

[defaults.upload.paths]
pattern = "^/api/uploads/images/.*"
yara_large_file_scan_mode = "header_only"
```

## Admin API

Upload and quarantine management endpoints are currently not exposed via the Admin API. Quarantined files must be managed directly on the filesystem.

### Managing Quarantined Files

Quarantined files are stored in the configured `quarantine_dir`:

```bash
# List quarantined files
ls -la /var/lib/synvoid/quarantine/

# View file metadata (stored alongside files)
cat /var/lib/synvoid/quarantine/.metadata.json

# Delete quarantined file
rm /var/lib/synvoid/quarantine/suspicious_file.exe

# Restore file (move back to original location if known)
mv /var/lib/synvoid/quarantine/file.pdf /original/path/
```

### Monitoring via Metrics

Upload activity can be monitored through logs and the quarantine directory:

1. **Access logs** - Check for blocked uploads in JSON access logs
2. **YARA logs** - Review malware detection logs
3. **Quarantine directory** - Monitor file count and size

```bash
# Check quarantined files count
ls -la /var/lib/synvoid/quarantine/ | wc -l
```

**Internal Metrics Available:**

The following upload statistics are tracked internally:

- `UPLOAD_TOTAL` - Total uploads processed
- `UPLOAD_RATE_LIMIT_EXCEEDED` - Uploads blocked by rate limiting
- `UPLOAD_SIZE_REJECTED` - Uploads rejected for being too large
- `UPLOAD_TYPE_REJECTED` - Uploads rejected due to disallowed MIME type
- `UPLOAD_MALWARE_DETECTED` - Files flagged by YARA scanning
- `UPLOAD_TOTAL_BYTES` - Total bytes processed
- `UPLOAD_SCAN_CLEAN` - Scans completed with no matches
- `UPLOAD_SCAN_MALICIOUS` - Scans that found malware
- `UPLOAD_SCAN_DISABLED` - Uploads where scanning was disabled by config
- `UPLOAD_SCAN_UNAVAILABLE` - Uploads where scanner was not available
- `UPLOAD_SCAN_INDETERMINATE` - Scans that failed to complete
- `UPLOAD_SCAN_FAIL_OPEN_ALLOWED` - Uploads allowed despite scan failure (fail_open policy)
- `UPLOAD_SCAN_QUARANTINE_ON_ERROR` - Uploads quarantined on scan failure

## Bounded Archive Inspection

ZIP uploads are inspected in-memory without disk extraction. Entry contents are scanned for malware, paths are sanitized, and multiple limits prevent archive bomb abuse.

### Configuration Options

```toml
[site.upload]
archive_inspection_enabled = true   # Enable archive inspection (default: true)
archive_max_depth = 3               # Max nested inspection depth (default: 3)
archive_max_entries = 1000          # Max entries per archive (default: 1000)
archive_max_total_uncompressed_bytes = 536870912  # 512 MB total (default)
archive_max_entry_uncompressed_bytes = 104857600  # 100 MB per entry (default)
archive_max_compression_ratio = 100.0             # Max compression ratio (default)
archive_max_nested_archives = 5     # Max nested archive entries (default: 5)
```

### What Gets Checked

1. **Path sanitization** — Rejects `..` traversal, absolute paths, UNC paths, Windows drive letters, null bytes, and backslashes (normalized to `/`)
2. **Entry content scanning** — Each entry's uncompressed content is scanned by the native heuristic rules and YARA-X
3. **Nested archive detection** — ZIP entries that are themselves archives (`.zip`, `.jar`, `.war`, `.ear`, `.docx`, `.xlsx`, `.pptx`, etc.) are counted
4. **Archive bomb protection** — Entry count, total size, per-entry size, and compression ratio limits

### How It Works

1. Upload bytes are scanned by native heuristics + YARA-X (as before)
2. If the file is a ZIP archive and inspection is enabled, entries are iterated in-memory
3. Each entry's path is sanitized; unsafe paths are rejected
4. Entry content is scanned for malware
5. Matches from archive entries are combined with outer-scan matches
6. Limit violations and malformed archives apply your `yara_failure_policy`

### Archive Metrics

- `UPLOAD_ARCHIVE_INSPECTIONS` - ZIP archives inspected
- `UPLOAD_ARCHIVE_ENTRIES_SCANNED` - Total entries scanned across all archives
- `UPLOAD_ARCHIVE_MALWARE_DETECTED` - Malware found in archive entries
- `UPLOAD_ARCHIVE_LIMIT_VIOLATIONS` - Limit exceeded errors
- `UPLOAD_ARCHIVE_MALFORMED` - Malformed ZIP archives encountered

### Limitations

- Only ZIP archives are inspected. TAR/GZIP/BZIP2/7z are detected by MIME but not opened.
- Nested archives are detected by filename but not recursively inspected by default.

## Security Considerations

1. **Quarantine Directory** - Ensure it's on a separate partition
2. **File Execution** - Never execute files from quarantine
3. **Regular Review** - Review quarantined files regularly
4. **YARA Rules** - Keep rules updated
5. **Size Limits** - Set appropriate limits for your application

## Troubleshooting

### YARA Not Loading

```bash
# Check rule files exist
ls -la rules/

# Validate YARA syntax
yara -C rules/ testfile
```

### Quarantine Full

```bash
# Check quarantine size
du -sh /var/lib/synvoid/quarantine

find /var/lib/synvoid/quarantine -mtime +30 -delete
```

### Upload Failing

1. Check file size limit
2. Verify MIME type is allowed
3. Check YARA scan timeout
4. Review logs for errors

## Integration Examples

### PHP Application

```php
// After upload, check with WAF
$response = file_get_contents(
    "http://localhost:8081/api/uploads/check?hash=" . 
    md5($uploaded_file)
);
```

### Web Server Configuration

```nginx
# Nginx: Pass uploads through WAF
location /upload {
    proxy_pass http://synvoid_backend;
    # WAF handles validation
}
```

## Native Malware Detector

SynVoid includes a built-in native heuristic malware detector as defense-in-depth alongside YARA-X. The native detector provides lightweight pattern-based scanning without requiring YARA rule compilation or loading.

### How It Works

Uploads are scanned in two layers:

1. **Native heuristics run first** — fast pattern matching using built-in rules
2. **YARA-X runs second** — full YARA rule matching (if enabled)

Both layers run independently. A match from either layer flags the upload. Native detection never replaces YARA scanning.

### Native Rules

| Native Rule | Category | Confidence | Detection Method |
|-------------|----------|------------|------------------|
| executable_pe | executable | High | MZ magic at offset 0 |
| executable_elf | executable | High | ELF magic (`\x7FELF`) |
| executable_macho | executable | High | Mach-O magic (`0xFEEDFACE`/`0xFEEDFACF`/`0xBEBAFECA`) |
| suspicious_polyglot | evasion | High | MZ at offset 0 + PK after offset 4 (bounded 1MB) |
| suspicious_office_macro_autoopen | macro | Medium | Auto-trigger keywords + shell execution patterns |
| suspicious_script_obfuscation | script | Medium | `eval`, `fromCharCode`, `unescape` patterns |
| suspicious_php_webshell | webshell | Medium | PHP exec function + user input |
| suspicious_jsp_webshell | webshell | Medium | `Runtime.exec` + parameter access |
| suspicious_asp_webshell | webshell | Medium | Shell execute + request object |
| suspicious_archive_bomb | archive | Medium | High density of archive signatures |
| suspicious_embedded_exe | embedded | Medium | MZ+PE in first 64 bytes of non-PE file |
| suspicious_double_extension | social_engineering | Low | Filename: `.pdf.exe`, `.doc.exe`, etc. |
| suspicious_hta_script | script | Medium | HTA tag + shell keywords |
| suspicious_shortcut_exploit | exploit | Medium | LNK magic + shell keywords |
| high_entropy_binary | entropy | Low | Shannon entropy > 7.5 |

### YARA Error Propagation

YARA errors now propagate as `MalwareError::YaraScanError` instead of being silently consumed. Under production defaults (`quarantine_on_error`), this results in `UploadScanStatus::Indeterminate` and the upload is quarantined/rejected. Scan errors are **never** treated as clean.

### Filename-Aware Scanning

Some detections (like `suspicious_double_extension`) depend on the uploaded filename. Use `scan_bytes_with_context()` for filename-aware scanning:

```rust
use synvoid_upload::malware::{ScanContext, MalwareScanner};

let context = ScanContext {
    filename: Some("report.pdf.exe".to_string()),
    declared_mime: None,
    detected_mime: None,
    size: Some(data.len() as u64),
};

let matches = scanner.scan_bytes_with_context(data, &context);
```

Without a filename in the `ScanContext`, filename-dependent rules are skipped.

### Match Metadata

Each `MalwareMatch` includes:

- `source`: `Native` or `Yara` — which layer detected the match
- `confidence`: `Low`, `Medium`, or `High` — detection confidence level
- `rule_name`, `category`, `description` — rule details

Results are deduplicated by `(rule_name, category)` and sorted by severity, then category, then rule name, then source (Native before Yara).

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [CONFIGURATION.md](./CONFIGURATION.md) - Upload configuration
- [STATIC_FILES.md](./STATIC_FILES.md) - File serving
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Upload issues

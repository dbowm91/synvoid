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
[defaults.upload.scan_with_yara]
enabled = true
rules_dir = "rules/"
quarantine_dir = "/var/lib/synvoidwaf/quarantine"

# Scanning options
[defaults.upload.scan_with_yara.options]
scan_content = true
max_scan_size_mb = 50
timeout_secs = 30
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
| `enabled` | `false` | Enable YARA scanning |
| `rules_dir` | `"rules/"` | Directory containing YARA rules |
| `quarantine_dir` | - | Directory for quarantined files |
| `scan_content` | `true` | Scan file content vs just extension |
| `max_scan_size_mb` | `50` | Maximum file size to scan |
| `timeout_secs` | `30` | Scan timeout |

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
        +--> Clean -----> Allow Upload
        |
        +--> Malware ---> Quarantine
        |
        +--> Error ----> Log & Allow
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

The following upload statistics are tracked internally but not yet exported to Prometheus:

- `UPLOAD_TOTAL` - Total uploads processed
- `UPLOAD_RATE_LIMIT_EXCEEDED` - Uploads blocked by rate limiting
- `UPLOAD_SIZE_REJECTED` - Uploads rejected for being too large
- `UPLOAD_TYPE_REJECTED` - Uploads rejected due to disallowed MIME type
- `UPLOAD_MALWARE_DETECTED` - Files flagged by YARA scanning
- `UPLOAD_TOTAL_BYTES` - Total bytes processed

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

## See Also

- [ATTACK_DETECTION.md](./ATTACK_DETECTION.md) - Attack detection details
- [CONFIGURATION.md](./CONFIGURATION.md) - Upload configuration
- [STATIC_FILES.md](./STATIC_FILES.md) - File serving
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Upload issues

# Upload Deep Dive

SynVoid's upload validation system provides multi-stage file upload validation with YARA-based malware scanning, archive inspection, sandboxing, and quarantine management.

## Validation Pipeline

```
Upload
├── Size Check (configurable limit)
├── MIME Detection (magic-byte based)
├── MIME Allowlist
├── YARA Scan (malware detection)
├── Archive Inspection (ZIP analysis)
└── Quarantine (on malware detection)
```

### YARA Scanning

```rust
pub struct YaraScanner {
    // Compiles and scans with YARA rules
    // Supports bundled, directory, inline, mesh-distributed, and compiled bundle sources
}

pub enum YaraLargeFileScanMode {
    Full,           // Scan entire file
    HeaderOnly,     // First N bytes
    Windowed,       // Sliding window scan
}
```

- Bundled and custom rule sources (`YaraRuleSourceType`: Bundled, Directory, Inline, Mesh, CompiledBundle)
- Configurable timeout per scan
- Max concurrent scans with queue limits
- Hot-reload when YARA rule version changes (mesh distribution)

### Archive Inspection

ZIP archive analysis:

```rust
pub struct ArchiveInspectionConfig {
    pub enabled: bool,
    pub max_depth: u32,                    // Default: 3
    pub max_entries: u32,
    pub max_total_uncompressed_bytes: u64,  // Default: 100MB
    pub max_entry_uncompressed_bytes: u64,
    pub max_compression_ratio: f64,
    pub max_nested_archives: u32,
}
```

### Sandbox

UUID-based temp directories with platform-level sandboxing:

```rust
pub struct Sandbox {
    pub config: SandboxConfig,
}

pub struct SandboxConfig {
    pub sandbox_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub sandbox_level: SandboxLevel,
}

// Platform backends (via synvoid-platform):
// - macOS: Seatbelt
// - Linux: Landlock
// - FreeBSD: Capsicum
// - Other: Stub (no-op)
```

### Quarantine

Malicious files quarantined with metadata:

```rust
pub struct QuarantineEntry {
    pub id: Uuid,
    pub original_filename: Option<String>,
    pub detected_mime: Option<String>,
    pub file_path: PathBuf,
    pub metadata_path: PathBuf,
    pub yara_matches: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
```

## Failure Policies

```rust
pub enum UploadScanFailurePolicy {
    FailClosed,           // Reject on scan error
    FailOpen,             // Allow on scan error
    QuarantineOnError,    // Quarantine on error
}
```

## Integration Points

- Used by HTTP upload handlers
- Config from `synvoid-config` with per-path overrides
- YARA rules distributed via mesh
- Metrics via `metrics` crate
- Quarantine for forensics

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `UploadValidator` | `crates/synvoid-upload/src/lib.rs` | Main entry point |
| `ValidationResult` | `crates/synvoid-upload/src/lib.rs` | Rich result with scan status |
| `YaraScanner` | `crates/synvoid-upload/src/yara_scanner.rs` | YARA compilation and scanning |
| `Sandbox` | `crates/synvoid-upload/src/sandbox.rs` | File isolation |
| `ArchiveInspectionConfig` | `crates/synvoid-upload/src/archive.rs` | Archive inspection parameters |

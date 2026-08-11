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
    rules: Arc<CompiledRules>,
    config: YaraScanConfig,
}

pub enum ScanMode {
    Full,           // Scan entire file
    HeaderOnly,     // First N bytes
    Windowed { offset, size },  // Specific region
}
```

- Bundled and custom rule sources
- Configurable timeout per scan
- Max concurrent scans with queue limits
- Hot-reload when YARA rule version changes (mesh distribution)

### Archive Inspection

ZIP archive analysis:

```rust
pub struct ArchiveInspectionConfig {
    max_entries: usize,
    max_entry_size: u64,
    max_total_size: u64,
    check_nested: bool,         // Recursion currently disabled
    reject_path_traversal: bool,
    reject_absolute_paths: bool,
    reject_unc_paths: bool,
    reject_symlinks: bool,
}
```

### Sandbox

UUID-based temp directories with platform-level sandboxing:

```rust
pub struct Sandbox {
    temp_dir: PathBuf,
    sandbox: ProcessSandbox,  // From synvoid-platform
}

// Platform backends:
// - macOS: Seatbelt
// - Linux: Landlock
// - FreeBSD: Capsicum
// - Other: Stub (no-op)
```

### Quarantine

Malicious files quarantined with metadata:

```rust
pub struct QuarantineEntry {
    pub filename: String,
    pub mime_type: String,
    pub yara_matches: Vec<YaraMatch>,
    pub quarantined_at: u64,
    pub original_path: String,
}
```

## Failure Policies

```rust
pub enum FailurePolicy {
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
| `ValidationResult` | `crates/synvoid-upload/src/result.rs` | Rich result with scan status |
| `YaraScanner` | `crates/synvoid-upload/src/yara.rs` | YARA compilation and scanning |
| `Sandbox` | `crates/synvoid-upload/src/sandbox.rs` | File isolation |
| `ArchiveInspectionConfig` | `crates/synvoid-upload/src/archive.rs` | Archive inspection parameters |

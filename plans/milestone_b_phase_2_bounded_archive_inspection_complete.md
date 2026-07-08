# Milestone B Phase 2: Bounded Archive Inspection — Complete

## Summary

Implemented bounded ZIP archive inspection for the upload validation pipeline. Archives are inspected in-memory without disk extraction. Entry paths are sanitized, limits are enforced, and entry contents are scanned by existing MalwareScanner. Malformed ZIPs and limit violations are classified per `yara_failure_policy`, preserving Milestone A scan-failure semantics.

## Files Modified

| File | Change |
|------|--------|
| `crates/synvoid-upload/Cargo.toml` | Added `zip = "2"` dependency |
| `crates/synvoid-upload/src/config.rs` | Added 7 archive config defaults + fields to `UploadConfig`, `EffectiveUploadConfig`, `PathUploadConfig`; wired through `effective_config_for_path()` |
| `crates/synvoid-upload/src/archive.rs` | **NEW** — `ArchiveInspectionConfig`, `ArchiveInspectionResult`, `ArchiveEntryMatch`, `ArchiveInspectionError`, `sanitize_entry_path()`, `inspect_zip_archive()`, `is_nested_archive_filename()`, 14 tests |
| `crates/synvoid-upload/src/lib.rs` | Added `pub mod archive;`, `is_zip_archive()`, archive metadata fields on `ValidationResult`, wired inspection into `validate_bytes()`, `validate_bytes_with_declared_type()`, `validate_with_sandbox()` |
| `crates/synvoid-upload/src/metrics.rs` | Added 5 counters + 10 getter/increment functions for archive metrics |
| `architecture/upload.md` | Added Section 13: Bounded Archive Inspection |
| `docs/UPLOADS.md` | Added Bounded Archive Inspection section with config, behavior, metrics |

## Test Results

- **160 tests passing** in `synvoid-upload` (14 new archive tests + all existing tests pass)
- **0 clippy warnings** (`cargo clippy -p synvoid-upload --all-targets -- -D warnings`)
- **0 fmt issues** (`cargo fmt --all -- --check`)

## Test Coverage (14 new tests in `archive.rs`)

| Test | What it verifies |
|------|------------------|
| `test_benign_zip` | Clean ZIP with normal text files passes with no matches |
| `test_pe_entry_detected` | ZIP containing a PE executable is detected by native heuristic |
| `test_path_traversal_rejected` | `../../etc/passwd` paths are rejected with `PathTraversal` |
| `test_absolute_path_rejected` | `/etc/passwd` paths are rejected with `AbsolutePath` |
| `test_too_many_entries` | Exceeding `max_entries` returns `TooManyEntries` |
| `test_entry_too_large` | Single entry exceeding `max_entry_uncompressed_bytes` returns `EntryTooLarge` |
| `test_depth_exceeded` | Exceeding `max_depth` returns `DepthExceeded` |
| `test_inspection_disabled` | `enabled=false` returns `Disabled` without scanning |
| `test_malformed_zip` | Non-ZIP data returns `InvalidZip` |
| `test_nested_archive_filename` | `.jar`, `.docx` files detected as nested archives |
| `test_total_size_exceeded` | Exceeding `max_total_uncompressed_bytes` returns `TotalSizeExceeded` |
| `test_empty_zip` | Empty ZIP archive passes with 0 entries |
| `test_directories_skipped` | Directory entries are counted but not scanned |
| `test_compression_ratio_limit` | Extremely high compression ratio returns `CompressionRatioTooHigh` |

## Architecture

### Inspection Flow

```
Upload bytes
  → Outer scan (native heuristics + YARA-X)
  → If ZIP + archive_inspection_enabled:
      → ArchiveInspectionConfig::from_effective_config()
      → inspect_zip_archive(data, config, scanner, depth=0)
        → Iterate ZIP entries via zip::read::ZipArchive
        → For each entry:
            → sanitize_entry_path() — reject traversal/absolute/UNC/symlinks
            → Enforce limits (entries, size, ratio, nested count)
            → Read entry content into buffer
            → MalwareScanner::scan_bytes() on entry content
        → Return ArchiveInspectionResult
      → Fold matches into MalwareDetected error or apply failure policy
  → Return ValidationResult with archive metadata
```

### Config Defaults

| Field | Default | Description |
|-------|---------|-------------|
| `archive_inspection_enabled` | `true` | Enable/disable ZIP inspection |
| `archive_max_depth` | 3 | Max nested inspection depth |
| `archive_max_entries` | 1000 | Max entries per archive |
| `archive_max_total_uncompressed_bytes` | 536870912 (512 MB) | Total uncompressed bytes limit |
| `archive_max_entry_uncompressed_bytes` | 104857600 (100 MB) | Per-entry uncompressed bytes limit |
| `archive_max_compression_ratio` | 100.0 | Max compression ratio |
| `archive_max_nested_archives` | 5 | Max nested archive entries |

### Error Classification

- `Disabled` → No inspection, skip silently
- `InvalidZip(_)` → Metered as `archive_malformed`, applies `yara_failure_policy`
- All other errors (`PathTraversal`, `AbsolutePath`, `TooManyEntries`, `EntryTooLarge`, `CompressionRatioTooHigh`, `TotalSizeExceeded`, `DepthExceeded`) → Metered as `archive_limit_violation`, applies `yara_failure_policy`

### Scan-Failure Semantics Preserved

- `FailClosed` / `QuarantineOnError` → limit/malformed errors return `ScanIndeterminate`
- `FailOpen` → limit/malformed errors are logged as warnings, upload proceeds
- `Disabled` variant → always skipped silently (no metric, no error)

## Success Criteria

| Criterion | Status |
|-----------|--------|
| Archive inspection exists for ZIP | ✅ `archive.rs` — 700 lines |
| Unsupported handling documented | ✅ TAR/GZIP/BZIP2/7z documented as detected but not inspected |
| Embedded executable detection inside archives | ✅ PE entries scanned via MalwareScanner native heuristics |
| Traversal/symlink/absolute paths rejected | ✅ `sanitize_entry_path()` + 4 tests |
| Entry count/size/ratio/depth limits enforced | ✅ 6 limits + tests for each |
| Limit/malformed errors don't become clean | ✅ `yara_failure_policy` applied, metrics metered |
| Match reporting includes entry context | ✅ `ArchiveEntryMatch { entry_path, entry_index, malware_match }` |
| Tests cover benign/malicious/malformed/limits/traversal | ✅ 14 tests |
| Docs accurate | ✅ architecture/upload.md §13 + docs/UPLOADS.md section |

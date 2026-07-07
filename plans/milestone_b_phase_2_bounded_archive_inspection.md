# Milestone B Phase 2: Bounded Archive Inspection

## Purpose

Implement or formally scope bounded archive inspection for uploads so archive-related detections are based on actual archive structure rather than shallow byte heuristics. This phase builds on Phase 1 detector correctness and must preserve Milestone A scan-failure semantics.

The goal is not to become a full antivirus engine. The goal is to safely inspect common archive containers enough to detect embedded executables, obvious archive bombs, nested archives within configured limits, and path traversal/symlink abuse, while keeping memory, CPU, and extraction risk bounded.

## Current issues to address

1. Existing archive-related controls expose depth/size limit names, but the scanner does not perform true archive traversal.
2. Current archive-bomb detection appears heuristic and does not validate entry count, uncompressed size, compression ratio, nesting depth, or path safety.
3. Embedded executable detection should inspect archive entries, not only the outer file bytes.
4. Archive inspection must not extract attacker-controlled paths to the real filesystem.
5. Scanning each entry must use the corrected scanner APIs from Phase 1 so YARA errors do not become clean fallback results.
6. Large archives must be bounded by explicit budgets and produce indeterminate/rejected outcomes under production defaults when inspection cannot complete safely.

## Non-goals

- Do not add broad support for every archive format at once.
- Do not perform unsafe filesystem extraction.
- Do not implement password cracking or recursive decompression beyond configured limits.
- Do not inspect unbounded compressed streams.
- Do not accept partial archive inspection as clean full coverage without explicit metadata.

## Format support policy

Start with the smallest useful set:

1. ZIP: required for this phase.
2. TAR: preferred if implementation cost is low and dependencies are already acceptable.
3. Gzip-wrapped single file: optional, useful but not release-blocking.
4. RAR/7z: defer unless a safe, lightweight, license-compatible, maintained crate is already acceptable.

If only ZIP is implemented, document that clearly. Archive type support must be explicit in docs and scan metadata.

## Dependency constraints

Before adding dependencies, evaluate:

- maintenance state
- RustSec/advisory state
- transitive dependency size
- memory behavior
- support for streaming entry metadata without extraction
- ability to bound decompressed bytes
- license compatibility

Prefer crates already in the dependency graph if safe. If adding a new archive crate, update `deny.toml` rationale if needed and run local dependency checks.

## Archive inspection model

Introduce an explicit archive inspection layer, for example:

```rust
struct ArchiveInspectionConfig {
    enabled: bool,
    max_depth: u32,
    max_entries: u32,
    max_total_uncompressed_bytes: u64,
    max_entry_uncompressed_bytes: u64,
    max_compression_ratio: f64,
    max_nested_archives: u32,
    scan_entry_mode: ArchiveEntryScanMode,
}

enum ArchiveEntryScanMode {
    Full,
    Windowed,
}

struct ArchiveInspectionResult {
    inspected: bool,
    archive_type: Option<String>,
    entries_seen: u32,
    entries_scanned: u32,
    nested_archives_seen: u32,
    max_depth_reached: u32,
    total_uncompressed_bytes_seen: u64,
    truncated: bool,
    matches: Vec<MalwareMatch>,
    warnings: Vec<String>,
}
```

This can be smaller if existing config already has equivalent fields. The important requirement is that scan coverage and truncation are visible to callers.

## Safety rules

Archive inspection must follow these rules:

1. Never extract entries to attacker-controlled paths.
2. Normalize archive entry paths and reject:
   - absolute paths
   - `..` traversal
   - Windows drive prefixes
   - UNC paths
   - embedded NULs
   - symlinks/hardlinks where the format exposes them
3. Enforce max entry count.
4. Enforce max per-entry uncompressed bytes.
5. Enforce max total uncompressed bytes.
6. Enforce max compression ratio where compressed/uncompressed sizes are available.
7. Enforce max recursion depth.
8. Enforce max nested archive count.
9. Treat malformed archive structure as indeterminate or malicious according to policy; do not silently treat as clean full inspection.
10. Avoid loading the entire archive plus all entries into memory at once.

## Implementation plan

### 1. Add archive detection and dispatch

Add a small archive dispatcher that identifies supported archive types by magic bytes and, where available, MIME detection:

- ZIP: `PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`
- TAR: ustar marker at the expected offset, if implemented
- gzip: `1f 8b`, if implemented

The dispatcher should return `Unsupported`, `NotArchive`, or `Supported(type)`.

### 2. Implement ZIP inspection first

For ZIP:

- iterate entries without extracting to disk
- inspect entry metadata before reading contents
- reject unsafe paths
- reject symlinks if exposed by the crate or Unix mode bits
- enforce entry count
- enforce per-entry and aggregate uncompressed byte limits
- enforce compression ratio if compressed size is available
- scan each entry through corrected scanner APIs
- detect nested archives by magic bytes in entry content or entry name and recurse only within depth limits

### 3. Integrate with upload scanning

Add an archive-aware path in upload validation:

- scan outer bytes as usual
- if archive inspection is enabled and the file is a supported archive, inspect entries
- combine outer and entry matches deterministically
- set scan/coverage metadata indicating archive inspection occurred
- if archive inspection fails due to limit/malformed/scan error, return indeterminate under production defaults unless a configured policy says otherwise

Avoid double-counting full file bytes in coverage metadata. It is acceptable to add archive-specific metadata separate from large-file byte coverage.

### 4. Archive bomb detection

Replace or supplement heuristic archive-bomb detection with structural checks:

- too many entries -> `ArchiveLimitExceeded`
- total uncompressed bytes exceeded -> `ArchiveLimitExceeded`
- single entry too large -> `ArchiveLimitExceeded`
- compression ratio exceeded -> `ArchiveBombSuspected`
- nested depth exceeded -> `ArchiveDepthExceeded`

Map these to upload policy:

- public upload default: reject/quarantine
- internal explicitly configured mode: allow only with indeterminate status if product policy permits

### 5. Nested archive handling

Nested inspection must be budgeted:

- decrement remaining depth
- decrement remaining nested archive count
- carry forward total entry and uncompressed byte budgets
- avoid recursion on same bytes repeatedly
- avoid unbounded stack recursion; iterative queue is preferred if implementation is straightforward

### 6. Context-aware match reporting

When an entry match is found, include entry context:

- archive type
- entry path, sanitized for logs
- entry index
- depth
- rule source
- match rule/category

Do not include raw payload bytes in normal logs.

### 7. Tests

Add tests for:

- benign ZIP with one text file -> no matches, inspected true.
- ZIP with embedded PE -> embedded executable match.
- ZIP with PE/ZIP polyglot entry -> polyglot match.
- ZIP with nested ZIP within depth -> nested payload detected.
- ZIP nested beyond depth -> rejected/indeterminate according to policy.
- ZIP with too many entries -> limit exceeded.
- ZIP with large uncompressed entry -> limit exceeded.
- ZIP with high compression ratio -> archive bomb suspected if ratio threshold is exceeded.
- ZIP path traversal entry `../evil` -> rejected.
- ZIP absolute path `/tmp/evil` -> rejected.
- ZIP Windows drive path `C:\evil` -> rejected.
- ZIP symlink entry -> rejected if symlink metadata is detectable.
- malformed ZIP -> indeterminate/rejected, not clean.
- unsupported archive type -> clearly marked unsupported; outer scan still applies.

Use in-memory test archives. Do not rely on external fixture downloads.

### 8. Documentation

Update docs to state:

- supported archive formats
- default archive inspection limits
- how unsupported archives are treated
- how limit exceedance maps to rejection/indeterminate status
- that archive inspection is bounded and not exhaustive antivirus coverage
- how entry paths are sanitized

## Configuration guidance

Recommended defaults for public uploads:

```toml
archive_scan_enabled = true
archive_max_depth = 3
archive_max_entries = 512
archive_max_total_uncompressed_bytes = 104857600
archive_max_entry_uncompressed_bytes = 52428800
archive_max_compression_ratio = 100.0
archive_max_nested_archives = 32
```

Use existing config names where already present. Do not introduce duplicate names if `archive_max_depth` or `archive_max_size` already exists; extend semantics around those fields or migrate carefully.

## Local validation commands

Minimum:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo test -p synvoid-upload --all-targets archive
cargo test -p synvoid-upload --all-targets
```

Preferred:

```bash
cargo test -p synvoid-upload --features mesh --all-targets
cargo test -p synvoid-upload --all-features --all-targets
cargo deny check
```

If archive dependencies are added:

```bash
cargo tree -p synvoid-upload
cargo deny check bans advisories licenses sources
```

## Success criteria

- Archive inspection exists for at least ZIP or unsupported archive handling is explicitly documented as deferred.
- Embedded executable detection works inside supported archives.
- Archive traversal, symlink, and absolute path entries are rejected.
- Entry count, size, compression ratio, and depth limits are enforced.
- Limit/malformed/scan errors do not become clean results under production defaults.
- Match reporting includes archive entry context without leaking raw payloads.
- Tests cover benign, malicious, malformed, limit-exceeded, and traversal archives.
- Docs accurately describe supported formats and limits.

## Handoff notes

This phase should be implemented after Phase 1 so archive entry scanning inherits corrected native/YARA error propagation. If Phase 1 is not complete, do not wire archive inspection into production validation paths yet; add isolated archive parsing tests only.

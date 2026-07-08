# Milestone B Residual Archive Hardening Plan

## Purpose

This plan closes the remaining minor hardening items after Milestone B implementation. The repo now has implementations for native detector correctness, bounded ZIP inspection, honeypot listener/accounting, protocol detection, and confidence-aware threat-intel capping. The remaining work is semantic tightening, not a new milestone.

This pass should focus on:

1. Making ZIP-only and non-recursive archive behavior unambiguous in code, docs, metadata, and tests.
2. Classifying archive structural violations as archive/security policy violations rather than generic malware matches unless intentionally modeled otherwise.
3. Auditing ZIP symlink detection using external file mode bits rather than platform-dependent directory behavior.
4. Recording local verification output because GitHub CI cannot be relied on for this line right now.

## Current status

Implemented:

- Bounded in-memory ZIP inspection via `crates/synvoid-upload/src/archive.rs`.
- Archive config fields for enablement, depth, entry count, aggregate bytes, per-entry bytes, compression ratio, and nested archive count.
- ZIP entry path sanitization for traversal, absolute paths, Windows drive prefixes, UNC-style paths, and NULs.
- Per-entry malware scanning through the upload malware scanner.
- Archive metrics and documentation.
- Confidence capping in honeypot threat-intel extraction.
- Local validation claims for upload and honeypot tests, clippy, and fmt.

Remaining concerns:

- Archive inspection is ZIP-only and nested archives are detected but not recursively inspected by default. This is acceptable only if docs, metadata, and tests never imply complete recursive archive coverage.
- Path traversal/absolute path/symlink conditions should be represented as archive inspection violations, not just synthetic malware matches, unless the product deliberately treats them as policy-blocking matches with distinct categories.
- ZIP symlink handling must be based on ZIP external attributes where possible. `is_dir()` or platform-dependent behavior is not enough to reject symlink entries reliably.
- Local validation output needs a clear handoff note for the final residual pass.

## Workstream 1: ZIP-only and non-recursive archive semantics

### Problem

Archive inspection currently supports ZIP only. Nested archives are counted by filename but not recursively inspected by default. This is acceptable for a bounded first pass, but the code and docs must not imply that `archive_max_depth` currently means recursive inspection is active.

### Tasks

1. Audit `ArchiveInspectionConfig` and `ArchiveInspectionResult` fields:

- `max_depth`
- `max_depth_reached`
- `nested_archives_seen`
- `truncated`
- `warnings`

2. Ensure `max_depth` semantics are accurate.

Preferred approach:

- If recursive nested inspection is not implemented, document `archive_max_depth` as reserved for future recursive inspection or apply it only when recursion is enabled.
- Consider adding `archive_recursive_inspection_enabled = false` only if product settings need to express the distinction now.
- Ensure `max_depth_reached` reports the actual depth inspected, not the configured max.

3. Ensure nested archive matches/metadata are clear:

- A nested ZIP/JAR/DOCX entry should set `nested_archives_seen += 1`.
- It should not set `entries_scanned` for inner entries unless inner entries were actually scanned.
- It should add a warning or metadata note such as `nested archive detected but not recursively inspected`.
- It should not imply full recursive inspection coverage.

4. Add tests:

- ZIP containing nested ZIP with embedded executable: outer inspection detects nested archive count but does not claim inner executable detection unless recursion is implemented.
- `max_depth_reached` remains accurate for non-recursive inspection.
- docs/example metadata for nested archives is consistent with behavior.

5. Update docs:

- `architecture/upload.md`
- `docs/UPLOADS.md`
- any Phase 2 completion note

Docs should say:

- ZIP is structurally inspected.
- TAR/GZIP/BZIP2/7z are not structurally inspected.
- Nested archives are detected/count-limited but not recursively opened unless a future recursive mode is implemented.
- Outer bytes and each directly inspected ZIP entry are scanned.

### Success criteria

- No code comment, config doc, or metric implies recursive inspection when it is not implemented.
- Nested archive metadata distinguishes detection from recursive scanning.
- Tests lock this behavior.

## Workstream 2: Archive structural violation classification

### Problem

Path traversal, absolute paths, UNC paths, Windows drive prefixes, symlinks, and limit violations are structural archive/security policy violations. If these are represented as synthetic `MalwareMatch` entries, downstream consumers may confuse malformed/malicious archive structure with malware signature detection.

The product may still block these uploads, but the classification should be explicit.

### Tasks

1. Review all `ArchiveInspectionError` variants:

- `PathTraversal`
- `AbsolutePath`
- `UncPath`
- `SymlinkRejected`
- `TooManyEntries`
- `EntryTooLarge`
- `CompressionRatioTooHigh`
- `TotalSizeExceeded`
- `TooManyNestedArchives`
- `DepthExceeded`
- `InvalidZip`

2. Decide final representation:

Preferred representation:

- Structural violations return `ArchiveInspectionError`.
- Upload validator maps archive inspection errors through the configured failure policy.
- `FailClosed` and `QuarantineOnError` reject/quarantine.
- `FailOpen` allows but returns indeterminate/non-clean status with archive error metadata.
- Archive-specific metrics increment.

Alternative representation:

- Structural violations are represented as `ArchiveEntryMatch` with `MatchSource::Native`, category `archive_policy_violation`, and confidence `High`.
- These must be clearly distinct from malware signatures.
- Docs must state that archive policy violations are blocking matches.

3. If synthetic matches remain, rename categories/rules to avoid malware-signature ambiguity:

- `archive_path_traversal`
- `archive_absolute_path`
- `archive_unc_path`
- `archive_symlink_entry`
- `archive_limit_exceeded`
- `archive_malformed`

4. Ensure downstream upload behavior blocks under production defaults regardless of representation.

5. Add tests:

- traversal entry returns structural error or clearly named policy-violation match.
- absolute path entry returns structural error or clearly named policy-violation match.
- too many entries returns limit violation, not clean.
- malformed ZIP returns indeterminate/rejected, not clean.
- fail-open on structural violation returns allowed-but-indeterminate/non-clean if using error path.

### Success criteria

- Structural archive violations cannot be mistaken for clean uploads.
- Structural archive violations are not mislabeled as ordinary malware signature hits unless intentionally categorized as `archive_policy_violation`.
- Metrics and docs use the same terminology as code.

## Workstream 3: ZIP symlink detection audit

### Problem

ZIP symlink detection is not portable if it relies on directory detection or platform-specific extraction behavior. ZIP symlink entries are usually indicated through Unix external file attributes. The implementation should inspect those attributes directly where the `zip` crate exposes them.

### Tasks

1. Inspect `zip::read::ZipFile` metadata APIs available in the chosen `zip` crate version.

Look for:

- `unix_mode()`
- external attributes
- file mode bits

2. Implement a helper:

```rust
fn is_zip_symlink(entry: &zip::read::ZipFile<'_, impl Read>) -> bool
```

or an equivalent helper compatible with the actual type signatures.

Expected Unix mode check:

- symlink file type bits: `0o120000`
- mask: `0o170000`
- `(mode & 0o170000) == 0o120000`

3. Reject symlink entries before reading contents.

4. Add tests that create a ZIP entry with Unix symlink mode bits. If the test ZIP builder cannot set mode bits directly, create a small helper fixture in memory or document why this is not possible with the current crate.

5. Confirm directory entries remain allowed/ignored as directories and are not confused with symlinks.

6. Update docs to remove platform ambiguity if the mode-bit check is implemented.

### Success criteria

- ZIP symlink rejection is based on external mode bits where available.
- Symlink fixtures are tested.
- Directory entries are not falsely rejected as symlinks.
- Docs no longer rely on vague platform-specific behavior unless there is a documented crate limitation.

## Workstream 4: Archive scan metadata and observability

### Problem

Operators need to distinguish these cases:

- no archive detected
- unsupported archive type
- ZIP inspected fully within configured limits
- ZIP inspected partially/truncated by limit
- ZIP rejected due structural violation
- malformed ZIP
- nested archive detected but not recursively inspected
- archive entry malware match

### Tasks

1. Extend result metadata or validation metadata to carry a compact archive inspection summary.

Fields should include:

- `archive_detected: bool`
- `archive_type: Option<String>`
- `archive_supported: bool`
- `archive_inspected: bool`
- `archive_entries_seen: u32`
- `archive_entries_scanned: u32`
- `archive_nested_seen: u32`
- `archive_recursive_inspection: bool`
- `archive_truncated: bool`
- `archive_error: Option<String>`

2. Ensure logs/metrics include archive error categories without raw entry contents.

3. Ensure docs describe these states.

4. Add tests for metadata states:

- non-archive upload
- supported ZIP inspected
- unsupported TAR/GZIP magic if detection exists
- malformed ZIP
- nested ZIP detected but not opened
- limit exceeded

### Success criteria

- Operators can distinguish partial archive coverage from clean full inspection.
- Unsupported archives are not reported as structurally inspected.
- Archive metadata avoids raw payload leakage.

## Workstream 5: Final local validation evidence

### Problem

GitHub CI remains unavailable/unreliable for this workstream. The final residual pass should leave an explicit local validation note.

### Tasks

1. Add or update:

- `plans/milestone_b_local_validation_note.md`

2. Record exact local commands and summarized output:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-upload --all-targets -- -D warnings
cargo test -p synvoid-upload --all-targets
cargo test -p synvoid-upload --all-features --all-targets
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
cargo deny check
```

3. If a command cannot run locally, record:

- exact failure
- whether it is environment/tooling/product
- substitute command
- follow-up plan if product-related

4. Update commit message with the validation summary.

### Success criteria

- Final Milestone B residual closure claims are backed by local command evidence.
- Any non-clean command is explicitly documented.

## Suggested execution order

1. Fix symlink detection first because it affects structural violation tests.
2. Normalize archive structural violation classification.
3. Tighten ZIP-only/non-recursive metadata and docs.
4. Add archive observability metadata if not already present.
5. Run and record local validation.

## Final acceptance checklist

- [ ] ZIP-only support is explicit in docs and metadata.
- [ ] Nested archives are not reported as recursively inspected unless recursion exists.
- [ ] `archive_max_depth` semantics are clarified or guarded behind recursive inspection.
- [ ] Structural archive violations are returned as errors or clearly labeled archive policy violations.
- [ ] Traversal/absolute/UNC/path-limit tests cover final behavior.
- [ ] ZIP symlink detection uses Unix mode bits where available.
- [ ] Symlink fixture test exists or a crate limitation is documented.
- [ ] Archive metadata distinguishes no archive, unsupported archive, inspected ZIP, malformed ZIP, limit violation, and nested-not-recursed.
- [ ] Local validation note is added or updated.
- [ ] Upload and honeypot docs match final behavior.

## Handoff guidance

Do not expand this pass into TAR/GZIP/7z structural inspection unless the current ZIP semantics are already closed. Additional archive format support should be a future milestone or an explicit Phase 2 extension after this residual hardening is complete.

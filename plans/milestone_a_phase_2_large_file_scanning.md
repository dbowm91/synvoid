# Milestone A Phase 2: Full-File and Large-File Scanning Correctness

## Objective

Make YARA-backed upload scanning meaningful for large files. MIME detection may remain header-based, but malware scanning must not be limited to the first 8 KiB when YARA scanning is enabled.

This phase should land after Phase 1 so that scan errors and timeouts are already failure-explicit. Expanding coverage without fixing failure semantics first would still leave the upload boundary vulnerable during scanner failure.

## Current risk summary

`validate_large_file` currently reads a fixed header and scans only that header. This can miss payloads that occur after the first 8 KiB, including appended executables, embedded webshells, macro streams, archive members, payloads in polyglots, and malicious content hidden in otherwise benign-looking containers.

The current behavior is acceptable for MIME sniffing. It is not acceptable as the sole malware scanning strategy for a public upload path.

## Desired behavior

Add explicit scan modes for large files and make production defaults safe.

Recommended scan modes:

- `full`: read and scan the entire upload up to the configured upload size limit.
- `windowed`: scan bounded windows from the file: header, footer, selected middle windows, and offsets around suspicious magic signatures.
- `header_only`: scan only the header. This should be documented as low-assurance and not recommended for production upload endpoints.

Recommended defaults:

- Small files: full scan.
- Large files within max upload limit: full scan unless explicitly configured for windowed mode.
- Very large accepted files: windowed scan with explicit warning in config docs.
- `header_only`: opt-in only.

## Implementation plan

### Step 1: Add scan mode config

Add a large-file scan mode to upload config and effective config.

Candidate enum:

```rust
pub enum YaraLargeFileScanMode {
    Full,
    Windowed,
    HeaderOnly,
}
```

Candidate config fields:

```toml
[upload]
yara_large_file_scan_mode = "full"
yara_window_size_bytes = 1048576
yara_max_window_count = 8
yara_magic_scan_limit_bytes = 16777216
```

Keep the initial config simple if needed, but the implementation should avoid hardcoding 8 KiB as the malware scan extent.

### Step 2: Separate MIME detection from malware scanning

Keep header read behavior for MIME detection:

- Read `HEADER_READ_SIZE` or a configured MIME sniff size.
- Use that for MIME detection only.

Then construct the YARA scan input according to scan mode.

For `full`, read the full sandboxed file and scan the full contents. Since upload size is already bounded by effective config, this should be acceptable for common production limits.

For `windowed`, collect windows without unbounded memory growth. Include:

- Header window.
- Footer window.
- Evenly spaced middle windows.
- Windows around suspicious offsets found by scanning for magic markers such as `MZ`, `PK\x03\x04`, ELF, Mach-O, PHP open tags, script tags, and office container signatures.

Represent windowed results carefully so a match can report approximate offset/window identity where possible.

For `header_only`, preserve current behavior but mark the result as low coverage.

### Step 3: Add scanner APIs for file-backed scanning

Avoid unnecessary `Vec` copies for large files where possible. Introduce one or more APIs:

```rust
scan_file_with_mode(path, mode, excluded_categories)
scan_reader_windows(reader, config, excluded_categories)
scan_bytes_with_context(data, context, excluded_categories)
```

YARA-X may require a contiguous byte slice for the actual scan call. If so, make the memory behavior explicit and bounded by scan mode.

### Step 4: Preserve sandbox/quarantine behavior

`validate_large_file` already has a sandbox handle and can quarantine the file by path. Keep that behavior. If scan mode is `full`, avoid copying the upload into a second temporary file. Use the existing sandbox path.

If malware is detected, quarantine the original sandboxed file. If scan is indeterminate, apply the Phase 1 failure policy.

### Step 5: Add coverage metadata

Extend `ValidationResult` or scan result metadata to include:

- scan mode
- bytes scanned
- windows scanned, if windowed
- rule version/hash if available
- scan duration

This helps operators understand whether a large file was fully scanned or sampled.

## Tests

Minimum tests:

1. A malicious payload located after byte 8192 is detected in `full` mode.
2. The same payload is not falsely reported as clean when scan mode is `windowed`; either detected by configured windows or explicitly reported with windowed coverage metadata.
3. A trailing malicious payload near EOF is detected by footer/windowed scan.
4. An embedded executable marker beyond the header is detected by full scan.
5. MIME detection still uses the header and enforces allowed MIME types.
6. Large files exceeding `max_size_bytes` are rejected before scanning.
7. Scan timeout/error in large-file validation follows Phase 1 policy.
8. `header_only` mode is opt-in and reports header-only coverage.

Use deterministic synthetic byte fixtures rather than large checked-in binary blobs when possible. Generate test buffers in memory or temporary files.

## Performance considerations

Full-file scanning is simpler and safer but can increase memory pressure. The implementation should respect configured upload size limits and the bounded scan executor from Phase 3 once it exists. Before Phase 3 lands, avoid adding any unbounded concurrent file reads.

Windowed scanning is not equivalent to full scanning. It should be framed as a resource tradeoff, not a complete malware guarantee.

Do not implement archive traversal in this phase unless it is trivial. Archive traversal belongs to the later detector/archive milestone. This phase is about not scanning only the first 8 KiB of an already materialized upload.

## Documentation updates

Document scan modes in upload configuration docs. Include examples:

```toml
[upload]
scan_with_yara = true
yara_large_file_scan_mode = "full"
yara_timeout_ms = 30000
```

For constrained deployments:

```toml
[upload]
scan_with_yara = true
yara_large_file_scan_mode = "windowed"
yara_window_size_bytes = 1048576
yara_max_window_count = 8
```

Explicitly warn that `header_only` is low assurance and should not be used for public executable/archive/document upload surfaces.

## Success criteria

- `validate_large_file` no longer scans only the first 8 KiB under production defaults.
- Full scan mode detects payloads beyond the header.
- Windowed mode is explicit and reports coverage.
- Scan failure behavior remains consistent with Phase 1.
- Tests cover post-header, middle, and trailing payloads.
- Documentation makes scan coverage understandable to operators.

## Non-goals

- Do not redesign scan executor concurrency here; that is Phase 3.
- Do not implement signed rule feed provenance here; that is Phase 4.
- Do not make archive-bomb claims unless actual archive traversal is implemented in a later milestone.
- Do not modify honeypot/tarpit behavior in this phase.

## Handoff checklist

- [ ] Add large-file scan mode enum and config wiring.
- [ ] Separate MIME header sniffing from malware scan coverage.
- [ ] Implement full-file scan path for sandboxed large files.
- [ ] Implement windowed scan path or defer with explicit config guard.
- [ ] Add coverage metadata to validation/scan results.
- [ ] Preserve quarantine behavior for malicious large files.
- [ ] Apply Phase 1 failure policy for indeterminate large-file scans.
- [ ] Add tests for malicious payloads beyond first 8 KiB.
- [ ] Update config docs and examples.
- [ ] Run `cargo test -p synvoid-upload`.

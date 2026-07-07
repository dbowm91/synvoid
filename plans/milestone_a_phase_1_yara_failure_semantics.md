# Milestone A Phase 1: YARA Failure Semantics and Upload Safety Closure

## Objective

Make upload malware scanning failure-explicit across all validation paths. A YARA timeout, scan panic, rule deserialization failure, scan execution error, unavailable scanner, or reload failure must not be represented as a clean upload under production defaults.

This phase is the first priority because it closes the clearest production security bug in the upload boundary: the current validation flow can log a scan error and continue as though the file has no malware matches.

## Current risk summary

The current upload validator has several paths that call `scanner.scan_bytes(data).await`, log `Malware scan error`, and continue with `(true, Vec::new())`. This makes the validation result say that scanning happened and found no matches. That behavior creates false confidence and can allow hostile files through during scanner failure, timeout, broken rule reload, or dependency-level scan failure.

Affected conceptual paths include:

- `UploadValidator::validate_bytes`
- `UploadValidator::validate_bytes_with_declared_type`
- `UploadValidator::validate_with_sandbox`
- `UploadValidator::validate_large_file`

This phase should avoid broad refactors except where needed to make the failure semantics consistent and testable.

## Desired behavior

Introduce explicit scan status and explicit failure policy.

Recommended scan statuses:

- `Clean`: scan completed and no matches were found.
- `Malicious`: scan completed and one or more matches were found.
- `Disabled`: scanning was disabled by effective config.
- `Unavailable`: scan was requested but no scanner was available.
- `Indeterminate`: scan was attempted but did not complete successfully.

Recommended failure policy values:

- `fail_closed`: reject the upload on scanner error, timeout, panic, unavailable scanner, or reload failure.
- `quarantine_on_error`: quarantine the upload if possible, then reject with a scan-indeterminate error.
- `fail_open`: allow upload on scan failure, but mark the result as scan-indeterminate and emit explicit warning metrics/logs. This must be opt-in, never the production default.

Recommended default:

- Global default: `quarantine_on_error` or `fail_closed`.
- Path-level override allowed for intentionally low-risk paths.
- `fail_open` requires explicit config and should be documented as unsafe for public upload endpoints.

## Implementation plan

### Step 1: Add config representation

Add a scan failure policy field to upload configuration. Prefer a typed enum rather than an unstructured string.

Candidate enum:

```rust
pub enum UploadScanFailurePolicy {
    FailClosed,
    QuarantineOnError,
    FailOpen,
}
```

Wire it through:

- `UploadConfig`
- `EffectiveUploadConfig`
- path-specific upload config overlays
- TOML deserialization
- config docs and examples

Use serde aliases if helpful, but keep canonical values stable.

### Step 2: Add validation result semantics

Extend `ValidationResult` so it can represent scan state without forcing callers to infer from `scanned: bool` and `yara_matches: Vec<String>`.

Candidate fields:

```rust
pub scan_status: UploadScanStatus,
pub scan_error: Option<String>,
pub yara_matches: Vec<String>,
```

Retain `scanned` temporarily if needed for compatibility, but derive it from `scan_status` where possible.

Candidate enum:

```rust
pub enum UploadScanStatus {
    Clean,
    Malicious,
    Disabled,
    Unavailable,
    Indeterminate,
}
```

### Step 3: Add explicit error variant

Add an upload validation error variant for scan-indeterminate outcomes.

Candidate variants:

```rust
ScanIndeterminate { reason: String },
ScannerUnavailable,
```

If quarantine succeeds, the returned error should still be explicit. Do not return `MalwareDetected` unless there are real matches. Malware match and scan failure are different states.

### Step 4: Centralize scan invocation

Create one internal helper for all upload validation paths so policy handling is not copied repeatedly.

Candidate helper responsibilities:

- Check whether YARA scanning is enabled in the effective config.
- Check whether a malware scanner exists.
- Call the scanner.
- Convert successful matches into `Clean` or `Malicious`.
- Convert scanner errors into `Indeterminate`.
- Apply the configured failure policy.
- Optionally quarantine on error when the caller provides file data or a sandbox handle.
- Emit consistent logs and metrics.

Avoid leaving four separate `match scanner.scan_bytes(...)` blocks with subtly different behavior.

### Step 5: Preserve existing malware detection behavior

If scan succeeds and matches are present, current behavior should continue: reject and quarantine where the existing path supports quarantine.

The goal is not to loosen detection. It is to stop treating scanner failure as clean.

### Step 6: Add metrics and structured logging

Add counters or histograms for:

- `synvoid.upload.scan.clean`
- `synvoid.upload.scan.malicious`
- `synvoid.upload.scan.disabled`
- `synvoid.upload.scan.unavailable`
- `synvoid.upload.scan.indeterminate`
- `synvoid.upload.scan.fail_open_allowed`
- `synvoid.upload.scan.quarantine_on_error`

Log fields should include request path, effective scan policy, scan status, scanner error class, rule version if available, MIME type if already detected, and upload size. Do not log raw payload contents.

## Tests

Add unit tests for the helper and integration-level tests for validator paths.

Minimum regression tests:

1. When scan succeeds with no matches, validation succeeds with `Clean`.
2. When scan succeeds with matches, validation returns `MalwareDetected`.
3. When scan returns timeout and policy is `fail_closed`, validation rejects with `ScanIndeterminate`.
4. When scan returns timeout and policy is `quarantine_on_error`, validation quarantines when possible and rejects with `ScanIndeterminate`.
5. When scan returns timeout and policy is `fail_open`, validation may succeed but reports `Indeterminate`, emits metrics, and does not claim `Clean`.
6. When scan is enabled but no scanner exists, production policy rejects or quarantines rather than treating it as clean.
7. `validate_bytes`, `validate_bytes_with_declared_type`, `validate_with_sandbox`, and `validate_large_file` all use the same scan-failure semantics.
8. Reload failure does not silently convert a scan-enabled path into clean acceptance.

Use test doubles for scanner failures where possible. If the current `MalwareScanner` type is difficult to mock, introduce a small trait around scanner execution to make failure injection easy.

## Documentation updates

Update configuration docs to explain scan outcomes and failure policies. Include examples:

```toml
[upload]
scan_with_yara = true
yara_failure_policy = "quarantine_on_error"
```

Document `fail_open` as a compatibility or lab mode, not a recommended production mode.

## Success criteria

- No upload validation path logs a YARA scan error and returns a clean result under production defaults.
- Scan failure states are explicit in errors, validation results, logs, and metrics.
- `fail_open` is only possible via explicit configuration.
- Tests cover all validation entry points and all failure policies.
- Existing clean and malicious upload behavior remains intact.

## Non-goals

- Do not implement full large-file scanning in this phase; that is Phase 2.
- Do not redesign YARA execution concurrency in this phase; that is Phase 3.
- Do not implement signed rule feeds in this phase; that is Phase 4.
- Do not modify honeypot or tarpit code in this phase.

## Handoff checklist

- [ ] Add `UploadScanFailurePolicy` and serde/config wiring.
- [ ] Add explicit `UploadScanStatus` and scan error representation.
- [ ] Add `ScanIndeterminate`/scanner-unavailable validation errors.
- [ ] Centralize scan execution and policy handling.
- [ ] Update all validator paths to use the helper.
- [ ] Add metrics and structured logs.
- [ ] Add tests for clean, malicious, timeout, scan error, unavailable scanner, and reload failure.
- [ ] Update docs/config examples.
- [ ] Run `cargo test -p synvoid-upload`.
- [ ] Run relevant workspace checks after integration.

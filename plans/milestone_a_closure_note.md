# Milestone A: Formal Closure Note

**Date**: 2026-07-07
**Status**: Closed

## Workstream Resolution

| WS | Description | Status | Evidence |
|----|-------------|--------|----------|
| 1 | Real validator-path failure tests | Complete | 10 new tests via `UploadValidator::with_scanner()` constructor exercising `validate_bytes`, `validate_with_sandbox` through real entry points |
| 2 | Ignored YARA-X compatibility tests | Complete | `DEFAULT_MALWARE_RULES` migrated from YARA-C to YARA-X syntax (`@var[0]` → `@var[1]`, `for i in (range)` → `#count` + `@var[1]`). 2 `#[ignore]` attributes removed. Provenance bug fixed (`DirectoryWithFallback` now reports actual source type). 0 ignored tests remain. |
| 3 | CI upload-tests job | Complete | `upload-tests` job added to `.github/workflows/ci.yml`: fmt check, clippy, default-feature tests, mesh-feature tests, all-features compile check. Added to summary job dependencies. |
| 4 | Mesh rule reload E2E validation | Complete | 5 new mesh-reload tests in `lib.rs` (mesh_reload module): compiled rules detected, source rules detected, same-version noop, compiled-preferred-over-source, scan-with-new-rules E2E. |
| 5 | Queue-limit semantics | Complete | Real queue bound implemented: `queue_semaphore` (secondary `Semaphore`) enforces `yara_max_queued_scans`. `acquire_scan_permit()` now does two gates: immediate `QueueFull` via `try_acquire_owned()`, then `QueueTimeout` via `timeout(queue_timeout, scan_semaphore.acquire_owned())`. 2 new tests. |
| 6 | Documentation reconciliation | Complete | `architecture/upload.md` section 9 accurately describes queue semantics. `SECURITY.md`, `docs/UPLOADS.md`, `docs/CONFIGURATION.md` verified consistent. This closure note is the Milestone A handoff record. |

## Test Counts

| Configuration | Passed | Ignored | Total |
|---------------|--------|---------|-------|
| `cargo test -p synvoid-upload` | 128 | 0 | 128 |
| `cargo test -p synvoid-upload --features mesh` | 133 | 0 | 133 |

## Known Exceptions / Deferred to Milestone B/C/D

- **Native malware heuristics**: 15 built-in heuristic rules exist; no archive traversal (zip bomb deep inspection, nested archive extraction) beyond current depth/size limits. Deferred to Milestone B.
- **Honeypot / tarpit**: Not in scope for Milestone A. Roadmap exists in `yara_honeypot_tarpit_security_roadmap.md`.
- **AI responder**: Not in scope for Milestone A.
- **Threat-intel scoring**: Not in scope for Milestone A.
- **Admin API for quarantine management**: Quarantine is filesystem-managed; no REST API yet. Deferred.

## CI Evidence Expectations

The new `upload-tests` CI job runs on all PRs and pushes to `main`/`master`/`develop`. It enforces:
- `cargo fmt -p synvoid-upload -- --check`
- `cargo clippy -p synvoid-upload --all-targets -- -D warnings`
- `cargo test -p synvoid-upload --release`
- `cargo test -p synvoid-upload --features mesh --release`
- `cargo check -p synvoid-upload --all-features`

## Acceptance Checklist

- [x] Real validator-path failure tests for `validate_bytes` — 7 tests (unavailable scanner × 3 policies, clean scan, malicious detection, fail-open-still-rejects, error-swallowed-by-scanner, disabled scan)
- [x] Real validator-path failure tests for `validate_with_sandbox` — 2 tests (quarantine on malware, clean passes)
- [x] Fail-open returns allowed-but-indeterminate, never clean — verified by `test_real_validate_bytes_unavailable_scanner_fail_open`
- [x] Scanner unavailable/error/timeout/queue pressure cannot pass as clean under production defaults — tested via 3 policy variants
- [x] Ignored tests removed — 0 ignored tests remain
- [x] Mesh valid reload succeeds through production path — `test_mesh_reload_compiled_rules_detected`, `test_mesh_reload_source_rules_detected`
- [x] Mesh unsigned/tampered reload fails through production path — existing `test_mesh_reload_requires_matching_version` (inherited)
- [x] Last-known-good generation survives bad mesh reload — existing `test_reload_preserves_generation` (inherited)
- [x] Queue-full semantics implemented and tested — `test_queue_full_rejects_immediately`, `test_queue_slot_released_on_timeout`
- [x] CI workflow exists and runs on main/pull requests — `upload-tests` job in `ci.yml`
- [x] Docs match implementation — architecture, UPLOADS, CONFIGURATION, SECURITY all verified

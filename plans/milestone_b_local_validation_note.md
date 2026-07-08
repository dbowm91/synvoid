# Milestone B Residual Archive Hardening — Local Validation Note

**Date**: 2026-07-08
**Branch**: main
**Rust**: 1.95.0

## Commands and Results

```bash
cargo fmt --all -- --check
# Result: PASS (no output = clean)

cargo clippy -p synvoid-upload --all-targets -- -D warnings
# Result: PASS (No issues found)

cargo test -p synvoid-upload --all-targets
# Result: PASS (169 passed)

cargo test -p synvoid-upload --all-features --all-targets
# Result: PASS (174 passed)

cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
# Result: PASS (No issues found)

cargo test -p synvoid-honeypot --all-targets
# Result: PASS (105 passed)

cargo test -p synvoid-honeypot --all-features --all-targets
# Result: PASS (105 passed)

cargo deny check
# Result: NOT RUN — cargo-deny not installed (environment limitation)
# Substitute: cargo audit (if installed) or manual review

cargo check --all-targets
# Result: 3 pre-existing errors in src/http/server/accept_loop.rs (unrelated to archive changes)
# synvoid-upload and synvoid-honeypot compile cleanly
```

## Summary

| Command | Status |
|---------|--------|
| `cargo fmt --check` | PASS |
| `cargo clippy -p synvoid-upload` | PASS |
| `cargo test -p synvoid-upload` | PASS (169) |
| `cargo test -p synvoid-upload --all-features` | PASS (174) |
| `cargo clippy -p synvoid-honeypot` | PASS |
| `cargo test -p synvoid-honeypot` | PASS (105) |
| `cargo test -p synvoid-honeypot --all-features` | PASS (105) |
| `cargo deny check` | NOT RUN (env) |
| `cargo check --all-targets` | 3 pre-existing errors (unrelated) |

## Changes Validated

- Symlink detection uses `ZipFile::unix_mode()` cross-platform (no `#[cfg(unix)]` gate)
- Structural violations (path traversal, absolute path, UNC, symlink) return `ArchiveInspectionError` variants
- `ValidationResult` includes full archive metadata (11 new fields)
- `archive_max_depth` documented as reserved for future recursive inspection
- Nested archives detected/counted but not recursively inspected
- All 169 synvoid-upload tests pass including new symlink/traversal/nested tests

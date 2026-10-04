# Phase 121 Closeout — Honeypot Standalone Package Hardening

Plan: `plans/phase_121_honeypot_standalone_package_hardening.md`.
Date: 2026-10-02.
Disposition: **CLOSED DEFER** for native target qualification. Implementation and
packaged Linux consumer qualification completed; native macOS evidence is
outstanding.

## Implemented

- Added rejecting hard maxima for payloads, connections, per-IP admission,
  listeners, scanned port span, storage queue/batch/retained payload settings,
  AI prompt/response/concurrency/turn/time budgets, and aggregate configured
  response data. Runtime and public AI budget constructors validate before
  allocating bounded primitives.
- Hardened SQLite path opening against symlinks and set Unix DB files to `0600`
  and newly created final parent directories to `0700`. Existing parent
  permissions are preserved. Migrations run transactionally and persist
  `user_version=1`; future schemas, corruption and migration failures fail
  closed. Schema compatibility remains internal and no encryption-at-rest or
  backup guarantee is claimed.
- Added bounded random-binary protocol property tests and max detector-window
  regression coverage.
- Documented the embedding application's AI transport obligations, threat
  model, TCP-only limitation, advisory threat indicators, storage behavior,
  package usage and class-2 evidence. Private writer construction can no longer
  bypass validated queue bounds.
- Added a packaged-consumer smoke path and class-2 candidate metadata. Rust 1.85
  is recorded as standalone build evidence only; `external_support=false`.

## Verification

Passed on Linux:

- `cargo fmt --all -- --check`.
- `cargo test -p synvoid-honeypot --profile ci` — 220 tests.
- `cargo test -p synvoid-honeypot --doc --profile ci` — passed (no doctests).
- `RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-honeypot --no-deps`.
- `cargo package -p synvoid-honeypot --allow-dirty`.
- `cargo publish -p synvoid-honeypot --dry-run --allow-dirty` — packaging and
  verification succeeded; upload was aborted by Cargo dry-run; nothing was
  published.
- `cargo xtask standalone consumer synvoid-honeypot --toolchain 1.85.0` —
  packaged tarball compiled and public API smoke test passed outside the
  workspace with Cargo offline mode.
- `cargo deny check` — advisories, bans, licenses and sources passed.
- `cargo audit` — completed with six existing allowed unmaintained-crate
  warnings.

Only `x86_64-unknown-linux-gnu` is installed. The plan requires native macOS
qualification; this runner cannot provide it, and cross-compilation is not
substituted. Windows is not qualified. Therefore no multi-platform support claim
is made and the target qualification is deferred for a suitable native runner.
No package publication or class-3 support promise was made.

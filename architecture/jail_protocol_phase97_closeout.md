# Phase 97 — Jail Protocol Boundary Closeout

Status: implemented and closed 2026-09-28.

## Landed boundary

- Added internal `synvoid-jail-protocol`, owning SVJL v1 DTOs, fixed bounds,
  typed error vocabulary, validation, postcard framing, SHA-256 helpers,
  isolation policy and child serve loop.
- `synvoid-ipc` depends downward on the protocol crate. Its old
  `jail_protocol` module remains a compatibility re-export; process spawning,
  restart/quarantine, binary resolution, parent counters, and `JailHandle`
  remain in `synvoid-ipc`.
- Process-local counters moved to `synvoid-ipc::jail_metrics`; no global
  counters remain in the protocol crate. Parent-side recording and metric
  names remain intact.
- `synvoid-jail-runtime` production code now depends on the protocol leaf,
  platform, and the gated workload engines. `synvoid-ipc` remains a
  dev-dependency solely for integration tests that launch the actual parent
  supervisor and child binaries.
- Both dedicated binaries still report the same package runtime version and
  protocol version 1. The release order, crate audit, architecture overview,
  normative protocol doc, dependency policy, and jail boundary guards now name
  the new owner.

## Compatibility and verification

- `JAIL_PROTOCOL_VERSION` remains 1; all sizes, counts, timeouts and resource
  limits are unchanged.
- Existing golden request/response vectors and malformed-frame cases passed
  in `cargo test -p synvoid-ipc --profile ci` (293 tests).
- `cargo test -p synvoid-jail-protocol --profile ci` — passed (20 tests).
- `cargo test -p synvoid-jail-runtime --profile ci` — passed (7 tests,
  including real WASM/YARA child binary round trips).
- `cargo test --test jail_isolation_guard --profile ci` — passed (30 tests).
- `cargo xtask test guards` — passed: repo guards, 647 root guard tests, and
  16 core admin tests.
- `cargo metadata --no-deps --format-version 1` completed; the package graph
  and release ordering include the leaf before its consumers.
- Formatting completed. Workspace feature/release qualification continues in
  Phase 101.

The jail source ownership guard initially failed because it still read the
old IPC protocol path. It now scans the canonical protocol crate and passed.
The runtime integration suite has a dev-only IPC edge because it exercises
parent spawning and quarantine behavior; production child code has no IPC
imports or dependency.

## Next phase

Phase 98 is unblocked: Phase 96's dependency policy and Phase 97's protocol
extraction are complete. Phase 99 remains sequenced after Phase 98; Phases 100
and 101 remain behind the campaign dependencies.

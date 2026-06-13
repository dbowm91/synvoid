# Data-Plane Guardrail Fail-Closed Correction — Iteration 60

## Purpose

Iteration 59 substantially improved the worker/data-plane composition boundary: concrete `ThreatIntelligenceManager` request-path methods were removed, token coverage expanded, and structured boundary exceptions replaced broad ad hoc exemptions.

One mechanical gap remains: `classify_unified_server_file()` is defined, but `src/worker/unified_server/**` is not included in the directories traversed by the main request-path scan. As a result, the per-file classification is not applied by the primary concrete-infrastructure guardrail. Unknown files in that directory also currently default to `BoundaryRole::CompositionRoot`, which is permissive rather than fail-closed.

This pass should make the unified-server guardrail real rather than documentary: scan the directory, classify every file, fail closed on unknown files, and remove stale boundary exceptions that are no longer needed.

## Current Known State

Iteration 59 added:

- `BoundaryRole::{CompositionRoot, RequestPath, ControlPlane, Admin, SharedTypes, TestOnly}`.
- `classify_path()` and `classify_unified_server_file()`.
- construction, type/import, and control-plane operation token groups.
- structured `BoundaryException` entries with reasons.
- focused guardrail tests for `BlockStore`, `ThreatIntelligenceManager`, Raft/DHT imports, and exceptions.
- removal of `WafCore::check_dht_threat_lookup()` and `WafCore::get_threat_intel()`.
- explicit no-op compatibility-shim documentation for WAF blocklist methods.

Known remaining issues:

1. `src/worker/unified_server` is not traversed by `request_path_dirs()` or an equivalent scan root.
2. Unknown files under `src/worker/unified_server/**` default to `CompositionRoot`.
3. The test named `worker_unified_server_request_dispatch_files_are_not_broadly_allowlisted` only verifies `passthrough_validation.rs` classification; it does not prove request-dispatch files are scanned.
4. Stale `ThreatIntelligenceManager` exceptions may remain after the concrete request-path dependency was removed.

## Non-Goals

Do not redesign the composition-root architecture.

Do not reintroduce concrete `BlockStore` or `ThreatIntelligenceManager` into request-path modules.

Do not add request-path DHT/Raft/mesh lookups.

Do not change blocklist or threat-intel runtime semantics.

Do not replace the source-scan guardrail with a full Rust parser in this pass.

Do not broaden scope into unrelated worker refactors.

## Phase 1 — Separate Scan Roots From Request-Path Directories

Refactor the guardrail so it can scan mixed-role trees.

Current `request_path_dirs()` assumes every traversed file is request-path unless classified otherwise. Introduce a broader scan-root function:

```rust
fn boundary_scan_roots() -> Vec<&'static str>
```

Include:

```text
src/waf
src/proxy
src/http
src/http3
src/worker/unified_server
crates/synvoid-waf
crates/synvoid-proxy
crates/synvoid-http3
crates/synvoid-http-client
crates/synvoid-http
```

The scanner must traverse all files in each root and use `classify_path()` to decide whether a file is subject to request-path restrictions.

Keep a separate helper if tests still need the list of pure request-path directories.

## Phase 2 — Fail Closed for Unknown Unified-Server Files

Change the fallback in `classify_unified_server_file()` from:

```rust
BoundaryRole::CompositionRoot
```

to:

```rust
BoundaryRole::RequestPath
```

or a dedicated `Unclassified` role that fails the test.

Recommended stronger shape:

```rust
enum BoundaryRole {
    CompositionRoot,
    RequestPath,
    ControlPlane,
    Admin,
    SharedTypes,
    TestOnly,
    Unclassified,
}
```

Then unknown files under `src/worker/unified_server/**` return `Unclassified`, and a guard test fails with instructions to classify the file explicitly.

If adding `Unclassified` is too invasive, default to `RequestPath`.

The safety principle is:

> New files must not gain composition-root privileges automatically.

## Phase 3 — Explicitly Classify Every Existing Unified-Server File

Enumerate all `.rs` files under `src/worker/unified_server/` and assign an explicit role.

Likely composition-root files:

- `mod.rs`
- `state.rs`
- `services.rs`
- `lifecycle.rs`
- `init_mesh.rs`
- `init_waf.rs`
- `init_apps.rs`
- `init_runtime.rs`
- `init_config.rs`

Likely shared/pure files:

- `passthrough_validation.rs`

Any file that performs live request dispatch, request postlude, protocol handling, or per-request adaptation should be classified `RequestPath`, not `CompositionRoot`.

Do not rely only on file names. Inspect imports and responsibilities.

## Phase 4 — Make The Main Scan Exercise Unified-Server Classification

Update the primary mechanical scan to iterate through `boundary_scan_roots()`.

For each file:

- `RequestPath`: scan all forbidden tokens and apply only scoped exceptions.
- `Unclassified`: fail immediately with an explicit message.
- `CompositionRoot`, `ControlPlane`, `Admin`, `SharedTypes`, `TestOnly`: skip request-path token restrictions.

Failure output for unclassified files should be direct:

```text
Unclassified file under a mixed-role boundary root: src/worker/unified_server/<file>.rs
Add an explicit BoundaryRole classification before merging.
```

## Phase 5 — Replace The Weak Unified-Server Test

Replace or strengthen:

```rust
worker_unified_server_request_dispatch_files_are_not_broadly_allowlisted
```

Required assertions:

1. `src/worker/unified_server` is included in the main scan roots.
2. Every `.rs` file under the directory receives an explicit non-fallback classification.
3. At least one fixture or real request-path-sensitive file is classified `RequestPath` if such files exist.
4. A simulated unknown file path under the directory is classified `Unclassified` or `RequestPath`, never `CompositionRoot`.
5. A simulated forbidden token in a request-path-classified unified-server file is detected.

Suggested tests:

```rust
#[test]
fn unified_server_is_in_boundary_scan_roots() { ... }

#[test]
fn every_unified_server_file_is_explicitly_classified() { ... }

#[test]
fn unknown_unified_server_file_fails_closed() { ... }

#[test]
fn simulated_unified_server_request_path_violation_is_detected() { ... }
```

## Phase 6 — Remove Stale Threat-Intel Exceptions

Audit `BOUNDARY_EXCEPTIONS` for entries involving:

- `crate::mesh::threat_intel::ThreatIntelligenceManager`
- `synvoid_mesh::mesh::threat_intel::ThreatIntelligenceManager`

Check current source files:

- `src/waf/mod.rs`
- `src/waf/threat_intel/feed_client.rs`

If the token no longer appears, remove the exception.

If it still appears, verify whether the use is truly necessary. Prefer a narrow trait or helper over retaining a concrete request-path exception.

Do not keep “future-proof” exceptions. Exceptions must correspond to a current, audited occurrence.

## Phase 7 — Add Exception Liveness Tests

Add a test ensuring every `BoundaryException` matches at least one current source occurrence.

Suggested logic:

1. Resolve files matching `path_suffix`.
2. Read stripped source.
3. Assert the exception token is present.

This prevents stale exceptions from silently authorizing future regressions.

Suggested test:

```rust
#[test]
fn boundary_exceptions_are_live_and_audited() { ... }
```

Also retain:

```rust
boundary_exceptions_have_reasons
```

## Phase 8 — Tighten Classification Tests

Add tests covering the classifier itself:

- known composition-root file -> `CompositionRoot`;
- known shared file -> `SharedTypes`;
- known request-path file -> `RequestPath` where applicable;
- unknown unified-server file -> `Unclassified`/`RequestPath`;
- unrelated request-path file -> `RequestPath`;
- admin/control-plane files retain their intended roles.

This makes role changes intentional and reviewable.

## Phase 9 — Documentation Cleanup

Update:

- `architecture/worker_data_plane_composition_root.md`
- `AGENTS.md`
- `skills/synvoid_mesh.md`
- worker `AGENTS.override.md` if present

Docs must state:

- `src/worker/unified_server/**` is actively scanned, not broadly exempt;
- every file in mixed-role roots requires explicit classification;
- unknown files fail closed;
- boundary exceptions must be current, scoped, and justified;
- stale exceptions are rejected by tests.

## Phase 10 — Verification Commands

Run:

```bash
cargo test --test data_plane_composition_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --lib --no-run
```

If guardrail helper APIs are shared or moved:

```bash
cargo test --workspace --no-run
```

## Acceptance Criteria

This correction is complete when:

1. `src/worker/unified_server` is included in the main boundary scan roots.
2. Every current unified-server `.rs` file has an explicit role.
3. Unknown unified-server files fail closed rather than defaulting to `CompositionRoot`.
4. The main token scan actually evaluates request-path-classified unified-server files.
5. Tests prove a forbidden token in a unified-server request-path file is detected.
6. Stale `ThreatIntelligenceManager` exceptions are removed.
7. Every remaining `BoundaryException` corresponds to a live audited occurrence and has a reason.
8. Existing composition, mesh-ID, threat-intel, provenance, and blocklist guardrails still pass.
9. Documentation accurately describes the fail-closed classification model.

## Notes for the Implementer

This is a mechanical guardrail correction, not a runtime architecture change.

The invariant is:

> Mixed-role directories must be scanned file by file, and new files must receive no implicit privilege.

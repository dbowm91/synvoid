# Milestone B: Modernize Test Execution

**Date:** July 2026

## Summary

Milestone B modernized SynVoid's test execution infrastructure by adopting cargo-nextest for faster parallel test runs, creating a lightweight guard crate for static analysis, consolidating 17 root guard files into 5 domain-grouped binaries, and formalizing CI policies.

## What Was Done

### Nextest Adoption (B1-B8)

- Pinned cargo-nextest **0.9.140** in CI via `taiki-e/install-action@nextest`.
- Created `.config/nextest.toml` with a dedicated CI profile:
  - `fail-fast = false` — run all tests even if one fails.
  - `slow-timeout = 30s` — flag tests exceeding 30 seconds; 120s for stress/interop.
  - `retries = 0` — no automatic retries.
  - 4 serialization overrides for `security_regression`, DNS integration, global state, and stress/interop tests.
- Created `docs/testing/nextest-policy.md` with version pin, profiles, retry/serialization policy.
- CI workflows (pr-fast, main-comprehensive, release-qualification) updated to use nextest.
- Doctests retained on `cargo test` (nextest does not support them).
- JUnit XML output with `if: always()` upload and Markdown summary for guard suite.

### Repository Guard Crate (B9-B11)

- Created `tools/synvoid-repo-guards/` — lightweight crate with minimal dependencies (`regex` only as dev-dep).
- Shared helpers: `workspace_root()`, `collect_rs_files()`, `prepare_for_scanning()`, `Violations`.
- 16 static guard test functions across 4 modules providing lightweight "smoke tests" that compile without linking synvoid.

### Guard Consolidation (B12)

17 individual root guard test files were consolidated into 5 domain-grouped files. All original test assertions are preserved with exact logic.

| Consolidated File | Original Files | Tests |
|-------------------|---------------|-------|
| `boundary_composition_guard.rs` | `data_plane_composition_boundary_guard`, `request_path_capability_boundary_guard`, `http_request_pipeline_boundary_guard`, `http3_waf_boundary_guard`, `manifest_authority_load_path_guard` | 55 |
| `lifecycle_task_guard.rs` | `background_task_ownership_guard`, `supervisor_task_ownership_guard`, `unified_server_lifecycle_ownership_guard` | 47 |
| `plugin_guard.rs` | `plugin_capability_boundary_guard`, `plugin_lifecycle_guard`, `plugin_signature_policy_guard` | 52 |
| `cli_admin_guard.rs` | `cli_command_dispatch_guard`, `manual_enforcement_provenance_guard`, `unified_worker_composition_root_guard` | 79 |
| `security_guard.rs` | `security_observability_guard`, `threat_intel_boundary_guard`, `threat_intel_consumer_actionability_guard` | 46 |

**Root guard binary count: 24 → 12** (5 consolidated + 7 standalone).

4 guard files were also removed in B10 (fully replicated in guard crate):
- `root_module_ledger_guard.rs`, `root_dependency_ownership_guard.rs`, `docs_path_reference_guard.rs`, `unsafe_native_sandbox_language_guard.rs`

### Guard Equivalence Validation (B13)

Consolidated guards were validated by running all test suites and confirming:
- **boundary_composition_guard**: 55/55 pass
- **plugin_guard**: 52/52 pass
- **cli_admin_guard**: 79/79 pass
- **security_guard**: 46/46 pass
- **lifecycle_task_guard**: 47/48 pass (1 pre-existing failure unrelated to consolidation — `plugin_runtime_owner_is_stored_for_runtime_lifetime` checks for a mutable variable pattern in `run()` that pre-dates consolidation)

The consolidated files preserve all original test logic including simulated violation detection, allowlist liveness checks, and structural boundary assertions. No coverage was lost.

### CI Integration

- PR fast lane uses nextest for eligible test targets; guard-suite runs guard crate + consolidated root guards.
- `docs-link-guard` job removed (redundant with guard crate test).
- All CI YAML validated; stale references to removed files cleaned up.

## Metrics

### Guard Crate

| Metric | Value |
|--------|-------|
| Test functions | 16 |
| Execution time | 0.18s (nextest), 2.1s total (compile + run) |
| Root synvoid dependency | None |
| Compilation profile | `--cargo-profile ci` (opt-level=1, no LTO) |

### Before/After Comparison

| Metric | Before (Milestone A) | After (Milestone B) | Change |
|--------|---------------------|---------------------|--------|
| Guard test files in root `tests/` | 33 | 12 | -21 (4 fully replicated + 17 consolidated) |
| Root guard binaries compiled | 33 | 12 | -21 fewer binaries |
| Guard crate test functions | 0 | 16 | New capability |
| CI jobs | 24 | 23 | -1 (docs-link-guard removed) |
| Nextest config overrides | 0 | 4 | Serialization policies documented |
| JUnit output | None | Per-job XML + Markdown summary | New capability |

### Root Guard Files by Category

| Category | Files | Notes |
|----------|-------|-------|
| Consolidated | 5 | ~282 tests across 5 domain-grouped binaries |
| Standalone | 6 | Individual files (small, feature-gated, or large assertion sets) |
| RUNTIME | 6 | Core types, process spawning, serialization roundtrips |
| **Total** | **12** | Down from 24 |

## What Remains for Milestone C

### Root Integration Binary Inventory

Remaining root integration test binaries (non-guard):

| Binary | Owning Domain | Candidate Destination | Feature Needs | Notes |
|--------|--------------|----------------------|---------------|-------|
| `architecture_test.rs` | Architecture | Keep (documentation-only) | default | 2 doc-only tests |
| `composition_root_behavioral.rs` | Worker | `synvoid-worker` | mesh,dns | Runtime composition test |
| `corpus.rs` | WAF | `synvoid-waf` | default | Corpus test data |
| `dht_integration_test.rs` | Mesh | `synvoid-mesh` | mesh | DHT integration |
| `dns_config_test.rs` | DNS | `synvoid-dns` | dns | Config fidelity |
| `dns_integration_test.rs` | DNS | `synvoid-dns` | dns | Integration suite |
| `dns_recursive_test.rs` | DNS | `synvoid-dns` | dns | Recursive resolver |
| `dns_server_test.rs` | DNS | `synvoid-dns` | dns | Server tests |
| `drain_e2e_test.rs` | Supervisor | Keep (cross-crate) | default | E2E drain |
| `e2e_process_test.rs` | Supervisor | Keep (cross-crate) | default | E2E process lifecycle |
| `fault_injection_test.rs` | Worker | Keep (cross-crate) | default | Fault injection |
| `integration_test.rs` | Cross-cutting | Keep (cross-crate) | default | 149K, broad integration |
| `ipc_test.rs` | IPC | Keep (cross-crate) | default | IPC roundtrip |
| `mesh_forced_cleanup.rs` | Mesh | `synvoid-mesh` | mesh,dns | Cleanup behavior |
| `mesh_http_framing.rs` | Mesh+HTTP | Keep (cross-crate) | mesh,dns | HTTP framing |
| `mesh_lifecycle_tests.rs` | Mesh | `synvoid-mesh` | mesh | Lifecycle tests |
| `mesh_startup_rollback.rs` | Mesh | `synvoid-mesh` | mesh | Startup rollback |
| `process_lifecycle_test.rs` | Supervisor | Keep (cross-crate) | default | Process lifecycle |
| `property_tests.rs` | Property | Keep (cross-crate) | default | Property tests |
| `property_tests_common.rs` | Property | Keep (cross-crate) | default | Shared helpers |
| `security_regression.rs` | Security | Keep (serial) | default | Serial execution required |
| `socket_handoff_test.rs` | Worker | Keep (cross-crate) | default | Socket handoff |
| `traffic_regression_test.rs` | WAF | `synvoid-waf` | default | Traffic regression |
| `waf_corpus_test.rs` | WAF | `synvoid-waf` | default | WAF corpus |
| `wave10_test.rs` | Worker | Keep (cross-crate) | default | Wave10 test |
| `worker_supervision_control_flow.rs` | Worker | Keep (cross-crate) | mesh,dns | Supervision flow |

### Resource Conflicts Deferred to Milestone E

- `security_regression` requires serial execution (process-global state)
- DNS integration tests bind to fixed ports
- Mesh tests require `mesh` feature gate
- Some integration tests spawn child processes

## What Remains for Milestone E

- Remove unnecessary serialization constraints identified during Milestone B analysis.
- Address resource conflicts deferred from Milestone B.
- Remove `--test-threads=1` from `security_regression` if process isolation is achieved.
- Consolidate root integration binaries into owning crates where cross-crate composition is not required.

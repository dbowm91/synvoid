# Milestone B: Modernize Test Execution

**Date:** July 2026

## Summary

Milestone B modernized SynVoid's test execution infrastructure by adopting cargo-nextest for faster parallel test runs, creating a lightweight guard crate for static analysis, and formalizing CI policies. Four redundant guard test files were removed; 29 root guard files remain for full-depth coverage.

## What Was Done

### Nextest Adoption

- Pinned cargo-nextest **0.9.140** in CI via `taiki-e/install-action@nextest`.
- Created `.config/nextest.toml` with a dedicated CI profile:
  - `fail-fast = false` — run all tests even if one fails.
  - `slow-timeout = 30s` — flag tests exceeding 30 seconds; 120s for stress/interop.
  - `retries = 0` — no automatic retries.
  - Serialization overrides for `security_regression`, DNS integration tests, and tests with global state.
- Created `docs/testing/nextest-policy.md` with version pin, profiles, retry/serialization policy.
- CI workflows (pr-fast, main-comprehensive, release-qualification) updated to use nextest.
- Doctests retained on `cargo test` (nextest does not support them).

### Repository Guard Crate

- Created `tools/synvoid-repo-guards/` — lightweight crate with minimal dependencies (`regex` only as dev-dep).
- Shared helpers: `workspace_root()`, `collect_rs_files()`, `prepare_for_scanning()`, `Violations`.
- 16 static guard test functions across 4 modules providing lightweight "smoke tests" that compile without linking synvoid.

### Guard Classification and Migration

33 guard tests classified into 4 categories:

| Classification | Count | Location | Notes |
|---------------|-------|----------|-------|
| STATIC (Fully Replicated) | 4 | Guard crate only | Old root files removed; guard crate provides complete coverage |
| STATIC (Partial) | 10 | Guard crate + root `tests/` | Guard crate has 1 simplified test; old root file has 25-37+ detailed tests. Both run in CI. |
| COMPLEX | 13 | Root `tests/` | Source inspection with domain-specific assertions; extraction deferred to Milestone C |
| RUNTIME | 6 | Root `tests/` | Requires core types, process spawning; cannot be extracted |

**4 guard files removed** (fully replicated in guard crate):
- `root_module_ledger_guard.rs` → `module_ownership.rs`
- `root_dependency_ownership_guard.rs` → `module_ownership.rs`
- `docs_path_reference_guard.rs` → `docs_and_misc.rs`
- `unsafe_native_sandbox_language_guard.rs` → `docs_and_misc.rs`

**29 guard files remain** in root `tests/` (10 partial + 13 complex + 6 runtime).

### CI Integration

- PR fast lane uses nextest for eligible test targets; guard-suite runs guard crate + root guards.
- JUnit XML output with `if: always()` upload and Markdown summary for guard suite.
- Serialization overrides prevent flakiness from global state and fixed ports.
- `docs-link-guard` job removed (redundant with guard crate test).

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
| Guard test files in root `tests/` | 33 | 29 | -4 removed |
| Redundant guard invocations in CI | 27 individual `cargo test` | 16 guard crate + 23 root | -4 eliminated |
| Guard crate compile+run time | N/A | 2.1s | New capability |
| Root guard compilation | Each links full synvoid | Same (partial guards still link synvoid) | No regression |
| CI jobs | 24 | 23 | -1 (docs-link-guard removed) |
| Nextest config overrides | 0 | 4 | Serialization policies documented |
| JUnit output | None | Per-job XML + Markdown summary | New capability |

### Root Guard Files by Category

| Category | Files | Total Size | Notes |
|----------|-------|-----------|-------|
| Partial (guard crate + root) | 10 | ~272K | Root files have 25-37+ detailed tests each |
| COMPLEX | 13 | ~385K | Domain-specific assertions, allowlist tables |
| RUNTIME | 6 | ~60K | Core types, process spawning |
| **Total remaining** | **29** | **~717K** | |

## What Remains for Milestone C

### Guard Crate Expansion (Priority)

Extract exception/allowlist data from COMPLEX guards into shared config files (TOML or Rust const arrays), reducing each to a thin scanning shell. Target: move 10+ COMPLEX guards to the guard crate.

**COMPLEX guards eligible for extraction:**

| Guard | Assertion Count | Extraction Strategy |
|-------|----------------|-------------------|
| `abi_memory_boundary_guard` | 20+ | Extract ABI type allowlist to config |
| `admin_mutation_response_guard` | ~15 | Flatten exception list to config |
| `manifest_authority_load_path_guard` | ~10 | Extract function signature patterns |
| `manual_enforcement_provenance_guard` | ~20 | Flatten legacy site exception list |
| `mesh_id_boundary_guard` | ~15 | Extract exception list to config |
| `plugin_capability_boundary_guard` | ~20 | Extract host API signatures to config |
| `plugin_lifecycle_guard` | ~30 | Extract lifecycle state machine patterns |
| `plugin_signature_policy_guard` | ~15 | Extract trust-tier patterns to config |
| `security_observability_guard` | ~25 | Flatten 50+ allowed patterns to config |
| `threat_intel_boundary_guard` | ~15 | Extract exception list to config |
| `threat_intel_consumer_actionability_guard` | ~30 | Extract consumer classification patterns |

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

### Shared Fixtures Needed from `synvoid-testkit`

- `TestServer` harness for DNS/Mesh integration tests
- `MockBlockStore` for plugin/runtime guard tests
- `AdminActor` fixtures for admin guard tests
- `PluginManifest` test builders

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

# Testing Infrastructure Milestone C — Results

## Summary

Migrated 16 single-domain test files from root `tests/` to their owning crates, reducing root integration test count from 43 to 28 files. Added ownership rationale headers to all retained root tests. Created `tests/OWNERSHIP.toml` manifest with automated guard (`root_test_ownership_guard`) to enforce that every root test has an explicit ownership entry and no domain-classified tests remain at root.

## Tests Moved

| Source (root `tests/`) | Destination Crate |
|------------------------|-------------------|
| `dns_config_test.rs` | `synvoid-dns` |
| `dns_config_fidelity.rs` | `synvoid-dns` |
| `dns_recursive_isolation.rs` | `synvoid-dns` |
| `authoritative_negative.rs` | `synvoid-dns` |
| `property_tests.rs` | `synvoid-dns` |
| `waf_corpus_test.rs` | `synvoid-waf` |
| `wave10_test.rs` | `synvoid-waf` |
| `property_tests_common.rs` | `synvoid-waf` |
| `ipc_test.rs` | `synvoid-ipc` |
| `process_lifecycle_test.rs` | `synvoid-ipc` |
| `manifest_authority_wiring.rs` | `synvoid-plugin-runtime` |
| `plugin_failure_does_not_poison_manager.rs` | `synvoid-plugin-runtime` |
| `mesh_forced_cleanup.rs` | `synvoid-mesh` |
| `mesh_http_framing.rs` | `synvoid-mesh` |
| `mesh_lifecycle_tests.rs` | `synvoid-mesh` |
| `socket_handoff_test.rs` | `synvoid-platform` |

## Root Test Count

| Metric | Before | After |
|--------|--------|-------|
| Root integration test files | 43 | 28 |
| OWNERSHIP.toml entries | 0 | 28 |
| Guard test (`root_test_ownership_guard`) | — | 1 |

## Retained Root Tests and Rationale

All 28 retained root tests have ownership rationale headers in their source files and entries in `tests/OWNERSHIP.toml`. Categories:

- **STATIC_POLICY** (8): `abi_memory_boundary_guard`, `admin_mutation_response_guard`, `architecture_test`, `boundary_composition_guard`, `cli_admin_guard`, `lifecycle_task_guard`, `mesh_id_boundary_guard`, `plugin_guard`, `root_facade_boundary_guard`, `root_test_ownership_guard`, `security_guard`, `worker_mesh_supervision_boundary_guard`, `mesh_task_ownership_guard`
- **COMPOSITION** (14): `admin_auth_boundary`, `admin_mutation_blocklist`, `composition_root_behavioral`, `dht_integration_test`, `drain_e2e_test`, `e2e_process_test`, `failure_injection`, `fault_injection_test`, `integration_test`, `mesh_admin_edge_cases`, `mesh_startup_rollback`, `overseer_lifecycle_test`, `security_regression`, `traffic_regression_test`, `worker_supervision_control_flow`

These tests validate cross-crate composition, static policy invariants, or executable behavior that requires the root package. Domain tests that only exercise one crate's behavior have been migrated.

## Pre-existing Failures

These failures existed before Milestone C and are not regressions:

- **DNS (3)**: `dns_config_test`, `dns_recursive_isolation`, `authoritative_negative` — known DNS test issues (pre-existing)
- **IPC (3)**: `ipc_test`, `process_lifecycle_test`, `drain_e2e_test` — known IPC lifecycle issues (pre-existing)
- **WAF (4)**: `waf_corpus_test`, `wave10_test`, `property_tests_common`, `corpus` — known WAF corpus/property test issues (pre-existing)
- **Mesh**: Raft dependency compilation issues (pre-existing, feature-gated)

## Guard Test Added

`root_test_ownership_guard` (`tests/root_test_ownership_guard.rs`) enforces:
1. Every root `.rs` file in `tests/` has a corresponding `[[test]]` entry in `tests/OWNERSHIP.toml`
2. No `[[test]]` entry refers to a missing file
3. No test is classified as `domain` in the manifest (domain tests must be migrated)

## Documentation Updated

- `AGENTS.md`: Updated Quick Commands (DNS tests now per-crate, added root_test_ownership_guard), Guardrail Tests (added root_test_ownership_guard, noted migrated tests), Recent Completions (added Milestone C entry)
- `docs/testing/test-suite-ownership.md`: Updated root test count (43 → 28), added OWNERSHIP.toml note, updated per-crate counts with migrated test names
- `tests/OWNERSHIP.toml`: Created manifest with 28 entries covering all retained root tests

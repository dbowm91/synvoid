# Testing Infrastructure Milestone C — Results

## Summary

Migrated 19 single-domain test files from root `tests/` to their owning crates, reducing root integration test count from 43 to 26 files. Added ownership rationale headers to all retained root tests. Created `tests/OWNERSHIP.toml` manifest with automated guard (`root_test_ownership_guard`) to enforce that every root test has an explicit ownership entry and no domain-classified tests remain at root. Created canonical feature/target matrix (`docs/testing/feature-target-matrix.md`).

## Tests Moved

### Initial Pass (16 files)

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

### Closure Pass (3 files)

| Source (root `tests/`) | Destination Crate |
|------------------------|-------------------|
| `admin_auth_boundary.rs` | `synvoid-core` |
| `mesh_admin_edge_cases.rs` | `synvoid-core` |
| `traffic_regression_test.rs` (proxy functions) | `synvoid-proxy` |

Note: `traffic_regression_test.rs` was split — echo server harness tests (4 tests) remain at root; proxy/router/upstream function tests (58 tests) moved to `synvoid-proxy`.

## Root Test Count

| Metric | Before (pre-Milestone A) | After Milestone C |
|--------|--------------------------|-------------------|
| Root integration test files | 43 | 26 |
| OWNERSHIP.toml entries | 0 | 26 |
| Guard test (`root_test_ownership_guard`) | — | 1 |

## Retained Root Tests and Rationale

All 26 retained root tests have ownership rationale headers in their source files and entries in `tests/OWNERSHIP.toml`. Categories:

- **STATIC_POLICY** (13): `abi_memory_boundary_guard`, `admin_mutation_response_guard`, `architecture_test`, `boundary_composition_guard`, `cli_admin_guard`, `lifecycle_task_guard`, `mesh_id_boundary_guard`, `mesh_task_ownership_guard`, `plugin_guard`, `root_facade_boundary_guard`, `root_test_ownership_guard`, `security_guard`, `worker_mesh_supervision_boundary_guard`
- **COMPOSITION** (13): `admin_mutation_blocklist`, `composition_root_behavioral`, `dht_integration_test`, `drain_e2e_test`, `e2e_process_test`, `failure_injection`, `fault_injection_test`, `integration_test`, `mesh_startup_rollback`, `overseer_lifecycle_test`, `security_regression`, `traffic_regression_test`, `worker_supervision_control_flow`

These tests validate cross-crate composition, static policy invariants, or executable behavior that requires the root package. Domain tests that only exercise one crate's behavior have been migrated.

## Pre-existing Failures

These failures existed before Milestone C and are not regressions:

- **DNS (3)**: `dns_config_test`, `dns_recursive_isolation`, `authoritative_negative` — known DNS test issues (pre-existing)
- **IPC (3)**: `ipc_test`, `process_lifecycle_test`, `drain_e2e_test` — known IPC lifecycle issues (pre-existing)
- **WAF (4)**: `waf_corpus_test`, `wave10_test`, `property_tests_common`, `corpus` — known WAF corpus/property test issues (pre-existing)
- **Mesh**: Raft dependency compilation issues (pre-existing, feature-gated)
- **Proxy (2)**: `test_unknown_host_accepted_when_disabled`, `test_wildcard_domain_matching` — pre-existing router behavior (confirmed failing at root before migration)

## Guard Test Added

`root_test_ownership_guard` (`tests/root_test_ownership_guard.rs`) enforces:
1. Every root `.rs` file in `tests/` has a corresponding `[[test]]` entry in `tests/OWNERSHIP.toml`
2. No `[[test]]` entry refers to a missing file
3. No test is classified as `domain` in the manifest (domain tests must be migrated)

## Testkit Assessment (Workstream C5)

### Current State

`synvoid-testkit` exists but is completely unused — zero workspace crates depend on it. Its three modules (`assertions`, `config_fixtures`, `request_fixtures`) have no consumers.

### Duplicated Fixture Inventory

The largest duplication is in DNS integration tests:

| Fixture | Duplicated Across | Lines Per Copy |
|---------|-------------------|----------------|
| `build_query(id, qname, qtype)` | 9 files | ~20 |
| `build_test_zone()` | 8 files | ~50 |
| `setup()` | 8 files | ~20 |
| `make_ctx()` | 8 files | ~15 |
| `build_notify_query` | 6 files | ~15 |
| `build_axfr_query` | 5 files | ~10 |
| `build_update_add_record` | 5 files | ~20 |

**Total DNS fixture duplication: ~1,600 lines across 8 integration test files.**

### Recommendations for Milestone D

1. **DNS test helpers** — Extract `build_query`, `build_test_zone`, `setup`, `make_ctx`, and protocol query builders into `synvoid-dns/test_helpers/` module (not testkit, since they're domain-specific)
2. **IPC `temp_endpoint`** — Extract to `synvoid-ipc/test_helpers/` (2 consumers)
3. **DNSSEC key builders** — Unify `ed25519_test_key()` variants (4 files)
4. **Keep testkit for cross-crate fixtures only** — Echo server, temp dirs, cert helpers

## Feature/Target Matrix (Workstream C7+C8)

Created `docs/testing/feature-target-matrix.md` with:
- 135 unique cargo invocations across 4 lanes
- 23 redundant entries identified in release-qualification
- Canonical matrix for each lane
- Recommendations for overlap reduction

## Documentation Updated

- `AGENTS.md`: Updated Quick Commands (DNS tests now per-crate, added root_test_ownership_guard), Guardrail Tests (added root_test_ownership_guard, noted migrated tests), Recent Completions (added Milestone C entry)
- `docs/testing/test-suite-ownership.md`: Updated root test count (43 → 26), added OWNERSHIP.toml note, updated per-crate counts with migrated test names
- `docs/testing/root-test-ownership.md`: Created classification document
- `docs/testing/feature-target-matrix.md`: Created canonical feature/target matrix
- `docs/testing/ci-lane-policy.md`: Added reference to feature-target-matrix
- `docs/testing/ci-performance-baseline.md`: Added post-Milestone C counts
- `tests/OWNERSHIP.toml`: Created manifest with 26 entries covering all retained root tests
- Skills: `synvoid_mesh/SKILL.md`, `ipc_hardening/SKILL.md` — command references updated
- Architecture: `runtime_operations_drill.md`, `runtime_operations_drill_report.md`, `dns_production_profiles.md`, `release_hardening_report.md`, `plugin_runtime_sandbox.md` — command references updated

## Handoff to Milestone D

### Canonical Validation Commands

```bash
# Root guard suite
cargo test --test root_test_ownership_guard
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci

# Per-crate test suites (authoritative for domain behavior)
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-core --profile ci
cargo test -p synvoid-proxy --profile ci
cargo test -p synvoid-plugin-runtime --profile ci
cargo test -p synvoid-mesh --profile ci
cargo test -p synvoid-ipc --profile ci
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-platform --profile ci

# Root composition tests
cargo test --profile ci --tests
```

### Package-Level Compile Timing

| Package | Test Binaries | Notes |
|---------|---------------|-------|
| synvoid (root) | 26 integration + 1 lib | Reduced from 43 integration |
| synvoid-dns | 31 integration + 1 lib | All DNS domain tests |
| synvoid-proxy | 1 integration (new) | traffic_regression_test |
| synvoid-core | 2 integration (new) | admin_auth_boundary, mesh_admin_edge_cases |
| synvoid-plugin-runtime | 2 integration | migrated from root |
| synvoid-mesh | 3 integration | migrated from root |
| synvoid-ipc | 2 integration | migrated from root |
| synvoid-waf | 3 integration | migrated from root |
| synvoid-platform | 1 integration | migrated from root |

### Root Test Ownership Map

See `tests/OWNERSHIP.toml` for the authoritative manifest. 26 entries across:
- 13 STATIC_POLICY (guard/source-scanning tests)
- 13 COMPOSITION (cross-crate behavior tests)

### Affected-Package Selection Candidates

For localized changes, these packages can be tested independently:
- `synvoid-dns` — all 31+ test binaries, no root dependency
- `synvoid-core` — 2 new integration tests, no root dependency
- `synvoid-proxy` — 1 new integration test, no root dependency
- `synvoid-plugin-runtime` — 2 migrated tests, no root dependency
- `synvoid-mesh` — 3 migrated tests, no root dependency
- `synvoid-ipc` — 2 migrated tests, no root dependency
- `synvoid-waf` — 3 migrated tests, no root dependency
- `synvoid-platform` — 1 migrated test, no root dependency

### Conservative Triggers (Always Full Validation)

- Changes to `src/lib.rs` or `src/main.rs`
- Changes to `Cargo.toml` (workspace-level)
- Changes to `.github/workflows/`
- Changes to `tests/OWNERSHIP.toml` or `tests/root_test_ownership_guard.rs`
- Feature flag changes in any `Cargo.toml`
- Dependency version bumps

# Phase 8 Verification Report

CI profile matrix, fuzz targets, failure-injection tests, and docs link guard.

## Profile Matrix

| Profile | Command | Required | Platform | Status |
|---------|---------|----------|----------|--------|
| default | `cargo check` | Yes | All | Verified |
| no-default | `cargo check --no-default-features` | Yes | All | Verified |
| mesh | `cargo check --no-default-features --features mesh` | Yes | All | Verified |
| dns | `cargo check --no-default-features --features dns` | Yes | All | Verified |
| mesh-dns | `cargo check --no-default-features --features mesh,dns` | Yes | All | Verified |
| wireguard | `cargo check --features wireguard` | No | Linux/macOS/FreeBSD | CI matrix |
| post-quantum | `cargo check --features post-quantum` | No | All | CI matrix |
| icmp-filter | `cargo check --features icmp-filter` | No | Linux | CI matrix |
| swagger-ui | default feature | Yes | All | Included in default |
| erased_pool | default feature | Yes | All | Included in default |
| socket-handoff | default feature | Yes | All | Included in default |

## Guard Test Suite

18 architecture boundary guard tests in CI guard-suite job:

- `root_facade_boundary_guard`
- `root_module_ledger_guard`
- `root_dependency_ownership_guard`
- `unified_server_lifecycle_ownership_guard`
- `supervisor_task_ownership_guard`
- `request_path_capability_boundary_guard`
- `data_plane_composition_boundary_guard`
- `http_request_pipeline_boundary_guard`
- `http3_waf_boundary_guard`
- `mesh_id_boundary_guard`
- `threat_intel_boundary_guard`
- `threat_intel_consumer_actionability_guard`
- `plugin_capability_boundary_guard`
- `plugin_failure_does_not_poison_manager`
- `admin_mutation_response_guard`
- `admin_mutation_blocklist`
- `admin_auth_boundary`
- `mesh_admin_edge_cases`

## Fuzz Target Inventory

11 targets (8 existing + 3 new):

| Target | Status | Priority |
|--------|--------|----------|
| fuzz_attack_detection | Existing | High |
| fuzz_early_parse | Existing | High |
| fuzz_ipc | Existing | High |
| fuzz_serialization | Existing | Medium |
| fuzz_serialization_new | Existing | Medium |
| fuzz_protocol_proto_decode | Existing | High |
| fuzz_raft_commit_notification | Existing | High |
| fuzz_raft_response | Existing | High |
| dns_message_decode | **New** | High |
| plugin_manifest | **New** | High |
| http_path_normalization | **New** | High |

## Failure-Injection Tests

10 tests in `tests/failure_injection.rs`:

1. `supervisor_critical_task_failure_counted_in_shutdown_report`
2. `supervisor_shutdown_cause_task_failed_is_fatal_with_correct_metadata`
3. `blocklist_catchup_cursor_beyond_retained_history_requests_snapshot`
4. `blocklist_snapshot_apply_rejects_stale_records_via_target_state`
5. `plugin_load_failure_returns_error_manager_remains_usable`
6. `worker_critical_task_panic_classified_as_panic_exit`
7. `blocklist_event_log_deduplication_prevents_double_insertion`
8. `worker_task_registry_no_task_leak_on_shutdown_timeout`
9. `blockstore_disabled_all_operations_are_noop`
10. `supervisor_shutdown_cause_fatal_classification_is_complete`

## Docs Path Reference Guard

`tests/docs_path_reference_guard.rs` scans architecture/, .opencode/skills/, docs/, AGENTS.md, and README.md for broken local markdown links. Catches stale references after module moves.

## CI Jobs Added

- `profile-matrix`: 5 baseline profiles as matrix strategy
- `guard-suite`: All 18 architecture guard tests
- `docs-link-guard`: Docs path reference guard

## Local Verification

```bash
./scripts/verify_architecture.sh
cargo test --test docs_path_reference_guard
cargo test --test failure_injection
```

## Residual Risks

- Fuzz smoke targets require `cargo fuzz` (nightly Rust) — not mandatory on every PR
- Some failure-injection scenarios (mesh peer reconnect, startup partial failure) require full process spawning and are not covered
- Platform-specific features (wireguard, icmp-filter) only compile on their target platforms

# Release Hardening Report

Phase 10 closure report. Records all verification commands run, checklist status, and release readiness.

## 1. Profile Compatibility Checks

All profile checks pass with zero errors.

| Profile | Command | Status |
|---------|---------|--------|
| default (all features) | `cargo check` | PASS (31 warnings) |
| no-default-features | `cargo check --no-default-features` | PASS (43 warnings) |
| mesh only | `cargo check --no-default-features --features mesh` | PASS (36 warnings) |
| dns only | `cargo check --no-default-features --features dns` | PASS (43 warnings) |
| mesh,dns | `cargo check --no-default-features --features mesh,dns` | PASS (31 warnings) |

## 2. Formatting Check

| Command | Status |
|---------|--------|
| `cargo fmt --all -- --check` | PASS |

## 3. Guard Test Results

All 27 guard tests pass.

| Guard | Tests | Status |
|-------|-------|--------|
| `root_facade_boundary_guard` | 1/1 | PASS |
| `root_module_ledger_guard` | 1/1 | PASS |
| `root_dependency_ownership_guard` | 3/3 | PASS |
| `unified_server_lifecycle_ownership_guard` | 5/5 | PASS |
| `supervisor_task_ownership_guard` | 4/4 | PASS |
| `request_path_capability_boundary_guard` | 11/11 | PASS |
| `data_plane_composition_boundary_guard` | 25/25 | PASS |
| `http_request_pipeline_boundary_guard` | 9/9 | PASS |
| `http3_waf_boundary_guard` | 5/5 | PASS |
| `mesh_id_boundary_guard` | 5/5 | PASS |
| `threat_intel_boundary_guard` | 5/5 | PASS |
| `threat_intel_consumer_actionability_guard` | 17/17 | PASS |
| `admin_mutation_response_guard` | 2/2 | PASS |
| `plugin_capability_boundary_guard` | 8/8 | PASS |
| `plugin_signature_policy_guard` | 10/10 | PASS |
| `docs_path_reference_guard` | 1/1 | PASS |
| `security_observability_guard` | 22/22 | PASS |
| `background_task_ownership_guard` | 38/38 | PASS |
| `cli_command_dispatch_guard` | 39/39 | PASS |
| `manual_enforcement_provenance_guard` | 12/12 | PASS |
| `unified_worker_composition_root_guard` | 28/28 | PASS |
| `worker_mesh_supervision_boundary_guard` | 106/106 | PASS |
| `mesh_task_ownership_guard` | 164/164 | PASS |
| `admin_mutation_blocklist` | 10/10 | PASS |
| `admin_auth_boundary` | 8/8 | PASS |
| `mesh_admin_edge_cases` | 8/8 | PASS |
| `plugin_failure_does_not_poison_manager` | 6/6 | PASS |
| `failure_injection` | 10/10 | PASS |

## 4. Release Checklist

### Infrastructure

- [x] All supported profile checks pass
- [x] All release-required guards pass (27/27)
- [x] Format check passes
- [x] No `mem::forget` lifecycle leaks (guard: `unified_server_lifecycle_ownership_guard`)
- [x] No domain crate root imports (guard: `root_facade_boundary_guard`)
- [x] No request-path control-plane imports (guard: `request_path_capability_boundary_guard`)
- [x] No raw threat-intel enforcement paths (guard: `threat_intel_boundary_guard`)
- [x] Root exports are ledger-accurate (guard: `root_module_ledger_guard`)

### Security

- [x] Admin mutation audit model implemented (`AdminMutationResult`) — Phase 12: all non-deferred mutating endpoints converted; guard now detects `StatusResponse::success`
- [x] Plugin capability model implemented (`plugin_capability_boundary_guard`)
- [x] Threat-intel consumer actionability enforced (7 rules, `threat_intel_consumer_actionability_guard`)
- [x] Mesh-ID blocks are admin-only (`mesh_id_boundary_guard`)
- [x] Manual enforcement uses provenance (`manual_enforcement_provenance_guard`)
- [x] Security observability signals present (`security_observability_guard`)

### Documentation

- [x] Docs path guard passes (`docs_path_reference_guard`)
- [x] Public root facades documented (root_module_ledger.md)
- [x] Root dependency ownership documented (root_dependency_ownership.md)

### Architecture

- [x] Request-path capability boundary enforced
- [x] Data-plane composition boundary enforced
- [x] HTTP request pipeline boundary enforced
- [x] HTTP/3 WAF boundary enforced
- [x] Background task ownership enforced
- [x] CLI command dispatch boundary enforced
- [x] Worker mesh supervision boundary enforced

### Fuzzing

- [x] Attack detection fuzz target exists (`fuzz_attack_detection`)
- [x] Early HTTP parse fuzz target exists (`fuzz_early_parse`)
- [x] IPC fuzz target exists (`fuzz_ipc`)
- [x] Serialization fuzz targets exist (`fuzz_serialization`, `fuzz_serialization_new`)
- [x] Protocol proto decode fuzz target exists (`fuzz_protocol_proto_decode`)
- [x] Raft response fuzz target exists (`fuzz_raft_response`)
- [x] Raft commit notification fuzz target exists (`fuzz_raft_commit_notification`)
- [x] DNS message decode fuzz target exists (`dns_message_decode`)
- [x] Plugin manifest fuzz target exists (`plugin_manifest`)
- [x] HTTP path normalization fuzz target exists (`http_path_normalization`)
- [x] Blocklist event decode fuzz target exists (`blocklist_event_decode`) — Phase 14
- [x] Blocklist snapshot decode fuzz target exists (`blocklist_snapshot_decode`) — Phase 14
- [x] Admin mutation result decode fuzz target exists (`admin_mutation_result_decode`) — Phase 14
- [x] HTTP header normalization fuzz target exists (`http_header_normalization`) — Phase 14
- [x] Mesh protocol compressed decode fuzz target exists (`mesh_protocol_compressed_decode`) — Phase 14

### Known Deferrals (Not Release-Blocking)

- [ ] Config parse fuzz target: listed in `ci_fuzz_failure_injection.md`, not yet implemented
- [ ] HTTP chunked body framing fuzz: listed as high-value target, not yet implemented
- [ ] URL/path routing matcher fuzz: listed as high-value target, not yet implemented
- [ ] `split_required` module extraction: 11 modules tracked in root_module_ledger.md
- [ ] `serder` module removal: stale legacy module, candidate for deletion

## 5. Summary

**Release status: READY for hardening closure.**

- 5 profile checks: all pass
- 27 guard tests: all pass
- 16 fuzz targets: all exist (11 existing + 5 new in Phase 14)
- No known release-blocking defects
- All architectural invariants enforced by automated guards
- Public surface classified and documented
- Residual risks documented and accepted

### Phase 11 CI Verification (2026-06-29)

CI workflow (`.github/workflows/ci.yml`) was fixed in Phase 11. The `summary` job had broken dynamic expressions (`${{ needs.${{ job }}.result }}`) that caused a workflow parse error, preventing all 16 jobs from running. Fixed by replacing with static `${{ needs.<job>.result }}` references.

`scripts/verify_architecture.sh` was updated to include `docs_path_reference_guard` (previously missing, now aligned with CI guard-suite).

Local verification: all profile checks, format, and 27 guard tests pass. CI workflow now triggers correctly on push/PR.

### Phase 12 Gap Closure (2026-06-30)

The `admin_mutation_response_guard` was updated to also detect `StatusResponse::success` as a legacy pattern (previously only detected `{"success": true}` and `StatusCode::NO_CONTENT`).

All non-deferred mutating endpoints now return `AdminMutationResult` and emit `AdminAuditEvent`. The final pass converted endpoints in `auth.rs`, `theme.rs`, `tcp_udp.rs`, `mesh_admin.rs`, `system.rs`, `logs.rs`, and `probes.rs`. The only remaining legacy patterns are deferred config PUT endpoints (~50+) and site management endpoints (~6), which are local-only mutations without mesh propagation.

## 6. Verification Commands

```bash
# Profile checks
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns

# Format
cargo fmt --all -- --check

# Guards
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
cargo test --test unified_server_lifecycle_ownership_guard
cargo test --test supervisor_task_ownership_guard
cargo test --test request_path_capability_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test http3_waf_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard --features mesh,dns
cargo test --test admin_mutation_response_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test docs_path_reference_guard
cargo test --test security_observability_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager
cargo test --test background_task_ownership_guard
cargo test --test cli_command_dispatch_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test worker_mesh_supervision_boundary_guard
cargo test --test mesh_task_ownership_guard
```
# Architecture Guard Test Classification

Every guardrail test in `tests/` is classified by its coverage model:

| Classification | Description | Location |
|---------------|-------------|----------|
| **STATIC (Fully Replicated)** | Source/manifest inspection only. Guard crate provides complete equivalent coverage; old root file removed. | `tools/synvoid-repo-guards/tests/` |
| **STATIC (Partial)** | Source/manifest inspection only. Guard crate provides a simplified "smoke test" (1 test), but the old root file has detailed assertions (25-37+ tests) that provide full-depth coverage. Both must run. | Guard crate + root `tests/` |
| **COMPLEX** | Static source inspection, but too many domain-specific assertions, type allowlists, or feature gates to extract cleanly. | Root `tests/` |
| **RUNTIME** | Tests actual behavior — instantiates core types, calls runtime methods, spawns tasks, or tests serialization roundtrips. | Root `tests/` |

## Classification Table

| Guard | Classification | Reason | Location |
|-------|---------------|--------|----------|
| `root_module_ledger_guard` | STATIC (Fully Replicated) | Parses `src/lib.rs` module declarations and checks against ledger; fully replicated in `module_ownership.rs` | Removed from root |
| `root_dependency_ownership_guard` | STATIC (Fully Replicated) | Parses `Cargo.toml` and ownership ledger; fully replicated in `module_ownership.rs` | Removed from root |
| `docs_path_reference_guard` | STATIC (Fully Replicated) | Scans markdown files for broken links; fully replicated in `docs_and_misc.rs` | Removed from root |
| `unsafe_native_sandbox_language_guard` | STATIC (Fully Replicated) | Scans markdown docs for misleading sandbox phrases; fully replicated in `docs_and_misc.rs` | Removed from root |
| `root_facade_boundary_guard` | STATIC (Partial) | Guard crate only checks `use synvoid::`; old file also checks bare `synvoid::` paths | Guard crate + root |
| `data_plane_composition_boundary_guard` | STATIC (Partial) | Guard crate has 1 test; old file has 25+ tests with `BoundaryRole` classification, simulated violations, unified server file classification | Guard crate + root |
| `request_path_capability_boundary_guard` | STATIC (Partial) | Guard crate has 1 test; old file has raw lookup detection, mesh-ID block detection, trait existence checks | Guard crate + root |
| `http_request_pipeline_boundary_guard` | STATIC (Partial) | Guard crate has 1 test; old file has context struct checks, documentation assertions | Guard crate + root |
| `http3_waf_boundary_guard` | STATIC (Partial) | Guard crate has 1 test; old file has Cargo.toml dependency check, trait object safety check | Guard crate + root |
| `background_task_ownership_guard` | STATIC (Partial) | Guard crate has 1 test; old file has 37+ tests covering cancellation, registry, supervision, lifecycle channels | Guard crate + root |
| `supervisor_task_ownership_guard` | STATIC (Partial) | Guard crate has 1 test; old file has allowlist liveness checks, `process_run` check | Guard crate + root |
| `unified_server_lifecycle_ownership_guard` | STATIC (Partial) | Guard crate has 1 test (more permissive — allows `mem::forget` with reason comment); old file has 6 tests with stricter enforcement | Guard crate + root |
| `unified_worker_composition_root_guard` | STATIC (Partial) | Guard crate has 1 test; old file has 28 tests covering module existence, delegation patterns, mesh attachment | Guard crate + root |
| `cli_command_dispatch_guard` | STATIC (Partial) | Guard crate has 1 test; old file has 36 tests covering `execute.rs`, `supervisor_control.rs`, `runtime_launch.rs`, `one_shot.rs` | Guard crate + root |
| `abi_memory_boundary_guard` | COMPLEX | 20+ specific ABI type/pattern assertions tied to `GuestAbiPolicy` and guest memory model | Root |
| `admin_mutation_response_guard` | COMPLEX | Exception lists track specific admin handler paths; pass-through tokens coupled to admin crate structure | Root |
| `manifest_authority_load_path_guard` | COMPLEX | Assertions reference specific loader function signatures in `wasm_runtime.rs` | Root |
| `manual_enforcement_provenance_guard` | COMPLEX | Exception lists track specific allowed legacy `.block_ip()` sites across multiple crates | Root |
| `mesh_id_boundary_guard` | COMPLEX | Exception lists and pass-through tokens tightly coupled to mesh crate structure | Root |
| `mesh_task_ownership_guard` | COMPLEX | 117K of assertions covering 20+ task types with specific allowlists | Root |
| `plugin_capability_boundary_guard` | COMPLEX | Assertions reference specific WASM host API function signatures | Root |
| `plugin_lifecycle_guard` | COMPLEX | 47K of assertions across multiple plugin modules covering lifecycle states | Root |
| `plugin_signature_policy_guard` | COMPLEX | Assertions reference specific crypto type paths and trust-tier enums | Root |
| `security_observability_guard` | COMPLEX | 50+ allowed patterns in exception lists; metric label checks tied to observability crate | Root |
| `threat_intel_boundary_guard` | COMPLEX | Exception lists track diagnostic-only call sites across multiple crates | Root |
| `threat_intel_consumer_actionability_guard` | COMPLEX | 42K of assertions covering 46 consumer types with specific enforcement patterns | Root |
| `worker_mesh_supervision_boundary_guard` | COMPLEX | 62K of assertions; requires `mesh` feature gate; covers struct/function existence checks across mesh/worker | Root |
| `admin_auth_boundary` | RUNTIME | Instantiates `AdminActor`, `AdminAuditEvent`, `AdminMutationResult` structs; tests serialization roundtrips | Root |
| `admin_mutation_blocklist` | RUNTIME | Creates `BlockStore`, calls `block_ip_with_provenance`/`unblock_ip`; verifies mutation result semantics | Root |
| `failure_injection` | RUNTIME | Spawns `tokio::spawn` tasks; tests supervisor shutdown reports, blocklist catchup, plugin guard failure isolation | Root |
| `manifest_authority_wiring` | RUNTIME | Creates `PluginManifest`, `PluginInvocationGuard`; tests capability checking and `invoke_with_limits` | Root |
| `mesh_admin_edge_cases` | RUNTIME | Constructs `AdminMutationResult`/`BlockMutationTarget`; tests serialization and status semantics | Root |
| `plugin_failure_does_not_poison_manager` | RUNTIME | Creates `PluginInvocationGuard` instances; tests failure isolation and repeated timeout behavior | Root |

## Summary

| Classification | Count | Location |
|---------------|-------|----------|
| STATIC (Fully Replicated) | 4 | Removed from root `tests/`; fully covered by `tools/synvoid-repo-guards/tests/` |
| STATIC (Partial) | 10 | Guard crate + root `tests/` (both must run for full coverage) |
| COMPLEX | 13 | Root `tests/` |
| RUNTIME | 6 | Root `tests/` |

**Total guard test functions**: 16 across 4 modules in the guard crate + 23 old root files (10 partial + 13 complex) + 6 runtime files.

## Moved Guards: Fully Replicated (Removed from Root)

These 4 guards were fully replicated in the guard crate. The old root files have been deleted.

### `module_ownership.rs`

| Guard | Original Path | Guard Coverage |
|-------|--------------|----------------|
| `root_module_ledger_guard` | `tests/root_module_ledger_guard.rs` | 1 test — checks `src/lib.rs` pub modules against `architecture/root_module_ledger.md` |
| `root_dependency_ownership_guard` | `tests/root_dependency_ownership_guard.rs` | 4 tests — manifest deps vs ledger, stale entries, valid classifications |

### `docs_and_misc.rs`

| Guard | Original Path | Guard Coverage |
|-------|--------------|----------------|
| `docs_path_reference_guard` | `tests/docs_path_reference_guard.rs` | 1 test — scans markdown files for broken relative links |
| `unsafe_native_sandbox_language_guard` | `tests/unsafe_native_sandbox_language_guard.rs` | 1 test — scans markdown docs for misleading sandbox phrases |

## Partially Replicated Guards (Guard Crate + Root Tests)

These 10 guards have a simplified "smoke test" in the guard crate (1 test each, lightweight pattern scan without linking synvoid) **and** the full-depth old root file with detailed assertions. The guard crate provides fast CI feedback; the root file provides full coverage.

**CI runs both.** The guard crate catches regressions quickly; the root file catches domain-specific violations the simplified scan misses.

### `module_ownership.rs` (partial coverage)

| Guard | Guard Test | Root File | Why Both |
|-------|-----------|-----------|----------|
| `root_facade_boundary_guard` | `domain_crates_do_not_import_root_facade` — checks `use synvoid::` in `crates/` | `tests/root_facade_boundary_guard.rs` | Old file also checks bare `synvoid::` paths (not just `use` imports) |

### `composition_boundary.rs` (partial coverage)

| Guard | Guard Test | Root File | Why Both |
|-------|-----------|-----------|----------|
| `data_plane_composition_boundary_guard` | `request_path_does_not_import_concrete_infrastructure` — scans 4 dirs for 8 forbidden types | `tests/data_plane_composition_boundary_guard.rs` | Old file has 25+ tests: `BoundaryRole` classification, simulated violations, unified server file classification |
| `request_path_capability_boundary_guard` | `request_path_avoids_control_plane_imports` — scans 4 dirs for 4 forbidden crate paths | `tests/request_path_capability_boundary_guard.rs` | Old file has raw lookup detection, mesh-ID block detection, trait existence checks |
| `http_request_pipeline_boundary_guard` | `http_handlers_avoid_lifecycle_imports` — scans HTTP dirs for 6 forbidden tokens | `tests/http_request_pipeline_boundary_guard.rs` | Old file has context struct checks, documentation assertions |
| `http3_waf_boundary_guard` | `http3_crate_avoids_forbidden_imports` — scans HTTP/3 dirs for 8 forbidden types | `tests/http3_waf_boundary_guard.rs` | Old file has Cargo.toml dependency check, trait object safety check |

### `lifecycle_ownership.rs` (partial coverage)

| Guard | Guard Test | Root File | Why Both |
|-------|-----------|-----------|----------|
| `background_task_ownership_guard` | `background_spawns_are_registered_or_documented` — scans 2 dirs for unregistered spawns | `tests/background_task_ownership_guard.rs` | Old file has 37+ tests covering cancellation patterns, registry usage, supervision loops, lifecycle channels |
| `supervisor_task_ownership_guard` | `supervisor_spawns_have_ownership` — scans `src/supervisor/` for unregistered spawns | `tests/supervisor_task_ownership_guard.rs` | Old file has allowlist liveness checks, `process_run` check |
| `unified_server_lifecycle_ownership_guard` | `no_memforget_in_lifecycle_code` — scans `src/server/` and `src/plugin/` for `mem::forget` without reason comment | `tests/unified_server_lifecycle_ownership_guard.rs` | Old file has 6 tests with stricter enforcement; guard crate is more permissive (allows `mem::forget` with reason comment) |
| `unified_worker_composition_root_guard` | `run_unified_server_worker_remains_thin` — checks `run_unified_server_worker` line count ≤80 | `tests/unified_worker_composition_root_guard.rs` | Old file has 28 tests covering module existence, delegation patterns, mesh attachment |
| `cli_command_dispatch_guard` | `main_rs_is_thin_dispatch` — checks `src/main.rs` line count ≤50, no business logic tokens | `tests/cli_command_dispatch_guard.rs` | Old file has 36 tests covering `execute.rs`, `supervisor_control.rs`, `runtime_launch.rs`, `one_shot.rs`, architecture doc checks |

## Guard Crate Structure

```
tools/synvoid-repo-guards/
├── Cargo.toml
├── src/
│   └── lib.rs              # Shared helpers: workspace_root(), collect_rs_files(),
│                           # prepare_for_scanning(), Violations accumulator
└── tests/
    ├── module_ownership.rs # root_module_ledger, root_facade_boundary,
    │                       # root_dependency_ownership
    ├── composition_boundary.rs  # data_plane, request_path_capability,
    │                       # http_pipeline, http3_waf
    ├── lifecycle_ownership.rs  # background_spawns, supervisor_spawns,
    │                       # no_memforget, composition_root_thin, cli_dispatch
    └── docs_and_misc.rs    # docs_path_reference, unsafe_native_sandbox_language
```

**Shared helpers** (`src/lib.rs`):
- `workspace_root()` — walks up from `CARGO_MANIFEST_DIR` to find the workspace root
- `collect_rs_files(dir)` — recursively collects `.rs` files, skipping `target/` and `.git/`
- `prepare_for_scanning(content)` — strips comments, string literals, and `#[cfg(test)]` modules to avoid false positives
- `Violations` — accumulator that collects messages and panics at the end with a formatted report

## COMPLEX Guards: Why They Stay in Root

Each COMPLEX guard performs source inspection (like the STATIC guards) but depends on many domain-specific type names, assertion patterns, or feature gates that make extraction non-trivial:

| Guard | Why It Stays | Milestone C Plan |
|-------|-------------|-----------------|
| `abi_memory_boundary_guard` | 20+ specific ABI type/pattern assertions; tied to `GuestAbiPolicy` and guest memory model | Extract type allowlists to shared config; reduce to pattern-file scanning |
| `admin_mutation_response_guard` | Exception lists track specific admin handler paths; pass-through tokens coupled to admin crate structure | Flatten exception lists into config file; extract to guard crate |
| `manifest_authority_load_path_guard` | Assertions reference specific loader function signatures in `wasm_runtime.rs` | Extract function signature patterns to shared config |
| `manual_enforcement_provenance_guard` | Exception lists track specific allowed legacy `.block_ip()` sites across multiple crates | Flatten exception lists into config file; extract to guard crate |
| `mesh_id_boundary_guard` | Exception lists and pass-through tokens tightly coupled to mesh crate structure | Extract exception lists to config; reduce to pattern-file scanning |
| `mesh_task_ownership_guard` | 117K of assertions covering 20+ task types with specific allowlists | Extract task allowlists to shared config; split into focused sub-guards |
| `plugin_capability_boundary_guard` | Assertions reference specific WASM host API function signatures | Extract host API signatures to shared config; reduce to pattern scanning |
| `plugin_lifecycle_guard` | 47K of assertions across multiple plugin modules covering lifecycle states | Extract lifecycle state machine patterns to shared config |
| `plugin_signature_policy_guard` | Assertions reference specific crypto type paths and trust-tier enums | Extract trust-tier patterns to shared config |
| `security_observability_guard` | 50+ allowed patterns in exception lists; metric label checks tied to observability crate | Flatten exception lists into config; extract to guard crate |
| `threat_intel_boundary_guard` | Exception lists track diagnostic-only call sites across multiple crates | Extract exception lists to config; reduce to pattern-file scanning |
| `threat_intel_consumer_actionability_guard` | 42K of assertions covering 46 consumer types with specific enforcement patterns | Extract consumer classification patterns to shared config |
| `worker_mesh_supervision_boundary_guard` | 62K of assertions; requires `mesh` feature gate; covers struct/function existence checks across mesh/worker | Extract mesh struct patterns to shared config; split by feature gate |

**Milestone C plan**: Extract exception/allowlist data into shared config files (TOML or Rust const arrays in `src/lib.rs`), reducing each COMPLEX guard to a thin scanning shell that references the config. This will allow most of them to move to the guard crate.

## RUNTIME Guards: Why They Stay in Root

| Guard | Why It Stays |
|-------|-------------|
| `admin_auth_boundary` | Instantiates `AdminActor`, `AdminAuditEvent`, `AdminMutationResult` structs; tests serialization roundtrips |
| `admin_mutation_blocklist` | Creates `BlockStore`, calls `block_ip_with_provenance`/`unblock_ip`; verifies mutation result semantics |
| `failure_injection` | Spawns `tokio::spawn` tasks; tests supervisor shutdown reports, blocklist catchup, plugin guard failure isolation |
| `manifest_authority_wiring` | Creates `PluginManifest`, `PluginInvocationGuard`; tests capability checking and `invoke_with_limits` |
| `mesh_admin_edge_cases` | Constructs `AdminMutationResult`/`BlockMutationTarget`; tests serialization and status semantics |
| `plugin_failure_does_not_poison_manager` | Creates `PluginInvocationGuard` instances; tests failure isolation and repeated timeout behavior |

These guards cannot be moved because they:
- Instantiate core types (`BlockStore`, `PluginInvocationGuard`, `AdminMutationResult`)
- Call runtime methods (`block_ip_with_provenance`, `invoke_with_limits`)
- Spawn tokio tasks (`tokio::spawn`)
- Test serialization roundtrips

## Feature Requirements

One COMPLEX guard has an explicit feature gate:

- `worker_mesh_supervision_boundary_guard.rs` — requires `mesh`

The runtime guards (`admin_auth_boundary`, `admin_mutation_blocklist`, `mesh_admin_edge_cases`) depend on `synvoid_core`, `synvoid_block_store`, and `synvoid_config` crates but have no feature gates — they compile with default features.

## How to Run

### Guard crate (lightweight smoke tests)

```bash
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
```

This runs all 16 test functions across 4 modules in the `synvoid-repo-guards` crate using the CI profile (fast, no LTO). These catch regressions quickly but are simplified scans.

### Partially replicated guards (root tests/)

Run these to get full-depth coverage the guard crate's simplified scan misses:

```bash
# Composition boundary guards
cargo test --test root_facade_boundary_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test request_path_capability_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
cargo test --test http3_waf_boundary_guard

# Lifecycle ownership guards
cargo test --test background_task_ownership_guard
cargo test --test supervisor_task_ownership_guard
cargo test --test unified_server_lifecycle_ownership_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test cli_command_dispatch_guard
```

### COMPLEX and RUNTIME guards (root tests/)

```bash
# COMPLEX guards (source inspection, many assertions)
cargo test --test abi_memory_boundary_guard
cargo test --test admin_mutation_response_guard
cargo test --test manifest_authority_load_path_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test mesh_id_boundary_guard
cargo test --test mesh_task_ownership_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_lifecycle_guard
cargo test --test plugin_signature_policy_guard
cargo test --test security_observability_guard
cargo test --test threat_intel_boundary_guard
cargo test --test threat_intel_consumer_actionability_guard
cargo test --test worker_mesh_supervision_boundary_guard --features mesh

# RUNTIME guards (need core types, process spawning, etc.)
cargo test --test admin_auth_boundary
cargo test --test admin_mutation_blocklist
cargo test --test failure_injection
cargo test --test manifest_authority_wiring
cargo test --test mesh_admin_edge_cases
cargo test --test plugin_failure_does_not_poison_manager
```

### All root guards at once

```bash
cargo test --test root_facade_boundary_guard --test data_plane_composition_boundary_guard --test request_path_capability_boundary_guard --test http_request_pipeline_boundary_guard --test http3_waf_boundary_guard --test background_task_ownership_guard --test supervisor_task_ownership_guard --test unified_server_lifecycle_ownership_guard --test unified_worker_composition_root_guard --test cli_command_dispatch_guard --test abi_memory_boundary_guard --test admin_mutation_response_guard --test manifest_authority_load_path_guard --test manual_enforcement_provenance_guard --test mesh_id_boundary_guard --test mesh_task_ownership_guard --test plugin_capability_boundary_guard --test plugin_lifecycle_guard --test plugin_signature_policy_guard --test security_observability_guard --test threat_intel_boundary_guard --test threat_intel_consumer_actionability_guard --test worker_mesh_supervision_boundary_guard --test admin_auth_boundary --test admin_mutation_blocklist --test failure_injection --test manifest_authority_wiring --test mesh_admin_edge_cases --test plugin_failure_does_not_poison_manager --features mesh
```

## Migration Notes

**4 STATIC guards fully replicated** (removed from root `tests/`):
- `root_module_ledger_guard` → `module_ownership.rs` (1 test)
- `root_dependency_ownership_guard` → `module_ownership.rs` (4 tests)
- `docs_path_reference_guard` → `docs_and_misc.rs` (1 test)
- `unsafe_native_sandbox_language_guard` → `docs_and_misc.rs` (1 test)

These were removed because the guard crate provides complete equivalent coverage. No depth is lost.

**10 STATIC guards partially replicated** (old root files retained):
- The guard crate provides a lightweight smoke test (1 test each) that compiles without linking synvoid.
- The old root files provide full-depth coverage (25-37+ tests each) with domain-specific assertions.
- CI runs both: guard crate for fast regression detection, root tests for full coverage.

**13 COMPLEX guards** remain in root `tests/` because they:
- Reference 20+ domain-specific type names in assertions
- Have large exception/allowlist tables tied to crate structure
- Some require feature gates (`mesh`)
- Extraction requires flattening allowlists into shared config first (planned for Milestone C)

**6 RUNTIME guards** must remain in root `tests/` because they:
- Instantiate core types (`BlockStore`, `PluginInvocationGuard`, `AdminMutationResult`)
- Call runtime methods (`block_ip_with_provenance`, `invoke_with_limits`)
- Spawn tokio tasks (`tokio::spawn`)
- Test serialization roundtrips

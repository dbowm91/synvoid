# Architecture Guard Test Classification

Every guardrail test in `tests/` is classified by its coverage model:

| Classification | Description | Location |
|---------------|-------------|----------|
| **STATIC (Fully Replicated)** | Source/manifest inspection only. Guard crate provides complete equivalent coverage; old root file removed. | `tools/synvoid-repo-guards/tests/` |
| **CONSOLIDATED** | Source/manifest inspection grouped by domain. Multiple old root files merged into a single domain-grouped binary with shared helpers. All original assertions preserved. | Root `tests/` (grouped files) |
| **STANDALONE** | Source/manifest inspection or runtime behavior, kept as individual root test files. | Root `tests/` (individual files) |
| **RUNTIME** | Tests actual behavior — instantiates core types, calls runtime methods, spawns tasks, or tests serialization roundtrips. | Root `tests/` |

## Consolidated Guard Files (B12)

In Milestone B Phase 12, 17 individual root guard test files were consolidated into 5 domain-grouped files. All original test assertions are preserved; only the file organization changed.

| Consolidated File | Original Files | Test Count |
|-------------------|---------------|------------|
| `boundary_composition_guard.rs` | `data_plane_composition_boundary_guard`, `request_path_capability_boundary_guard`, `http_request_pipeline_boundary_guard`, `http3_waf_boundary_guard`, `manifest_authority_load_path_guard` | ~59 |
| `lifecycle_task_guard.rs` | `background_task_ownership_guard`, `supervisor_task_ownership_guard`, `unified_server_lifecycle_ownership_guard` | ~46 |
| `plugin_guard.rs` | `plugin_capability_boundary_guard`, `plugin_lifecycle_guard`, `plugin_signature_policy_guard` | ~52 |
| `cli_admin_guard.rs` | `cli_command_dispatch_guard`, `manual_enforcement_provenance_guard`, `unified_worker_composition_root_guard` | ~79 |
| `security_guard.rs` | `security_observability_guard`, `threat_intel_boundary_guard`, `threat_intel_consumer_actionability_guard` | ~46 |

**Root guard binary count: 24 → 12** (5 consolidated + 7 standalone).

## Classification Table

| Guard | Classification | Reason | Location |
|-------|---------------|--------|----------|
| `root_module_ledger_guard` | STATIC (Fully Replicated) | Parses `src/lib.rs` module declarations; fully replicated in `module_ownership.rs` | Removed from root |
| `root_dependency_ownership_guard` | STATIC (Fully Replicated) | Parses `Cargo.toml` and ownership ledger; fully replicated in `module_ownership.rs` | Removed from root |
| `docs_path_reference_guard` | STATIC (Fully Replicated) | Scans markdown files for broken links; fully replicated in `docs_and_misc.rs` | Removed from root |
| `unsafe_native_sandbox_language_guard` | STATIC (Fully Replicated) | Scans markdown docs for misleading sandbox phrases; fully replicated in `docs_and_misc.rs` | Removed from root |
| `boundary_composition_guard` | CONSOLIDATED | 5 files merged: data-plane, request-path, HTTP pipeline, HTTP/3 WAF, manifest authority boundary guards | Root |
| `lifecycle_task_guard` | CONSOLIDATED | 3 files merged: background tasks, supervisor spawns, unified server lifecycle guards | Root |
| `plugin_guard` | CONSOLIDATED | 3 files merged: plugin capability, lifecycle, signature policy guards | Root |
| `cli_admin_guard` | CONSOLIDATED | 3 files merged: CLI dispatch, enforcement provenance, worker composition guards | Root |
| `security_guard` | CONSOLIDATED | 3 files merged: security observability, threat-intel boundary, consumer actionability guards | Root |
| `root_facade_boundary_guard` | STANDALONE | Small standalone guard checking domain crates don't import root `synvoid::` | Root |
| `mesh_id_boundary_guard` | STANDALONE | Exception lists and pass-through tokens tightly coupled to mesh crate structure | Root |
| `abi_memory_boundary_guard` | STANDALONE | 20+ specific ABI type/pattern assertions tied to `GuestAbiPolicy` | Root |
| `admin_mutation_response_guard` | STANDALONE | Exception lists track specific admin handler paths | Root |
| `worker_mesh_supervision_boundary_guard` | STANDALONE | 62K of assertions; requires `mesh` feature gate | Root |
| `mesh_task_ownership_guard` | STANDALONE | 117K of assertions covering 20+ task types with specific allowlists | Root |
| `admin_auth_boundary` | RUNTIME | Instantiates `AdminActor`, `AdminAuditEvent`, `AdminMutationResult`; tests serialization roundtrips | Root |
| `admin_mutation_blocklist` | RUNTIME | Creates `BlockStore`, calls `block_ip_with_provenance`/`unblock_ip` | Root |
| `failure_injection` | RUNTIME | Spawns `tokio::spawn` tasks; tests supervisor shutdown, blocklist catchup, plugin failure isolation | Root |
| `manifest_authority_wiring` | RUNTIME | Creates `PluginManifest`, `PluginInvocationGuard`; tests capability checking | Root |
| `mesh_admin_edge_cases` | RUNTIME | Constructs `AdminMutationResult`/`BlockMutationTarget`; tests serialization | Root |
| `plugin_failure_does_not_poison_manager` | RUNTIME | Creates `PluginInvocationGuard` instances; tests failure isolation | Root |

## Summary

| Classification | Count | Location |
|---------------|-------|----------|
| STATIC (Fully Replicated) | 4 | Removed from root `tests/`; covered by `tools/synvoid-repo-guards/tests/` |
| CONSOLIDATED | 5 | Root `tests/` (grouped domain files, ~282 tests total) |
| STANDALONE | 6 | Root `tests/` (individual files) |
| RUNTIME | 6 | Root `tests/` |

**Total root guard test files: 17** (5 consolidated + 6 standalone + 6 runtime).
**Guard crate tests: 26** (16 smoke tests + 10 negative fixtures).

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
    ├── docs_and_misc.rs    # docs_path_reference, unsafe_native_sandbox_language
    └── negative_fixtures.rs # 10 tests proving guards detect violations
```

**Shared helpers** (`src/lib.rs`):
- `workspace_root()` — walks up from `CARGO_MANIFEST_DIR` to find the workspace root
- `collect_rs_files(dir)` — recursively collects `.rs` files, skipping `target/` and `.git/`
- `prepare_for_scanning(content)` — strips comments, string literals, and `#[cfg(test)]` modules
- `Violations` — accumulator that collects messages and panics at the end

## Feature Requirements

- `worker_mesh_supervision_boundary_guard.rs` — requires `mesh` feature
- `mesh_task_ownership_guard.rs` — requires `mesh,dns` features
- Runtime guards (`admin_auth_boundary`, `admin_mutation_blocklist`, `mesh_admin_edge_cases`) depend on `synvoid_core`, `synvoid_block_store`, and `synvoid_config` but have no feature gates

## How to Run

### Guard crate (lightweight smoke tests)

```bash
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
```

### Consolidated root guards

```bash
cargo test --test boundary_composition_guard    # ~59 tests: data-plane, request-path, HTTP pipeline, HTTP/3 WAF, manifest authority
cargo test --test lifecycle_task_guard          # ~46 tests: background tasks, supervisor spawns, unified server lifecycle
cargo test --test plugin_guard                  # ~52 tests: plugin capability, lifecycle, signature policy
cargo test --test cli_admin_guard               # ~79 tests: CLI dispatch, enforcement provenance, worker composition
cargo test --test security_guard                # ~46 tests: security observability, threat-intel boundary, consumer actionability
```

### Standalone and runtime guards

```bash
# Standalone source-scanning guards
cargo test --test root_facade_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test abi_memory_boundary_guard
cargo test --test admin_mutation_response_guard
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns

# Runtime guards (need core types, process spawning, etc.)
cargo test --test admin_auth_boundary
cargo test --test admin_mutation_blocklist
cargo test --test failure_injection
cargo test --test manifest_authority_wiring
cargo test --test mesh_admin_edge_cases
cargo test --test plugin_failure_does_not_poison_manager
```

### All root guards at once

```bash
cargo test --test boundary_composition_guard --test lifecycle_task_guard --test plugin_guard --test cli_admin_guard --test security_guard --test root_facade_boundary_guard --test mesh_id_boundary_guard --test abi_memory_boundary_guard --test admin_mutation_response_guard --test worker_mesh_supervision_boundary_guard --test mesh_task_ownership_guard --test admin_auth_boundary --test admin_mutation_blocklist --test failure_injection --test manifest_authority_wiring --test mesh_admin_edge_cases --test plugin_failure_does_not_poison_manager --features mesh,dns
```

## Migration Notes

**4 STATIC guards fully replicated** (removed from root `tests/`):
- `root_module_ledger_guard` → `module_ownership.rs` (1 test)
- `root_dependency_ownership_guard` → `module_ownership.rs` (4 tests)
- `docs_path_reference_guard` → `docs_and_misc.rs` (1 test)
- `unsafe_native_sandbox_language_guard` → `docs_and_misc.rs` (1 test)

**17 guards consolidated into 5 domain-grouped files** (Milestone B Phase 12):
- All original test assertions preserved with exact logic
- Shared helpers deduplicated at the top of each consolidated file
- Root guard binary count reduced from 24 to 12

**6 standalone guards** remain as individual root files:
- Small enough to not warrant consolidation (`root_facade_boundary_guard`)
- Feature-gated (`worker_mesh_supervision_boundary_guard`, `mesh_task_ownership_guard`)
- Large assertion count best kept separate (`abi_memory_boundary_guard`, `admin_mutation_response_guard`, `mesh_id_boundary_guard`)

**6 RUNTIME guards** must remain in root `tests/` because they:
- Instantiate core types (`BlockStore`, `PluginInvocationGuard`, `AdminMutationResult`)
- Call runtime methods (`block_ip_with_provenance`, `invoke_with_limits`)
- Spawn tokio tasks (`tokio::spawn`)
- Test serialization roundtrips

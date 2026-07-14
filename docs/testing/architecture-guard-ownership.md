# Architecture Guard Test Classification

Every guardrail test in `tests/` is classified as **STATIC** (source/manifest inspection only), **RUNTIME** (tests actual behavior), or **COMPLEX** (static but too many domain-specific assertions to extract cleanly). This determines whether the guard can be moved to the lightweight `synvoid-repo-guards` crate or must remain in root integration tests.

## Milestone B Changes

As of Milestone B, the simplest STATIC guards were extracted to `tools/synvoid-repo-guards/`, a dedicated crate with minimal dependencies (`regex`, `std::fs`). The remaining guards are split into two categories:

- **RUNTIME** guards that require instantiating core types, calling runtime methods, or spawning tasks.
- **COMPLEX** guards that perform source inspection but depend on many domain-specific type names, assertion patterns, or feature gates, making extraction non-trivial.

## Classification Table

| Guard | Classification | Reason | Location |
|-------|---------------|--------|----------|
| `root_module_ledger_guard.rs` | STATIC | Parses `src/lib.rs` module declarations and checks against `architecture/root_module_ledger.md` | Moved |
| `root_facade_boundary_guard.rs` | STATIC | Scans `crates/` for forbidden `use synvoid::` imports | Moved |
| `root_dependency_ownership_guard.rs` | STATIC | Parses `Cargo.toml` and ownership ledger for missing entries | Moved |
| `data_plane_composition_boundary_guard.rs` | STATIC | Scans request-path `.rs` files for forbidden concrete infrastructure imports | Moved |
| `request_path_capability_boundary_guard.rs` | STATIC | Scans request-path `.rs` files for forbidden control-plane imports | Moved |
| `http_request_pipeline_boundary_guard.rs` | STATIC | Scans HTTP handler `.rs` files for forbidden worker lifecycle imports | Moved |
| `http3_waf_boundary_guard.rs` | STATIC | Scans `crates/synvoid-http3/` for forbidden concrete app-service imports | Moved |
| `background_task_ownership_guard.rs` | STATIC | Scans `src/` for `tokio::spawn` calls, checks allowlist and registry usage patterns | Moved |
| `supervisor_task_ownership_guard.rs` | STATIC | Scans `src/supervisor/` for `tokio::spawn` calls, checks allowlist and registry usage | Moved |
| `unified_server_lifecycle_ownership_guard.rs` | STATIC | Scans `src/server/` and `src/plugin/` for `mem::forget`, missing `reason` comments, unregistered spawns | Moved |
| `unified_worker_composition_root_guard.rs` | STATIC | Reads `unified_server/mod.rs`, checks `run_unified_server_worker` line count and delegation structure | Moved |
| `cli_command_dispatch_guard.rs` | STATIC | Reads `src/main.rs`, checks line count and forbidden command-implementation tokens | Moved |
| `docs_path_reference_guard.rs` | STATIC | Scans markdown files for broken relative links | Moved |
| `unsafe_native_sandbox_language_guard.rs` | STATIC | Scans markdown docs for forbidden sandbox language patterns | Remains (root) |
| `abi_memory_boundary_guard.rs` | COMPLEX | Reads source via `include_str!`, checks for removed patterns and required structs/functions; 20+ specific type/pattern assertions tied to ABI memory model | Root |
| `admin_mutation_response_guard.rs` | COMPLEX | Scans admin handler `.rs` files for forbidden ad-hoc JSON response patterns; exception lists and pass-through tokens are tightly coupled to admin crate structure | Root |
| `manifest_authority_load_path_guard.rs` | COMPLEX | Scans `wasm_runtime.rs` for direct `WasmRuntime::load` calls bypassing manifest enforcement; assertions reference specific loader function signatures | Root |
| `manual_enforcement_provenance_guard.rs` | COMPLEX | Scans source files for legacy `.block_ip()` calls instead of `block_ip_with_provenance`; exception lists track specific allowed legacy sites | Root |
| `mesh_id_boundary_guard.rs` | COMPLEX | Scans source files for forbidden `is_mesh_id_blocked()` calls; exception lists and pass-through tokens are tightly coupled to mesh crate structure | Root |
| `mesh_task_ownership_guard.rs` | COMPLEX | Scans mesh `transport.rs` for spawn patterns, `select!` with shutdown, task group usage; 117K of assertions covering 20+ task types with specific allowlists | Root |
| `plugin_capability_boundary_guard.rs` | COMPLEX | Scans `wasm_runtime.rs` for capability-gated host function wrappers, `mem::forget`; assertions reference specific WASM host API function signatures | Root |
| `plugin_lifecycle_guard.rs` | COMPLEX | Scans plugin source files for lifecycle invariants (duplicate name checks, generation tracking, hot-reload gates); 47K of assertions across multiple plugin modules | Root |
| `plugin_signature_policy_guard.rs` | COMPLEX | Scans plugin source files for `enforce_plugin_load_policy`, trust-tier enforcement, key material leakage; assertions reference specific crypto type paths | Root |
| `security_observability_guard.rs` | COMPLEX | Scans source files for forbidden metric label keys, raw threat-intel lookups in metric functions, doc coverage; exception lists track 50+ allowed patterns | Root |
| `threat_intel_boundary_guard.rs` | COMPLEX | Scans enforcement-sensitive paths for forbidden raw lookup calls; exception lists track diagnostic-only call sites across multiple crates | Root |
| `threat_intel_consumer_actionability_guard.rs` | COMPLEX | Scans threat-intel files for forbidden raw lookups, `LegacyUnknown` provenance, admin-supervisor authority misuse; 42K of assertions covering 46 consumer types | Root |
| `worker_mesh_supervision_boundary_guard.rs` | COMPLEX | Scans mesh/worker source files for required struct/function existence and delegation patterns; requires `mesh` feature gate and covers 62K of assertions | Root |
| `admin_auth_boundary.rs` | RUNTIME | Instantiates `AdminActor`, `AdminAuditEvent`, `AdminMutationResult` structs, tests serialization roundtrips | Root |
| `admin_mutation_blocklist.rs` | RUNTIME | Creates `BlockStore`, calls `block_ip_with_provenance`/`unblock_ip`, verifies mutation result semantics | Root |
| `failure_injection.rs` | RUNTIME | Spawns `tokio::spawn` tasks, tests supervisor shutdown reports, blocklist catchup, plugin guard failure isolation | Root |
| `manifest_authority_wiring.rs` | RUNTIME | Creates `PluginManifest`, `PluginInvocationGuard`, tests capability checking and `invoke_with_limits` | Root |
| `mesh_admin_edge_cases.rs` | RUNTIME | Constructs `AdminMutationResult`/`BlockMutationTarget`, tests serialization and status semantics | Root |
| `plugin_failure_does_not_poison_manager.rs` | RUNTIME | Creates `PluginInvocationGuard` instances, tests failure isolation and repeated timeout behavior | Root |

## Summary

| Classification | Count | Location |
|---------------|-------|----------|
| STATIC (Moved) | 14 | `tools/synvoid-repo-guards/tests/` |
| COMPLEX (Root) | 13 | Root `tests/` |
| RUNTIME (Root) | 6 | Root `tests/` |

## Moved Guards: Original → New Paths

All 14 moved guards were source/manifest inspection only, with no runtime dependencies. They share common patterns: reading `.rs` files via `std::fs::read_to_string` or `include_str!`, parsing `Cargo.toml` manifests, scanning markdown documentation, and using `regex` for pattern matching.

### `module_ownership.rs`

| Guard | Original Path | New Path | Why Moveable |
|-------|--------------|----------|--------------|
| `root_module_ledger_guard` | `tests/root_module_ledger_guard.rs` | `tools/synvoid-repo-guards/tests/module_ownership.rs` | Parses `src/lib.rs` and a markdown ledger; no runtime deps |
| `root_facade_boundary_guard` | `tests/root_facade_boundary_guard.rs` | `tools/synvoid-repo-guards/tests/module_ownership.rs` | Scans `crates/` for import patterns; no runtime deps |
| `root_dependency_ownership_guard` | `tests/root_dependency_ownership_guard.rs` | `tools/synvoid-repo-guards/tests/module_ownership.rs` | Parses `Cargo.toml` and a markdown ledger; no runtime deps |

### `composition_boundary.rs`

| Guard | Original Path | New Path | Why Moveable |
|-------|--------------|----------|--------------|
| `data_plane_composition_boundary_guard` | `tests/data_plane_composition_boundary_guard.rs` | `tools/synvoid-repo-guards/tests/composition_boundary.rs` | Scans request-path `.rs` files for forbidden imports; no runtime deps |
| `request_path_capability_boundary_guard` | `tests/request_path_capability_boundary_guard.rs` | `tools/synvoid-repo-guards/tests/composition_boundary.rs` | Scans request-path `.rs` files for control-plane imports; no runtime deps |
| `http_request_pipeline_boundary_guard` | `tests/http_request_pipeline_boundary_guard.rs` | `tools/synvoid-repo-guards/tests/composition_boundary.rs` | Scans HTTP handler `.rs` files for lifecycle imports; no runtime deps |
| `http3_waf_boundary_guard` | `tests/http3_waf_boundary_guard.rs` | `tools/synvoid-repo-guards/tests/composition_boundary.rs` | Scans `crates/synvoid-http3/` for concrete type imports; no runtime deps |

### `lifecycle_ownership.rs`

| Guard | Original Path | New Path | Why Moveable |
|-------|--------------|----------|--------------|
| `background_task_ownership_guard` | `tests/background_task_ownership_guard.rs` | `tools/synvoid-repo-guards/tests/lifecycle_ownership.rs` | Scans `src/` for spawn patterns; no runtime deps |
| `supervisor_task_ownership_guard` | `tests/supervisor_task_ownership_guard.rs` | `tools/synvoid-repo-guards/tests/lifecycle_ownership.rs` | Scans `src/supervisor/` for spawn patterns; no runtime deps |
| `unified_server_lifecycle_ownership_guard` | `tests/unified_server_lifecycle_ownership_guard.rs` | `tools/synvoid-repo-guards/tests/lifecycle_ownership.rs` | Scans `src/server/` and `src/plugin/` for `mem::forget`; no runtime deps |
| `unified_worker_composition_root_guard` | `tests/unified_worker_composition_root_guard.rs` | `tools/synvoid-repo-guards/tests/lifecycle_ownership.rs` | Reads `unified_server/mod.rs` line count; no runtime deps |
| `cli_command_dispatch_guard` | `tests/cli_command_dispatch_guard.rs` | `tools/synvoid-repo-guards/tests/lifecycle_ownership.rs` | Reads `src/main.rs` line count; no runtime deps |

### `docs_and_misc.rs`

| Guard | Original Path | New Path | Why Moveable |
|-------|--------------|----------|--------------|
| `docs_path_reference_guard` | `tests/docs_path_reference_guard.rs` | `tools/synvoid-repo-guards/tests/docs_and_misc.rs` | Scans markdown files for broken links; no runtime deps |
| `unsafe_native_sandbox_language_guard` | `tests/unsafe_native_sandbox_language_guard.rs` | `tools/synvoid-repo-guards/tests/docs_and_misc.rs` | Scans markdown docs for misleading phrases; no runtime deps |

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

One guard has an explicit feature gate:

- `worker_mesh_supervision_boundary_guard.rs` — requires `mesh`

The runtime guards (`admin_auth_boundary`, `admin_mutation_blocklist`, `mesh_admin_edge_cases`) depend on `synvoid_core`, `synvoid_block_store`, and `synvoid_config` crates but have no feature gates — they compile with default features.

## How to Run

### Static guards (moved to guard crate)

```bash
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
```

This runs all 14 STATIC guards in the `synvoid-repo-guards` crate using the CI profile (fast, no LTO).

### Complex and runtime guards (root tests/)

Run individual guards by name:

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

### All guards at once

```bash
cargo test --test abi_memory_boundary_guard --test admin_auth_boundary --test admin_mutation_blocklist --test admin_mutation_response_guard --test failure_injection --test manifest_authority_load_path_guard --test manifest_authority_wiring --test manual_enforcement_provenance_guard --test mesh_admin_edge_cases --test mesh_id_boundary_guard --test mesh_task_ownership_guard --test plugin_capability_boundary_guard --test plugin_failure_does_not_poison_manager --test plugin_lifecycle_guard --test plugin_signature_policy_guard --test security_observability_guard --test threat_intel_boundary_guard --test threat_intel_consumer_actionability_guard --test worker_mesh_supervision_boundary_guard --features mesh
```

## Migration Notes

**14 STATIC guards** were extracted to `tools/synvoid-repo-guards/` because they only:
- Read `.rs` source files via `std::fs::read_to_string` or `include_str!`
- Parse `Cargo.toml` manifests
- Scan markdown documentation
- Use `regex` for pattern matching
- Have zero runtime behavior
- Have no domain-specific type dependencies

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

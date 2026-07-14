#!/usr/bin/env bash
set -euo pipefail

# Architecture verification script
# Runs profile compatibility checks and guard tests.

echo "=== Formatting check ==="
cargo fmt --all -- --check

echo ""
echo "=== Profile matrix checks ==="
echo "--- default (all features) ---"
cargo check
echo "--- no-default-features ---"
cargo check --no-default-features
echo "--- mesh only ---"
cargo check --no-default-features --features mesh
echo "--- dns only ---"
cargo check --no-default-features --features dns
echo "--- mesh,dns ---"
cargo check --no-default-features --features mesh,dns

echo ""
echo "=== Guard test suite ==="
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
cargo test --test plugin_capability_boundary_guard
cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager
cargo test --test abi_memory_boundary_guard
cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test plugin_signature_policy_guard
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases
cargo test --test security_observability_guard
cargo test --test failure_injection
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test cli_command_dispatch_guard
cargo test --test manual_enforcement_provenance_guard
cargo test --test background_task_ownership_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test plugin_lifecycle_guard
cargo test --test unsafe_native_sandbox_language_guard
cargo test --test docs_path_reference_guard

echo ""
echo "=== Plugin runtime crate checks ==="
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime

echo ""
echo "=== All architecture checks passed ==="

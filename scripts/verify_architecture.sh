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
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test --test admin_auth_boundary
cargo test --test mesh_admin_edge_cases

echo ""
echo "=== All architecture checks passed ==="

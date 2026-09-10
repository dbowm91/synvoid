#!/usr/bin/env bash
set -euo pipefail

# Architecture verification script
# Runs profile compatibility checks and guard tests.
# This is a local-only tool; CI runs `cargo xtask verify` instead.

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
echo "=== Repo-guards crate ==="
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci

echo ""
echo "=== Guard test suite ==="
cargo test --test boundary_composition_guard
cargo test --test lifecycle_task_guard
cargo test --test plugin_guard
cargo test --test cli_admin_guard
cargo test --test security_guard
cargo test --test root_facade_boundary_guard
cargo test --test mesh_id_boundary_guard
cargo test --test admin_mutation_response_guard
cargo test --test admin_mutation_blocklist
cargo test -p synvoid-core --test admin_auth_boundary
cargo test -p synvoid-core --test mesh_admin_edge_cases
cargo test --test failure_injection
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test abi_memory_boundary_guard
cargo test --test root_test_ownership_guard
echo ""
echo "=== Track 3 ownership/enforcement guards (Phases 17-21) ==="
cargo test --test enforcement_decision_contract_guard
cargo test --test http_normalization_ownership_guard
cargo test --test waf_ownership_guard
cargo test --test static_file_manager_ownership_guard
cargo test --test facade_disposition_guard
cargo test --test admin_plugin_boundary_guard
echo ""
echo "=== Phase 24 closure suites ==="
cargo test --test track3_invariant_closure
cargo test --test http_differential_closure
cargo test --test track3_concurrency_closure
cargo test --test jail_isolation_guard
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns

echo ""
echo "=== Security regression (single-threaded) ==="
cargo test --test security_regression -- --test-threads=1

echo ""
echo "=== Plugin runtime crate checks ==="
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime

echo ""
echo "=== All architecture checks passed ==="

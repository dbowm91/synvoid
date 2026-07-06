#!/usr/bin/env bash
# DNS Stress and Resource Limit Tests - Workstream 7
# Non-timing stress tests that verify overload behavior is bounded.
#
# Usage:
#   ./scripts/dns/stress_tests.sh
#
# These tests are safe to run in CI (no timing sensitivity).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== DNS Stress & Resource Limit Tests ==="
echo ""

echo "--- Running stress resource limit tests ---"
cargo test -p synvoid-dns --test dns_stress_resource_limits -- --test-threads=1 2>&1

echo ""
echo "--- Running all DNS tests (regression check) ---"
cargo test -p synvoid-dns 2>&1

echo ""
echo "=== All stress tests passed ==="

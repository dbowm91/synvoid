#!/usr/bin/env bash
# DNS Conformance & Interop Test Suite
# Validates DNS protocol conformance and interoperability across authoritative,
# DNSSEC, transfer, update/notify, encrypted transport, and recursive resolver tests.
#
# Usage:
#   ./scripts/dns/conformance.sh [--release] [--test-threads=N]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RELEASE_FLAG=""
TEST_THREADS_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --release)
            RELEASE_FLAG="--release"
            ;;
        --test-threads=*)
            TEST_THREADS_FLAG="$arg"
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [--release] [--test-threads=N]"
            exit 1
            ;;
    esac
done

echo "=== DNS Conformance & Interop Test Suite ==="
echo ""

PASSED=0
FAILED=0

run_test() {
    local name="$1"
    local test_target="$2"

    echo "--- $name ---"
    if cargo test -p synvoid-dns $RELEASE_FLAG --test "$test_target" $TEST_THREADS_FLAG 2>&1; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $name"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

run_test "dns_interop_authoritative" "dns_interop_authoritative"
run_test "dns_interop_truncation" "dns_interop_truncation"
run_test "dns_interop_dnssec" "dns_interop_dnssec"
run_test "dns_interop_transfers" "dns_interop_transfers"
run_test "dns_interop_update_notify" "dns_interop_update_notify"
run_test "dns_interop_encrypted" "dns_interop_encrypted"
run_test "dns_interop_recursive" "dns_interop_recursive"

TOTAL=$((PASSED + FAILED))
echo "=== DNS Conformance & Interop Summary ==="
echo "Total:  $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo "FAILED"
    exit 1
fi

echo "=== All conformance tests passed ==="

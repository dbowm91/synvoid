#!/usr/bin/env bash
# DNS Internal Conformance & Optional External Interop Suite
#
# === Internal (required, always run) ===
# Runs the in-process Rust integration test suites under
# crates/synvoid-dns/tests/dns_interop_*. These call DnsServer::handle_query()
# directly and assert on wire bytes. They do NOT require network or external
# tools and are part of CI.
#
# === External (optional, local-only) ===
# When external tools (dig, kdig, delv, named-checkzone, ldns-verify-zone, curl)
# are available, additional live-wire smoke checks can be run against an
# in-memory DnsServer. These are NOT in CI — they require the operator's
# environment and a running DnsServer on a local port.
# Tools are detected; missing tools print SKIP and continue.
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

echo "=== DNS Internal Conformance & External Interop Suite ==="
echo ""

# ──────────────────────────────────────────────────────────────
# Internal conformance tests (required, always run in CI)
# ──────────────────────────────────────────────────────────────
echo "=== Internal Conformance (in-process, no external tools) ==="
echo ""

INTERNAL_PASSED=0
INTERNAL_FAILED=0

run_internal() {
    local name="$1"
    local test_target="$2"

    echo "--- $name ---"
    if cargo test -p synvoid-dns $RELEASE_FLAG --test "$test_target" $TEST_THREADS_FLAG 2>&1; then
        INTERNAL_PASSED=$((INTERNAL_PASSED + 1))
    else
        echo "FAILED: $name"
        INTERNAL_FAILED=$((INTERNAL_FAILED + 1))
    fi
    echo ""
}

run_internal "dns_interop_authoritative" "dns_interop_authoritative"
run_internal "dns_interop_truncation" "dns_interop_truncation"
run_internal "dns_interop_dnssec" "dns_interop_dnssec"
run_internal "dns_interop_transfers" "dns_interop_transfers"
run_internal "dns_interop_update_notify" "dns_interop_update_notify"
run_internal "dns_interop_encrypted" "dns_interop_encrypted"
run_internal "dns_interop_recursive" "dns_interop_recursive"

INTERNAL_TOTAL=$((INTERNAL_PASSED + INTERNAL_FAILED))

echo "=== Internal Summary ==="
echo "Total:  $INTERNAL_TOTAL"
echo "Passed: $INTERNAL_PASSED"
echo "Failed: $INTERNAL_FAILED"
echo ""

# ──────────────────────────────────────────────────────────────
# External interop checks (optional, local-only, not in CI)
# ──────────────────────────────────────────────────────────────
echo "=== External Interop (optional, requires local tools + DnsServer) ==="
echo ""

EXTERNAL_RUNNABLE=0
EXTERNAL_SKIPPED=0

declare -A TOOL_FOUND
for tool in dig kdig delv ldns-verify-zone named-checkzone curl; do
    if command -v "$tool" &>/dev/null; then
        TOOL_FOUND[$tool]=1
        echo "  [FOUND]  $tool"
    else
        TOOL_FOUND[$tool]=0
        echo "  [SKIP]   $tool (not installed)"
    fi
done
echo ""

# Each external check is a placeholder. Full live-wire tests require spawning
# an in-memory DnsServer on an ephemeral port, which is out of scope for this
# script. These markers document the intended coverage.

check_external() {
    local name="$1"
    local tool="$2"
    local description="$3"

    if [[ "${TOOL_FOUND[$tool]}" -eq 1 ]]; then
        echo "  [READY]  $name — $description"
        echo "           (requires running DnsServer on local port; not executed here)"
        EXTERNAL_RUNNABLE=$((EXTERNAL_RUNNABLE + 1))
    else
        echo "  [SKIP]   $name — $description (missing: $tool)"
        EXTERNAL_SKIPPED=$((EXTERNAL_SKIPPED + 1))
    fi
}

check_external "Authoritative A/AAAA query" "dig" \
    "dig +short @127.0.0.1 -p <port> example.com A"
check_external "DoT transport query" "kdig" \
    "kdig @127.0.0.1 -p <port> example.com A"
check_external "DNSSEC validation" "delv" \
    "delv @127.0.0.1 -p <port> example.com A +rtrace"
check_external "Zone file lint" "named-checkzone" \
    "named-checkzone example.com /path/to/zone.file"
check_external "DNSSEC zone signature verify" "ldns-verify-zone" \
    "ldns-verify-zone /path/to/signed.zone"
check_external "DoH query" "curl" \
    "curl -H 'accept: application/dns-message' https://127.0.0.1/dns-query"

echo ""
echo "=== External Summary ==="
echo "Runnable: $EXTERNAL_RUNNABLE (tool present, requires DnsServer to execute)"
echo "Skipped: $EXTERNAL_SKIPPED (tool not installed)"
echo ""

# ──────────────────────────────────────────────────────────────
# Overall summary
# ──────────────────────────────────────────────────────────────
echo "=== Overall Summary ==="
echo "Internal: $INTERNAL_PASSED/$INTERNAL_TOTAL passed"
if [[ "$INTERNAL_FAILED" -gt 0 ]]; then
    echo "FAILED — $INTERNAL_FAILED internal test(s) failed"
    exit 1
fi
echo "External: $EXTERNAL_RUNNABLE runnable, $EXTERNAL_SKIPPED skipped (not in CI)"
echo ""
echo "=== All internal conformance tests passed ==="

#!/usr/bin/env bash
# DNS Diagnostic Smoke Tests — quick live check of UDP, TCP, SOA, and DNSSEC
# queries against a running SynVoid DNS server.
#
# Usage:
#   ./scripts/dns_diagnostic_smoke.sh [HOST] [PORT] [DOT_PORT] [DOH_URL]
#
# Arguments:
#   HOST      DNS server IP to query          (default: 127.0.0.1)
#   PORT      DNS server port                 (default: 53)
#   DOT_PORT  DNS-over-TLS port               (default: 853)
#   DOH_URL   DNS-over-HTTPS endpoint         (default: https://<HOST>/dns-query)
set -euo pipefail

# --- Pre-flight checks ---
if ! command -v dig >/dev/null 2>&1; then
    echo "ERROR: dig is required for this script. Install bind-utils (RHEL/Fedora) or dnsutils (Debian/Ubuntu)." >&2
    exit 1
fi

HOST="${1:-127.0.0.1}"
PORT="${2:-53}"
DOT_PORT="${3:-853}"
DOH_URL="${4:-https://${HOST}/dns-query}"

if [ "${PORT}" -eq 53 ] && [ "${EUID}" -ne 0 ]; then
    echo "WARNING: port 53 typically requires root or CAP_NET_BIND_SERVICE." >&2
fi

FAILURES=0

echo "=== DNS Diagnostic Smoke Tests ==="
echo "Target: ${HOST}:${PORT}"
echo ""

echo -n "UDP A record query... "
if dig @"${HOST}" -p "${PORT}" example.com A +short +time=2 +tries=1 >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
    FAILURES=$((FAILURES + 1))
fi

echo -n "TCP A record query... "
if dig @"${HOST}" -p "${PORT}" example.com A +tcp +short +time=2 +tries=1 >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
    FAILURES=$((FAILURES + 1))
fi

echo -n "SOA record query... "
if dig @"${HOST}" -p "${PORT}" example.com SOA +short +time=2 +tries=1 >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
    FAILURES=$((FAILURES + 1))
fi

echo -n "DNSSEC query... "
if dig @"${HOST}" -p "${PORT}" example.com A +dnssec +short +time=2 +tries=1 >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
    FAILURES=$((FAILURES + 1))
fi

echo ""
echo "=== Results: $((4 - FAILURES))/4 passed ==="

if [ "${FAILURES}" -gt 0 ]; then
    echo "Some tests failed. Check DNS server logs for details."
    exit 1
else
    echo "All smoke tests passed."
    exit 0
fi

#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-53}"
DOT_PORT="${3:-853}"
DOH_URL="${4:-https://${HOST}/dns-query}"
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

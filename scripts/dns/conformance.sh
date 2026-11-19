#!/usr/bin/env bash
# DNS Internal Conformance & Optional External Interop Suite
#
# === Internal (required, always run) ===
# Runs the in-process Rust integration test suites under
# crates/synvoid-dns/tests/, including the phase 10 DNS serving-correctness
# suites. They either call DnsServer::handle_query() directly or start a
# loopback listener in-process. They do NOT require a network service or
# external tools and are part of CI.
#
# The phase 10 suites are:
#   dns_wire_contract, dns_envelope_contract, dns_admission_contract,
#   dnssec_signature_contract, dnssec_denial_contract, dns_recursive_contract,
#   dns_control_plane_contract, dns_authoritative_lookup,
#   dns_external_interop (skips cleanly when dig/delv are absent), and
#   dns_mesh_trust_contract (requires --features mesh).
# The root-package `dns_truthfulness_contract` lane runs with --features dns.
#
# === External (optional, local-only) ===
# Set DNS_CONFORMANCE_TARGET=host:port to run real dig/delv/curl checks
# against an already-running server that is authoritative for example.com.
# Every command is printed before it runs; a missing tool is [SKIP], never a
# failure. The script's exit code depends only on the internal lanes.
#
# Optional external knobs:
#   DNS_CONFORMANCE_TRUST_ANCHOR=/path/anchor.conf
#       Passed as `delv -a <file> +root=example.com`; a validation failure is
#       then a real [FAIL]. Without it, delv validation is [INCONCLUSIVE].
#   DNS_CONFORMANCE_DOH_URL=https://host:port/dns-query
#       Override the curl target (default: https://$DNS_CONFORMANCE_TARGET/dns-query).
#
# Tools that are absent on this host (kdig, ldns-verify-zone, named-checkzone)
# are reported as [SKIP] in the inventory below. They never change the exit
# code, and they are not counted as validation evidence.
#
# Usage:
#   ./scripts/dns/conformance.sh [--release] [--test-threads=N]
#   DNS_CONFORMANCE_TARGET=127.0.0.1:5353 ./scripts/dns/conformance.sh
#   DNS_CONFORMANCE_TARGET=127.0.0.1:5353 \
#     DNS_CONFORMANCE_TRUST_ANCHOR=/tmp/anchor.conf \
#     ./scripts/dns/conformance.sh

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
            # Harness argument, not a cargo argument: it must follow `--`.
            TEST_THREADS_FLAG="-- $arg"
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

# `features` is optional. Bash 3.2 has no associative arrays; a string flag
# keeps the call sites readable and stays compatible with macOS's bash.
run_internal() {
    local name="$1"
    local test_target="$2"
    local features="${3:-}"
    local feature_flag=""

    if [[ -n "$features" ]]; then
        feature_flag="--features $features"
    fi

    echo "--- $name ---"
    if cargo test -p synvoid-dns $RELEASE_FLAG $feature_flag --test "$test_target" $TEST_THREADS_FLAG 2>&1; then
        INTERNAL_PASSED=$((INTERNAL_PASSED + 1))
    else
        echo "FAILED: $name"
        INTERNAL_FAILED=$((INTERNAL_FAILED + 1))
    fi
    echo ""
}

# Same accounting, for a lane that lives in a different package.
run_internal_pkg() {
    local pkg="$1"
    local name="$2"
    local test_target="$3"
    local features="${4:-}"
    local feature_flag=""

    if [[ -n "$features" ]]; then
        feature_flag="--features $features"
    fi

    echo "--- $name ($pkg) ---"
    if cargo test -p "$pkg" $RELEASE_FLAG $feature_flag --test "$test_target" $TEST_THREADS_FLAG 2>&1; then
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
# NOTE: the former `dns_interop_encrypted` lane was removed in Phase 128.
# Despite the `dns_interop_` prefix it only ever asserted persisted
# `DnsDotConfig`/`DnsDohConfig`/`DnsDoqConfig` JSON round-trips — no wire
# bytes, no `handle_query()` — so it moved to the crate that owns the
# schema as `encrypted_transport_schema` below. No protocol coverage was
# lost; the name was simply misleading. The actual encrypted-transport
# runtime coverage is `synvoid-dns/tests/encrypted_transport.rs`.
run_internal "dns_interop_recursive" "dns_interop_recursive"
# Phase 45: persistent TCP/DoT contract, DoQ bind fidelity (fail-closed config
# contract).
run_internal "dns_phase45_contract" "dns_phase45_contract"
# Phase 128 moved the two persisted-schema lanes out of `synvoid-dns` (which no
# longer depends on `synvoid-config`) into the crate that owns the schema.
# They are still part of DNS qualification, so they run here from their new
# home rather than being dropped from the suite.
run_internal_pkg "synvoid-config" "example_configs_parse" "example_configs_parse"
run_internal_pkg "synvoid-config" "encrypted_transport_schema" "encrypted_transport_schema"
# Phase 131: the bind-determinism evidence that replaced the `free_port()`
# TOCTOU reservation. It runs here because it is what makes the listener
# lanes above trustworthy, so it belongs in the same lane as the thing it
# protects rather than only in the crate suite.
run_internal "bind_determinism" "bind_determinism"

# ──────────────────────────────────────────────────────────────
# Phase 10 DNS serving-correctness suites
# ──────────────────────────────────────────────────────────────
# These are the campaign's evidence lanes. Keep them in lockstep with the
# suite list in plans/dns_serving_correctness_phase_10_verification_and_release_gate.md
# and with `verify_steps()`; a lane that exists in only one place is invisible.
run_internal "dns_wire_contract" "dns_wire_contract"
run_internal "dns_envelope_contract" "dns_envelope_contract"
run_internal "dns_admission_contract" "dns_admission_contract"
run_internal "dnssec_signature_contract" "dnssec_signature_contract"
run_internal "dnssec_denial_contract" "dnssec_denial_contract"
run_internal "dns_recursive_contract" "dns_recursive_contract"
run_internal "dns_control_plane_contract" "dns_control_plane_contract"
run_internal "dns_authoritative_lookup" "dns_authoritative_lookup"
# Starts a real listener and invokes dig/delv. Missing tools are skipped inside
# the test, so this lane is safe on a host without BIND installed.
run_internal "dns_external_interop" "dns_external_interop"
# `dns_mesh_trust_contract` is `#![cfg(feature = "mesh")]`; without the feature
# the target compiles but executes zero tests, which is a false green.
run_internal "dns_mesh_trust_contract" "dns_mesh_trust_contract" "mesh"
# The root-package truthfulness suite declares `required-features = ["dns"]`;
# pass the feature so a plain conformance run does not silently skip it.
run_internal_pkg "synvoid" "dns_truthfulness_contract" "dns_truthfulness_contract" "dns"

INTERNAL_TOTAL=$((INTERNAL_PASSED + INTERNAL_FAILED))

echo "=== Internal Summary ==="
echo "Total:  $INTERNAL_TOTAL"
echo "Passed: $INTERNAL_PASSED"
echo "Failed: $INTERNAL_FAILED"
echo ""

# ──────────────────────────────────────────────────────────────
# External interop checks (optional, local-only, not in CI)
# ──────────────────────────────────────────────────────────────
echo "=== External Interop (optional; set DNS_CONFORMANCE_TARGET=host:port) ==="
echo ""

# Tool inventory first, so an operator can see why a lane is skipped. The
# target-driven lanes below run dig/delv/curl; the other tools are reported
# for compatibility with the pre-phase-10 script but are not silently counted
# as evidence.
for tool in dig delv curl kdig ldns-verify-zone named-checkzone; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  [FOUND]  $tool"
    else
        echo "  [SKIP]   $tool (not installed)"
    fi
done
echo ""

TARGET="${DNS_CONFORMANCE_TARGET:-}"
TARGET_TRUST_ANCHOR="${DNS_CONFORMANCE_TRUST_ANCHOR:-}"
DOH_URL="${DNS_CONFORMANCE_DOH_URL:-}"

EXTERNAL_PASS=0
EXTERNAL_FAIL=0
EXTERNAL_SKIP=0
EXTERNAL_INCONCLUSIVE=0

# Bound a tool that can stall. `timeout` is coreutils; when it is absent the
# checks still run, just without the outer bound (curl also has --max-time).
EXTERNAL_TIMEOUT=""
if command -v timeout >/dev/null 2>&1; then
    EXTERNAL_TIMEOUT="timeout 10"
fi

if [[ -n "$TARGET" ]]; then
    TARGET_HOST="${TARGET%:*}"
    TARGET_PORT="${TARGET##*:}"
    if [[ -z "$TARGET_HOST" || -z "$TARGET_PORT" || "$TARGET_HOST" == "$TARGET" ]]; then
        echo "  [FAIL]   DNS_CONFORMANCE_TARGET must be host:port (got '$TARGET')"
        EXTERNAL_FAIL=$((EXTERNAL_FAIL + 1))
        TARGET=""
        TARGET_HOST=""
        TARGET_PORT=""
    fi
else
    TARGET_HOST=""
    TARGET_PORT=""
fi

if [[ -z "$TARGET" ]]; then
    DISPLAY_HOST="<host>"
    DISPLAY_PORT="<port>"
else
    DISPLAY_HOST="$TARGET_HOST"
    DISPLAY_PORT="$TARGET_PORT"
fi

external_skip() {
    local label="$1"
    local display="$2"
    local reason="$3"

    echo "  [SKIP]   $label"
    echo "           reason: $reason"
    echo "           command: $display"
    EXTERNAL_SKIP=$((EXTERNAL_SKIP + 1))
}

external_pass() {
    echo "  [PASS]   $1"
    EXTERNAL_PASS=$((EXTERNAL_PASS + 1))
}

external_fail() {
    echo "  [FAIL]   $1"
    EXTERNAL_FAIL=$((EXTERNAL_FAIL + 1))
}

external_tool_ready() {
    local tool="$1"
    local label="$2"
    local display="$3"

    if [[ -z "$TARGET" ]]; then
        external_skip "$label" "$display" "DNS_CONFORMANCE_TARGET is not set"
        return 1
    fi
    if ! command -v "$tool" >/dev/null 2>&1; then
        external_skip "$label" "$display" "$tool not installed"
        return 1
    fi
    return 0
}

# Run one external command. EXTERNAL_STATUS / EXTERNAL_OUTPUT are the result.
# Returns 1 when the lane was skipped (nothing ran), 0 when a command ran.
external_run() {
    local label="$1"
    local display="$2"
    local tool="$3"
    shift 3

    if ! external_tool_ready "$tool" "$label" "$display"; then
        EXTERNAL_STATUS=127
        EXTERNAL_OUTPUT=""
        return 1
    fi

    echo "  [RUN]    $label"
    echo "           command: $display"

    if EXTERNAL_OUTPUT="$($EXTERNAL_TIMEOUT "$tool" "$@" 2>&1)"; then
        EXTERNAL_STATUS=0
    else
        EXTERNAL_STATUS=$?
    fi

    if [[ -n "$EXTERNAL_OUTPUT" ]]; then
        printf '%s\n' "$EXTERNAL_OUTPUT" | sed 's/^/           | /'
    fi
    return 0
}

# Modes: nonempty, nxdomain, noerror, dnssec, budget.
dig_check() {
    local label="$1"
    local mode="$2"
    local display="$3"
    shift 3

    if ! external_run "$label" "$display" dig "$@"; then
        return 0
    fi

    local output="$EXTERNAL_OUTPUT"
    local status="$EXTERNAL_STATUS"

    if [[ "$status" -ne 0 ]]; then
        external_fail "$label (dig exit $status)"
        return 0
    fi

    case "$mode" in
        nonempty)
            if [[ -n "$(printf '%s' "$output" | tr -d '[:space:]')" ]]; then
                external_pass "$label"
            else
                external_fail "$label (empty +short output)"
            fi
            ;;
        nxdomain)
            if [[ "$output" == *"status: NXDOMAIN"* ]]; then
                external_pass "$label (status NXDOMAIN)"
            else
                external_fail "$label (expected status NXDOMAIN)"
            fi
            ;;
        noerror)
            if [[ "$output" == *"status: NOERROR"* ]]; then
                external_pass "$label (status NOERROR)"
            else
                external_fail "$label (expected status NOERROR)"
            fi
            ;;
        dnssec)
            if [[ "$output" == *"RRSIG"* ]]; then
                external_pass "$label (RRSIG present; signed answer)"
            elif [[ "$output" == *"status: NOERROR"* ]]; then
                external_pass "$label (NOERROR; unsigned answer, no RRSIG)"
            else
                external_fail "$label (no NOERROR answer)"
            fi
            ;;
        budget)
            local size
            size="$(printf '%s\n' "$output" | sed -n 's/.*MSG SIZE.*rcvd: *\([0-9][0-9]*\).*/\1/p' | tail -n 1)"
            if [[ -z "$size" ]]; then
                external_fail "$label (dig did not report MSG SIZE)"
            elif [[ "$size" -le 512 ]]; then
                if [[ "$output" == *" tc"* ]]; then
                    external_pass "$label (MSG SIZE $size, TC=1)"
                else
                    external_pass "$label (MSG SIZE $size, TC=0)"
                fi
            else
                external_fail "$label (MSG SIZE $size exceeds 512)"
            fi
            ;;
        *)
            external_fail "$label (unknown check mode '$mode')"
            ;;
    esac
}

# Modes: answer (must return a record), validate (may be inconclusive without
# an anchor), unsupported (recorded, never a claimed result).
delv_check() {
    local label="$1"
    local mode="$2"
    local display="$3"
    shift 3

    if ! external_run "$label" "$display" delv "$@"; then
        return 0
    fi

    local output="$EXTERNAL_OUTPUT"
    local status="$EXTERNAL_STATUS"

    case "$mode" in
        answer)
            if [[ "$status" -eq 0 && "$output" != *"resolution failed"* && "$output" != *"unable to validate"* && "$output" != *"no valid trust anchor"* ]]; then
                external_pass "$label"
            else
                external_fail "$label (delv did not answer)"
            fi
            ;;
        validate)
            if [[ "$output" == *"fully validated"* ]]; then
                external_pass "$label (fully validated)"
            elif [[ -n "$TARGET_TRUST_ANCHOR" ]]; then
                external_fail "$label (trust anchor supplied but delv did not validate)"
            else
                echo "  [INCONCLUSIVE] $label — delv needs a trust anchor; set DNS_CONFORMANCE_TRUST_ANCHOR"
                EXTERNAL_INCONCLUSIVE=$((EXTERNAL_INCONCLUSIVE + 1))
            fi
            ;;
        unsupported)
            echo "  [INCONCLUSIVE] $label — +cd is a dig option, not a delv 9.18 validation-off switch (use -i)"
            EXTERNAL_INCONCLUSIVE=$((EXTERNAL_INCONCLUSIVE + 1))
            ;;
        *)
            external_fail "$label (unknown check mode '$mode')"
            ;;
    esac
}

# DoH GET with a precomputed wire query (www.example.com A). Base64url is the
# RFC 8484 encoding; no padding.
curl_check() {
    local label="DoH query over HTTPS"
    local query="AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    local url="$DOH_URL"

    if [[ -z "$url" ]]; then
        if [[ -n "$TARGET" ]]; then
            url="https://$TARGET/dns-query"
        else
            url="https://<host>:<port>/dns-query"
        fi
    fi

    local display
    display="curl -sk --max-time 10 -o /dev/null -w '%{http_code} %{size_download}' '$url?dns=$query'"

    if ! external_run "$label" "$display" curl -sk --max-time 10 -o /dev/null -w '%{http_code} %{size_download}' "$url?dns=$query"; then
        return 0
    fi

    local code size
    code="${EXTERNAL_OUTPUT%% *}"
    size="${EXTERNAL_OUTPUT##* }"

    if [[ "$EXTERNAL_STATUS" -eq 0 && "$code" == "200" && "$size" -gt 0 ]]; then
        external_pass "$label (HTTP 200, $size bytes)"
    else
        external_fail "$label (HTTP $code, ${size} bytes, exit $EXTERNAL_STATUS)"
    fi
}

# ── dig ────────────────────────────────────────────────────────
dig_check "dig +short A (www.example.com)" nonempty \
    "dig +short @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
    +short "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A

dig_check "dig +dnssec A (RRSIG when signed)" dnssec \
    "dig @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A +dnssec" \
    "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A +dnssec

dig_check "dig NXDOMAIN (missing.deep.example.com)" nxdomain \
    "dig @$DISPLAY_HOST -p $DISPLAY_PORT missing.deep.example.com A" \
    "@$TARGET_HOST" -p "$TARGET_PORT" missing.deep.example.com A

dig_check "dig +bufsize=512 (UDP budget)" budget \
    "dig +bufsize=512 @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
    +bufsize=512 "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A

dig_check "dig +tcp (TCP transport)" noerror \
    "dig +tcp @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
    +tcp "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A

# ── delv ───────────────────────────────────────────────────────
# `-i` is delv's documented "disable validation" switch; `+cd` belongs to dig
# and is accepted syntactically by delv 9.18 without disabling checking.
delv_check "delv -i (validation off, must answer)" answer \
    "delv -i @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
    -i "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A

delv_check "delv +cd (unsupported by delv 9.18)" unsupported \
    "delv +cd @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
    +cd "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A

if [[ -n "$TARGET_TRUST_ANCHOR" ]]; then
    delv_check "delv -a (trust anchor validation)" validate \
        "delv -a $TARGET_TRUST_ANCHOR +root=example.com @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
        -a "$TARGET_TRUST_ANCHOR" +root=example.com "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A
else
    delv_check "delv (no trust anchor configured)" validate \
        "delv @$DISPLAY_HOST -p $DISPLAY_PORT www.example.com A" \
        "@$TARGET_HOST" -p "$TARGET_PORT" www.example.com A
fi

# ── curl (DoH) ─────────────────────────────────────────────────
curl_check

echo ""
echo "=== External Summary ==="
if [[ -z "$TARGET" ]]; then
    echo "Target: not set (DNS_CONFORMANCE_TARGET=host:port enables these checks)"
else
    echo "Target: $TARGET"
fi
echo "Passed: $EXTERNAL_PASS"
echo "Failed: $EXTERNAL_FAIL (reported only; the exit code is internal-only)"
echo "Inconclusive: $EXTERNAL_INCONCLUSIVE"
echo "Skipped: $EXTERNAL_SKIP"
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
if [[ "$EXTERNAL_FAIL" -gt 0 ]]; then
    echo "External: $EXTERNAL_FAIL check(s) reported FAIL; they do not change the exit code"
else
    echo "External: no failures reported"
fi
echo ""
echo "=== All internal conformance tests passed ==="

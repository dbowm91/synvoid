#!/usr/bin/env bash
# test-affected.sh — Run tests for packages and root tests affected by changes.
#
# Uses scripts/ci/select-affected.py to determine what's affected, then
# executes cargo nextest and cargo test accordingly.
#
# Usage:
#   ./scripts/test-affected.sh [BASE_REF] [OPTIONS]
#
# Arguments:
#   BASE_REF       Git ref to diff against (default: origin/main)
#
# Options:
#   --full         Force full workspace validation (ignore selective detection)
#   --dry-run      Print what would be tested, then exit
#   --json         Machine-readable JSON output
#   --verbose      Detailed output for each test command
#
# Examples:
#   ./scripts/test-affected.sh                    # Affected packages vs origin/main
#   ./scripts/test-affected.sh HEAD~5             # Affected packages vs 5 commits ago
#   ./scripts/test-affected.sh --dry-run          # Preview what would be tested
#   ./scripts/test-affected.sh --full --json      # Full validation, JSON output
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SELECTOR="${SCRIPT_DIR}/ci/select-affected.py"

# ── Defaults ──────────────────────────────────────────────────────────────────
BASE_REF="origin/main"
FULL_MODE=false
DRY_RUN=false
JSON_MODE=false
VERBOSE=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)
            FULL_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --json)
            JSON_MODE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            sed -n '2,/^set -euo/p' "$0" | head -n -1 | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
        *)
            BASE_REF="$1"
            shift
            ;;
    esac
done

# ── Prerequisite checks ──────────────────────────────────────────────────────
check_prereqs() {
    local missing=()
    if ! command -v git &>/dev/null; then
        missing+=("git")
    fi
    if ! command -v cargo &>/dev/null; then
        missing+=("cargo")
    fi
    if ! command -v python3 &>/dev/null; then
        missing+=("python3")
    fi
    if ! command -v jq &>/dev/null && ! command -v python3 &>/dev/null; then
        missing+=("jq or python3 (for JSON parsing)")
    fi
    if [[ ! -f "${SELECTOR}" ]]; then
        echo "ERROR: Selector script not found: ${SELECTOR}" >&2
        exit 1
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing required tools: ${missing[*]}" >&2
        exit 1
    fi
}

# ── JSON parsing helpers ──────────────────────────────────────────────────────
# Uses jq if available, falls back to python3

# Get a string value from JSON
json_get() {
    local json="$1"
    local path="$2"
    if command -v jq &>/dev/null; then
        echo "${json}" | jq -r "${path}"
    else
        echo "${json}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
keys = '''${path}'''.strip('.').split('.')
for k in keys:
    if isinstance(data, dict):
        data = data.get(k, '')
    elif isinstance(data, list):
        try:
            data = data[int(k)]
        except (ValueError, IndexError):
            data = ''
    else:
        data = ''
        break
if isinstance(data, bool):
    print('true' if data else 'false')
elif data is None:
    print('')
else:
    print(data)
"
    fi
}

# Get length of a JSON array
json_len() {
    local json="$1"
    local path="$2"
    if command -v jq &>/dev/null; then
        echo "${json}" | jq "${path} | length"
    else
        echo "${json}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
keys = '''${path}'''.strip('.').split('.')
for k in keys:
    if isinstance(data, dict):
        data = data.get(k, [])
    elif isinstance(data, list):
        try:
            data = data[int(k)]
        except (ValueError, IndexError):
            data = []
    else:
        data = []
        break
print(len(data) if isinstance(data, list) else 0)
"
    fi
}

# Get all items from a JSON array (one per line)
json_each() {
    local json="$1"
    local path="$2"
    if command -v jq &>/dev/null; then
        echo "${json}" | jq -r "${path}[]"
    else
        echo "${json}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
keys = '''${path}'''.strip('.').split('.')
for k in keys:
    if isinstance(data, dict):
        data = data.get(k, [])
    elif isinstance(data, list):
        try:
            data = data[int(k)]
        except (ValueError, IndexError):
            data = []
    else:
        data = []
        break
if isinstance(data, list):
    for item in data:
        print(item)
"
    fi
}

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ "${JSON_MODE}" == "false" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    DIM=''
    NC=''
fi

# ── Timing ────────────────────────────────────────────────────────────────────
SECONDS=0
START_TIME=$(date +%s%N 2>/dev/null || echo "0")

timer_start() {
    date +%s%N 2>/dev/null || echo "0"
}

timer_elapsed_ms() {
    local start="$1"
    local now
    now=$(date +%s%N 2>/dev/null || echo "0")
    if [[ "${start}" == "0" ]] || [[ "${now}" == "0" ]]; then
        echo "0"
    else
        echo $(( (now - start) / 1000000 ))
    fi
}

format_duration() {
    local ms="$1"
    local secs=$((ms / 1000))
    local mins=$((secs / 60))
    secs=$((secs % 60))
    if [[ ${mins} -gt 0 ]]; then
        printf "%dm%ds" "${mins}" "${secs}"
    else
        printf "%d.%ds" "${secs}" "$(( (ms % 1000) / 100 ))"
    fi
}

# ── State ─────────────────────────────────────────────────────────────────────
TOTAL_PACKAGES=0
TOTAL_ROOT_TESTS=0
PASSED=0
FAILED=0
FAILED_ITEMS=()
ALL_RUNS=()

# ── Output helpers ────────────────────────────────────────────────────────────
log() {
    if [[ "${JSON_MODE}" == "false" ]]; then
        echo -e "$@"
    fi
}

log_bold() {
    log "${BOLD}$@${NC}"
}

log_dim() {
    log "${DIM}$@${NC}"
}

log_ok() {
    log "${GREEN}✓${NC} $@"
}

log_fail() {
    log "${RED}✗${NC} $@"
}

log_info() {
    log "${BLUE}→${NC} $@"
}

log_skip() {
    log "${YELLOW}⊘${NC} $@"
}

# ── Test runners ──────────────────────────────────────────────────────────────

# Run a workspace package with nextest. Returns elapsed time in ms.
run_package_test() {
    local pkg_name="$1"
    local t_start
    t_start=$(timer_start)

    log_info "cargo nextest run -p ${pkg_name} --cargo-profile ci --profile ci"

    local run_log
    if [[ "${VERBOSE}" == "true" ]]; then
        if cargo nextest run -p "${pkg_name}" --cargo-profile ci --profile ci; then
            PASSED=$((PASSED + 1))
            log_ok "PASS: ${pkg_name}"
        else
            FAILED=$((FAILED + 1))
            FAILED_ITEMS+=("pkg:${pkg_name}")
            log_fail "FAIL: ${pkg_name}"
        fi
    else
        if run_log=$(cargo nextest run -p "${pkg_name}" --cargo-profile ci --profile ci 2>&1); then
            PASSED=$((PASSED + 1))
            log_ok "PASS: ${pkg_name}"
        else
            FAILED=$((FAILED + 1))
            FAILED_ITEMS+=("pkg:${pkg_name}")
            log_fail "FAIL: ${pkg_name}"
            echo "${run_log}" | tail -20 | while IFS= read -r line; do
                log_dim "    ${line}"
            done
        fi
    fi

    timer_elapsed_ms "${t_start}"
}

# Run a root guard test. Returns elapsed time in ms.
run_root_test() {
    local test_name="$1"
    local t_start
    t_start=$(timer_start)

    log_info "cargo test --test ${test_name}"

    local run_log
    if [[ "${VERBOSE}" == "true" ]]; then
        if cargo test --test "${test_name}"; then
            PASSED=$((PASSED + 1))
            log_ok "PASS: ${test_name}"
        else
            FAILED=$((FAILED + 1))
            FAILED_ITEMS+=("test:${test_name}")
            log_fail "FAIL: ${test_name}"
        fi
    else
        if run_log=$(cargo test --test "${test_name}" 2>&1); then
            PASSED=$((PASSED + 1))
            log_ok "PASS: ${test_name}"
        else
            FAILED=$((FAILED + 1))
            FAILED_ITEMS+=("test:${test_name}")
            log_fail "FAIL: ${test_name}"
            echo "${run_log}" | tail -20 | while IFS= read -r line; do
                log_dim "    ${line}"
            done
        fi
    fi

    timer_elapsed_ms "${t_start}"
}

# ── JSON summary ──────────────────────────────────────────────────────────────
emit_json_summary() {
    local total_time_ms
    total_time_ms=$(timer_elapsed_ms "${START_TIME}")

    local failed_pkgs_json="[]"
    local failed_tests_json="[]"

    # Separate packages and tests from FAILED_ITEMS
    local fp_items=()
    local ft_items=()
    for item in "${FAILED_ITEMS[@]}"; do
        if [[ "${item}" == pkg:* ]]; then
            fp_items+=("${item#pkg:}")
        elif [[ "${item}" == test:* ]]; then
            ft_items+=("${item#test:}")
        fi
    done

    if [[ ${#fp_items[@]} -gt 0 ]]; then
        failed_pkgs_json=$(printf '%s\n' "${fp_items[@]}" | python3 -c "
import sys, json
items = [line.strip() for line in sys.stdin if line.strip()]
print(json.dumps(items))
")
    fi

    if [[ ${#ft_items[@]} -gt 0 ]]; then
        failed_tests_json=$(printf '%s\n' "${ft_items[@]}" | python3 -c "
import sys, json
items = [line.strip() for line in sys.stdin if line.strip()]
print(json.dumps(items))
")
    fi

    python3 -c "
import json
summary = {
    'summary': {
        'passed': ${PASSED},
        'failed': ${FAILED},
        'total_packages': ${TOTAL_PACKAGES},
        'total_root_tests': ${TOTAL_ROOT_TESTS},
        'total_time_ms': ${total_time_ms},
        'failed_packages': ${failed_pkgs_json},
        'failed_tests': ${failed_tests_json},
    }
}
print(json.dumps(summary, indent=2))
" 2>/dev/null || echo '{"summary": {"passed": 0, "failed": 0, "error": "json generation failed"}}'
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_prereqs

    cd "${REPO_ROOT}"

    # Validate base ref
    if ! git rev-parse --verify "${BASE_REF}" &>/dev/null; then
        echo "ERROR: Base ref '${BASE_REF}' is not a valid git ref." >&2
        echo "Available branches:" >&2
        git branch -a 2>/dev/null | head -10 >&2
        exit 1
    fi

    local head_ref
    head_ref=$(git rev-parse HEAD)

    log_bold "═══════════════════════════════════════════════════════════"
    log_bold "  synvoid test-affected"
    log_bold "═══════════════════════════════════════════════════════════"
    log ""
    log "  Base:  ${DIM}${BASE_REF}${NC} ($(git rev-parse --short "${BASE_REF}" 2>/dev/null || echo "?"))"
    log "  Head:  ${DIM}${head_ref}${NC} ($(git rev-parse --short HEAD 2>/dev/null || echo "?"))"
    log ""

    # Run the selector
    local selector_args=("--base" "${BASE_REF}" "--head" "HEAD" "--format" "json")
    if [[ "${FULL_MODE}" == "true" ]]; then
        selector_args+=("--full")
    fi
    if [[ "${VERBOSE}" == "true" ]]; then
        selector_args+=("--verbose")
    fi

    local selector_output
    if ! selector_output=$(python3 "${SELECTOR}" "${selector_args[@]}" 2>/dev/null); then
        echo "ERROR: Selector script failed." >&2
        exit 1
    fi

    # Parse selector output
    # Schema: { mode, reason, changed_packages, reverse_dependents, root_tests, feature_classes, full_fallback, fallback_reasons }
    local mode
    mode=$(json_get "${selector_output}" ".mode")
    local reason
    reason=$(json_get "${selector_output}" ".reason")

    # Combine changed_packages + reverse_dependents into all packages
    local all_packages
    all_packages=$(echo "${selector_output}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
pkgs = data.get('changed_packages', []) + data.get('reverse_dependents', [])
for p in sorted(set(pkgs)):
    print(p)
")
    local pkg_count
    pkg_count=$(echo "${all_packages}" | { grep -c . || true; } | tr -d '[:space:]')
    [[ -z "${pkg_count}" ]] && pkg_count=0

    local root_tests
    root_tests=$(json_each "${selector_output}" ".root_tests")
    local test_count
    test_count=$(echo "${root_tests}" | { grep -c . || true; } | tr -d '[:space:]')
    [[ -z "${test_count}" ]] && test_count=0

    local feature_classes
    feature_classes=$(json_each "${selector_output}" ".feature_classes")
    local fc_count
    fc_count=$(echo "${feature_classes}" | { grep -c . || true; } | tr -d '[:space:]')
    [[ -z "${fc_count}" ]] && fc_count=0

    local full_fallback
    full_fallback=$(json_get "${selector_output}" ".full_fallback")

    if [[ "${JSON_MODE}" == "true" ]]; then
        log_info "Mode: ${mode}, Reason: ${reason}"
        log_info "Packages: ${pkg_count}, Root tests: ${test_count}"
    else
        log_bold "── Selection ──────────────────────────────────────────────"
        log "  Mode:   ${BOLD}${mode}${NC}"
        log "  Reason: ${reason}"
        log "  Packages:  ${BOLD}${pkg_count}${NC} (direct + transitive dependents)"
        log "  Root tests: ${BOLD}${test_count}${NC}"
        if [[ "${full_fallback}" == "true" ]]; then
            log "  ${YELLOW}Full fallback: YES${NC}"
        fi
        log ""

        # Print package list
        if [[ "${pkg_count}" -gt 0 ]]; then
            log_bold "── Packages ───────────────────────────────────────────────"
            local idx=1
            while IFS= read -r pkg; do
                [[ -z "${pkg}" ]] && continue
                log "  ${DIM}${idx}.${NC} ${pkg}"
                idx=$((idx + 1))
            done <<< "${all_packages}"
            log ""
        fi

        # Print root test list
        if [[ "${test_count}" -gt 0 ]]; then
            log_bold "── Root tests ─────────────────────────────────────────────"
            local idx=1
            while IFS= read -r test; do
                [[ -z "${test}" ]] && continue
                log "  ${DIM}${idx}.${NC} ${test}"
                idx=$((idx + 1))
            done <<< "${root_tests}"
            log ""
        fi

        # Print feature classes
        if [[ "${fc_count}" -gt 0 ]]; then
            log_bold "── Feature classes ────────────────────────────────────────"
            while IFS= read -r fc; do
                [[ -z "${fc}" ]] && continue
                log "  ${fc}"
            done <<< "${feature_classes}"
            log ""
        fi
    fi

    # Dry run: print and exit
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_skip "Dry run — no tests executed."
        if [[ "${JSON_MODE}" == "true" ]]; then
            python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
print(json.dumps({
    'dry_run': True,
    'mode': data.get('mode', ''),
    'reason': data.get('reason', ''),
    'packages': len(data.get('changed_packages', [])) + len(data.get('reverse_dependents', [])),
    'root_tests': len(data.get('root_tests', [])),
    'feature_classes': len(data.get('feature_classes', []))
}, indent=2))
" <<< "${selector_output}" 2>/dev/null || echo '{"dry_run": true}'
        fi
        exit 0
    fi

    # Nothing to test
    if [[ "${pkg_count}" -eq 0 ]] && [[ "${test_count}" -eq 0 ]]; then
        log_ok "Nothing to test."
        exit 0
    fi

    log_bold "── Running tests ──────────────────────────────────────────"
    log ""

    # Run package tests
    while IFS= read -r pkg; do
        [[ -z "${pkg}" ]] && continue
        TOTAL_PACKAGES=$((TOTAL_PACKAGES + 1))
        run_package_test "${pkg}"
    done <<< "${all_packages}"

    # Run root tests
    while IFS= read -r test; do
        [[ -z "${test}" ]] && continue
        TOTAL_ROOT_TESTS=$((TOTAL_ROOT_TESTS + 1))
        run_root_test "${test}"
    done <<< "${root_tests}"

    # Feature class runs — for classes beyond default, run affected packages with extra features
    local needs_extra=false
    while IFS= read -r fc; do
        [[ -z "${fc}" ]] && continue
        [[ "${fc}" == "default" ]] && continue
        needs_extra=true
        break
    done <<< "${feature_classes}"

    if [[ "${needs_extra}" == "true" ]]; then
        log ""
        log_bold "── Feature-class additional runs ──────────────────────────"
        while IFS= read -r fc; do
            [[ -z "${fc}" ]] && continue
            [[ "${fc}" == "default" ]] && continue

            # Determine packages that need this feature class
            local fc_pkgs
            fc_pkgs=$(echo "${all_packages}" | while IFS= read -r pkg; do
                [[ -z "${pkg}" ]] && continue
                # Map feature class to package name pattern
                case "${fc}" in
                    mesh)    [[ "${pkg}" == *mesh* ]] && echo "${pkg}" ;;
                    dns)     [[ "${pkg}" == *dns* ]] && echo "${pkg}" ;;
                    plugin)  [[ "${pkg}" == *plugin* ]] && echo "${pkg}" ;;
                    http)    [[ "${pkg}" == *http* ]] && echo "${pkg}" ;;
                    proxy)   [[ "${pkg}" == *proxy* ]] && echo "${pkg}" ;;
                    waf)     [[ "${pkg}" == *waf* ]] && echo "${pkg}" ;;
                    admin)   [[ "${pkg}" == *admin* ]] && echo "${pkg}" ;;
                    tls)     [[ "${pkg}" == *tls* ]] && echo "${pkg}" ;;
                    tunnel)  [[ "${pkg}" == *tunnel* ]] && echo "${pkg}" ;;
                    platform) [[ "${pkg}" == *platform* ]] && echo "${pkg}" ;;
                    honeypot) [[ "${pkg}" == *honeypot* ]] && echo "${pkg}" ;;
                    tarpit)  [[ "${pkg}" == *tarpit* ]] && echo "${pkg}" ;;
                    *)       echo "${pkg}" ;;
                esac
            done)

            if [[ -n "${fc_pkgs}" ]]; then
                while IFS= read -r pkg; do
                    [[ -z "${pkg}" ]] && continue
                    log_info "cargo nextest run -p ${pkg} --features ${fc} --cargo-profile ci --profile ci"
                    local t_start
                    t_start=$(timer_start)
                    local run_log
                    if run_log=$(cargo nextest run -p "${pkg}" --features "${fc}" --cargo-profile ci --profile ci 2>&1); then
                        PASSED=$((PASSED + 1))
                        log_ok "PASS: ${pkg} [${fc}]"
                    else
                        FAILED=$((FAILED + 1))
                        FAILED_ITEMS+=("pkg:${pkg}[${fc}]")
                        log_fail "FAIL: ${pkg} [${fc}]"
                        echo "${run_log}" | tail -20 | while IFS= read -r line; do
                            log_dim "    ${line}"
                        done
                    fi
                done <<< "${fc_pkgs}"
            fi
        done <<< "${feature_classes}"
    fi

    # Summary
    local total_time_ms
    total_time_ms=$(timer_elapsed_ms "${START_TIME}")

    log ""
    log_bold "═══════════════════════════════════════════════════════════"

    if [[ "${FAILED}" -gt 0 ]]; then
        log_fail "${RED}${BOLD}${FAILED} failed${NC} / $((PASSED + FAILED)) total"
        log ""
        log_fail "Failed items:"
        for item in "${FAILED_ITEMS[@]}"; do
            log_fail "  - ${item}"
        done
    else
        log_ok "${GREEN}${BOLD}All tests passed${NC} (${PASSED}/${PASSED})"
    fi

    log ""
    log "  Total time: $(format_duration "${total_time_ms}")"
    log "  Packages: ${TOTAL_PACKAGES}, Root tests: ${TOTAL_ROOT_TESTS}"
    log_bold "═══════════════════════════════════════════════════════════"

    # JSON summary for CI
    if [[ "${JSON_MODE}" == "true" ]]; then
        emit_json_summary
    fi

    [[ "${FAILED}" -eq 0 ]] && exit 0 || exit 1
}

main "$@"

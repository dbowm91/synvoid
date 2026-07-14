#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0
STEPS=()

green() { printf '\033[0;32m%s\033[0m\n' "$1"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$1"; }

pass() {
    green "  PASS: $1"
    PASS=$((PASS + 1))
    STEPS+=("PASS $1")
}

fail() {
    red "  FAIL: $1"
    FAIL=$((FAIL + 1))
    STEPS+=("FAIL $1")
}

run() {
    local label="$1"; shift
    echo ""
    echo ">>> $label"
    if "$@"; then
        pass "$label"
    else
        fail "$label"
    fi
}

echo "========================================"
echo " Plugin Runtime Verification"
echo "========================================"

# 1. Format check
run "Format check" cargo fmt --all -- --check

# 2. Clippy on plugin runtime
run "Clippy (synvoid-plugin-runtime)" cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings

# 3. Unit tests
run "Unit tests (synvoid-plugin-runtime)" cargo test -p synvoid-plugin-runtime

# 4. Guard tests (plugin-specific)
run "Guard: plugin_capability_boundary_guard" cargo test --test plugin_capability_boundary_guard
run "Guard: plugin_signature_policy_guard" cargo test --test plugin_signature_policy_guard
run "Guard: plugin_failure_does_not_poison_manager" cargo test -p synvoid-plugin-runtime --test plugin_failure_does_not_poison_manager
run "Guard: plugin_lifecycle_guard" cargo test --test plugin_lifecycle_guard
run "Guard: unsafe_native_sandbox_language_guard" cargo test --test unsafe_native_sandbox_language_guard
run "Guard: manifest_authority_wiring" cargo test -p synvoid-plugin-runtime --test manifest_authority_wiring
run "Guard: manifest_authority_load_path_guard" cargo test --test manifest_authority_load_path_guard

# 5. Feature profile checks
run "Profile: no-default-features" cargo check --no-default-features
run "Profile: mesh" cargo check --no-default-features --features mesh
run "Profile: dns" cargo check --no-default-features --features dns
run "Profile: mesh,dns" cargo check --no-default-features --features mesh,dns

# Summary
TOTAL=$((PASS + FAIL))
echo ""
echo "========================================"
echo " Summary: $PASS/$TOTAL passed, $FAIL failed"
echo "========================================"
for s in "${STEPS[@]}"; do
    case "$s" in
        PASS*) green "  $s" ;;
        FAIL*) red   "  $s" ;;
    esac
done
echo ""

if [ "$FAIL" -gt 0 ]; then
    red "FAILED"
    exit 1
fi

green "ALL PASSED"
exit 0

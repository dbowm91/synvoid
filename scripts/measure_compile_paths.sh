#!/usr/bin/env bash
# SynVoid compile path timing harness.
#
# Runs representative `cargo check` invocations for the most-edited crates
# and the root feature profiles. Prints wall-clock timings so we can compare
# clean and incremental rebuild costs.
#
# Usage: bash scripts/measure_compile_paths.sh
#
# On darwin (and most Linux) `/usr/bin/time -p` is available and emits
# POSIX-style "real/user/sys" lines that are easy to parse. We fall back to
# the shell `time` builtin if `/usr/bin/time -p` is missing.

set -euo pipefail

if /usr/bin/time -p echo "ok" >/dev/null 2>&1; then
    TIME_CMD=(/usr/bin/time -p)
else
    TIME_CMD=(time)
fi

run() {
    local label="$1"
    shift
    echo
    echo "== $label =="
    echo "+ $*"
    # Capture stdout/stderr from cargo, but let /usr/bin/time's "real/user/sys"
    # lines print to stderr where they belong.
    if "${TIME_CMD[@]}" "$@"; then
        echo "  -> $label OK"
    else
        echo "  -> $label FAILED (rc=$?)"
    fi
}

# Per-crate subsystem checks (represent the work a small agent does when
# iterating on a single subsystem).
run "synvoid-core"             cargo check -p synvoid-core
run "synvoid-waf"              cargo check -p synvoid-waf
run "synvoid-proxy"            cargo check -p synvoid-proxy
run "synvoid-http"             cargo check -p synvoid-http
run "synvoid-static-files"     cargo check -p synvoid-static-files
run "synvoid-ipc"              cargo check -p synvoid-ipc

# Root profile checks (these exercise the orchestration code that lives in
# src/ and link the workspace together).
run "root lib core"            cargo check --lib --no-default-features
run "root lib mesh"            cargo check --no-default-features --features mesh
run "root lib dns"             cargo check --no-default-features --features dns
run "root lib mesh+dns"        cargo check --no-default-features --features mesh,dns

# Full workspace check (expensive, run last).
run "workspace all targets"    cargo check --workspace --all-targets

echo
echo "=== measure_compile_paths.sh complete ==="

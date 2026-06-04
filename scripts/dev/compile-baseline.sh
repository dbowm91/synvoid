#!/bin/bash
set -e
echo "=== SynVoid Compile Baseline ==="
echo "Date: $(date)"
echo ""

echo "--- Clean build ---"
cargo clean 2>/dev/null || true
time cargo build --lib 2>&1 | tail -5
echo ""

echo "--- Workspace check ---"
time cargo check --workspace --all-targets 2>&1 | tail -5
echo ""

echo "--- Profile checks ---"
echo "Core profile:"
time cargo check --no-default-features 2>&1 | tail -3
echo ""
echo "Mesh profile:"
time cargo check --no-default-features --features mesh 2>&1 | tail -3
echo ""
echo "DNS profile:"
time cargo check --no-default-features --features dns 2>&1 | tail -3
echo ""
echo "Full profile:"
time cargo check --no-default-features --features mesh,dns 2>&1 | tail -3
echo ""

echo "--- Incremental checks ---"
touch src/waf/bot.rs
time cargo check --lib 2>&1 | tail -3
echo ""
touch src/http/server.rs
time cargo check --lib 2>&1 | tail -3
echo ""
touch crates/synvoid-config/src/lib.rs
time cargo check --workspace 2>&1 | tail -3
echo ""
echo "=== Baseline Complete ==="

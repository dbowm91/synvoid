#!/usr/bin/env bash
# DNS Benchmark Runner - Workstream 1
# Reproducible benchmark suite for synvoid-dns performance baselines.
#
# Usage:
#   ./scripts/dns/run_benchmarks.sh [--all] [--cache] [--wire] [--zone] [--coalescer] [--limits] [--quick]
#
# Defaults to --all if no flag specified.
# Results are saved to benchmarks/dns/results/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$PROJECT_ROOT/benchmarks/dns/results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RESULTS_FILE="$RESULTS_DIR/bench_${TIMESTAMP}.txt"

mkdir -p "$RESULTS_DIR"

# Record environment info
record_env() {
    echo "=== DNS Benchmark Run: $(date) ===" | tee "$RESULTS_FILE"
    echo "" | tee -a "$RESULTS_FILE"
    echo "--- Environment ---" | tee -a "$RESULTS_FILE"
    echo "OS: $(uname -a)" | tee -a "$RESULTS_FILE"
    echo "CPU: $(lscpu 2>/dev/null | grep 'Model name' | head -1 || echo 'unknown')" | tee -a "$RESULTS_FILE"
    echo "RAM: $(free -h 2>/dev/null | awk '/Mem:/{print $2}' || echo 'unknown')" | tee -a "$RESULTS_FILE"
    echo "Rust: $(rustc --version 2>/dev/null || echo 'unknown')" | tee -a "$RESULTS_FILE"
    echo "Cargo: $(cargo --version 2>/dev/null || echo 'unknown')" | tee -a "$RESULTS_FILE"
    echo "Profile: release" | tee -a "$RESULTS_FILE"
    echo "" | tee -a "$RESULTS_FILE"
}

run_bench() {
    local name="$1"
    echo "--- Running: $name ---" | tee -a "$RESULTS_FILE"
    cargo bench -p synvoid-dns --bench "$name" 2>&1 | tee -a "$RESULTS_FILE"
    echo "" | tee -a "$RESULTS_FILE"
}

# Parse arguments
RUN_ALL=true
RUN_CACHE=false
RUN_WIRE=false
RUN_ZONE=false
RUN_COALESCER=false
RUN_LIMITS=false
QUICK=false

for arg in "$@"; do
    case "$arg" in
        --all) RUN_ALL=true ;;
        --cache) RUN_CACHE=true; RUN_ALL=false ;;
        --wire) RUN_WIRE=true; RUN_ALL=false ;;
        --zone) RUN_ZONE=true; RUN_ALL=false ;;
        --coalescer) RUN_COALESCER=true; RUN_ALL=false ;;
        --limits) RUN_LIMITS=true; RUN_ALL=false ;;
        --quick) QUICK=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

record_env

if $RUN_ALL || $RUN_CACHE; then
    run_bench "cache_bench"
fi

if $RUN_ALL || $RUN_WIRE; then
    run_bench "wire_bench"
fi

if $RUN_ALL || $RUN_ZONE; then
    run_bench "zone_bench"
fi

if $RUN_ALL || $RUN_COALESCER; then
    run_bench "coalescer_bench"
fi

if $RUN_ALL || $RUN_LIMITS; then
    run_bench "limits_bench"
fi

echo "=== Benchmark complete ===" | tee -a "$RESULTS_FILE"
echo "Results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
echo "Compare with previous runs:" | tee -a "$RESULTS_FILE"
echo "  ls $RESULTS_DIR/" | tee -a "$RESULTS_FILE"

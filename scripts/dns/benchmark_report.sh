#!/usr/bin/env bash
# DNS Benchmark Report Generator - Workstream 8
# Generates a markdown report from the latest benchmark run.
#
# Usage:
#   ./scripts/dns/benchmark_report.sh [bench_results_file]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$PROJECT_ROOT/benchmarks/dns/results"

if [ -n "${1:-}" ]; then
    RESULTS_FILE="$1"
else
    RESULTS_FILE="$(ls -t "$RESULTS_DIR"/bench_*.txt 2>/dev/null | head -1)"
fi

if [ -z "$RESULTS_FILE" ] || [ ! -f "$RESULTS_FILE" ]; then
    echo "No benchmark results found. Run: ./scripts/dns/run_benchmarks.sh"
    exit 1
fi

REPORT_FILE="$RESULTS_DIR/report_$(date +%Y%m%d_%H%M%S).md"

echo "# DNS Benchmark Report" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "**Generated**: $(date)" >> "$REPORT_FILE"
echo "**Source**: $(basename "$RESULTS_FILE")" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Extract environment info
echo "## Environment" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
sed -n '/--- Environment ---/,/^$/p' "$RESULTS_FILE" | head -10 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Extract bench results
echo "## Results" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
grep -E "(bench_|Running:|time:)" "$RESULTS_FILE" >> "$REPORT_FILE" 2>/dev/null || true
echo "" >> "$REPORT_FILE"

echo "Report saved to: $REPORT_FILE"

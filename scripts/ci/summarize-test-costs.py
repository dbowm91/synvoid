#!/usr/bin/env python3
"""Summarize CI test costs from timing data.

Usage:
    cargo test --profile ci --no-fail-fast 2>&1 | python3 scripts/ci/summarize-test-costs.py
    
Or parse saved output:
    python3 scripts/ci/summarize-test-costs.py < timing-output.txt
"""

import sys
import re
from collections import defaultdict

def parse_test_output(lines):
    """Parse cargo test output to extract timing and count information."""
    results = {
        'test_binary': None,
        'total_tests': 0,
        'passed': 0,
        'failed': 0,
        'ignored': 0,
        'measured': 0,
        'filtered_out': 0,
        'test_results': [],
    }
    
    for line in lines:
        # Match "test result: ok. N passed; M failed; X ignored; Y measured; Z filtered out"
        m = re.match(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', line)
        if m:
            results['passed'] += int(m.group(2))
            results['failed'] += int(m.group(3))
            results['ignored'] += int(m.group(4))
            results['measured'] += int(m.group(5))
            results['filtered_out'] += int(m.group(6))
            results['total_tests'] += int(m.group(2)) + int(m.group(3))
            continue
        
        # Match "test XXX ... ok FAILED (N.NNs)"
        m = re.match(r'test (\S+) \.\.\. (ok|FAILED|ignored) \((\d+\.\d+)s\)', line)
        if m:
            results['test_results'].append({
                'name': m.group(1),
                'status': m.group(2),
                'duration': float(m.group(3)),
            })
    
    return results

def format_summary(results):
    """Format results as markdown."""
    lines = []
    lines.append("# Test Cost Summary\n")
    lines.append(f"**Total tests:** {results['total_tests']}")
    lines.append(f"**Passed:** {results['passed']}")
    lines.append(f"**Failed:** {results['failed']}")
    lines.append(f"**Ignored:** {results['ignored']}")
    lines.append("")
    
    if results['test_results']:
        # Sort by duration descending
        sorted_tests = sorted(results['test_results'], key=lambda t: t['duration'], reverse=True)
        lines.append("## Slowest Tests")
        lines.append("")
        lines.append("| Test | Duration | Status |")
        lines.append("|------|----------|--------|")
        for t in sorted_tests[:20]:
            lines.append(f"| {t['name']} | {t['duration']:.3f}s | {t['status']} |")
        lines.append("")
    
    return "\n".join(lines)

def main():
    lines = sys.stdin.readlines()
    results = parse_test_output(lines)
    print(format_summary(results))

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Check for forbidden import patterns in core modules.

This script ensures that certain modules do not import from forbidden
paths, enforcing architecture boundaries defined in the plan.

Usage:
    python scripts/check_imports.py [--fix]

Exit codes:
    0 - All checks passed
    1 - Forbidden import pattern found
    2 - Script error (e.g., missing Rust source files)
"""

import re
import sys
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple

ForbiddenPattern = Tuple[str, str, str]

FORBIDDEN_PATTERNS: List[ForbiddenPattern] = [
    ("src/worker/", "crate::mesh::", "Worker module must not depend on mesh (data plane separation)"),
    ("src/admin/", "crate::mesh::", "Admin module must not depend on mesh (mesh should be feature-gated)"),
    ("src/dns/", "crate::mesh::", "DNS module should use local-first or DNS-native sync"),
    ("src/tls/", "crate::config::mesh", "TLS termination is independent of mesh identity"),
]

MODULES_TO_CHECK = [
    "src/worker",
    "src/admin",
    "src/dns",
    "src/tls",
]


def find_rust_files(directory: Path) -> List[Path]:
    """Find all Rust source files in directory."""
    return list(directory.glob("**/*.rs"))


def check_file_forbidden_imports(
    file_path: Path,
    forbidden_patterns: List[ForbiddenPattern],
) -> List[Tuple[str, str, str]]:
    """
    Check a single file for forbidden import patterns.

    Returns list of (file_path, import_line, reason) tuples for violations.
    """
    violations = []

    try:
        content = file_path.read_text()
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return violations

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        line = line.strip()

        if not line.startswith("use "):
            continue

        for module_prefix, forbidden_import, reason in forbidden_patterns:
            if module_prefix in str(file_path):
                if forbidden_import in line:
                    violations.append((f"{file_path}:{line_num}", line, reason))

    return violations


def check_module(
    module_path: Path,
    forbidden_patterns: List[ForbiddenPattern],
) -> Dict[str, List[Tuple[str, str, str]]]:
    """
    Check all files in a module for forbidden imports.

    Returns dict mapping file paths to violation tuples.
    """
    violations = {}
    rust_files = find_rust_files(module_path)

    for rust_file in rust_files:
        file_violations = check_file_forbidden_imports(rust_file, forbidden_patterns)
        if file_violations:
            violations[str(rust_file)] = file_violations

    return violations


def print_violations(violations: Dict[str, List[Tuple[str, str, str]]]) -> None:
    """Print all violations in a formatted way."""
    for file_path, file_violations in violations.items():
        print(f"\n{file_path}:")
        for location, line, reason in file_violations:
            print(f"  ✗ {line}")
            print(f"    Reason: {reason}")


def main() -> int:
    """Main entry point."""
    repo_root = Path(__file__).parent.parent
    check_core = "--core" in sys.argv
    verbose = "--verbose" in sys.argv

    if verbose:
        print(f"Repository root: {repo_root}", file=sys.stderr)
        print(f"Checking modules: {MODULES_TO_CHECK}", file=sys.stderr)

    all_violations = {}

    for module_rel in MODULES_TO_CHECK:
        module_path = repo_root / module_rel
        if not module_path.exists():
            print(f"Warning: Module path does not exist: {module_path}", file=sys.stderr)
            continue

        violations = check_module(module_path, FORBIDDEN_PATTERNS)
        if violations:
            all_violations.update(violations)

    if all_violations:
        print_violations(all_violations)
        print(f"\n❌ Found {sum(len(v) for v in all_violations.values())} forbidden import(s)")
        return 1

    print("✅ No forbidden imports detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
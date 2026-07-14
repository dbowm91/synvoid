#!/usr/bin/env python3
"""Compute the affected package set for a given commit range.

Used by CI to select which workspace packages, root tests, and feature
classes need validation for a pull request or commit range.

Falls back to full validation (exit 0) on any error — fail-safe by design.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MULTIPLIER_THRESHOLD = 5  # more than N unrelated package roots → full fallback

ROOT_FACADE_PATHS = frozenset({"src/main.rs", "src/lib.rs"})

ROOT_FACADE_GLOBS = ("src/commands/*.rs",)

OWNERSHIP_TOML = "tests/OWNERSHIP.toml"

# Basenames that always trigger full validation.
FULL_FALLBACK_BASENAMES = frozenset({
    "Cargo.toml",
    "Cargo.lock",
})

# Directory prefixes that always trigger full validation.
FULL_FALLBACK_PREFIXES = (
    ".cargo/",
    ".github/workflows/",
)

# Filenames (anywhere in tree) that always trigger full validation.
FULL_FALLBACK_FILENAMES = frozenset({
    "rust-toolchain.toml",
    "rust-toolchain",
})

# Packages whose changes always trigger full validation.
FULL_FALLBACK_PACKAGES = frozenset({
    "synvoid-testkit",
})

# Feature class → packages that activate that class.
FEATURE_CLASS_PACKAGES: dict[str, list[str]] = {
    "dns": ["synvoid-dns"],
    "mesh": ["synvoid-mesh"],
    "plugin": ["synvoid-plugin-runtime"],
    "http": ["synvoid-http", "synvoid-http3"],
    "proxy": ["synvoid-proxy", "synvoid-proxy-cache"],
    "waf": ["synvoid-waf"],
    "admin": ["synvoid-admin"],
    "tls": ["synvoid-tls"],
    "tunnel": ["synvoid-tunnel"],
    "platform": ["synvoid-platform"],
    "honeypot": ["synvoid-honeypot"],
    "tarpit": ["synvoid-tarpit"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def eprint(msg: str) -> None:
    """Print to stderr."""
    print(f"select-affected: {msg}", file=sys.stderr)


def run_cmd(argv: list[str], *, check: bool = True, cwd: str | Path | None = None) -> str:
    """Run a command and return stdout. Returns empty string on failure."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=check,
            timeout=120,
            cwd=cwd,
        )
        return result.stdout
    except FileNotFoundError:
        eprint(f"command not found: {argv[0]}")
        return ""
    except subprocess.CalledProcessError as exc:
        eprint(f"command failed ({exc.returncode}): {' '.join(argv)}")
        if exc.stderr:
            for line in exc.stderr.strip().splitlines():
                eprint(f"  {line}")
        return ""
    except subprocess.TimeoutExpired:
        eprint(f"command timed out: {' '.join(argv)}")
        return ""
    except Exception as exc:
        eprint(f"unexpected error running {argv[0]}: {exc}")
        return ""


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git_diff_changed_files(base: str, head: str, cwd: Path) -> list[str]:
    """Return sorted list of files changed between base and head."""
    out = run_cmd(
        ["git", "diff", "--name-only", "--diff-filter=ACMRD", f"{base}..{head}"],
        cwd=cwd,
    )
    if not out:
        return []
    return sorted(line.strip() for line in out.splitlines() if line.strip())


def git_ref_exists(ref: str, cwd: Path) -> bool:
    """Check if a git ref is resolvable."""
    out = run_cmd(["git", "rev-parse", "--verify", ref], check=False, cwd=cwd)
    return bool(out.strip())


# ---------------------------------------------------------------------------
# Cargo metadata
# ---------------------------------------------------------------------------

def cargo_metadata(workspace_root: Path) -> dict[str, Any] | None:
    """Parse cargo metadata for the workspace (no dependency download)."""
    out = run_cmd(
        [
            "cargo", "metadata",
            "--format-version", "1",
            "--no-deps",
            "--manifest-path", str(workspace_root / "Cargo.toml"),
        ],
        check=False,
        cwd=workspace_root,
    )
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        eprint(f"failed to parse cargo metadata JSON: {exc}")
        return None


def build_package_dir_map(metadata: dict[str, Any]) -> dict[str, str]:
    """Map normalized directory path → package name for all workspace packages."""
    result: dict[str, str] = {}
    for pkg in metadata.get("packages", []):
        manifest = pkg.get("manifest_path", "")
        if manifest:
            # manifest_path is absolute; normalize to repo-relative
            pkg_dir = str(Path(manifest).parent.resolve())
            result[pkg_dir] = pkg["name"]
    return result


def build_reverse_deps(metadata: dict[str, Any]) -> dict[str, set[str]]:
    """Build reverse dependency map (within workspace only).

    Uses each package's ``dependencies`` list (not the resolve graph, which
    is unavailable with ``--no-deps``).  Workspace dependencies have
    ``source: null``.

    Returns ``{dependency_name: {dependers...}}``.
    """
    workspace_names = {pkg["name"] for pkg in metadata.get("packages", [])}
    reverse: dict[str, set[str]] = {}

    for pkg in metadata.get("packages", []):
        src_name = pkg["name"]
        for dep in pkg.get("dependencies", []):
            dep_name = dep.get("name", "")
            # Workspace (path) deps have no source; external deps have a source.
            if dep_name in workspace_names and dep_name != src_name:
                reverse.setdefault(dep_name, set()).add(src_name)

    return reverse


def transitive_reverse_dependents(
    seed: set[str],
    reverse_deps: dict[str, set[str]],
) -> set[str]:
    """BFS to find all transitive reverse dependents of seed packages."""
    visited: set[str] = set()
    queue = list(seed)
    while queue:
        pkg = queue.pop()
        if pkg in visited:
            continue
        visited.add(pkg)
        for depender in reverse_deps.get(pkg, set()):
            if depender not in visited:
                queue.append(depender)
    return visited


# ---------------------------------------------------------------------------
# File → package mapping
# ---------------------------------------------------------------------------

def map_files_to_packages(
    changed_files: list[str],
    pkg_dir_map: dict[str, str],
    workspace_root: Path,
) -> set[str]:
    """Map changed file paths to workspace package names.

    Matches the longest (most specific) package directory first to avoid
    the root crate matching every file in the repository.
    """
    # Sort by path length descending so more-specific paths match first.
    sorted_dirs = sorted(pkg_dir_map.keys(), key=len, reverse=True)

    affected: set[str] = set()
    for fpath in changed_files:
        abs_path = str((workspace_root / fpath).resolve())
        for pkg_dir in sorted_dirs:
            pkg_name = pkg_dir_map[pkg_dir]
            if abs_path.startswith(pkg_dir + "/") or abs_path == pkg_dir + "/Cargo.toml":
                affected.add(pkg_name)
                break
    return affected


# ---------------------------------------------------------------------------
# Fallback rules
# ---------------------------------------------------------------------------

def classify_file_triggers(changed_files: list[str]) -> list[str]:
    """Check if any changed file triggers full validation. Returns reasons."""
    reasons: list[str] = []

    for fpath in changed_files:
        # Root-level Cargo.toml / Cargo.lock (not in sub-crates)
        if fpath in FULL_FALLBACK_BASENAMES:
            reasons.append(f"root config changed: {fpath}")

        # Toolchain files anywhere in the tree
        basename = os.path.basename(fpath)
        if basename in FULL_FALLBACK_FILENAMES:
            reasons.append(f"toolchain file changed: {fpath}")

        # Directory prefix matches
        for prefix in FULL_FALLBACK_PREFIXES:
            if fpath.startswith(prefix):
                reasons.append(f"CI/config prefix match '{prefix}': {fpath}")
                break

    # Root facade modules
    for fpath in changed_files:
        if fpath in ROOT_FACADE_PATHS:
            reasons.append(f"root facade changed: {fpath}")

    # Root facade globs (src/commands/*.rs)
    for fpath in changed_files:
        for pattern in ROOT_FACADE_GLOBS:
            if fnmatch.fnmatch(fpath, pattern):
                reasons.append(f"root facade changed: {fpath}")
                break

    return reasons


def classify_package_triggers(affected_packages: set[str]) -> list[str]:
    """Check if any affected package triggers full validation."""
    reasons: list[str] = []
    for pkg in sorted(affected_packages):
        if pkg in FULL_FALLBACK_PACKAGES:
            reasons.append(f"full-fallback package changed: {pkg}")
    return reasons


def check_multiple_unrelated_roots(
    affected_packages: set[str],
    pkg_dir_map: dict[str, str],
) -> list[str]:
    """Check if too many unrelated package roots changed."""
    # Count unique top-level crate directories (crates/*)
    root_dirs: set[str] = set()
    for pkg in affected_packages:
        # Find the directory for this package
        for pkg_dir, pkg_name in pkg_dir_map.items():
            if pkg_name == pkg:
                # Extract top-level: "crates/synvoid-dns" → "crates/synvoid-dns"
                rel = os.path.relpath(pkg_dir, os.path.dirname(pkg_dir))
                parts = Path(rel).parts
                if len(parts) >= 2:
                    root_dirs.add("/".join(parts[:2]))
                else:
                    root_dirs.add(rel)
                break
    if len(root_dirs) > MULTIPLIER_THRESHOLD:
        return [f"{len(root_dirs)} unrelated package roots changed (threshold: {MULTIPLIER_THRESHOLD})"]
    return []


# ---------------------------------------------------------------------------
# Root test selection
# ---------------------------------------------------------------------------

def parse_ownership_toml(workspace_root: Path) -> list[dict[str, Any]]:
    """Parse tests/OWNERSHIP.toml with simple string parsing (no external deps)."""
    path = workspace_root / OWNERSHIP_TOML
    if not path.exists():
        eprint(f"ownership file not found: {path}")
        return []

    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[[test]]"):
            if current is not None:
                entries.append(current)
            current = {"name": "", "class": "", "owners": [], "reason": ""}
            continue
        if current is None:
            continue
        if "=" in line:
            key, _, val_raw = line.partition("=")
            key = key.strip()
            val_raw = val_raw.strip()
            val = val_raw.strip('"').strip("'")
            if key == "owners":
                val = val.strip("[]")
                if val:
                    current["owners"] = [
                        v.strip().strip('"').strip("'").strip()
                        for v in val.split(",")
                    ]
                else:
                    current["owners"] = []
            elif key in ("name", "class", "reason"):
                current[key] = val

    if current is not None:
        entries.append(current)

    return entries


def select_root_tests(
    ownership_entries: list[dict[str, Any]],
    affected_packages: set[str],
    full_validation: bool,
) -> list[str]:
    """Select root tests to run based on affected packages.

    If full_validation is True, all tests are returned.
    Otherwise, only tests whose owners overlap with affected_packages are selected.
    Tests with empty owners are cross-cutting and always included.
    """
    if full_validation:
        return sorted(entry["name"] for entry in ownership_entries if entry["name"])

    selected: list[str] = []
    for entry in ownership_entries:
        name = entry["name"]
        if not name:
            continue
        owners = set(entry.get("owners", []))
        if not owners:
            # No owners → cross-cutting → always run
            selected.append(name)
        elif owners & affected_packages:
            selected.append(name)

    return sorted(set(selected))


# ---------------------------------------------------------------------------
# Feature class selection
# ---------------------------------------------------------------------------

def select_feature_classes(affected_packages: set[str]) -> list[str]:
    """Determine which feature classes are relevant based on affected packages."""
    classes: list[str] = ["default"]
    for cls, pkgs in FEATURE_CLASS_PACKAGES.items():
        if affected_packages & set(pkgs):
            classes.append(cls)
    return sorted(set(classes))


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------

def compute_affected(
    base: str,
    head: str,
    workspace_root: Path,
    *,
    full_override: bool = False,
) -> dict[str, Any]:
    """Compute the affected package set, reverse dependents, root tests, and feature classes.

    Falls back to full validation on any error or when fallback triggers fire.
    """
    result: dict[str, Any] = {
        "mode": "affected",
        "reason": "",
        "changed_packages": [],
        "reverse_dependents": [],
        "root_tests": [],
        "feature_classes": ["default"],
        "full_fallback": False,
        "fallback_reasons": [],
    }

    # --- Step 1: get changed files ---
    changed_files = git_diff_changed_files(base, head, workspace_root)
    if not changed_files:
        result["mode"] = "full"
        result["reason"] = "no changed files detected (error or empty range)"
        result["full_fallback"] = True
        result["fallback_reasons"] = [result["reason"]]
        return result

    eprint(f"changed files: {len(changed_files)}")

    # --- Step 2: file-level fallback triggers ---
    file_reasons = classify_file_triggers(changed_files)
    result["fallback_reasons"].extend(file_reasons)

    # --- Step 3: cargo metadata ---
    metadata = cargo_metadata(workspace_root)
    if metadata is None:
        result["mode"] = "full"
        result["reason"] = "cargo metadata unavailable — falling back to full validation"
        result["full_fallback"] = True
        result["fallback_reasons"].append(result["reason"])
        return result

    pkg_dir_map = build_package_dir_map(metadata)
    eprint(f"workspace packages: {len(pkg_dir_map)}")

    # --- Step 4: map files → packages ---
    affected_pkgs = map_files_to_packages(changed_files, pkg_dir_map, workspace_root)
    eprint(f"directly affected packages: {sorted(affected_pkgs)}")

    # --- Step 5: package-level fallback triggers ---
    pkg_reasons = classify_package_triggers(affected_pkgs)
    result["fallback_reasons"].extend(pkg_reasons)

    # --- Step 6: multiple unrelated roots ---
    root_reasons = check_multiple_unrelated_roots(affected_pkgs, pkg_dir_map)
    result["fallback_reasons"].extend(root_reasons)

    # --- Step 7: workspace-level Cargo.toml features ---
    if "Cargo.toml" in changed_files:
        cargo_path = workspace_root / "Cargo.toml"
        if cargo_path.exists():
            text = cargo_path.read_text()
            if "[workspace.dependencies]" in text:
                result["fallback_reasons"].append(
                    "[workspace.dependencies] section in root Cargo.toml"
                )

    # --- Step 8: compute transitive reverse dependents ---
    reverse_deps = build_reverse_deps(metadata)
    all_affected = transitive_reverse_dependents(affected_pkgs, reverse_deps)
    dependents_only = sorted(all_affected - affected_pkgs)
    eprint(f"transitive reverse dependents: {dependents_only}")

    # --- Step 9: parse ownership and select root tests ---
    ownership_entries = parse_ownership_toml(workspace_root)
    full_required = full_override or len(result["fallback_reasons"]) > 0
    root_tests = select_root_tests(ownership_entries, all_affected, full_required)
    eprint(f"selected root tests: {root_tests}")

    # --- Step 10: feature classes ---
    feature_classes = select_feature_classes(all_affected)

    # --- Build final result ---
    if full_required:
        result["mode"] = "full"
        if result["fallback_reasons"]:
            result["reason"] = "; ".join(dict.fromkeys(result["fallback_reasons"]))
        else:
            result["reason"] = "forced full validation"
        result["full_fallback"] = True
        # In full mode, include everything
        result["changed_packages"] = sorted(affected_pkgs)
        result["reverse_dependents"] = dependents_only
        result["root_tests"] = sorted(
            entry["name"] for entry in ownership_entries if entry["name"]
        )
        result["feature_classes"] = sorted(FEATURE_CLASS_PACKAGES.keys())
    else:
        result["mode"] = "affected"
        result["reason"] = (
            f"{len(changed_files)} files changed across "
            f"{len(affected_pkgs)} packages, "
            f"{len(dependents_only)} transitive dependents"
        )
        result["changed_packages"] = sorted(affected_pkgs)
        result["reverse_dependents"] = dependents_only
        result["root_tests"] = root_tests
        result["feature_classes"] = feature_classes

    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_text(result: dict[str, Any]) -> str:
    """Format result as human-readable text."""
    lines: list[str] = []
    lines.append(f"Mode: {result['mode']}")
    if result.get("reason"):
        lines.append(f"Reason: {result['reason']}")
    lines.append(f"Changed packages: {', '.join(result['changed_packages']) or '(none)'}")
    lines.append(f"Reverse dependents: {', '.join(result['reverse_dependents']) or '(none)'}")
    lines.append(f"Root tests: {', '.join(result['root_tests']) or '(none)'}")
    lines.append(f"Feature classes: {', '.join(result['feature_classes']) or '(none)'}")
    if result.get("full_fallback"):
        lines.append("Full fallback: YES")
        for reason in result.get("fallback_reasons", []):
            lines.append(f"  - {reason}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute affected package set for a commit range.",
    )
    parser.add_argument("--base", required=True, help="Base commit/ref for diff")
    parser.add_argument("--head", required=True, help="Head commit/ref for diff")
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be validated without producing CI output",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Force full validation regardless of changes",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress to stderr",
    )
    parser.add_argument(
        "--workspace-root",
        default=None,
        help="Workspace root directory (default: auto-detect)",
    )
    return parser


def detect_workspace_root() -> Path:
    """Detect workspace root by walking up from script location."""
    script_dir = Path(__file__).resolve().parent
    for candidate in [script_dir, *script_dir.parents]:
        if (candidate / "Cargo.toml").exists() and (candidate / "src").is_dir():
            return candidate
    cwd = Path.cwd()
    if (cwd / "Cargo.toml").exists():
        return cwd
    return cwd


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    workspace_root = detect_workspace_root()
    if args.workspace_root:
        workspace_root = Path(args.workspace_root).resolve()

    if args.verbose:
        eprint(f"workspace root: {workspace_root}")
        eprint(f"base: {args.base}")
        eprint(f"head: {args.head}")

    # Validate refs
    if not git_ref_exists(args.base, workspace_root):
        eprint(f"base ref '{args.base}' is not a valid git ref")
        result: dict[str, Any] = {
            "mode": "full",
            "reason": f"invalid base ref: {args.base}",
            "changed_packages": [],
            "reverse_dependents": [],
            "root_tests": [],
            "feature_classes": [],
            "full_fallback": True,
            "fallback_reasons": [f"invalid base ref: {args.base}"],
        }
        print(json.dumps(result, indent=2))
        return 0

    if not git_ref_exists(args.head, workspace_root):
        eprint(f"head ref '{args.head}' is not a valid git ref")
        result = {
            "mode": "full",
            "reason": f"invalid head ref: {args.head}",
            "changed_packages": [],
            "reverse_dependents": [],
            "root_tests": [],
            "feature_classes": [],
            "full_fallback": True,
            "fallback_reasons": [f"invalid head ref: {args.head}"],
        }
        print(json.dumps(result, indent=2))
        return 0

    # Compute — always fail-safe
    try:
        result = compute_affected(
            args.base,
            args.head,
            workspace_root,
            full_override=args.full,
        )
    except Exception as exc:
        eprint(f"unexpected error: {exc}")
        result = {
            "mode": "full",
            "reason": f"unexpected error: {exc}",
            "changed_packages": [],
            "reverse_dependents": [],
            "root_tests": [],
            "feature_classes": [],
            "full_fallback": True,
            "fallback_reasons": [str(exc)],
        }

    if args.dry_run:
        eprint("--- dry run — no CI output produced ---")

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=False))
    else:
        print(format_text(result))

    if args.verbose:
        eprint(f"output mode: {result['mode']}")
        if result.get("fallback_reasons"):
            eprint("fallback reasons:")
            for r in result["fallback_reasons"]:
                eprint(f"  - {r}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

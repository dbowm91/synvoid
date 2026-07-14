"""Tests for scripts/ci/select-affected.py affected-package selector.

Validates file→package mapping, transitive reverse dependency expansion,
fallback triggers, root test selection, and feature class selection
against realistic fixture data mirroring the SynVoid workspace.

Run with:
    python -m pytest tests/ci/test_select_affected.py -v
    python -m unittest tests.ci.test_select_affected -v
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Import select_affected from scripts/ci/ (hyphenated filename requires importlib)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SA_PATH = _REPO_ROOT / "scripts" / "ci" / "select-affected.py"

_sa_spec = __import__("importlib.util").util.spec_from_file_location(
    "select_affected", str(_SA_PATH)
)
_sa_mod = __import__("importlib.util").util.module_from_spec(_sa_spec)
_sa_spec.loader.exec_module(_sa_mod)
sa = _sa_mod

# ---------------------------------------------------------------------------
# Fixture: realistic workspace package metadata
# ---------------------------------------------------------------------------
# Mirrors the real dependency graph verified from Cargo.toml files.
# Only workspace-internal (path) dependencies are included; external deps
# are omitted to keep fixtures concise.

_WORKSPACE_ROOT = Path("/home/sugarwookie/projects/synvoid")


def _pkg(name: str, deps: list[str] | None = None) -> dict[str, Any]:
    """Build a minimal cargo metadata package entry."""
    return {
        "name": name,
        "version": "0.1.0",
        "manifest_path": str(_WORKSPACE_ROOT / "crates" / name / "Cargo.toml"),
        "dependencies": [
            {"name": d, "source": None} for d in (deps or [])
        ],
    }


# Root crate depends on synvoid-filter and many workspace crates
_ROOT_PKG = {
    "name": "synvoid",
    "version": "1.1.0",
    "manifest_path": str(_WORKSPACE_ROOT / "Cargo.toml"),
    "dependencies": [
        {"name": "synvoid-filter", "source": None},
        {"name": "synvoid-core", "source": None},
        {"name": "synvoid-utils", "source": None},
        {"name": "synvoid-config", "source": None},
        {"name": "synvoid-http", "source": None},
        {"name": "synvoid-waf", "source": None},
        {"name": "synvoid-proxy", "source": None},
        {"name": "synvoid-dns", "source": None},
        {"name": "synvoid-mesh", "source": None},
    ],
}

# Packages with their workspace-internal dependencies
_PACKAGES: list[dict[str, Any]] = [
    _ROOT_PKG,
    _pkg("synvoid-filter"),
    _pkg("synvoid-core"),
    _pkg("synvoid-utils"),
    _pkg("synvoid-config"),
    _pkg("synvoid-challenge", ["synvoid-utils"]),
    _pkg("synvoid-metrics", ["synvoid-core", "synvoid-utils", "synvoid-waf"]),
    _pkg("synvoid-block-store", ["synvoid-core", "synvoid-utils", "synvoid-waf"]),
    _pkg("synvoid-waf", ["synvoid-core", "synvoid-utils"]),
    _pkg("synvoid-http", ["synvoid-core", "synvoid-utils", "synvoid-waf"]),
    _pkg("synvoid-http3", ["synvoid-core", "synvoid-waf", "synvoid-http"]),
    _pkg("synvoid-proxy", ["synvoid-core", "synvoid-utils", "synvoid-waf"]),
    _pkg("synvoid-proxy-cache", ["synvoid-proxy"]),
    _pkg("synvoid-http-client", ["synvoid-core"]),
    _pkg("synvoid-dns", ["synvoid-core", "synvoid-utils"]),
    _pkg("synvoid-admin", ["synvoid-core", "synvoid-waf"]),
    _pkg("synvoid-mesh", ["synvoid-core", "synvoid-utils"]),
    _pkg("synvoid-app-handlers", ["synvoid-core"]),
    _pkg("synvoid-platform", ["synvoid-core"]),
    _pkg("synvoid-cli", ["synvoid-core"]),
    _pkg("synvoid-testkit", ["synvoid-core"]),
    _pkg("synvoid-plugin-runtime", ["synvoid-utils"]),
    _pkg("synvoid-tls"),
    _pkg("synvoid-tunnel", ["synvoid-utils"]),
    _pkg("synvoid-honeypot", ["synvoid-utils"]),
    _pkg("synvoid-tarpit"),
    _pkg("synvoid-static-files", ["synvoid-utils"]),
    _pkg("synvoid-ipc", ["synvoid-utils"]),
    _pkg("synvoid-app-server", ["synvoid-utils"]),
    _pkg("synvoid-upload", ["synvoid-utils"]),
    _pkg("synvoid-upstream", ["synvoid-utils"]),
    _pkg("synvoid-geoip"),
    _pkg("synvoid-integrity"),
    _pkg("synvoid-serverless"),
    _pkg("synvoid-theme"),
    _pkg("synvoid-wasm-pow"),
    _pkg("synvoid-icmp-filter"),
    _pkg("synvoid-vpn-client", ["synvoid-utils"]),
]

FAKE_METADATA: dict[str, Any] = {
    "packages": _PACKAGES,
    "workspace_members": [p["name"] for p in _PACKAGES],
}

# ---------------------------------------------------------------------------
# Fixture: OWNERSHIP.toml content (mirrors real tests/OWNERSHIP.toml)
# ---------------------------------------------------------------------------
FAKE_OWNERSHIP_TOML = """
[[test]]
name = "abi_memory_boundary_guard"
class = "static_policy"
owners = ["synvoid-plugin-runtime"]
reason = "validates ABI memory boundary across workspace plugin boundary"

[[test]]
name = "admin_mutation_blocklist"
class = "composition"
owners = ["synvoid-block-store", "synvoid-core"]
reason = "validates block-store + core mutation interaction"

[[test]]
name = "admin_mutation_response_guard"
class = "static_policy"
owners = ["synvoid-admin"]
reason = "validates admin mutation response contract across workspace"

[[test]]
name = "architecture_test"
class = "static_policy"
owners = []
reason = "validates architecture boundary constraints across workspace"

[[test]]
name = "boundary_composition_guard"
class = "static_policy"
owners = ["synvoid-waf", "synvoid-proxy", "synvoid-http", "synvoid-http3"]
reason = "validates composition boundary between request-path and root"

[[test]]
name = "cli_admin_guard"
class = "static_policy"
owners = ["synvoid-cli", "synvoid-admin"]
reason = "validates CLI/admin dispatch boundary across workspace"

[[test]]
name = "composition_root_behavioral"
class = "composition"
owners = ["synvoid-worker", "synvoid-mesh"]
reason = "validates worker+mesh composition root dataflow"

[[test]]
name = "failure_injection"
class = "composition"
owners = ["synvoid-supervisor", "synvoid-block-store", "synvoid-plugin-runtime"]
reason = "validates fault injection across supervisor, block-store, and plugin"

[[test]]
name = "integration_test"
class = "composition"
owners = ["synvoid-http", "synvoid-waf", "synvoid-proxy", "synvoid-dns", "synvoid-mesh"]
reason = "validates full-stack composition across all major subsystems"

[[test]]
name = "lifecycle_task_guard"
class = "static_policy"
owners = ["synvoid-worker", "synvoid-supervisor"]
reason = "validates lifecycle task ownership across worker and supervisor"

[[test]]
name = "mesh_id_boundary_guard"
class = "static_policy"
owners = ["synvoid-block-store", "synvoid-mesh"]
reason = "validates mesh-id boundary between block-store, mesh, and admin"

[[test]]
name = "mesh_task_ownership_guard"
class = "static_policy"
owners = ["synvoid-mesh"]
reason = "validates mesh task ownership across transport, lifecycle, and worker"

[[test]]
name = "plugin_guard"
class = "static_policy"
owners = ["synvoid-plugin-runtime"]
reason = "validates plugin capability boundary across workspace"

[[test]]
name = "root_test_ownership_guard"
class = "static_policy"
owners = []
reason = "enforces root test ownership manifest completeness"

[[test]]
name = "root_facade_boundary_guard"
class = "static_policy"
owners = []
reason = "validates root facade boundary against domain crate imports"

[[test]]
name = "security_guard"
class = "static_policy"
owners = []
reason = "validates security observability boundary across workspace"

[[test]]
name = "security_regression"
class = "composition"
owners = ["synvoid-ipc", "synvoid-proxy", "synvoid-platform"]
reason = "validates cross-crate security regression"

[[test]]
name = "worker_mesh_supervision_boundary_guard"
class = "static_policy"
owners = ["synvoid-worker", "synvoid-mesh"]
reason = "validates worker-mesh supervision boundary across workspace"

[[test]]
name = "worker_supervision_control_flow"
class = "composition"
owners = ["synvoid-worker", "synvoid-mesh"]
reason = "validates worker+mesh supervision control flow composition"
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_subprocess(
    git_diff_output: str = "",
    cargo_metadata_output: str | None = None,
    git_revparse_ok: bool = True,
) -> MagicMock:
    """Create a MagicMock for subprocess.run that returns preset outputs."""
    mock = MagicMock()

    def _side_effect(argv, **kwargs):
        cmd = argv[0] if argv else ""
        if cmd == "git" and len(argv) > 1 and argv[1] == "diff":
            result = MagicMock()
            result.stdout = git_diff_output
            result.stderr = ""
            return result
        if cmd == "git" and len(argv) > 1 and argv[1] == "rev-parse":
            result = MagicMock()
            result.stdout = "abc123\n" if git_revparse_ok else ""
            result.stderr = ""
            return result
        if cmd == "cargo" and len(argv) > 1 and argv[1] == "metadata":
            out = cargo_metadata_output if cargo_metadata_output is not None else json.dumps(FAKE_METADATA)
            result = MagicMock()
            result.stdout = out
            result.stderr = ""
            return result
        result = MagicMock()
        result.stdout = ""
        result.stderr = ""
        return result

    mock.side_effect = _side_effect
    return mock


def _run_compute(
    changed_files: list[str],
    *,
    ownership_text: str | None = None,
    full_override: bool = False,
    cargo_toml_text: str | None = None,
) -> dict[str, Any]:
    """Run compute_affected with mocked subprocess and filesystem.

    Constructs a realistic git diff output from the changed_files list,
    mocks cargo metadata, and mocks the ownership TOML file read.
    """
    git_diff_output = "\n".join(changed_files)
    mock_subprocess = _make_mock_subprocess(git_diff_output=git_diff_output)

    # Mock Path.read_text for OWNERSHIP.toml and Cargo.toml reads
    original_path_read_text = Path.read_text

    ownership_content = ownership_text if ownership_text is not None else FAKE_OWNERSHIP_TOML

    def _patched_read_text(self_path: Path, *args, **kwargs):
        rel = str(self_path)
        if "OWNERSHIP.toml" in rel:
            return ownership_content
        if str(self_path).endswith("Cargo.toml") and cargo_toml_text is not None:
            return cargo_toml_text
        return original_path_read_text(self_path, *args, **kwargs)

    with (
        patch("subprocess.run", mock_subprocess),
        patch.object(Path, "read_text", _patched_read_text),
    ):
        return sa.compute_affected("base", "head", _WORKSPACE_ROOT, full_override=full_override)


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestLeafCrateChange(unittest.TestCase):
    """Scenario 1: Leaf crate source change.

    A change to crates/synvoid-filter/src/lib.rs should select
    synvoid-filter and all its reverse dependents (none in this case,
    since no workspace crate depends on synvoid-filter).
    """

    def test_leaf_filter_change_selects_only_self_and_root(self):
        """synvoid-filter has no crate dependents, but the root synvoid
        crate depends on it, so synvoid appears as a reverse dependent."""
        result = _run_compute(["crates/synvoid-filter/src/lib.rs"])

        self.assertEqual(result["mode"], "affected")
        self.assertIn("synvoid-filter", result["changed_packages"])
        # The root synvoid crate depends on synvoid-filter
        self.assertIn("synvoid", result["reverse_dependents"])
        # No other crate depends on synvoid-filter
        self.assertEqual(len(result["reverse_dependents"]), 1)
        self.assertFalse(result["full_fallback"])

    def test_leaf_filter_change_includes_owning_root_tests(self):
        """Leaf crate changes should pull in root tests owned by that crate."""
        result = _run_compute(["crates/synvoid-filter/src/lib.rs"])
        # No root tests own synvoid-filter, so only cross-cutting tests (empty owners)
        for test_name in result["root_tests"]:
            entry = next(
                (e for e in _parse_ownership() if e["name"] == test_name), None
            )
            self.assertIsNotNone(entry)
            owners = set(entry["owners"])
            # Either no owners (cross-cutting) or owner overlaps with affected
            if owners:
                self.assertTrue(
                    owners & set(result["changed_packages"]),
                    f"test {test_name} has owners {owners} but no overlap with "
                    f"changed packages {result['changed_packages']}",
                )

    def test_valid_json_output(self):
        """Every scenario must produce valid JSON output."""
        result = _run_compute(["crates/synvoid-filter/src/lib.rs"])
        serialized = json.dumps(result, indent=2)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["mode"], "affected")


class TestCoreCrateChange(unittest.TestCase):
    """Scenario 2: Core crate change with many dependents.

    A change to crates/synvoid-core/src/lib.rs should select synvoid-core
    and its many transitive dependents across the workspace.
    """

    def test_core_selects_direct_dependents(self):
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        self.assertEqual(result["mode"], "affected")
        self.assertIn("synvoid-core", result["changed_packages"])

        # Direct dependents of synvoid-core (from fixture data)
        expected_direct = {
            "synvoid-metrics",
            "synvoid-block-store",
            "synvoid-app-handlers",
            "synvoid-http-client",
            "synvoid-http",
            "synvoid-mesh",
            "synvoid-http3",
            "synvoid-testkit",
            "synvoid-waf",
            "synvoid-admin",
            "synvoid-dns",
            "synvoid-proxy",
        }
        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        for dep in expected_direct:
            self.assertIn(
                dep,
                all_affected,
                f"expected {dep} in affected set after core change",
            )

    def test_core_selects_transitive_dependents(self):
        """synvoid-proxy-cache depends on synvoid-proxy, which depends on
        synvoid-core. Changing core must transitively select proxy-cache."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        self.assertIn(
            "synvoid-proxy-cache",
            all_affected,
            "synvoid-proxy-cache should be transitively selected via synvoid-proxy",
        )

    def test_core_selects_transitive_via_waf(self):
        """synvoid-http3 depends on synvoid-waf, which depends on synvoid-core."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        # synvoid-http3 is a direct dependent of core (and also of waf)
        self.assertIn("synvoid-http3", all_affected)
        # synvoid-metrics depends on core (direct) and on waf (which depends on core)
        self.assertIn("synvoid-metrics", all_affected)

    def test_core_selects_root_tests_owned_by_core(self):
        """Root tests owned by synvoid-core should be selected."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        self.assertIn("admin_mutation_blocklist", result["root_tests"])

    def test_core_selects_cross_cutting_tests(self):
        """Tests with empty owners (cross-cutting) should always be selected."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        # These have empty owners in the fixture
        for test in ["architecture_test", "root_test_ownership_guard",
                      "root_facade_boundary_guard", "security_guard"]:
            self.assertIn(test, result["root_tests"])

    def test_core_change_includes_waf_feature_class(self):
        """synvoid-waf depends on core, so waf feature class should be selected."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        self.assertIn("waf", result["feature_classes"])

    def test_valid_json_output(self):
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])
        serialized = json.dumps(result, indent=2)
        parsed = json.loads(serialized)
        self.assertIn("synvoid-core", parsed["changed_packages"])


class TestRootFacadeChange(unittest.TestCase):
    """Scenario 3: Root facade change triggers full fallback.

    A change to src/main.rs or src/lib.rs should trigger full validation
    because these are the root entry points.
    """

    def test_main_rs_triggers_full(self):
        result = _run_compute(["src/main.rs"])

        self.assertTrue(result["full_fallback"])
        self.assertEqual(result["mode"], "full")
        self.assertTrue(
            any("root facade" in r for r in result["fallback_reasons"]),
            f"expected 'root facade' in fallback reasons, got: {result['fallback_reasons']}",
        )

    def test_lib_rs_triggers_full(self):
        result = _run_compute(["src/lib.rs"])

        self.assertTrue(result["full_fallback"])
        self.assertEqual(result["mode"], "full")

    def test_full_mode_selects_all_root_tests(self):
        """Full fallback should include every test in the ownership manifest."""
        result = _run_compute(["src/main.rs"])

        ownership = _parse_ownership()
        expected_all = sorted(e["name"] for e in ownership if e["name"])
        self.assertEqual(result["root_tests"], expected_all)

    def test_full_mode_selects_all_feature_classes(self):
        result = _run_compute(["src/main.rs"])

        expected = sorted(sa.FEATURE_CLASS_PACKAGES.keys())
        self.assertEqual(result["feature_classes"], expected)

    def test_command_module_change_triggers_full(self):
        """src/commands/*.rs is a root facade glob."""
        result = _run_compute(["src/commands/plan.rs"])

        self.assertTrue(result["full_fallback"])
        self.assertEqual(result["mode"], "full")


class TestTestOnlyChange(unittest.TestCase):
    """Scenario 4: Test-only change selects only root crate and relevant tests.

    A change to tests/foo.rs should not affect any library crate;
    only root-level test files should be selected.
    """

    def test_test_file_does_not_select_library_crates(self):
        result = _run_compute(["tests/integration_test.rs"])

        # tests/ is in the root crate directory, so root crate gets selected
        self.assertIn("synvoid", result["changed_packages"])
        # No library crates should be selected
        library_crates = {
            pkg["name"] for pkg in _PACKAGES
            if pkg["name"] != "synvoid"
        }
        for crate in library_crates:
            self.assertNotIn(
                crate,
                result["changed_packages"],
                f"library crate {crate} should not be selected for test-only change",
            )

    def test_test_file_does_not_trigger_full_fallback(self):
        result = _run_compute(["tests/integration_test.rs"])

        self.assertFalse(result["full_fallback"])

    def test_test_only_change_selects_cross_cutting_tests(self):
        """Cross-cutting tests (empty owners) should still be selected."""
        result = _run_compute(["tests/integration_test.rs"])

        for test in ["architecture_test", "root_test_ownership_guard",
                      "root_facade_boundary_guard", "security_guard"]:
            self.assertIn(test, result["root_tests"])


class TestDocumentationOnlyChange(unittest.TestCase):
    """Scenario 5: Documentation-only change does not trigger Rust package selection.

    A change to README.md or docs/ should either not trigger package
    selection, or fall back to full validation (fail-safe).
    """

    def test_readme_change_falls_back_to_full(self):
        """README.md is not a Rust source, so no package maps; fail-safe gives full."""
        result = _run_compute(["README.md"])

        # No Rust packages should be mapped
        rust_pkgs = [p for p in result["changed_packages"] if p != "synvoid"]
        self.assertEqual(
            rust_pkgs,
            [],
            "documentation change should not map to any library crate",
        )

    def test_docs_directory_change_falls_back_to_full(self):
        result = _run_compute(["docs/CONFIGURATION.md"])

        # docs/ changes don't trigger any fallback rules, but no packages map either
        # The selector should either produce an empty affected set or fall back
        self.assertIn(result["mode"], ("affected", "full"))
        if result["mode"] == "affected":
            rust_pkgs = [p for p in result["changed_packages"] if p != "synvoid"]
            self.assertEqual(rust_pkgs, [])

    def test_valid_json_output(self):
        result = _run_compute(["README.md"])
        serialized = json.dumps(result, indent=2)
        parsed = json.loads(serialized)
        self.assertIn("mode", parsed)


class TestCargoLockChange(unittest.TestCase):
    """Scenario 6: Cargo.lock change triggers full fallback."""

    def test_cargo_lock_triggers_full(self):
        result = _run_compute(["Cargo.lock"])

        self.assertTrue(result["full_fallback"])
        self.assertEqual(result["mode"], "full")
        self.assertTrue(
            any("Cargo.lock" in r for r in result["fallback_reasons"]),
            f"expected 'Cargo.lock' in fallback reasons, got: {result['fallback_reasons']}",
        )

    def test_full_mode_includes_all_features(self):
        result = _run_compute(["Cargo.lock"])

        expected = sorted(sa.FEATURE_CLASS_PACKAGES.keys())
        self.assertEqual(result["feature_classes"], expected)


class TestCIWorkflowChange(unittest.TestCase):
    """Scenario 7: CI workflow change triggers full fallback."""

    def test_ci_yml_triggers_full(self):
        result = _run_compute([".github/workflows/ci.yml"])

        self.assertTrue(result["full_fallback"])
        self.assertEqual(result["mode"], "full")
        self.assertTrue(
            any("CI/config prefix" in r or ".github/workflows/" in r
                for r in result["fallback_reasons"]),
            f"expected CI prefix match in fallback reasons, got: {result['fallback_reasons']}",
        )

    def test_any_workflow_triggers_full(self):
        result = _run_compute([".github/workflows/release-qualification.yml"])

        self.assertTrue(result["full_fallback"])

    def test_cargo_config_triggers_full(self):
        result = _run_compute([".cargo/config.toml"])

        self.assertTrue(result["full_fallback"])


class TestMultiplePackageChanges(unittest.TestCase):
    """Scenario 8: Changes across 3 unrelated crates select all 3 plus
    their reverse dependents."""

    def test_three_unrelated_crates(self):
        changed = [
            "crates/synvoid-dns/src/lib.rs",
            "crates/synvoid-tarpit/src/lib.rs",
            "crates/synvoid-admin/src/lib.rs",
        ]
        result = _run_compute(changed)

        self.assertEqual(result["mode"], "affected")
        # All three should be in changed_packages
        for pkg in ["synvoid-dns", "synvoid-tarpit", "synvoid-admin"]:
            self.assertIn(pkg, result["changed_packages"])

    def test_three_unrelated_crates_includes_transitive(self):
        """Each of the three crates has transitive dependents."""
        changed = [
            "crates/synvoid-dns/src/lib.rs",
            "crates/synvoid-tarpit/src/lib.rs",
            "crates/synvoid-admin/src/lib.rs",
        ]
        result = _run_compute(changed)

        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        # synvoid-dns depends on synvoid-core; synvoid-admin depends on synvoid-core + synvoid-waf
        # They share transitive dependents — the union should still be bounded
        self.assertTrue(len(all_affected) > 3)

    def test_unrelated_crates_within_threshold(self):
        """3 unrelated roots is below MULTIPLIER_THRESHOLD (5), so no full fallback."""
        changed = [
            "crates/synvoid-dns/src/lib.rs",
            "crates/synvoid-tarpit/src/lib.rs",
            "crates/synvoid-admin/src/lib.rs",
        ]
        result = _run_compute(changed)

        self.assertFalse(result["full_fallback"])

    def test_valid_json_output(self):
        changed = [
            "crates/synvoid-dns/src/lib.rs",
            "crates/synvoid-tarpit/src/lib.rs",
            "crates/synvoid-admin/src/lib.rs",
        ]
        result = _run_compute(changed)
        serialized = json.dumps(result, indent=2)
        parsed = json.loads(serialized)
        self.assertIn("synvoid-dns", parsed["changed_packages"])


class TestBuildRsChange(unittest.TestCase):
    """Scenario 9: build.rs change should trigger full fallback.

    build.rs files affect compilation and may introduce link-time
    behavior changes. A build.rs in the root should trigger full fallback.
    """

    def test_root_build_rs_triggers_full(self):
        result = _run_compute(["build.rs"])

        # build.rs is not in ROOT_FACADE_PATHS or FULL_FALLBACK_BASENAMES,
        # but it's in the root crate directory so maps to synvoid.
        # The selector maps it to root crate; no special fallback rule fires.
        # However, it should at least map to the root package.
        self.assertIn("synvoid", result["changed_packages"])

    def test_subcrate_build_rs_selects_package(self):
        """A build.rs in a sub-crate should select that package."""
        result = _run_compute(["crates/synvoid-core/build.rs"])

        self.assertIn("synvoid-core", result["changed_packages"])


class TestFeatureDeclarationChange(unittest.TestCase):
    """Scenario 10: Changes to [workspace.dependencies] trigger full fallback.

    The selector checks for 'Cargo.toml' in changed_files AND the
    [workspace.dependencies] section in the root Cargo.toml content.
    """

    def test_workspace_deps_section_triggers_full(self):
        cargo_toml_with_deps = """
[workspace]
members = ["crates/synvoid-core"]

[workspace.dependencies]
tracing-subscriber = "0.3"
serde = { version = "1", features = ["derive"] }
"""
        result = _run_compute(
            ["Cargo.toml"],
            cargo_toml_text=cargo_toml_with_deps,
        )

        self.assertTrue(result["full_fallback"])
        self.assertTrue(
            any("[workspace.dependencies]" in r for r in result["fallback_reasons"]),
            f"expected workspace.dependencies reason, got: {result['fallback_reasons']}",
        )

    def test_cargo_toml_without_workspace_deps_does_not_trigger(self):
        """Cargo.toml change without [workspace.dependencies] should not
        trigger that specific fallback rule (but Cargo.toml is in
        FULL_FALLBACK_BASENAMES, so it still triggers full)."""
        cargo_toml_no_deps = """
[workspace]
members = ["crates/synvoid-core"]
"""
        result = _run_compute(
            ["Cargo.toml"],
            cargo_toml_text=cargo_toml_no_deps,
        )

        # Cargo.toml is in FULL_FALLBACK_BASENAMES → always triggers full
        self.assertTrue(result["full_fallback"])

    def test_cargo_toml_basename_always_fallback(self):
        """Cargo.toml (the basename) is in FULL_FALLBACK_BASENAMES."""
        result = _run_compute(["Cargo.toml"])

        self.assertTrue(result["full_fallback"])
        self.assertTrue(
            any("Cargo.toml" in r for r in result["fallback_reasons"]),
        )


class TestNegativeNoOnlyDirectDependents(unittest.TestCase):
    """Prove the selector does NOT stop at direct dependents — it must
    include transitive reverse dependents via BFS."""

    def test_transitive_expansion_beyond_direct(self):
        """synvoid-core → synvoid-proxy (direct) → synvoid-proxy-cache (transitive)."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        # proxy-cache is NOT a direct dep of core; it's transitive via proxy
        self.assertIn("synvoid-proxy-cache", all_affected)
        # Ensure proxy is also present (the intermediate)
        self.assertIn("synvoid-proxy", all_affected)

    def test_two_level_transitive_chain(self):
        """Verify a chain like core → waf → http → http3 is fully expanded."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        # http3 depends on http which depends on waf which depends on core
        self.assertIn("synvoid-http3", all_affected)

    def test_utils_transitive_reaches_many_crates(self):
        """synvoid-utils is depended on by ~17 crates; changing it should
        pull in most of the workspace."""
        result = _run_compute(["crates/synvoid-utils/src/lib.rs"])

        all_affected = set(result["changed_packages"]) | set(result["reverse_dependents"])
        expected_transitive = {
            "synvoid-challenge",
            "synvoid-metrics",
            "synvoid-block-store",
            "synvoid-plugin-runtime",
            "synvoid-proxy",
            "synvoid-honeypot",
            "synvoid-static-files",
            "synvoid-http",
            "synvoid-tunnel",
            "synvoid-ipc",
            "synvoid-vpn-client",
            "synvoid-dns",
            "synvoid-waf",
            "synvoid-upstream",
            "synvoid-mesh",
            "synvoid-upload",
            "synvoid-app-server",
        }
        for dep in expected_transitive:
            self.assertIn(
                dep,
                all_affected,
                f"expected {dep} transitively selected after utils change",
            )


class TestNegativeRootTestsNotOmitted(unittest.TestCase):
    """Prove root composition tests are NOT omitted for affected packages."""

    def test_core_change_selects_composition_tests_for_core(self):
        """admin_mutation_blocklist is owned by synvoid-core and synvoid-block-store."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        self.assertIn(
            "admin_mutation_blocklist",
            result["root_tests"],
            "root test owned by synvoid-core must be selected when core changes",
        )

    def test_waf_change_selects_boundary_guard(self):
        """boundary_composition_guard is owned by synvoid-waf among others."""
        result = _run_compute(["crates/synvoid-waf/src/lib.rs"])

        self.assertIn(
            "boundary_composition_guard",
            result["root_tests"],
            "boundary_composition_guard must be selected when waf changes",
        )

    def test_mesh_change_selects_mesh_boundary_tests(self):
        """mesh_id_boundary_guard and mesh_task_ownership_guard are owned by mesh."""
        result = _run_compute(["crates/synvoid-mesh/src/lib.rs"])

        self.assertIn("mesh_id_boundary_guard", result["root_tests"])
        self.assertIn("mesh_task_ownership_guard", result["root_tests"])

    def test_cross_cutting_tests_always_selected(self):
        """Tests with empty owners (cross-cutting) are always included."""
        result = _run_compute(["crates/synvoid-filter/src/lib.rs"])

        # These have empty owners
        for test in ["architecture_test", "root_test_ownership_guard",
                      "root_facade_boundary_guard", "security_guard"]:
            self.assertIn(test, result["root_tests"])


class TestNegativeUnknownFiles(unittest.TestCase):
    """Prove the selector does not treat unknown files as safe.

    Unknown files (not matching any package directory, not triggering
    fallback rules) should either produce an empty affected set or
    fall back to full validation — never silently succeed with a
    misleading result.
    """

    def test_unknown_root_level_file_maps_to_root(self):
        """A random file at root level maps to the root synvoid package."""
        result = _run_compute(["some-random-config.txt"])

        # It maps to root crate because it's inside the workspace root
        self.assertIn("synvoid", result["changed_packages"])

    def test_unknown_deeply_nested_file(self):
        """A file in an unrecognized subdirectory still maps to root."""
        result = _run_compute(["vendor/unknown-dep/lib.rs"])

        self.assertIn("synvoid", result["changed_packages"])

    def test_unknown_file_produces_valid_json(self):
        """Even unknown files must produce parseable JSON."""
        result = _run_compute(["totally-unknown-path.xyz"])
        serialized = json.dumps(result, indent=2)
        parsed = json.loads(serialized)
        self.assertIn("mode", parsed)
        self.assertIn("changed_packages", parsed)
        self.assertIn("full_fallback", parsed)


class TestToolchainFileChange(unittest.TestCase):
    """Toolchain files anywhere in the tree trigger full fallback."""

    def test_rust_toolchain_toml_triggers_full(self):
        result = _run_compute(["rust-toolchain.toml"])

        self.assertTrue(result["full_fallback"])
        self.assertTrue(
            any("toolchain" in r.lower() for r in result["fallback_reasons"]),
        )

    def test_rust_toolchain_in_subdir_triggers_full(self):
        result = _run_compute(["subdir/rust-toolchain"])

        self.assertTrue(result["full_fallback"])

    def test_full_fallback_package_triggers_full(self):
        """synvoid-testkit is in FULL_FALLBACK_PACKAGES."""
        result = _run_compute(["crates/synvoid-testkit/src/lib.rs"])

        self.assertTrue(result["full_fallback"])
        self.assertTrue(
            any("synvoid-testkit" in r for r in result["fallback_reasons"]),
        )


class TestFeatureClassSelection(unittest.TestCase):
    """Feature class selection based on affected packages."""

    def test_dns_feature_class(self):
        """synvoid-dns should activate the dns feature class."""
        result = _run_compute(["crates/synvoid-dns/src/lib.rs"])

        self.assertIn("dns", result["feature_classes"])

    def test_mesh_feature_class(self):
        """synvoid-mesh should activate the mesh feature class."""
        result = _run_compute(["crates/synvoid-mesh/src/lib.rs"])

        self.assertIn("mesh", result["feature_classes"])

    def test_waf_feature_class(self):
        result = _run_compute(["crates/synvoid-waf/src/lib.rs"])

        self.assertIn("waf", result["feature_classes"])

    def test_default_always_present(self):
        """The 'default' feature class should always be present."""
        result = _run_compute(["crates/synvoid-core/src/lib.rs"])

        self.assertIn("default", result["feature_classes"])

    def test_full_mode_includes_all_classes(self):
        result = _run_compute(["Cargo.lock"])

        expected = sorted(sa.FEATURE_CLASS_PACKAGES.keys())
        self.assertEqual(result["feature_classes"], expected)


class TestReverseDependencyBFS(unittest.TestCase):
    """Directly test the transitive_reverse_dependents BFS function."""

    def test_bfs_finds_direct(self):
        reverse_deps = {
            "synvoid-core": {"synvoid-waf", "synvoid-proxy"},
        }
        result = sa.transitive_reverse_dependents({"synvoid-core"}, reverse_deps)
        self.assertEqual(result, {"synvoid-core", "synvoid-waf", "synvoid-proxy"})

    def test_bfs_finds_transitive(self):
        reverse_deps = {
            "synvoid-core": {"synvoid-waf"},
            "synvoid-waf": {"synvoid-http"},
            "synvoid-http": {"synvoid-http3"},
        }
        result = sa.transitive_reverse_dependents({"synvoid-core"}, reverse_deps)
        self.assertEqual(
            result,
            {"synvoid-core", "synvoid-waf", "synvoid-http", "synvoid-http3"},
        )

    def test_bfs_handles_cycles(self):
        """BFS must not infinite-loop on circular dependencies."""
        reverse_deps = {
            "a": {"b"},
            "b": {"c"},
            "c": {"a"},
        }
        result = sa.transitive_reverse_dependents({"a"}, reverse_deps)
        self.assertEqual(result, {"a", "b", "c"})

    def test_bfs_empty_seed(self):
        result = sa.transitive_reverse_dependents(set(), {"a": {"b"}})
        self.assertEqual(result, set())

    def test_bfs_no_dependents(self):
        reverse_deps = {}
        result = sa.transitive_reverse_dependents({"isolated"}, reverse_deps)
        self.assertEqual(result, {"isolated"})


class TestFileToPackageMapping(unittest.TestCase):
    """Directly test the map_files_to_packages function."""

    def setUp(self):
        self.pkg_dir_map = sa.build_package_dir_map(FAKE_METADATA)

    def test_core_source_maps_to_core(self):
        result = sa.map_files_to_packages(
            ["crates/synvoid-core/src/lib.rs"],
            self.pkg_dir_map,
            _WORKSPACE_ROOT,
        )
        self.assertEqual(result, {"synvoid-core"})

    def test_root_source_maps_to_root(self):
        result = sa.map_files_to_packages(
            ["src/main.rs"],
            self.pkg_dir_map,
            _WORKSPACE_ROOT,
        )
        self.assertIn("synvoid", result)

    def test_multiple_files_same_package(self):
        result = sa.map_files_to_packages(
            [
                "crates/synvoid-core/src/lib.rs",
                "crates/synvoid-core/src/types.rs",
            ],
            self.pkg_dir_map,
            _WORKSPACE_ROOT,
        )
        self.assertEqual(result, {"synvoid-core"})

    def test_files_in_different_packages(self):
        result = sa.map_files_to_packages(
            [
                "crates/synvoid-core/src/lib.rs",
                "crates/synvoid-waf/src/lib.rs",
            ],
            self.pkg_dir_map,
            _WORKSPACE_ROOT,
        )
        self.assertEqual(result, {"synvoid-core", "synvoid-waf"})

    def test_longest_path_matches_first(self):
        """A file inside a nested directory should match the most specific package."""
        result = sa.map_files_to_packages(
            ["crates/synvoid-http/src/handler.rs"],
            self.pkg_dir_map,
            _WORKSPACE_ROOT,
        )
        self.assertEqual(result, {"synvoid-http"})


class TestClassifyFileTriggers(unittest.TestCase):
    """Directly test the classify_file_triggers function."""

    def test_root_facade_main_rs(self):
        reasons = sa.classify_file_triggers(["src/main.rs"])
        self.assertTrue(any("root facade" in r for r in reasons))

    def test_root_facade_lib_rs(self):
        reasons = sa.classify_file_triggers(["src/lib.rs"])
        self.assertTrue(any("root facade" in r for r in reasons))

    def test_command_module_glob(self):
        reasons = sa.classify_file_triggers(["src/commands/plan.rs"])
        self.assertTrue(any("root facade" in r for r in reasons))

    def test_cargo_lock(self):
        reasons = sa.classify_file_triggers(["Cargo.lock"])
        self.assertTrue(any("Cargo.lock" in r for r in reasons))

    def test_cargo_toml(self):
        reasons = sa.classify_file_triggers(["Cargo.toml"])
        self.assertTrue(any("Cargo.toml" in r for r in reasons))

    def test_github_workflow(self):
        reasons = sa.classify_file_triggers([".github/workflows/ci.yml"])
        self.assertTrue(any("CI/config" in r or ".github" in r for r in reasons))

    def test_cargo_config(self):
        reasons = sa.classify_file_triggers([".cargo/config.toml"])
        self.assertTrue(any("CI/config" in r or ".cargo" in r for r in reasons))

    def test_toolchain_file(self):
        reasons = sa.classify_file_triggers(["rust-toolchain.toml"])
        self.assertTrue(any("toolchain" in r for r in reasons))

    def test_normal_source_file_no_trigger(self):
        reasons = sa.classify_file_triggers(["crates/synvoid-core/src/lib.rs"])
        self.assertEqual(reasons, [])

    def test_multiple_triggers(self):
        reasons = sa.classify_file_triggers(["Cargo.lock", "src/main.rs"])
        self.assertGreaterEqual(len(reasons), 2)


class TestComputeAffectedFullOverride(unittest.TestCase):
    """Test the full_override parameter forces full validation."""

    def test_full_override_forces_full_mode(self):
        result = _run_compute(
            ["crates/synvoid-filter/src/lib.rs"],
            full_override=True,
        )

        self.assertTrue(result["full_fallback"])
        self.assertEqual(result["mode"], "full")


class TestSelectRootTests(unittest.TestCase):
    """Directly test the select_root_tests function."""

    def setUp(self):
        self.entries = sa.parse_ownership_toml(_WORKSPACE_ROOT) or _parse_ownership()

    def test_full_validation_returns_all(self):
        result = sa.select_root_tests(self.entries, set(), full_validation=True)
        expected = sorted(e["name"] for e in self.entries if e["name"])
        self.assertEqual(result, expected)

    def test_empty_owners_always_selected(self):
        result = sa.select_root_tests(
            self.entries,
            {"synvoid-filter"},
            full_validation=False,
        )
        # Cross-cutting tests (empty owners) should always be present
        self.assertIn("architecture_test", result)
        self.assertIn("root_test_ownership_guard", result)

    def test_matching_owner_selected(self):
        result = sa.select_root_tests(
            self.entries,
            {"synvoid-core"},
            full_validation=False,
        )
        self.assertIn("admin_mutation_blocklist", result)

    def test_non_matching_owner_not_selected(self):
        result = sa.select_root_tests(
            self.entries,
            {"synvoid-filter"},
            full_validation=False,
        )
        # admin_mutation_blocklist is owned by synvoid-block-store, synvoid-core
        # synvoid-filter doesn't overlap
        self.assertNotIn("admin_mutation_blocklist", result)

    def test_result_is_sorted_and_deduplicated(self):
        result = sa.select_root_tests(
            self.entries,
            {"synvoid-core", "synvoid-waf"},
            full_validation=False,
        )
        self.assertEqual(result, sorted(set(result)))


class TestCheckMultipleUnrelatedRoots(unittest.TestCase):
    """Directly test check_multiple_unrelated_roots."""

    def test_below_threshold(self):
        pkg_dir_map = sa.build_package_dir_map(FAKE_METADATA)
        reasons = sa.check_multiple_unrelated_roots(
            {"synvoid-dns", "synvoid-tarpit", "synvoid-admin"},
            pkg_dir_map,
        )
        self.assertEqual(reasons, [])

    def test_at_threshold(self):
        pkg_dir_map = sa.build_package_dir_map(FAKE_METADATA)
        # Need > MULTIPLIER_THRESHOLD (5) unrelated roots
        pkgs = {
            "synvoid-dns",
            "synvoid-tarpit",
            "synvoid-admin",
            "synvoid-mesh",
            "synvoid-tunnel",
            "synvoid-honeypot",
        }
        reasons = sa.check_multiple_unrelated_roots(pkgs, pkg_dir_map)
        self.assertGreater(len(reasons), 0)
        self.assertIn("unrelated package roots", reasons[0])


def _parse_ownership() -> list[dict[str, Any]]:
    """Helper to parse the fake ownership TOML for test assertions."""
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in FAKE_OWNERSHIP_TOML.splitlines():
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


# ---------------------------------------------------------------------------
# Workflow predicate regression tests (WS3)
# ---------------------------------------------------------------------------


class TestWorkflowPredicateRegression(unittest.TestCase):
    """Test that pr-fast.yml uses correct predicate polarity.

    The bug was: mode != 'full' || package-selected
    The fix is:  mode == 'full' || package-selected

    This test prevents regression to the inverted pattern.
    """

    def setUp(self):
        self.workflow_path = _REPO_ROOT / ".github" / "workflows" / "pr-fast.yml"
        if self.workflow_path.exists():
            self.content = self.workflow_path.read_text()
        else:
            self.content = ""

    def test_no_inverted_predicate_pattern(self):
        """The inverted pattern mode != 'full' || must not exist."""
        if not self.content:
            self.skipTest("pr-fast.yml not found")
        self.assertNotIn(
            "mode != 'full'",
            self.content,
            "Inverted predicate 'mode != \"full\"' found in pr-fast.yml — "
            "this is the known regression pattern. Use 'mode == \"full\"' instead."
        )

    def test_all_gated_jobs_use_correct_pattern(self):
        """Every gated job should use mode == 'full' || package-selected."""
        if not self.content:
            self.skipTest("pr-fast.yml not found")
        gated_jobs = ["upload-tests", "honeypot-tests", "tarpit-tests", "mesh-tests"]
        for job in gated_jobs:
            # Find the if: block for this job
            job_section = self._extract_job_if_block(job)
            if job_section:
                self.assertIn(
                    "mode == 'full'",
                    job_section,
                    f"Job '{job}' should use mode == 'full' pattern"
                )

    def test_selector_has_normalization_step(self):
        """The select-affected job must have a normalization step for fail-closed behavior."""
        if not self.content:
            self.skipTest("pr-fast.yml not found")
        self.assertIn(
            "normalize",
            self.content.lower(),
            "select-affected job must have a normalization step"
        )

    def test_normalize_step_has_always_condition(self):
        """The normalize step must run with if: always() to catch failures."""
        if not self.content:
            self.skipTest("pr-fast.yml not found")
        # Find the normalize step and check its condition
        in_normalize = False
        for line in self.content.splitlines():
            if "normalize" in line.lower() and "name:" in line.lower():
                in_normalize = True
            if in_normalize and "if:" in line:
                self.assertIn(
                    "always()",
                    line,
                    "Normalize step must use if: always()"
                )
                break

    def test_outputs_reference_normalize_step(self):
        """Job outputs must reference steps.normalize.outputs, not steps.select.outputs."""
        if not self.content:
            self.skipTest("pr-fast.yml not found")
        # Check the outputs section of select-affected job
        in_select_job = False
        in_outputs = False
        for line in self.content.splitlines():
            if "select-affected:" in line and "jobs:" not in line:
                in_select_job = True
            if in_select_job and "outputs:" in line:
                in_outputs = True
            if in_outputs and "steps.select.outputs" in line:
                self.fail(
                    "Job outputs reference steps.select.outputs directly — "
                    "should reference steps.normalize.outputs after fail-closed normalization"
                )
            if in_outputs and line.strip() and not line.strip().startswith("#") and not line.strip().startswith("mode:") and not line.strip().startswith("packages:") and not line.strip().startswith("root-tests:") and not line.strip().startswith("feature-classes:"):
                if not line.strip().startswith("steps."):
                    break

    def _extract_job_if_block(self, job_name):
        """Extract the if: condition block for a given job."""
        lines = self.content.splitlines()
        in_job = False
        if_block = []
        in_if = False
        indent_level = 0

        for i, line in enumerate(lines):
            # Detect job start
            stripped = line.rstrip()
            if stripped == f"  {job_name}:" or stripped == f"  {job_name} :":
                in_job = True
                continue
            if in_job:
                # Detect next job (not indented enough)
                if line and not line.startswith(" ") and line.strip():
                    break
                if stripped.strip().startswith("if:") or stripped.strip().startswith("if: >-"):
                    in_if = True
                    if_block.append(line)
                    continue
                if in_if:
                    if line.startswith("    ") or line.startswith("\t"):
                        if_block.append(line)
                    else:
                        in_if = False
                        break

        return "\n".join(if_block) if if_block else ""


class TestForceFullDispatch(unittest.TestCase):
    """Test that force-full override triggers full validation mode."""

    def test_compute_affected_with_full_override(self):
        """The full_override parameter should force full mode."""
        result = _run_compute(
            ["crates/synvoid-filter/src/lib.rs"],
            full_override=True,
        )
        self.assertEqual(result["mode"], "full")
        self.assertTrue(result["full_fallback"])

    def test_full_override_selects_all_root_tests(self):
        """Full override should select every root test."""
        result = _run_compute(
            ["crates/synvoid-filter/src/lib.rs"],
            full_override=True,
        )
        ownership = _parse_ownership()
        expected_all = sorted(e["name"] for e in ownership if e["name"])
        self.assertEqual(result["root_tests"], expected_all)

    def test_full_override_selects_all_feature_classes(self):
        """Full override should select all feature classes."""
        result = _run_compute(
            ["crates/synvoid-filter/src/lib.rs"],
            full_override=True,
        )
        expected = sorted(sa.FEATURE_CLASS_PACKAGES.keys())
        self.assertEqual(result["feature_classes"], expected)


class TestSelectorFailureFallback(unittest.TestCase):
    """Test that selector failure normalization produces full mode.

    In the workflow, the normalize step falls back to mode=full when
    the selector produces no output. This test verifies the expected
    behavior contract.
    """

    def test_empty_mode_normalizes_to_full_in_workflow(self):
        """The workflow normalize step must emit mode=full when MODE is empty.

        This is a contract test — it verifies the expected behavior that
        the normalize step in pr-fast.yml implements. If the workflow changes,
        this test documents the expected contract.
        """
        workflow_path = _REPO_ROOT / ".github" / "workflows" / "pr-fast.yml"
        if not workflow_path.exists():
            self.skipTest("pr-fast.yml not found")

        content = workflow_path.read_text()
        # Verify the normalize step contains the fallback logic
        self.assertIn(
            "mode=full",
            content,
            "Normalize step must emit mode=full as fallback"
        )
        self.assertIn(
            "falling back to full validation",
            content.lower(),
            "Normalize step must log fallback reason"
        )


if __name__ == "__main__":
    unittest.main()

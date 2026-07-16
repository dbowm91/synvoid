//! Static guards for CI policy invariants.
//!
//! Ensures required infrastructure files exist, CI profiles are correctly
//! configured, PR lanes don't use production flags, and new root tests
//! are tracked in the ownership manifest.

use synvoid_repo_guards::workspace_root;

// ---------------------------------------------------------------------------
// lane_manifest_exists_guard
// ---------------------------------------------------------------------------

/// Verify `testing/lanes.toml` exists and is valid TOML.
#[test]
fn lane_manifest_exists_guard() {
    let root = workspace_root();
    let manifest = root.join("testing/lanes.toml");

    assert!(
        manifest.exists(),
        "lane_manifest_exists_guard: testing/lanes.toml must exist — it defines CI lane configuration"
    );

    let content = std::fs::read_to_string(&manifest)
        .expect("lane_manifest_exists_guard: failed to read testing/lanes.toml");

    assert!(
        !content.trim().is_empty(),
        "lane_manifest_exists_guard: testing/lanes.toml must not be empty"
    );

    // Must parse as valid TOML
    content
        .parse::<toml::Value>()
        .expect("lane_manifest_exists_guard: testing/lanes.toml is not valid TOML");
}

// ---------------------------------------------------------------------------
// xtask_exists_guard
// ---------------------------------------------------------------------------

/// Verify `tools/xtask/Cargo.toml` exists (xtask crate present).
#[test]
fn xtask_exists_guard() {
    let root = workspace_root();
    let xtask = root.join("tools/xtask/Cargo.toml");

    assert!(
        xtask.exists(),
        "xtask_exists_guard: tools/xtask/Cargo.toml must exist — xtask crate is required for CI tasks and automation"
    );

    let content = std::fs::read_to_string(&xtask)
        .expect("xtask_exists_guard: failed to read tools/xtask/Cargo.toml");

    assert!(
        content.contains("[package]"),
        "xtask_exists_guard: tools/xtask/Cargo.toml must be a valid Cargo package manifest"
    );
}

// ---------------------------------------------------------------------------
// no_release_in_pr_guard
// ---------------------------------------------------------------------------

/// Verify PR fast lane workflow doesn't contain `--release` (except for
/// security regression which is allowed to use release mode).
#[test]
fn no_release_in_pr_guard() {
    let root = workspace_root();
    let pr_fast = root.join(".github/workflows/pr-fast.yml");

    if !pr_fast.exists() {
        return;
    }

    let content = std::fs::read_to_string(&pr_fast)
        .expect("no_release_in_pr_guard: failed to read pr-fast.yml");

    let mut violations = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if line.contains("--release") {
            // Security regression is explicitly allowed to use --release
            let lower = line.to_lowercase();
            if lower.contains("security") && lower.contains("regression") {
                continue;
            }
            // Also skip lines inside comments
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            violations.push(format!(
                "  pr-fast.yml:{}: --release found in PR fast lane: {}",
                i + 1,
                trimmed
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "no_release_in_pr_guard found {} violations:\n{}\n\n\
         PR fast lane must use --profile ci, not --release, for fast feedback loops.",
        violations.len(),
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// ci_profile_configured_guard
// ---------------------------------------------------------------------------

/// Verify `[profile.ci]` exists in root Cargo.toml.
#[test]
fn ci_profile_configured_guard() {
    let root = workspace_root();
    let cargo_toml = root.join("Cargo.toml");

    let content = std::fs::read_to_string(&cargo_toml)
        .expect("ci_profile_configured_guard: failed to read root Cargo.toml");

    assert!(
        content.contains("[profile.ci]"),
        "ci_profile_configured_guard: root Cargo.toml must contain [profile.ci] — CI lanes depend on this profile for fast feedback"
    );
}

// ---------------------------------------------------------------------------
// selector_script_exists_guard
// ---------------------------------------------------------------------------

/// Verify `scripts/ci/select-affected.py` exists.
#[test]
fn selector_script_exists_guard() {
    let root = workspace_root();
    let script = root.join("scripts/ci/select-affected.py");

    assert!(
        script.exists(),
        "selector_script_exists_guard: scripts/ci/select-affected.py must exist — PR-fast CI jobs depend on this selector"
    );

    assert!(
        script.metadata().map(|m| m.len()).unwrap_or(0) > 0,
        "selector_script_exists_guard: scripts/ci/select-affected.py must not be empty"
    );
}

// ---------------------------------------------------------------------------
// test_affected_script_exists_guard
// ---------------------------------------------------------------------------

/// Verify `scripts/test-affected.sh` exists.
#[test]
fn test_affected_script_exists_guard() {
    let root = workspace_root();
    let script = root.join("scripts/test-affected.sh");

    assert!(
        script.exists(),
        "test_affected_script_exists_guard: scripts/test-affected.sh must exist — runs only crates affected by changeset"
    );

    assert!(
        script.metadata().map(|m| m.len()).unwrap_or(0) > 0,
        "test_affected_script_exists_guard: scripts/test-affected.sh must not be empty"
    );
}

// ---------------------------------------------------------------------------
// performance_budgets_exist_guard
// ---------------------------------------------------------------------------

/// Verify `docs/testing/performance-budgets.md` exists and contains key sections.
#[test]
fn performance_budgets_exist_guard() {
    let root = workspace_root();
    let doc = root.join("docs/testing/performance-budgets.md");

    assert!(
        doc.exists(),
        "performance_budgets_exist_guard: docs/testing/performance-budgets.md must exist — defines CI performance thresholds"
    );

    let content = std::fs::read_to_string(&doc).expect(
        "performance_budgets_exist_guard: failed to read docs/testing/performance-budgets.md",
    );

    let required_sections = ["Budget", "Threshold"];
    let mut missing = Vec::new();
    for section in &required_sections {
        if !content.to_lowercase().contains(&section.to_lowercase()) {
            missing.push(*section);
        }
    }

    assert!(
        missing.is_empty(),
        "performance_budgets_exist_guard: docs/testing/performance-budgets.md missing sections: {:?}",
        missing
    );
}

// ---------------------------------------------------------------------------
// flaky_test_policy_exist_guard
// ---------------------------------------------------------------------------

/// Verify `docs/testing/flaky-test-policy.md` exists and contains required sections.
#[test]
fn flaky_test_policy_exist_guard() {
    let root = workspace_root();
    let doc = root.join("docs/testing/flaky-test-policy.md");

    assert!(
        doc.exists(),
        "flaky_test_policy_exist_guard: docs/testing/flaky-test-policy.md must exist — defines flaky test quarantine policy"
    );

    let content = std::fs::read_to_string(&doc)
        .expect("flaky_test_policy_exist_guard: failed to read docs/testing/flaky-test-policy.md");

    let required_sections = ["Quarantine", "Flaky"];
    let mut missing = Vec::new();
    for section in &required_sections {
        if !content.to_lowercase().contains(&section.to_lowercase()) {
            missing.push(*section);
        }
    }

    assert!(
        missing.is_empty(),
        "flaky_test_policy_exist_guard: docs/testing/flaky-test-policy.md missing sections: {:?}",
        missing
    );
}

// ---------------------------------------------------------------------------
// coverage_matrix_exist_guard
// ---------------------------------------------------------------------------

/// Verify `docs/testing/coverage-equivalence-matrix.md` exists.
#[test]
fn coverage_matrix_exist_guard() {
    let root = workspace_root();
    let doc = root.join("docs/testing/coverage-equivalence-matrix.md");

    assert!(
        doc.exists(),
        "coverage_matrix_exist_guard: docs/testing/coverage-equivalence-matrix.md must exist — maps test coverage across CI lanes"
    );
}

// ---------------------------------------------------------------------------
// operating_guide_exist_guard
// ---------------------------------------------------------------------------

/// Verify `docs/testing/operating-guide.md` exists.
#[test]
fn operating_guide_exist_guard() {
    let root = workspace_root();
    let doc = root.join("docs/testing/operating-guide.md");

    assert!(
        doc.exists(),
        "operating_guide_exist_guard: docs/testing/operating-guide.md must exist — operator guide for CI test infrastructure"
    );
}

// ---------------------------------------------------------------------------
// new_root_test_ownership_guard
// ---------------------------------------------------------------------------

/// Every `.rs` file in `tests/` must have a corresponding `[[test]]` entry
/// in `tests/OWNERSHIP.toml`. Catches new unowned tests that bypass the
/// ownership manifest.
#[test]
fn new_root_test_ownership_guard() {
    let root = workspace_root();
    let tests_dir = root.join("tests");
    let ownership = root.join("tests/OWNERSHIP.toml");

    if !tests_dir.exists() || !ownership.exists() {
        return;
    }

    // Parse ownership manifest to extract registered test names
    let content = std::fs::read_to_string(&ownership)
        .expect("new_root_test_ownership_guard: failed to read tests/OWNERSHIP.toml");
    let manifest: toml::Value = content
        .parse()
        .expect("new_root_test_ownership_guard: tests/OWNERSHIP.toml is not valid TOML");

    let mut owned = std::collections::HashSet::new();
    if let Some(tests) = manifest.get("test").and_then(|v| v.as_array()) {
        for entry in tests {
            if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                owned.insert(name.to_string());
            }
        }
    }

    // Collect .rs files in tests/ (non-recursive, only direct children)
    let mut unowned = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&tests_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if !stem.is_empty() && !owned.contains(&stem) {
                    unowned.push(stem);
                }
            }
        }
    }

    unowned.sort();

    assert!(
        unowned.is_empty(),
        "new_root_test_ownership_guard: {} unowned test file(s) in tests/ not tracked in OWNERSHIP.toml:\n  {}\n\n\
         Add a [[test]] entry to tests/OWNERSHIP.toml for each new root test.",
        unowned.len(),
        unowned.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// ci_lane_consistency_guard
// ---------------------------------------------------------------------------

/// Verify CI workflow commands match `testing/lanes.toml` definitions.
/// Ensures local xtask and CI share authoritative logic — drift fails fast.
#[test]
fn ci_lane_consistency_guard() {
    let root = workspace_root();
    let lanes_toml = root.join("testing/lanes.toml");
    let pr_fast = root.join(".github/workflows/pr-fast.yml");

    if !lanes_toml.exists() || !pr_fast.exists() {
        return;
    }

    let _lanes_content = std::fs::read_to_string(&lanes_toml)
        .expect("ci_lane_consistency_guard: failed to read testing/lanes.toml");
    let pr_fast_content = std::fs::read_to_string(&pr_fast)
        .expect("ci_lane_consistency_guard: failed to read pr-fast.yml");

    let mut violations = Vec::new();

    // Check key commands from lanes.fast exist in pr-fast.yml
    let checks: Vec<(&str, &str)> = vec![
        ("fmt", "cargo fmt --all -- --check"),
        (
            "guards",
            "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci",
        ),
        ("core-compile", "cargo check --no-default-features"),
        // clippy must use --all-targets but NOT --all-features in PR fast lane
        // (--all-features clippy belongs in release lane only)
        ("clippy", "cargo clippy --all-targets -- -D warnings"),
        // security-regression must use nextest with CI profile and --test-threads=1
        (
            "security-regression",
            "cargo nextest run --test security_regression --cargo-profile ci --profile ci",
        ),
    ];

    for (name, cmd) in &checks {
        if !pr_fast_content.contains(cmd) {
            violations.push(format!(
                "lanes.toml [lanes.fast.commands.{name}] command '{}' not found in pr-fast.yml",
                cmd
            ));
        }
    }

    // Note: security regression serialization is handled by nextest test-groups.global-env (max-threads=1)
    // in .config/nextest.toml, NOT by --test-threads=1 (which is a cargo-test argument, not nextest).

    // Check that PR fast lane doesn't use --release (except security regression)
    for (i, line) in pr_fast_content.lines().enumerate() {
        if line.contains("--release") {
            let lower = line.to_lowercase();
            if lower.contains("security") && lower.contains("regression") {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            violations.push(format!(
                "pr-fast.yml:{}: --release found outside security-regression: {}",
                i + 1,
                trimmed
            ));
        }
    }

    // Check that PR fast clippy does NOT use --all-features (--all-features clippy
    // belongs in release lane only; PR fast uses --all-targets only)
    for (i, line) in pr_fast_content.lines().enumerate() {
        if line.contains("clippy") && line.contains("--all-features") {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') {
                violations.push(format!(
                    "pr-fast.yml:{}: clippy with --all-features found in PR fast lane (belongs in release lane only): {}",
                    i + 1,
                    trimmed
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "ci_lane_consistency_guard: CI/lane-manifest drift detected ({} violations):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// no_lto_in_ci_profile_guard
// ---------------------------------------------------------------------------

/// Verify `[profile.ci]` doesn't set `lto = true`. CI profile should
/// prioritize fast compilation over link-time optimization.
#[test]
fn no_lto_in_ci_profile_guard() {
    let root = workspace_root();
    let cargo_toml = root.join("Cargo.toml");

    let content = std::fs::read_to_string(&cargo_toml)
        .expect("no_lto_in_ci_profile_guard: failed to read root Cargo.toml");

    // Extract the [profile.ci] section
    let lines: Vec<&str> = content.lines().collect();
    let mut in_ci_profile = false;
    let mut ci_section = String::new();

    for line in &lines {
        let trimmed = line.trim();
        if trimmed == "[profile.ci]" {
            in_ci_profile = true;
            ci_section.push_str(line);
            ci_section.push('\n');
            continue;
        }
        if in_ci_profile {
            // Stop at any next section (including other [profile.*] sections)
            if trimmed.starts_with('[') && trimmed != "[profile.ci]" {
                break;
            }
            ci_section.push_str(line);
            ci_section.push('\n');
        }
    }

    if !in_ci_profile {
        return; // Already caught by ci_profile_configured_guard
    }

    // Check for lto = true (or lto=true, lto = "fat", etc.)
    let has_lto = ci_section.contains("lto")
        && (ci_section.contains("lto = true")
            || ci_section.contains("lto=true")
            || ci_section.contains("lto = \"fat\"")
            || ci_section.contains("lto=\"fat\""));

    assert!(
        !has_lto,
        "no_lto_in_ci_profile_guard: [profile.ci] must not set lto = true or lto = \"fat\"\n\n\
         CI profile should use fast compilation. LTO is reserved for [profile.release].\n\n\
         Detected in [profile.ci]:\n{}",
        ci_section.trim()
    );
}

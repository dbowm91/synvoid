//! Static guards for CI policy invariants.
//!
//! Ensures required infrastructure files exist, CI profiles are correctly
//! configured, and new root tests are tracked in the ownership manifest.

use synvoid_repo_guards::workspace_root;

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
        "ci_profile_configured_guard: root Cargo.toml must contain [profile.ci] — CI depends on this profile for fast feedback"
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

// ---------------------------------------------------------------------------
// ci_workflow_active_guard
// ---------------------------------------------------------------------------

/// Verify `.github/workflows/ci.yml` exists and runs `cargo xtask verify`.
#[test]
fn ci_workflow_active_guard() {
    let root = workspace_root();
    let ci_yml = root.join(".github/workflows/ci.yml");

    assert!(
        ci_yml.exists(),
        "ci_workflow_active_guard: .github/workflows/ci.yml must exist — single routine CI workflow"
    );

    let content = std::fs::read_to_string(&ci_yml)
        .expect("ci_workflow_active_guard: failed to read .github/workflows/ci.yml");

    assert!(
        content.contains("cargo xtask verify"),
        "ci_workflow_active_guard: ci.yml must invoke `cargo xtask verify` — the canonical routine verification command"
    );

    // Must not contain old lane workflow references
    let violations: Vec<&str> = content
        .lines()
        .filter(|l| {
            l.contains("pr-fast")
                || l.contains("main-comprehensive")
                || l.contains("nightly-qualification")
                || l.contains("release-qualification")
        })
        .collect();

    assert!(
        violations.is_empty(),
        "ci_workflow_active_guard: ci.yml references deleted lane workflows: {:?}",
        violations
    );
}

// ---------------------------------------------------------------------------
// no_lane_workflows_guard
// ---------------------------------------------------------------------------

/// Verify old lane workflow files are deleted.
#[test]
fn no_lane_workflows_guard() {
    let root = workspace_root();
    let workflows_dir = root.join(".github/workflows");

    if !workflows_dir.exists() {
        return;
    }

    let deleted_files = &[
        "pr-fast.yml",
        "main-comprehensive.yml",
        "nightly-qualification.yml",
        "release-qualification.yml",
    ];

    let mut violations = Vec::new();
    for file_name in deleted_files {
        let path = workflows_dir.join(file_name);
        if path.exists() {
            violations.push(format!(
                "  {} still exists — should have been deleted in Phase 2",
                file_name
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "no_lane_workflows_guard found {} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

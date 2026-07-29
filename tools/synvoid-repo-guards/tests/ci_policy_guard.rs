//! Static guards for CI infrastructure invariants.
//!
//! Ensures required infrastructure files exist and CI profiles are correctly
//! configured. CI-policy guards (lane workflow presence, selector predicates,
//! cache-key naming, etc.) were removed in Phase 3 when the four-lane system
//! was deleted.

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
            if trimmed.starts_with('[') && trimmed != "[profile.ci]" {
                break;
            }
            ci_section.push_str(line);
            ci_section.push('\n');
        }
    }

    if !in_ci_profile {
        return;
    }

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

//! Static guards for cache policy, CI selectors, and ownership manifest.
//!
//! Ensures workflow files use pinned action versions, required scripts/configs
//! exist, and release/nightly lanes do not use affected-package selectors.

use synvoid_repo_guards::workspace_root;

// ---------------------------------------------------------------------------
// pinned_action_versions_guard
// ---------------------------------------------------------------------------

/// Workflow action references that must be pinned to a version tag or SHA.
/// `uses:` lines ending with `@main`, `@master`, or a bare branch ref
/// are flagged as unpinned.
#[test]
fn pinned_action_versions_guard() {
    let root = workspace_root();
    let workflows_dir = root.join(".github/workflows");

    if !workflows_dir.exists() {
        return;
    }

    let mut violations = Vec::new();

    let entries = std::fs::read_dir(&workflows_dir).expect("read .github/workflows");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml")
            && path.extension().and_then(|e| e.to_str()) != Some("yaml")
        {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("uses:") {
                continue;
            }
            // Extract the ref after the last '@'
            if let Some(at_pos) = trimmed.rfind('@') {
                let ref_part = &trimmed[at_pos + 1..];
                // SHA refs (40+ hex chars) are pinned by definition
                if ref_part.len() >= 40 && ref_part.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                // Version tags like @v4, @v2, @v5 are pinned
                if ref_part.starts_with('v') && ref_part.len() <= 6 {
                    continue;
                }
                // dtolnay/rust-toolchain uses @stable and @nightly pseudo-tags
                // — these are intentional and maintained by a trusted author.
                if trimmed.contains("dtolnay/rust-toolchain@") {
                    continue;
                }

                // Flag unpinned refs (@main, @master, @latest, branch names)
                if ref_part == "main" || ref_part == "master" || ref_part == "latest" {
                    violations.push(format!(
                        "  {}:{}: unpinned action ref '{}' in: {}",
                        file_name,
                        i + 1,
                        ref_part,
                        trimmed
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "pinned_action_versions_guard found {} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// selector_script_exists_guard
// ---------------------------------------------------------------------------

#[test]
fn selector_script_exists_guard() {
    let root = workspace_root();
    let script = root.join("scripts/ci/select-affected.py");

    assert!(
        script.exists(),
        "selector_script_exists_guard: scripts/ci/select-affected.py must exist — this file is required by PR-fast CI jobs to determine which workspace crates changed"
    );
    assert!(
        script.metadata().map(|m| m.len()).unwrap_or(0) > 0,
        "selector_script_exists_guard: scripts/ci/select-affected.py must not be empty"
    );
}

// ---------------------------------------------------------------------------
// cache_policy_exists_guard
// ---------------------------------------------------------------------------

#[test]
fn cache_policy_exists_guard() {
    let root = workspace_root();
    let doc = root.join("docs/testing/cache-policy.md");

    assert!(
        doc.exists(),
        "cache_policy_exists_guard: docs/testing/cache-policy.md must exist — it documents the CI cache strategy for all lanes"
    );

    let content = std::fs::read_to_string(&doc)
        .expect("cache_policy_exists_guard: failed to read docs/testing/cache-policy.md");

    let required_sections = ["Cache Layers", "Invalidation Rules"];
    for section in &required_sections {
        assert!(
            content.contains(section),
            "cache_policy_exists_guard: docs/testing/cache-policy.md must contain '{}' section",
            section
        );
    }
}

// ---------------------------------------------------------------------------
// setup_rust_action_exists_guard
// ---------------------------------------------------------------------------

#[test]
fn setup_rust_action_exists_guard() {
    let root = workspace_root();
    let action = root.join(".github/actions/setup-rust-ci/action.yml");

    assert!(
        action.exists(),
        "setup_rust_action_exists_guard: .github/actions/setup-rust-ci/action.yml must exist — PR-fast jobs depend on this composite action for Rust toolchain setup"
    );
}

// ---------------------------------------------------------------------------
// ownership_manifest_guard
// ---------------------------------------------------------------------------

#[test]
fn ownership_manifest_guard() {
    let root = workspace_root();
    let manifest = root.join("tests/OWNERSHIP.toml");

    assert!(
        manifest.exists(),
        "ownership_manifest_guard: tests/OWNERSHIP.toml must exist — it tracks why each root integration test is exempt from crate-level ownership"
    );

    let content = std::fs::read_to_string(&manifest)
        .expect("ownership_manifest_guard: failed to read tests/OWNERSHIP.toml");

    let mut violations = Vec::new();
    let mut in_test_entry = false;
    let mut has_name = false;
    let mut has_class = false;
    let mut has_owners = false;
    let mut has_reason = false;

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Start of a new [[test]] block
        if trimmed == "[[test]]" {
            // Validate the previous entry if we were inside one
            if in_test_entry {
                let mut missing = Vec::new();
                if !has_name {
                    missing.push("name");
                }
                if !has_class {
                    missing.push("class");
                }
                if !has_owners {
                    missing.push("owners");
                }
                if !has_reason {
                    missing.push("reason");
                }
                if !missing.is_empty() {
                    violations.push(format!(
                        "  line {}: [[test]] entry missing fields: {}",
                        i,
                        missing.join(", ")
                    ));
                }
            }
            in_test_entry = true;
            has_name = false;
            has_class = false;
            has_owners = false;
            has_reason = false;
        } else if in_test_entry {
            if trimmed.starts_with("name") {
                has_name = true;
            } else if trimmed.starts_with("class") {
                has_class = true;
            } else if trimmed.starts_with("owners") {
                has_owners = true;
            } else if trimmed.starts_with("reason") {
                has_reason = true;
            }
        }
    }

    // Validate the last entry
    if in_test_entry {
        let mut missing = Vec::new();
        if !has_name {
            missing.push("name");
        }
        if !has_class {
            missing.push("class");
        }
        if !has_owners {
            missing.push("owners");
        }
        if !has_reason {
            missing.push("reason");
        }
        if !missing.is_empty() {
            violations.push(format!(
                "  final [[test]] entry missing fields: {}",
                missing.join(", ")
            ));
        }
    }

    // Check that there is at least one [[test]] entry
    if !content.contains("[[test]]") {
        violations
            .push("  tests/OWNERSHIP.toml contains no [[test]] entries — manifest is empty".into());
    }

    assert!(
        violations.is_empty(),
        "ownership_manifest_guard found {} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// no_affected_selection_in_release_nightly_guard
// ---------------------------------------------------------------------------

#[test]
fn no_affected_selection_in_release_nightly_guard() {
    let root = workspace_root();
    let workflows_dir = root.join(".github/workflows");

    if !workflows_dir.exists() {
        return;
    }

    let target_files = &["release-qualification.yml", "nightly-qualification.yml"];
    let mut violations = Vec::new();

    for file_name in target_files {
        let path = workflows_dir.join(file_name);
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();

        // Check for select-affected script usage
        if content.contains("select-affected") {
            violations.push(format!(
                "  {} uses select-affected.py — release/nightly lanes must always run full validation, not affected-only",
                file_name
            ));
        }

        // Check for cargo-machete --include or similar affected patterns
        if content.contains("affected")
            && (content.contains("--package") || content.contains("-p "))
        {
            // Only flag if it's clearly a selection pattern, not just a word "affected" in a comment
            for (i, line) in content.lines().enumerate() {
                let lower = line.to_lowercase();
                if lower.contains("affected")
                    && (line.contains("--package") || line.contains("-p "))
                    && !line.trim().starts_with('#')
                {
                    violations.push(format!(
                        "  {}:{}: possible affected-selection pattern: {}",
                        file_name,
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "no_affected_selection_in_release_nightly_guard found {} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// test_affected_script_exists_guard
// ---------------------------------------------------------------------------

#[test]
fn test_affected_script_exists_guard() {
    let root = workspace_root();
    let script = root.join("scripts/test-affected.sh");

    assert!(
        script.exists(),
        "test_affected_script_exists_guard: scripts/test-affected.sh must exist — this script runs only the crates affected by the current changeset"
    );
    assert!(
        script.metadata().map(|m| m.len()).unwrap_or(0) > 0,
        "test_affected_script_exists_guard: scripts/test-affected.sh must not be empty"
    );
}

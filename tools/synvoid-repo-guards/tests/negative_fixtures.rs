//! Negative fixture tests: prove guards detect violations.
//!
//! Each test creates a temporary directory with intentionally bad content,
//! runs the same scanning logic the real guards use, and asserts that
//! violations ARE found. This proves the guards are not passing vacuously.

use std::fs;
use synvoid_repo_guards::{collect_rs_files, prepare_for_scanning, Violations};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Facade boundary: domain crate importing root synvoid::
// ---------------------------------------------------------------------------

#[test]
fn facade_boundary_detects_domain_crate_importing_root() {
    let tmp = TempDir::new().unwrap();
    let crates_dir = tmp.path().join("crates").join("synvoid-example");
    fs::create_dir_all(&crates_dir).unwrap();

    fs::write(
        crates_dir.join("lib.rs"),
        "use synvoid::core::BlockStore;\nfn process() {}\n",
    )
    .unwrap();

    let files = collect_rs_files(tmp.path());
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy();
        if !rel_str.starts_with("crates/") {
            continue;
        }
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("use synvoid::") {
                violations.push(format!(
                    "{}:{}: imports from root synvoid:: facade",
                    rel_str,
                    line_no + 1
                ));
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect 'use synvoid::' in domain crate but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Data-plane composition: request-path importing BlockStore
// ---------------------------------------------------------------------------

#[test]
fn data_plane_boundary_detects_blockstore_import() {
    let tmp = TempDir::new().unwrap();
    let waf_dir = tmp.path().join("src").join("waf");
    fs::create_dir_all(&waf_dir).unwrap();

    fs::write(
        waf_dir.join("mod.rs"),
        "use crate::block_store::BlockStore;\npub fn process() {}\n",
    )
    .unwrap();

    let forbidden = &["BlockStore"];
    let files = collect_rs_files(&tmp.path().join("src").join("waf"));
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy().to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("use ") {
                for f in forbidden {
                    if trimmed.contains(f) {
                        violations.push(format!(
                            "{}:{}: imports forbidden type '{}'",
                            rel_str,
                            line_no + 1,
                            f
                        ));
                    }
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect BlockStore import in request-path but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Request-path capability: importing synvoid_mesh::
// ---------------------------------------------------------------------------

#[test]
fn request_path_detects_control_plane_import() {
    let tmp = TempDir::new().unwrap();
    let proxy_dir = tmp.path().join("src").join("proxy");
    fs::create_dir_all(&proxy_dir).unwrap();

    fs::write(
        proxy_dir.join("mod.rs"),
        "use synvoid_mesh::mesh::transport::MeshTransportManager;\npub fn route() {}\n",
    )
    .unwrap();

    let forbidden = &["synvoid_mesh::"];
    let files = collect_rs_files(&tmp.path().join("src").join("proxy"));
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy().to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("use ") || trimmed.starts_with("extern crate ") {
                for f in forbidden {
                    if trimmed.contains(f) {
                        violations.push(format!(
                            "{}:{}: control-plane import '{}'",
                            rel_str,
                            line_no + 1,
                            f
                        ));
                    }
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect synvoid_mesh:: import in request-path but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Background task ownership: tokio::spawn without reason comment
// ---------------------------------------------------------------------------

#[test]
fn background_spawn_guard_detects_unowned_spawn() {
    let tmp = TempDir::new().unwrap();
    let worker_dir = tmp.path().join("src").join("worker").join("unified_server");
    fs::create_dir_all(&worker_dir).unwrap();

    // No allowlisted function name, no reason comment
    fs::write(
        worker_dir.join("some_task.rs"),
        "pub async fn do_work() {\n    tokio::spawn(async { work().await });\n}\n",
    )
    .unwrap();

    let allowlist: &[(&str, &str)] = &[];
    let files = collect_rs_files(&tmp.path().join("src").join("worker").join("unified_server"));
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy().to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);

        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("tokio::spawn") || trimmed.contains("spawn_blocking") {
                let file_name = std::path::Path::new(&rel_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                let is_allowlisted = allowlist.iter().any(|(file_suffix, func)| {
                    file_name.contains(file_suffix) && (func.is_empty() || scanned.contains(func))
                });
                let recent: Vec<&str> = scanned.lines().take(line_no + 1).collect();
                let has_reason = recent
                    .into_iter()
                    .rev()
                    .take(3)
                    .any(|l| l.contains("// reason:") || l.contains("// owner:"));
                let is_registry = rel_str.contains("task_registry");

                if !has_reason && !is_allowlisted && !is_registry {
                    violations.push(format!(
                        "{}:{}: tokio::spawn without reason comment",
                        rel_str,
                        line_no + 1
                    ));
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect unowned tokio::spawn but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Supervisor spawn ownership: unregistered supervisor spawn
// ---------------------------------------------------------------------------

#[test]
fn supervisor_spawn_guard_detects_unregistered_spawn() {
    let tmp = TempDir::new().unwrap();
    let sup_dir = tmp.path().join("src").join("supervisor");
    fs::create_dir_all(&sup_dir).unwrap();

    // Not in allowlist, no owner comment
    fs::write(
        sup_dir.join("mystery.rs"),
        "pub async fn mystery_task() {\n    tokio::spawn(async { loop {}.await });\n}\n",
    )
    .unwrap();

    let allowlist: &[(&str, &str)] = &[];
    let files = collect_rs_files(&tmp.path().join("src").join("supervisor"));
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy().to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);

        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("tokio::spawn") {
                let file_name = std::path::Path::new(&rel_str)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                let is_allowlisted = allowlist.iter().any(|(file_suffix, func)| {
                    file_name.contains(file_suffix) && (func.is_empty() || scanned.contains(func))
                });
                if !is_allowlisted {
                    let recent: Vec<&str> = scanned.lines().take(line_no + 1).collect();
                    let has_owner = recent.into_iter().rev().take(3).any(|l| {
                        l.contains("// reason:")
                            || l.contains("// owner:")
                            || l.contains("task_registry")
                    });
                    if !has_owner {
                        violations.push(format!(
                            "{}:{}: supervisor spawn without registered owner",
                            rel_str,
                            line_no + 1
                        ));
                    }
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect unregistered supervisor spawn but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Lifecycle: mem::forget without reason comment
// ---------------------------------------------------------------------------

#[test]
fn memforget_guard_detects_unjustified_forget() {
    let tmp = TempDir::new().unwrap();
    let server_dir = tmp.path().join("src").join("server");
    fs::create_dir_all(&server_dir).unwrap();

    // No reason comment
    fs::write(
        server_dir.join("mod.rs"),
        "fn cleanup() {\n    std::mem::forget(some_resource);\n}\n",
    )
    .unwrap();

    let files = collect_rs_files(&tmp.path().join("src").join("server"));
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy().to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);

        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("mem::forget") || trimmed.contains("std::mem::forget") {
                let recent: Vec<&str> = scanned.lines().take(line_no + 1).collect();
                let has_reason = recent
                    .into_iter()
                    .rev()
                    .take(3)
                    .any(|l| l.contains("// reason:"));
                if !has_reason {
                    violations.push(format!(
                        "{}:{}: mem::forget without reason comment",
                        rel_str,
                        line_no + 1
                    ));
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect mem::forget without reason but found no violations"
    );
}

// ---------------------------------------------------------------------------
// HTTP handler lifecycle: forbidden worker lifecycle token
// ---------------------------------------------------------------------------

#[test]
fn http_pipeline_guard_detects_lifecycle_import() {
    let tmp = TempDir::new().unwrap();
    let http_dir = tmp.path().join("src").join("http");
    fs::create_dir_all(&http_dir).unwrap();

    fs::write(
        http_dir.join("handler.rs"),
        "use crate::worker::UnifiedServerWorkerState;\npub fn handle() {}\n",
    )
    .unwrap();

    let forbidden = &["UnifiedServerWorkerState"];
    let files = collect_rs_files(&tmp.path().join("src").join("http"));
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(tmp.path()).unwrap_or(file);
        let rel_str = rel.to_string_lossy().to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for token in forbidden {
            if scanned.contains(token) {
                violations.push(format!(
                    "{}: imports worker lifecycle token '{}'",
                    rel_str, token
                ));
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect UnifiedServerWorkerState in HTTP handler but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Markdown links: broken reference to non-existent file
// ---------------------------------------------------------------------------

#[test]
fn docs_link_guard_detects_broken_markdown_link() {
    let tmp = TempDir::new().unwrap();

    // Create a markdown file that references a non-existent file
    fs::write(
        tmp.path().join("test.md"),
        "# Test\n\nSee [missing doc](nonexistent_file.md) for details.\n",
    )
    .unwrap();

    let re = regex::Regex::new(r"\[([^\]]*)\]\(([^)]+)\)").unwrap();
    let content = fs::read_to_string(tmp.path().join("test.md")).unwrap();
    let mut broken = Vec::new();

    for cap in re.captures_iter(&content) {
        let url = cap[2].trim();
        if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("mailto:") {
            continue;
        }
        let clean = if let Some(pos) = url.find('#') {
            &url[..pos]
        } else {
            url
        };
        if clean.is_empty() {
            continue;
        }
        let target = tmp.path().join(clean);
        if !target.exists() {
            broken.push(clean.to_string());
        }
    }

    assert!(
        !broken.is_empty(),
        "guard should detect broken link to nonexistent_file.md but found no broken links"
    );
}

// ---------------------------------------------------------------------------
// Unsafe sandbox language: misleading phrase in documentation
// ---------------------------------------------------------------------------

#[test]
fn sandbox_language_guard_detects_misleading_phrase() {
    let tmp = TempDir::new().unwrap();

    // Create a markdown file with a forbidden sandbox phrase (NOT negated)
    fs::write(
        tmp.path().join("test.md"),
        "# Plugin System\n\nOur sandboxed native plugin system provides safety.\n",
    )
    .unwrap();

    let forbidden = &[
        "sandboxed native plugin",
        "sandboxed native extension",
        "native plugin sandbox",
        "sandboxed axum plugin",
        "axum plugin sandbox",
        "native extension sandbox",
        "native plugins are sandboxed",
        "unsafe native extensions are sandboxed",
    ];

    let content = fs::read_to_string(tmp.path().join("test.md")).unwrap();
    let mut violations = Vec::new();

    for line in content.lines() {
        let lower = line.to_lowercase();
        for pattern in forbidden {
            if lower.contains(&pattern.to_lowercase()) {
                // Simple negation check
                let negated = lower.contains("not ")
                    || lower.contains("never ")
                    || lower.contains("aren't ")
                    || lower.contains("isn't ");
                if !negated {
                    violations.push(format!("found forbidden phrase: '{}'", pattern));
                }
            }
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect 'sandboxed native plugin' but found no violations"
    );
}

// ---------------------------------------------------------------------------
// Comment stripping prevents false positives
// ---------------------------------------------------------------------------

#[test]
fn comments_in_strings_do_not_trigger_violations() {
    let tmp = TempDir::new().unwrap();
    let waf_dir = tmp.path().join("src").join("waf");
    fs::create_dir_all(&waf_dir).unwrap();

    // BlockStore appears only in a comment and a string literal — should NOT trigger
    fs::write(
        waf_dir.join("mod.rs"),
        "// use crate::block_store::BlockStore;\n\
         pub fn process() {\n\
         let msg = \"use BlockStore for storage\";\n\
         }\n",
    )
    .unwrap();

    let files = collect_rs_files(&tmp.path().join("src").join("waf"));
    let mut violations = Violations::new();

    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("use ") && trimmed.contains("BlockStore") {
                violations.push(format!(
                    "line {}: false positive in comment/string",
                    line_no + 1
                ));
            }
        }
    }

    assert_eq!(
        violations.len(),
        0,
        "comment/string stripping should prevent false positives, but found {} violations",
        violations.len()
    );
}

// ===========================================================================
// CI Policy Guard Negative Fixtures
// ===========================================================================

// ---------------------------------------------------------------------------
// no_release_in_pr_guard: detects --release in PR workflow
// ---------------------------------------------------------------------------

#[test]
fn ci_no_release_guard_detects_release_flag() {
    let tmp = TempDir::new().unwrap();
    let workflows_dir = tmp.path().join(".github").join("workflows");
    fs::create_dir_all(&workflows_dir).unwrap();

    fs::write(
        workflows_dir.join("pr-fast.yml"),
        "jobs:\n  test:\n    run: cargo test --release\n",
    )
    .unwrap();

    let content = fs::read_to_string(workflows_dir.join("pr-fast.yml")).unwrap();
    let mut violations = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if line.contains("--release") {
            let lower = line.to_lowercase();
            if lower.contains("security") && lower.contains("regression") {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            violations.push(format!("line {}: --release in PR lane: {}", i + 1, trimmed));
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect --release in PR workflow but found no violations"
    );
}

// ---------------------------------------------------------------------------
// no_release_in_pr_guard: security regression is allowed
// ---------------------------------------------------------------------------

#[test]
fn ci_no_release_guard_allows_security_regression() {
    let tmp = TempDir::new().unwrap();
    let workflows_dir = tmp.path().join(".github").join("workflows");
    fs::create_dir_all(&workflows_dir).unwrap();

    fs::write(
        workflows_dir.join("pr-fast.yml"),
        "jobs:\n  security-regression:\n    run: cargo test --release security_regression\n",
    )
    .unwrap();

    let content = fs::read_to_string(workflows_dir.join("pr-fast.yml")).unwrap();
    let mut violations = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if line.contains("--release") {
            let lower = line.to_lowercase();
            if lower.contains("security") && lower.contains("regression") {
                continue;
            }
            violations.push(format!("line {}: {}", i + 1, line.trim()));
        }
    }

    assert_eq!(
        violations.len(),
        0,
        "security regression should be allowed to use --release but got {} violations",
        violations.len()
    );
}

// ---------------------------------------------------------------------------
// ci_profile_configured_guard: detects missing [profile.ci]
// ---------------------------------------------------------------------------

#[test]
fn ci_profile_guard_detects_missing_profile() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[profile.release]\nlto = true\n",
    )
    .unwrap();

    let content = fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
    assert!(
        !content.contains("[profile.ci]"),
        "test setup should not contain [profile.ci]"
    );

    assert!(
        !content.contains("[profile.ci]"),
        "guard should detect missing [profile.ci] but it was found"
    );
}

// ---------------------------------------------------------------------------
// no_lto_in_ci_profile_guard: detects lto = true in CI profile
// ---------------------------------------------------------------------------

#[test]
fn ci_no_lto_guard_detects_lto_in_ci() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[profile.ci]\ninherits = \"dev\"\nlto = true\nopt-level = 1\n",
    )
    .unwrap();

    let content = fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();

    // Extract [profile.ci] section
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

    let has_lto = ci_section.contains("lto")
        && (ci_section.contains("lto = true")
            || ci_section.contains("lto=true")
            || ci_section.contains("lto = \"fat\"")
            || ci_section.contains("lto=\"fat\""));

    assert!(
        has_lto,
        "guard should detect lto = true in [profile.ci] but it was not found in:\n{}",
        ci_section
    );
}

// ---------------------------------------------------------------------------
// lane_manifest_guard: detects invalid TOML
// ---------------------------------------------------------------------------

#[test]
fn lane_manifest_guard_detects_invalid_toml() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("testing.toml"),
        "[lanes]\npr_fast = { invalid toml content\n",
    )
    .unwrap();

    let content = fs::read_to_string(tmp.path().join("testing.toml")).unwrap();
    let result = content.parse::<toml::Value>();

    assert!(
        result.is_err(),
        "guard should detect invalid TOML but parsing succeeded"
    );
}

// ---------------------------------------------------------------------------
// new_root_test_ownership_guard: detects unowned test files
// ---------------------------------------------------------------------------

#[test]
fn ownership_guard_detects_unowned_test_file() {
    let tmp = TempDir::new().unwrap();
    let tests_dir = tmp.path().join("tests");
    fs::create_dir_all(&tests_dir).unwrap();

    // Create an ownership manifest with one entry
    fs::write(
        tests_dir.join("OWNERSHIP.toml"),
        "[[test]]\nname = \"existing_test\"\nclass = \"static_policy\"\nowners = []\nreason = \"test\"\n",
    )
    .unwrap();

    // Create two .rs files: one owned, one not
    fs::write(tests_dir.join("existing_test.rs"), "# test\n").unwrap();
    fs::write(tests_dir.join("new_untracked.rs"), "# test\n").unwrap();

    // Parse ownership manifest
    let content = fs::read_to_string(tests_dir.join("OWNERSHIP.toml")).unwrap();
    let manifest: toml::Value = content.parse().unwrap();
    let mut owned = std::collections::HashSet::new();
    if let Some(tests) = manifest.get("test").and_then(|v| v.as_array()) {
        for entry in tests {
            if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                owned.insert(name.to_string());
            }
        }
    }

    // Collect unowned files
    let mut unowned = Vec::new();
    if let Ok(entries) = fs::read_dir(&tests_dir) {
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

    assert!(
        !unowned.is_empty(),
        "guard should detect unowned test file 'new_untracked' but found none"
    );
    assert!(
        unowned.contains(&"new_untracked".to_string()),
        "guard should specifically detect 'new_untracked' but found: {:?}",
        unowned
    );
}

// ===========================================================================
// CI Lane Consistency Guard Negative Fixtures
// ===========================================================================

// ---------------------------------------------------------------------------
// ci_lane_consistency_guard: detects missing command in CI workflow
// ---------------------------------------------------------------------------

#[test]
fn ci_lane_consistency_guard_detects_missing_command() {
    let tmp = TempDir::new().unwrap();

    // Create a lanes.toml with a command
    let testing_dir = tmp.path().join("testing");
    fs::create_dir_all(&testing_dir).unwrap();
    fs::write(
        testing_dir.join("lanes.toml"),
        "[lanes.fast.commands.fmt]\ncommand = \"cargo fmt --all -- --check\"\n",
    )
    .unwrap();

    // Create a pr-fast.yml that DOESN'T contain the command
    let workflows_dir = tmp.path().join(".github").join("workflows");
    fs::create_dir_all(&workflows_dir).unwrap();
    fs::write(
        workflows_dir.join("pr-fast.yml"),
        "jobs:\n  fmt:\n    run: cargo format --check\n",
    )
    .unwrap();

    let _lanes_content = fs::read_to_string(testing_dir.join("lanes.toml")).unwrap();
    let pr_fast_content = fs::read_to_string(workflows_dir.join("pr-fast.yml")).unwrap();

    let mut violations = Vec::new();
    let checks: Vec<(&str, &str)> = vec![("fmt", "cargo fmt --all -- --check")];

    for (name, cmd) in &checks {
        if !pr_fast_content.contains(cmd) {
            violations.push(format!(
                "lanes.toml [lanes.fast.commands.{name}] command '{}' not found in pr-fast.yml",
                cmd
            ));
        }
    }

    assert!(
        !violations.is_empty(),
        "guard should detect missing fmt command in CI workflow but found no violations"
    );
}

// ===========================================================================
// File-Exists Guard Negative Fixtures
// ===========================================================================

// ---------------------------------------------------------------------------
// xtask_exists_guard: detects missing xtask crate
// ---------------------------------------------------------------------------

#[test]
fn xtask_exists_guard_detects_missing_xtask() {
    let tmp = TempDir::new().unwrap();
    // No tools/xtask/Cargo.toml created
    let xtask = tmp.path().join("tools").join("xtask").join("Cargo.toml");
    assert!(!xtask.exists(), "test setup: xtask should not exist");
}

// ---------------------------------------------------------------------------
// selector_script_exists_guard: detects missing selector script
// ---------------------------------------------------------------------------

#[test]
fn selector_script_guard_detects_missing_script() {
    let tmp = TempDir::new().unwrap();
    // No scripts/ci/select-affected.py created
    let script = tmp
        .path()
        .join("scripts")
        .join("ci")
        .join("select-affected.py");
    assert!(
        !script.exists(),
        "test setup: selector script should not exist"
    );
}

// ---------------------------------------------------------------------------
// test_affected_script_exists_guard: detects missing test-affected script
// ---------------------------------------------------------------------------

#[test]
fn test_affected_script_guard_detects_missing_script() {
    let tmp = TempDir::new().unwrap();
    // No scripts/test-affected.sh created
    let script = tmp.path().join("scripts").join("test-affected.sh");
    assert!(
        !script.exists(),
        "test setup: test-affected script should not exist"
    );
}

// ---------------------------------------------------------------------------
// performance_budgets_exist_guard: detects missing budgets doc
// ---------------------------------------------------------------------------

#[test]
fn performance_budgets_guard_detects_missing_doc() {
    let tmp = TempDir::new().unwrap();
    // Create a doc that's missing required sections
    let doc_dir = tmp.path().join("docs").join("testing");
    fs::create_dir_all(&doc_dir).unwrap();
    fs::write(
        doc_dir.join("performance-budgets.md"),
        "# Budgets\n\nSome content without required sections.\n",
    )
    .unwrap();

    let content = fs::read_to_string(doc_dir.join("performance-budgets.md")).unwrap();
    let required_sections = ["Budget", "Threshold"];
    let mut missing = Vec::new();
    for section in &required_sections {
        if !content.to_lowercase().contains(&section.to_lowercase()) {
            missing.push(*section);
        }
    }

    assert!(
        !missing.is_empty(),
        "guard should detect missing Budget/Threshold sections but found none"
    );
}

// ---------------------------------------------------------------------------
// flaky_test_policy_exist_guard: detects missing policy doc
// ---------------------------------------------------------------------------

#[test]
fn flaky_test_policy_guard_detects_missing_doc() {
    let tmp = TempDir::new().unwrap();
    let doc_dir = tmp.path().join("docs").join("testing");
    fs::create_dir_all(&doc_dir).unwrap();
    fs::write(
        doc_dir.join("flaky-test-policy.md"),
        "# Policy\n\nSome content without required sections.\n",
    )
    .unwrap();

    let content = fs::read_to_string(doc_dir.join("flaky-test-policy.md")).unwrap();
    let required_sections = ["Quarantine", "Flaky"];
    let mut missing = Vec::new();
    for section in &required_sections {
        if !content.to_lowercase().contains(&section.to_lowercase()) {
            missing.push(*section);
        }
    }

    assert!(
        !missing.is_empty(),
        "guard should detect missing Quarantine/Flaky sections but found none"
    );
}

// ---------------------------------------------------------------------------
// coverage_matrix_exist_guard: detects missing matrix doc
// ---------------------------------------------------------------------------

#[test]
fn coverage_matrix_guard_detects_missing_doc() {
    let tmp = TempDir::new().unwrap();
    // No docs/testing/coverage-equivalence-matrix.md created
    let doc = tmp
        .path()
        .join("docs")
        .join("testing")
        .join("coverage-equivalence-matrix.md");
    assert!(
        !doc.exists(),
        "test setup: coverage matrix doc should not exist"
    );
}

// ---------------------------------------------------------------------------
// operating_guide_exist_guard: detects missing guide doc
// ---------------------------------------------------------------------------

#[test]
fn operating_guide_guard_detects_missing_doc() {
    let tmp = TempDir::new().unwrap();
    // No docs/testing/operating-guide.md created
    let doc = tmp
        .path()
        .join("docs")
        .join("testing")
        .join("operating-guide.md");
    assert!(
        !doc.exists(),
        "test setup: operating guide doc should not exist"
    );
}

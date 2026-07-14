//! Static guards for root module ledger, facade boundary, and dependency ownership.
//!
//! These guards ensure:
//! - Every public root module in `src/lib.rs` is recorded in the ownership ledger
//! - Domain crates (`crates/`) do not import root `synvoid::` paths
//! - Root dependencies have ownership ledger entries

use std::collections::BTreeSet;
use std::fs;
use synvoid_repo_guards::{collect_source_files, workspace_root, Violations};

// ---------------------------------------------------------------------------
// root_module_ledger_guard
// ---------------------------------------------------------------------------

#[test]
fn root_exports_are_recorded_in_ownership_ledger() {
    let repo = workspace_root();
    let lib = fs::read_to_string(repo.join("src/lib.rs")).unwrap();
    let ledger = fs::read_to_string(repo.join("architecture/root_module_ledger.md")).unwrap();

    let mut missing = Vec::new();
    for line in lib.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            let name = rest
                .split(|c: char| c == ';' || c == '{' || c.is_whitespace())
                .next()
                .unwrap_or("");
            if name.is_empty() || name == "test_utils" {
                continue;
            }
            let needle = format!("| {} ", name);
            if !ledger.contains(&needle) {
                missing.push(name.to_string());
            }
        }
        if let Some(rest) = trimmed.strip_prefix("pub use synvoid_") {
            if let Some(as_pos) = rest.find(" as ") {
                let name = rest[as_pos + 4..]
                    .split(|c: char| c == ';' || c.is_whitespace())
                    .next()
                    .unwrap_or("");
                if !name.is_empty() {
                    let needle = format!("| {} ", name);
                    if !ledger.contains(&needle) {
                        missing.push(name.to_string());
                    }
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "root modules missing from architecture/root_module_ledger.md: {}",
        missing.join(", ")
    );
}

// ---------------------------------------------------------------------------
// root_facade_boundary_guard
// ---------------------------------------------------------------------------

/// Files in `crates/` that are exempt from the facade boundary because they
/// are the legacy root re-export facade itself or test utilities.
const FACADE_EXEMPT: &[&str] = &["crates/synvoid-testkit/"];

#[test]
fn domain_crates_do_not_import_root_facade() {
    let repo = workspace_root();
    let _crates_dir = repo.join("crates");
    let files = collect_source_files(&repo);
    let mut violations = Violations::new();

    for file in &files {
        let rel = file.strip_prefix(&repo).unwrap_or(file);
        let rel_str = rel.to_string_lossy();

        // Only scan crates/ files (not src/)
        if !rel_str.starts_with("crates/") {
            continue;
        }

        // Skip exempt files
        if FACADE_EXEMPT.iter().any(|e| rel_str.starts_with(e)) {
            continue;
        }

        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = synvoid_repo_guards::prepare_for_scanning(&content);

        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            // Check for `use synvoid::` imports
            if trimmed.contains("use synvoid::") {
                violations.push(format!(
                    "{}:{}: imports from root synvoid:: facade (domain crates must use narrow traits)",
                    rel_str,
                    line_no + 1
                ));
            }
        }
    }

    violations.assert_ok("root_facade_boundary_guard: domain crates must not import root facade");
}

// ---------------------------------------------------------------------------
// root_dependency_ownership_guard
// ---------------------------------------------------------------------------

fn root_manifest_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_root_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_root_deps = trimmed == "[dependencies]";
            continue;
        }
        if !in_root_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                deps.insert(name.to_string());
            }
        }
    }
    deps
}

fn root_build_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_build_deps = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_build_deps = trimmed == "[build-dependencies]";
            continue;
        }
        if !in_build_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                deps.insert(name.to_string());
            }
        }
    }
    deps
}

const VALID_CLASSIFICATIONS: &[&str] = &[
    "composition_runtime",
    "compat_facade",
    "migration_blocker",
    "test_or_tooling",
    "remove_candidate",
];

fn parse_ledger_entries(ledger: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in ledger.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| ") || !trimmed.ends_with(" |") {
            continue;
        }
        if trimmed.contains("---") || trimmed.contains("Dependency") {
            continue;
        }
        let cells: Vec<&str> = trimmed[2..trimmed.len() - 2]
            .split(" | ")
            .map(|s| s.trim())
            .collect();
        if cells.len() >= 3 {
            let dep_name = cells[0].to_string();
            let classification = cells[2].to_string();
            if !dep_name.starts_with('#') && !dep_name.is_empty() {
                entries.push((dep_name, classification));
            }
        }
    }
    entries
}

#[test]
fn root_dependencies_have_ownership_entries() {
    let repo = workspace_root();
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let deps = root_manifest_dependencies(&manifest);
    let mut missing = Vec::new();
    for dep in &deps {
        let needle = format!("| {} |", dep);
        if !ledger.contains(&needle) {
            missing.push(dep.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "root dependencies missing ownership ledger entries:\n{}",
        missing.join("\n")
    );
    for forbidden in ["TBD", "unknown", "fill me in"] {
        assert!(
            !ledger.contains(forbidden),
            "root dependency ledger contains placeholder: {forbidden}"
        );
    }
}

#[test]
fn ledger_entries_are_live() {
    let repo = workspace_root();
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let mut all_deps = root_manifest_dependencies(&manifest);
    all_deps.extend(root_build_dependencies(&manifest));

    let entries = parse_ledger_entries(&ledger);
    let mut stale = Vec::new();
    for (dep_name, classification) in &entries {
        if classification == "remove_candidate" {
            continue;
        }
        if !all_deps.contains(dep_name.as_str()) {
            stale.push(dep_name.clone());
        }
    }
    assert!(
        stale.is_empty(),
        "ledger entries for dependencies not in Cargo.toml (stale entries):\n{}",
        stale.join("\n")
    );
}

#[test]
fn ledger_classifications_are_valid() {
    let repo = workspace_root();
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let entries = parse_ledger_entries(&ledger);
    let mut invalid = Vec::new();
    for (dep_name, classification) in &entries {
        if !VALID_CLASSIFICATIONS.contains(&classification.as_str()) {
            invalid.push(format!(
                "{}: unknown classification '{}'",
                dep_name, classification
            ));
        }
    }
    assert!(
        invalid.is_empty(),
        "ledger entries with invalid classifications:\n{}",
        invalid.join("\n")
    );
}

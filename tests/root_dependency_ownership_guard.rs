use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

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
        if let Some((name, _rest)) = trimmed.split_once('=') {
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
        if let Some((name, _rest)) = trimmed.split_once('=') {
            let name = name.trim();
            if !name.is_empty() {
                deps.insert(name.to_string());
            }
        }
    }

    deps
}

/// Valid classification values for root dependency ownership.
const VALID_CLASSIFICATIONS: &[&str] = &[
    "composition_runtime",
    "compat_facade",
    "migration_blocker",
    "test_or_tooling",
    "remove_candidate",
];

/// Parse the ledger table and return (dependency_name, classification) pairs.
fn parse_ledger_entries(ledger: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in ledger.lines() {
        let trimmed = line.trim();
        // Ledger table rows start with "| " and end with " |"
        if !trimmed.starts_with("| ") || !trimmed.ends_with(" |") {
            continue;
        }
        // Skip header and separator rows
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
            // Skip section headers like "## Build Dependencies"
            if !dep_name.starts_with('#') && !dep_name.is_empty() {
                entries.push((dep_name, classification));
            }
        }
    }
    entries
}

#[test]
fn root_dependencies_have_ownership_entries() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

/// Every ledger entry must correspond to an actual direct dependency in
/// Cargo.toml (either `[dependencies]` or `[build-dependencies]`). Stale
/// entries silently mask removed dependencies.
///
/// Entries with classification `remove_candidate` are exempt — they document
/// dependencies that have already been removed from Cargo.toml.
#[test]
fn ledger_entries_are_live() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let mut all_deps = root_manifest_dependencies(&manifest);
    all_deps.extend(root_build_dependencies(&manifest));

    let entries = parse_ledger_entries(&ledger);
    let mut stale = Vec::new();

    for (dep_name, classification) in &entries {
        // remove_candidate entries document dependencies that were already removed
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

/// Every ledger entry must use a valid classification value. Unknown
/// classifications indicate documentation drift or typo.
#[test]
fn ledger_classifications_are_valid() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

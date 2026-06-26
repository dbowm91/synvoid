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

#[test]
fn root_dependencies_have_ownership_entries() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).expect("read Cargo.toml");
    let ledger = fs::read_to_string(repo.join("architecture/root_dependency_ownership.md"))
        .expect("read root dependency ownership ledger");

    let deps = root_manifest_dependencies(&manifest);
    let mut missing = Vec::new();

    for dep in deps {
        let needle = format!("| {} |", dep);
        if !ledger.contains(&needle) {
            missing.push(dep);
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

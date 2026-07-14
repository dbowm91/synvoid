//! Root-test ownership: STATIC_POLICY
//! Rationale: enforces that every root integration test has an explicit ownership entry

use std::collections::HashSet;
use std::fs;

const OWNERSHIP_FILE: &str = "tests/OWNERSHIP.toml";

#[test]
fn root_test_ownership_manifest_covers_all_tests() {
    let manifest = fs::read_to_string(OWNERSHIP_FILE).expect("tests/OWNERSHIP.toml must exist");

    let mut manifest_names = HashSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with("name = ") {
            let name = line
                .trim_start_matches("name = ")
                .trim_matches('"')
                .to_string();
            manifest_names.insert(name);
        }
    }

    let tests_dir = fs::read_dir("tests").expect("tests/ directory must exist");
    let mut root_test_names = HashSet::new();
    for entry in tests_dir {
        let entry = entry.expect("able to read dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            root_test_names.insert(name);
        }
    }

    let mut missing_from_manifest: Vec<_> = root_test_names
        .difference(&manifest_names)
        .cloned()
        .collect();
    missing_from_manifest.sort();

    let mut stale_in_manifest: Vec<_> = manifest_names
        .difference(&root_test_names)
        .cloned()
        .collect();
    stale_in_manifest.sort();

    assert!(
        missing_from_manifest.is_empty(),
        "Root test files without OWNERSHIP.toml entry: {:?}. \
         Every root test must have an explicit ownership entry.",
        missing_from_manifest
    );

    assert!(
        stale_in_manifest.is_empty(),
        "OWNERSHIP.toml entries for missing test files: {:?}. \
         Remove stale entries.",
        stale_in_manifest
    );
}

#[test]
fn root_test_ownership_manifest_no_domain_tests() {
    let manifest = fs::read_to_string(OWNERSHIP_FILE).expect("tests/OWNERSHIP.toml must exist");

    let mut domain_tests = Vec::new();
    let mut current_name = String::new();
    #[allow(unused_assignments)]
    let mut current_class = String::new();

    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with("name = ") {
            current_name = line
                .trim_start_matches("name = ")
                .trim_matches('"')
                .to_string();
        } else if line.starts_with("class = ") {
            current_class = line
                .trim_start_matches("class = ")
                .trim_matches('"')
                .to_string();
            if current_class == "domain" {
                domain_tests.push(current_name.clone());
            }
        }
    }

    assert!(
        domain_tests.is_empty(),
        "Domain-classified tests found in root OWNERSHIP.toml: {:?}. \
         Domain tests should be migrated to their owning crate.",
        domain_tests
    );
}

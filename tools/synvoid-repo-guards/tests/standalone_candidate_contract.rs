use serde::Deserialize;
use std::{collections::BTreeSet, fs, path::PathBuf};

#[derive(Deserialize)]
struct Registry {
    schema: String,
    #[serde(default)]
    candidates: Vec<Candidate>,
}
#[derive(Deserialize)]
struct Candidate {
    package: String,
    #[serde(default)]
    allowed_siblings: Vec<String>,
}

fn root() -> PathBuf {
    synvoid_repo_guards::workspace_root()
}

#[test]
fn registered_standalone_class2_candidates_obey_contract() {
    let root = root();
    let path = root.join("architecture/standalone_crate_candidates.toml");
    let registry: Registry = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(registry.schema, "synvoid.standalone-candidates.v1");
    let mut seen = BTreeSet::new();
    for candidate in registry.candidates {
        assert!(
            seen.insert(candidate.package.clone()),
            "duplicate candidate {}",
            candidate.package
        );
        assert!(
            candidate.package.starts_with("synvoid-"),
            "non-SynVoid candidate {}",
            candidate.package
        );
        let folder = candidate.package.strip_prefix("synvoid-").unwrap();
        let manifest_path = root.join("crates").join(folder).join("Cargo.toml");
        let manifest_text = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("{}: {e}", manifest_path.display()));
        let manifest: toml::Value = toml::from_str(&manifest_text).unwrap();
        let package = manifest
            .get("package")
            .and_then(toml::Value::as_table)
            .expect("[package]");
        for field in [
            "description",
            "license",
            "repository",
            "readme",
            "rust-version",
        ] {
            assert!(
                package
                    .get(field)
                    .and_then(toml::Value::as_str)
                    .is_some_and(|v| !v.is_empty()),
                "{} must declare package.{field}",
                candidate.package
            );
        }
        let metadata = package
            .get("metadata")
            .and_then(|v| v.get("synvoid"))
            .expect("[package.metadata.synvoid]");
        assert_eq!(
            metadata
                .get("standalone_class")
                .and_then(toml::Value::as_str),
            Some("class2")
        );
        assert_eq!(
            metadata
                .get("external_support")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
        assert_ne!(
            metadata.get("release_class").and_then(toml::Value::as_str),
            Some("class3"),
            "class-3 promotion requires the public-crate release process"
        );
        let allowed: BTreeSet<_> = candidate
            .allowed_siblings
            .iter()
            .map(String::as_str)
            .collect();
        if let Some(deps) = manifest.get("dependencies").and_then(toml::Value::as_table) {
            for dep in deps
                .keys()
                .filter(|name| name.starts_with("synvoid") && *name != "synvoid")
            {
                assert!(
                    allowed.contains(dep.as_str()),
                    "{} has undeclared normal SynVoid dependency {dep}",
                    candidate.package
                );
                assert!(
                    !["synvoid-config", "synvoid-core"].contains(&dep.as_str()),
                    "{} depends on application policy crate {dep}",
                    candidate.package
                );
            }
            assert!(
                !deps.contains_key("synvoid"),
                "{} depends on the root application",
                candidate.package
            );
        }
    }
}

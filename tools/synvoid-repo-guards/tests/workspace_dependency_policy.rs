use std::collections::BTreeSet;
use std::fs;
use synvoid_repo_guards::{workspace_root, Violations};

#[derive(serde::Deserialize)]
struct Policy {
    rules: Vec<Rule>,
}

#[derive(serde::Deserialize)]
struct Rule {
    package: String,
    forbidden: Vec<String>,
    reason: String,
}

#[test]
fn workspace_dependency_direction_policy() {
    let root = workspace_root();
    let policy: Policy = toml::from_str(
        &fs::read_to_string(root.join("architecture/workspace_dependency_policy.toml"))
            .expect("read dependency policy"),
    )
    .expect("parse dependency policy");
    let mut violations = Violations::new();
    for rule in policy.rules {
        let manifest_path = root.join(format!("crates/{}/Cargo.toml", rule.package));
        let manifest: toml::Value = toml::from_str(
            &fs::read_to_string(&manifest_path)
                .unwrap_or_else(|_| panic!("read {manifest_path:?}")),
        )
        .unwrap_or_else(|_| panic!("parse {manifest_path:?}"));
        let mut dependencies = BTreeSet::new();
        collect_dependencies(&manifest, &mut dependencies);
        for forbidden in rule.forbidden {
            if dependencies.contains(&forbidden) {
                violations.push(format!(
                    "{} -> {} forbidden by dependency policy: {}",
                    rule.package, forbidden, rule.reason
                ));
            }
        }
    }
    violations.assert_ok("workspace_dependency_direction_policy");
}

fn collect_dependencies(value: &toml::Value, found: &mut BTreeSet<String>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (section, contents) in table {
        if section == "dependencies" || section == "build-dependencies" {
            if let Some(deps) = contents.as_table() {
                found.extend(deps.keys().cloned());
            }
        }
        if section == "target" {
            collect_dependencies(contents, found);
        }
    }
}

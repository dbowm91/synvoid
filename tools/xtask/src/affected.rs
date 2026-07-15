use std::path::Path;
use std::process::Command;

use crate::lanes::Step;

/// Run the select-affected.py script and return the parsed JSON output.
pub fn run_selector(
    base_ref: &str,
    head_ref: &str,
    dry_run: bool,
    verbose: bool,
    workspace_root: &Path,
) -> Result<serde_json::Value, String> {
    let selector = workspace_root
        .join("scripts")
        .join("ci")
        .join("select-affected.py");

    if !selector.exists() {
        return Err(format!("selector script not found: {}", selector.display()));
    }

    let mut args = vec![
        selector.to_str().unwrap().to_string(),
        "--base".to_string(),
        base_ref.to_string(),
        "--head".to_string(),
        head_ref.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];

    if dry_run {
        args.push("--dry-run".to_string());
    }
    if verbose {
        args.push("--verbose".to_string());
    }

    let output = Command::new("python3")
        .args(&args)
        .output()
        .map_err(|e| format!("failed to run selector: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "selector failed (exit {}): {}",
            output.status.code().unwrap_or(1),
            stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout).map_err(|e| format!("failed to parse selector JSON: {e}"))
}

/// Build test steps from the affected selector output.
pub fn build_affected_steps(
    selector_output: &serde_json::Value,
    _workspace_root: &Path,
) -> Vec<Step> {
    let mut steps = Vec::new();

    // Combine changed_packages and reverse_dependents
    let mut all_packages: Vec<String> = Vec::new();
    if let Some(changed) = selector_output["changed_packages"].as_array() {
        for p in changed {
            if let Some(s) = p.as_str() {
                all_packages.push(s.to_string());
            }
        }
    }
    if let Some(rev_deps) = selector_output["reverse_dependents"].as_array() {
        for p in rev_deps {
            if let Some(s) = p.as_str() {
                if !all_packages.contains(&s.to_string()) {
                    all_packages.push(s.to_string());
                }
            }
        }
    }

    for pkg in &all_packages {
        steps.push(Step::new(
            Box::leak(pkg.clone().into_boxed_str()),
            "cargo nextest run -p <PKG> --cargo-profile ci --profile ci",
        ));
    }

    let root_tests = selector_output["root_tests"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for test in &root_tests {
        if let Some(name) = test.as_str() {
            steps.push(Step::new(
                Box::leak(name.to_string().into_boxed_str()),
                "cargo test --test <TEST>",
            ));
        }
    }

    // Feature class tests
    let feature_classes = selector_output["feature_classes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let feature_class_args: Vec<String> = feature_classes
        .iter()
        .filter_map(|fc| fc.as_str().map(String::from))
        .collect();

    if !feature_class_args.is_empty() {
        let features_flag = feature_class_args.join(",");
        steps.push(Step::new(
            "feature-classes",
            Box::leak(
                format!("cargo check --no-default-features --features {features_flag}")
                    .into_boxed_str(),
            ),
        ));
    }

    steps
}

/// Get the full command for a step, replacing placeholders.
pub fn resolve_command(step: &Step, base_ref: Option<&str>, package: Option<&str>) -> String {
    let mut cmd = step.command.to_string();

    if let Some(base) = base_ref {
        cmd = cmd.replace("<BASE_REF>", base);
    }
    if let Some(pkg) = package {
        cmd = cmd.replace("<PKG>", pkg);
        cmd = cmd.replace("<TEST>", pkg);
    }

    cmd
}

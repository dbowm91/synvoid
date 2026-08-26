use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::report::{LaneReport, StepResult, StepStatus};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Find workspace root by walking up to Cargo.toml with [workspace].
fn find_workspace_root() -> Result<std::path::PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| format!("failed to get cwd: {e}"))?;

    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)
                .map_err(|e| format!("failed to read {}: {e}", cargo_toml.display()))?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }

        dir = dir
            .parent()
            .ok_or("reached filesystem root without finding workspace Cargo.toml")?
            .to_path_buf();
    }
}

/// Run a single shell command. Returns (success, duration_ms).
fn run_command(cmd: &str, workspace_root: &Path, verbose: bool) -> (bool, u64) {
    let start = Instant::now();

    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(workspace_root)
        .status();

    let duration_ms = start.elapsed().as_millis() as u64;

    match status {
        Ok(s) => (s.success(), duration_ms),
        Err(e) => {
            if verbose {
                eprintln!("  failed to execute `{cmd}`: {e}");
            }
            (false, duration_ms)
        }
    }
}

/// Execute a named verification contract with fail-fast behavior.
fn run_contract(
    name: &str,
    steps: &[(&str, &str)],
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    let workspace_root = find_workspace_root()?;

    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask {name}");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    let mut report = LaneReport::new(name);

    for (step_name, cmd) in steps {
        if dry_run {
            let result = StepResult {
                name: step_name.to_string(),
                command: cmd.to_string(),
                status: StepStatus::DryRun,
                duration_ms: 0,
            };
            report.add_result(result);
            continue;
        }

        if verbose {
            println!("  → {cmd}");
        }

        let (success, duration_ms) = run_command(cmd, &workspace_root, verbose);
        let status = if success {
            StepStatus::Success
        } else {
            StepStatus::Failed
        };

        report.add_result(StepResult {
            name: step_name.to_string(),
            command: cmd.to_string(),
            status,
            duration_ms,
        });

        if !success && !dry_run {
            if !json_output {
                println!();
                println!("  ✗ Failed at step: {step_name}");
                println!("    Command: {cmd}");
            }
            break;
        }
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("{report}");
    }

    if !report.is_success() {
        return Err(format!("{} step(s) failed", report.failed));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Routine verification (what CI runs on every PR)
// ---------------------------------------------------------------------------

fn verify_steps() -> Vec<(&'static str, &'static str)> {
    vec![
        ("fmt", "cargo fmt --all -- --check"),
        (
            "clippy",
            "cargo clippy --profile ci --all-targets -- -D warnings",
        ),
        (
            "core-compile",
            "cargo check --no-default-features --profile ci",
        ),
        (
            "repo-guards",
            "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci",
        ),
        (
            "security-regression",
            "cargo test --test security_regression --profile ci -- --test-threads=1",
        ),
        (
            "root-guards",
            "cargo nextest run --cargo-profile ci --profile ci \
             --test boundary_composition_guard \
             --test lifecycle_task_guard \
             --test plugin_guard \
             --test cli_admin_guard \
             --test security_guard \
             --test root_facade_boundary_guard \
             --test mesh_id_boundary_guard \
             --test admin_mutation_response_guard \
             --test admin_mutation_blocklist \
             --test abi_memory_boundary_guard \
             --test root_test_ownership_guard \
             --test worker_mesh_supervision_boundary_guard \
             --test mesh_task_ownership_guard \
             --features mesh",
        ),
        (
            "core-admin-tests",
            "cargo nextest run -p synvoid-core --cargo-profile ci --profile ci \
             --test admin_auth_boundary \
             --test mesh_admin_edge_cases",
        ),
        (
            "failure-injection",
            "cargo test --test failure_injection --profile ci",
        ),
    ]
}

/// Run the canonical routine verification contract.
pub fn run_verify(dry_run: bool, json_output: bool, verbose: bool) -> Result<(), String> {
    run_contract("verify", &verify_steps(), dry_run, json_output, verbose)
}

// ---------------------------------------------------------------------------
// Full local verification (broader than routine, manually invoked)
//
// verify-full shares the cheap format/lint preflight with verify but does NOT
// re-run the routine test binaries. A single broad nextest invocation covers
// workspace tests, guard tests, security regression, and subsystem suites.
// ---------------------------------------------------------------------------

fn verify_full_steps() -> Vec<(&'static str, &'static str)> {
    vec![
        // Format + lint preflight (shared with routine, cheap)
        ("fmt", "cargo fmt --all -- --check"),
        (
            "clippy",
            "cargo clippy --profile ci --all-targets -- -D warnings",
        ),
        // Feature profile compilation
        (
            "profile-mesh",
            "cargo check --no-default-features --features mesh",
        ),
        (
            "profile-dns",
            "cargo check --no-default-features --features dns",
        ),
        (
            "profile-full",
            "cargo check --no-default-features --features mesh,dns",
        ),
        // Broad deterministic tests — covers workspace unit/integration,
        // guard tests, security regression, DNS, plugin-runtime, honeypot,
        // tarpit, and all other package tests in one invocation.
        (
            "nextest-all",
            "cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz",
        ),
        // Doctests
        ("doctests", "cargo test --workspace --doc --profile ci"),
    ]
}

/// Run full local verification (broader than routine, manually invoked).
pub fn run_verify_full(dry_run: bool, json_output: bool, verbose: bool) -> Result<(), String> {
    run_contract(
        "verify-full",
        &verify_full_steps(),
        dry_run,
        json_output,
        verbose,
    )
}

// ---------------------------------------------------------------------------
// Release verification (production artifacts + package inspection)
// ---------------------------------------------------------------------------

/// Crates that are explicitly not publishable (must match manifest `publish = false`).
const NONPUBLISHABLE: &[&str] = &["synvoid-fuzz", "xtask", "admin-ui", "synvoid-repo-guards"];

/// Example / demo crates that should never be published.
const EXAMPLE_CRATES: &[&str] = &["myapp-dynamic", "my-waf-app"];

/// Path-prohibited file patterns for package content inspection.
///
/// These are checked against normalized relative paths from `cargo package --list`.
/// Patterns use exact component or extension matching, not broad substring matching.
const PROHIBITED_PATH_PREFIXES: &[&str] = &["target/", ".git/", "fuzz/", "plans/", "corpus/"];

const PROHIBITED_BASENAMES: &[&str] = &[
    ".env",
    "credentials",
    "credentials.toml",
    "htpasswd",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
];

const PROHIBITED_EXTENSIONS: &[&str] = &[".key", ".pem", ".p12", ".pfx", ".keystore"];

// ---------------------------------------------------------------------------
// Release qualification types
// ---------------------------------------------------------------------------

/// Release qualification state for a publishable crate.
#[derive(Debug, Clone)]
enum CrateQualification {
    /// `cargo package --no-verify` succeeded.
    Assembled,
    /// `cargo package` (with verify) succeeded.
    PackagedSourceVerified,
    /// Registry qualification deferred until named publishable predecessors are published.
    DeferredOnInternalPredecessors { predecessors: Vec<String> },
    /// Cannot be published to crates.io (depends on non-publishable internal crate).
    NotPrepublishable { reason: String },
    /// Package step failed for an unexpected reason.
    Failed { phase: String, reason: String },
}

/// Dependency analysis for a publishable crate.
#[derive(Debug, Clone)]
struct CrateDepInfo {
    /// Normal/build dependencies that are publishable workspace crates.
    publishable_predecessors: Vec<String>,
    /// Normal/build dependencies that are non-publishable workspace crates.
    nonpublishable_deps: Vec<String>,
}

/// Summary of release qualification results (for JSON output).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ReleaseQualificationSummary {
    assembled: Vec<String>,
    packaged_source_verified: Vec<String>,
    deferred_on_predecessors: Vec<DeferredCrate>,
    not_prepublishable: Vec<NotPrepublishableCrate>,
    failed: Vec<FailedCrate>,
    publication_order: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeferredCrate {
    name: String,
    predecessors: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NotPrepublishableCrate {
    name: String,
    reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FailedCrate {
    name: String,
    phase: String,
    reason: String,
}

// ---------------------------------------------------------------------------
// Package content inspection
// ---------------------------------------------------------------------------

/// Check if a file path is prohibited in a published package.
fn is_prohibited_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");

    // Check path prefixes (directories)
    for prefix in PROHIBITED_PATH_PREFIXES {
        if normalized.starts_with(prefix) || normalized.contains(prefix) {
            return true;
        }
    }

    // Check basename patterns
    let basename = normalized.rsplit('/').next().unwrap_or(&normalized);
    for name in PROHIBITED_BASENAMES {
        if basename == *name || basename.starts_with(&format!("{name}.")) {
            return true;
        }
    }

    // Check extensions
    if let Some(dot_pos) = basename.rfind('.') {
        let ext = &basename[dot_pos..];
        for prohibited_ext in PROHIBITED_EXTENSIONS {
            if ext == *prohibited_ext {
                return true;
            }
        }
    }

    false
}

/// Check if a crate is nonpublishable by reading its Cargo.toml `publish` field.
///
/// This is a narrow manifest read for a field that cargo metadata does not
/// reliably expose for workspace-inherited packages.
fn is_publishable(crate_dir: &Path) -> bool {
    let cargo_toml = crate_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        return false;
    }
    let content = match std::fs::read_to_string(&cargo_toml) {
        Ok(c) => c,
        Err(_) => return false,
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "publish = false" || trimmed == "publish=false" {
            return false;
        }
    }
    true
}

/// Discover all publishable workspace crates using `cargo metadata`.
///
/// Returns a topologically sorted Vec of (package_name, manifest_dir_path).
/// Detects publishable crates that depend on nonpublishable internal crates
/// via path dependencies — such dependencies cannot resolve from crates.io.
fn discover_publishable_crates(workspace_root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run cargo metadata: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse cargo metadata: {e}"))?;

    let workspace_members: Vec<String> = metadata["workspace_members"]
        .as_array()
        .ok_or("missing workspace_members in metadata")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing packages in metadata")?;

    // Classify each workspace member
    let mut publishable = Vec::new();
    let mut all_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for member_id in &workspace_members {
        let pkg = packages
            .iter()
            .find(|p| p["id"].as_str() == Some(member_id))
            .ok_or_else(|| format!("package not found for member: {member_id}"))?;

        let name = pkg["name"]
            .as_str()
            .ok_or("missing package name")?
            .to_string();
        let manifest_path = pkg["manifest_path"]
            .as_str()
            .ok_or("missing manifest_path")?
            .to_string();
        let manifest_dir = PathBuf::from(&manifest_path)
            .parent()
            .ok_or("invalid manifest_path")?
            .to_path_buf();

        all_names.insert(name.clone());

        // Skip nonpublishable and example crates
        if NONPUBLISHABLE.contains(&name.as_str()) || EXAMPLE_CRATES.contains(&name.as_str()) {
            continue;
        }

        if !is_publishable(&manifest_dir) {
            continue;
        }

        publishable.push((name, manifest_dir));
    }

    // Topological sort with dependency validation
    let mut sorted = Vec::new();
    let mut visited = std::collections::HashSet::new();

    fn visit(
        name: &str,
        packages: &[serde_json::Value],
        all_names: &std::collections::HashSet<String>,
        visited: &mut std::collections::HashSet<String>,
        sorted: &mut Vec<(String, PathBuf)>,
        nonpublishable: &[&str],
        examples: &[&str],
    ) -> Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        visited.insert(name.to_string());

        let pkg = packages
            .iter()
            .find(|p| p["name"].as_str() == Some(name))
            .ok_or_else(|| format!("package not found: {name}"))?;

        // Visit path dependencies first
        if let Some(deps) = pkg["dependencies"].as_array() {
            for dep in deps {
                if let Some(_path) = dep["path"].as_str() {
                    let dep_name = dep["name"].as_str().unwrap_or("");
                    let is_internal = nonpublishable.contains(&dep_name)
                        || examples.contains(&dep_name)
                        || !all_names.contains(dep_name);

                    if is_internal {
                        // A publishable crate depends on a nonpublishable crate
                        // via path — this cannot resolve from crates.io.
                        return Err(format!(
                            "publishable crate `{name}` depends on nonpublishable \
                             internal crate `{dep_name}` via path dependency — this \
                             cannot be published to crates.io"
                        ));
                    }

                    visit(
                        dep_name,
                        packages,
                        all_names,
                        visited,
                        sorted,
                        nonpublishable,
                        examples,
                    )?;
                }
            }
        }

        let manifest_path = pkg["manifest_path"]
            .as_str()
            .ok_or("missing manifest_path")?
            .to_string();
        let manifest_dir = PathBuf::from(&manifest_path)
            .parent()
            .ok_or("invalid manifest_path")?
            .to_path_buf();

        sorted.push((name.to_string(), manifest_dir));
        Ok(())
    }

    for member_id in &workspace_members {
        let pkg = packages
            .iter()
            .find(|p| p["id"].as_str() == Some(member_id))
            .ok_or_else(|| format!("package not found for member: {member_id}"))?;
        let name = pkg["name"]
            .as_str()
            .ok_or("missing package name")?
            .to_string();

        if NONPUBLISHABLE.contains(&name.as_str()) || EXAMPLE_CRATES.contains(&name.as_str()) {
            continue;
        }

        if !is_publishable(
            Path::new(
                pkg["manifest_path"]
                    .as_str()
                    .ok_or("missing manifest_path")?,
            )
            .parent()
            .unwrap(),
        ) {
            continue;
        }

        visit(
            &name,
            packages,
            &all_names,
            &mut visited,
            &mut sorted,
            NONPUBLISHABLE,
            EXAMPLE_CRATES,
        )?;
    }

    Ok(sorted)
}

// ---------------------------------------------------------------------------
// Dependency graph and cycle detection
// ---------------------------------------------------------------------------

/// Build a dependency graph for publishable crates.
///
/// For each publishable crate, classifies its normal/build path dependencies as
/// either publishable predecessors or non-publishable internal dependencies.
/// Dev-dependencies are excluded because they follow Cargo publication rules.
fn build_publishable_dependency_graph(
    metadata: &serde_json::Value,
    publishable_names: &std::collections::HashSet<String>,
    nonpublishable_names: &std::collections::HashSet<String>,
) -> Result<std::collections::HashMap<String, CrateDepInfo>, String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing packages in metadata")?;

    let mut graph = std::collections::HashMap::new();

    for name in publishable_names {
        let pkg = packages
            .iter()
            .find(|p| p["name"].as_str() == Some(name.as_str()))
            .ok_or_else(|| format!("package not found: {name}"))?;

        let mut publishable_predecessors = Vec::new();
        let mut nonpublishable_deps = Vec::new();

        if let Some(deps) = pkg["dependencies"].as_array() {
            for dep in deps {
                let dep_name = dep["name"].as_str().unwrap_or("");

                // Only check normal and build dependencies (dev-dependencies
                // follow Cargo publication rules and are excluded from resolution).
                let dep_kind = dep["kind"].as_str().unwrap_or("normal");
                if dep_kind == "dev" {
                    continue;
                }

                // Only check workspace path dependencies
                if dep["path"].is_null() {
                    continue;
                }

                if publishable_names.contains(dep_name) {
                    publishable_predecessors.push(dep_name.to_string());
                } else if nonpublishable_names.contains(dep_name) {
                    nonpublishable_deps.push(dep_name.to_string());
                }
            }
        }

        graph.insert(
            name.clone(),
            CrateDepInfo {
                publishable_predecessors,
                nonpublishable_deps,
            },
        );
    }

    Ok(graph)
}

/// Detect cycles in the publishable dependency graph.
///
/// Returns an error if any cycle is found, naming one of the crates involved.
fn detect_cycles(graph: &std::collections::HashMap<String, CrateDepInfo>) -> Result<(), String> {
    let mut visited = std::collections::HashSet::new();
    let mut in_stack = std::collections::HashSet::new();

    fn dfs(
        node: &str,
        graph: &std::collections::HashMap<String, CrateDepInfo>,
        visited: &mut std::collections::HashSet<String>,
        in_stack: &mut std::collections::HashSet<String>,
    ) -> Result<(), String> {
        if in_stack.contains(node) {
            return Err(format!("cycle detected involving crate `{node}`"));
        }
        if visited.contains(node) {
            return Ok(());
        }

        visited.insert(node.to_string());
        in_stack.insert(node.to_string());

        if let Some(info) = graph.get(node) {
            for pred in &info.publishable_predecessors {
                dfs(pred, graph, visited, in_stack)?;
            }
        }

        in_stack.remove(node);
        Ok(())
    }

    for node in graph.keys() {
        dfs(node, graph, &mut visited, &mut in_stack)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Package assembly and source verification helpers
// ---------------------------------------------------------------------------

/// Attempt `cargo package --no-verify` for a crate.
fn attempt_assembly(
    name: &str,
    allow_dirty: bool,
    verbose: bool,
    workspace_root: &Path,
) -> CrateQualification {
    if verbose {
        println!("  → cargo package --no-verify -p {name}");
    }

    let mut args = vec!["package", "--no-verify", "-p", name];
    if allow_dirty {
        args.push("--allow-dirty");
    }
    let output = Command::new("cargo")
        .args(&args)
        .current_dir(workspace_root)
        .output();

    match output {
        Ok(out) if out.status.success() => CrateQualification::Assembled,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            CrateQualification::Failed {
                phase: "assembly".to_string(),
                reason: stderr.to_string(),
            }
        }
        Err(e) => CrateQualification::Failed {
            phase: "assembly".to_string(),
            reason: e.to_string(),
        },
    }
}

/// Attempt `cargo package` (with verify) for a crate.
fn attempt_source_verification(
    name: &str,
    allow_dirty: bool,
    verbose: bool,
    workspace_root: &Path,
) -> CrateQualification {
    if verbose {
        println!("  → cargo package -p {name}");
    }

    let mut args = vec!["package", "-p", name];
    if allow_dirty {
        args.push("--allow-dirty");
    }
    let output = Command::new("cargo")
        .args(&args)
        .current_dir(workspace_root)
        .output();

    match output {
        Ok(out) if out.status.success() => CrateQualification::PackagedSourceVerified,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            CrateQualification::Failed {
                phase: "source-verification".to_string(),
                reason: stderr.to_string(),
            }
        }
        Err(e) => CrateQualification::Failed {
            phase: "source-verification".to_string(),
            reason: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Metadata validation
// ---------------------------------------------------------------------------

/// Validate metadata for all publishable crates.
fn validate_package_metadata(
    publishable: &[(String, PathBuf)],
    workspace_root: &Path,
) -> Result<(), String> {
    let mut issues: Vec<String> = Vec::new();

    for (name, manifest_dir) in publishable {
        let cargo_toml = manifest_dir.join("Cargo.toml");
        let content = match std::fs::read_to_string(&cargo_toml) {
            Ok(c) => c,
            Err(e) => {
                issues.push(format!("{name}: cannot read {}: {e}", cargo_toml.display()));
                continue;
            }
        };

        let has_description = content.lines().any(|l| l.trim().starts_with("description"));
        let has_license = content.lines().any(|l| {
            let t = l.trim();
            t.starts_with("license") || t.starts_with("license-file")
        });

        if !has_description {
            issues.push(format!("{name}: missing `description` field"));
        }
        if !has_license {
            let root_cargo = workspace_root.join("Cargo.toml");
            let root_content = std::fs::read_to_string(&root_cargo).unwrap_or_default();
            if !root_content.contains("[workspace.package]") || !root_content.contains("license") {
                issues.push(format!(
                    "{name}: missing `license` field (no workspace fallback)"
                ));
            }
        }

        // Check that referenced readme file exists
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("readme") {
                if let Some(start) = trimmed.find('"') {
                    if let Some(end) = trimmed[start + 1..].find('"') {
                        let readme_path = manifest_dir.join(&trimmed[start + 1..start + 1 + end]);
                        if !readme_path.exists() {
                            issues.push(format!(
                                "{name}: referenced readme does not exist: {}",
                                readme_path.display()
                            ));
                        }
                    }
                }
            }
        }
    }

    if !issues.is_empty() {
        return Err(format!(
            "{} package metadata issue(s) found:\n  {}",
            issues.len(),
            issues.join("\n  ")
        ));
    }

    Ok(())
}

/// Validate that internal path dependencies use compatible semver requirements.
///
/// Uses cargo metadata's parsed `req` field rather than substring extraction.
/// Rejects missing version requirements and `*` (unless explicitly allowlisted).
fn validate_dependency_versions(
    publishable: &[(String, PathBuf)],
    metadata: &serde_json::Value,
) -> Result<(), String> {
    let mut issues: Vec<String> = Vec::new();
    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing packages in metadata")?;

    for (name, _manifest_dir) in publishable {
        let pkg = packages
            .iter()
            .find(|p| p["name"].as_str() == Some(name.as_str()))
            .ok_or_else(|| format!("package not found in metadata: {name}"))?;

        if let Some(deps) = pkg["dependencies"].as_array() {
            for dep in deps {
                let dep_name = dep["name"].as_str().unwrap_or("");

                // Only check workspace path dependencies (internal crates)
                if dep["path"].is_null() {
                    continue;
                }

                // Only check normal/build dependencies (dev-dependencies follow
                // Cargo publication rules and are excluded from resolution).
                let dep_kind = dep["kind"].as_str().unwrap_or("normal");
                if dep_kind == "dev" {
                    continue;
                }

                let req_str = dep["req"].as_str().unwrap_or("");

                if req_str.is_empty() {
                    issues.push(format!(
                        "{name}: path dependency `{dep_name}` has no version requirement — \
                         publishable crates must specify a registry-compatible semver requirement"
                    ));
                    continue;
                }

                if req_str == "*" {
                    issues.push(format!(
                        "{name}: path dependency `{dep_name}` uses `*` version requirement — \
                         use a compatible semver requirement (e.g. `0.1` or `^0.1.0`)"
                    ));
                    continue;
                }
            }
        }
    }

    if !issues.is_empty() {
        return Err(format!(
            "{} dependency version issue(s) found:\n  {}",
            issues.len(),
            issues.join("\n  ")
        ));
    }

    Ok(())
}

/// Inspect package contents for each publishable crate using `cargo package --list`.
///
/// Uses path-aware rules: exact component or extension matching, not broad
/// substring matching. Legitimate source paths containing `secret` or `key`
/// as part of module names are not rejected.
fn validate_package_contents(
    publishable: &[(String, PathBuf)],
    workspace_root: &Path,
    verbose: bool,
    allow_dirty: bool,
) -> Result<(), String> {
    let mut issues: Vec<String> = Vec::new();

    for (name, _manifest_dir) in publishable {
        let mut args = vec!["package", "--list", "-p", name];
        if allow_dirty {
            args.push("--allow-dirty");
        }
        let output = Command::new("cargo")
            .args(&args)
            .current_dir(workspace_root)
            .output();

        match output {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    issues.push(format!("{name}: cargo package --list failed: {stderr}"));
                    continue;
                }

                let listing = String::from_utf8_lossy(&out.stdout);

                for line in listing.lines() {
                    if is_prohibited_path(line) {
                        issues.push(format!("{name}: prohibited file in package: {line}"));
                    }
                }

                if verbose && issues.is_empty() {
                    let file_count = listing.lines().count();
                    println!("    {name}: {file_count} files");
                }
            }
            Err(e) => {
                issues.push(format!("{name}: failed to run cargo package: {e}"));
            }
        }
    }

    if !issues.is_empty() {
        return Err(format!(
            "{} package content issue(s) found:\n  {}",
            issues.len(),
            issues.join("\n  ")
        ));
    }

    Ok(())
}

/// Check that the working tree is clean (no uncommitted changes).
fn check_dirty_tree(workspace_root: &Path) -> Result<bool, String> {
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git status: {e}"))?;

    let stdout = String::from_utf8_lossy(&status.stdout);
    Ok(!stdout.trim().is_empty())
}

// ---------------------------------------------------------------------------
// Release verification
// ---------------------------------------------------------------------------

/// Run release verification (production artifacts + package inspection).
///
/// This validates the exact source and package surfaces that can be validated
/// before publication. It never invokes `cargo publish` — publication is
/// always manual through `cargo publish -p <crate>` in topological order.
///
/// Every publishable crate receives an explicit qualification state:
/// - `Assembled`: `cargo package --no-verify` succeeded
/// - `PackagedSourceVerified`: `cargo package` (with verify) succeeded
/// - `DeferredOnInternalPredecessors`: registry qualification deferred until named predecessors are published
/// - `NotPrepublishable`: depends on non-publishable internal crate (release blocker)
/// - `Failed`: unexpected failure (release blocker)
pub fn run_verify_release(
    dry_run: bool,
    json_output: bool,
    verbose: bool,
    allow_dirty: bool,
) -> Result<(), String> {
    let workspace_root = find_workspace_root()?;

    // --- Phase 0: Dirty working tree check ---
    // Policy: fail by default. Provide --allow-dirty for local experimentation.
    if !dry_run {
        let is_dirty = check_dirty_tree(&workspace_root)?;
        if is_dirty && !allow_dirty {
            if !json_output {
                eprintln!("✗ Working tree is not clean.");
                eprintln!("  Release verification requires a clean working tree.");
                eprintln!("  Use --allow-dirty to override (package output will not be release evidence).");
            }
            return Err("dirty working tree (use --allow-dirty to override)".to_string());
        }
        if is_dirty && allow_dirty && !json_output {
            eprintln!("⚠  Working tree is not clean (--allow-dirty specified).");
            eprintln!("   Package output is NOT release evidence.");
            eprintln!();
        }
    }

    // --- Phase 1: Verification (fmt + clippy + feature compilation + broad tests + doctests) ---
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask verify-release (phase 1: verification)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    let mut release_steps = verify_full_steps();
    release_steps.extend_from_slice(&[
        // All-features clippy (catches eBPF and other feature-gated warnings)
        (
            "clippy-all-features",
            "cargo clippy --all-targets --all-features -- -D warnings",
        ),
        // Release profile compilation
        ("compile-release", "cargo test --lib --no-run --release"),
    ]);

    run_contract(
        "verify-release",
        &release_steps,
        dry_run,
        json_output,
        verbose,
    )?;

    // --- Phase 2: Package metadata and content inspection ---
    if !json_output {
        println!();
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask verify-release (phase 2: package inspection)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    // Discover publishable crates via cargo metadata
    let publishable = discover_publishable_crates(&workspace_root)?;

    if publishable.is_empty() {
        if !json_output {
            println!("  No publishable crates discovered.");
        }
        return Ok(());
    }

    if !json_output {
        println!("  Publishable crates ({}):\n", publishable.len());
        for (i, (name, _)) in publishable.iter().enumerate() {
            println!("    {}. {name}", i + 1);
        }
        println!();
    }

    // Load metadata for dependency validation
    let metadata_output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(&workspace_root)
        .output()
        .map_err(|e| format!("failed to run cargo metadata: {e}"))?;

    if !metadata_output.status.success() {
        return Err("cargo metadata failed during release verification".to_string());
    }

    let metadata: serde_json::Value = serde_json::from_slice(&metadata_output.stdout)
        .map_err(|e| format!("failed to parse cargo metadata: {e}"))?;

    // Validate metadata fields
    validate_package_metadata(&publishable, &workspace_root)?;
    if !json_output {
        println!("  ✓ Package metadata valid for all publishable crates");
        println!();
    }

    // Validate dependency version requirements
    validate_dependency_versions(&publishable, &metadata)?;
    if !json_output {
        println!("  ✓ Internal path dependencies use compatible version specs");
        println!();
    }

    // Inspect package contents
    validate_package_contents(&publishable, &workspace_root, verbose, allow_dirty)?;
    if !json_output {
        println!("  ✓ Package contents valid for all publishable crates");
        println!();
    }

    // --- Phase 3: Package assembly with qualification model ---
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask verify-release (phase 3: package qualification)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    // Build dependency graph for qualification
    let publishable_names: std::collections::HashSet<String> =
        publishable.iter().map(|(n, _)| n.clone()).collect();
    let mut nonpublishable_names: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for name in NONPUBLISHABLE {
        nonpublishable_names.insert(name.to_string());
    }
    for name in EXAMPLE_CRATES {
        nonpublishable_names.insert(name.to_string());
    }

    let dep_graph =
        build_publishable_dependency_graph(&metadata, &publishable_names, &nonpublishable_names)?;

    // Detect cycles in publishable dependency graph
    detect_cycles(&dep_graph).map_err(|e| format!("publication graph has a cycle: {e}"))?;

    // Precompute which publishable crates have been resolved (assembled or verified).
    // A crate is "resolved" once we know its predecessors are on crates.io.
    // We iterate topologically (publishable is topologically sorted), so we can
    // build this set incrementally.
    let mut resolved_set: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Classify and attempt assembly for each publishable crate
    let mut assembly_results: Vec<(String, CrateQualification)> = Vec::new();

    for (name, _) in &publishable {
        let info = dep_graph
            .get(name)
            .ok_or_else(|| format!("missing dependency info for `{name}`"))?;

        // Non-publishable deps are a release blocker
        if !info.nonpublishable_deps.is_empty() {
            assembly_results.push((
                name.clone(),
                CrateQualification::NotPrepublishable {
                    reason: format!(
                        "depends on non-publishable internal crate(s): {}",
                        info.nonpublishable_deps.join(", ")
                    ),
                },
            ));
            continue;
        }

        // Publishable predecessors mean the crate is blocked on publication
        if !info.publishable_predecessors.is_empty() {
            assembly_results.push((
                name.clone(),
                CrateQualification::DeferredOnInternalPredecessors {
                    predecessors: info.publishable_predecessors.clone(),
                },
            ));
            continue;
        }

        // Check if any path dependency (including dev-deps) references a workspace
        // crate that is itself blocked or not yet resolved. This catches crates like
        // synvoid-platform that have dev-dependencies on deferred workspace crates.
        let pkg = metadata["packages"]
            .as_array()
            .ok_or("missing packages in metadata")?
            .iter()
            .find(|p| p["name"].as_str() == Some(name.as_str()))
            .ok_or_else(|| format!("package not found: {name}"))?;

        let mut blocked_on_unresolved: Vec<String> = Vec::new();
        if let Some(deps) = pkg["dependencies"].as_array() {
            for dep in deps {
                if dep["path"].is_string() {
                    let dep_name = dep["name"].as_str().unwrap_or("");
                    // Check if this path dependency is a workspace crate that we haven't resolved yet
                    if publishable_names.contains(dep_name)
                        && !nonpublishable_names.contains(dep_name)
                        && !resolved_set.contains(dep_name)
                    {
                        blocked_on_unresolved.push(dep_name.to_string());
                    }
                }
            }
        }

        if !blocked_on_unresolved.is_empty() {
            assembly_results.push((
                name.clone(),
                CrateQualification::DeferredOnInternalPredecessors {
                    predecessors: blocked_on_unresolved,
                },
            ));
            continue;
        }

        // No internal publishable predecessors — attempt assembly
        let result = attempt_assembly(name, allow_dirty, verbose, &workspace_root);
        // If assembly succeeded (assembled or verified), mark as resolved
        if matches!(
            result,
            CrateQualification::Assembled | CrateQualification::PackagedSourceVerified
        ) {
            resolved_set.insert(name.clone());
        }
        assembly_results.push((name.clone(), result));
    }

    // --- Phase 3b: Packaged-source verification for assembled crates ---
    let mut source_results: Vec<(String, CrateQualification)> = Vec::new();

    for (name, qual) in &assembly_results {
        match qual {
            CrateQualification::Assembled => {
                // Attempt source verification for assembled crates
                source_results.push((
                    name.clone(),
                    attempt_source_verification(name, allow_dirty, verbose, &workspace_root),
                ));
            }
            _ => {
                // Carry forward the qualification state
                source_results.push((name.clone(), qual.clone()));
            }
        }
    }

    // --- Build and print summary ---
    let mut summary = ReleaseQualificationSummary {
        assembled: Vec::new(),
        packaged_source_verified: Vec::new(),
        deferred_on_predecessors: Vec::new(),
        not_prepublishable: Vec::new(),
        failed: Vec::new(),
        publication_order: publishable.iter().map(|(n, _)| n.clone()).collect(),
    };

    for (name, qual) in &source_results {
        match qual {
            CrateQualification::PackagedSourceVerified => {
                summary.packaged_source_verified.push(name.clone());
            }
            CrateQualification::Assembled => {
                summary.assembled.push(name.clone());
            }
            CrateQualification::DeferredOnInternalPredecessors { predecessors } => {
                summary.deferred_on_predecessors.push(DeferredCrate {
                    name: name.clone(),
                    predecessors: predecessors.clone(),
                });
            }
            CrateQualification::NotPrepublishable { reason } => {
                summary.not_prepublishable.push(NotPrepublishableCrate {
                    name: name.clone(),
                    reason: reason.clone(),
                });
            }
            CrateQualification::Failed { phase, reason } => {
                summary.failed.push(FailedCrate {
                    name: name.clone(),
                    phase: phase.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    } else {
        // Print qualification summary
        println!("  Package qualification summary:");
        println!("    Assembled: {} crate(s)", summary.assembled.len());
        if !summary.assembled.is_empty() {
            for name in &summary.assembled {
                println!("      ✓ {name}");
            }
        }
        println!(
            "    Packaged-source verified: {} crate(s)",
            summary.packaged_source_verified.len()
        );
        if !summary.packaged_source_verified.is_empty() {
            for name in &summary.packaged_source_verified {
                println!("      ✓ {name}");
            }
        }
        println!(
            "    Deferred (pending internal predecessors): {} crate(s)",
            summary.deferred_on_predecessors.len()
        );
        for blocked in &summary.deferred_on_predecessors {
            println!(
                "      ⊘ {} — deferred on: {}",
                blocked.name,
                blocked.predecessors.join(", ")
            );
        }
        if !summary.not_prepublishable.is_empty() {
            println!(
                "    Not prepublishable: {} crate(s)",
                summary.not_prepublishable.len()
            );
            for np in &summary.not_prepublishable {
                println!("      ✗ {} — {}", np.name, np.reason);
            }
        }
        if !summary.failed.is_empty() {
            println!("    Failed: {} crate(s)", summary.failed.len());
            for f in &summary.failed {
                println!("      ✗ {} ({})", f.name, f.phase);
                eprintln!("        {}", f.reason);
            }
        }
        println!();

        // Print follow-up instructions for deferred crates
        if !summary.deferred_on_predecessors.is_empty() {
            println!("  Follow-up after publishing predecessors:");
            for blocked in &summary.deferred_on_predecessors {
                println!("    After publishing {}:", blocked.predecessors.join(", "));
                println!("      cargo package --no-verify -p {}", blocked.name);
                println!("      cargo package -p {}", blocked.name);
            }
            println!();
        }

        // Exit message
        let has_blockers = !summary.not_prepublishable.is_empty() || !summary.failed.is_empty();
        let has_deferred = !summary.deferred_on_predecessors.is_empty();

        if has_blockers {
            eprintln!("  ✗ Release verification FAILED — blockers found");
        } else if has_deferred {
            println!("  PRE-PUBLICATION READY WITH DEFERRED REGISTRY CHECKS");
            println!(
                "  {} crate(s) deferred until predecessors are published",
                summary.deferred_on_predecessors.len()
            );
        } else {
            println!("  ✓ All publishable crates fully qualified");
        }
        println!();
    }

    // --- Phase 4: Print manual publication order ---
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  Manual publication order ({} crates):", publishable.len());
        println!("═══════════════════════════════════════════════════════════");
        println!();
        for (i, (name, _)) in publishable.iter().enumerate() {
            println!("  {}. cargo publish -p {name}", i + 1);
        }
        println!();
        println!("  After each crate, verify it resolves from crates.io before");
        println!("  publishing dependents. Wait for docs.rs to index if needed.");
        println!();
    }

    // Exit policy: nonzero for blockers/failures, zero when only deferred
    if !summary.not_prepublishable.is_empty() || !summary.failed.is_empty() {
        return Err(format!(
            "{} release blocker(s)/failure(s) found",
            summary.not_prepublishable.len() + summary.failed.len()
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test subcommands
// ---------------------------------------------------------------------------

/// Run a specific package test.
pub fn run_package(
    pkg: &str,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    let cmd = format!("cargo nextest run -p {pkg} --cargo-profile ci --profile ci");
    run_contract(
        &format!("test package {pkg}"),
        &[(pkg, &cmd)],
        dry_run,
        json_output,
        verbose,
    )
}

/// Run all guard tests (repo-guards crate + root guard tests).
pub fn run_guards(dry_run: bool, json_output: bool, verbose: bool) -> Result<(), String> {
    let steps: Vec<(&str, &str)> = vec![
        (
            "repo-guards",
            "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci",
        ),
        (
            "root-guards",
            "cargo nextest run --cargo-profile ci --profile ci \
             --test boundary_composition_guard \
             --test lifecycle_task_guard \
             --test plugin_guard \
             --test cli_admin_guard \
             --test security_guard \
             --test root_facade_boundary_guard \
             --test mesh_id_boundary_guard \
             --test admin_mutation_response_guard \
             --test admin_mutation_blocklist \
             --test abi_memory_boundary_guard \
             --test root_test_ownership_guard \
             --test worker_mesh_supervision_boundary_guard \
             --test mesh_task_ownership_guard \
             --features mesh",
        ),
        (
            "core-admin-tests",
            "cargo nextest run -p synvoid-core --cargo-profile ci --profile ci \
             --test admin_auth_boundary \
             --test mesh_admin_edge_cases",
        ),
    ];

    run_contract("test guards", &steps, dry_run, json_output, verbose)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type MockCrateDeps<'a> = Vec<(&'a str, &'a str, &'a str)>;
    type MockCrate<'a> = (&'a str, &'a str, MockCrateDeps<'a>);

    // Helper to create a mock metadata JSON value for a crate with given deps
    fn mock_metadata(crates: &[MockCrate<'_>]) -> serde_json::Value {
        // crates: Vec of (name, version, deps)
        // deps: Vec of (dep_name, dep_kind, dep_path_or_empty)
        let packages: Vec<serde_json::Value> = crates
            .iter()
            .map(|(name, version, deps)| {
                let deps_json: Vec<serde_json::Value> = deps
                    .iter()
                    .map(|(dep_name, dep_kind, dep_path)| {
                        let mut dep = serde_json::json!({
                            "name": dep_name,
                            "kind": dep_kind,
                            "req": format!("^{version}"),
                        });
                        if !dep_path.is_empty() {
                            dep["path"] = serde_json::json!(dep_path);
                        }
                        dep
                    })
                    .collect();
                serde_json::json!({
                    "name": name,
                    "version": version,
                    "manifest_path": format!("/workspace/{name}/Cargo.toml"),
                    "dependencies": deps_json,
                })
            })
            .collect();

        let members: Vec<String> = crates
            .iter()
            .map(|(name, _, _)| format!("{name}:0.0.0"))
            .collect();

        serde_json::json!({
            "workspace_members": members,
            "packages": packages,
        })
    }

    // --- Workstream A: Dependency graph tests ---

    #[test]
    fn test_crate_with_no_internal_deps_is_assembly_eligible() {
        let metadata = mock_metadata(&[("synvoid-utils", "0.1.0", vec![])]);
        let publishable: std::collections::HashSet<String> =
            ["synvoid-utils".to_string()].into_iter().collect();
        let nonpublishable: std::collections::HashSet<String> = std::collections::HashSet::new();

        let graph =
            build_publishable_dependency_graph(&metadata, &publishable, &nonpublishable).unwrap();
        let info = graph.get("synvoid-utils").unwrap();

        assert!(info.publishable_predecessors.is_empty());
        assert!(info.nonpublishable_deps.is_empty());
    }

    #[test]
    fn test_publishable_predecessor_is_classified() {
        let metadata = mock_metadata(&[
            ("synvoid-core", "0.1.0", vec![]),
            (
                "synvoid-config",
                "0.1.0",
                vec![("synvoid-core", "normal", "../../synvoid-core")],
            ),
        ]);
        let publishable: std::collections::HashSet<String> =
            ["synvoid-core".to_string(), "synvoid-config".to_string()]
                .into_iter()
                .collect();
        let nonpublishable: std::collections::HashSet<String> = std::collections::HashSet::new();

        let graph =
            build_publishable_dependency_graph(&metadata, &publishable, &nonpublishable).unwrap();

        let core_info = graph.get("synvoid-core").unwrap();
        assert!(core_info.publishable_predecessors.is_empty());

        let config_info = graph.get("synvoid-config").unwrap();
        assert_eq!(config_info.publishable_predecessors, vec!["synvoid-core"]);
        assert!(config_info.nonpublishable_deps.is_empty());
    }

    #[test]
    fn test_nonpublishable_dep_is_classified() {
        let metadata = mock_metadata(&[(
            "synvoid-core",
            "0.1.0",
            vec![("xtask", "normal", "../../tools/xtask")],
        )]);
        let publishable: std::collections::HashSet<String> =
            ["synvoid-core".to_string()].into_iter().collect();
        let mut nonpublishable: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        nonpublishable.insert("xtask".to_string());

        let graph =
            build_publishable_dependency_graph(&metadata, &publishable, &nonpublishable).unwrap();
        let info = graph.get("synvoid-core").unwrap();

        assert!(info.publishable_predecessors.is_empty());
        assert_eq!(info.nonpublishable_deps, vec!["xtask"]);
    }

    #[test]
    fn test_dev_dependency_is_excluded() {
        let metadata = mock_metadata(&[
            (
                "synvoid-core",
                "0.1.0",
                vec![("synvoid-utils", "dev", "../../synvoid-utils")],
            ),
            ("synvoid-utils", "0.1.0", vec![]),
        ]);
        let publishable: std::collections::HashSet<String> =
            ["synvoid-core".to_string(), "synvoid-utils".to_string()]
                .into_iter()
                .collect();
        let nonpublishable: std::collections::HashSet<String> = std::collections::HashSet::new();

        let graph =
            build_publishable_dependency_graph(&metadata, &publishable, &nonpublishable).unwrap();
        let info = graph.get("synvoid-core").unwrap();

        // Dev-dependencies should not appear in the graph
        assert!(info.publishable_predecessors.is_empty());
        assert!(info.nonpublishable_deps.is_empty());
    }

    // --- Cycle detection tests ---

    #[test]
    fn test_no_cycle_in_acyclic_graph() {
        let mut graph = std::collections::HashMap::new();
        graph.insert(
            "a".to_string(),
            CrateDepInfo {
                publishable_predecessors: vec!["b".to_string()],
                nonpublishable_deps: vec![],
            },
        );
        graph.insert(
            "b".to_string(),
            CrateDepInfo {
                publishable_predecessors: vec![],
                nonpublishable_deps: vec![],
            },
        );

        assert!(detect_cycles(&graph).is_ok());
    }

    #[test]
    fn test_cycle_is_detected() {
        let mut graph = std::collections::HashMap::new();
        graph.insert(
            "a".to_string(),
            CrateDepInfo {
                publishable_predecessors: vec!["b".to_string()],
                nonpublishable_deps: vec![],
            },
        );
        graph.insert(
            "b".to_string(),
            CrateDepInfo {
                publishable_predecessors: vec!["a".to_string()],
                nonpublishable_deps: vec![],
            },
        );

        let result = detect_cycles(&graph);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cycle"));
    }

    #[test]
    fn test_self_cycle_is_detected() {
        let mut graph = std::collections::HashMap::new();
        graph.insert(
            "a".to_string(),
            CrateDepInfo {
                publishable_predecessors: vec!["a".to_string()],
                nonpublishable_deps: vec![],
            },
        );

        let result = detect_cycles(&graph);
        assert!(result.is_err());
    }

    #[test]
    fn test_long_chain_has_no_cycle() {
        let mut graph = std::collections::HashMap::new();
        for i in 0..10 {
            let name = format!("crate_{i}");
            let mut predecessors = Vec::new();
            if i > 0 {
                predecessors.push(format!("crate_{}", i - 1));
            }
            graph.insert(
                name.clone(),
                CrateDepInfo {
                    publishable_predecessors: predecessors,
                    nonpublishable_deps: vec![],
                },
            );
        }

        assert!(detect_cycles(&graph).is_ok());
    }

    // --- Qualification summary tests ---

    #[test]
    fn test_summary_counts() {
        let source_results = vec![
            (
                "crate_a".to_string(),
                CrateQualification::PackagedSourceVerified,
            ),
            ("crate_b".to_string(), CrateQualification::Assembled),
            (
                "crate_c".to_string(),
                CrateQualification::DeferredOnInternalPredecessors {
                    predecessors: vec!["crate_a".to_string()],
                },
            ),
            (
                "crate_d".to_string(),
                CrateQualification::Failed {
                    phase: "assembly".to_string(),
                    reason: "some error".to_string(),
                },
            ),
        ];
        let publishable = [
            ("crate_a".to_string(), PathBuf::from("/a")),
            ("crate_b".to_string(), PathBuf::from("/b")),
            ("crate_c".to_string(), PathBuf::from("/c")),
            ("crate_d".to_string(), PathBuf::from("/d")),
        ];

        let mut summary = ReleaseQualificationSummary {
            assembled: Vec::new(),
            packaged_source_verified: Vec::new(),
            deferred_on_predecessors: Vec::new(),
            not_prepublishable: Vec::new(),
            failed: Vec::new(),
            publication_order: publishable.iter().map(|(n, _)| n.clone()).collect(),
        };

        for (name, qual) in &source_results {
            match qual {
                CrateQualification::PackagedSourceVerified => {
                    summary.packaged_source_verified.push(name.clone());
                }
                CrateQualification::Assembled => {
                    summary.assembled.push(name.clone());
                }
                CrateQualification::DeferredOnInternalPredecessors { predecessors } => {
                    summary.deferred_on_predecessors.push(DeferredCrate {
                        name: name.clone(),
                        predecessors: predecessors.clone(),
                    });
                }
                CrateQualification::Failed { phase, reason } => {
                    summary.failed.push(FailedCrate {
                        name: name.clone(),
                        phase: phase.clone(),
                        reason: reason.clone(),
                    });
                }
                _ => {}
            }
        }

        assert_eq!(summary.packaged_source_verified.len(), 1);
        assert_eq!(summary.assembled.len(), 1);
        assert_eq!(summary.deferred_on_predecessors.len(), 1);
        assert_eq!(summary.failed.len(), 1);
        assert_eq!(summary.not_prepublishable.len(), 0);
    }

    #[test]
    fn test_deferred_crate_not_counted_as_assembled() {
        let source_results = vec![(
            "crate_a".to_string(),
            CrateQualification::DeferredOnInternalPredecessors {
                predecessors: vec!["crate_b".to_string()],
            },
        )];

        let mut assembled = Vec::new();
        let mut verified = Vec::new();
        let mut blocked = Vec::new();

        for (name, qual) in &source_results {
            match qual {
                CrateQualification::PackagedSourceVerified => verified.push(name.clone()),
                CrateQualification::Assembled => assembled.push(name.clone()),
                CrateQualification::DeferredOnInternalPredecessors { .. } => {
                    blocked.push(name.clone())
                }
                _ => {}
            }
        }

        assert_eq!(assembled.len(), 0);
        assert_eq!(verified.len(), 0);
        assert_eq!(blocked.len(), 1);
    }

    // --- is_prohibited_path tests ---

    #[test]
    fn test_prohibited_path_prefixes() {
        assert!(is_prohibited_path("target/debug/foo"));
        assert!(is_prohibited_path(".git/config"));
        assert!(is_prohibited_path("fuzz/corpus/foo"));
        assert!(is_prohibited_path("plans/foo.md"));
        assert!(is_prohibited_path("corpus/foo.bin"));
    }

    #[test]
    fn test_prohibited_basenames() {
        assert!(is_prohibited_path(".env"));
        assert!(is_prohibited_path(".env.production"));
        assert!(is_prohibited_path("credentials"));
        assert!(is_prohibited_path("credentials.toml"));
        assert!(is_prohibited_path("id_rsa"));
        assert!(is_prohibited_path("id_ed25519"));
        assert!(is_prohibited_path("id_ecdsa"));
        assert!(is_prohibited_path("htpasswd"));
    }

    #[test]
    fn test_prohibited_extensions() {
        assert!(is_prohibited_path("server.key"));
        assert!(is_prohibited_path("cert.pem"));
        assert!(is_prohibited_path("keystore.p12"));
        assert!(is_prohibited_path("cert.pfx"));
        assert!(is_prohibited_path("cert.keystore"));
    }

    #[test]
    fn test_legitimate_paths_not_prohibited() {
        assert!(!is_prohibited_path("src/secret_handling.rs"));
        assert!(!is_prohibited_path("src/crypto/key_exchange.rs"));
        assert!(!is_prohibited_path("src/auth/private_key_store.rs"));
        assert!(!is_prohibited_path("src/main.rs"));
        assert!(!is_prohibited_path("Cargo.toml"));
        assert!(!is_prohibited_path("README.md"));
    }

    #[test]
    fn test_windows_path_normalization() {
        assert!(is_prohibited_path("target\\debug\\foo"));
        assert!(!is_prohibited_path("src\\main.rs"));
    }
}

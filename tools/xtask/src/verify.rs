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

/// Run release verification (production artifacts + package inspection).
///
/// This validates the exact source and package surfaces that can be validated
/// before publication. It never invokes `cargo publish` — publication is
/// always manual through `cargo publish -p <crate>` in topological order.
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

    // --- Phase 3: Package assembly (no-verify, no registry resolution) ---
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask verify-release (phase 3: package assembly)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    let mut assembly_issues: Vec<String> = Vec::new();
    for (name, _manifest_dir) in &publishable {
        if verbose {
            println!("  → cargo package --no-verify -p {name}");
        }

        let mut args = vec!["package", "--no-verify", "-p", name];
        if allow_dirty {
            args.push("--allow-dirty");
        }
        let output = Command::new("cargo")
            .args(&args)
            .current_dir(&workspace_root)
            .output();

        match output {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    assembly_issues.push(format!("{name}: package assembly failed: {stderr}"));
                }
            }
            Err(e) => {
                assembly_issues.push(format!("{name}: failed to run cargo package: {e}"));
            }
        }
    }

    if !assembly_issues.is_empty() {
        if !json_output {
            eprintln!("  Package assembly issues:");
            for issue in &assembly_issues {
                eprintln!("    ✗ {issue}");
            }
            eprintln!();
        }
        return Err(format!(
            "{} package assembly issue(s) found",
            assembly_issues.len()
        ));
    }

    if !json_output {
        println!("  ✓ Package assembly successful for all publishable crates");
        println!();
    }

    // --- Phase 3b: Bounded packaged-source check ---
    // For crates whose dependencies are all resolvable from crates.io (no
    // unpublished internal path deps), run `cargo package --verify` to validate
    // the packaged source builds correctly. Crates with unpublished internal
    // deps are skipped — their correctness is ensured by the full source
    // verification in Phase 1.
    if !json_output {
        println!("  Packaged-source check (feasible crates):");
    }
    let mut source_check_skipped: Vec<String> = Vec::new();
    let mut source_check_passed: Vec<String> = Vec::new();
    let mut source_check_failed: Vec<String> = Vec::new();

    for (name, _manifest_dir) in &publishable {
        // Check if all path deps are other publishable crates (resolvable
        // after sequential publication) or external (already on crates.io).
        let pkg = metadata["packages"]
            .as_array()
            .and_then(|pkgs| pkgs.iter().find(|p| p["name"].as_str() == Some(name)));
        let has_unpublished_path_dep = pkg
            .and_then(|p| p["dependencies"].as_array())
            .map(|deps| {
                deps.iter().any(|d| {
                    if d["path"].as_str().is_some() {
                        // A path dep is "unpublished" if it's not in the
                        // publishable set (would not resolve from crates.io).
                        !publishable
                            .iter()
                            .any(|(pn, _)| pn == d["name"].as_str().unwrap_or(""))
                    } else {
                        false
                    }
                })
            })
            .unwrap_or(false);

        if has_unpublished_path_dep {
            source_check_skipped.push(name.clone());
            continue;
        }

        let mut args = vec!["package", "--verify", "-p", name];
        if allow_dirty {
            args.push("--allow-dirty");
        }
        let output = Command::new("cargo")
            .args(&args)
            .current_dir(&workspace_root)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                source_check_passed.push(name.clone());
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                source_check_failed.push(format!("{name}: {stderr}"));
            }
            Err(e) => {
                source_check_failed.push(format!("{name}: {e}"));
            }
        }
    }

    if !json_output {
        if !source_check_passed.is_empty() {
            println!(
                "    ✓ Packaged-source verified: {}",
                source_check_passed.join(", ")
            );
        }
        if !source_check_skipped.is_empty() {
            println!(
                "    ⊘ Skipped (unpublished internal deps): {}",
                source_check_skipped.join(", ")
            );
        }
        if !source_check_failed.is_empty() {
            for fail in &source_check_failed {
                eprintln!("    ✗ {fail}");
            }
        }
        println!();
    }

    if !source_check_failed.is_empty() {
        return Err(format!(
            "{} packaged-source check(s) failed",
            source_check_failed.len()
        ));
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

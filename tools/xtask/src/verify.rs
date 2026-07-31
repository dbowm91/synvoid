use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::report::{LaneReport, StepResult, StepStatus};

/// Shared helper: find workspace root by walking up to Cargo.toml with [workspace].
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

/// Shared helper: run a single shell command. Returns (success, duration_ms).
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
// ---------------------------------------------------------------------------

fn verify_full_steps() -> Vec<(&'static str, &'static str)> {
    let mut steps = verify_steps();

    steps.extend_from_slice(&[
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
        // Full workspace tests
        (
            "nextest-all",
            "cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz",
        ),
        // Doctests
        ("doctests", "cargo test --workspace --doc --profile ci"),
        // Domain-specific suites
        (
            "dns-full",
            "cargo nextest run -p synvoid-dns --cargo-profile ci --profile ci",
        ),
        (
            "plugin-full",
            "cargo nextest run -p synvoid-plugin-runtime --cargo-profile ci --profile ci",
        ),
        ("honeypot", "cargo test -p synvoid-honeypot --all-targets"),
        ("tarpit", "cargo test -p synvoid-tarpit --all-targets"),
    ]);

    steps
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

/// Crates that are explicitly not publishable.
const NONPUBLISHABLE: &[&str] = &["synvoid-fuzz", "xtask", "admin-ui", "synvoid-repo-guards"];

/// Example / demo crates that should never be published.
const EXAMPLE_CRATES: &[&str] = &["myapp-dynamic", "my-waf-app"];

/// Check if a crate is publishable by reading its Cargo.toml.
fn is_publishable(crate_dir: &Path) -> bool {
    let cargo_toml = crate_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        return false;
    }
    let content = match std::fs::read_to_string(&cargo_toml) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // Check for explicit publish = false
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("publish") && trimmed.contains("false") {
            return false;
        }
    }
    true
}

/// Discover all publishable workspace crates in dependency order.
/// Returns Vec of (package_name, manifest_dir_path).
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

    let mut publishable = Vec::new();

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

        // Skip nonpublishable and example crates
        if NONPUBLISHABLE.contains(&name.as_str()) || EXAMPLE_CRATES.contains(&name.as_str()) {
            continue;
        }

        if !is_publishable(&manifest_dir) {
            continue;
        }

        publishable.push((name, manifest_dir));
    }

    // Topological sort by workspace path dependencies
    let mut sorted = Vec::new();
    let mut visited = std::collections::HashSet::new();

    fn visit(
        name: &str,
        packages: &[serde_json::Value],
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
                    if !nonpublishable.contains(&dep_name) && !examples.contains(&dep_name) {
                        visit(
                            dep_name,
                            packages,
                            visited,
                            sorted,
                            nonpublishable,
                            examples,
                        )?;
                    }
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
            &PathBuf::from(
                pkg["manifest_path"]
                    .as_str()
                    .ok_or("missing manifest_path")?,
            )
            .parent()
            .unwrap()
            .to_path_buf(),
        ) {
            continue;
        }

        visit(
            &name,
            packages,
            &mut visited,
            &mut sorted,
            NONPUBLISHABLE,
            EXAMPLE_CRATES,
        )?;
    }

    Ok(sorted)
}

fn verify_release_steps() -> Vec<(&'static str, &'static str)> {
    let mut steps = verify_full_steps();

    steps.extend_from_slice(&[
        // All-features clippy
        (
            "clippy-all-features",
            "cargo clippy --all-targets --all-features -- -D warnings",
        ),
        // Release profile compilation
        ("compile-release", "cargo test --lib --no-run --release"),
        (
            "nextest-release",
            "cargo nextest run --workspace --release --exclude synvoid-fuzz",
        ),
        ("doctests-release", "cargo test --workspace --doc --release"),
    ]);

    steps
}

/// Run release verification (production artifacts + package inspection).
///
/// This runs verify-full, then adds release-specific checks and package
/// inspection for every publishable workspace crate. It never invokes
/// `cargo publish` — publication is always manual.
pub fn run_verify_release(dry_run: bool, json_output: bool, verbose: bool) -> Result<(), String> {
    let workspace_root = find_workspace_root()?;

    // --- Phase 1: Clean working tree check ---
    //
    // Policy: warn-only, not fail. A local dev tool that hard-fails on a dirty
    // tree would block iterative development (e.g., running verify-release after
    // partial edits). Publication still requires a clean, tagged commit — this
    // check is advisory, not a gate.
    if !dry_run {
        let status = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&workspace_root)
            .output()
            .map_err(|e| format!("failed to run git status: {e}"))?;

        let stdout = String::from_utf8_lossy(&status.stdout);
        if !stdout.trim().is_empty() {
            if !json_output {
                eprintln!("⚠  Working tree is not clean (dirty-tree policy: warn-only).");
                eprintln!("   Release verification proceeds. Publication should only");
                eprintln!("   happen from a clean, tagged commit.");
                eprintln!();
            }
        }
    }

    // --- Phase 2: verify-full (includes verify) ---
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask verify-release (phase 1: verification)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    let verify_steps = verify_release_steps();
    run_contract(
        "verify-release",
        &verify_steps,
        dry_run,
        json_output,
        verbose,
    )?;

    // --- Phase 3: Package inspection ---
    if !json_output {
        println!();
        println!("═══════════════════════════════════════════════════════════");
        println!("  cargo xtask verify-release (phase 2: package inspection)");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

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

    // Validate metadata: each publishable crate must have description, license, repository
    let mut metadata_issues: Vec<String> = Vec::new();
    for (name, manifest_dir) in &publishable {
        let cargo_toml = manifest_dir.join("Cargo.toml");
        let content = match std::fs::read_to_string(&cargo_toml) {
            Ok(c) => c,
            Err(e) => {
                metadata_issues.push(format!("{name}: cannot read {}: {e}", cargo_toml.display()));
                continue;
            }
        };

        let has_description = content.lines().any(|l| l.trim().starts_with("description"));
        let has_license = content.lines().any(|l| {
            let t = l.trim();
            t.starts_with("license") || t.starts_with("license-file")
        });

        if !has_description {
            metadata_issues.push(format!("{name}: missing `description` field"));
        }
        if !has_license {
            // Check if workspace license applies
            let root_cargo = workspace_root.join("Cargo.toml");
            let root_content = std::fs::read_to_string(&root_cargo).unwrap_or_default();
            if !root_content.contains("[workspace.package]") || !root_content.contains("license") {
                metadata_issues.push(format!(
                    "{name}: missing `license` field (no workspace fallback)"
                ));
            }
        }

        // Check that readme file exists if explicitly referenced
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("readme") {
                if let Some(start) = trimmed.find('"') {
                    if let Some(end) = trimmed[start + 1..].find('"') {
                        let readme_path = manifest_dir.join(&trimmed[start + 1..start + 1 + end]);
                        if !readme_path.exists() {
                            metadata_issues.push(format!(
                                "{name}: referenced readme does not exist: {}",
                                readme_path.display()
                            ));
                        }
                    }
                }
            }
        }
    }

    if !metadata_issues.is_empty() {
        if !json_output {
            eprintln!("  Package metadata issues:");
            for issue in &metadata_issues {
                eprintln!("    ✗ {issue}");
            }
            eprintln!();
        }
        return Err(format!(
            "{} package metadata issue(s) found",
            metadata_issues.len()
        ));
    }

    if !json_output {
        println!("  ✓ Package metadata valid for all publishable crates");
        println!();
    }

    // Run cargo package --list for each publishable crate
    let mut package_issues: Vec<String> = Vec::new();
    for (name, _manifest_dir) in &publishable {
        if verbose {
            println!("  → cargo publish --dry-run -p {name}");
        }

        let output = Command::new("cargo")
            .args(["package", "--list", "-p", name])
            .current_dir(&workspace_root)
            .output();

        match output {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    package_issues.push(format!("{name}: cargo package --list failed: {stderr}"));
                    continue;
                }

                let listing = String::from_utf8_lossy(&out.stdout);

                // Check for prohibited patterns — credential-like files, build
                // outputs, planning docs, and test corpora must never ship in a
                // published crate.
                let prohibited = [
                    "target/",
                    ".git/",
                    ".env",
                    "credentials",
                    "fuzz/",
                    "plans/",
                    "corpus/",
                    "crash-",
                    ".key",
                    ".pem",
                    ".p12",
                    ".pfx",
                    ".keystore",
                    "id_rsa",
                    "id_ed25519",
                    "id_ecdsa",
                    "htpasswd",
                    "secret",
                    ".secret",
                    "private_key",
                ];

                for line in listing.lines() {
                    for pattern in &prohibited {
                        if line.contains(pattern) {
                            package_issues
                                .push(format!("{name}: prohibited file in package: {line}"));
                        }
                    }
                }

                if verbose && package_issues.is_empty() {
                    let file_count = listing.lines().count();
                    println!("    {name}: {file_count} files");
                }
            }
            Err(e) => {
                package_issues.push(format!("{name}: failed to run cargo package: {e}"));
            }
        }
    }

    if !package_issues.is_empty() {
        if !json_output {
            eprintln!("  Package content issues:");
            for issue in &package_issues {
                eprintln!("    ✗ {issue}");
            }
            eprintln!();
        }
        return Err(format!(
            "{} package content issue(s) found",
            package_issues.len()
        ));
    }

    if !json_output {
        println!("  ✓ Package contents valid for all publishable crates");
        println!();
    }

    // Check that internal path dependencies use * version specs
    let mut dep_issues: Vec<String> = Vec::new();
    for (name, manifest_dir) in &publishable {
        let cargo_toml = manifest_dir.join("Cargo.toml");
        let content = match std::fs::read_to_string(&cargo_toml) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Simple check: look for path deps with pinned versions (not `*`)
        // This is a heuristic — exact version pins on path deps cause publish failures
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("path = ") && trimmed.contains("version = ") {
                // Check if version is a specific number (not `*`)
                if let Some(vstart) = trimmed.find("version = \"") {
                    let vstr = &trimmed[vstart + 11..];
                    if let Some(vend) = vstr.find('"') {
                        let ver = &vstr[..vend];
                        if ver != "*" && !ver.contains('{') {
                            dep_issues.push(format!(
                                "{name}: path dependency with pinned version `{ver}` — use `*` for local path deps"
                            ));
                        }
                    }
                }
            }
        }
    }

    if !dep_issues.is_empty() {
        if !json_output {
            eprintln!("  Internal dependency version issues:");
            for issue in &dep_issues {
                eprintln!("    ✗ {issue}");
            }
            eprintln!();
        }
        return Err(format!(
            "{} internal dependency issue(s) found",
            dep_issues.len()
        ));
    }

    if !json_output {
        println!("  ✓ Internal path dependencies use compatible version specs");
        println!();
    }

    // Dry-run package assembly for each crate
    let mut dry_run_issues: Vec<String> = Vec::new();
    for (name, _manifest_dir) in &publishable {
        if verbose {
            println!("  → cargo publish --dry-run -p {name}");
        }

        let output = Command::new("cargo")
            .args(["publish", "--dry-run", "-p", name])
            .current_dir(&workspace_root)
            .output();

        match output {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    dry_run_issues.push(format!("{name}: dry-run failed: {stderr}"));
                }
            }
            Err(e) => {
                dry_run_issues.push(format!(
                    "{name}: failed to run cargo publish --dry-run: {e}"
                ));
            }
        }
    }

    if !dry_run_issues.is_empty() {
        if !json_output {
            eprintln!("  Dry-run issues:");
            for issue in &dry_run_issues {
                eprintln!("    ✗ {issue}");
            }
            eprintln!();
        }
        return Err(format!("{} dry-run issue(s) found", dry_run_issues.len()));
    }

    if !json_output {
        println!("  ✓ Dry-run packaging successful for all publishable crates");
        println!();
    }

    // Print manual publication order
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

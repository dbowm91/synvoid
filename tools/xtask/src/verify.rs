use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::report::{LaneReport, StepResult, StepStatus};

/// Canonical routine verification steps.
///
/// This is the single source of truth for what CI runs on every pull request.
/// Derived from `docs/testing/verification-contract.md` Section 1.
fn verify_steps() -> Vec<(&'static str, &'static str)> {
    vec![
        ("fmt", "cargo fmt --all -- --check"),
        ("clippy", "cargo clippy --all-targets -- -D warnings"),
        ("core-compile", "cargo check --no-default-features"),
        (
            "repo-guards",
            "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci",
        ),
        (
            "security-regression",
            "cargo test --test security_regression --profile ci -- --test-threads=1",
        ),
        ("compile", "cargo test --lib --no-run"),
        (
            "boundary-composition-guard",
            "cargo test --test boundary_composition_guard",
        ),
        (
            "lifecycle-task-guard",
            "cargo test --test lifecycle_task_guard",
        ),
        ("plugin-guard", "cargo test --test plugin_guard"),
        ("cli-admin-guard", "cargo test --test cli_admin_guard"),
        ("security-guard", "cargo test --test security_guard"),
        (
            "root-facade-boundary-guard",
            "cargo test --test root_facade_boundary_guard",
        ),
        (
            "mesh-id-boundary-guard",
            "cargo test --test mesh_id_boundary_guard",
        ),
        (
            "admin-mutation-response-guard",
            "cargo test --test admin_mutation_response_guard",
        ),
        (
            "admin-mutation-blocklist",
            "cargo test --test admin_mutation_blocklist",
        ),
        (
            "admin-auth-boundary",
            "cargo test -p synvoid-core --test admin_auth_boundary",
        ),
        (
            "mesh-admin-edge-cases",
            "cargo test -p synvoid-core --test mesh_admin_edge_cases",
        ),
        ("failure-injection", "cargo test --test failure_injection"),
        (
            "worker-mesh-supervision-boundary-guard",
            "cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns",
        ),
        (
            "mesh-task-ownership-guard",
            "cargo test --test mesh_task_ownership_guard --features mesh,dns",
        ),
        (
            "abi-memory-boundary-guard",
            "cargo test --test abi_memory_boundary_guard",
        ),
        (
            "root-test-ownership-guard",
            "cargo test --test root_test_ownership_guard",
        ),
    ]
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

/// Find the workspace root by walking up to find Cargo.toml with [workspace].
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

/// Execute the canonical routine verification contract.
pub fn run_verify(dry_run: bool, json_output: bool, verbose: bool) -> Result<(), String> {
    let workspace_root = find_workspace_root()?;
    let steps = verify_steps();

    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  synvoid xtask verify");
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    let mut report = LaneReport::new("verify");

    for (name, cmd) in &steps {
        if dry_run {
            let result = StepResult {
                name: name.to_string(),
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
            name: name.to_string(),
            command: cmd.to_string(),
            status,
            duration_ms,
        });

        // Stop on first failure (fail-fast)
        if !success && !dry_run {
            if !json_output {
                println!();
                println!("  ✗ Failed at step: {name}");
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

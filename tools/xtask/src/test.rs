use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::affected;
use crate::lanes;
use crate::report::{LaneReport, StepResult, StepStatus};

/// Dispatch a `test` subcommand.
pub fn dispatch(
    positional: &[&str],
    flags: &[&str],
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    let workspace_root = find_workspace_root()?;

    match positional.first().copied() {
        Some("fast") => run_fast(&workspace_root, dry_run, json_output, verbose),
        Some("affected") => {
            let base_ref = find_flag_value(flags, "--base").unwrap_or("origin/main".to_string());
            run_affected(&workspace_root, &base_ref, dry_run, json_output, verbose)
        }
        Some("package") => {
            let pkg = positional
                .get(1)
                .ok_or("usage: cargo xtask test package <name>")?;
            run_package(pkg, &workspace_root, dry_run, json_output, verbose)
        }
        Some("guards") => run_lane(
            "guards",
            &workspace_root,
            dry_run,
            json_output,
            verbose,
            None,
            None,
        ),
        Some("security") => run_lane(
            "security",
            &workspace_root,
            dry_run,
            json_output,
            verbose,
            None,
            None,
        ),
        Some("comprehensive") => run_lane(
            "comprehensive",
            &workspace_root,
            dry_run,
            json_output,
            verbose,
            None,
            None,
        ),
        Some("nightly-plan") => run_lane(
            "nightly-plan",
            &workspace_root,
            dry_run,
            json_output,
            verbose,
            None,
            None,
        ),
        Some("qualification") => run_lane(
            "qualification",
            &workspace_root,
            dry_run,
            json_output,
            verbose,
            None,
            None,
        ),
        Some("release") => run_lane(
            "release",
            &workspace_root,
            dry_run,
            json_output,
            verbose,
            None,
            None,
        ),
        Some("list") => {
            list_lanes(json_output);
            Ok(())
        }
        Some("explain") => {
            let lane = positional
                .get(1)
                .ok_or("usage: cargo xtask test explain <lane>")?;
            explain_lane(lane, json_output)
        }
        Some(other) => Err(format!(
            "unknown test lane `{other}`. Run `cargo xtask test list` for available lanes."
        )),
        None => {
            Err("missing test lane. Run `cargo xtask test list` for available lanes.".to_string())
        }
    }
}

/// Find the workspace root by walking up to find Cargo.toml with [workspace].
fn find_workspace_root() -> Result<PathBuf, String> {
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

/// Find the value of a flag like --base from a list of flags.
fn find_flag_value(flags: &[&str], key: &str) -> Option<String> {
    for (i, flag) in flags.iter().enumerate() {
        if *flag == key {
            return flags.get(i + 1).map(|s| s.to_string());
        }
    }
    None
}

/// Run a single shell command. Returns (success, duration_ms).
fn run_command(cmd: &str, workspace_root: &Path, _verbose: bool) -> (bool, u64) {
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
            eprintln!("  failed to execute `{cmd}`: {e}");
            (false, duration_ms)
        }
    }
}

/// Run the fast lane.
fn run_fast(
    workspace_root: &Path,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    let lane = lanes::get_lane("fast").ok_or("fast lane not found")?;
    run_lane_inner(
        &lane,
        workspace_root,
        dry_run,
        json_output,
        verbose,
        None,
        None,
    )
}

/// Run the affected lane.
fn run_affected(
    workspace_root: &Path,
    base_ref: &str,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  synvoid xtask test affected");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!("  Base: {base_ref}");
        println!("  Head: HEAD");
        println!();
    }

    let selector_output =
        affected::run_selector(base_ref, "HEAD", dry_run, verbose, workspace_root)?;

    let mode = selector_output["mode"].as_str().unwrap_or("unknown");
    let reason = selector_output["reason"].as_str().unwrap_or("none");

    if !json_output {
        println!("  Mode:   {mode}");
        println!("  Reason: {reason}");
        println!();
    }

    if dry_run {
        let steps = affected::build_affected_steps(&selector_output, workspace_root);

        let mut report = LaneReport::new("affected");

        for step in &steps {
            let cmd = affected::resolve_command(step, Some(base_ref), None);
            let result = StepResult {
                name: step.name.to_string(),
                command: cmd,
                status: StepStatus::DryRun,
                duration_ms: 0,
            };
            report.add_result(result);
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            println!("{report}");
        }
        return Ok(());
    }

    let steps = affected::build_affected_steps(&selector_output, workspace_root);
    let mut report = LaneReport::new("affected");

    for step in &steps {
        let cmd = affected::resolve_command(step, Some(base_ref), None);
        if verbose {
            println!("  → {cmd}");
        }

        let (success, duration_ms) = run_command(&cmd, workspace_root, verbose);
        let status = if success {
            StepStatus::Success
        } else {
            StepStatus::Failed
        };

        report.add_result(StepResult {
            name: step.name.to_string(),
            command: cmd,
            status,
            duration_ms,
        });
    }

    report.check_budgets();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("{report}");
    }

    if !report.is_success() {
        return Err(format!("{} step(s) failed", report.failed));
    }

    if report.blocking_breaches() > 0 {
        return Err(format!(
            "{} blocking budget breach(es)",
            report.blocking_breaches()
        ));
    }

    Ok(())
}

/// Run a specific package test.
fn run_package(
    pkg: &str,
    workspace_root: &Path,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
) -> Result<(), String> {
    let cmd = format!("cargo nextest run -p {pkg} --cargo-profile ci --profile ci");

    if dry_run {
        let result = StepResult {
            name: pkg.to_string(),
            command: cmd,
            status: StepStatus::DryRun,
            duration_ms: 0,
        };
        let mut report = LaneReport::new("package");
        report.add_result(result);

        if json_output {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            println!("{report}");
        }
        return Ok(());
    }

    if !json_output {
        println!("Testing package: {pkg}");
    }

    let (success, duration_ms) = run_command(&cmd, workspace_root, verbose);

    let mut report = LaneReport::new("package");
    report.add_result(StepResult {
        name: pkg.to_string(),
        command: cmd,
        status: if success {
            StepStatus::Success
        } else {
            StepStatus::Failed
        },
        duration_ms,
    });

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("{report}");
    }

    if !report.is_success() {
        return Err(format!("package `{pkg}` test failed"));
    }

    Ok(())
}

/// Run a named lane.
fn run_lane(
    lane_name: &str,
    workspace_root: &Path,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
    base_ref: Option<&str>,
    package: Option<&str>,
) -> Result<(), String> {
    let lane = lanes::get_lane(lane_name).ok_or_else(|| format!("lane `{lane_name}` not found"))?;
    run_lane_inner(
        &lane,
        workspace_root,
        dry_run,
        json_output,
        verbose,
        base_ref,
        package,
    )
}

/// Inner implementation for running a lane.
fn run_lane_inner(
    lane: &lanes::Lane,
    workspace_root: &Path,
    dry_run: bool,
    json_output: bool,
    verbose: bool,
    base_ref: Option<&str>,
    package: Option<&str>,
) -> Result<(), String> {
    if !json_output {
        println!("═══════════════════════════════════════════════════════════");
        println!("  synvoid xtask test {}", lane.name);
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    let mut report = LaneReport::new(lane.name);

    for step in &lane.steps {
        let mut cmd = step.command.to_string();

        // Replace placeholders
        if let Some(base) = base_ref {
            cmd = cmd.replace("<BASE_REF>", base);
        }
        if let Some(pkg) = package {
            cmd = cmd.replace("<PKG>", pkg);
        }

        if dry_run {
            let result = StepResult {
                name: step.name.to_string(),
                command: cmd,
                status: StepStatus::DryRun,
                duration_ms: 0,
            };
            report.add_result(result);
            continue;
        }

        if verbose {
            println!("  → {cmd}");
        }

        let (success, duration_ms) = run_command(&cmd, workspace_root, verbose);
        let status = if success {
            StepStatus::Success
        } else {
            StepStatus::Failed
        };

        report.add_result(StepResult {
            name: step.name.to_string(),
            command: cmd,
            status,
            duration_ms,
        });
    }

    report.check_budgets();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("{report}");
    }

    if !report.is_success() {
        return Err(format!("{} step(s) failed", report.failed));
    }

    if report.blocking_breaches() > 0 {
        return Err(format!(
            "{} blocking budget breach(es)",
            report.blocking_breaches()
        ));
    }

    Ok(())
}

/// List all lanes.
fn list_lanes(json_output: bool) {
    let lane_names = lanes::list_lane_names();

    if json_output {
        let lanes: Vec<serde_json::Value> = lane_names
            .iter()
            .map(|name| {
                let lane = lanes::get_lane(name).unwrap();
                serde_json::json!({
                    "name": lane.name,
                    "description": lane.description,
                    "steps": lane.steps.len(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&lanes).unwrap());
    } else {
        println!("Available test lanes:");
        println!();
        for name in &lane_names {
            let lane = lanes::get_lane(name).unwrap();
            println!(
                "  {:<15} {} ({} steps)",
                lane.name,
                lane.description,
                lane.steps.len()
            );
        }
    }
}

/// Explain a specific lane.
fn explain_lane(lane_name: &str, json_output: bool) -> Result<(), String> {
    let lane = lanes::get_lane(lane_name).ok_or_else(|| format!("lane `{lane_name}` not found"))?;

    if json_output {
        let output = serde_json::json!({
            "name": lane.name,
            "description": lane.description,
            "steps": lane.steps.iter().map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "command": s.command,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("Lane: {}", lane.name);
        println!();
        println!("{}", lane.description);
        println!();
        println!("Steps:");
        for (i, step) in lane.steps.iter().enumerate() {
            println!("  {}. {} — {}", i + 1, step.name, step.command);
        }
    }

    Ok(())
}

//! Root-test ownership: STATIC_POLICY
//! Rationale: validates CLI/admin dispatch boundary across workspace
//!
//! Consolidated guard tests for CLI command dispatch, enforcement provenance,
//! and worker composition root boundaries.
//!
//! This file merges the following three guard test suites:
//! - `cli_command_dispatch_guard.rs` — ensures `src/main.rs` remains a thin
//!   process entrypoint and command dispatch follows plan/execute boundaries.
//! - `manual_enforcement_provenance_guard.rs` — ensures production enforcement
//!   paths use `block_ip_with_provenance` and avoid legacy `LegacyUnknown`
//!   provenance in production code.
//! - `unified_worker_composition_root_guard.rs` — ensures
//!   `run_unified_server_worker()` stays a thin orchestration wrapper and
//!   delegates to extracted modules (startup_plan, supervision_loop,
//!   shutdown_executor, mesh_attachment, supervisor_notify).

use std::fs;
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip single-line (`//`) and block (`/* */`) comments from source.
/// Byte-level scan for reliable handling of inline comments.
fn strip_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Recursively collect every `.rs` file under `dir`.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            results.extend(collect_rs_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            results.push(path);
        }
    }
    results
}

/// Strip everything from the first `#[cfg(test)]` attribute onward.
fn strip_test_modules(content: &str) -> &str {
    if let Some(idx) = content.find("#[cfg(test)]") {
        &content[..idx]
    } else {
        content
    }
}

/// For a given file content (already stripped of test modules and comments),
/// return line numbers where `.block_ip(` appears outside of trait defs and
/// `BlockEntry::new()` calls.
fn find_legacy_block_ip_calls(content: &str) -> Vec<usize> {
    let mut violations = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("trait ") || trimmed.starts_with("pub trait ") {
            continue;
        }

        if line.contains("BlockEntry::new(") {
            continue;
        }

        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        if line.contains(".block_ip(") && !line.contains(".block_ip_with_provenance(") {
            violations.push(idx + 1);
        }
    }
    violations
}

/// Compute line ranges (0-indexed start, 1-indexed end) for `impl Default`
/// and `fn default()` blocks so they can be excluded from scanning.
fn default_impl_line_ranges(content: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.contains("impl Default") || trimmed.contains("fn default()") {
            let start = i;
            let mut depth: i32 = 0;
            let mut found_open = false;
            let mut j = i;
            while j < lines.len() {
                for ch in lines[j].chars() {
                    if ch == '{' {
                        depth += 1;
                        found_open = true;
                    } else if ch == '}' {
                        depth -= 1;
                    }
                }
                if found_open && depth == 0 {
                    ranges.push((start, j + 1));
                    i = j + 1;
                    break;
                }
                j += 1;
                if j == lines.len() {
                    ranges.push((start, j));
                    i = j;
                    break;
                }
            }
            if !found_open {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    ranges
}

/// For a given file content (already stripped of test modules and comments),
/// return line numbers where `LegacyUnknown` is used as an explicit provenance
/// kind outside of tests and default impls.
fn find_legacy_unknown_usages(content: &str) -> Vec<usize> {
    let skip_ranges = default_impl_line_ranges(content);
    let mut violations = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        let inside_default = skip_ranges
            .iter()
            .any(|&(start, end)| idx >= start && idx < end);
        if inside_default {
            continue;
        }

        if line.contains("BlockProvenanceKind::LegacyUnknown") {
            violations.push(idx + 1);
        }
    }
    violations
}

/// Scan for unconditional `BlockProvenanceKind::SupervisorSync` in blocklist
/// ingestion paths, excluding the `ipc_data_to_provenance` helper.
fn find_unconditional_supervisor_sync(content: &str) -> Vec<usize> {
    let mut violations = Vec::new();
    let mut in_helper = false;
    let mut depth: i32 = 0;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("fn ipc_data_to_provenance(") {
            in_helper = true;
            depth = 0;
        }
        if in_helper {
            for ch in trimmed.chars() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                    if depth == 0 {
                        in_helper = false;
                    }
                }
            }
            continue;
        }

        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        if trimmed.starts_with("//") {
            continue;
        }

        if line.contains("BlockProvenanceKind::SupervisorSync")
            && !line.contains("Some(\"SupervisorSync\")")
        {
            violations.push(idx + 1);
        }
    }
    violations
}

/// Extract the body of `run_unified_server_worker()` from the source.
fn extract_run_unified_server_worker_body(source: &str) -> String {
    let start = source
        .find("pub async fn run_unified_server_worker")
        .expect("function exists");
    let body = &source[start..];

    let end = body
        .lines()
        .enumerate()
        .find(|(_, line)| {
            if line.starts_with("#[cfg(test)]") {
                return true;
            }
            if line.trim() == "}" && !line.starts_with(' ') && !line.starts_with('\t') {
                return true;
            }
            false
        })
        .map(|(i, _)| i)
        .unwrap_or(0);

    body.lines().take(end).collect::<Vec<&str>>().join("\n")
}

/// Extract the body of a named async function from source.
fn extract_function_body(source: &str, name: &str) -> String {
    let needle = format!("async fn {}", name);
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("function '{}' not found in source", name));
    let body = &source[start..];

    let mut depth = 0;
    let mut found_open = false;
    let mut end = body.len();
    for (i, ch) in body.char_indices() {
        match ch {
            '{' => {
                depth += 1;
                found_open = true;
            }
            '}' => {
                depth -= 1;
                if found_open && depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }

    body[..end].to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section: CLI Command Dispatch Guards
// (from tests/cli_command_dispatch_guard.rs)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn main_rs_remains_thin_command_entrypoint() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/main.rs")).expect("read src/main.rs");
    let non_comment = strip_comments(&source);

    let line_count = non_comment.lines().count();
    assert!(
        line_count <= 30,
        "src/main.rs should remain a thin process entrypoint, found {} non-comment lines (limit 30)",
        line_count
    );

    assert!(
        non_comment.contains("plan_command"),
        "src/main.rs should delegate to plan_command()"
    );

    assert!(
        non_comment.contains("execute_command"),
        "src/main.rs should delegate to execute_command()"
    );
}

#[test]
fn main_rs_does_not_contain_command_implementations() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/main.rs")).expect("read src/main.rs");
    let non_comment = strip_comments(&source);

    let forbidden = [
        "export_threat_feed",
        "generate_token",
        "handle_configtest",
        "handle_generatenewtoken",
        "handle_generatetoken",
        "handle_rehash",
        "handle_status",
        "handle_stop",
        "run_unified_server_worker",
        "run_cpu_worker",
        "setup_worker_panic_handler",
        "setup_unified_server_panic_handler",
        "acquire_pid_file",
        "print_test_mode_warning",
        "build_cpu_worker_args",
        "build_unified_server_worker_args",
    ];

    let mut violations = Vec::new();
    for token in &forbidden {
        if non_comment.contains(token) {
            violations.push(*token);
        }
    }

    assert!(
        violations.is_empty(),
        "src/main.rs contains command implementations that should live in src/commands/: {:?}",
        violations
    );
}

#[test]
fn command_dispatch_does_not_drop_restart_control_tls() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        !non_comment.contains("handle_stop(ca, false)"),
        "restart pre-stop must not force TLS=false or drop control address"
    );
}

#[test]
fn execute_uses_typed_pre_action_for_restart() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("CommandPreAction::RestartSupervisor"),
        "restart must use typed CommandPreAction::RestartSupervisor"
    );
}

#[test]
fn supervisor_control_exit_mapping_is_typed() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("SupervisorControlOutcome")
            || non_comment.contains("execute_supervisor_control_command"),
        "execute.rs must use typed SupervisorControlOutcome or execute_supervisor_control_command for supervisor-control exit mapping"
    );
}

#[test]
fn restart_pre_action_uses_supervisor_control_adapter() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("execute_restart_pre_stop"),
        "restart pre-stop must use execute_restart_pre_stop adapter"
    );
}

#[test]
fn supervisor_control_module_exists() {
    let root = workspace_root();
    let path = root.join("src/commands/supervisor_control.rs");
    assert!(
        path.exists(),
        "src/commands/supervisor_control.rs must exist for typed supervisor-control boundary"
    );
}

#[test]
fn supervisor_control_outcome_type_is_exported() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/mod.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("SupervisorControlOutcome"),
        "src/commands/mod.rs must export SupervisorControlOutcome"
    );
    assert!(
        non_comment.contains("SupervisorControlError"),
        "src/commands/mod.rs must export SupervisorControlError"
    );
}

#[test]
fn supervisor_control_does_not_use_placeholder_threat_feed_bytes() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/supervisor_control.rs")).unwrap();

    assert!(
        !source.contains("ThreatFeedExported { bytes: 0 }"),
        "supervisor_control.rs must not use placeholder ThreatFeedExported {{ bytes: 0 }} — use ThreatFeedExportSummary instead"
    );
}

#[test]
fn execute_delegates_formatting_through_outcomes() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("outcome.display()"),
        "execute.rs must delegate formatting through outcome.display() — handlers should not print directly"
    );
}

#[test]
fn supervisor_control_outcome_has_data_bearing_variants() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/supervisor_control.rs")).unwrap();

    assert!(
        source.contains("Status(SupervisorStatusDisplay)"),
        "SupervisorControlOutcome must have Status(SupervisorStatusDisplay) variant"
    );
    assert!(
        source.contains("ThreatFeedExported(ThreatFeedExportSummary)"),
        "SupervisorControlOutcome must have ThreatFeedExported(ThreatFeedExportSummary) variant"
    );
}

#[test]
fn supervisor_control_error_has_actionable_variants() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/supervisor_control.rs")).unwrap();

    assert!(
        source.contains("ConnectionUnavailable"),
        "SupervisorControlError must have ConnectionUnavailable variant"
    );
    assert!(
        source.contains("Timeout"),
        "SupervisorControlError must have Timeout variant"
    );
}

#[test]
fn supervisor_control_uses_classified_error_conversion() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/supervisor_control.rs")).unwrap();

    assert!(
        source.contains("classify_control_error"),
        "supervisor_control.rs must use classify_control_error for error conversion"
    );
    assert!(
        !source.contains("boxed_error_to_control_error"),
        "supervisor_control.rs must not contain boxed_error_to_control_error — replaced by classify_control_error"
    );
}

#[test]
fn execute_rs_does_not_build_runtimes_or_worker_args() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    let forbidden = [
        "tokio::runtime::Builder",
        "build_cpu_worker_args",
        "build_unified_server_worker_args",
        "run_cpu_worker",
        "run_unified_server_worker",
        "acquire_pid_file",
        "setup_worker_panic_handler",
        "setup_unified_server_panic_handler",
        "init_logging_simple",
    ];

    let mut violations = Vec::new();
    for token in &forbidden {
        if non_comment.contains(token) {
            violations.push(*token);
        }
    }

    assert!(
        violations.is_empty(),
        "src/commands/execute.rs contains runtime-launch details that should live in runtime_launch.rs: {:?}",
        violations
    );
}

#[test]
fn execute_rs_delegates_to_runtime_launch_boundary() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("plan_runtime_launch") || non_comment.contains("runtime_launch"),
        "execute.rs must reference the runtime-launch boundary (plan_runtime_launch or runtime_launch module)"
    );
}

#[test]
fn runtime_launch_module_exists() {
    let root = workspace_root();
    let path = root.join("src/commands/runtime_launch.rs");
    assert!(
        path.exists(),
        "src/commands/runtime_launch.rs must exist for typed runtime-launch boundary"
    );
}

#[test]
fn runtime_launch_has_planner_and_executor() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/runtime_launch.rs")).unwrap();

    assert!(
        source.contains("pub fn plan_runtime_launch"),
        "runtime_launch.rs must export plan_runtime_launch()"
    );
    assert!(
        source.contains("pub fn execute_runtime_launch"),
        "runtime_launch.rs must export execute_runtime_launch()"
    );
    assert!(
        source.contains("RuntimeLaunchContext"),
        "runtime_launch.rs must define RuntimeLaunchContext"
    );
    assert!(
        source.contains("RuntimeLaunchPlan"),
        "runtime_launch.rs must define RuntimeLaunchPlan"
    );
}

#[test]
fn runtime_launch_plan_pure_no_tokio_builder() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/runtime_launch.rs")).unwrap();

    let planner_start = source.find("pub fn plan_runtime_launch").unwrap();
    let planner_end = source.find("pub fn execute_runtime_launch").unwrap();
    let planner_body = &source[planner_start..planner_end];

    assert!(
        !planner_body.contains("tokio::runtime::Builder"),
        "plan_runtime_launch() must not build Tokio runtimes — it should be pure"
    );
    assert!(
        !planner_body.contains("acquire_pid_file"),
        "plan_runtime_launch() must not acquire PID files — it should be pure"
    );
    assert!(
        !planner_body.contains("init_logging"),
        "plan_runtime_launch() must not initialize logging — it should be pure"
    );
}

#[test]
fn runtime_launch_mod_exports_types() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/mod.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("RuntimeLaunchContext"),
        "commands/mod.rs must export RuntimeLaunchContext"
    );
    assert!(
        non_comment.contains("RuntimeLaunchPlan"),
        "commands/mod.rs must export RuntimeLaunchPlan"
    );
    assert!(
        non_comment.contains("RuntimeLaunchOutcome"),
        "commands/mod.rs must export RuntimeLaunchOutcome"
    );
    assert!(
        non_comment.contains("plan_runtime_launch"),
        "commands/mod.rs must export plan_runtime_launch"
    );
    assert!(
        non_comment.contains("execute_runtime_launch"),
        "commands/mod.rs must export execute_runtime_launch"
    );
}

// --- One-shot command boundary guards (Iteration 107) ---

#[test]
fn one_shot_module_exists() {
    let root = workspace_root();
    let path = root.join("src/commands/one_shot.rs");
    assert!(
        path.exists(),
        "src/commands/one_shot.rs must exist for typed one-shot boundary"
    );
}

#[test]
fn one_shot_outcome_type_is_exported() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/mod.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("OneShotOutcome"),
        "src/commands/mod.rs must export OneShotOutcome"
    );
    assert!(
        non_comment.contains("OneShotError"),
        "src/commands/mod.rs must export OneShotError"
    );
}

#[test]
fn one_shot_has_execute_one_shot_command() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    assert!(
        source.contains("pub fn execute_one_shot_command"),
        "one_shot.rs must export execute_one_shot_command()"
    );
}

#[test]
fn execute_rs_delegates_to_one_shot_adapter() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        non_comment.contains("execute_one_shot_command"),
        "execute.rs must delegate to execute_one_shot_command for one-shot commands"
    );
}

#[test]
fn execute_rs_does_not_contain_one_shot_implementation_details() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    let forbidden = [
        "schema_for!",
        "synvoidOpenApi::openapi_json",
        "hash_admin_token_with_cost",
        "check_regex_complexity",
        "GenesisKeyConfig::generate",
    ];

    let mut violations = Vec::new();
    for token in &forbidden {
        if non_comment.contains(token) {
            violations.push(*token);
        }
    }

    assert!(
        violations.is_empty(),
        "src/commands/execute.rs contains one-shot implementation details that should live in one_shot.rs: {:?}",
        violations
    );
}

#[test]
fn one_shot_outcome_has_exit_code() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    assert!(
        source.contains("pub fn exit_code"),
        "OneShotOutcome must have exit_code() method"
    );
}

#[test]
fn one_shot_outcome_has_display() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    assert!(
        source.contains("pub fn display"),
        "OneShotOutcome must have display() method"
    );
}

#[test]
fn one_shot_error_has_display_impl() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    assert!(
        source.contains("impl std::fmt::Display for OneShotError"),
        "OneShotError must implement Display"
    );
}

#[test]
fn one_shot_error_has_exit_code() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    assert!(
        source.contains("pub fn exit_code"),
        "OneShotError must have exit_code() method"
    );
}

// --- Iteration 108: Documentation synchronization guards ---

#[test]
fn architecture_doc_lists_all_command_categories() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("OneShot"),
        "architecture doc must mention OneShot command category"
    );
    assert!(
        source.contains("SupervisorControl"),
        "architecture doc must mention SupervisorControl command category"
    );
    assert!(
        source.contains("Runtime"),
        "architecture doc must mention Runtime command category"
    );
}

#[test]
fn architecture_doc_mentions_restart_pre_action() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("RestartSupervisor"),
        "architecture doc must mention RestartSupervisor pre-action"
    );
    assert!(
        source.contains("pre-action") || source.contains("Pre-Action"),
        "architecture doc must document pre-actions"
    );
}

#[test]
fn architecture_doc_mentions_runtime_launch_boundary() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("RuntimeLaunchPlan"),
        "architecture doc must mention RuntimeLaunchPlan"
    );
    assert!(
        source.contains("plan_runtime_launch"),
        "architecture doc must mention plan_runtime_launch"
    );
    assert!(
        source.contains("execute_runtime_launch"),
        "architecture doc must mention execute_runtime_launch"
    );
}

#[test]
fn architecture_doc_mentions_one_shot_boundary() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("OneShotOutcome"),
        "architecture doc must mention OneShotOutcome"
    );
    assert!(
        source.contains("OneShotError"),
        "architecture doc must mention OneShotError"
    );
    assert!(
        source.contains("execute_one_shot_command"),
        "architecture doc must mention execute_one_shot_command"
    );
}

#[test]
fn architecture_doc_mentions_supervisor_control_boundary() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("SupervisorControlOutcome"),
        "architecture doc must mention SupervisorControlOutcome"
    );
    assert!(
        source.contains("SupervisorControlError"),
        "architecture doc must mention SupervisorControlError"
    );
    assert!(
        source.contains("classify_control_error"),
        "architecture doc must mention classify_control_error"
    );
}

#[test]
fn architecture_doc_mentions_exit_code_model() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("Exit Code") || source.contains("exit code"),
        "architecture doc must document exit code model"
    );
}

#[test]
fn architecture_doc_mentions_precedence_rules() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("Precedence") || source.contains("precedence"),
        "architecture doc must document precedence rules"
    );
}

// --- Iteration 109: Output contract guards ---

#[test]
fn one_shot_json_outputs_are_not_prefixed_with_human_text() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    assert!(
        !source.contains("OpenAPI schema:"),
        "one_shot.rs must not contain 'OpenAPI schema:' preamble in display"
    );
    assert!(
        !source.contains("Exported OpenAPI"),
        "one_shot.rs must not contain 'Exported OpenAPI' in display"
    );
    assert!(
        !source.contains("API Schema"),
        "one_shot.rs must not contain 'API Schema' in display"
    );
}

#[test]
fn token_hash_outputs_are_not_labeled() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/one_shot.rs")).unwrap();

    let display_start = source
        .find("pub fn display(")
        .expect("display function must exist");
    let display_body = &source[display_start..];

    assert!(
        !display_body.contains("Hash: {}"),
        "display() must not format output as 'Hash: {{}}' — hash must be bare"
    );
    assert!(
        !display_body.contains("Token: {}"),
        "display() must not format output as 'Token: {{}}' — token must be bare"
    );
}

#[test]
fn output_contract_section_exists_in_architecture_doc() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("Output Compatibility Contracts") || source.contains("Output Contract"),
        "architecture doc must document output compatibility contracts"
    );
}

#[test]
fn output_contract_documents_script_facing_commands() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("architecture/cli_supervisor_command_dispatch.md"))
            .unwrap();

    assert!(
        source.contains("--export-openapi"),
        "output contract must document --export-openapi"
    );
    assert!(
        source.contains("--export-api-spec"),
        "output contract must document --export-api-spec"
    );
    assert!(
        source.contains("--hash-token"),
        "output contract must document --hash-token"
    );
    assert!(
        source.contains("--generatetoken"),
        "output contract must document --generatetoken"
    );
    assert!(
        source.contains("--generatenewtoken"),
        "output contract must document --generatenewtoken"
    );
    assert!(
        source.contains("--checkregex"),
        "output contract must document --checkregex"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section: Enforcement Provenance Guards
// (from tests/manual_enforcement_provenance_guard.rs)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Denylist directories ─────────────────────────────────────────────────────

const DENYLIST_DIRS: &[&str] = &["src/admin", "src/supervisor", "src/worker/unified_server"];

const BLOCKLIST_INGESTION_DIRS: &[&str] =
    &["src/worker/unified_server", "src/supervisor", "src/process"];

// ── Phase 1: Legacy .block_ip() Check ────────────────────────────────────────

#[test]
fn no_legacy_block_ip_in_production_paths() {
    let workspace_root = workspace_root();
    let mut violations: Vec<String> = Vec::new();

    for dir in DENYLIST_DIRS {
        let path = workspace_root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_test_modules(&content);
            let production = strip_comments(production);

            let lines = find_legacy_block_ip_calls(&production);
            if !lines.is_empty() {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                violations.push(format!(
                    "  {relative}: .block_ip( found at lines: {}",
                    line_list.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Legacy `.block_ip()` method used in a production enforcement path. \
             Use `block_ip_with_provenance()` instead, which records provenance \
             for audit and trust-domain classification.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 2: LegacyUnknown Provenance Check ──────────────────────────────────

#[test]
fn no_explicit_legacy_unknown_provenance_in_production() {
    let workspace_root = workspace_root();
    let mut violations: Vec<String> = Vec::new();

    for dir in DENYLIST_DIRS {
        let path = workspace_root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_test_modules(&content);
            let production = strip_comments(production);

            let lines = find_legacy_unknown_usages(&production);
            if !lines.is_empty() {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                violations.push(format!(
                    "  {relative}: LegacyUnknown used at lines: {}",
                    line_list.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Explicit `LegacyUnknown` provenance kind used in production code. \
             New enforcement paths should use a meaningful provenance kind \
             (e.g. `WafEnforcement`, `MeshSync`, `AdminAction`). \
             `LegacyUnknown` is acceptable only in Default impls, backward-compat \
             shims, and tests.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 3: Positive Boundary Tests ─────────────────────────────────────────

#[test]
fn denylist_directories_are_valid() {
    let workspace_root = workspace_root();

    for dir in DENYLIST_DIRS {
        let path = workspace_root.join(dir);
        if path.exists() {
            let files = collect_rs_files(&path);
            assert!(
                !files.is_empty(),
                "Denylist directory `{dir}` exists but contains no .rs files"
            );
        }
    }
}

#[test]
fn simulated_legacy_block_ip_is_detected() {
    let fake_content =
        "fn handle_block() {\n    store.block_ip(ip, \"reason\", 3600, Scope::Global);\n}\n";

    let lines = find_legacy_block_ip_calls(fake_content);
    assert!(
        !lines.is_empty(),
        "Simulated legacy .block_ip( call must be detected"
    );
}

#[test]
fn provenance_api_is_not_flagged() {
    let fake_content =
        "fn handle_block() {\n    store.block_ip_with_provenance(ip, \"reason\", 3600, Scope::Global, provenance);\n}\n";

    let lines = find_legacy_block_ip_calls(fake_content);
    assert!(
        lines.is_empty(),
        "block_ip_with_provenance should not be flagged as a violation"
    );
}

#[test]
fn block_entry_new_is_not_flagged() {
    let fake_content =
        "fn create_entry() {\n    let entry = BlockEntry::new(ip, reason, ttl, scope);\n}\n";

    let lines = find_legacy_block_ip_calls(fake_content);
    assert!(
        lines.is_empty(),
        "BlockEntry::new() should not be flagged as a .block_ip( violation"
    );
}

#[test]
fn simulated_legacy_unknown_is_detected() {
    let fake_content =
        "fn apply_block() {\n    let provenance = BlockProvenanceKind::LegacyUnknown;\n}\n";

    let lines = find_legacy_unknown_usages(fake_content);
    assert!(
        !lines.is_empty(),
        "Simulated LegacyUnknown in production code must be detected"
    );
}

#[test]
fn legacy_unknown_in_default_impl_is_not_flagged() {
    let fake_content =
        "impl Default for Foo {\n    fn default() -> Self {\n        Self { kind: BlockProvenanceKind::LegacyUnknown }\n    }\n}\n";

    let lines = find_legacy_unknown_usages(fake_content);
    assert!(
        lines.is_empty(),
        "LegacyUnknown in Default impl should not be flagged"
    );
}

#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let content = r#"
        fn real_function() {
            store.block_ip(ip, "reason", 3600, Scope::Global);
        }

        #[cfg(test)]
        mod tests {
            fn test_block() {
                store.block_ip(ip, "reason", 3600, Scope::Global);
            }
        }
    "#;

    let stripped = strip_test_modules(content);

    assert!(
        !stripped.contains("#[cfg(test)]"),
        "Test module marker should be stripped"
    );
    let lines = find_legacy_block_ip_calls(&strip_comments(stripped));
    assert!(
        !lines.is_empty(),
        "Production .block_ip( before #[cfg(test)] must still be detected"
    );
}

// ── Phase 4: Iteration 50 — SupervisorSync Provenance Guard ───────────────────

#[test]
fn no_unconditional_supervisor_sync_in_blocklist_ingestion() {
    let workspace_root = workspace_root();
    let mut violations: Vec<String> = Vec::new();

    for dir in BLOCKLIST_INGESTION_DIRS {
        let path = workspace_root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_test_modules(&content);
            let production = strip_comments(production);

            let lines = find_unconditional_supervisor_sync(&production);
            if !lines.is_empty() {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                violations.push(format!(
                    "  {relative}: SupervisorSync used at lines: {}",
                    line_list.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Unconditional `BlockProvenanceKind::SupervisorSync` found in blocklist ingestion paths. \
             After Iteration 50, these paths must use `ipc_data_to_provenance()` to preserve \
             original provenance. `SupervisorSync` should only be used when the supervisor \
             itself originated the block, not as a blanket relay default.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

#[test]
fn simulated_unconditional_supervisor_sync_is_detected() {
    let fake_content = r#"fn apply_blocklist_update() {
    let provenance = BlockProvenance {
        kind: BlockProvenanceKind::SupervisorSync,
        source: Some("blocklist_update".to_string()),
    };
}"#;

    let lines = find_unconditional_supervisor_sync(fake_content);
    assert!(
        !lines.is_empty(),
        "Simulated unconditional SupervisorSync must be detected"
    );
}

#[test]
fn supervisor_sync_in_helper_is_not_flagged() {
    let fake_content = r#"fn ipc_data_to_provenance(kind_str: Option<&str>, source: Option<&str>) -> BlockProvenance {
    let kind = match kind_str {
        Some("SupervisorSync") => BlockProvenanceKind::SupervisorSync,
        _ => BlockProvenanceKind::LegacyUnknown,
    };
}"#;

    let lines = find_unconditional_supervisor_sync(fake_content);
    assert!(
        lines.is_empty(),
        "SupervisorSync in ipc_data_to_provenance helper should not be flagged"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section: Worker Composition Root Guards
// (from tests/unified_worker_composition_root_guard.rs)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn run_unified_server_worker_remains_a_thin_orchestration_wrapper() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    let function = extract_run_unified_server_worker_body(&source);
    let line_count = function.lines().count();

    assert!(
        line_count <= 80,
        "run_unified_server_worker should stay a thin orchestration wrapper; found {} lines (threshold: 80). \
         If the function grew, consider extracting more logic into startup_plan, supervision_loop, \
         shutdown_executor, or supervisor_notify modules.",
        line_count
    );
}

#[test]
fn run_unified_server_worker_does_not_map_supervision_outcome_inline() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    let function = extract_run_unified_server_worker_body(&source);

    assert!(
        !function.contains("match supervision_result.outcome"),
        "run_unified_server_worker must not map supervision outcome inline; \
         delegate to shutdown_executor::WorkerShutdownPlan::from_supervision_outcome"
    );
    assert!(
        !function.contains("SupervisionOutcome::Lifecycle"),
        "run_unified_server_worker must not contain SupervisionOutcome::Lifecycle"
    );
    assert!(
        !function.contains("SupervisionOutcome::DirectCause"),
        "run_unified_server_worker must not contain SupervisionOutcome::DirectCause"
    );
}

#[test]
fn run_unified_server_worker_delegates_to_startup_plan() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("startup_plan::build_worker_startup"),
        "run_unified_server_worker must delegate startup to startup_plan::build_worker_startup"
    );
}

#[test]
fn run_unified_server_worker_delegates_to_supervision_loop() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("supervision_loop::run_worker_supervision"),
        "run_unified_server_worker must delegate supervision to supervision_loop::run_worker_supervision"
    );
}

#[test]
fn run_unified_server_worker_delegates_to_shutdown_executor() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("shutdown_executor::execute_worker_shutdown"),
        "run_unified_server_worker must delegate shutdown to shutdown_executor::execute_worker_shutdown"
    );
}

#[test]
fn run_unified_server_worker_uses_from_supervision_result() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("WorkerShutdownContext::from_supervision_result"),
        "run_unified_server_worker must use WorkerShutdownContext::from_supervision_result"
    );
}

#[test]
fn startup_plan_module_exists() {
    let repo = workspace_root();
    assert!(
        repo.join("src/worker/unified_server/startup_plan.rs")
            .exists(),
        "startup_plan.rs module must exist"
    );
}

#[test]
fn supervision_loop_module_exists() {
    let repo = workspace_root();
    assert!(
        repo.join("src/worker/unified_server/supervision_loop.rs")
            .exists(),
        "supervision_loop.rs module must exist"
    );
}

#[test]
fn shutdown_executor_module_exists() {
    let repo = workspace_root();
    assert!(
        repo.join("src/worker/unified_server/shutdown_executor.rs")
            .exists(),
        "shutdown_executor.rs module must exist"
    );
}

#[test]
fn supervisor_notify_module_exists() {
    let repo = workspace_root();
    assert!(
        repo.join("src/worker/unified_server/supervisor_notify.rs")
            .exists(),
        "supervisor_notify.rs module must exist"
    );
}

#[test]
fn shutdown_executor_does_not_call_startup_builders() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/shutdown_executor.rs"))
            .unwrap();
    let non_comment_lines: Vec<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let non_comment_source = non_comment_lines.join("\n");
    assert!(
        !non_comment_source.contains("build_worker_startup"),
        "shutdown_executor.rs must not call startup builders"
    );
    assert!(
        !non_comment_source.contains("init_mesh_and_threat_intel"),
        "shutdown_executor.rs must not initialize mesh"
    );
}

#[test]
fn shutdown_executor_explicitly_stops_active_mesh_support() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/shutdown_executor.rs"))
            .unwrap();
    let non_comment_lines: Vec<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let non_comment_source = non_comment_lines.join("\n");

    assert!(
        non_comment_source.contains("stop_mesh_generation_support"),
        "shutdown_executor.rs must explicitly stop active mesh support via stop_mesh_generation_support"
    );
    assert!(
        non_comment_source.contains("SupportStopContext::WorkerShutdown"),
        "shutdown_executor.rs must use SupportStopContext::WorkerShutdown for whole-worker shutdown"
    );
    assert!(
        !non_comment_source.contains("active_mesh_support: _,"),
        "shutdown_executor.rs must not discard active_mesh_support with _"
    );
}

#[test]
fn shutdown_executor_has_from_supervision_outcome() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/shutdown_executor.rs"))
            .unwrap();
    assert!(
        source.contains("fn from_supervision_outcome"),
        "shutdown_executor.rs must contain WorkerShutdownPlan::from_supervision_outcome"
    );
    assert!(
        source.contains("struct WorkerShutdownPlan"),
        "shutdown_executor.rs must define WorkerShutdownPlan"
    );
}

#[test]
fn startup_plan_does_not_perform_shutdown() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    let non_comment_lines: Vec<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let non_comment_source = non_comment_lines.join("\n");
    assert!(
        !non_comment_source.contains("shutdown_and_join"),
        "startup_plan.rs must not call shutdown_and_join"
    );
    assert!(
        !non_comment_source.contains("begin_coordinated_shutdown"),
        "startup_plan.rs must not call begin_coordinated_shutdown"
    );
}

// ── Iteration 95: mesh attachment extraction ────────────────────────────────

#[test]
fn startup_plan_delegates_mesh_attachment() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    assert!(
        source.contains("mesh_attachment"),
        "startup_plan.rs must reference mesh_attachment module"
    );
    assert!(
        source.contains("attach_mesh"),
        "startup_plan.rs must call attach_mesh"
    );
}

#[test]
fn startup_plan_no_longer_owns_mesh_select_loop() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    let non_comment_lines: Vec<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let non_comment_source = non_comment_lines.join("\n");
    assert!(
        !non_comment_source.contains("mesh_support_registration"),
        "startup_plan.rs must not contain mesh_support_registration one-shot"
    );
    assert!(
        !non_comment_source.contains("pending_optional_failure"),
        "startup_plan.rs must not contain pending_optional_failure tracking"
    );
    assert!(
        !non_comment_source.contains("MeshSupervisorDecision::RestartMesh"),
        "startup_plan.rs must not handle RestartMesh decisions inline"
    );
}

#[test]
fn mesh_attachment_module_exists() {
    let repo = workspace_root();
    assert!(
        repo.join("src/worker/unified_server/mesh_attachment.rs")
            .exists(),
        "mesh_attachment.rs module must exist"
    );
}

#[test]
fn mesh_attachment_owns_optional_degradation_cleanup() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    assert!(
        source.contains("SupportStopContext::OptionalMeshDegraded"),
        "mesh_attachment.rs must handle optional degradation cleanup"
    );
    assert!(
        source.contains("stop_mesh_generation_support"),
        "mesh_attachment.rs must call stop_mesh_generation_support"
    );
}

#[test]
fn mesh_attachment_handles_required_mesh_startup() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    assert!(
        source.contains("start_mesh_generation"),
        "mesh_attachment.rs must call start_mesh_generation for required mesh"
    );
    assert!(
        source.contains("register_mesh_generation_support"),
        "mesh_attachment.rs must register mesh generation support"
    );
}

#[test]
fn mesh_attachment_handles_optional_mesh_startup() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    assert!(
        source.contains("mesh_startup"),
        "mesh_attachment.rs must spawn mesh_startup one-shot"
    );
    assert!(
        source.contains("mesh_support_registration"),
        "mesh_attachment.rs must spawn mesh_support_registration one-shot"
    );
}

#[test]
fn mod_rs_declares_mesh_attachment() {
    let repo = workspace_root();
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("pub mod mesh_attachment"),
        "mod.rs must declare mesh_attachment module"
    );
}

// ── Iteration 96: attach_mesh polish guards ────────────────────────────────

#[test]
fn attach_mesh_remains_a_thin_orchestration_wrapper() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    let function = extract_function_body(&source, "attach_mesh");
    let line_count = function.lines().count();

    assert!(
        line_count <= 80,
        "attach_mesh should stay a thin orchestration wrapper; found {} lines (threshold: 80). \
         If the function grew, consider extracting more logic into helper functions.",
        line_count
    );
}

#[test]
fn attach_mesh_delegates_required_and_optional_paths() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    let function = extract_function_body(&source, "attach_mesh");

    assert!(
        function.contains("start_required_mesh"),
        "attach_mesh must delegate required path to start_required_mesh"
    );
    assert!(
        function.contains("start_optional_mesh")
            || function.contains("await_optional_mesh_startup"),
        "attach_mesh must delegate optional path to a startup helper"
    );
    assert!(
        !function.contains("tokio::select!"),
        "attach_mesh must not contain tokio::select! inline"
    );
    assert!(
        !function.contains("pending_optional_failure"),
        "attach_mesh must not track pending_optional_failure inline"
    );
}

#[test]
fn mesh_attachment_owns_critical_patterns() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();

    assert!(
        source.contains("mesh_support_registration"),
        "mesh_attachment.rs must own mesh_support_registration pattern"
    );
    assert!(
        source.contains("mesh_startup"),
        "mesh_attachment.rs must own mesh_startup pattern"
    );
    assert!(
        source.contains("SupportStopContext::OptionalMeshDegraded"),
        "mesh_attachment.rs must own OptionalMeshDegraded cleanup"
    );
    assert!(
        !source.contains("SupportStopContext::WorkerShutdown"),
        "mesh_attachment.rs must not own WorkerShutdown cleanup (belongs in shutdown_executor.rs)"
    );
}

#[test]
fn mesh_attachment_has_helper_structs() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();

    assert!(
        source.contains("struct MeshPipelineRuntime"),
        "mesh_attachment.rs must define MeshPipelineRuntime"
    );
    assert!(
        source.contains("struct RequiredMeshStartInput"),
        "mesh_attachment.rs must define RequiredMeshStartInput"
    );
    assert!(
        source.contains("struct RequiredMeshStartOutput"),
        "mesh_attachment.rs must define RequiredMeshStartOutput"
    );
    assert!(
        source.contains("struct OptionalMeshStartInput"),
        "mesh_attachment.rs must define OptionalMeshStartInput"
    );
    assert!(
        source.contains("struct OptionalMeshStartOutput"),
        "mesh_attachment.rs must define OptionalMeshStartOutput"
    );
}

#[test]
fn mesh_attachment_has_extracted_helpers() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();

    assert!(
        source.contains("fn create_mesh_pipeline"),
        "mesh_attachment.rs must define create_mesh_pipeline helper"
    );
    assert!(
        source.contains("fn send_ready_if_deferred"),
        "mesh_attachment.rs must define send_ready_if_deferred helper"
    );
    assert!(
        source.contains("fn start_required_mesh"),
        "mesh_attachment.rs must define start_required_mesh helper"
    );
    assert!(
        source.contains("fn spawn_optional_support_registration"),
        "mesh_attachment.rs must define spawn_optional_support_registration helper"
    );
    assert!(
        source.contains("fn spawn_optional_mesh_startup"),
        "mesh_attachment.rs must define spawn_optional_mesh_startup helper"
    );
    assert!(
        source.contains("fn await_optional_mesh_startup"),
        "mesh_attachment.rs must define await_optional_mesh_startup helper"
    );
}

// ── Iteration 97: ordering and input-shape guards ──────────────────────────

#[test]
fn optional_mesh_marks_starting_before_spawning_one_shots() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();

    let support_idx = source
        .find("let support_rx = spawn_optional_support_registration")
        .expect("optional support registration call exists");
    let startup_idx = source[support_idx..]
        .find("spawn_optional_mesh_startup(")
        .map(|i| i + support_idx)
        .expect("optional mesh startup call exists");

    let prefix = &source[..support_idx];
    let starting_idx = prefix
        .rfind("s.transition_starting();")
        .expect("optional branch has a transition_starting before support registration");

    assert!(
        starting_idx < support_idx,
        "optional mesh must transition to starting before spawning support registration"
    );
    assert!(
        starting_idx < startup_idx,
        "optional mesh must transition to starting before spawning mesh startup"
    );
}

#[test]
fn required_mesh_start_uses_explicit_mesh_status_field() {
    let repo = workspace_root();
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();
    let helper = extract_function_body(&source, "start_required_mesh");
    assert!(
        helper.contains("input.mesh_status.clone()"),
        "start_required_mesh must use the explicit mesh_status field from RequiredMeshStartInput"
    );
    assert!(
        !helper.contains("input.state.mesh_status.clone()"),
        "start_required_mesh must not bypass RequiredMeshStartInput by cloning from input.state"
    );
}

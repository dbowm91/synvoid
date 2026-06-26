//! Guard test ensuring `src/main.rs` remains a thin process entrypoint.
//!
//! Command dispatch should live in `src/commands/`, not in `main.rs`.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn strip_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut in_block_comment = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

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

    // Must use command planning
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

    // Forbidden tokens: command implementations that should live in src/commands/
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

    // Restart pre-stop must go through the typed adapter, not call handle_stop directly
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

    // Must have Status(SupervisorStatusDisplay) instead of StatusDisplayed
    assert!(
        source.contains("Status(SupervisorStatusDisplay)"),
        "SupervisorControlOutcome must have Status(SupervisorStatusDisplay) variant"
    );
    // Must have ThreatFeedExported(ThreatFeedExportSummary) instead of ThreatFeedExported { bytes }
    assert!(
        source.contains("ThreatFeedExported(ThreatFeedExportSummary)"),
        "SupervisorControlOutcome must have ThreatFeedExported(ThreatFeedExportSummary) variant"
    );
}

#[test]
fn supervisor_control_error_has_actionable_variants() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/supervisor_control.rs")).unwrap();

    // Must have Connection variant for connection failures
    assert!(
        source.contains("ConnectionUnavailable"),
        "SupervisorControlError must have ConnectionUnavailable variant"
    );
    // Must have Timeout variant for timeout failures
    assert!(
        source.contains("Timeout"),
        "SupervisorControlError must have Timeout variant"
    );
}

#[test]
fn supervisor_control_uses_classified_error_conversion() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/supervisor_control.rs")).unwrap();

    // Must use the classifier, not the old broad converter
    assert!(
        source.contains("classify_control_error"),
        "supervisor_control.rs must use classify_control_error for error conversion"
    );
    // The old broad converter must not exist
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

    // The planner function should not contain Tokio runtime building
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

    // Must document all three command categories
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

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

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

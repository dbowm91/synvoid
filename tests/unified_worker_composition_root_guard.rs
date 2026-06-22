// Guard: run_unified_server_worker() must remain a thin orchestration wrapper.
//
// This test prevents the composition root function from growing back into
// a giant inline implementation after extraction into startup_plan,
// supervision_loop, shutdown_executor, and supervisor_notify modules.

#[test]
fn run_unified_server_worker_remains_a_thin_orchestration_wrapper() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    let start = source
        .find("pub async fn run_unified_server_worker")
        .expect("function exists");
    let body = &source[start..];

    // Count lines from the function signature until the closing brace at column 0.
    // This is a crude parser — good enough for a guard test.
    let lines_until_next_item = body
        .lines()
        .take_while(|line| {
            // Stop at the next pub fn/async fn at column 0, or the #[cfg(test)] block.
            if line.starts_with("#[cfg(test)]") {
                return false;
            }
            // The function body ends with a lone `}` at column 0.
            if line.trim() == "}" && !line.starts_with(' ') && !line.starts_with('\t') {
                return false;
            }
            true
        })
        .count();

    assert!(
        lines_until_next_item <= 150,
        "run_unified_server_worker should stay a thin orchestration wrapper; found {} lines (threshold: 150). \
         If the function grew, consider extracting more logic into startup_plan, supervision_loop, \
         shutdown_executor, or supervisor_notify modules.",
        lines_until_next_item
    );
}

#[test]
fn run_unified_server_worker_delegates_to_startup_plan() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("startup_plan::build_worker_startup"),
        "run_unified_server_worker must delegate startup to startup_plan::build_worker_startup"
    );
}

#[test]
fn run_unified_server_worker_delegates_to_supervision_loop() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("supervision_loop::run_worker_supervision"),
        "run_unified_server_worker must delegate supervision to supervision_loop::run_worker_supervision"
    );
}

#[test]
fn run_unified_server_worker_delegates_to_shutdown_executor() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("shutdown_executor::execute_worker_shutdown"),
        "run_unified_server_worker must delegate shutdown to shutdown_executor::execute_worker_shutdown"
    );
}

#[test]
fn startup_plan_module_exists() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        repo.join("src/worker/unified_server/startup_plan.rs")
            .exists(),
        "startup_plan.rs module must exist"
    );
}

#[test]
fn supervision_loop_module_exists() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        repo.join("src/worker/unified_server/supervision_loop.rs")
            .exists(),
        "supervision_loop.rs module must exist"
    );
}

#[test]
fn shutdown_executor_module_exists() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        repo.join("src/worker/unified_server/shutdown_executor.rs")
            .exists(),
        "shutdown_executor.rs module must exist"
    );
}

#[test]
fn supervisor_notify_module_exists() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        repo.join("src/worker/unified_server/supervisor_notify.rs")
            .exists(),
        "supervisor_notify.rs module must exist"
    );
}

#[test]
fn shutdown_executor_does_not_call_startup_builders() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
fn startup_plan_does_not_perform_shutdown() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/startup_plan.rs")).unwrap();
    // Check for actual calls, not just mentions in comments.
    // Lines starting with // are comments; only check non-comment lines.
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

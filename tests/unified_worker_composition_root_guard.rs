// Guard: run_unified_server_worker() must remain a thin orchestration wrapper.
//
// This test prevents the composition root function from growing back into
// a giant inline implementation after extraction into startup_plan,
// supervision_loop, shutdown_executor, and supervisor_notify modules.
//
// Iteration 94: Tightened threshold to 80 lines, added inline-mapping guard,
// and added shutdown-executor active-mesh-support guard.

/// Extract the body of `run_unified_server_worker()` from the source.
/// Returns the function body as a String.
fn extract_run_unified_server_worker_body(source: &str) -> String {
    let start = source
        .find("pub async fn run_unified_server_worker")
        .expect("function exists");
    let body = &source[start..];

    // Count until the closing brace at column 0 or the next item.
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

#[test]
fn run_unified_server_worker_remains_a_thin_orchestration_wrapper() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    let function = extract_run_unified_server_worker_body(&source);

    // The wrapper should delegate outcome mapping to shutdown_executor,
    // not contain the match block itself.
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
fn run_unified_server_worker_uses_from_supervision_result() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("WorkerShutdownContext::from_supervision_result"),
        "run_unified_server_worker must use WorkerShutdownContext::from_supervision_result"
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
fn shutdown_executor_explicitly_stops_active_mesh_support() {
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

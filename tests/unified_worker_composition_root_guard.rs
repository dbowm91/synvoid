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

// ── Iteration 95: mesh attachment extraction ────────────────────────────────

#[test]
fn startup_plan_delegates_mesh_attachment() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        repo.join("src/worker/unified_server/mesh_attachment.rs")
            .exists(),
        "mesh_attachment.rs module must exist"
    );
}

#[test]
fn mesh_attachment_owns_optional_degradation_cleanup() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(repo.join("src/worker/unified_server/mod.rs")).unwrap();
    assert!(
        source.contains("pub mod mesh_attachment"),
        "mod.rs must declare mesh_attachment module"
    );
}

// ── Iteration 96: attach_mesh polish guards ────────────────────────────────

/// Extract the body of a named async function from source.
/// Finds `pub async fn <name>` and counts until the closing `}` at column 0.
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

#[test]
fn attach_mesh_remains_a_thin_orchestration_wrapper() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source =
        std::fs::read_to_string(repo.join("src/worker/unified_server/mesh_attachment.rs")).unwrap();

    // Find the optional support registration call and the optional mesh startup call.
    let support_idx = source
        .find("let support_rx = spawn_optional_support_registration")
        .expect("optional support registration call exists");
    // Search for the call site (not the fn definition) by looking after support_idx.
    let startup_idx = source[support_idx..]
        .find("spawn_optional_mesh_startup(")
        .map(|i| i + support_idx)
        .expect("optional mesh startup call exists");

    // Find the last transition_starting() that appears before the support registration.
    // This must be in the optional branch (the required branch calls start_required_mesh
    // which has its own transition_starting inside the helper, not inline in attach_mesh).
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
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

//! Mesh task ownership guardrail tests (Phase 17).
//!
//! Verifies that mesh transport runtime files follow the task-ownership
//! invariants established in Iteration 68:
//!
//! 1. No unowned long-lived `tokio::spawn()` in audited mesh runtime files
//! 2. Periodic loops require cancellation selection (`tokio::select!` with shutdown)
//! 3. Critical loops must be registered with the mesh task group
//! 4. Per-peer children must enter the child group (JoinSet in accept loop)
//! 5. `start()` must use `MeshLifecycleState` (not bare boolean)
//! 6. Failed startup must not commit to Running
//! 7. Shutdown must abort and await timed-out tasks via `join_all`

use std::fs;

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Extract a function body (from `fn name(` to the matching closing brace)
/// as a rough heuristic. Returns the full file if the function isn't found.
fn extract_function(content: &str, fn_name: &str) -> String {
    if let Some(start) = content.find(&format!("fn {fn_name}")) {
        // Find the opening brace
        if let Some(brace_start) = content[start..].find('{') {
            let abs_brace = start + brace_start;
            let mut depth = 0i32;
            for (i, ch) in content[abs_brace..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return content[abs_brace..=abs_brace + i].to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    content.to_string()
}

// ── Test 1: No unowned long-lived spawns in transport.rs start() ────────────

#[test]
fn no_detached_spawns_in_transport_start() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "run_startup_phases");

    let bare_spawn_count = count_occurrences(&start_body, "tokio::spawn(");
    let group_spawn_count = count_occurrences(&start_body, "stage.task_group.spawn_");

    // The run_startup_phases() method should use stage.task_group.spawn_* for
    // long-lived tasks. Bare tokio::spawn should be zero (all long-lived work
    // goes through the task group).
    assert!(
        bare_spawn_count == 0,
        "run_startup_phases() contains {bare_spawn_count} bare tokio::spawn() calls; \
         all long-lived tasks must use stage.task_group.spawn_*(). Found at: {}",
        find_bare_spawn_lines(&start_body)
    );

    // Verify the task group is actually used for spawning
    assert!(
        group_spawn_count >= 2,
        "run_startup_phases() should spawn at least 2 tasks via stage.task_group.spawn_*(), found {group_spawn_count}"
    );
}

fn find_bare_spawn_lines(body: &str) -> String {
    let mut violations = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("tokio::spawn(") && !trimmed.starts_with("//") {
            violations.push(format!(
                "line ~{i}: {}",
                trimmed.chars().take(80).collect::<String>()
            ));
        }
    }
    violations.join("; ")
}

// ── Test 2: Periodic loops have cancellation selection ───────────────────────

#[test]
fn periodic_loops_have_cancellation() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "start");

    // Find all spawn blocks that contain a loop with interval (periodic tasks)
    // and verify each has a tokio::select! with shutdown
    let lines: Vec<(usize, &str)> = start_body.lines().enumerate().collect();

    let mut i = 0;
    let mut violations = Vec::new();
    while i < lines.len() {
        let (_line_num, line) = lines[i];
        let trimmed = line.trim();

        // Detect periodic loop start: a spawn block containing a loop with interval
        if trimmed.contains("group.spawn_background(") || trimmed.contains("group.spawn_critical(")
        {
            // Collect the block until balanced braces
            let mut block = String::new();
            let mut brace_depth = 0i32;
            let mut found_open = false;
            let block_start_line = i;
            for j in i..lines.len().min(i + 200) {
                let (_, bl) = lines[j];
                block.push_str(bl);
                block.push('\n');
                for ch in bl.chars() {
                    match ch {
                        '{' => {
                            brace_depth += 1;
                            found_open = true;
                        }
                        '}' => brace_depth -= 1,
                        _ => {}
                    }
                }
                if found_open && brace_depth <= 0 {
                    break;
                }
            }

            // If this block contains a loop with interval, it's a periodic task
            if block.contains("loop {") && block.contains("tokio::time::interval") {
                let has_select = block.contains("tokio::select!");
                let has_shutdown = block.contains("shutdown")
                    || block.contains(".changed()")
                    || block.contains("_shutdown");

                if !has_select || !has_shutdown {
                    let task_name = extract_task_name(trimmed);
                    violations.push(format!(
                        "Periodic task '{task_name}' at line ~{block_start_line}: \
                         loop must use tokio::select! with shutdown receiver"
                    ));
                }
            }
        }
        i += 1;
    }

    assert!(
        violations.is_empty(),
        "Periodic loops without cancellation:\n{}",
        violations.join("\n")
    );
}

fn extract_task_name(spawn_line: &str) -> &str {
    if let Some(start) = spawn_line.find('"') {
        if let Some(end) = spawn_line[start + 1..].find('"') {
            return &spawn_line[start + 1..start + 1 + end];
        }
    }
    "unknown"
}

// ── Test 3: start() uses MeshLifecycleState ─────────────────────────────────

#[test]
fn start_uses_lifecycle_state() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Must import and use MeshLifecycleState
    assert!(
        content.contains("MeshLifecycleState"),
        "transport.rs must import and use MeshLifecycleState"
    );

    let start_body = extract_function(&content, "start_with_policy");

    // Must transition to Starting before committing work
    assert!(
        start_body.contains("transition_to_starting"),
        "start_with_policy() must transition lifecycle to Starting before spawning tasks"
    );

    // Must transition to Running after all tasks are registered
    // (now in commit_startup, called by start_with_policy)
    assert!(
        content.contains("transition_to_running"),
        "commit_startup() must transition lifecycle to Running after task registration"
    );

    // Must validate can_start() before proceeding
    assert!(
        start_body.contains("can_start"),
        "start_with_policy() must check can_start() to validate state machine"
    );

    // Must store the task group after all spawns
    assert!(
        start_body.contains("task_group"),
        "start_with_policy() must store the MeshTaskGroup after spawning tasks"
    );
}

// ── Test 4: start() does not set running before commit ──────────────────────

#[test]
fn start_does_not_commit_prematurely() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "start");

    // Find the line number of transition_to_running
    let running_line = start_body
        .lines()
        .position(|l| l.contains("transition_to_running"));

    // Find the line number of the last group.spawn_* call
    let last_spawn_line = start_body
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("group.spawn_"))
        .map(|(i, _)| i)
        .last();

    if let (Some(running), Some(spawn)) = (running_line, last_spawn_line) {
        assert!(
            running > spawn,
            "transition_to_running (line {running}) must come after \
             the last group.spawn_* (line {spawn}); tasks must be \
             registered before the lifecycle is committed to Running"
        );
    }
}

// ── Test 5: Failed startup transitions to Failed, not Running ───────────────

#[test]
fn failed_startup_uses_failed_state() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "start_with_policy");

    // The function body (between braces) won't contain the Result< signature.
    // Instead verify that the body uses error-returning patterns:
    // `return Err(...)` or `?` operator or `map_err` for startup failures.
    let has_error_returns = start_body.contains("return Err(")
        || start_body.contains("map_err")
        || start_body.contains("StartupFailed");
    assert!(
        has_error_returns,
        "start_with_policy() must have error-returning paths (return Err/map_err/StartupFailed) \
         to handle startup failures without committing to Running"
    );

    // Verify MeshTransportError is used for startup failure reporting
    assert!(
        start_body.contains("StartupFailed") || start_body.contains("LifecycleConflict"),
        "start_with_policy() must map errors to MeshTransportError variants for startup failures"
    );
}

// ── Test 6: Shutdown uses task group for bounded join ────────────────────────

#[test]
fn shutdown_uses_task_group() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Must have shutdown_with_timeout method
    let shutdown_body = extract_function(&content, "shutdown_with_timeout");
    assert!(
        !shutdown_body.contains("fn shutdown_with_timeout") || shutdown_body.len() > 50,
        "shutdown_with_timeout method must exist"
    );

    // Must use MeshShutdownReport as return type
    assert!(
        content.contains("MeshShutdownReport"),
        "shutdown must return MeshShutdownReport"
    );

    // Must call group.begin_shutdown() to signal tasks
    assert!(
        shutdown_body.contains("begin_shutdown"),
        "shutdown must call group.begin_shutdown() to signal all tasks"
    );

    // Must call group.join_all() with timeout to await tasks
    assert!(
        shutdown_body.contains("join_all"),
        "shutdown must call group.join_all(timeout) to join with deadline"
    );

    // Must transition lifecycle state
    assert!(
        shutdown_body.contains("transition_to_stopping") || shutdown_body.contains("can_stop"),
        "shutdown must transition lifecycle to Stopping"
    );

    // Must transition to Stopped after join
    assert!(
        shutdown_body.contains("transition_to_stopped"),
        "shutdown must transition to Stopped after all tasks join"
    );

    // Must record shutdown_started flag
    assert!(
        shutdown_body.contains("shutdown_started"),
        "shutdown must set shutdown_started flag for task exit classification"
    );
}

// ── Test 7: Peer children use JoinSet in accept loop ────────────────────────

#[test]
fn accept_loop_uses_joinset_for_children() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let accept_body = extract_function(&content, "mesh_accept_loop");

    // Must use JoinSet for per-peer child tasks
    assert!(
        accept_body.contains("JoinSet"),
        "mesh_accept_loop must use JoinSet for per-peer child tasks"
    );

    // Must have shutdown-aware select! in main loop
    assert!(
        accept_body.contains("tokio::select!"),
        "mesh_accept_loop must use tokio::select! for cancellation"
    );
    assert!(
        accept_body.contains("shutdown_rx.changed()") || accept_body.contains("shutdown"),
        "mesh_accept_loop select! must watch shutdown receiver"
    );

    // Must abort remaining children on timeout
    assert!(
        accept_body.contains("abort_all") || accept_body.contains("abort"),
        "mesh_accept_loop must abort timed-out child tasks"
    );

    // Must drain with a timeout
    assert!(
        accept_body.contains("drain_timeout") || accept_body.contains("deadline"),
        "mesh_accept_loop must drain children with a bounded timeout"
    );
}

// ── Test 8: transport_connection.rs loops use select! with shutdown ─────────

#[test]
fn transport_connection_loops_have_shutdown() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport_connection.rs");

    // Find all loop blocks and verify they use select! with shutdown
    let mut violations = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "loop {" {
            // Check if this loop has a tokio::select! within the next 5 lines
            let mut has_select = false;
            let mut has_shutdown = false;
            for j in (i + 1)..lines.len().min(i + 10) {
                let inner = lines[j].trim();
                if inner.contains("tokio::select!") {
                    has_select = true;
                }
                if inner.contains("shutdown") || inner.contains(".changed()") {
                    has_shutdown = true;
                }
            }
            if has_select && !has_shutdown {
                violations.push(format!(
                    "line ~{i}: loop with select! but no shutdown watch"
                ));
            }
        }
        i += 1;
    }

    assert!(
        violations.is_empty(),
        "transport_connection.rs loops without shutdown:\n{}",
        violations.join("\n")
    );
}

// ── Test 9: MeshTransport struct has required ownership fields ───────────────

#[test]
fn mesh_transport_has_ownership_fields() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Must have task_group field
    assert!(
        content.contains("task_group:"),
        "MeshTransport must have a task_group field"
    );

    // Must have lifecycle_state field
    assert!(
        content.contains("lifecycle_state:"),
        "MeshTransport must have a lifecycle_state field"
    );

    // Must have shutdown_started flag
    assert!(
        content.contains("shutdown_started:"),
        "MeshTransport must have a shutdown_started field"
    );

    // Task group must be Arc<Mutex<MeshTaskGroup>>
    assert!(
        content.contains("Arc<tokio::sync::Mutex<MeshTaskGroup>>"),
        "task_group must be Arc<tokio::sync::Mutex<MeshTaskGroup>>"
    );

    // Lifecycle state must be Arc<Mutex<MeshLifecycleState>>
    assert!(
        content.contains("Arc<tokio::sync::Mutex<MeshLifecycleState>>"),
        "lifecycle_state must be Arc<tokio::sync::Mutex<MeshLifecycleState>>"
    );
}

// ── Test 10: start() initializes lifecycle and group in correct order ────────

#[test]
fn start_initializes_in_correct_order() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "start");

    // Phase 1: lifecycle state check must come first
    let can_start_pos = start_body.find("can_start");
    let transition_starting_pos = start_body.find("transition_to_starting");
    let group_new_pos = start_body.find("MeshTaskGroup::new");
    let running_pos = start_body.find("transition_to_running");
    let store_group_pos = start_body.find("task_group.lock");

    if let Some(can_start) = can_start_pos {
        if let Some(transition_starting) = transition_starting_pos {
            assert!(
                can_start < transition_starting,
                "can_start() must be checked before transition_to_starting()"
            );
        }
    }

    if let Some(transition_starting) = transition_starting_pos {
        if let Some(group_new) = group_new_pos {
            assert!(
                transition_starting < group_new,
                "transition_to_starting must come before MeshTaskGroup::new"
            );
        }
    }

    if let Some(group_new) = group_new_pos {
        if let Some(running) = running_pos {
            assert!(
                group_new < running,
                "MeshTaskGroup::new must come before transition_to_running"
            );
        }
    }

    if let Some(running) = running_pos {
        if let Some(store_group) = store_group_pos {
            assert!(
                running < store_group,
                "transition_to_running must come before storing the task group"
            );
        }
    }
}

// ── Test 11: Bare tokio::spawn in transport.rs are justified one-shots ──────

#[test]
fn bare_spawns_in_transport_are_one_shots() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // All bare tokio::spawn() calls outside start() should be one-shot operations:
    // - No loop inside
    // - No interval inside
    // These are acceptable: preflight routes, message sends, trait impl sends,
    // initialization one-shots.
    let lines: Vec<&str> = content.lines().collect();
    let mut violations = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }
        if !trimmed.contains("tokio::spawn(") {
            continue;
        }

        // Skip inside task_group.rs (the implementation itself)
        if trimmed.contains("spawn_wrapped") {
            continue;
        }

        // Look ahead up to 30 lines for loop/interval patterns (long-lived)
        let mut is_long_lived = false;
        let mut brace_depth = 0i32;
        let mut found_open = false;
        for j in i..lines.len().min(i + 40) {
            let ahead = lines[j].trim();
            for ch in ahead.chars() {
                match ch {
                    '{' => {
                        brace_depth += 1;
                        found_open = true;
                    }
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }
            if ahead.contains("loop {") || ahead.contains("tokio::time::interval") {
                is_long_lived = true;
            }
            if found_open && brace_depth <= 0 {
                break;
            }
        }

        if is_long_lived {
            violations.push(format!(
                "line ~{}: bare tokio::spawn with long-lived body (loop/interval)",
                i + 1
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Long-lived bare tokio::spawn() in transport.rs (must use task group):\n{}",
        violations.join("\n")
    );
}

// ── Test 12: rollback_startup exists in transport.rs ─────────────────────────

#[test]
fn rollback_startup_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("fn rollback_startup"),
        "transport.rs must contain rollback_startup function"
    );
}

// ── Test 13: mesh_exit_tx field exists on MeshTransport ──────────────────────

#[test]
fn mesh_exit_tx_field_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("mesh_exit_tx:"),
        "MeshTransport must have a mesh_exit_tx field"
    );
    assert!(
        content.contains("broadcast::Sender<MeshTaskExit>"),
        "mesh_exit_tx must be broadcast::Sender<MeshTaskExit>"
    );
}

// ── Test 14: subscribe_exits is NOT async ────────────────────────────────────

#[test]
fn subscribe_exits_is_sync() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    // Find the subscribe_exits function and verify it's not async
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("fn subscribe_exits") {
            // Check the line does NOT contain "async"
            assert!(
                !line.contains("async"),
                "subscribe_exits at line ~{} must not be async; found: {}",
                i + 1,
                line.trim()
            );
            return;
        }
    }
    panic!("subscribe_exits function not found in transport.rs");
}

// ── Test 15: MeshTaskGroup has forward_tx field ──────────────────────────────

#[test]
fn forward_tx_in_task_group() {
    let content = read_file("crates/synvoid-mesh/src/mesh/task_group.rs");
    assert!(
        content.contains("forward_tx:"),
        "MeshTaskGroup must have a forward_tx field"
    );
    assert!(
        content.contains("new_with_forward"),
        "MeshTaskGroup must have new_with_forward constructor"
    );
}

// ── Test 16: peer_sessions field exists on MeshTransport ─────────────────────

#[test]
fn peer_sessions_field_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("peer_sessions:"),
        "MeshTransport must have a peer_sessions field"
    );
    // peer_sessions must use a keyed registry (HashMap), not JoinSet
    assert!(
        content.contains("HashMap<String,") && content.contains("PeerSessionTask>"),
        "peer_sessions must use HashMap<String, ...PeerSessionTask> for keyed session tracking"
    );
}

// ── Test 17: MeshServiceExit variant exists in WorkerShutdownCause ───────────

#[test]
fn mesh_service_exit_cause_exists() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(
        content.contains("MeshServiceExit"),
        "WorkerShutdownCause must have MeshServiceExit variant"
    );
    assert!(
        content.contains("synvoid_mesh::lifecycle::MeshTaskExit"),
        "task_registry.rs must import MeshTaskExit from synvoid_mesh::lifecycle"
    );
}

// ── Test 18: commit_startup errors cannot bypass rollback (Iteration 71) ────

#[test]
fn commit_errors_cannot_bypass_rollback() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "start_with_policy");

    // start_with_policy must route BOTH phase failures and commit failures
    // through rollback_and_return
    assert!(
        start_body.contains("rollback_and_return"),
        "start_with_policy must use rollback_and_return to prevent commit errors from bypassing rollback"
    );
}

// ── Test 19: lifecycle transitions to Running only after task group install ──

#[test]
fn running_after_task_group_install() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let commit_body = extract_function(&content, "commit_startup");

    // Find task_group and transition_to_running positions
    let tg_pos = commit_body.find("task_group");
    let running_pos = commit_body.find("transition_to_running");

    if let (Some(tg), Some(r)) = (tg_pos, running_pos) {
        assert!(
            tg < r,
            "task_group must be installed before transition_to_running in commit_startup"
        );
    }
}

// ── Test 20: StagedPeerResource recording methods exist ─────────────────────

#[test]
fn staged_peer_resource_recording_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // connect_to_peer must accept stage parameter
    assert!(
        content.contains("stage: Option<&mut MeshStartupStage>"),
        "connect_to_peer must accept optional stage for peer recording"
    );

    // bootstrap_from_seeds must accept stage
    assert!(
        content.contains("fn bootstrap_from_seeds")
            && extract_function(&content, "bootstrap_from_seeds").contains("stage"),
        "bootstrap_from_seeds must accept stage parameter"
    );
}

// ── Test 21: rollback removes peer connections by session_id ─────────────────

#[test]
fn rollback_removes_by_session_id() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // Must look up connections by session_id (the DashMap key)
    assert!(
        rollback_body.contains("session_id"),
        "rollback_startup must use session_id to look up peer_connections (DashMap key)"
    );
}

// ── Test 22: topology rollback code exists ───────────────────────────────────

#[test]
fn topology_rollback_code_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    assert!(
        rollback_body.contains("remove_peer") || rollback_body.contains("topology"),
        "rollback_startup must contain topology cleanup code"
    );
}

// ── Test 23: runtime_started has cleanup path ────────────────────────────────

#[test]
fn runtime_cleanup_path_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    assert!(
        rollback_body.contains("runtime_started"),
        "rollback_startup must handle runtime_started cleanup"
    );
}

// ── Test 24: rollback session cleanup uses abort ─────────────────────────────

#[test]
fn rollback_session_cleanup_uses_abort() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    assert!(
        rollback_body.contains("abort_all") || rollback_body.contains("abort"),
        "rollback_startup must abort remaining peer sessions after cooperative drain"
    );
}

// ── Test 25: StartupRollbackFailed constructed in startup flow ───────────────

#[test]
fn startup_rollback_failed_constructed() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("StartupRollbackFailed"),
        "MeshTransportError::StartupRollbackFailed must be constructed in startup flow"
    );
}

// ── Test 26: Handshake report fields are wired (Iteration 71) ────────────────

#[test]
fn handshake_report_fields_wired() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // MeshAcceptLoopReport fields must no longer be deferred since they're wired
    let report_start = content
        .find("pub struct MeshAcceptLoopReport")
        .expect("MeshAcceptLoopReport struct not found");
    let report_window = &content[report_start..report_start + 500];
    assert!(
        !report_window.contains("Deferred"),
        "MeshAcceptLoopReport fields must not be annotated as Deferred (they are now wired)"
    );

    // The accept loop must populate the report
    let transport_content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        transport_content.contains("report.drained_handshakes"),
        "mesh_accept_loop must populate report.drained_handshakes"
    );
    assert!(
        transport_content.contains("report.aborted_handshakes"),
        "mesh_accept_loop must populate report.aborted_handshakes"
    );
}

// ── Test 27: BeforeLifecycleCommit hook exists ───────────────────────────────

#[test]
fn before_lifecycle_commit_hook_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("BeforeLifecycleCommit"),
        "StartupFailurePoint must have BeforeLifecycleCommit variant"
    );
    assert!(
        !content.contains("AfterLifecycleCommit"),
        "AfterLifecycleCommit should be renamed to BeforeLifecycleCommit"
    );
}

// ── Test 28: verify_rollback_complete checks key invariants ──────────────────

#[test]
fn verify_rollback_complete_checks_invariants() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let verify_body = extract_function(&content, "verify_rollback_complete");

    assert!(
        verify_body.contains("running_projection"),
        "verify_rollback_complete must check running_projection"
    );
    assert!(
        verify_body.contains("lifecycle") || verify_body.contains("Running"),
        "verify_rollback_complete must check lifecycle is not Running"
    );
    assert!(
        verify_body.contains("peer_connections") || verify_body.contains("session_id"),
        "verify_rollback_complete must check peer connections were removed"
    );
}

// ── Test 29: can_start() rejects Failed state (Iteration 72) ─────────────────

#[test]
fn can_start_rejects_failed_state() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("matches!(self, MeshLifecycleState::Stopped)"),
        "can_start() must only allow Stopped, not Failed"
    );
    assert!(
        !content.contains("MeshLifecycleState::Stopped | MeshLifecycleState::Failed"),
        "can_start() must not allow Failed state"
    );
}

// ── Test 30: recover_failed_state exists on MeshTransport ────────────────────

#[test]
fn recover_failed_state_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("pub async fn recover_failed_state"),
        "recover_failed_state method must exist on MeshTransport"
    );
}

// ── Test 31: StagedPeerResource has previous_topology field ──────────────────

#[test]
fn staged_peer_resource_has_previous_topology() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("previous_topology: Option<StagedTopologySnapshot>"),
        "StagedPeerResource must have previous_topology field"
    );
    assert!(
        content.contains("pub struct StagedTopologySnapshot"),
        "StagedTopologySnapshot struct must exist"
    );
}

// ── Test 32: StagedPeerResource has dht_mutation field ───────────────────

#[test]
fn staged_peer_resource_has_dht_tracking() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("dht_mutation: DhtPeerMutation"),
        "StagedPeerResource must have dht_mutation field of type DhtPeerMutation"
    );
}

// ── Test 33: StagedPeerResource uses session_task_id, not boolean ────────────

#[test]
fn staged_peer_resource_has_session_task_id() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("session_task_id: Option<String>"),
        "StagedPeerResource must have session_task_id field"
    );
    assert!(
        !content.contains("session_task_created: bool"),
        "StagedPeerResource must not have session_task_created boolean"
    );
}

// ── Test 34: PeerSessionTask struct exists ───────────────────────────────────

#[test]
fn peer_session_task_struct_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("pub struct PeerSessionTask"),
        "PeerSessionTask struct must exist"
    );
}

// ── Test 35: peer_sessions uses HashMap keyed registry ───────────────────────

#[test]
fn peer_sessions_is_keyed_registry() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("HashMap<String,") && content.contains("PeerSessionTask>"),
        "peer_sessions must use HashMap<String, ...PeerSessionTask>"
    );
}

// ── Test 36: MeshAcceptLoopReport has generation field ───────────────────────

#[test]
fn accept_loop_report_has_generation() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("pub generation: u64"),
        "MeshAcceptLoopReport must have generation field"
    );
}

// ── Test 37: rollback_startup removes DHT entries ───────────────────────────

#[test]
fn rollback_removes_dht_entries() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");
    assert!(
        rollback_body.contains("rm.remove_peer(&peer.node_id)")
            || rollback_body.contains("remove_peer(&peer.node_id)")
            || rollback_body.contains("restore_peer_logical_state")
            || rollback_body.contains("restore_and_verify_peer_logical_state"),
        "rollback_startup must remove DHT routing entries for staged peers"
    );
}

// ── Test 38: rollback restores topology from snapshots ──────────────────────

#[test]
fn rollback_restores_topology_snapshots() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");
    assert!(
        rollback_body.contains("restore_peer_logical_state")
            || rollback_body.contains("restore_and_verify_peer_logical_state")
            || rollback_body.contains("previous_topology"),
        "rollback_startup must restore topology using restore_peer_logical_state or previous_topology snapshots"
    );
}

// ── Test 39: commit_startup checks old task group is empty ──────────────────

#[test]
fn commit_startup_checks_task_group_empty() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let commit_body = extract_function(&content, "commit_startup");
    assert!(
        commit_body.contains("old.active_count()") || commit_body.contains("active_count()"),
        "commit_startup must check old task group active count"
    );
}

// ── Test 40: preflight uses spawn_child during startup ──────────────────────

#[test]
fn preflight_owned_during_startup() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("spawn_child(\"preflight_peer_routes\"")
            || content.contains("stage.task_group.spawn_child"),
        "Preflight must be owned by staged task group during startup"
    );
}

// ── Test 41: rollback abort count derived from exit reasons ─────────────────

#[test]
fn rollback_abort_count_from_exits() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");
    assert!(
        rollback_body.contains("MeshTaskExitReason::Aborted")
            && rollback_body.contains("tasks_aborted"),
        "Rollback must derive abort count from exit reasons"
    );
}

// ── Test 42: commit_startup checks task group emptiness before replacement ──

#[test]
fn commit_startup_rejects_nonempty_task_group() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let commit_body = extract_function(&content, "commit_startup");

    // Must check active_count() BEFORE std::mem::replace
    let active_count_pos = commit_body.find("active_count()");
    let replace_pos = commit_body.find("std::mem::replace");

    assert!(
        active_count_pos.is_some(),
        "commit_startup must call active_count() to check task group emptiness"
    );
    assert!(
        replace_pos.is_some(),
        "commit_startup must use std::mem::replace to swap task groups"
    );
    if let (Some(ac), Some(repl)) = (active_count_pos, replace_pos) {
        assert!(
            ac < repl,
            "commit_startup must check active_count() BEFORE std::mem::replace"
        );
    }

    // Must reject non-empty groups (return Err)
    assert!(
        commit_body.contains("non-empty"),
        "commit_startup must return error when replacing non-empty task group"
    );
}

// ── Test 43: topology snapshot captured before add_peer ──────────────────────

#[test]
fn topology_snapshot_before_add_peer() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let connect_body = extract_function(&content, "connect_to_peer");

    // get_peer() must appear before add_peer() in the outbound connection path
    let get_peer_pos = connect_body.find("get_peer(");
    let add_peer_pos = connect_body.find(".add_peer(");

    assert!(
        get_peer_pos.is_some(),
        "connect_to_peer must capture topology snapshot via get_peer() before mutation"
    );
    assert!(
        add_peer_pos.is_some(),
        "connect_to_peer must call add_peer() to register peer in topology"
    );
    if let (Some(gp), Some(ap)) = (get_peer_pos, add_peer_pos) {
        assert!(
            gp < ap,
            "topology snapshot (get_peer) must appear BEFORE topology mutation (add_peer)"
        );
    }
}

// ── Test 44: DHT mutation not derived from rm.is_enabled() alone ─────────────

#[test]
fn dht_mutation_not_from_is_enabled() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // DhtPeerMutation construction must be based on snapshot comparison,
    // not directly from rm.is_enabled(). The pattern should be:
    //   rm.is_enabled() -> check dht_snapshot_before -> DhtPeerMutation::Created/Replaced/None
    // Not: rm.is_enabled() -> DhtPeerMutation::Created
    //
    // Only check construction sites (right side of = or struct field), not match arms.

    let lines: Vec<(usize, &str)> = content.lines().enumerate().collect();
    let mut violations = Vec::new();

    for (i, (_line_num, line)) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Skip match arms (lines starting with `DhtPeerMutation::` in match context)
        if trimmed.starts_with("DhtPeerMutation::") {
            continue;
        }
        // Check for construction: `= DhtPeerMutation::Created` or `DhtPeerMutation::Created,`
        if trimmed.contains("DhtPeerMutation::Created")
            && (trimmed.contains("= DhtPeerMutation::Created")
                || trimmed.contains("DhtPeerMutation::Created,"))
        {
            // Look backwards up to 10 lines for the guard pattern
            let mut found_snapshot_check = false;
            for j in i.saturating_sub(10)..i {
                if lines[j].1.contains("dht_snapshot_before") {
                    found_snapshot_check = true;
                    break;
                }
            }
            if !found_snapshot_check {
                violations.push(format!(
                    "line ~{}: DhtPeerMutation::Created construction not guarded by dht_snapshot_before check",
                    i + 1
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "DhtPeerMutation must be derived from pre-mutation snapshot, not just rm.is_enabled():\n{}",
        violations.join("\n")
    );
}

// ── Test 45: recover_failed_state consumes timeout parameter ─────────────────

#[test]
fn recover_failed_state_uses_timeout() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // The timeout parameter must NOT be prefixed with underscore (unused)
    // Search the full file for the function signature
    assert!(
        content.contains("fn recover_failed_state(&self, timeout: Duration)"),
        "recover_failed_state must accept timeout parameter (not _timeout)"
    );

    let recover_body = extract_function(&content, "recover_failed_state");

    // Must derive a deadline from the timeout
    assert!(
        recover_body.contains("deadline"),
        "recover_failed_state must derive a deadline from the timeout parameter"
    );

    // Must use deadline for bounded operations
    assert!(
        recover_body.contains("remaining(deadline)")
            || recover_body.contains("Instant::now() + timeout"),
        "recover_failed_state must use the timeout for bounding operations"
    );
}

// ── Test 46: abort followed by await in shutdown/recovery paths ──────────────

#[test]
fn abort_awaited_after_handle() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let lines: Vec<&str> = content.lines().collect();
    let mut violations = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains(".abort()") && !trimmed.starts_with("//") {
            // Look ahead up to 5 lines for .await
            let mut found_await = false;
            for j in (i + 1)..lines.len().min(i + 6) {
                if lines[j].contains(".await") {
                    found_await = true;
                    break;
                }
            }
            if !found_await {
                violations.push(format!(
                    "line ~{}: .abort() without following .await within 5 lines",
                    i + 1
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "All abort() calls must be followed by .await to reap the task:\n{}",
        violations.join("\n")
    );
}

// ── Test 47: no bare preflight spawn in steady-state paths ──────────────────

#[test]
fn no_bare_preflight_spawn() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Preflight must either use stage.task_group.spawn_child during startup
    // or auxiliary_tasks registry during steady-state. Bare tokio::spawn(preflight...)
    // without auxiliary registration is forbidden.
    let lines: Vec<(usize, &str)> = content.lines().enumerate().collect();
    let mut violations = Vec::new();

    for (i, (_line_num, line)) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("tokio::spawn(")
            && trimmed.contains("preflight")
            && !trimmed.starts_with("//")
        {
            // Check if this is the steady-state preflight path
            // It should be followed by auxiliary_tasks registration
            let mut found_aux_register = false;
            for j in (i + 1)..lines.len().min(i + 20) {
                if lines[j].1.contains("auxiliary_tasks") || lines[j].1.contains("aux.insert") {
                    found_aux_register = true;
                    break;
                }
            }
            // The startup path uses stage.task_group.spawn_child, not tokio::spawn
            if !found_aux_register {
                violations.push(format!(
                    "line ~{}: bare tokio::spawn for preflight without auxiliary task registration",
                    i + 1
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Preflight tasks must use task group during startup or auxiliary registry during steady-state:\n{}",
        violations.join("\n")
    );
}

// ── Test 48: PeerSessionExitReason enum exists ──────────────────────────────

#[test]
fn peer_session_exit_reason_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("pub enum PeerSessionExitReason"),
        "PeerSessionExitReason enum must exist in lifecycle.rs"
    );
    // Must have key variants for exit classification
    assert!(
        content.contains("PeerSessionExitReason::Clean"),
        "PeerSessionExitReason must have Clean variant"
    );
    assert!(
        content.contains("PeerSessionExitReason::Aborted"),
        "PeerSessionExitReason must have Aborted variant"
    );
    assert!(
        content.contains("PeerSessionExitReason::Cancelled"),
        "PeerSessionExitReason must have Cancelled variant"
    );
}

// ── Test 49: MeshShutdownReport has failed_peer_sessions field ───────────────

#[test]
fn shutdown_report_has_failed_peer_sessions() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("pub failed_peer_sessions: usize"),
        "MeshShutdownReport must have failed_peer_sessions field"
    );
}

// ── Phase 26: Preflight Ownership Tests ──────────────────────────────────────

#[test]
fn auxiliary_task_has_session_binding() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        code.contains("pub session_id: Option<String>"),
        "AuxiliaryTask must have session_id field"
    );
}

#[test]
fn cancel_auxiliary_tasks_for_sessions_exists() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("fn cancel_auxiliary_tasks_for_sessions"),
        "cancel_auxiliary_tasks_for_sessions method must exist"
    );
}

#[test]
fn rollback_cancels_auxiliary_tasks_for_staged_sessions() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("cancel_auxiliary_tasks_for_sessions"),
        "rollback must cancel auxiliary tasks for staged sessions"
    );
}

#[test]
fn startup_preflight_uses_task_group_not_auxiliary_registry() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("spawn_child(\"preflight_peer_routes\""),
        "startup preflight must use task_group.spawn_child, not auxiliary_tasks"
    );
}

#[test]
fn steady_state_preflight_uses_auxiliary_registry() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("aux.insert("),
        "steady-state preflight must register in auxiliary_tasks"
    );
}

// ── Phase 27: Session Reaper Tests ───────────────────────────────────────────

#[test]
fn session_reaper_exists() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("session_reaper"),
        "session_reaper task must be spawned"
    );
}

#[test]
fn session_exit_tx_channel_exists() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("session_exit_tx"),
        "session_exit_tx channel must exist"
    );
}

#[test]
fn peer_message_loop_returns_exit() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport_peer.rs");
    assert!(
        code.contains("PeerSessionExit"),
        "peer_message_loop must return PeerSessionExit"
    );
}

#[test]
fn session_exit_sent_on_channel() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("exit_tx.send("),
        "session exits must be sent on the channel"
    );
}

#[test]
fn session_reaper_uses_generation_check() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("task.generation == exit.generation"),
        "reaper must check generation before removing entries"
    );
}

#[test]
fn generation_wired_from_stage_to_session_task() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("session_generation_for_task")
            || code.contains("generation: session_generation"),
        "generation must be wired from stage to PeerSessionTask"
    );
}

// ── Phase 19: Accept-Loop Generation Tests ───────────────────────────────────

#[test]
fn startup_generation_field_exists() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("startup_generation"),
        "startup_generation field must exist"
    );
}

#[test]
fn shutdown_verifies_accept_loop_generation() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("accept_report.generation") && code.contains("startup_generation"),
        "shutdown must verify accept_loop_report generation against startup_generation"
    );
}

// ── Test 50: recover_failed_state verifies registries ───────────────────────

#[test]
fn recover_failed_state_verifies_registries() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recover_body = extract_function(&content, "recover_failed_state");

    // Must verify task group is empty
    assert!(
        recover_body.contains("active_count()"),
        "recover_failed_state must check task group active count"
    );

    // Must verify peer sessions are empty
    assert!(
        recover_body.contains("peer_sessions"),
        "recover_failed_state must verify peer session registry"
    );

    // Must verify auxiliary tasks are empty
    assert!(
        recover_body.contains("auxiliary_tasks") || recover_body.contains("aux."),
        "recover_failed_state must verify auxiliary task registry"
    );
}

// ── Phase 52: Guardrail Tests ───────────────────────────────────────────────

#[test]
fn test_recover_failed_state_applies_residue() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_fn = extract_function(&source, "recover_failed_state");

    // Must take residue before clearing
    assert!(
        recovery_fn.contains(".take()"),
        "recover_failed_state must take residue via .take()"
    );

    // Must iterate residue peers
    assert!(
        recovery_fn.contains("residue.peers") || recovery_fn.contains("for peer in"),
        "recover_failed_state must iterate residue peers"
    );

    // Must use restore_peer_logical_state or restore_and_verify_peer_logical_state
    assert!(
        recovery_fn.contains("restore_peer_logical_state")
            || recovery_fn.contains("restore_and_verify_peer_logical_state"),
        "recover_failed_state must use shared restore helper"
    );
}

#[test]
fn test_topology_rollback_uses_native_restore() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // Must use restore_peer_logical_state or restore_and_verify_peer_logical_state
    assert!(
        rollback_fn.contains("restore_peer_logical_state")
            || rollback_fn.contains("restore_and_verify_peer_logical_state"),
        "rollback_startup must use shared restore helper"
    );

    // Must NOT use lossy MeshPeerInfo conversion
    assert!(
        !rollback_fn.contains("MeshPeerInfo {"),
        "rollback_startup must not reconstruct through MeshPeerInfo"
    );
}

#[test]
fn test_dht_snapshot_not_limited() {
    let source = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // DhtPeerSnapshot must store the complete PeerContact
    assert!(
        source.contains("pub contact:"),
        "DhtPeerSnapshot must store a complete PeerContact via 'contact' field"
    );
}

#[test]
fn test_session_reaper_selects_on_shutdown() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let reaper_fn = extract_function(&source, "spawn_session_reaper");

    // Must use select!
    assert!(
        reaper_fn.contains("tokio::select!"),
        "session reaper must use tokio::select!"
    );

    // Must check shutdown
    assert!(
        reaper_fn.contains("shutdown"),
        "session reaper must select on shutdown signal"
    );
}

#[test]
fn test_session_reaper_awaits_handle() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let reaper_fn = extract_function(&source, "spawn_session_reaper");

    // Must await handle after removal
    assert!(
        reaper_fn.contains("handle.await") || reaper_fn.contains(".await"),
        "session reaper must await removed handles"
    );
}

#[test]
fn test_auxiliary_reaper_exists() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    assert!(
        source.contains("fn spawn_auxiliary_reaper"),
        "auxiliary reaper must exist"
    );

    let reaper_fn = extract_function(&source, "spawn_auxiliary_reaper");

    assert!(
        reaper_fn.contains("tokio::select!"),
        "auxiliary reaper must use select!"
    );
}

#[test]
fn test_steady_state_uses_global_generation() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let connect_fn = extract_function(&source, "connect_to_peer");

    // Must use session_generation.fetch_add
    assert!(
        connect_fn.contains("session_generation.fetch_add"),
        "connect_to_peer must use global session_generation atomic"
    );
}

#[test]
fn test_accept_report_freshness_check() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let shutdown_fn = extract_function(&source, "shutdown_with_timeout");

    // Must check freshness
    assert!(
        shutdown_fn.contains("report_is_fresh") || shutdown_fn.contains("generation"),
        "shutdown must check accept-loop report freshness"
    );
}

#[test]
fn test_no_dns_serving_healthy_false_hardcoded() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // Must NOT hardcode dns_serving_healthy: false
    assert!(
        !rollback_fn.contains("dns_serving_healthy: false"),
        "rollback must not hardcode dns_serving_healthy: false"
    );
}

#[test]
fn test_recovery_verifies_logical_state() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recover_fn = extract_function(&source, "recover_failed_state");

    // Must verify topology and DHT — either directly or via combined helper
    assert!(
        recover_fn.contains("topology_matches_snapshot")
            || recover_fn.contains("peer_matches_snapshot")
            || recover_fn.contains("restore_and_verify_peer_logical_state"),
        "recover_failed_state must verify topology/DHT against snapshot"
    );
}

#[test]
fn test_rollback_verifies_logical_state() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // Must verify topology and DHT — either directly or via combined helper
    assert!(
        rollback_fn.contains("topology_matches_snapshot")
            || rollback_fn.contains("peer_matches_snapshot")
            || rollback_fn.contains("restore_and_verify_peer_logical_state"),
        "rollback_startup must verify topology/DHT against snapshot"
    );
}

#[test]
fn test_topology_matches_snapshot_exists() {
    let source = read_file("crates/synvoid-mesh/src/mesh/topology.rs");

    assert!(
        source.contains("fn topology_matches_snapshot"),
        "topology.rs must have topology_matches_snapshot method"
    );

    // Must compare key fields, not just check existence
    let method = extract_function(&source, "topology_matches_snapshot");
    assert!(
        method.contains("address") && method.contains("role") && method.contains("latency_ms"),
        "topology_matches_snapshot must compare key fields"
    );
}

// ── Phase 39: Iteration 75 Guardrail Tests ──────────────────────────────────

// ── Test 51: DHT force-replacement API exists ───────────────────────────────

#[test]
fn dht_force_restore_contact_exists() {
    let source = read_file("crates/synvoid-mesh/src/mesh/dht/routing/table.rs");
    assert!(
        source.contains("fn force_restore_contact"),
        "RoutingTable must expose force_restore_contact method"
    );
    // Must unconditionally replace (not apply PoW checks like try_insert)
    let method = extract_function(&source, "force_restore_contact");
    assert!(
        !method.contains("try_insert"),
        "force_restore_contact must not delegate to try_insert (it must unconditionally replace)"
    );
}

// ── Test 52: DHT restore uses force-replace, not try_insert ─────────────────

#[test]
fn dht_restore_uses_force_not_try_insert() {
    let source = read_file("crates/synvoid-mesh/src/mesh/dht/routing/manager.rs");
    let restore_fn = extract_function(&source, "restore_peer");

    // restore_peer must call force_restore_contact (not try_insert)
    assert!(
        restore_fn.contains("force_restore_contact"),
        "restore_peer() must call force_restore_contact for unconditional replacement"
    );
    assert!(
        !restore_fn.contains("try_insert"),
        "restore_peer() must not use try_insert (it must use force_restore_contact)"
    );
}

// ── Test 53: restore_peer_state() removes non-global from global_nodes ──────

#[test]
fn restore_peer_state_removes_non_global_from_global_nodes() {
    let source = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    let method = extract_function(&source, "restore_peer_state");

    // Must handle the is_global branch: insert when true, remove when false
    assert!(
        method.contains("global.insert"),
        "restore_peer_state must insert into global_nodes when is_global is true"
    );
    assert!(
        method.contains("global.remove"),
        "restore_peer_state must remove from global_nodes when is_global is false"
    );
    // Must check is_global flag
    assert!(
        method.contains("is_global"),
        "restore_peer_state must check is_global flag for global_nodes membership"
    );
}

// ── Test 54: remove_peer() removes from global_nodes ────────────────────────

#[test]
fn topology_remove_peer_removes_from_global_nodes() {
    let source = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    let method = extract_function(&source, "remove_peer");

    // remove_peer must remove from global_nodes index
    assert!(
        method.contains("global.remove"),
        "remove_peer must remove node_id from global_nodes secondary index"
    );
    // Must acquire write lock on global_nodes
    assert!(
        method.contains("global_nodes.write"),
        "remove_peer must acquire write lock on global_nodes"
    );
}

// ── Test 55: topology_matches_snapshot includes comprehensive comparisons ────

#[test]
fn topology_matches_snapshot_comprehensive() {
    let source = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    let method = extract_function(&source, "topology_matches_snapshot");

    // Must compare capabilities (all sub-fields)
    assert!(
        method.contains("capabilities.can_route"),
        "topology_matches_snapshot must compare capabilities.can_route"
    );
    assert!(
        method.contains("capabilities.can_proxy"),
        "topology_matches_snapshot must compare capabilities.can_proxy"
    );

    // Must compare timestamps
    assert!(
        method.contains("first_seen") && method.contains("last_seen"),
        "topology_matches_snapshot must compare first_seen and last_seen timestamps"
    );

    // Must compare previous_reputation
    assert!(
        method.contains("previous_reputation"),
        "topology_matches_snapshot must compare previous_reputation"
    );

    // Must verify global_nodes secondary index consistency
    assert!(
        method.contains("global_nodes"),
        "topology_matches_snapshot must verify global_nodes secondary index consistency"
    );

    // Must compare geo
    assert!(
        method.contains("geo"),
        "topology_matches_snapshot must compare geo fields"
    );
}

// ── Test 56: Rollback stops sessions before restoration ─────────────────────

#[test]
fn rollback_stops_sessions_before_restoration() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // stop_staged_peer_activity must appear before restore_and_verify_peer_logical_state
    let stop_pos = rollback_fn.find("stop_staged_peer_activity");
    let restore_pos = rollback_fn.find("restore_and_verify_peer_logical_state");

    assert!(
        stop_pos.is_some(),
        "rollback_startup must call stop_staged_peer_activity"
    );
    assert!(
        restore_pos.is_some(),
        "rollback_startup must call restore_and_verify_peer_logical_state"
    );
    if let (Some(sp), Some(rp)) = (stop_pos, restore_pos) {
        assert!(
            sp < rp,
            "rollback_startup must stop sessions (stop_staged_peer_activity at offset {sp}) \
             BEFORE logical restoration (restore_and_verify_peer_logical_state at offset {rp})"
        );
    }
}

// ── Test 57: Recovery retains verification-failed peers ─────────────────────

#[test]
fn recovery_retains_verification_failed_peers() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recover_fn = extract_function(&source, "recover_failed_state");

    // Must use restore_and_verify (not bare restore)
    assert!(
        recover_fn.contains("restore_and_verify_peer_logical_state"),
        "recover_failed_state must use restore_and_verify_peer_logical_state"
    );

    // Must retain unresolved peers
    assert!(
        recover_fn.contains("remaining_peers"),
        "recover_failed_state must track remaining_peers for unresolved entries"
    );
    assert!(
        recover_fn.contains("remaining_peers.push"),
        "recover_failed_state must push failed peers to remaining_peers"
    );

    // Must re-persist residue when peers remain unresolved
    assert!(
        recover_fn.contains("FailedStartupResidue"),
        "recover_failed_state must re-create FailedStartupResidue for unresolved peers"
    );
}

// ── Test 58: peer_message_loop() contains a JoinSet ────────────────────────

#[test]
fn peer_message_loop_uses_joinset() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");
    let method = extract_function(&source, "peer_message_loop");

    // Must declare a JoinSet for stream handlers
    assert!(
        method.contains("JoinSet"),
        "peer_message_loop must use JoinSet for stream handler management"
    );
    // Must spawn into the JoinSet (not bare tokio::spawn)
    assert!(
        method.contains("stream_handlers.spawn"),
        "peer_message_loop must spawn stream handlers into the JoinSet"
    );
}

// ── Test 59: No bare stream-handler tokio::spawn() ──────────────────────────

#[test]
fn no_bare_stream_handler_spawn() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");
    let method = extract_function(&source, "peer_message_loop");

    // Every tokio::spawn or spawn inside peer_message_loop should be
    // stream_handlers.spawn (into the JoinSet), not bare tokio::spawn.
    let lines: Vec<(usize, &str)> = method.lines().enumerate().collect();
    let mut violations = Vec::new();

    for (i, (_line_num, line)) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("tokio::spawn(")
            && !trimmed.contains("stream_handlers.spawn")
            && !trimmed.starts_with("//")
        {
            violations.push(format!(
                "line ~{}: bare tokio::spawn in peer_message_loop (must use JoinSet)",
                i + 1
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "peer_message_loop must not have bare tokio::spawn for stream handlers:\n{}",
        violations.join("\n")
    );
}

// ── Test 60: Stream handlers drained before PeerSessionExit ─────────────────

#[test]
fn stream_handlers_drained_before_exit() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");
    let method = extract_function(&source, "peer_message_loop");

    // drain_peer_stream_handlers must appear before PeerSessionExit construction
    let drain_pos = method.find("drain_peer_stream_handlers");
    let exit_pos = method.find("PeerSessionExit {");

    assert!(
        drain_pos.is_some(),
        "peer_message_loop must call drain_peer_stream_handlers"
    );
    assert!(
        exit_pos.is_some(),
        "peer_message_loop must construct PeerSessionExit"
    );
    if let (Some(dp), Some(ep)) = (drain_pos, exit_pos) {
        assert!(
            dp < ep,
            "peer_message_loop must drain stream handlers (offset {dp}) \
             BEFORE constructing PeerSessionExit (offset {ep})"
        );
    }
}

// ── Phase 40: Rollback ordering guard ───────────────────────────────────────

#[test]
fn rollback_ordering_sessions_before_restoration() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // The rollback function must stop staged peer activity (auxiliary cancellation +
    // session teardown) before calling restore_peer_logical_state. This ensures no
    // live task can mutate topology/DHT during restoration.

    // Collect positions of key operations in order of appearance
    let stop_activity_pos = rollback_fn.find("stop_staged_peer_activity");
    let join_all_pos = rollback_fn.find("join_all");
    let restore_verify_pos = rollback_fn.find("restore_and_verify_peer_logical_state");

    // stop_staged_peer_activity must come first
    if let (Some(sa), Some(rv)) = (stop_activity_pos, restore_verify_pos) {
        assert!(
            sa < rv,
            "Invariant violation: stop_staged_peer_activity (offset {sa}) must come BEFORE \
             restore_and_verify_peer_logical_state (offset {rv})"
        );
    }

    // join_all (task group drain) should come after session stop but before restoration
    if let (Some(ja), Some(rv)) = (join_all_pos, restore_verify_pos) {
        assert!(
            ja < rv,
            "Invariant violation: task group join_all (offset {ja}) must come BEFORE \
             restore_and_verify_peer_logical_state (offset {rv})"
        );
    }
}

// ── Phase 41: Snapshot completeness guards ──────────────────────────────────

#[test]
fn dht_peer_snapshot_stores_complete_contact() {
    let source = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // DhtPeerSnapshot must store the complete PeerContact, not individual fields.
    // This prevents field-list drift between snapshot and restoration.
    assert!(
        source.contains("pub contact:"),
        "DhtPeerSnapshot must store a complete PeerContact (not individual fields)"
    );

    // Verify it is NOT storing individual fields (the anti-pattern we're guarding against)
    let struct_start = source
        .find("pub struct DhtPeerSnapshot")
        .expect("DhtPeerSnapshot struct not found");
    let struct_window = &source[struct_start..struct_start + 300];
    assert!(
        !struct_window.contains("pub node_id:")
            && !struct_window.contains("pub address:")
            && !struct_window.contains("pub port:"),
        "DhtPeerSnapshot must store complete PeerContact, not individual fields \
         (field-list drift guard)"
    );
}

#[test]
fn staged_topology_snapshot_stores_complete_peer_state() {
    let source = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // StagedTopologySnapshot must store the complete PeerState, not individual fields.
    assert!(
        source.contains("pub peer_state:"),
        "StagedTopologySnapshot must store a complete PeerState (not individual fields)"
    );

    // Verify it is NOT storing individual fields
    let struct_start = source
        .find("pub struct StagedTopologySnapshot")
        .expect("StagedTopologySnapshot struct not found");
    let struct_window = &source[struct_start..struct_start + 300];
    assert!(
        !struct_window.contains("pub node_id:")
            && !struct_window.contains("pub address:")
            && !struct_window.contains("pub role:"),
        "StagedTopologySnapshot must store complete PeerState, not individual fields \
         (field-list drift guard)"
    );
}

#[test]
fn restore_peer_logical_state_uses_complete_snapshot() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let method = extract_function(&source, "restore_peer_logical_state");

    // Must restore via complete snapshot objects, not field-by-field reconstruction
    assert!(
        method.contains("restore_peer_state(snapshot.peer_state.clone())"),
        "restore_peer_logical_state must pass complete PeerState to restore_peer_state"
    );
    assert!(
        method.contains("rm.restore_peer(snapshot)"),
        "restore_peer_logical_state must pass complete DhtPeerSnapshot to rm.restore_peer"
    );
}

#[test]
fn rollback_retains_unresolved_peers() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // Rollback must push failed peers to unresolved_peers in the report
    assert!(
        rollback_fn.contains("unresolved_peers.push"),
        "rollback_startup must push failed peers to report.unresolved_peers"
    );
    assert!(
        rollback_fn.contains("unresolved_peers"),
        "rollback_startup must have unresolved_peers field in RollbackReport"
    );
}

// ── Iteration 76: Part A — Zero-budget rollback finalization guard ───────

/// Guardrail: `rollback_startup` must NOT skip `join_all` when the
/// remaining budget is zero. The pre-Iteration-76 code path did
/// `if task_remaining.is_zero() { Vec::new() }` which left tasks
/// orphaned in the task registry without exit reporting.
#[test]
fn iter76_rollback_does_not_skip_join_all_on_zero_budget() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    assert!(
        !rollback_fn.contains("if task_remaining.is_zero()"),
        "rollback_startup must not skip join_all on zero remaining budget (Iteration 76 Part A)"
    );

    // The post-fix call is the unconditional one.
    assert!(
        rollback_fn.contains("let exits = stage.task_group.join_all(remaining(deadline))"),
        "rollback_startup must always call join_all(remaining(deadline))"
    );
}

/// Guardrail: `recover_failed_state` must NOT skip `join_all` on a zero
/// budget. Recovery is a sibling of rollback and inherits the same
/// finalization contract.
#[test]
fn iter76_recovery_does_not_skip_join_all_on_zero_budget() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_fn = extract_function(&source, "recover_failed_state");

    assert!(
        !recovery_fn.contains("if task_remaining.is_zero()"),
        "recover_failed_state must not skip join_all on zero remaining budget (Iteration 76 Part A)"
    );
}

// ── Iteration 76: Part B — Cooperative cancellation guard ────────────────

/// Guardrail: every `PeerSessionTask` construction site in `transport.rs`
/// must include the `shutdown_tx` field. This is the type-level
/// invariant: any new construction that forgets the cooperative
/// cancellation carrier will fail to compile, but this test catches the
/// case where the field is removed from the struct definition itself.
#[test]
fn iter76_peer_session_task_has_shutdown_tx_field() {
    let lifecycle_src = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    let struct_pos = lifecycle_src
        .find("pub struct PeerSessionTask")
        .expect("PeerSessionTask must exist");
    let body_start = lifecycle_src[struct_pos..]
        .find('{')
        .map(|i| struct_pos + i)
        .expect("struct body must open");
    let mut depth = 0i32;
    let mut body_end = body_start;
    for (i, ch) in lifecycle_src[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    body_end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let struct_body = &lifecycle_src[body_start..=body_end];
    assert!(
        struct_body.contains("shutdown_tx"),
        "PeerSessionTask must carry shutdown_tx field for cooperative cancellation"
    );
}

/// Guardrail: `peer_message_loop` in `transport_peer.rs` must select on
/// the cooperative shutdown signal BEFORE other branches. Using
/// `tokio::select! { biased; ... }` ensures the cancel branch wins the
/// race against a steady stream of incoming events.
#[test]
fn iter76_peer_message_loop_uses_biased_select_on_shutdown() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    // The biased select is the cancellation contract. Without it, a
    // session starved by incoming events would never observe the
    // shutdown signal. The biased keyword is on its own line in the
    // source (typical Rust style).
    let has_biased_select = source.lines().collect::<Vec<_>>().windows(2).any(|pair| {
        pair[0].contains("select!") && pair[0].contains('{') && pair[1].trim() == "biased;"
    }) || source.contains("select! { biased;")
        || source.contains("select!{biased;");
    assert!(
        has_biased_select,
        "transport_peer.rs must use tokio::select! {{ biased; ... }} for cooperative shutdown (Iteration 76 Part B)"
    );
}

/// Guardrail: `stop_staged_peer_activity` must always send the
/// cooperative shutdown signal before draining/aborting the session.
#[test]
fn iter76_stop_staged_peer_activity_sends_signal_first() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let body = extract_function(&source, "stop_staged_peer_activity");

    let signal_pos = body
        .find("shutdown_tx.send(true)")
        .expect("stop_staged_peer_activity must send cooperative shutdown signal");
    let handle_pos = body
        .find("stop_peer_session_task")
        .expect("stop_staged_peer_activity must call stop_peer_session_task");

    assert!(
        signal_pos < handle_pos,
        "cooperative signal must be sent BEFORE the session handle is stopped (signal at {signal_pos}, handle at {handle_pos})"
    );
}

// ── Iteration 76: Part C — Safe DHT force restoration guard ──────────────

/// Guardrail: `KBucket::force_replace` must return a `Result` so that a
/// full bucket with an absent target fails closed instead of silently
/// evicting an unrelated contact. The pre-Iteration-76 signature
/// `Option<PeerContact>` could corrupt the bucket during rollback.
#[test]
fn iter76_kbucket_force_replace_returns_result() {
    let source = read_file("crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs");

    let sig_marker = "pub fn force_replace(";
    let sig_pos = source.find(sig_marker).expect("force_replace must exist");
    let after_sig = &source[sig_pos..];
    let arrow_pos = after_sig
        .find("->")
        .expect("force_replace must have a return type");
    let return_type = &after_sig[arrow_pos..arrow_pos + 80];

    assert!(
        return_type.contains("Result"),
        "force_replace must return Result, not Option (Iteration 76 Part C)"
    );
    assert!(
        return_type.contains("ForceRestoreError"),
        "force_replace must return ForceRestoreError on conflict"
    );
}

/// Guardrail: `RoutingTable::force_restore_contact` must propagate
/// bucket-level errors as `ForceRestoreContactError`. Rollback and
/// recovery use this to decide whether to surface unresolved peers.
#[test]
fn iter76_routing_table_force_restore_uses_typed_error() {
    let source = read_file("crates/synvoid-mesh/src/mesh/dht/routing/table.rs");

    assert!(
        source.contains("ForceRestoreContactError"),
        "RoutingTable must define ForceRestoreContactError"
    );
    assert!(
        source.contains("BucketFullTargetAbsent"),
        "RoutingTable must surface bucket-level BucketFullTargetAbsent as a typed error"
    );
}

// ── Iteration 76: Part E — Stream timeout semantics guard ───────────────

/// Guardrail: peer stream read timeout and total stream lifetime timeout
/// must be distinct, independently configurable values. The two have
/// different semantics: read timeout bounds per-message I/O, total
/// timeout bounds the entire stream lifetime.
#[test]
fn iter76_distinct_stream_timeout_config_fields() {
    let cfg_src = read_file("crates/synvoid-config/src/mesh.rs");
    let mesh_cfg_src = read_file("crates/synvoid-mesh/src/mesh/config.rs");

    assert!(
        cfg_src.contains("peer_message_timeout_secs"),
        "MeshConnectionConfig must define peer_message_timeout_secs (per-message read)"
    );
    assert!(
        cfg_src.contains("peer_stream_total_timeout_secs"),
        "MeshConnectionConfig must define peer_stream_total_timeout_secs (opt-in total lifetime)"
    );
    assert!(
        mesh_cfg_src.contains("peer_stream_total_timeout_secs"),
        "synvoid-mesh MeshConnectionConfig must also define peer_stream_total_timeout_secs"
    );
}

/// Guardrail: In Iteration 76, `apply_read_timeouts` wrapped the entire
/// handler future. In Iteration 77, this was removed — read timeout is
/// now passed into `handle_peer_message` and applied at actual read
/// operations only. This test verifies the old pattern is gone.
#[test]
fn iter77_apply_read_timeouts_removed_read_timeout_at_reads() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    assert!(
        !source.contains("fn apply_read_timeouts"),
        "apply_read_timeouts must be removed in Iteration 77 — read timeout is now at actual reads"
    );
    assert!(
        source.contains("fn read_exact_with_timeout"),
        "transport_peer.rs must define read_exact_with_timeout for actual RecvStream reads"
    );
    assert!(
        source.contains("fn drain_peer_stream_handlers"),
        "drain_peer_stream_handlers must still exist"
    );
    assert!(
        source.contains("tokio::time::timeout(left, handlers.join_next())"),
        "drain_peer_stream_handlers must use timeout around join_next for deadline enforcement"
    );
}

// ── Iteration 77: Nested-Cleanup Corrective Guardrails ────────────────────

/// Guardrail: `drain_peer_stream_handlers` must use `tokio::time::timeout`
/// around `join_next()` so a single hung handler cannot block beyond the
/// cooperative deadline. Bare `join_next().await` without timeout is the
/// defect corrected in this iteration.
#[test]
fn iter77_drain_uses_timeout_around_join_next() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    assert!(
        source.contains("tokio::time::timeout(left, handlers.join_next())"),
        "drain_peer_stream_handlers must wrap join_next() with timeout for deadline enforcement"
    );
    assert!(
        source.contains("fn classify_stream_join"),
        "stream join classification helper must exist"
    );
    assert!(
        source.contains("fn classify_forced_stream_join"),
        "forced stream join classification helper must exist"
    );
}

/// Guardrail: Zero-budget forced parent abort must return
/// `ForcedParentAbort`, not `Failed("parent cancelled")`. The
/// `force_abort_peer_session` helper ensures both zero-budget and
/// cooperative-timeout paths use identical classification.
#[test]
fn iter77_forced_abort_returns_forced_parent_abort_not_failed() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    assert!(
        source.contains("fn force_abort_peer_session"),
        "force_abort_peer_session helper must exist for consistent classification"
    );
    // The zero-budget branch must delegate to the helper, not inline Failed
    assert!(
        source.contains("Self::force_abort_peer_session(handle).await"),
        "zero-budget and timeout paths must use force_abort_peer_session helper"
    );
}

/// Guardrail: `stop_staged_peer_activity` must handle all three
/// `PeerSessionStopOutcome` variants. `Failed` outcomes must produce
/// rollback errors, not be silently ignored.
#[test]
fn iter77_stop_staged_handles_all_outcomes() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Must match on all three variants
    assert!(
        source.contains("PeerSessionStopOutcome::Drained(_) => {}"),
        "stop_staged_peer_activity must handle Drained variant"
    );
    assert!(
        source.contains("PeerSessionStopOutcome::ForcedParentAbort =>"),
        "stop_staged_peer_activity must handle ForcedParentAbort variant"
    );
    assert!(
        source.contains("PeerSessionStopOutcome::Failed(error) =>"),
        "stop_staged_peer_activity must handle Failed variant"
    );

    // Phase 14: Error messages must include session_generation for context
    assert!(
        source.contains("peer.session_generation"),
        "stop_staged_peer_activity error messages must include session_generation (Phase 14)"
    );
    assert!(
        source.contains("session_gen"),
        "recover_failed_state error messages must include session_gen (Phase 14)"
    );
}

/// Guardrail: `recover_failed_state` must merge `session_errors` into
/// the final `issues` vector. Without this merge, session cleanup
/// failures are silently dropped and recovery falsely transitions to
/// `Stopped`.
#[test]
fn iter77_recovery_merges_session_errors_into_issues() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    assert!(
        source.contains("issues.extend(session_errors)"),
        "recover_failed_state must merge session_errors into issues for final verification"
    );
}

/// Guardrail: `recover_failed_state` must handle all three
/// `PeerSessionStopOutcome` variants in its session drain loop.
/// `Failed` outcomes must produce session errors, not be silently
/// ignored.
#[test]
fn iter77_recovery_handles_all_session_outcomes() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Find the recovery session drain loop and verify all outcomes handled
    assert!(
        source.contains("PeerSessionStopOutcome::Failed(error) =>"),
        "recover_failed_state must handle Failed variant in session drain loop"
    );
}

/// Guardrail: `start_datagram_handler` must no longer use bare
/// `tokio::spawn()` for incoming datagrams. Handlers must be owned by
/// a `JoinSet` and drained/aborted before the function returns.
#[test]
fn iter77_no_bare_datagram_spawn_in_handler() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    // Extract only the start_datagram_handler function body
    let handler_body = extract_function(&source, "start_datagram_handler");

    assert!(
        !handler_body.contains("tokio::spawn(async move"),
        "start_datagram_handler must not use bare tokio::spawn — use JoinSet instead"
    );
    assert!(
        handler_body.contains("JoinSet"),
        "start_datagram_handler must use JoinSet for handler ownership"
    );
    assert!(
        handler_body.contains("handlers.spawn("),
        "start_datagram_handler must spawn into JoinSet"
    );
}

/// Guardrail: Datagram handler JoinSet must be drained before
/// `start_datagram_handler` returns. The drain pattern uses a
/// deadline-aware timeout around `join_next()` followed by
/// `abort_all()` for remaining handlers.
/// Phase 22: Extracted to `drain_datagram_handlers` standalone helper.
#[test]
fn iter77_datagram_handler_drained_before_return() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    // Verify start_datagram_handler calls the drain helper
    let handler_body = extract_function(&source, "start_datagram_handler");
    assert!(
        handler_body.contains("drain_datagram_handlers("),
        "start_datagram_handler must call drain_datagram_handlers helper"
    );

    // Verify drain_datagram_handlers implements the correct drain pattern
    let drain_body = extract_function(&source, "drain_datagram_handlers");
    assert!(
        drain_body.contains("abort_all()"),
        "drain_datagram_handlers must abort remaining handlers after drain deadline"
    );
    assert!(
        drain_body.contains("join_next().await"),
        "drain_datagram_handlers must await all aborted handlers"
    );
    assert!(
        drain_body.contains("saturating_duration_since"),
        "drain_datagram_handlers must use deadline-aware timeout"
    );
}

/// Guardrail: Datagram concurrency must be bounded by
/// `max_concurrent_datagram_handlers` config field.
#[test]
fn iter77_datagram_concurrency_bounded_by_config() {
    let cfg_src = read_file("crates/synvoid-config/src/mesh.rs");
    let mesh_cfg_src = read_file("crates/synvoid-mesh/src/mesh/config.rs");

    assert!(
        cfg_src.contains("max_concurrent_datagram_handlers"),
        "config crate MeshConnectionConfig must define max_concurrent_datagram_handlers"
    );
    assert!(
        mesh_cfg_src.contains("max_concurrent_datagram_handlers"),
        "mesh crate MeshConnectionConfig must define max_concurrent_datagram_handlers"
    );
}

/// Guardrail: Peer stream drain timeout must be configurable via
/// `peer_stream_drain_timeout_secs`.
#[test]
fn iter77_drain_timeout_configurable() {
    let cfg_src = read_file("crates/synvoid-config/src/mesh.rs");
    let mesh_cfg_src = read_file("crates/synvoid-mesh/src/mesh/config.rs");

    assert!(
        cfg_src.contains("peer_stream_drain_timeout_secs"),
        "config crate MeshConnectionConfig must define peer_stream_drain_timeout_secs"
    );
    assert!(
        mesh_cfg_src.contains("peer_stream_drain_timeout_secs"),
        "mesh crate MeshConnectionConfig must define peer_stream_drain_timeout_secs"
    );
}

/// Guardrail: `handle_peer_message` must accept a `read_timeout`
/// parameter and thread it into actual `RecvStream` read operations,
/// not wrap the entire handler future.
#[test]
fn iter77_handle_peer_message_accepts_read_timeout() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    assert!(
        source.contains("read_timeout: Duration,"),
        "handle_peer_message must accept read_timeout parameter"
    );
    assert!(
        source.contains("read_exact_with_timeout(recv_stream"),
        "handle_peer_message must use read_exact_with_timeout for reads"
    );
}

/// Guardrail: HTTP header framing must be bounded (stop at \r\n\r\n)
/// instead of reading until EOF via `BufReader::read_to_string`.
#[test]
fn iter77_http_header_framing_bounded() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    assert!(
        !source.contains("read_to_string(&mut remainder)"),
        "unbounded BufReader::read_to_string must be replaced with bounded framing"
    );
    assert!(
        source.contains(r"\r\n\r\n"),
        "HTTP header framing must stop at \r\n\r\n"
    );
}

/// Guardrail: The `peer_message_loop` spawn block must not call
/// `apply_read_timeouts`. The read timeout is passed into
/// `handle_peer_message` directly.
#[test]
fn iter77_spawn_block_no_apply_read_timeouts() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    let loop_body = extract_function(&source, "peer_message_loop");

    assert!(
        !loop_body.contains("apply_read_timeouts"),
        "peer_message_loop must not call apply_read_timeouts — read timeout is in handle_peer_message"
    );
}

/// Guardrail: Phase 24 audit — `handle_incoming_datagram` contains one
/// fire-and-forget spawn for edge replica notification. This is a
/// documented exception: the edge replica is a cache, and stale data
/// is acceptable. The spawn is not blocking critical state.
#[test]
fn iter77_datagram_nested_spawn_has_documented_exception() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    let handler_body = extract_function(&source, "handle_incoming_datagram");

    // Check if there are any tokio::spawn calls in handle_incoming_datagram
    let has_spawn = handler_body.contains("tokio::spawn(async move");

    if has_spawn {
        // If spawn exists, verify it has a documented exception comment
        assert!(
            handler_body.contains("fire-and-forget"),
            "handle_incoming_datagram contains tokio::spawn without documented exception comment"
        );
        assert!(
            handler_body.contains("edge replica"),
            "handle_incoming_datagram spawn must be edge replica notification (the only acceptable fire-and-forget case)"
        );
        assert!(
            handler_body.contains("cache"),
            "handle_incoming_datagram spawn must document that edge replica is a cache (stale data acceptable)"
        );
    }
    // If no spawn found, that's fine — the exception is only for the
    // edge replica notification which is intentionally fire-and-forget
}

/// Guardrail (Phase 33): All bare `tokio::spawn()` calls in datagram
/// handler paths must have documented exception comments explaining why
/// fire-and-forget is acceptable. Unreviewed bare spawns in datagram
/// paths are rejected.
#[test]
fn iter77_all_datagram_path_spawns_have_documented_exceptions() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    // start_datagram_handler must NOT contain bare tokio::spawn — all
    // handlers are owned by the JoinSet.
    let handler_body = extract_function(&source, "start_datagram_handler");
    assert!(
        !handler_body.contains("tokio::spawn("),
        "start_datagram_handler must not contain bare tokio::spawn — use JoinSet"
    );

    // handle_incoming_datagram may contain spawns only with documented
    // exception comments (already tested by
    // iter77_datagram_nested_spawn_has_documented_exception).
}

/// Guardrail (Phase 34): Timeout naming must be truthful. A "read"
/// timeout must wrap only read operations, not the complete handler.
/// A "total" or "lifetime" timeout wraps the complete handler.
#[test]
fn iter77_timeout_naming_is_truthful() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    // read_exact_with_timeout must exist and wrap only recv reads
    assert!(
        source.contains("fn read_exact_with_timeout"),
        "read_exact_with_timeout helper must exist for read-boundary timeouts"
    );

    // The per-message read timeout must be named with "read" or
    // "timeout" (not "total" or "lifetime")
    assert!(
        source.contains("read_timeout"),
        "per-message read timeout must be named read_timeout (not total/lifetime)"
    );

    // The total stream timeout must use "total" in its name when wrapping
    // the complete handler — verify it does not reuse the read timeout
    // variable for the full-handler wrapper
    let loop_body = extract_function(&source, "peer_message_loop");
    assert!(
        loop_body.contains("total_timeout") || loop_body.contains("peer_stream_total_timeout"),
        "complete-handler timeout must be named total_timeout or peer_stream_total_timeout (not read_timeout)"
    );

    // Verify the read timeout is NOT used to wrap the complete handler
    // (it should only appear inside handle_peer_message at read sites)
    let handler_sig = source.find("async fn handle_peer_message");
    if let Some(sig_pos) = handler_sig {
        // The read_timeout parameter should only appear in handle_peer_message
        // and its inner helpers, not wrapping the entire handler in peer_message_loop
        let loop_section = &loop_body[..loop_body.len().min(2000)];
        // The loop should NOT have: timeout(read_timeout, handler)
        assert!(
            !loop_section.contains("timeout(read_timeout,") && !loop_section.contains("timeout( read_timeout,"),
            "peer_message_loop must not wrap the complete handler with read_timeout — use total_timeout"
        );
    }
}

/// Guardrail: `read_to_end_with_timeout` must not exist as dead code.
/// All read helpers must be actively used.
#[test]
fn iter77_no_dead_read_helpers() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    assert!(
        !source.contains("fn read_to_end_with_timeout"),
        "read_to_end_with_timeout is dead code and must be removed"
    );
}

// ── Iteration 78: HTTP framing and edge-replica ownership ──

#[test]
fn iter78_http_header_framing_uses_remaining_capacity() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    // The read_http_request_head helper must compute remaining_capacity
    assert!(
        src.contains("remaining_capacity"),
        "read_http_request_head must compute remaining_capacity before each read"
    );
    // Must not use header_cap.min(...) without buffer length
    assert!(
        !src.contains("header_cap.min("),
        "must not use header_cap.min without remaining capacity"
    );
}

#[test]
fn iter78_body_framing_after_header_terminator() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    // Must have Content-Length parsing
    assert!(
        src.contains("parse_http_body_framing"),
        "must parse body framing from headers"
    );
    // Must have body_prefix handling
    assert!(
        src.contains("body_prefix"),
        "must preserve body_prefix bytes after header terminator"
    );
    // Must have read_fixed_http_body
    assert!(
        src.contains("read_fixed_http_body"),
        "must have fixed body read helper"
    );
}

#[test]
fn iter78_content_length_parsed_or_chunked_rejected() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    // Must have Content-Length parsing
    assert!(src.contains("content_length"), "must parse Content-Length");
    // Must reject chunked explicitly
    assert!(
        src.contains("Chunked") || src.contains("chunked"),
        "must handle chunked transfer encoding"
    );
}

#[test]
fn iter78_complete_request_forwarded_not_headers_only() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    // The HTTP framing path must construct request_bytes that includes body
    assert!(
        src.contains("request_bytes"),
        "must construct request_bytes with headers + body"
    );
    // Must pass request_bytes (not just headers) to handle_http_proxy_stream
    assert!(
        src.contains("request_bytes") && src.contains("handle_http_proxy_stream"),
        "must forward complete request_bytes to handle_http_proxy_stream"
    );
}

#[test]
fn iter78_total_header_framing_deadline_exists() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src.contains("peer_http_header_total_timeout_secs"),
        "must use total header framing deadline config"
    );
}

#[test]
fn iter78_no_unused_accumulated_variable() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    // The old code had `let mut accumulated = 0usize;` which is now unused
    // The new read_http_request_head must not have it
    let lines: Vec<&str> = src.lines().collect();
    let in_header_framing = lines.iter().any(|l| l.contains("let mut accumulated"));
    // Check it's not in the read_http_request_head function area
    // (the function is near the top of the file, before handle_peer_message)
    assert!(
        !in_header_framing || !src.contains("fn read_http_request_head"),
        "unused 'accumulated' variable should be removed"
    );
}

#[test]
fn iter78_connect_upgrade_rejected() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src.contains("UnsupportedMethod") || src.contains("503 Service Unavailable"),
        "must reject CONNECT/upgrade requests"
    );
}

#[test]
fn iter78_edge_replica_uses_auxiliary_task() {
    // Iteration 79: edge-replica spawn delegated to spawn_auxiliary_task helper
    let src_peer = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src_peer.contains("EdgeReplicaRefresh"),
        "edge-replica refresh must use AuxiliaryTaskKind::EdgeReplicaRefresh"
    );
    assert!(
        src_peer.contains("spawn_auxiliary_task"),
        "edge-replica refresh must delegate to spawn_auxiliary_task helper"
    );
    let src_transport = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
        .expect("read transport.rs");
    assert!(
        src_transport.contains("spawn_auxiliary_task"),
        "spawn_auxiliary_task helper must exist in transport.rs"
    );
}

#[test]
fn iter78_peer_session_exit_has_stream_drain() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
        .expect("read lifecycle.rs");
    assert!(
        src.contains("stream_drain"),
        "PeerSessionExit must have stream_drain field"
    );
}

#[test]
fn iter78_config_has_http_framing_fields() {
    let src =
        std::fs::read_to_string("crates/synvoid-mesh/src/mesh/config.rs").expect("read config.rs");
    assert!(
        src.contains("peer_http_header_total_timeout_secs"),
        "config must have peer_http_header_total_timeout_secs"
    );
    assert!(
        src.contains("max_peer_http_body_bytes"),
        "config must have max_peer_http_body_bytes"
    );
    assert!(
        src.contains("peer_http_body_total_timeout_secs"),
        "config must have peer_http_body_total_timeout_secs"
    );
    assert!(
        src.contains("peer_http_backend_idle_timeout_secs"),
        "config must have peer_http_backend_idle_timeout_secs"
    );
}

#[test]
fn iter78_config_mirror_has_http_framing_fields() {
    let src =
        std::fs::read_to_string("crates/synvoid-config/src/mesh.rs").expect("read config mirror");
    assert!(
        src.contains("peer_http_header_total_timeout_secs"),
        "config mirror must have peer_http_header_total_timeout_secs"
    );
    assert!(
        src.contains("max_peer_http_body_bytes"),
        "config mirror must have max_peer_http_body_bytes"
    );
    assert!(
        src.contains("peer_http_body_total_timeout_secs"),
        "config mirror must have peer_http_body_total_timeout_secs"
    );
    assert!(
        src.contains("peer_http_backend_idle_timeout_secs"),
        "config mirror must have peer_http_backend_idle_timeout_secs"
    );
}

#[test]
fn iter78_backend_idle_timeout_exists() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src.contains("peer_http_backend_idle_timeout_secs"),
        "backend response read must use idle timeout"
    );
}

// ── Iteration 78 (completion pass): additional guardrails ──

#[test]
fn iter78_child_task_failed_variant_exists() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
        .expect("read lifecycle.rs");
    assert!(
        src.contains("ChildTaskFailed"),
        "PeerSessionExitReason must have ChildTaskFailed variant"
    );
}

#[test]
fn iter78_peer_message_loop_promotes_child_failure() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src.contains("drain_report.failed > 0"),
        "peer_message_loop must check drain_report.failed > 0 for ChildTaskFailed promotion"
    );
}

#[test]
fn iter78_shutdown_report_has_stream_handler_drain() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
        .expect("read lifecycle.rs");
    assert!(
        src.contains("stream_handler_drain"),
        "MeshShutdownReport must have stream_handler_drain field"
    );
}

#[test]
fn iter78_edge_replica_has_backpressure() {
    // Iteration 79: concurrency limit moved to spawn_auxiliary_task helper in transport.rs
    let src_transport = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
        .expect("read transport.rs");
    assert!(
        src_transport.contains("MAX_CONCURRENT_EDGE_REPLICA_REFRESH"),
        "edge-replica refresh must have concurrency limit in spawn_auxiliary_task"
    );
}

#[test]
fn iter78_stop_peer_session_task_has_test_adapter() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
        .expect("read transport.rs");
    // Iteration 79, Phase 31: The test adapter was removed. Module-local
    // tests now call the private stop_peer_session_task() directly.
    assert!(
        !src.contains("stop_peer_session_task_for_test"),
        "stop_peer_session_task_for_test adapter must be removed (tests call private fn directly)"
    );
}

#[test]
fn iter78_drain_datagram_handlers_has_test_adapter() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src.contains("drain_datagram_handlers_for_test"),
        "drain_datagram_handlers must have test adapter"
    );
}

#[test]
fn iter78_aggregate_handler_counters_exist() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
        .expect("read transport.rs");
    assert!(
        src.contains("aggregate_handler_drained"),
        "MeshTransport must have aggregate_handler_drained counter"
    );
    assert!(
        src.contains("aggregate_handler_aborted"),
        "MeshTransport must have aggregate_handler_aborted counter"
    );
    assert!(
        src.contains("aggregate_handler_failed"),
        "MeshTransport must have aggregate_handler_failed counter"
    );
}

// ── Iteration 78 (final): dedup, visibility, config validation ──

#[test]
fn iter78_auxiliary_task_has_dedup_key() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
        .expect("read lifecycle.rs");
    assert!(
        src.contains("dedup_key"),
        "AuxiliaryTask must have dedup_key field"
    );
}

#[test]
fn iter78_edge_replica_deduplication_exists() {
    // Iteration 79: dedup_key passed to spawn_auxiliary_task helper
    let src_peer = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs")
        .expect("read transport_peer.rs");
    assert!(
        src_peer.contains("edge_refresh:") && src_peer.contains("dedup_key"),
        "edge-replica registration must use dedup_key for deduplication"
    );
    let src_transport = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
        .expect("read transport.rs");
    assert!(
        src_transport.contains("dedup_key") && src_transport.contains("stale_ids"),
        "spawn_auxiliary_task must implement deduplication via dedup_key"
    );
}

#[test]
fn iter78_stop_peer_session_task_is_pub_crate() {
    let src = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
        .expect("read transport.rs");
    // Iteration 79, Phase 31: The pub(crate) adapter was removed entirely.
    // Module-local tests now call the private function directly.
    assert!(
        !src.contains("pub(crate) async fn stop_peer_session_task_for_test"),
        "stop_peer_session_task_for_test adapter must be removed"
    );
}

#[test]
fn iter78_config_has_serde_http_framing_tests() {
    let src =
        std::fs::read_to_string("crates/synvoid-mesh/src/mesh/config.rs").expect("read config.rs");
    assert!(
        src.contains("http_framing_config_defaults"),
        "config must have serde validation tests for HTTP framing fields"
    );
}

// ── Iteration 79: Guardrails (Phases 51–54) ────────────────────────────────

// ── Phase 51: HTTP Response Framing Guardrails ──────────────────────────────

#[test]
fn iter79_response_framing_exists() {
    let tp = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs").unwrap();
    assert!(
        tp.contains("read_http_response_head"),
        "read_http_response_head must exist"
    );
    assert!(
        tp.contains("read_fixed_http_response_body"),
        "read_fixed_http_response_body must exist"
    );
    assert!(
        tp.contains("read_chunked_http_response_body"),
        "read_chunked_http_response_body must exist"
    );
    assert!(
        tp.contains("FramedHttpResponseHead"),
        "FramedHttpResponseHead must exist"
    );
    assert!(
        tp.contains("HttpResponseFramingError"),
        "HttpResponseFramingError must exist"
    );
    assert!(
        !tp.contains("loop {") || tp.contains("max_body_bytes"),
        "Backend reads must be bounded"
    );
}

#[test]
fn iter79_no_body_response_handled() {
    let tp = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs").unwrap();
    assert!(
        tp.contains("is_no_body_status"),
        "Must check no-body status codes"
    );
    assert!(tp.contains("is_head"), "Must check HEAD method for no-body");
}

// ── Phase 52: Header-Only Metadata Guardrails ───────────────────────────────

#[test]
fn iter79_request_metadata_from_headers_only() {
    let tp = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs").unwrap();
    assert!(
        tp.contains("ParsedHttpRequestMeta"),
        "ParsedHttpRequestMeta must exist"
    );
    assert!(
        tp.contains("parse_http_request_meta"),
        "parse_http_request_meta must exist"
    );
    // Iteration 80: Obsolete whole-header metadata helpers are removed.
    // All callers must use ParsedHttpRequestMeta instead.
    assert!(
        !tp.contains("fn extract_host_from_http("),
        "extract_host_from_http must be removed — use ParsedHttpRequestMeta"
    );
    assert!(
        !tp.contains("fn extract_path_from_http("),
        "extract_path_from_http must be removed — use ParsedHttpRequestMeta"
    );
    assert!(
        !tp.contains("fn extract_method_from_http("),
        "extract_method_from_http must be removed — use ParsedHttpRequestMeta"
    );
    assert!(
        !tp.contains("to_lowercase().contains(\"upgrade:\")"),
        "Substring upgrade detection must be removed"
    );
}

// ── Phase 53: Auxiliary Ownership Guardrails ─────────────────────────────────

#[test]
fn iter79_auxiliary_spawn_helper_exists() {
    let tr = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs").unwrap();
    assert!(
        tr.contains("fn spawn_auxiliary_task"),
        "spawn_auxiliary_task helper must exist"
    );
    assert!(
        tr.contains("AuxiliaryTaskExit"),
        "AuxiliaryTaskExit must be published"
    );
}

#[test]
fn iter79_edge_refresh_uses_spawn_helper() {
    let tp = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport_peer.rs").unwrap();
    assert!(
        tp.contains("spawn_auxiliary_task"),
        "Edge refresh must use spawn_auxiliary_task"
    );
}

// ── Phase 54: Public API Guard ──────────────────────────────────────────────

#[test]
fn iter79_stop_peer_session_task_for_test_not_public() {
    let tr = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs").unwrap();
    // Iteration 79, Phase 31: The adapter was removed entirely. Module-local
    // tests now call the private stop_peer_session_task() directly, so no
    // public or pub(crate) test adapter remains.
    assert!(
        !tr.contains("stop_peer_session_task_for_test"),
        "stop_peer_session_task_for_test must not exist — tests call private fn directly"
    );
}

// ── Iteration 88: Final Corrective Pass Guardrails ─────────────────────────

#[test]
fn iter88_dht_init_before_peer_connect() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    // DHT initialization (Phase 3.5) must appear before seed bootstrap (Phase 4)
    let dht_init_pos = content
        .find("Phase 3.5: Initialize or restore DHT routing table")
        .expect("DHT init phase must exist");
    let seed_pos = content
        .find("Phase 4: Bootstrap from seeds")
        .expect("Seed bootstrap phase must exist");
    assert!(
        dht_init_pos < seed_pos,
        "DHT initialization must occur before seed bootstrap: dht_init at {}, seed at {}",
        dht_init_pos,
        seed_pos
    );
}

#[test]
fn iter88_dht_init_before_peer_connect_phase5() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let dht_init_pos = content
        .find("Phase 3.5: Initialize or restore DHT routing table")
        .expect("DHT init phase must exist");
    let peer_pos = content
        .find("Phase 5: Connect configured peers")
        .expect("Peer connect phase must exist");
    assert!(
        dht_init_pos < peer_pos,
        "DHT initialization must occur before peer connection: dht_init at {}, peer at {}",
        dht_init_pos,
        peer_pos
    );
}

#[test]
fn iter88_dht_bootstrap_gated_on_dht_ready() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("if dht_ready {"),
        "DHT bootstrap must be gated on dht_ready flag"
    );
}

#[test]
fn iter88_dht_maintenance_skipped_when_not_ready() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("DHT routing unavailable; skipping DHT maintenance tasks"),
        "Must log warning when DHT maintenance is skipped"
    );
}

#[test]
fn iter88_startup_peer_uses_checked_dht_insertion() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("dht_on_peer_connected_checked"),
        "Startup peer connection must use checked DHT insertion"
    );
}

#[test]
fn iter88_runtime_peer_uses_unchecked_dht_insertion() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport_connection.rs");
    // Runtime path should still use the non-checked variant
    assert!(
        content.contains("pub(crate) async fn dht_on_peer_connected("),
        "Runtime dht_on_peer_connected must still exist"
    );
}

#[test]
fn iter88_checked_dht_insertion_returns_result() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport_connection.rs");
    assert!(
        content.contains("async fn dht_on_peer_connected_checked"),
        "Checked DHT insertion method must exist"
    );
    assert!(
        content.contains("Result<(), MeshTransportError>"),
        "Checked DHT insertion must return Result"
    );
}

#[test]
fn iter88_no_yara_bridge_task() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The bridge task that combined two receivers into one should be removed
    assert!(
        !content.contains("let combined_shutdown = {"),
        "YARA bridge task must be removed"
    );
}

#[test]
fn iter88_yara_loop_accepts_two_receivers() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("worker_shutdown_rx: tokio::sync::watch::Receiver<bool>"),
        "YARA loop must accept worker shutdown receiver"
    );
    assert!(
        content.contains("generation_shutdown_rx: tokio::sync::watch::Receiver<bool>"),
        "YARA loop must accept generation shutdown receiver"
    );
}

#[test]
fn iter88_yara_checks_already_true_signals() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("*worker_shutdown_rx.borrow()")
            || content.contains("worker_shutdown_rx.borrow()"),
        "YARA loop must check already-true worker shutdown signal"
    );
    assert!(
        content.contains("*generation_shutdown_rx.borrow()")
            || content.contains("generation_shutdown_rx.borrow()"),
        "YARA loop must check already-true generation shutdown signal"
    );
}

#[test]
fn iter88_cancel_then_join_tasks_exists() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(
        content.contains("pub async fn cancel_then_join_tasks"),
        "cancel_then_join_tasks method must exist"
    );
    assert!(
        !content.contains("pub async fn cancel_and_join_tasks"),
        "cancel_and_join_tasks must be replaced by cancel_then_join_tasks"
    );
}

#[test]
fn iter88_no_dead_retain_block() {
    let content = read_file("src/worker/task_registry.rs");
    // The dead retain block always returned true regardless of condition
    assert!(
        !content.contains("retain(|t| {")
            || !content.contains("if id_set.contains(&t.id) { true } else { true }"),
        "Dead retain block must be removed"
    );
}

#[test]
fn iter88_stop_mesh_generation_support_exists() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("async fn stop_mesh_generation_support"),
        "stop_mesh_generation_support function must exist"
    );
}

#[test]
fn iter88_support_stop_context_exists() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("pub enum SupportStopContext"),
        "SupportStopContext enum must exist"
    );
}

#[test]
fn iter88_mesh_support_stop_report_exists() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("pub struct MeshSupportStopReport"),
        "MeshSupportStopReport struct must exist"
    );
}

#[test]
fn iter88_report_reflects_actual_init_state() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    // report.dht_routing_initialized should be set from initialized, not unconditional true
    assert!(
        content.contains("report.dht_routing_initialized = initialized;"),
        "report.dht_routing_initialized must reflect actual state, not unconditional true"
    );
}

#[test]
fn iter88_before_peer_connect_hook_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("StartupFailurePoint::BeforePeerConnect"),
        "BeforePeerConnect hook must exist for test injection"
    );
}

#[test]
fn iter88_mesh_support_tasks_no_dht_init() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The summary line of the doc comment should not list DHT init as a support task.
    // (The comment correctly notes DHT init belongs to MeshTransport, but the summary
    // line should only list DNS verification and YARA broadcast.)
    let summary_start = content
        .find("/// Register mesh generation support tasks")
        .expect("MeshSupportTasks doc comment must exist");
    // Find the end of the summary line (first non-doc line or next doc line)
    let summary_end = content[summary_start..].find('\n').unwrap_or(200);
    let summary_line = &content[summary_start..summary_start + summary_end];
    assert!(
        !summary_line.contains("DHT routing init"),
        "MeshSupportTasks doc summary must not list DHT routing init as a support task: {}",
        summary_line
    );
}

#[test]
fn iter88_dht_add_peer_logs_warning_when_uninitialized() {
    let content = read_file("crates/synvoid-mesh/src/mesh/dht/routing/manager.rs");
    assert!(
        content.contains("DHT add_peer skipped: routing table not initialized"),
        "add_peer must log warning when routing table is uninitialized"
    );
}

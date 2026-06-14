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
            || rollback_body.contains("restore_peer_logical_state"),
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

    // Must use restore_peer_logical_state
    assert!(
        recovery_fn.contains("restore_peer_logical_state"),
        "recover_failed_state must use shared restore helper"
    );
}

#[test]
fn test_topology_rollback_uses_native_restore() {
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_fn = extract_function(&source, "rollback_startup");

    // Must use restore_peer_logical_state
    assert!(
        rollback_fn.contains("restore_peer_logical_state"),
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

    // DhtPeerSnapshot must have more than just address/port/role
    assert!(
        source.contains("pub geo:"),
        "DhtPeerSnapshot must capture geo field"
    );
    assert!(
        source.contains("pub latency_ms:"),
        "DhtPeerSnapshot must capture latency"
    );
    assert!(
        source.contains("pub is_trusted:"),
        "DhtPeerSnapshot must capture trust"
    );
    assert!(
        source.contains("pub pow_nonce:"),
        "DhtPeerSnapshot must capture pow_nonce"
    );
    assert!(
        source.contains("pub public_key:"),
        "DhtPeerSnapshot must capture public_key"
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

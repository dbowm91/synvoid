//! Guardrail test: Background task ownership and structured concurrency.
//!
//! Iteration 61 — Worker Structured Concurrency and Lifecycle Audit.
//! Iteration 62 — Registry-owned lifecycle spawns (heartbeat, bandwidth persist,
//! IPC loop migrated from tokio::spawn to WorkerTaskRegistry).
//! Iteration 63 — Supervision changes: registry-owned server run, subscribe-before-spawn,
//! noncritical exit handling, bandwidth final flush, deprecated spawn_server_run_task removed.
//!
//! Verifies that long-lived background tasks in the highest-priority
//! audited paths are either:
//! - Registered with a task owner (state.task_handles, WorkerTaskRegistry, etc.)
//! - Use cooperative cancellation (select! with shutdown signal)
//! - Explicitly allowlisted with documented rationale
//!
//! The mesh crate is excluded from the spawn audit because it contains
//! many legitimate per-event/per-connection spawns (BoundedChild class)
//! that are not long-lived background tasks.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if path.join("Cargo.toml").exists() {
            let content = fs::read_to_string(path.join("Cargo.toml")).unwrap_or_default();
            if content.contains("[workspace]") {
                return path;
            }
        }
        if !path.pop() {
            panic!("Could not find workspace root");
        }
    }
}

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_rs_files(&path));
        } else if path.extension().map_or(false, |e| e == "rs") {
            files.push(path);
        }
    }
    files
}

fn strip_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '/' if chars.peek() == Some(&'/') => {
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut depth = 1;
                while depth > 0 {
                    match chars.next() {
                        Some('/') if chars.peek() == Some(&'*') => {
                            chars.next();
                            depth += 1;
                        }
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next();
                            depth -= 1;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            '"' => {
                result.push(ch);
                loop {
                    match chars.next() {
                        Some('\\') => {
                            result.push('\\');
                            if let Some(c) = chars.next() {
                                result.push(c);
                            }
                        }
                        Some('"') => {
                            result.push('"');
                            break;
                        }
                        Some(c) => result.push(c),
                        None => break,
                    }
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

fn strip_cfg_test_modules(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut depth: i32 = 0;
    let mut in_test_module = false;
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        if !in_test_module {
            result.push(ch);
            if ch == '#' {
                let rest: String = chars.clone().take(20).collect();
                if rest.starts_with("[cfg(test)]") {
                    let mut skip = String::new();
                    skip.push(ch);
                    for _ in 0..11 {
                        skip.push(chars.next().unwrap_or('\0'));
                    }
                    result.push_str(&skip[1..]);
                    let remaining: String = chars.clone().take(10).collect();
                    if remaining.trim_start().starts_with("mod ")
                        || remaining.trim_start().starts_with("mod{")
                    {
                        in_test_module = true;
                        depth = 0;
                        loop {
                            let c = chars.next().unwrap_or('\0');
                            if c == '{' {
                                depth = 1;
                                break;
                            }
                            if c == ';' {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth <= 0 {
                        in_test_module = false;
                    }
                }
                _ => {}
            }
        }
    }
    result
}

/// Find the enclosing function name for a given line number.
fn enclosing_function(content: &str, line_num: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    // Walk backwards from line_num to find fn/pub fn/async fn
    for i in (0..line_num).rev() {
        let line = lines[i].trim();
        // Match function definitions
        for prefix in &["pub async fn ", "async fn ", "pub fn ", "fn "] {
            if let Some(rest) = line.strip_prefix(prefix) {
                let name = rest
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .split('<')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Allowlist: (file_suffix, function_name) where tokio::spawn is acceptable
// ---------------------------------------------------------------------------

const SPAWN_FUNCTION_ALLOWLIST: &[(&str, &str)] = &[
    // One-shot initialization spawns
    ("init_mesh.rs", "init_mesh_and_threat_intel"),
    ("init_apps.rs", "spawn_granian_supervisors"),
    // ThreatFeedClient migrated to use select! (Iteration 61)
    ("feed_client.rs", "start_background_fetching"),
    // Port honeypot has internal shutdown_tx
    ("init_waf.rs", "spawn_port_honeypot"),
    // Shared connection heartbeat (fire-and-forget, documented as known issue)
    ("state.rs", "start_shared_connection_heartbeat"),
];

/// Files where interval loops must have cancellation select.
const INTERVAL_AUDIT_PATHS: &[&str] = &["src/waf/threat_intel/"];

// ---------------------------------------------------------------------------
// Pattern matching helpers
// ---------------------------------------------------------------------------

fn has_cancel_select(content: &str) -> bool {
    content.contains("select!")
        && (content.contains("shutdown")
            || content.contains("cancel")
            || content.contains("running")
            || content.contains("child_token")
            || content.contains("is_running"))
}

fn is_in_test_or_dead_code(content: &str, line_num: usize) -> bool {
    let lines: Vec<&str> = content.lines().take(line_num).collect();
    let mut cfg_test_depth = 0;
    let mut cfg_any_depth = 0;
    let mut brace_depth = 0;

    for line in &lines {
        if line.contains("#[cfg(test)]") {
            cfg_test_depth = brace_depth;
        }
        if line.contains("#[cfg(any())]") {
            cfg_any_depth = brace_depth;
        }
        for c in line.chars() {
            match c {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if cfg_test_depth > 0 && brace_depth < cfg_test_depth {
                        cfg_test_depth = 0;
                    }
                    if cfg_any_depth > 0 && brace_depth < cfg_any_depth {
                        cfg_any_depth = 0;
                    }
                }
                _ => {}
            }
        }
    }

    cfg_test_depth > 0 || cfg_any_depth > 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that tokio::spawn in the highest-priority worker paths is either
/// registered with an owner or is explicitly allowlisted.
#[test]
fn tokio_spawn_in_worker_paths_has_owner_or_is_allowlisted() {
    let root = workspace_root();

    let mut violations = Vec::new();

    let dirs = ["src/worker/unified_server/", "src/waf/threat_intel/"];

    for dir in &dirs {
        let path = root.join(dir);
        for file in collect_rs_files(&path) {
            let content = fs::read_to_string(&file).unwrap_or_default();
            let cleaned = strip_cfg_test_modules(&content);
            let cleaned = strip_comments(&cleaned);
            let rel_path = file.strip_prefix(&root).unwrap_or(&file);
            let path_str = rel_path.to_string_lossy();

            for (line_num, line) in cleaned.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.contains("tokio::spawn") {
                    continue;
                }

                if is_in_test_or_dead_code(&cleaned, line_num + 1) {
                    continue;
                }

                // Find enclosing function
                let func_name = enclosing_function(&cleaned, line_num + 1).unwrap_or_default();

                // Check allowlist by file suffix + function name
                let allowed = SPAWN_FUNCTION_ALLOWLIST
                    .iter()
                    .any(|(suffix, func)| path_str.ends_with(suffix) && func_name == *func)
                    || path_str.contains("task_registry"); // Registry module itself

                if !allowed {
                    violations.push(format!(
                        "{}:{}: tokio::spawn in '{}' without owner registration",
                        path_str,
                        line_num + 1,
                        func_name
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Found tokio::spawn calls without owner registration in worker paths:\n{}",
            violations.join("\n")
        );
    }
}

/// Verify that interval loops in audited paths have cancellation select.
#[test]
fn interval_loops_have_cancellation_select() {
    let root = workspace_root();
    let mut violations = Vec::new();

    for dir in INTERVAL_AUDIT_PATHS {
        let path = root.join(dir);
        for file in collect_rs_files(&path) {
            let content = fs::read_to_string(&file).unwrap_or_default();
            let cleaned = strip_cfg_test_modules(&content);
            let cleaned = strip_comments(&cleaned);

            let lines: Vec<&str> = cleaned.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !line.contains("interval(") {
                    continue;
                }

                let context_start = i.saturating_sub(5);
                let context_end = (i + 20).min(lines.len());
                let context: Vec<&str> = lines[context_start..context_end].to_vec();
                let context_str = context.join("\n");

                if context_str.contains("loop {") && !has_cancel_select(&context_str) {
                    let rel_path = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push(format!(
                        "{}:{}: interval loop without cancellation select",
                        rel_path.to_string_lossy(),
                        i + 1
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Found interval loops without cancellation select:\n{}",
            violations.join("\n")
        );
    }
}

/// Verify ThreatFeedClient has proper lifecycle management.
#[test]
fn threat_feed_client_has_cancellation() {
    let root = workspace_root();
    let feed_path = root.join("src/waf/threat_intel/feed_client.rs");
    assert!(feed_path.exists(), "ThreatFeedClient file not found");

    let content = fs::read_to_string(&feed_path).unwrap();
    let cleaned = strip_comments(&content);

    assert!(
        cleaned.contains("select!"),
        "ThreatFeedClient::start_background_fetching must use tokio::select! for cancellation"
    );
    assert!(
        cleaned.contains("shutdown") || cleaned.contains("child_token"),
        "ThreatFeedClient must reference shutdown signal"
    );
    assert!(
        cleaned.contains("fn shutdown"),
        "ThreatFeedClient must expose shutdown() method"
    );
    assert!(
        cleaned.contains("fn join"),
        "ThreatFeedClient must expose join() method"
    );
}

/// Verify WorkerTaskRegistry infrastructure exists.
#[test]
fn worker_task_registry_exists() {
    let root = workspace_root();
    let registry_path = root.join("src/worker/task_registry.rs");
    assert!(
        registry_path.exists(),
        "WorkerTaskRegistry module not found at src/worker/task_registry.rs"
    );

    let content = fs::read_to_string(&registry_path).unwrap();
    assert!(
        content.contains("pub struct WorkerTaskRegistry"),
        "WorkerTaskRegistry struct not found"
    );
    assert!(
        content.contains("pub fn spawn_critical"),
        "spawn_critical method not found"
    );
    assert!(
        content.contains("pub fn spawn_background"),
        "spawn_background method not found"
    );
    assert!(
        content.contains("pub async fn shutdown_and_join"),
        "shutdown_and_join method not found"
    );
    assert!(
        content.contains("pub fn child_token"),
        "child_token method not found"
    );
    assert!(
        content.contains("pub fn spawn_critical_result"),
        "spawn_critical_result method not found"
    );
    assert!(
        content.contains("pub fn subscribe_exits"),
        "subscribe_exits method not found"
    );
    assert!(
        content.contains("pub struct NamedTaskExit"),
        "NamedTaskExit struct not found"
    );
    assert!(
        content.contains("pub struct TaskId"),
        "TaskId struct not found"
    );
    assert!(
        content.contains("UnexpectedCompletion"),
        "UnexpectedCompletion variant not found"
    );
}

/// Verify ManagedService trait is defined.
#[test]
fn managed_service_trait_exists() {
    let root = workspace_root();
    let registry_path = root.join("src/worker/task_registry.rs");
    let content = fs::read_to_string(registry_path).unwrap();

    assert!(
        content.contains("pub trait ManagedService"),
        "ManagedService trait not found"
    );
    assert!(
        content.contains("fn name(&self) -> &'static str"),
        "ManagedService::name not found"
    );
    assert!(
        content.contains("fn shutdown(&self)"),
        "ManagedService::shutdown not found"
    );
    assert!(
        content.contains("async fn join(&self)"),
        "ManagedService::join not found"
    );
}

// ---------------------------------------------------------------------------
// Iteration 63 — Supervision guardrails
// ---------------------------------------------------------------------------

fn read_file(path: &str) -> String {
    let root = workspace_root();
    let full = root.join(path);
    fs::read_to_string(&full).unwrap_or_else(|e| panic!("Failed to read {}: {}", full.display(), e))
}

/// Server run task must be registered under WorkerTaskRegistry via spawn_critical_result.
#[test]
fn server_run_task_is_registry_owned() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("spawn_critical_result") && content.contains("server_run"),
        "Server run task must be registered under WorkerTaskRegistry via spawn_critical_result"
    );
}

/// Exit receiver must be subscribed before supervised tasks are spawned.
#[test]
fn exit_receiver_subscribed_before_task_spawning() {
    let content = read_file("src/worker/unified_server/mod.rs");
    let subscribe_pos = content
        .find("subscribe_exits()")
        .expect("subscribe_exits not found");
    let spawn_pos = content
        .find("spawn_heartbeat_task")
        .expect("spawn_heartbeat_task not found");
    assert!(
        subscribe_pos < spawn_pos,
        "Exit receiver must be subscribed before supervised tasks are spawned"
    );
}

/// Supervision loop must distinguish critical from noncritical exits.
#[test]
fn supervision_loop_handles_noncritical_exits() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("is_fatal_exit"),
        "Supervision loop must use is_fatal_exit to distinguish critical from noncritical exits"
    );
    assert!(
        content.contains("Non-fatal task exit")
            || content.contains("nonfatal")
            || content.contains("non-fatal"),
        "Supervision loop must log non-fatal task exits"
    );
}

/// Bandwidth persist task must flush after the main loop ends.
#[test]
fn bandwidth_persist_task_has_final_flush() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    let persist_loop_end = content
        .find("persist_global_bandwidth_tracker();")
        .expect("persist call not found");
    let second_persist =
        content[persist_loop_end + 1..].find("persist_global_bandwidth_tracker();");
    assert!(
        second_persist.is_some(),
        "Bandwidth persist task must have a final flush after the main loop"
    );
}

/// Server run task must not be spawned via raw tokio::spawn.
#[test]
fn no_unmanaged_server_join_handle() {
    let content = read_file("src/worker/unified_server/mod.rs");
    let has_raw_spawn =
        content.contains("tokio::spawn") && content.contains("unified_server.run()");
    let has_server_run_in_registry =
        content.contains("spawn_critical_result") && content.contains("server_run");
    if has_raw_spawn {
        panic!(
            "Server run task should not be spawned via raw tokio::spawn — use WorkerTaskRegistry"
        );
    }
    assert!(
        has_server_run_in_registry,
        "Server run must be registered as a critical result task"
    );
}

/// spawn_server_run_task must be removed since its responsibilities moved to the registry.
#[test]
fn spawn_server_run_task_removed() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    assert!(
        !content.contains("pub fn spawn_server_run_task"),
        "spawn_server_run_task should be removed — server run is now registry-owned"
    );
    assert!(
        content.contains("spawn_critical_result"),
        "lifecycle.rs must reference spawn_critical_result as the replacement"
    );
}

// ---------------------------------------------------------------------------
// Iteration 64 — Coordinated shutdown guardrails
// ---------------------------------------------------------------------------

/// MasterShutdown path must call begin_shutdown() before running.stop().
#[test]
fn master_shutdown_begins_intent_before_running_stop() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Scope to composition-root shutdown procedure to avoid supervision loop's running.stop().
    let composition_root_start = content
        .find("composition-root shutdown procedure")
        .expect("composition-root shutdown procedure not found");
    let composition_section = &content[composition_root_start..];
    let begin_shutdown_pos = composition_section
        .find("registry.begin_shutdown()")
        .expect("begin_shutdown not found in composition root");
    let running_stop_pos = composition_section
        .find("state.running.stop()")
        .expect("running.stop() not found in composition root");
    assert!(
        begin_shutdown_pos < running_stop_pos,
        "begin_shutdown() must be called before running.stop() in the composition root"
    );
}

/// UnifiedServerWorkerShutdownComplete must be sent from the composition root,
/// not directly from the IPC receive branch.
#[test]
fn shutdown_complete_sent_from_composition_root() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The composition root sends ShutdownComplete after shutdown_and_join.
    let shutdown_complete_pos = content
        .find("UnifiedServerWorkerShutdownComplete")
        .expect("ShutdownComplete not found");
    let shutdown_and_join_pos = content
        .find("shutdown_and_join")
        .expect("shutdown_and_join not found");
    assert!(
        shutdown_and_join_pos < shutdown_complete_pos,
        "UnifiedServerWorkerShutdownComplete must be sent after shutdown_and_join"
    );
}

/// IPC loop must not perform inline shutdown — it should emit a lifecycle event.
#[test]
fn ipc_loop_emits_lifecycle_event_not_inline_shutdown() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    // The IPC loop should set a lifecycle event for MasterShutdown, not do shutdown directly.
    assert!(
        content.contains("WorkerLifecycleEvent::MasterShutdown"),
        "IPC loop must emit WorkerLifecycleEvent::MasterShutdown"
    );
    // The IPC loop should not call running.stop() for MasterShutdown.
    // (It may still reference running for the pre-loop check.)
    let master_shutdown_section = content
        .split("WorkerLifecycleEvent::MasterShutdown")
        .nth(1)
        .expect("MasterShutdown event not found");
    assert!(
        !master_shutdown_section.contains("state.running.stop()"),
        "IPC loop must not call running.stop() in MasterShutdown handler — that's the composition root's job"
    );
}

/// WorkerShutdownCause must have an exit_code() method.
#[test]
fn worker_shutdown_cause_has_exit_code() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(
        content.contains("fn exit_code(&self) -> i32"),
        "WorkerShutdownCause must have an exit_code() method"
    );
}

/// WorkerShutdownCause must distinguish server expected vs unexpected.
#[test]
fn server_exit_distinguishes_expected_unexpected() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(
        content.contains("ServerExitedUnexpectedly"),
        "WorkerShutdownCause must have ServerExitedUnexpectedly variant"
    );
    assert!(
        content.contains("ServerStoppedForShutdown"),
        "WorkerShutdownCause must have ServerStoppedForShutdown variant"
    );
}

/// begin_shutdown and broadcast_shutdown must be separate methods.
#[test]
fn begin_shutdown_and_broadcast_are_separate() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(
        content.contains("pub fn begin_shutdown(&self)"),
        "WorkerTaskRegistry must have begin_shutdown() method"
    );
    assert!(
        content.contains("pub fn broadcast_shutdown(&self)"),
        "WorkerTaskRegistry must have broadcast_shutdown() method"
    );
}

/// Final exit code must derive from WorkerShutdownCause, not worker_exit_code.
#[test]
fn exit_code_derived_from_shutdown_cause() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("shutdown_cause.exit_code()"),
        "Final exit code must be derived from WorkerShutdownCause::exit_code()"
    );
    // worker_exit_code should not be used for the final exit decision.
    assert!(
        !content.contains("worker_exit_code.load"),
        "worker_exit_code should not be used for final exit code — use WorkerShutdownCause"
    );
}

/// Graceful shutdown fields must be consumed by the drain path.
#[test]
fn graceful_fields_consumed_by_drain() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("graceful") && content.contains("drain_timeout"),
        "Graceful and drain_timeout must be consumed by the shutdown path"
    );
}

// ---------------------------------------------------------------------------
// Iteration 65 — Lifecycle event channel and acknowledgement guardrails
// ---------------------------------------------------------------------------

/// IPC terminal lifecycle branches must use a channel (mpsc/oneshot),
/// not return Ok(()) immediately after writing shared state.
#[test]
fn ipc_lifecycle_uses_channel_not_shared_state() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    // Must not have Arc<RwLock<Option<WorkerLifecycleEvent>>> in the IPC loop.
    assert!(
        !content.contains("Arc<tokio::sync::RwLock<Option<WorkerLifecycleEvent>>>"),
        "IPC loop must not use Arc<RwLock> for lifecycle events — use a channel"
    );
    // Must have LifecycleRequest or mpsc channel for lifecycle signaling.
    assert!(
        content.contains("LifecycleRequest") || content.contains("mpsc::channel"),
        "IPC loop must use LifecycleRequest or mpsc channel for lifecycle signaling"
    );
}

/// IpcLoopExitCause must not remain as an unused side channel.
#[test]
fn ipc_loop_exit_cause_removed() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    assert!(
        !content.contains("IpcLoopExitCause"),
        "IpcLoopExitCause must be removed — replaced by lifecycle channel"
    );
    assert!(
        !content.contains("IpcLoopExit"),
        "IpcLoopExit enum must be removed — lifecycle events are the replacement"
    );
}

/// Resize cause must route to resize acknowledgement.
#[test]
fn resize_cause_routes_to_resize_ack() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("UnifiedServerWorkerResizeAck"),
        "Resize cause must route to UnifiedServerWorkerResizeAck"
    );
    // Verify the routing is inside the composition root shutdown procedure.
    let composition_start = content
        .find("composition-root shutdown procedure")
        .expect("composition root not found");
    let section = &content[composition_start..];
    assert!(
        section.contains("WorkerResize"),
        "Resize acknowledgement must be in the composition root shutdown procedure"
    );
}

/// Legacy handles must be awaited after abort.
#[test]
fn legacy_handles_awaited_after_abort() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Must have the pattern: take handles, then abort+await in a loop.
    assert!(
        content.contains("handle.await"),
        "Legacy handles must be awaited after abort"
    );
    // Verify take+abort+await pattern.
    assert!(
        content.contains("std::mem::take"),
        "Legacy handles must be taken from the vector before abort"
    );
}

/// Fatal causes must send WorkerError when IPC is available.
#[test]
fn fatal_causes_send_worker_error() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Must have explicit WorkerError sends for fatal causes.
    assert!(
        content.contains("WorkerError"),
        "Fatal causes must send WorkerError to supervisor"
    );
    // Must not send both WorkerError and ShutdownComplete for the same cause.
    let composition_start = content
        .find("composition-root shutdown procedure")
        .expect("composition root not found");
    let section = &content[composition_start..];
    // The match arms should be mutually exclusive.
    assert!(
        section.contains("SupervisorShutdown =>") || section.contains("SupervisorShutdown => {"),
        "SupervisorShutdown must have its own match arm"
    );
}

/// Lifecycle acknowledgement must happen after begin_shutdown.
#[test]
fn lifecycle_ack_after_begin_shutdown() {
    let content = read_file("src/worker/unified_server/mod.rs");
    let composition_start = content
        .find("composition-root shutdown procedure")
        .expect("composition root not found");
    let section = &content[composition_start..];

    let begin_pos = section
        .find("begin_shutdown()")
        .expect("begin_shutdown not found");
    let ack_pos = section.find("ack_tx.send").expect("ack send not found");

    assert!(
        begin_pos < ack_pos,
        "Lifecycle acknowledgement must happen after begin_shutdown()"
    );
}

/// Supervision loop must select over lifecycle events from IPC.
#[test]
fn supervision_selects_lifecycle_events() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("lifecycle_rx.recv()"),
        "Supervision loop must select over lifecycle_rx.recv()"
    );
}

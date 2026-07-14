//! Static guards for task ownership, lifecycle, and CLI dispatch.
//!
//! Ensures background tasks have registered owners, spawns have reason comments,
//! no `mem::forget` is used for plugin lifecycles, and CLI dispatch is thin.

use synvoid_repo_guards::{prepare_for_scanning, workspace_root, Violations};

// ---------------------------------------------------------------------------
// background_task_ownership_guard
// ---------------------------------------------------------------------------

/// Directories to audit for background spawns (matching original guard scope).
const SPAWN_AUDIT_DIRS: &[&str] = &["src/worker/unified_server/", "src/waf/threat_intel/"];

/// Known (file_suffix, function_name) pairs where tokio::spawn is acceptable.
const SPAWN_FUNCTION_ALLOWLIST: &[(&str, &str)] = &[
    ("init_mesh.rs", "init_mesh_and_threat_intel"),
    ("init_apps.rs", "spawn_granian_supervisors"),
    ("feed_client.rs", "start_background_fetching"),
    ("init_waf.rs", "spawn_port_honeypot"),
    ("state.rs", "start_shared_connection_heartbeat"),
    ("mod.rs", "register_mesh_generation_support"),
];

#[test]
fn background_spawns_are_registered_or_documented() {
    let repo = workspace_root();
    let mut violations = Violations::new();

    for dir in SPAWN_AUDIT_DIRS {
        let full_dir = repo.join(dir);
        let files = synvoid_repo_guards::collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            let content = std::fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("tokio::spawn") || trimmed.contains("spawn_blocking") {
                    let file_name = std::path::Path::new(&rel_str)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    let is_allowlisted =
                        SPAWN_FUNCTION_ALLOWLIST.iter().any(|(file_suffix, func)| {
                            file_name.contains(file_suffix)
                                && (func.is_empty() || scanned.contains(func))
                        });

                    let recent: Vec<&str> = scanned.lines().take(line_no + 1).collect();
                    let has_reason = recent
                        .into_iter()
                        .rev()
                        .take(3)
                        .any(|l| l.contains("// reason:") || l.contains("// owner:"));

                    let is_registry = rel_str.contains("task_registry");

                    if !has_reason && !is_allowlisted && !is_registry {
                        violations.push(format!(
                            "{}:{}: tokio::spawn without '// reason:' or '// owner:' comment",
                            rel_str,
                            line_no + 1
                        ));
                    }
                }
            }
        }
    }

    violations.assert_ok("background_task_ownership_guard");
}

// ---------------------------------------------------------------------------
// supervisor_task_ownership_guard
// ---------------------------------------------------------------------------

/// Approved (file, function) pairs under src/supervisor/.
const SUPERVISOR_SPAWN_ALLOWLIST: &[(&str, &str)] = &[
    ("task_registry.rs", ""),
    ("process.rs", "run"),
    ("process.rs", "run_supervisor_ipc_accept_loop"),
    ("process.rs", "run_supervisor_control_api_task"),
    ("api.rs", "stop"),
    ("mesh.rs", ""),
    ("ipc.rs", "handle_worker_connection_internal"),
];

/// Files where any function may contain tokio::spawn.
const SUPERVISOR_FULLY_ALLOWLISTED: &[&str] =
    &["src/supervisor/task_registry.rs", "src/supervisor/mesh.rs"];

#[test]
fn supervisor_spawns_have_ownership() {
    let repo = workspace_root();
    let supervisor_dirs = &["src/supervisor/"];
    let mut violations = Violations::new();

    for dir in supervisor_dirs {
        let full_dir = repo.join(dir);
        let files = synvoid_repo_guards::collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            // Skip fully allowlisted files
            if SUPERVISOR_FULLY_ALLOWLISTED
                .iter()
                .any(|e| rel_str.contains(e))
            {
                continue;
            }

            let content = std::fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.contains("tokio::spawn") {
                    let file_name = std::path::Path::new(&rel_str)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    let is_allowlisted =
                        SUPERVISOR_SPAWN_ALLOWLIST
                            .iter()
                            .any(|(file_suffix, func)| {
                                file_name.contains(file_suffix)
                                    && (func.is_empty() || scanned.contains(func))
                            });

                    if !is_allowlisted {
                        let recent: Vec<&str> = scanned.lines().take(line_no + 1).collect();
                        let has_owner = recent.into_iter().rev().take(3).any(|l| {
                            l.contains("// reason:")
                                || l.contains("// owner:")
                                || l.contains("task_registry")
                        });

                        if !has_owner {
                            violations.push(format!(
                                "{}:{}: supervisor spawn without registered owner",
                                rel_str,
                                line_no + 1
                            ));
                        }
                    }
                }
            }
        }
    }

    violations.assert_ok("supervisor_task_ownership_guard");
}

// ---------------------------------------------------------------------------
// unified_server_lifecycle_ownership_guard
// ---------------------------------------------------------------------------

#[test]
fn no_memforget_in_lifecycle_code() {
    let repo = workspace_root();
    let lifecycle_dirs = &["src/server/", "src/plugin/"];
    let mut violations = Violations::new();

    for dir in lifecycle_dirs {
        let full_dir = repo.join(dir);
        let files = synvoid_repo_guards::collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            let content = std::fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.contains("mem::forget") || trimmed.contains("std::mem::forget") {
                    let recent: Vec<&str> = scanned.lines().take(line_no + 1).collect();
                    let has_reason = recent
                        .into_iter()
                        .rev()
                        .take(3)
                        .any(|l| l.contains("// reason:"));

                    if !has_reason {
                        violations.push(format!(
                            "{}:{}: mem::forget without '// reason:' comment",
                            rel_str,
                            line_no + 1
                        ));
                    }
                }
            }
        }
    }

    violations.assert_ok("unified_server_lifecycle_ownership_guard: no mem::forget without reason");
}

// ---------------------------------------------------------------------------
// unified_worker_composition_root_guard
// ---------------------------------------------------------------------------

#[test]
fn run_unified_server_worker_remains_thin() {
    let repo = workspace_root();
    let mod_file = repo.join("src/worker/unified_server/mod.rs");
    let source = std::fs::read_to_string(&mod_file).expect("read unified_server/mod.rs");

    // Extract run_unified_server_worker body
    let start = source
        .find("pub async fn run_unified_server_worker")
        .expect("run_unified_server_worker function exists");
    let body = &source[start..];
    let end = body
        .lines()
        .enumerate()
        .find(|(_, line)| {
            line.starts_with("#[cfg(test)]")
                || (line.trim() == "}" && !line.starts_with(' ') && !line.starts_with('\t'))
        })
        .map(|(i, _)| i)
        .unwrap_or(0);
    let function: String = body.lines().take(end).collect::<Vec<&str>>().join("\n");
    let line_count = function.lines().count();

    assert!(
        line_count <= 80,
        "run_unified_server_worker should stay thin; found {} lines (threshold: 80)",
        line_count
    );
    assert!(
        !function.contains("match supervision_result.outcome"),
        "run_unified_server_worker must not map supervision outcome inline"
    );
}

// ---------------------------------------------------------------------------
// cli_command_dispatch_guard
// ---------------------------------------------------------------------------

#[test]
fn main_rs_is_thin_dispatch() {
    let repo = workspace_root();
    let main_rs = repo.join("src/main.rs");
    let content = std::fs::read_to_string(&main_rs).expect("read main.rs");
    let scanned = prepare_for_scanning(&content);

    let non_empty: Vec<&str> = scanned.lines().filter(|l| !l.trim().is_empty()).collect();

    assert!(
        non_empty.len() <= 50,
        "src/main.rs has {} non-empty lines after stripping comments/blank lines (target ≤50).\n\
         CLI dispatch should delegate to src/commands/ modules.",
        non_empty.len()
    );

    // Check that main.rs does not contain business logic patterns
    let has_forbidden = scanned.lines().any(|l| {
        let t = l.trim();
        t.contains("BlockStore::new")
            || t.contains("ThreatIntelligenceManager::new")
            || t.contains("start_server")
            || t.contains("bind(")
    });

    assert!(
        !has_forbidden,
        "src/main.rs contains business logic (server startup, store creation, etc.).\n\
         CLI dispatch should delegate to src/commands/ modules."
    );
}

//! Guardrail test: Supervisor task ownership and structured concurrency.
//!
//! Scans `src/supervisor/` for `tokio::spawn` calls and ensures they are only
//! in approved locations. The supervisor is the process-lifecycle owner; raw
//! spawns outside of allowlisted functions indicate unregistered background work
//! that will not be tracked or cleanly shut down.
//!
//! Pattern mirrors tests/background_task_ownership_guard.rs (worker-side equivalent).

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
        } else if path.extension().is_some_and(|e| e == "rs") {
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

/// Strip `#[cfg(test)] mod tests { ... }` blocks so test-only spawns are ignored.
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
                    loop {
                        let remaining: String = chars.clone().take(20).collect();
                        let trimmed = remaining.trim_start();
                        if trimmed.starts_with("#[") {
                            for c in chars.by_ref() {
                                if c == ']' {
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
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
    for i in (0..line_num).rev() {
        let line = lines[i].trim();
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

fn is_in_test_or_dead_code(content: &str, line_num: usize) -> bool {
    let lines: Vec<&str> = content.lines().take(line_num).collect();
    let mut cfg_test_depth: i32 = -1;
    let mut cfg_any_depth: i32 = -1;
    let mut brace_depth: i32 = 0;

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
                    if cfg_test_depth >= 0 && brace_depth <= cfg_test_depth {
                        cfg_test_depth = -1;
                    }
                    if cfg_any_depth >= 0 && brace_depth <= cfg_any_depth {
                        cfg_any_depth = -1;
                    }
                }
                _ => {}
            }
        }
    }

    cfg_test_depth >= 0 || cfg_any_depth >= 0
}

// ---------------------------------------------------------------------------
// Supervisor spawn allowlist
// ---------------------------------------------------------------------------

/// Approved (file, function) pairs where `tokio::spawn` is permitted.
const SPAWN_FUNCTION_ALLOWLIST: &[(&str, &str)] = &[
    // --- src/supervisor/task_registry.rs ---
    // Task registration internals; test code also uses tokio::spawn.
    ("task_registry.rs", ""),
    // --- src/supervisor/process.rs ---
    // Registry registration spawns (spawn task + register with SupervisorTaskRegistry).
    ("process.rs", "run"),
    // Per-connection IPC accept loop handlers.
    ("process.rs", "run_supervisor_ipc_accept_loop"),
    // Control API server task.
    ("process.rs", "run_supervisor_control_api_task"),
    // --- src/supervisor/api.rs ---
    // Delayed shutdown trigger — short-lived utility spawn.
    ("api.rs", "stop"),
    // --- src/supervisor/mesh.rs ---
    // Mesh topology/DHT background tasks — documented exception, not yet
    // integrated into registry.
    ("mesh.rs", ""),
    // --- src/supervisor/ipc.rs ---
    // Per-connection handler — short-lived cert-reload broadcast utility spawn.
    ("ipc.rs", "handle_worker_connection_internal"),
];

/// Files that are fully allowlisted (any function may contain tokio::spawn).
const FULLY_ALLOWLISTED_FILES: &[&str] = &[
    "src/supervisor/task_registry.rs", // task registration internals + tests
    "src/supervisor/mesh.rs",          // documented mesh exception
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Scan all `.rs` files under `src/supervisor/` and verify every `tokio::spawn`
/// call is either in an approved file+function pair or in dead/test code.
#[test]
fn supervisor_tokio_spawns_are_allowlisted() {
    let root = workspace_root();
    let supervisor_dir = root.join("src/supervisor");
    let files = collect_rs_files(&supervisor_dir);

    assert!(
        !files.is_empty(),
        "No .rs files found under src/supervisor/ — is the directory present?"
    );

    let mut violations = Vec::new();

    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let cleaned = strip_cfg_test_modules(&content);
        let cleaned = strip_comments(&cleaned);
        let rel_path = file.strip_prefix(&root).unwrap_or(file);
        let path_str = rel_path.to_string_lossy();

        for (line_num, line) in cleaned.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.contains("tokio::spawn") {
                continue;
            }

            if is_in_test_or_dead_code(&cleaned, line_num + 1) {
                continue;
            }

            let func_name = enclosing_function(&cleaned, line_num + 1).unwrap_or_default();

            // Check: fully allowlisted file (any function)?
            let fully_allowed = FULLY_ALLOWLISTED_FILES
                .iter()
                .any(|suffix| path_str.ends_with(suffix));

            if fully_allowed {
                continue;
            }

            // Check: file + function pair in allowlist?
            let allowed = SPAWN_FUNCTION_ALLOWLIST.iter().any(|(suffix, func)| {
                path_str.ends_with(suffix) && (func.is_empty() || func_name == *func)
            });

            if !allowed {
                violations.push(format!(
                    "{}:{}: unapproved tokio::spawn in '{}' — add to allowlist or migrate to registry",
                    path_str,
                    line_num + 1,
                    func_name,
                ));
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "Found unapproved tokio::spawn calls in supervisor paths:\n{}",
            violations.join("\n")
        );
    }
}

/// Verify that every file+function pair in `SPAWN_FUNCTION_ALLOWLIST` actually
/// exists in the codebase. Stale entries silently permit regressions.
#[test]
fn spawn_allowlist_entries_are_live() {
    let root = workspace_root();
    let supervisor_dir = root.join("src/supervisor");

    for (file_suffix, func_name) in SPAWN_FUNCTION_ALLOWLIST {
        // Find the file
        let matching_files: Vec<PathBuf> = collect_rs_files(&supervisor_dir)
            .iter()
            .filter(|p| p.to_string_lossy().ends_with(file_suffix))
            .cloned()
            .collect();

        assert!(
            !matching_files.is_empty(),
            "SPAWN_FUNCTION_ALLOWLIST file suffix '{}' matches no files under src/supervisor/ — \
             entry is stale",
            file_suffix
        );

        // If a function name is specified, verify it exists in the file
        if !func_name.is_empty() {
            let content = fs::read_to_string(&matching_files[0]).unwrap_or_default();
            let cleaned = strip_comments(&content);
            let func_pattern = format!("fn {}(", func_name);
            assert!(
                cleaned.contains(&func_pattern),
                "SPAWN_FUNCTION_ALLOWLIST function '{}' not found in '{}' — \
                 entry is stale or function was renamed",
                func_name,
                file_suffix
            );
        }
    }
}

/// Verify that every file in `FULLY_ALLOWLISTED_FILES` actually exists.
#[test]
fn fully_allowlisted_files_are_live() {
    let root = workspace_root();
    let supervisor_dir = root.join("src/supervisor");
    let all_files = collect_rs_files(&supervisor_dir);

    for file_suffix in FULLY_ALLOWLISTED_FILES {
        let exists = all_files
            .iter()
            .any(|p| p.to_string_lossy().ends_with(file_suffix));
        assert!(
            exists,
            "FULLY_ALLOWLISTED_FILES entry '{}' matches no files under src/supervisor/ — \
             entry is stale",
            file_suffix
        );
    }
}

/// Verify that `process.rs` does NOT bare-spawn tasks inside the main `run()` body.
/// Tasks should be registered, not spawned ad-hoc.
#[test]
fn process_run_method_has_no_bare_spawns() {
    let root = workspace_root();
    let path = root.join("src/supervisor/process.rs");
    if !path.exists() {
        eprintln!("skipping: src/supervisor/process.rs not found");
        return;
    }

    let content = fs::read_to_string(&path).unwrap();
    let cleaned = strip_comments(&content);

    // Find the main `pub fn run()` or `pub async fn run()` function.
    let run_start = cleaned
        .find("pub fn run(")
        .or_else(|| cleaned.find("pub async fn run("));
    let Some(start) = run_start else {
        eprintln!("skipping: no pub fn run() found in process.rs");
        return;
    };

    // Extract the function body by matching braces.
    let mut brace_depth = 0;
    let mut found_open = false;
    let mut run_body = String::new();
    for ch in cleaned[start..].chars() {
        match ch {
            '{' => {
                brace_depth += 1;
                found_open = true;
                run_body.push(ch);
            }
            '}' => {
                brace_depth -= 1;
                run_body.push(ch);
                if found_open && brace_depth == 0 {
                    break;
                }
            }
            _ => {
                run_body.push(ch);
            }
        }
    }

    // Allowed function names that may be called via tokio::spawn inside run().
    // These are the registered task entry points — the spawn is followed by
    // supervisor_tasks.register() on the next line.
    let allowed_spawn_targets = [
        "run_supervisor_ipc_accept_loop",
        "run_supervisor_control_api_task",
    ];

    let bare_spawns: Vec<_> = run_body
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("tokio::spawn"))
        .filter(|(_, l)| {
            // Allow spawns that call registered task functions (registry pattern:
            // tokio::spawn(function_call) followed by supervisor_tasks.register()).
            !allowed_spawn_targets.iter().any(|name| l.contains(name))
        })
        .map(|(i, _)| i + 1)
        .collect();

    assert!(
        bare_spawns.is_empty(),
        "src/supervisor/process.rs run() contains bare tokio::spawn at relative lines {:?} \
         — tasks must be registered via the task registry, not spawned ad-hoc",
        bare_spawns,
    );
}

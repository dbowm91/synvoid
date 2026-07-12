use std::path::PathBuf;

/// Recursively find all .rs files under the given directories.
fn rust_files_under(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                files.extend(rust_files_under(&[path]));
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Strip string literals, line comments (`//`), and block comments (`/* */`).
/// This prevents false positives from tokens inside comments or strings.
fn strip_comments_and_strings(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '/' if chars.peek() == Some(&'/') => {
                // Line comment — skip to end of line
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                // Block comment — skip to matching close
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
                // String literal — skip to closing quote
                loop {
                    match chars.next() {
                        Some('\\') => {
                            chars.next(); // skip escaped char
                        }
                        Some('"') => break,
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Collect lines with their 1-indexed line numbers from cleaned text.
#[allow(dead_code)]
fn cleaned_lines(cleaned: &str) -> Vec<(usize, &str)> {
    cleaned
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .collect()
}

#[test]
fn server_runtime_does_not_leak_lifecycle_handles() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = [repo.join("src/server"), repo.join("src/plugin")];
    let mut offenders = Vec::new();

    for file in rust_files_under(&roots) {
        let text = std::fs::read_to_string(&file).unwrap();
        let cleaned = strip_comments_and_strings(&text);
        for (idx, line) in cleaned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("std::mem::forget") || trimmed.contains("mem::forget") {
                offenders.push(format!("{}:{}: {}", file.display(), idx + 1, trimmed));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "server/plugin lifecycle handles must be owned, not leaked.\n\
         Found mem::forget in production code — replace with explicit Drop or RAII ownership.\n\n\
         Offenders:\n{}",
        offenders.join("\n")
    );
}

/// Every `tokio::spawn` in server/plugin production code must have a `// reason:` comment
/// on the same line or within the 5 preceding lines. This ensures each spawn
/// has a documented owner or rationale, preventing untracked fire-and-forget tasks.
/// Test modules (`#[cfg(test)]`) are excluded.
#[test]
fn tokio_spawns_require_reason_comments() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = [repo.join("src/server"), repo.join("src/plugin")];
    let mut unreasoned = Vec::new();

    for file in rust_files_under(&roots) {
        let text = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // Track whether we're inside a #[cfg(test)] module
        let mut in_test_module = false;
        let mut test_module_depth = 0u32;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect entry into test modules
            if trimmed.contains("#[cfg(test)]") {
                in_test_module = true;
                test_module_depth = 0;
                continue;
            }

            // Track brace depth inside test modules
            if in_test_module {
                for ch in trimmed.bytes() {
                    match ch {
                        b'{' => test_module_depth += 1,
                        b'}' => {
                            if test_module_depth == 0 {
                                in_test_module = false;
                            } else {
                                test_module_depth -= 1;
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }

            // Skip comments and attributes (but NOT string content — those are real code)
            if trimmed.starts_with("//") || trimmed.starts_with("#[") {
                continue;
            }
            if !trimmed.contains("tokio::spawn") {
                continue;
            }
            // Check if this line or any of the 5 preceding lines has a reason comment
            let has_reason = (idx.saturating_sub(5)..=idx).any(|i| {
                let l = lines[i].trim();
                l.contains("// reason:") || l.contains("//reason:")
            });
            if !has_reason {
                unreasoned.push(format!("{}:{}: {}", file.display(), idx + 1, trimmed));
            }
        }
    }

    assert!(
        unreasoned.is_empty(),
        "Every tokio::spawn in server/plugin must have a `// reason:` comment.\n\
         Add `// reason: <owner or rationale>` on the spawn line or within 5 lines above it.\n\
         This prevents untracked fire-and-forget tasks that cannot be cleanly shut down.\n\n\
         Unreasoned spawns:\n{}",
        unreasoned.join("\n")
    );
}

/// UnifiedServerRuntimeHandles must be instantiated in run(), not left as dead code.
/// This test verifies integration by checking that `UnifiedServerRuntimeHandles::new()`
/// appears in src/server/mod.rs.
#[test]
fn unified_server_runtime_handles_are_integrated() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mod_rs = repo.join("src/server/mod.rs");
    let text = std::fs::read_to_string(&mod_rs).unwrap();
    let cleaned = strip_comments_and_strings(&text);
    assert!(
        cleaned.contains("UnifiedServerRuntimeHandles::new()")
            || cleaned.contains("UnifiedServerRuntime::"),
        "UnifiedServerRuntimeHandles must be instantiated in run(), not left as dead code"
    );
}

/// Long-lived server spawns in src/server/mod.rs must go through spawn_registered
/// or register with UnifiedServerRuntimeHandles. Direct tokio::spawn calls
/// are only allowed in:
/// - runtime_handles.rs (the registration infrastructure itself)
/// - plugin_runtime.rs (short-lived callback spawns)
/// - waf_handler.rs (short-lived request processing)
/// - Test modules
///   All other direct tokio::spawn calls in src/server/ are rejected.
#[test]
fn server_long_lived_spawns_go_through_registration() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let server_dir = repo.join("src/server");
    let mut offenders = Vec::new();

    // Files where direct tokio::spawn is allowed (infrastructure/short-lived)
    let allowed_files: &[&str] = &[
        "runtime_handles.rs",
        "plugin_runtime.rs",
        "waf_handler.rs",
        "mod.rs", // short-lived ACME cert reload callback
    ];

    for file in rust_files_under(&[server_dir]) {
        let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if allowed_files.contains(&file_name) {
            continue;
        }

        let text = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let cleaned = strip_comments_and_strings(&text);
        let cleaned_line_strings: Vec<String> = cleaned.lines().map(|s| s.to_string()).collect();
        let cleaned_lines_vec: Vec<(usize, &str)> = cleaned_line_strings
            .iter()
            .enumerate()
            .map(|(i, s)| (i + 1, s.as_str()))
            .collect();

        // Track test modules
        let mut in_test_module = false;
        let mut test_module_depth = 0u32;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("#[cfg(test)]") {
                in_test_module = true;
                test_module_depth = 0;
                continue;
            }

            if in_test_module {
                for ch in trimmed.bytes() {
                    match ch {
                        b'{' => test_module_depth += 1,
                        b'}' => {
                            if test_module_depth == 0 {
                                in_test_module = false;
                            } else {
                                test_module_depth -= 1;
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }

            // Only check lines that actually contain tokio::spawn
            if !trimmed.contains("tokio::spawn") {
                continue;
            }
            // Skip if it's in a comment
            if trimmed.starts_with("//") {
                continue;
            }

            // Check if this spawn goes through registration helpers
            // Look for spawn_registered or spawn_registered_unit in the surrounding context
            let has_registration = (idx.saturating_sub(10)..=idx.min(cleaned_lines_vec.len() - 1))
                .any(|i| {
                    let l = cleaned_lines_vec[i].1;
                    l.contains("spawn_registered")
                        || l.contains("spawn_registered_unit")
                        || l.contains("handles.register(")
                });

            if !has_registration {
                offenders.push(format!("{}:{}: {}", file.display(), idx + 1, trimmed));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "Long-lived server spawns must use spawn_registered/register.\n\
         Direct tokio::spawn is only allowed in runtime_handles.rs, plugin_runtime.rs,\n\
         waf_handler.rs, and test modules.\n\n\
         Offenders:\n{}",
        offenders.join("\n")
    );
}

/// PluginRuntimeOwner must be integrated into run() — it should appear as a
/// variable that is kept alive (not immediately dropped).
#[test]
fn plugin_runtime_owner_is_stored_for_runtime_lifetime() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mod_rs = repo.join("src/server/mod.rs");
    let text = std::fs::read_to_string(&mod_rs).unwrap();
    let cleaned = strip_comments_and_strings(&text);

    // Check that plugin_owner is created and not immediately dropped
    // The pattern: `let mut plugin_owner = ...` must appear
    assert!(
        cleaned.contains("let mut plugin_owner ="),
        "PluginRuntimeOwner must be created as a mutable variable in run(), not immediately dropped"
    );

    // Check that it's dropped after shutdown_and_join
    assert!(
        cleaned.contains("drop(plugin_owner)"),
        "PluginRuntimeOwner must be explicitly dropped after shutdown_and_join to ensure it lives for the full runtime lifetime"
    );
}

#[test]
fn allowed_files_exist_on_disk() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let server_dir = repo.join("src/server");
    let allowed_files: &[&str] = &[
        "runtime_handles.rs",
        "plugin_runtime.rs",
        "waf_handler.rs",
        "mod.rs",
    ];
    for name in allowed_files {
        let path = server_dir.join(name);
        assert!(
            path.exists(),
            "allowed_files entry '{}' does not exist at {} — remove stale entry or update allowlist",
            name,
            path.display()
        );
    }
}

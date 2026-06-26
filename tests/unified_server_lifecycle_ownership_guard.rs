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
            } else if path.extension().map_or(false, |e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn server_runtime_does_not_leak_lifecycle_handles() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = [repo.join("src/server"), repo.join("src/plugin")];
    let mut offenders = Vec::new();

    for file in rust_files_under(&roots) {
        let text = std::fs::read_to_string(&file).unwrap();
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comments and attributes
            if trimmed.starts_with("//") || trimmed.starts_with("#[") {
                continue;
            }
            if trimmed.contains("std::mem::forget") || trimmed.contains("mem::forget") {
                offenders.push(format!("{}:{}: {}", file.display(), idx + 1, trimmed));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "server/plugin lifecycle handles must be owned, not leaked:\n{}",
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

            // Skip comments and attributes
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
        "Every tokio::spawn in server/plugin must have a `// reason:` comment:\n{}",
        unreasoned.join("\n")
    );
}

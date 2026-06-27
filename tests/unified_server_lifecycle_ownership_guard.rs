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

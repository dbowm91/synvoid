//! Shared helpers for lightweight static architecture guards.
//!
//! These utilities avoid depending on the root `synvoid` package,
//! keeping the guard crate's dependency tree minimal.

use std::path::{Path, PathBuf};

/// Locate the workspace root by walking up from `CARGO_MANIFEST_DIR`
/// until a `Cargo.toml` containing `[workspace]` is found.
pub fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml).unwrap_or_default();
            if content.contains("[workspace]") {
                return path;
            }
        }
        if !path.pop() {
            panic!("Could not find workspace root");
        }
    }
}

/// Recursively collect all `.rs` files under `dir`, skipping `target/` and `.git/`.
pub fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" {
                continue;
            }
            if path.is_dir() {
                files.extend(collect_rs_files(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Recursively collect all `.rs` files under `dir` for specific subdirectories.
pub fn collect_rs_files_in(dir: &Path, subdirs: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for sub in subdirs {
        let path = dir.join(sub);
        files.extend(collect_rs_files(&path));
    }
    files
}

/// Strip line comments (`//`) and block comments (`/* ... */`) from Rust source.
/// Also strips string literals to avoid false positives from tokens inside strings.
pub fn strip_comments(content: &str) -> String {
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

/// Strip `#[cfg(test)]` modules (brace-depth-aware) to avoid false positives.
pub fn strip_cfg_test_modules(content: &str) -> String {
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

/// Prepare source for pattern scanning: strip comments, strings, and test modules.
pub fn prepare_for_scanning(content: &str) -> String {
    let stripped = strip_comments(content);
    strip_cfg_test_modules(&stripped)
}

/// Collect `.rs` files from the standard source directories.
pub fn collect_source_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    // crates/ directory
    files.extend(collect_rs_files(&root.join("crates")));
    // src/ directory
    files.extend(collect_rs_files(&root.join("src")));
    files
}

/// A violation accumulator that collects messages and panics at the end.
pub struct Violations {
    messages: Vec<String>,
}

impl Violations {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn push(&mut self, msg: String) {
        self.messages.push(msg);
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn assert_ok(&self, context: &str) {
        assert!(
            self.messages.is_empty(),
            "{} ({} violations):\n{}",
            context,
            self.messages.len(),
            self.messages.join("\n")
        );
    }
}

impl Default for Violations {
    fn default() -> Self {
        Self::new()
    }
}

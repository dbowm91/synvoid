//! Guardrail test preventing language that implies native plugins are sandboxed.
//!
//! Native extensions loaded via `libloading` run with full Synvoid process
//! authority. Documentation must never describe them as "sandboxed" or imply
//! they share the WASM trust boundary.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_markdown_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_markdown_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(path);
        }
    }
}

/// Patterns that incorrectly imply native plugins are sandboxed.
/// Each entry is (pattern, explanation).
const FORBIDDEN_PATTERNS: &[(&str, &str)] = &[
    (
        "sandboxed native plugin",
        "native plugins are NOT sandboxed",
    ),
    (
        "sandboxed native extension",
        "native extensions are NOT sandboxed",
    ),
    (
        "native plugin sandbox",
        "native extensions are NOT sandboxed",
    ),
    (
        "sandboxed axum plugin",
        "axum plugins are native extensions, NOT sandboxed",
    ),
    (
        "axum plugin sandbox",
        "axum plugins are native extensions, NOT sandboxed",
    ),
    (
        "native extension sandbox",
        "native extensions are NOT sandboxed",
    ),
    (
        "native plugins are sandboxed",
        "native plugins are NOT sandboxed",
    ),
    (
        "unsafe native extensions are sandboxed",
        "unsafe native extensions are NOT sandboxed",
    ),
];

/// Allowlisted occurrences where these phrases appear in a safe context
/// (e.g., in a "NOT sandboxed" or negation context).
fn is_negated_context(line: &str, pattern: &str) -> bool {
    let lower = line.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    // Check for negation words before the pattern
    for negation in &[
        "not ", "never ", "are not ", "is not ", "aren't ", "isn't ", "no ",
    ] {
        if let Some(pos) = lower.find(&pattern_lower) {
            let before = &lower[..pos];
            if before.contains(negation) {
                return true;
            }
        }
    }
    // Check for "not sandboxed" following the pattern
    if let Some(pos) = lower.find(&pattern_lower) {
        let after = &lower[pos + pattern_lower.len()..];
        if after.contains("not ") || after.contains("aren't") {
            return true;
        }
    }
    false
}

#[test]
fn no_docs_imply_native_plugins_are_sandboxed() {
    let root = workspace_root();
    let mut md_files: Vec<PathBuf> = Vec::new();

    // Scan all documentation directories
    for dir in &["architecture", "docs", ".opencode/skills"] {
        collect_markdown_files(&root.join(dir), &mut md_files);
    }
    // Top-level files
    for name in &["AGENTS.md", "README.md"] {
        let path = root.join(name);
        if path.exists() {
            md_files.push(path);
        }
    }

    let mut violations: Vec<String> = Vec::new();

    for md_file in &md_files {
        let content = match std::fs::read_to_string(md_file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let relative = md_file.strip_prefix(&root).unwrap_or(md_file);

        for (i, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            for &(pattern, explanation) in FORBIDDEN_PATTERNS {
                if lower.contains(&pattern.to_lowercase()) && !is_negated_context(line, pattern) {
                    violations.push(format!(
                        "  {}:{}: '{}' — {}",
                        relative.display(),
                        i + 1,
                        line.trim(),
                        explanation
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Documentation implies native plugins are sandboxed ({} violations):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

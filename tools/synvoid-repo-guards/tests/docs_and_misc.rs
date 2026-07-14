//! Static guards for documentation and miscellaneous checks.
//!
//! Ensures markdown links resolve, unsafe/native sandbox language is not
//! misleading, and docs reference existing files.

use std::path::PathBuf;
use synvoid_repo_guards::{workspace_root, Violations};

// ---------------------------------------------------------------------------
// docs_path_reference_guard
// ---------------------------------------------------------------------------

fn collect_markdown_files(root: &std::path::Path, out: &mut Vec<PathBuf>) {
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

fn extract_local_links(content: &str) -> Vec<String> {
    let mut links = Vec::new();
    let re = regex::Regex::new(r"\[([^\]]*)\]\(([^)]+)\)").unwrap();
    for cap in re.captures_iter(content) {
        let url = cap[2].trim();
        if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("mailto:") {
            continue;
        }
        let clean = if let Some(pos) = url.find('#') {
            &url[..pos]
        } else {
            url
        };
        if clean.is_empty() {
            continue;
        }
        let clean = if let Some(pos) = clean.rfind(':') {
            let suffix = &clean[pos + 1..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                &clean[..pos]
            } else {
                clean
            }
        } else {
            clean
        };
        links.push(clean.to_string());
    }
    links
}

fn is_source_ref(link: &str) -> bool {
    link.ends_with(".rs") || link.starts_with("crates/") || link.starts_with("src/")
}

#[test]
fn all_markdown_links_resolve_to_existing_files() {
    let root = workspace_root();

    let allowlist: &[(&str, &str)] = &[
        ("plugin_deep_dive.md", "removed during docs consolidation"),
        ("zero_copy.md", "removed; content merged into other docs"),
        (
            "serde.md",
            "removed; content merged into serialization docs",
        ),
        (
            "plan.md",
            "historical planning doc; superseded by roadmap.md",
        ),
        (
            "spin_wasm.md",
            "historical skill doc; superseded by .opencode/skills/",
        ),
        (
            "wasm_components.md",
            "historical skill doc; superseded by .opencode/skills/",
        ),
        (
            "skills/serverless_wasm.md",
            "malformed; actual path is .opencode/skills/serverless_wasm/SKILL.md",
        ),
        (
            "skills/dns_dnssec.md",
            "malformed; actual path is .opencode/skills/dns_dnssec/SKILL.md",
        ),
        (
            "../../AGENTS.md",
            "malformed relative path from architecture/",
        ),
    ];
    let allowset: std::collections::HashSet<&str> = allowlist.iter().map(|(p, _)| *p).collect();

    let mut md_files: Vec<PathBuf> = Vec::new();
    collect_markdown_files(&root.join("architecture"), &mut md_files);
    collect_markdown_files(&root.join(".opencode/skills"), &mut md_files);
    collect_markdown_files(&root.join("docs"), &mut md_files);
    for name in &["AGENTS.md", "README.md"] {
        let path = root.join(name);
        if path.exists() {
            md_files.push(path);
        }
    }

    let mut broken: Vec<String> = Vec::new();

    for md_file in &md_files {
        let content = match std::fs::read_to_string(md_file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let links = extract_local_links(&content);
        let file_dir = md_file.parent().unwrap_or(&root);

        for link in &links {
            if allowset.iter().any(|a| link.contains(*a)) {
                continue;
            }
            let target = file_dir.join(link);
            if target.exists() {
                continue;
            }
            if is_source_ref(link) {
                let root_target = root.join(link);
                if root_target.exists() {
                    continue;
                }
            }
            let relative_file = md_file.strip_prefix(&root).unwrap_or(md_file);
            broken.push(format!(
                "  {} references '{}' (no match from {})",
                relative_file.display(),
                link,
                file_dir.strip_prefix(&root).unwrap_or(file_dir).display()
            ));
        }
    }

    assert!(
        broken.is_empty(),
        "Broken markdown links found ({} total):\n{}",
        broken.len(),
        broken.join("\n")
    );
}

// ---------------------------------------------------------------------------
// unsafe_native_sandbox_language_guard
// ---------------------------------------------------------------------------

/// Forbidden misleading phrases about native plugin sandboxing.
const FORBIDDEN_SANDBOX_PHRASES: &[(&str, &str)] = &[
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

/// Check if the pattern appears in a negation context.
fn is_negated_context(line: &str, pattern: &str) -> bool {
    let lower = line.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    for negation in &[
        "not ",
        "never ",
        "are not ",
        "is not ",
        "aren't ",
        "isn't ",
        "no ",
        "forbidden ",
    ] {
        if let Some(pos) = lower.find(&pattern_lower) {
            let before = &lower[..pos];
            if before.contains(negation) {
                return true;
            }
        }
    }
    if let Some(pos) = lower.find(&pattern_lower) {
        let after = &lower[pos + pattern_lower.len()..];
        if after.contains("not ") || after.contains("aren't") {
            return true;
        }
    }
    false
}

#[test]
fn no_misleading_sandbox_language() {
    let root = workspace_root();
    let mut md_files: Vec<PathBuf> = Vec::new();

    // Scan specific documentation directories (matching original guard scope)
    for dir in &["architecture", "docs", ".opencode/skills"] {
        collect_markdown_files(&root.join(dir), &mut md_files);
    }
    for name in &["AGENTS.md", "README.md"] {
        let path = root.join(name);
        if path.exists() {
            md_files.push(path);
        }
    }

    let mut violations = Violations::new();

    for md_file in &md_files {
        let rel = md_file.strip_prefix(&root).unwrap_or(md_file);
        let rel_str = rel.to_string_lossy().to_string();

        if rel_str.starts_with("target/") {
            continue;
        }

        let content = std::fs::read_to_string(md_file).unwrap_or_default();

        for (i, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            for &(pattern, explanation) in FORBIDDEN_SANDBOX_PHRASES {
                if lower.contains(&pattern.to_lowercase()) && !is_negated_context(line, pattern) {
                    violations.push(format!(
                        "  {}:{}: '{}' — {}",
                        rel_str,
                        i + 1,
                        line.trim(),
                        explanation
                    ));
                }
            }
        }
    }

    violations.assert_ok("unsafe_native_sandbox_language_guard");
}

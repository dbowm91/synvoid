//! Guard test ensuring all local markdown links point to existing files.
//!
//! Scans `architecture/`, `.opencode/skills/`, `docs/`, `AGENTS.md`, and
//! `README.md` for relative markdown links and verifies the target files
//! exist on disk. Catches broken documentation links early.

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

/// Extract local relative markdown links from content.
/// Matches patterns like `[text](./path)` or `[text](path)` or `[text](../path)`.
/// Skips external URLs (http://, https://) and strips anchors (#...) when resolving.
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
        // Strip line/col suffixes like ":7" or ":7:12" for source file references
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

/// Returns true if the link looks like a source code file reference
/// (e.g., paths containing .rs files, or starting with crates/, src/).
fn is_source_ref(link: &str) -> bool {
    link.ends_with(".rs") || link.starts_with("crates/") || link.starts_with("src/")
}

#[test]
fn all_markdown_links_resolve_to_existing_files() {
    let root = workspace_root();

    // Allowlist of known historical removed files that are still referenced
    // in docs. Each entry is a link substring and a reason.
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

    // Collect markdown files from target directories
    let mut md_files: Vec<PathBuf> = Vec::new();

    // architecture/
    collect_markdown_files(&root.join("architecture"), &mut md_files);

    // .opencode/skills/
    collect_markdown_files(&root.join(".opencode/skills"), &mut md_files);

    // docs/
    collect_markdown_files(&root.join("docs"), &mut md_files);

    // Top-level files (if they exist)
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
            // Check allowlist
            if allowset.iter().any(|a| link.contains(*a)) {
                continue;
            }

            // Try resolving relative to the markdown file's directory
            let target = file_dir.join(link);
            if target.exists() {
                continue;
            }

            // For source code references, also try resolving from workspace root
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

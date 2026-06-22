//! Guard test preventing domain crates from importing the root `synvoid` crate.
//!
//! Domain crates should import dedicated `synvoid-*` crates directly rather than
//! going through the root `synvoid` compatibility facade. This test scans all
//! `.rs` files under `crates/` and rejects any that use `synvoid::` path syntax.
//!
//! See `architecture/root_module_ledger.md` for the ownership ledger.

use std::path::{Path, PathBuf};

fn walk_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
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
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Returns true if the line is a comment or blank (should be skipped).
fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with("*")
}

#[test]
fn domain_crates_do_not_import_root_synvoid_crate() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = repo.join("crates");
    let mut files = Vec::new();
    walk_rs_files(&crates_dir, &mut files);

    // Allowlist: (path_substring, reason)
    // Keep this allowlist empty unless a crate cannot avoid a root `synvoid::` path
    // during a staged migration. Every allowlist entry must include a matching
    // blocker in `architecture/root_module_ledger.md` and should be removed by the
    // next targeted extraction pass.
    let allowlist: &[(&str, &str)] = &[];

    let allowset: std::collections::HashSet<&str> = allowlist.iter().map(|(p, _)| *p).collect();

    let mut offenders = Vec::new();
    for path in &files {
        let relative = path.strip_prefix(&repo).unwrap().display().to_string();

        // Check allowlist
        if allowset.iter().any(|a| relative.contains(a)) {
            continue;
        }

        let text = std::fs::read_to_string(path).expect("read Rust source");
        for (line_num, line) in text.lines().enumerate() {
            if is_comment_or_blank(line) {
                continue;
            }
            // Reject `use synvoid::` imports and bare `synvoid::` path references
            // in non-comment, non-string-literal code.
            //
            // The string-literal check below is intentionally heuristic. It avoids obvious
            // false positives in diagnostics/doc examples, but this guard is primarily a
            // source-level architectural tripwire, not a Rust parser.
            if line.contains("use synvoid::") || line.contains("synvoid::") {
                // Heuristic: skip lines where `synvoid::` appears inside a string literal.
                let before = line.split("synvoid::").next().unwrap_or("");
                let open_quotes = before.matches('"').count();
                if open_quotes % 2 == 1 {
                    // Inside a string literal — skip
                    continue;
                }
                offenders.push(format!("  {}:{}: {}", relative, line_num + 1, line.trim()));
                break; // one violation per file is enough
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "domain crates must import dedicated synvoid-* crates, not root synvoid paths:\n{}",
        offenders.join("\n")
    );
}

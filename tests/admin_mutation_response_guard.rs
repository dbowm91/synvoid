//! Guardrail: mutating admin endpoints must not return generic `{"success": true}` responses.
//!
//! This test scans admin handler source files for generic success tokens that
//! indicate ad-hoc JSON responses instead of typed `AdminMutationResult` returns.
//!
//! Read-only diagnostics endpoints are allowed to return simple responses.

use std::fs;
use std::path::Path;

/// Strip string literals, line comments (`//`), and block comments (`/* */`).
/// Prevents false positives from tokens inside comments or strings.
fn strip_comments_and_strings(content: &str) -> String {
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
            '"' => loop {
                match chars.next() {
                    Some('\\') => {
                        chars.next();
                    }
                    Some('"') => break,
                    Some(_) => {}
                    None => break,
                }
            },
            _ => result.push(ch),
        }
    }
    result
}

/// Generic success tokens that indicate ad-hoc responses in mutating handlers.
const GENERIC_SUCCESS_TOKENS: &[&str] = &[
    "\"success\": true",
    "success: true",
    "StatusCode::OK, Json(json!",
];

/// Directories to scan for admin handlers.
const HANDLER_DIRS: &[&str] = &["src/admin/handlers", "crates/synvoid-admin/src/handlers"];

/// Files that are allowed to contain generic success tokens (read-only endpoints).
const ALLOWLIST: &[&str] = &[
    // Read-only endpoints that legitimately return simple responses
    "stats.rs",
    "api_discovery.rs",
    "mesh_topology.rs",
    "behavioral_intel.rs",
    "threat_intel_policy.rs",
];

#[test]
fn admin_mutation_response_guard() {
    let mut violations = Vec::new();

    for dir in HANDLER_DIRS {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }

        let entries = fs::read_dir(dir_path).expect("read handler directory");
        for entry in entries {
            let entry = entry.expect("read entry");
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Skip allowed files
            if ALLOWLIST.contains(&file_name) {
                continue;
            }

            // Only scan .rs files
            if !path.extension().map_or(false, |e| e == "rs") {
                continue;
            }

            let raw = fs::read_to_string(&path).expect("read file");
            let content = strip_comments_and_strings(&raw);
            let lines: Vec<&str> = content.lines().collect();

            // Track if we're inside a mutating handler function
            let mut in_mutation_handler = false;
            let mut brace_depth = 0;

            for (line_num, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect handler function signatures (pub async fn ban_*, pub async fn unban, etc.)
                if trimmed.contains("pub async fn")
                    && (trimmed.contains("ban_")
                        || trimmed.contains("unban")
                        || trimmed.contains("block")
                        || trimmed.contains("unblock")
                        || trimmed.contains("delete_")
                        || trimmed.contains("create_")
                        || trimmed.contains("update_")
                        || trimmed.contains("apply_")
                        || trimmed.contains("reload_")
                        || trimmed.contains("restart_")
                        || trimmed.contains("scale_")
                        || trimmed.contains("stop_")
                        || trimmed.contains("drain_"))
                {
                    in_mutation_handler = true;
                    brace_depth = 0;
                }

                if in_mutation_handler {
                    brace_depth += line.matches('{').count();
                    brace_depth = brace_depth.saturating_sub(line.matches('}').count());

                    for token in GENERIC_SUCCESS_TOKENS {
                        if line.contains(token) {
                            let rel_path = path
                                .strip_prefix("src/")
                                .or_else(|_| path.strip_prefix("crates/"))
                                .unwrap_or(&path);
                            violations.push(format!(
                                "{}:{}:{}: found generic success token '{}' in mutating handler",
                                rel_path.display(),
                                line_num + 1,
                                trimmed,
                                token
                            ));
                        }
                    }

                    // End of function when braces close
                    if brace_depth == 0 && line.contains('}') {
                        in_mutation_handler = false;
                    }
                }
            }
        }
    }

    if !violations.is_empty() {
        let msg = format!(
            "Found {} mutating admin handlers with generic success responses:\n{}",
            violations.len(),
            violations.join("\n")
        );
        panic!("{}\n\nMutating admin endpoints must return typed AdminMutationResult instead of generic {{\"success\": true}}. See architecture/admin_control_plane_authority.md", msg);
    }
}

#[test]
fn admin_mutation_authority_variants_documented() {
    // Verify that all AdminMutationAuthority variants are present in the architecture doc
    let doc_path = Path::new("architecture/admin_control_plane_authority.md");
    if !doc_path.exists() {
        eprintln!("Skipping: architecture/admin_control_plane_authority.md not found");
        return;
    }

    let content = fs::read_to_string(doc_path).expect("read architecture doc");
    let required_variants = [
        "AdminManual",
        "SupervisorManual",
        "SupervisorSync",
        "MeshPolicyGated",
        "LocalDetector",
        "WorkerIpc",
        "CompatibilityLegacy",
    ];

    let mut missing = Vec::new();
    for variant in &required_variants {
        if !content.contains(variant) {
            missing.push(variant.to_string());
        }
    }

    if !missing.is_empty() {
        panic!(
            "architecture/admin_control_plane_authority.md is missing documentation for AdminMutationAuthority variants: {:?}",
            missing
        );
    }
}

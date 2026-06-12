//! Manual enforcement provenance guard tests.
//!
//! Ensures that production enforcement paths use `block_ip_with_provenance`
//! (the provenance-aware API) rather than the legacy `.block_ip()` method.
//! Also verifies that `LegacyUnknown` is not used as an explicit provenance
//! kind in production code outside of backward-compat and default impls.

use std::fs;
use std::path::{Path, PathBuf};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Recursively collect every `.rs` file under `dir`.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            results.extend(collect_rs_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            results.push(path);
        }
    }
    results
}

/// Strip everything from the first `#[cfg(test)]` attribute onward.
fn strip_test_modules(content: &str) -> &str {
    if let Some(idx) = content.find("#[cfg(test)]") {
        &content[..idx]
    } else {
        content
    }
}

/// Strip single-line comments (`// ...`) and block comments (`/* ... */`).
/// This is a best-effort heuristic — nested or tricky comments may slip through,
/// but that is acceptable for a guardrail.
fn strip_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Skip until end of line
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // Skip until closing */
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2; // skip */
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// For a given file content (already stripped of test modules and comments),
/// return line numbers where `.block_ip(` appears outside of trait defs and
/// `BlockEntry::new()` calls.
fn find_legacy_block_ip_calls(content: &str) -> Vec<usize> {
    let mut violations = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip trait definitions
        if trimmed.starts_with("trait ") || trimmed.starts_with("pub trait ") {
            continue;
        }

        // Skip BlockEntry::new() — these produce LegacyUnknown but are
        // acceptable for backward compat
        if line.contains("BlockEntry::new(") {
            continue;
        }

        // Skip lines that are purely doc comments (already stripped, but be safe)
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        if line.contains(".block_ip(") {
            // Make sure it's not .block_ip_with_provenance
            if !line.contains(".block_ip_with_provenance(") {
                violations.push(idx + 1); // 1-indexed
            }
        }
    }
    violations
}

/// Compute line ranges (0-indexed start, 1-indexed end) for `impl Default`
/// and `fn default()` blocks so they can be excluded from scanning.
fn default_impl_line_ranges(content: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.contains("impl Default") || trimmed.contains("fn default()") {
            // Find the opening brace
            let start = i;
            let mut depth: i32 = 0;
            let mut found_open = false;
            let mut j = i;
            while j < lines.len() {
                for ch in lines[j].chars() {
                    if ch == '{' {
                        depth += 1;
                        found_open = true;
                    } else if ch == '}' {
                        depth -= 1;
                    }
                }
                if found_open && depth == 0 {
                    ranges.push((start, j + 1)); // end is exclusive
                    i = j + 1;
                    break;
                }
                j += 1;
                if j == lines.len() {
                    // Unterminated block — skip to end
                    ranges.push((start, j));
                    i = j;
                    break;
                }
            }
            if !found_open {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    ranges
}

/// For a given file content (already stripped of test modules and comments),
/// return line numbers where `LegacyUnknown` is used as an explicit provenance
/// kind outside of tests and default impls.
fn find_legacy_unknown_usages(content: &str) -> Vec<usize> {
    let skip_ranges = default_impl_line_ranges(content);
    let mut violations = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip doc comments
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        // Skip lines inside Default impl blocks
        let inside_default = skip_ranges
            .iter()
            .any(|&(start, end)| idx >= start && idx < end);
        if inside_default {
            continue;
        }

        // Only flag the enum variant, not string patterns like "LegacyUnknown"
        if line.contains("BlockProvenanceKind::LegacyUnknown") {
            violations.push(idx + 1);
        }
    }
    violations
}

// ── Denylist directories ─────────────────────────────────────────────────────

const DENYLIST_DIRS: &[&str] = &["src/admin", "src/supervisor", "src/worker/unified_server"];

// ── Phase 1: Legacy .block_ip() Check ────────────────────────────────────────

/// Scan denylist directories for legacy `.block_ip(` calls outside of test code.
#[test]
fn no_legacy_block_ip_in_production_paths() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations: Vec<String> = Vec::new();

    for dir in DENYLIST_DIRS {
        let path = workspace_root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_test_modules(&content);
            let production = strip_comments(&production);

            let lines = find_legacy_block_ip_calls(&production);
            if !lines.is_empty() {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                violations.push(format!(
                    "  {relative}: .block_ip( found at lines: {}",
                    line_list.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Legacy `.block_ip()` method used in a production enforcement path. \
             Use `block_ip_with_provenance()` instead, which records provenance \
             for audit and trust-domain classification.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 2: LegacyUnknown Provenance Check ──────────────────────────────────

/// Scan denylist directories for explicit `LegacyUnknown` provenance usage
/// outside of tests and default impls.
#[test]
fn no_explicit_legacy_unknown_provenance_in_production() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations: Vec<String> = Vec::new();

    for dir in DENYLIST_DIRS {
        let path = workspace_root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_test_modules(&content);
            let production = strip_comments(&production);

            let lines = find_legacy_unknown_usages(&production);
            if !lines.is_empty() {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                violations.push(format!(
                    "  {relative}: LegacyUnknown used at lines: {}",
                    line_list.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Explicit `LegacyUnknown` provenance kind used in production code. \
             New enforcement paths should use a meaningful provenance kind \
             (e.g. `WafEnforcement`, `MeshSync`, `AdminAction`). \
             `LegacyUnknown` is acceptable only in Default impls, backward-compat \
             shims, and tests.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 3: Positive Boundary Tests ─────────────────────────────────────────

/// Verify that denylist directories exist and contain `.rs` files.
#[test]
fn denylist_directories_are_valid() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    for dir in DENYLIST_DIRS {
        let path = workspace_root.join(dir);
        if path.exists() {
            let files = collect_rs_files(&path);
            assert!(
                !files.is_empty(),
                "Denylist directory `{dir}` exists but contains no .rs files"
            );
        }
    }
}

/// Confirm that a simulated legacy `.block_ip(` call would be caught.
#[test]
fn simulated_legacy_block_ip_is_detected() {
    let fake_content =
        "fn handle_block() {\n    store.block_ip(ip, \"reason\", 3600, Scope::Global);\n}\n";

    let lines = find_legacy_block_ip_calls(fake_content);
    assert!(
        !lines.is_empty(),
        "Simulated legacy .block_ip( call must be detected"
    );
}

/// Confirm that `block_ip_with_provenance` is NOT flagged.
#[test]
fn provenance_api_is_not_flagged() {
    let fake_content =
        "fn handle_block() {\n    store.block_ip_with_provenance(ip, \"reason\", 3600, Scope::Global, provenance);\n}\n";

    let lines = find_legacy_block_ip_calls(fake_content);
    assert!(
        lines.is_empty(),
        "block_ip_with_provenance should not be flagged as a violation"
    );
}

/// Confirm that `BlockEntry::new()` is NOT flagged.
#[test]
fn block_entry_new_is_not_flagged() {
    let fake_content =
        "fn create_entry() {\n    let entry = BlockEntry::new(ip, reason, ttl, scope);\n}\n";

    let lines = find_legacy_block_ip_calls(fake_content);
    assert!(
        lines.is_empty(),
        "BlockEntry::new() should not be flagged as a .block_ip( violation"
    );
}

/// Confirm that simulated `LegacyUnknown` in production code is detected.
#[test]
fn simulated_legacy_unknown_is_detected() {
    let fake_content =
        "fn apply_block() {\n    let provenance = BlockProvenanceKind::LegacyUnknown;\n}\n";

    let lines = find_legacy_unknown_usages(fake_content);
    assert!(
        !lines.is_empty(),
        "Simulated LegacyUnknown in production code must be detected"
    );
}

/// Confirm that `LegacyUnknown` in a Default impl is NOT flagged.
#[test]
fn legacy_unknown_in_default_impl_is_not_flagged() {
    let fake_content =
        "impl Default for Foo {\n    fn default() -> Self {\n        Self { kind: BlockProvenanceKind::LegacyUnknown }\n    }\n}\n";

    let lines = find_legacy_unknown_usages(fake_content);
    assert!(
        lines.is_empty(),
        "LegacyUnknown in Default impl should not be flagged"
    );
}

/// Verify that test modules are stripped so inline test code is not flagged.
#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let content = r#"
        fn real_function() {
            store.block_ip(ip, "reason", 3600, Scope::Global);
        }

        #[cfg(test)]
        mod tests {
            fn test_block() {
                store.block_ip(ip, "reason", 3600, Scope::Global);
            }
        }
    "#;

    let stripped = strip_test_modules(content);

    assert!(
        !stripped.contains("#[cfg(test)]"),
        "Test module marker should be stripped"
    );
    // The production .block_ip( should still be found
    let lines = find_legacy_block_ip_calls(&strip_comments(stripped));
    assert!(
        !lines.is_empty(),
        "Production .block_ip( before #[cfg(test)] must still be detected"
    );
}

// ── Phase 4: Iteration 50 — SupervisorSync Provenance Guard ───────────────────

/// Scan worker/supervisor blocklist ingestion paths for unconditional
/// `BlockProvenanceKind::SupervisorSync` assignment. After Iteration 50,
/// these paths should use `ipc_data_to_provenance()` to preserve original
/// provenance, not hardcode `SupervisorSync`.
fn find_unconditional_supervisor_sync(content: &str) -> Vec<usize> {
    let mut violations = Vec::new();
    // Track whether we're inside the ipc_data_to_provenance helper function
    let mut in_helper = false;
    let mut depth: i32 = 0;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Track function boundaries for the helper
        if trimmed.contains("fn ipc_data_to_provenance(") {
            in_helper = true;
            depth = 0;
        }
        if in_helper {
            for ch in trimmed.chars() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                    if depth == 0 {
                        in_helper = false;
                    }
                }
            }
            continue; // Skip all lines inside the helper
        }

        // Skip doc comments
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        // Skip comments
        if trimmed.starts_with("//") {
            continue;
        }

        // Flag direct SupervisorSync construction in blocklist ingestion paths
        if line.contains("BlockProvenanceKind::SupervisorSync")
            && !line.contains("Some(\"SupervisorSync\")")
        {
            violations.push(idx + 1);
        }
    }
    violations
}

const BLOCKLIST_INGESTION_DIRS: &[&str] =
    &["src/worker/unified_server", "src/supervisor", "src/process"];

/// Scan blocklist ingestion paths for unconditional `SupervisorSync` assignment.
/// After Iteration 50, these paths should use `ipc_data_to_provenance()` instead.
#[test]
fn no_unconditional_supervisor_sync_in_blocklist_ingestion() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations: Vec<String> = Vec::new();

    for dir in BLOCKLIST_INGESTION_DIRS {
        let path = workspace_root.join(dir);
        if !path.exists() {
            continue;
        }

        let files = collect_rs_files(&path);
        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let production = strip_test_modules(&content);
            let production = strip_comments(&production);

            let lines = find_unconditional_supervisor_sync(&production);
            if !lines.is_empty() {
                let line_list: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
                violations.push(format!(
                    "  {relative}: SupervisorSync used at lines: {}",
                    line_list.join(", ")
                ));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Unconditional `BlockProvenanceKind::SupervisorSync` found in blocklist ingestion paths. \
             After Iteration 50, these paths must use `ipc_data_to_provenance()` to preserve \
             original provenance. `SupervisorSync` should only be used when the supervisor \
             itself originated the block, not as a blanket relay default.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

/// Confirm that a simulated unconditional SupervisorSync assignment is detected.
#[test]
fn simulated_unconditional_supervisor_sync_is_detected() {
    let fake_content = r#"fn apply_blocklist_update() {
    let provenance = BlockProvenance {
        kind: BlockProvenanceKind::SupervisorSync,
        source: Some("blocklist_update".to_string()),
    };
}"#;

    let lines = find_unconditional_supervisor_sync(fake_content);
    assert!(
        !lines.is_empty(),
        "Simulated unconditional SupervisorSync must be detected"
    );
}

/// Confirm that SupervisorSync in the ipc_data_to_provenance helper is NOT flagged.
#[test]
fn supervisor_sync_in_helper_is_not_flagged() {
    let fake_content = r#"fn ipc_data_to_provenance(kind_str: Option<&str>, source: Option<&str>) -> BlockProvenance {
    let kind = match kind_str {
        Some("SupervisorSync") => BlockProvenanceKind::SupervisorSync,
        _ => BlockProvenanceKind::LegacyUnknown,
    };
}"#;

    let lines = find_unconditional_supervisor_sync(fake_content);
    assert!(
        lines.is_empty(),
        "SupervisorSync in ipc_data_to_provenance helper should not be flagged"
    );
}

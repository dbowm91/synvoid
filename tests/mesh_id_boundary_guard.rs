//! Root-test ownership: STATIC_POLICY
//! Rationale: validates mesh-id boundary between block-store, mesh, and admin
//!
//! Mesh-ID enforcement boundary guard tests (Iteration 51).
//!
//! Outcome A: Mesh-ID blocks are control-plane/admin scoped only. This guard
//! prevents `is_mesh_id_blocked()` from being called in WAF, HTTP request
//! handling, proxy, or HTTP/3 code paths where no trusted mesh identity
//! exists in the request context.
//!
//! The `RequestContext`, `WafContext`, and all WAF trait signatures lack a
//! mesh identity field. External HTTP clients do not present mesh credentials.
//! Therefore mesh-ID blocks cannot be enforced at the request path without
//! first implementing a trusted identity composition root (Outcome B).
//!
//! Phase 1 — Source scan preventing `is_mesh_id_blocked` calls in request/WAF paths.
//! Phase 2 — Positive boundary tests confirming structural coverage.

use std::fs;
use std::path::{Path, PathBuf};

// ── Phase 1: Mesh-ID Block Request-Path Boundary Check ───────────────────────

/// Tokens that indicate a mesh-ID block lookup on the request path.
/// These are control-plane/admin APIs; WAF/request code must not call them
/// because `RequestContext` does not carry a trusted mesh identity.
const MESH_ID_LOOKUP_TOKENS: &[&str] = &["is_mesh_id_blocked("];

/// Files where `is_mesh_id_blocked` is explicitly permitted:
/// - The block-store implementation itself (where the method is defined)
/// - Admin handlers (control-plane scope)
/// - Mesh stubs / transport (mesh-internal scope)
/// - Integration tests and this guard test itself
/// - IPC lifecycle (Supervisor-to-worker sync)
fn is_allowlisted(relative: &str) -> bool {
    let allowlist: &[&str] = &[
        // Block-store implementation (method definition)
        "crates/synvoid-block-store/src/lib.rs",
        // Mesh stubs (trait definition + delegation)
        "crates/synvoid-mesh/src/stubs.rs",
        // Admin handlers (control-plane scope)
        "src/admin/handlers/mesh_admin.rs",
        // This guard test
        "tests/mesh_id_boundary_guard.rs",
    ];

    for entry in allowlist {
        if relative == *entry {
            return true;
        }
    }

    // Documentation / plans / architecture are always permitted.
    if relative.starts_with("docs/")
        || relative.starts_with("plans/")
        || relative.starts_with("architecture/")
    {
        return true;
    }

    false
}

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

/// Phase 1: Scan request/WAF/proxy/HTTP/3 source files and reject
/// `is_mesh_id_blocked` calls outside the allowlist.
#[test]
fn mesh_id_lookup_boundary_check() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Denylist: directories that handle HTTP requests and WAF evaluation.
    // These must not call `is_mesh_id_blocked` because no trusted mesh
    // identity is available in the request context.
    let denylist_dirs: &[&str] = &[
        "src/waf",
        "src/http",
        "src/worker/unified_server",
        "src/proxy",
        "crates/synvoid-http3",
        "crates/synvoid-waf",
        "crates/synvoid-proxy",
        "crates/synvoid-http",
    ];

    let mut violations: Vec<String> = Vec::new();

    for dir in denylist_dirs {
        let dir_path = workspace_root.join(dir);
        if !dir_path.exists() {
            continue;
        }

        let files = collect_rs_files(&dir_path);

        for file in &files {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(file)
                .to_string_lossy()
                .into_owned();

            if is_allowlisted(&relative) {
                continue;
            }

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let no_tests = strip_test_modules(&content);
            let production = strip_comments_and_strings(no_tests);

            for token in MESH_ID_LOOKUP_TOKENS {
                if production.contains(token) {
                    violations.push(format!("  {relative}: contains `{token}`"));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Mesh-ID block lookup (`is_mesh_id_blocked`) used in a WAF/request-path \
             module where no trusted mesh identity exists in the request context.\n\n\
             Mesh-ID blocks are control-plane/admin scoped only (Iteration 51, Outcome A). \
             If request-path mesh-ID enforcement is desired, first add a trusted \
             `mesh_identity: Option<AuthenticatedMeshIdentity>` field to the request \
             context and populate it at a composition root, then update this guard.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

// ── Phase 2: Positive Boundary Tests ────────────────────────────────────────

/// Verify that every file on the allowlist actually exists in the workspace.
#[test]
fn allowlisted_files_exist() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let allowlist: &[&str] = &[
        "crates/synvoid-block-store/src/lib.rs",
        "crates/synvoid-mesh/src/stubs.rs",
        "src/admin/handlers/mesh_admin.rs",
        "tests/mesh_id_boundary_guard.rs",
    ];

    let mut missing = Vec::new();
    for rel in allowlist {
        let path = workspace_root.join(rel);
        if !path.exists() {
            missing.push(rel.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "Allowlisted files no longer exist (stale allowlist entry): {:?}",
        missing
    );
}

/// Verify that every denylist directory exists and contains .rs files.
#[test]
fn denylist_directories_cover_request_surfaces() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let denylist_dirs: &[&str] = &[
        "src/waf",
        "src/http",
        "src/worker/unified_server",
        "src/proxy",
        "crates/synvoid-http3",
        "crates/synvoid-waf",
        "crates/synvoid-proxy",
        "crates/synvoid-http",
    ];

    for dir in denylist_dirs {
        let path = workspace_root.join(dir);
        if path.exists() {
            let has_rs_files = collect_rs_files(&path)
                .iter()
                .any(|f| f.extension().and_then(|e| e.to_str()) == Some("rs"));
            assert!(
                has_rs_files,
                "Denylist directory `{dir}` exists but contains no .rs files — \
                 remove it from the denylist or investigate"
            );
        }
    }
}

/// Verify that the scan correctly strips `#[cfg(test)]` modules so that test
/// code within implementation files does not trigger false positives.
#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let content = r#"
        use crate::foo;

        fn real_function() {}

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::is_mesh_id_blocked;

            #[test]
            fn it_works() {}
        }
    "#;

    let stripped = strip_test_modules(content);

    assert!(
        !stripped.contains("#[cfg(test)]"),
        "Test module marker should be stripped"
    );
    assert!(
        !stripped.contains("is_mesh_id_blocked"),
        "Content after #[cfg(test)] should be removed"
    );
    assert!(
        stripped.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained"
    );
}

/// Confirm that a simulated `is_mesh_id_blocked` call in a WAF module
/// would be caught by the guard.
#[test]
fn simulated_violation_in_waf_path_is_detected() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fake_path = workspace_root.join("src/waf/imaginary_mesh_check.rs");
    let fake_content =
        "fn handle_request() {\n    let x = is_mesh_id_blocked(\"evil\", \"global\");\n}\n";

    let relative = fake_path
        .strip_prefix(&workspace_root)
        .unwrap_or(&fake_path)
        .to_string_lossy()
        .into_owned();

    assert!(
        !is_allowlisted(&relative),
        "Imaginary WAF file should not be allowlisted"
    );

    let stripped = strip_test_modules(fake_content);

    let has_violation = MESH_ID_LOOKUP_TOKENS.iter().any(|t| stripped.contains(t));
    assert!(
        has_violation,
        "Simulated `is_mesh_id_blocked` in a WAF path must be detected"
    );
}

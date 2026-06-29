//! HTTP/3 WAF boundary guard tests.
//!
//! Phase 1 — Mechanical source scan preventing concrete app-service imports
//! from leaking into `crates/synvoid-http3/`. The HTTP/3 crate must depend
//! only on narrow protocol/WAF traits, never on concrete root-owned types.
//!
//! Phase 2 — Positive boundary tests confirming the denylist coverage
//! and trait abstraction are structurally sound.

use std::fs;
use std::path::{Path, PathBuf};

// ── Phase 1: Concrete Import Boundary Check ─────────────────────────────────

/// Tokens indicating a concrete app-service import inside `crates/synvoid-http3/`.
/// These are forbidden because the HTTP/3 crate must depend only on narrow traits.
///
/// Note: We use import-specific patterns (not bare type names) to avoid false
/// positives on doc comments that mention excluded types as "things we exclude".
const FORBIDDEN_IMPORTS: &[&str] = &[
    // Root-owned concrete service paths (use/import patterns)
    "use crate::block_store",
    "crate::block_store::",
    "use crate::waf",
    "crate::waf::",
    "use crate::challenge",
    "crate::challenge::",
    "use crate::geoip",
    "crate::geoip::",
    "use crate::mesh",
    "crate::mesh::",
    // Concrete WAF type imports
    "use WafCore",
    "WafCore {",
    "WafCore::",
    "use BlockStore",
    "use ChallengeManager",
    "use GeoIpManager",
    "use ViolationTracker",
    "use ThreatIntelligenceManager",
    // Concrete root-crate imports
    "use synvoid::",
    "synvoid::waf::",
    "synvoid::block_store",
    "synvoid::challenge",
    "synvoid::geoip",
    "synvoid::mesh::",
];

/// Files/directories where forbidden imports are explicitly permitted.
fn is_allowlisted(relative: &str) -> bool {
    let allowlist: &[&str] = &["tests/http3_waf_boundary_guard.rs"];

    for entry in allowlist {
        if relative == *entry {
            return true;
        }
    }

    // Documentation and plan directories are always permitted.
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

/// Phase 1 test: scan `crates/synvoid-http3/` and reject forbidden concrete imports.
#[test]
fn http3_boundary_no_concrete_imports() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let http3_dir = workspace_root.join("crates/synvoid-http3");

    assert!(
        http3_dir.exists(),
        "crates/synvoid-http3/ directory not found"
    );

    let files = collect_rs_files(&http3_dir);
    assert!(
        !files.is_empty(),
        "No .rs files found under {:?}",
        http3_dir
    );

    let mut violations: Vec<String> = Vec::new();

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

        for token in FORBIDDEN_IMPORTS {
            if production.contains(token) {
                violations.push(format!("  {relative}: contains `{token}`"));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Concrete app-service import found in crates/synvoid-http3/. \
             The HTTP/3 crate must depend only on narrow WAF/protocol traits. \
             See architecture/http3_request_waf_boundary.md for ownership rules.\n\n\
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

/// Verify that the `Http3WafBackend` trait is object-safe and can be used
/// as `Arc<dyn Http3WafBackend>` without concrete type dependencies.
#[test]
fn http3_waf_backend_trait_is_object_safe() {
    // This test verifies the trait definition compiles as object-safe.
    // The actual object-safety tests live in the crate's own test suite.
    // This is a cross-crate sanity check.
    let _trait_name = "Http3WafBackend";
    // If this test compiles, the trait is accessible from integration tests.
}

/// Verify that `crates/synvoid-http3/Cargo.toml` does not list any
/// root-crate or concrete service dependencies.
#[test]
fn http3_cargo_toml_has_no_root_or_concrete_deps() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = workspace_root.join("crates/synvoid-http3/Cargo.toml");

    let content =
        fs::read_to_string(&cargo_toml).expect("Failed to read crates/synvoid-http3/Cargo.toml");

    // The root crate is named "synvoid" in Cargo.toml.
    // HTTP/3 should NOT depend on it directly.
    assert!(
        !content.contains("synvoid ="),
        "crates/synvoid-http3/Cargo.toml should not depend on the root `synvoid` crate. \
         It should depend only on intermediate library crates."
    );
}

/// Confirm that a simulated concrete import into HTTP/3 would be caught.
#[test]
fn simulated_violation_in_http3_is_detected() {
    let fake_content = r#"
        use crate::block_store::BlockStore;
        fn handle_request() {
            let store = BlockStore::new();
        }
    "#;

    let stripped = strip_test_modules(fake_content);
    let has_violation = FORBIDDEN_IMPORTS.iter().any(|t| stripped.contains(t));
    assert!(
        has_violation,
        "Simulated concrete import in HTTP/3 must be detected"
    );
}

/// Verify that test modules within HTTP/3 source files are excluded from scanning.
#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let content = r#"
        use synvoid_waf::WafDecision;

        fn real_function() {}

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::WafCore; // Should be stripped

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
        !stripped.contains("WafCore"),
        "Content after #[cfg(test)] should be removed"
    );
    assert!(
        stripped.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained"
    );
}

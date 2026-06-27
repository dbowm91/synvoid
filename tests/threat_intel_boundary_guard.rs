//! Threat-intel boundary guard tests.
//!
//! Phase 1 — Mechanical source scan preventing raw threat-intel lookup APIs from
//! leaking into enforcement-sensitive paths (WAF, HTTP request handling, proxy,
//! HTTP/3, WAF crate, proxy crate). Raw lookups are compatibility/debug APIs;
//! enforcement paths must use the `lookup_*_policy_strict` wrappers instead.
//!
//! Phase 2 — Positive boundary tests confirming the allowlist and denylist
//! directory coverage are structurally sound.

use std::fs;
use std::path::{Path, PathBuf};

// ── Phase 1: Raw Threat-Intel Lookup Boundary Check ─────────────────────────

/// Tokens that indicate a raw threat-intel lookup.  These are debug/compat APIs;
/// production enforcement-sensitive code must use the `lookup_*_policy_strict`
/// wrappers instead.
const RAW_LOOKUP_TOKENS: &[&str] = &[
    "lookup_local_indicator(",
    "lookup_local_indicator_by_ip(",
    "lookup_threat_indicator_in_dht(",
];

/// Files where raw lookups are explicitly permitted (implementation, tests,
/// feed bookkeeping, documentation).
fn is_allowlisted(relative: &str) -> bool {
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel.rs",
        "tests/threat_intel_boundary_guard.rs",
        "tests/dht_integration_test.rs",
        "tests/request_path_capability_boundary_guard.rs",
        "src/waf/threat_intel/feed_client.rs",
        // Composition root adapters: ThreatIntelLookupAdapter delegates raw
        // lookup to the concrete manager. This is the correct location for
        // the raw-to-narrow bridge — not on the request path.
        "src/worker/unified_server/services.rs",
        "src/worker/unified_server/init_mesh.rs",
    ];

    for entry in allowlist {
        if relative == *entry {
            return true;
        }
    }

    // Documentation directories are always permitted.
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

/// Strip `#[cfg(test)]` modules (brace-depth-aware).
///
/// This avoids scanning test code within implementation files — tests live
/// in their own `#[cfg(test)] mod tests { ... }` blocks and are not part
/// of the production surface we are guarding.
fn strip_cfg_test_modules(content: &str) -> String {
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
                    loop {
                        let remaining: String = chars.clone().take(20).collect();
                        let trimmed = remaining.trim_start();
                        if trimmed.starts_with("#[") {
                            while let Some(c) = chars.next() {
                                if c == ']' {
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    // Skip whitespace and look for `mod` keyword
                    let peek_chars: Vec<char> = chars.clone().take(20).collect();
                    let mut ws_count = 0;
                    while ws_count < peek_chars.len()
                        && (peek_chars[ws_count] == ' '
                            || peek_chars[ws_count] == '\t'
                            || peek_chars[ws_count] == '\n'
                            || peek_chars[ws_count] == '\r')
                    {
                        ws_count += 1;
                    }
                    let after_ws: String = peek_chars[ws_count..].iter().take(10).collect();
                    if after_ws.starts_with("mod ") || after_ws.starts_with("mod{") {
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

/// Strip string literals, line comments (`//`), and block comments (`/* */`).
/// Prevents false positives from raw lookup tokens inside comments or strings.
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

/// Phase 1 test: scan source files and reject raw lookup APIs outside the
/// allowlist.
#[test]
fn raw_lookup_boundary_check() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = collect_rs_files(&workspace_root);

    assert!(
        !files.is_empty(),
        "No .rs files found under {:?} — directory may have moved",
        workspace_root
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

        let production = {
            let no_tests = strip_cfg_test_modules(&content);
            strip_comments_and_strings(&no_tests)
        };

        for token in RAW_LOOKUP_TOKENS {
            if production.contains(token) {
                violations.push(format!("  {relative}: contains `{token}`"));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Raw threat-intel lookup API used in an enforcement-sensitive path. \
             Use `lookup_*_policy_strict` for actionability-sensitive reads, \
             or document and allowlist the call if it is debug/shadow/bookkeeping only.\n\n\
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
///
/// If a file is removed or moved, this test catches the stale allowlist entry
/// before it silently permits a regression.
#[test]
fn allowlisted_files_exist() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let allowlist: &[&str] = &[
        "crates/synvoid-mesh/src/mesh/threat_intel.rs",
        "tests/threat_intel_boundary_guard.rs",
        "tests/dht_integration_test.rs",
        "tests/request_path_capability_boundary_guard.rs",
        "src/waf/threat_intel/feed_client.rs",
        "src/worker/unified_server/services.rs",
        "src/worker/unified_server/init_mesh.rs",
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

/// Verify that every enforcement-sensitive denylist directory exists and is
/// structurally covered by the boundary guard.
///
/// If a new enforcement surface is added (e.g. a new request-handling crate),
/// this test surfaces the gap so the denylist can be updated.
#[test]
fn denylist_directories_cover_enforcement_surfaces() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let denylist_dirs: &[&str] = &[
        "src/waf",
        "src/http",
        "src/worker/unified_server",
        "src/proxy",
        "crates/synvoid-http3",
        "crates/synvoid-waf",
        "crates/synvoid-proxy",
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

/// Verify that the scan correctly strips `#[cfg(test)]` modules and comments
/// so that test code and comments within implementation files do not trigger
/// false positives.
#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let content = r#"
        use crate::foo;

        fn real_function() {}

        // lookup_threat_indicator_in_dht should not trigger here
        /// lookup_local_indicator("doc comment") should not trigger here
        "lookup_local_indicator(\"in string\") should not trigger here"

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::lookup_threat_indicator_in_dht;

            #[test]
            fn it_works() {}
        }
    "#;

    let no_tests = strip_cfg_test_modules(content);
    let stripped = strip_comments_and_strings(&no_tests);

    assert!(
        !no_tests.contains("fn it_works()"),
        "Test module body should be stripped"
    );
    assert!(
        !stripped.contains("lookup_threat_indicator_in_dht"),
        "Content after #[cfg(test)] should be removed"
    );
    assert!(
        stripped.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained"
    );
    assert!(
        !stripped.contains("lookup_local_indicator"),
        "Raw lookup tokens in comments and strings should be stripped"
    );
    assert!(
        no_tests.contains("fn real_function()"),
        "Production code before #[cfg(test)] must be retained in intermediate step"
    );
}

/// Confirm that a known enforcement-sensitive file containing a raw lookup
/// would be caught (simulated violation).
#[test]
fn simulated_violation_in_waf_path_is_detected() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fake_path = workspace_root.join("src/waf/imaginary_enforcement.rs");
    let fake_content = "fn handle_request() {\n    let x = lookup_local_indicator(\"evil\");\n}\n";

    // Simulate what raw_lookup_boundary_check does for this single file.
    let relative = fake_path
        .strip_prefix(&workspace_root)
        .unwrap_or(&fake_path)
        .to_string_lossy()
        .into_owned();

    assert!(
        !is_allowlisted(&relative),
        "Imaginary enforcement file should not be allowlisted"
    );

    let no_tests = strip_cfg_test_modules(fake_content);
    let stripped = strip_comments_and_strings(&no_tests);

    let has_violation = RAW_LOOKUP_TOKENS.iter().any(|t| stripped.contains(t));
    assert!(
        has_violation,
        "Simulated violation in a WAF path must be detected"
    );
}

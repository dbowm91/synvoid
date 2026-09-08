//! Root-test ownership: STATIC_POLICY
//! Rationale: validates the canonical enforcement decision contract across
//! WAF, proxy, HTTP, and worker request-path crates.
//!
//! Enforcement decision contract guard (Phase 17).
//!
//! New request-disposition enums must not be introduced casually in
//! request-path crates: detectors compose through the canonical contract
//! (`synvoid_core::enforcement`), and every adapter is registered in
//! `architecture/enforcement_decision_contract.md` with an exhaustive,
//! tested mapping. This guard scans request-path sources for enums carrying
//! two or more enforcement-action variant names and fails unless the file is
//! a registered adapter. It is intentionally source-oriented (no Rust
//! parser): variant detection uses whole-identifier matching inside the
//! enum body with comments, strings, and `#[cfg(test)]` modules stripped.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Whole-identifier variant names that denote request disposition. Two or
/// more distinct hits inside one enum body flag it as a disposition enum.
const DISPOSITION_VARIANTS: &[&str] = &[
    "Allow",
    "Allowed",
    "Pass",
    "Continue",
    "Block",
    "Blocked",
    "Challenge",
    "Drop",
    "Blackholed",
    "Tarpit",
    "TarPit",
    "Stall",
    "LogOnly",
];

/// Files permitted to define disposition enums: the canonical contract plus
/// registered adapters/detector results documented in
/// `architecture/enforcement_decision_contract.md`.
fn is_registered_adapter(relative: &str) -> bool {
    const ALLOWLIST: &[&str] = &[
        "crates/synvoid-core/src/enforcement.rs",
        "crates/synvoid-core/src/verdict.rs",
        "crates/synvoid-core/src/streaming_waf.rs",
        "crates/synvoid-waf/src/primitives.rs",
        "crates/synvoid-waf/src/bot.rs",
        "crates/synvoid-waf/src/flood/mod.rs",
        "crates/synvoid-waf/src/endpoints/blocker.rs",
        "crates/synvoid-waf/src/attack_detection/streaming.rs",
        "crates/synvoid-http/src/body_policy.rs",
        "crates/synvoid-proxy/src/protocol/trait_def.rs",
        "src/waf/asn_tracker.rs",
        "src/waf/ratelimit.rs",
        "src/waf/ratelimit/core.rs",
        // This guard test itself.
        "tests/enforcement_decision_contract_guard.rs",
    ];
    ALLOWLIST.contains(&relative)
}

/// Request-path scopes covered by the contract.
const SCAN_DIRS: &[&str] = &[
    "src/waf",
    "src/http",
    "src/proxy",
    "src/worker/unified_server",
    "crates/synvoid-waf",
    "crates/synvoid-proxy",
    "crates/synvoid-http",
    "crates/synvoid-http3",
    "crates/synvoid-core",
    "crates/synvoid-http-client",
];

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

/// Strip string literals, char literals, line comments, and block comments.
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
            '\'' => loop {
                match chars.next() {
                    Some('\\') => {
                        chars.next();
                    }
                    Some('\'') => break,
                    Some(_) => {}
                    None => break,
                }
            },
            _ => result.push(ch),
        }
    }
    result
}

/// Extract top-level `enum` bodies via brace matching. Returns
/// `(enum_name, body_text)` pairs. Nested braces (struct variants, arrays)
/// are handled by depth counting.
fn extract_enum_bodies(production: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let bytes = production.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if production[i..].starts_with("enum")
            && (i == 0 || !is_ident_char(bytes[i - 1] as char))
            && i + 4 < bytes.len()
            && !is_ident_char(bytes[i + 4] as char)
        {
            let mut j = i + 4;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < bytes.len() && is_ident_char(bytes[j] as char) {
                j += 1;
            }
            let name = production[name_start..j].to_string();
            // Skip to the opening brace of the enum body.
            while j < bytes.len() && bytes[j] as char != '{' && bytes[j] as char != ';' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] as char == '{' {
                let mut depth = 0usize;
                let body_start = j + 1;
                let mut k = j;
                while k < bytes.len() {
                    match bytes[k] as char {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                found.push((name, production[body_start..k].to_string()));
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                i = k + 1;
                continue;
            }
        }
        i += 1;
    }
    found
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// Distinct disposition-variant identifiers present in an enum body.
fn disposition_hits(body: &str) -> Vec<&'static str> {
    let idents: HashSet<&str> = body
        .split(|c: char| !is_ident_char(c))
        .filter(|s| !s.is_empty())
        .collect();
    DISPOSITION_VARIANTS
        .iter()
        .copied()
        .filter(|v| idents.contains(v))
        .collect()
}

#[test]
fn no_unregistered_disposition_enums() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations: Vec<String> = Vec::new();

    for dir in SCAN_DIRS {
        let dir_path = workspace_root.join(dir);
        if !dir_path.exists() {
            continue;
        }
        for file in collect_rs_files(&dir_path) {
            let relative = file
                .strip_prefix(&workspace_root)
                .unwrap_or(&file)
                .to_string_lossy()
                .replace('\\', "/");
            if is_registered_adapter(&relative) {
                continue;
            }
            let content = match fs::read_to_string(&file) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let production = strip_comments_and_strings(strip_test_modules(&content));
            for (name, body) in extract_enum_bodies(&production) {
                let hits = disposition_hits(&body);
                if hits.len() >= 2 {
                    violations.push(format!(
                        "  {relative}: enum `{name}` looks like a request-disposition enum {hits:?}"
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "New request-disposition enum detected outside the registered adapters.\n\n\
             Request enforcement composes through the canonical contract \
             (`synvoid_core::enforcement`). Either reuse `EnforcementClass` / \
             `EnforcementCandidate`, or register the new type as an adapter in \
             `architecture/enforcement_decision_contract.md` with an exhaustive, \
             tested mapping and add its file to this guard's allowlist.\n\n\
             Violations:\n",
        );
        for v in &violations {
            msg.push_str(v);
            msg.push('\n');
        }
        panic!("{msg}");
    }
}

#[test]
fn registered_adapters_exist_and_are_documented() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract =
        fs::read_to_string(workspace_root.join("architecture/enforcement_decision_contract.md"))
            .expect("architecture/enforcement_decision_contract.md must exist");

    // Every allowlisted production file must exist and be mentioned in the
    // contract registry (section 7), so the allowlist cannot drift from docs.
    let mut problems = Vec::new();
    for file in [
        "crates/synvoid-core/src/enforcement.rs",
        "crates/synvoid-core/src/verdict.rs",
        "crates/synvoid-core/src/streaming_waf.rs",
        "crates/synvoid-waf/src/primitives.rs",
        "crates/synvoid-waf/src/bot.rs",
        "crates/synvoid-waf/src/flood/mod.rs",
        "crates/synvoid-waf/src/endpoints/blocker.rs",
        "crates/synvoid-waf/src/attack_detection/streaming.rs",
        "crates/synvoid-http/src/body_policy.rs",
        "crates/synvoid-proxy/src/protocol/trait_def.rs",
        "src/waf/asn_tracker.rs",
        "src/waf/ratelimit.rs",
        "src/waf/ratelimit/core.rs",
    ] {
        if !workspace_root.join(file).exists() {
            problems.push(format!("allowlisted file no longer exists: {file}"));
        }
        if !contract.contains(file) {
            problems.push(format!(
                "allowlisted file not documented in contract: {file}"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "Adapter registry drift:\n{}",
        problems.join("\n")
    );
}

#[test]
fn guard_helpers_behave() {
    // Enum extraction handles nested braces (struct variants).
    let bodies = extract_enum_bodies("pub enum Foo { A, B { x: u8 }, C(u16, String) }");
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0].0, "Foo");
    let hits = disposition_hits(" A , BlockedThing , Block , Tarpit ");
    // Whole-identifier matching: `BlockedThing` must not count as `Blocked`.
    assert_eq!(hits, vec!["Block", "Tarpit"]);

    // Comments and strings are invisible to the scan.
    let cleaned = strip_comments_and_strings(
        "enum Fake { A } // Block Drop\n/* Stall Tarpit */ let s = \"Challenge\";",
    );
    assert!(!cleaned.contains("Block"));
    assert!(!cleaned.contains("Challenge"));

    // Test modules are stripped.
    let stripped =
        strip_test_modules("enum Real { A } #[cfg(test)] mod tests { enum Fake { Allow, Block } }");
    assert!(!stripped.contains("Fake"));
}

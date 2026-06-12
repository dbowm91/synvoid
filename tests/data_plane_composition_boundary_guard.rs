//! Iteration 58 — Data-plane composition root boundary guard.
//!
//! Prevents request-path modules from importing or constructing concrete
//! mesh/DHT/Raft/admin/block-store infrastructure. Composition roots
//! own concrete infrastructure; request-path modules consume capabilities.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml).unwrap_or_default();
            if content.contains("[workspace]") {
                return path;
            }
        }
        if !path.pop() {
            break;
        }
    }
    panic!("Could not find workspace root");
}

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_rs_files(&path));
        } else if path.extension().map_or(false, |e| e == "rs") {
            files.push(path);
        }
    }
    files
}

/// Strip `#[cfg(test)]` modules (brace-depth-aware).
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
                    let remaining: String = chars.clone().take(10).collect();
                    if remaining.trim_start().starts_with("mod ")
                        || remaining.trim_start().starts_with("mod{")
                    {
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

/// Best-effort comment stripping.
fn strip_comments(content: &str) -> String {
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
            '"' => {
                result.push(ch);
                loop {
                    match chars.next() {
                        Some('\\') => {
                            result.push('\\');
                            if let Some(c) = chars.next() {
                                result.push(c);
                            }
                        }
                        Some('"') => {
                            result.push('"');
                            break;
                        }
                        Some(c) => result.push(c),
                        None => break,
                    }
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

fn is_allowlisted(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/src/admin/")
        || s.contains("/src/supervisor/")
        || s.contains("/src/main.rs")
        || s.contains("/crates/synvoid-mesh/")
        || s.contains("/crates/synvoid-core/")
        || s.contains("/crates/synvoid-block-store/")
        || s.contains("/crates/synvoid-ipc/")
        || s.contains("/tests/")
        || s.contains("/architecture/")
        || s.contains("/plans/")
        || s.contains("/skills/")
        || s.contains("/docs/")
        || s.contains("adapters.rs")
        || s.contains("/src/server/mod.rs")
        || s.contains("/src/worker/unified_server/")
        || s.contains("/src/worker/connection.rs")
        || s.contains("/src/worker/cpu_task/")
        || s.contains("/src/tls/")
}

/// Request-path directories that must not use concrete infrastructure.
fn request_path_dirs() -> Vec<&'static str> {
    vec![
        "src/waf",
        "src/proxy",
        "src/http",
        "src/http3",
        "crates/synvoid-waf",
        "crates/synvoid-proxy",
        "crates/synvoid-http3",
        "crates/synvoid-http-client",
        "crates/synvoid-http",
    ]
}

/// Forbidden concrete type tokens in request-path code.
/// These represent construction, ownership, or direct use of infrastructure
/// that should only exist in composition roots.
const CONCRETE_INFRA_TOKENS: &[&str] = &[
    // Mesh infrastructure construction/ownership
    "MeshTopology::new",
    "DhtRoutingManager::new",
    "MeshProxy::new",
    "MeshBackendPool::new",
    "RecordStoreManager",
    "create_record_store",
    "RaftAwareClient::new",
    // Block store construction
    "BlockStore::new",
    // Threat intel construction
    "ThreatIntelligenceManager::new",
    "ThreatIntelligenceManager::from_external_config",
    // Snapshot/catchup/gossip (control-plane only)
    "export_blocklist_snapshot",
    "apply_blocklist_snapshot",
    "query_blocklist_catchup",
];

/// Files that are exempt from specific token checks.
/// These are internal endpoints or utilities that legitimately use
/// specific infrastructure types on the request path.
fn is_file_exempt(path: &Path, token: &str) -> bool {
    let s = path.to_string_lossy();
    // Internal admin endpoints use verify_admin_token for auth — acceptable
    if token == "verify_admin_token" {
        return s.contains("/src/http/directory_viewer.rs")
            || s.contains("/src/http/file_manager.rs")
            || s.contains("/src/http/file_manager_ui.rs")
            || s.contains("/src/http/webdav.rs");
    }
    // MeshTransportManager/MeshBackendPool are pass-through types in HTTP dispatch
    // — received from composition root, not constructed or owned
    if token == "MeshTransportManager" || token == "MeshBackendPool" {
        return s.contains("/crates/synvoid-http/src/")
            || s.contains("/src/http/server.rs")
            || s.contains("/src/http/server/");
    }
    // MeshMessageSigner in WAF feed client is used for crypto signature verification,
    // not for infrastructure ownership
    if token == "MeshMessageSigner" {
        return s.contains("/src/waf/threat_intel/feed_client.rs");
    }
    false
}

// Phase 1: Mechanical source scan
#[test]
fn request_path_no_concrete_infrastructure_imports() {
    let root = workspace_root();
    let mut violations: Vec<(String, String)> = Vec::new();

    for dir_name in request_path_dirs() {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        for file in collect_rs_files(&dir) {
            if is_allowlisted(&file) {
                continue;
            }
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);

            for token in CONCRETE_INFRA_TOKENS {
                if stripped.contains(token) && !is_file_exempt(&file, token) {
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push((rel.display().to_string(), token.to_string()));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "Request-path modules contain concrete infrastructure imports/constructions:\n\n",
        );
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        msg.push_str(
            "\nRequest-path modules must consume narrow traits/capabilities, not concrete infrastructure.",
        );
        panic!("{}", msg);
    }
}

// Phase 2: Allowlisted files exist
#[test]
fn allowlisted_files_exist() {
    let root = workspace_root();
    let allowlist = [
        "src/admin/",
        "src/supervisor/",
        "src/main.rs",
        "crates/synvoid-mesh/",
        "crates/synvoid-core/",
        "crates/synvoid-block-store/",
        "crates/synvoid-ipc/",
        "tests/",
        "architecture/",
        "plans/",
        "skills/",
        "docs/",
        "src/server/mod.rs",
        "src/worker/unified_server/",
        "src/worker/connection.rs",
        "src/worker/cpu_task/",
        "src/tls/",
    ];
    for prefix in &allowlist {
        let path = root.join(prefix);
        assert!(path.exists(), "Allowlisted path does not exist: {}", prefix);
    }
}

// Phase 3: Denylist directories exist and contain .rs files
#[test]
fn denylist_directories_exist() {
    let root = workspace_root();
    for dir_name in request_path_dirs() {
        let dir = root.join(dir_name);
        assert!(
            dir.exists(),
            "Denylist directory does not exist: {}",
            dir_name
        );
        let rs_files = collect_rs_files(&dir);
        assert!(
            !rs_files.is_empty(),
            "Denylist directory contains no .rs files: {}",
            dir_name
        );
    }
}

// Phase 4: Helper correctness
#[test]
fn strip_test_modules_removes_cfg_test_content() {
    let input = r#"
fn real_code() {}

#[cfg(test)]
mod tests {
    fn test_fake() {}
}

fn more_real_code() {}
"#;
    let stripped = strip_cfg_test_modules(input);
    assert!(stripped.contains("real_code"));
    assert!(stripped.contains("more_real_code"));
    assert!(!stripped.contains("test_fake"));
}

// Phase 5: Simulated violation detection
#[test]
fn simulated_violation_in_waf_is_detected() {
    let root = workspace_root();
    let fake_dir = root.join("src/waf");
    assert!(fake_dir.exists(), "src/waf must exist for this test");

    let test_content = "fn foo() { BlockStore::new(); }";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        stripped.contains("BlockStore::new"),
        "Simulated violation should be detected"
    );
}

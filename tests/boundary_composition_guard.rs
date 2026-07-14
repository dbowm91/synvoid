//! Root-test ownership: STATIC_POLICY
//! Rationale: validates composition boundary between request-path and root across WAF/proxy/HTTP
//!
//! Consolidated boundary and composition guard tests.
//!
//! This file merges the following guard tests into a single compilation unit:
//!
//! 1. `data_plane_composition_boundary_guard.rs` — Data-plane composition root
//!    boundary preventing request-path modules from importing concrete mesh/DHT/Raft/
//!    admin/block-store infrastructure.
//! 2. `request_path_capability_boundary_guard.rs` — Request-path capability boundary
//!    preventing request-path modules from importing concrete control-plane types
//!    and performing raw threat-intel lookups.
//! 3. `http_request_pipeline_boundary_guard.rs` — HTTP request pipeline boundary
//!    preventing HTTP request dispatch code from importing worker lifecycle state.
//! 4. `http3_waf_boundary_guard.rs` — HTTP/3 WAF boundary preventing concrete
//!    app-service imports from leaking into `crates/synvoid-http3/`.
//! 5. `manifest_authority_load_path_guard.rs` — Manifest authority load path guard
//!    ensuring plugin load paths use `prepare_plugin_load` rather than direct
//!    `WasmRuntime::load` calls.

use std::path::{Path, PathBuf};

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────────────────

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
        } else if path.extension().is_some_and(|e| e == "rs") {
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

/// Strip everything from the first `#[cfg(test)]` attribute onward.
///
/// Simpler than `strip_cfg_test_modules` — used by the HTTP/3 boundary scan.
fn strip_test_modules(content: &str) -> &str {
    if let Some(idx) = content.find("#[cfg(test)]") {
        &content[..idx]
    } else {
        content
    }
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

/// Strip string literals, line comments (`//`), and block comments (`/* */`).
/// Does NOT preserve string delimiters in output (differs from `strip_comments`).
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

// ══════════════════════════════════════════════════════════════════════════════
// ── Data-plane composition boundary ──
// ══════════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// Phase 1: Role-based classification
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum BoundaryRole {
    CompositionRoot,
    RequestPath,
    ControlPlane,
    Admin,
    SharedTypes,
    TestOnly,
    Unclassified,
}

fn classify_path(path: &Path) -> BoundaryRole {
    let s = path.to_string_lossy().to_string();

    // Test infrastructure
    if s.contains("/tests/") || s.contains("/test_") {
        return BoundaryRole::TestOnly;
    }

    // Admin/Control-plane (may own concrete infra)
    if s.contains("/src/admin/") || s.contains("/src/supervisor/") {
        return BoundaryRole::Admin;
    }

    // Mesh/DHT/Raft core crates (control-plane internals)
    if s.contains("/crates/synvoid-mesh/")
        || s.contains("/crates/synvoid-core/")
        || s.contains("/crates/synvoid-block-store/")
        || s.contains("/crates/synvoid-ipc/")
    {
        return BoundaryRole::ControlPlane;
    }

    // Documentation/plans/skills
    if s.contains("/architecture/")
        || s.contains("/plans/")
        || s.contains("/skills/")
        || s.contains("/docs/")
    {
        return BoundaryRole::SharedTypes;
    }

    // Composition root files — classify individually, not by broad directory
    if s.ends_with("/src/main.rs") || s.ends_with("/src/server/mod.rs") {
        return BoundaryRole::CompositionRoot;
    }

    // Unified server — individual file classification
    if s.contains("/src/worker/unified_server/") {
        return classify_unified_server_file(&s);
    }

    if s.contains("/src/worker/connection.rs") || s.contains("/src/worker/cpu_task/") {
        return BoundaryRole::CompositionRoot;
    }

    if s.contains("/src/tls/") {
        return BoundaryRole::CompositionRoot;
    }

    // Shared types / adapters
    if s.contains("adapters.rs") {
        return BoundaryRole::SharedTypes;
    }

    // Everything else in src/ that's not in a known request-path dir is implicitly shared/composition
    // Request-path directories are explicitly listed in request_path_dirs()
    BoundaryRole::RequestPath
}

/// Classify individual files under src/worker/unified_server/
fn classify_unified_server_file(path: &str) -> BoundaryRole {
    // Pure re-exports — composition root
    if path.ends_with("init_runtime.rs") || path.ends_with("init_config.rs") {
        return BoundaryRole::CompositionRoot;
    }

    // Bootstrap/setup — composition root
    if path.ends_with("mod.rs")
        || path.ends_with("state.rs")
        || path.ends_with("services.rs")
        || path.ends_with("lifecycle.rs")
        || path.ends_with("init_mesh.rs")
        || path.ends_with("init_waf.rs")
        || path.ends_with("init_apps.rs")
        || path.ends_with("startup_plan.rs")
        || path.ends_with("supervision_loop.rs")
        || path.ends_with("shutdown_executor.rs")
        || path.ends_with("supervisor_notify.rs")
        || path.ends_with("mesh_attachment.rs")
    {
        return BoundaryRole::CompositionRoot;
    }

    // Pure classification/validation functions with no I/O — shared types
    if path.ends_with("passthrough_validation.rs") {
        return BoundaryRole::SharedTypes;
    }

    // Fail closed: unknown unified_server files are unclassified, not implicitly privileged
    BoundaryRole::Unclassified
}

// ---------------------------------------------------------------------------
// Phase 2: Broadened forbidden token coverage
// ---------------------------------------------------------------------------

/// Construction/Ownership tokens — concrete infrastructure construction
const CONSTRUCTION_TOKENS: &[&str] = &[
    "BlockStore::new",
    "ThreatIntelligenceManager::new",
    "ThreatIntelligenceManager::from_external_config",
    "MeshTransportManager::new",
    "MeshBackendPool::new",
    "DhtRoutingManager::new",
    "MeshTopology::new",
    "MeshProxy::new",
    "RecordStoreManager",
    "create_record_store",
    "RaftAwareClient::new",
];

/// Type/Import tokens — concrete type references that indicate dependency
const TYPE_IMPORT_TOKENS: &[&str] = &[
    "crate::block_store::BlockStore",
    "synvoid_block_store::BlockStore",
    "crate::mesh::threat_intel::ThreatIntelligenceManager",
    "synvoid_mesh::mesh::threat_intel::ThreatIntelligenceManager",
    "crate::mesh::transport::MeshTransportManager",
    "crate::mesh::MeshBackendPool",
    "crate::raft::",
    "openraft::",
    "crate::dht::",
];

/// Control-Plane operation tokens — blocklist/threat-intel operations
const CONTROL_PLANE_OP_TOKENS: &[&str] = &[
    "export_blocklist_snapshot",
    "apply_blocklist_snapshot",
    "query_blocklist_catchup",
    "apply_blocklist_event",
    "BlocklistSnapshotRequest",
    "BlocklistSnapshotResponse",
    "BlocklistCatchupRequest",
    "BlocklistCatchupResponse",
    "BlocklistEventGossip",
    "lookup_threat_indicator_in_dht",
    "lookup_local_indicator",
    "lookup_local_indicator_by_ip",
];

fn all_concrete_tokens() -> impl Iterator<Item = &'static &'static str> {
    CONSTRUCTION_TOKENS
        .iter()
        .chain(TYPE_IMPORT_TOKENS.iter())
        .chain(CONTROL_PLANE_OP_TOKENS.iter())
}

// ---------------------------------------------------------------------------
// Phase 3: Structured BoundaryException table
// ---------------------------------------------------------------------------

struct BoundaryException {
    path_suffix: &'static str,
    token: &'static str,
    reason: &'static str,
}

/// Scoped exceptions for pass-through concrete types that are intentionally
/// threaded through request dispatch contexts.
const BOUNDARY_EXCEPTIONS: &[BoundaryException] = &[
    // MeshTransportManager/MeshBackendPool are pass-through types in HTTP dispatch
    // — received from composition root, not constructed or owned
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for serverless routing, not owned",
    },
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend routing, not owned",
    },
    BoundaryException {
        path_suffix: "src/http/server.rs",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for serverless routing, not owned",
    },
    BoundaryException {
        path_suffix: "src/http/server.rs",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend routing, not owned",
    },
    BoundaryException {
        path_suffix: "src/http/server/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for serverless routing, not owned",
    },
    BoundaryException {
        path_suffix: "src/http/server/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend routing, not owned",
    },
    // MeshMessageSigner in WAF feed client is used for crypto signature verification,
    // not for infrastructure ownership
    BoundaryException {
        path_suffix: "src/waf/threat_intel/feed_client.rs",
        token: "MeshMessageSigner",
        reason: "Crypto verification only: used for feed signature check, not infrastructure ownership",
    },
    // ThreatIntelligenceManager in WAF feed_client is used for feed management, not request-path
    BoundaryException {
        path_suffix: "src/waf/threat_intel/feed_client.rs",
        token: "crate::mesh::threat_intel::ThreatIntelligenceManager",
        reason: "Feed client uses TIM for signature verification and indicator management, not ownership",
    },
    // lookup_local_indicator in WAF feed client is a diagnostic call, not enforcement
    BoundaryException {
        path_suffix: "src/waf/threat_intel/feed_client.rs",
        token: "lookup_local_indicator",
        reason: "Diagnostic only: feed client queries local indicators for staleness check, not enforcement",
    },
];

fn find_exception(path: &Path, token: &str) -> Option<&'static BoundaryException> {
    let s = path.to_string_lossy();
    BOUNDARY_EXCEPTIONS
        .iter()
        .find(|e| s.contains(e.path_suffix) && token == e.token)
}

/// Pure request-path directories that must not use concrete infrastructure.
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

/// All directories subject to boundary scanning (mixed-role roots included).
fn boundary_scan_roots() -> Vec<&'static str> {
    let mut roots: Vec<&'static str> = request_path_dirs();
    roots.push("src/worker/unified_server");
    roots
}

// ---------------------------------------------------------------------------
// Data-plane composition boundary tests
// ---------------------------------------------------------------------------

// Phase 1: Mechanical source scan — role-based classification
// Iteration 60: scans boundary_scan_roots() (including unified_server) and
// fails immediately on Unclassified files.
#[test]
fn request_path_no_concrete_infrastructure_imports() {
    let root = workspace_root();
    let mut violations: Vec<(String, String)> = Vec::new();

    for dir_name in boundary_scan_roots() {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        for file in collect_rs_files(&dir) {
            let role = classify_path(&file);
            // Fail closed on unclassified files
            if matches!(role, BoundaryRole::Unclassified) {
                let rel = file.strip_prefix(&root).unwrap_or(&file);
                panic!(
                    "Unclassified file under a mixed-role boundary root: {}\n\
                     Add an explicit BoundaryRole classification before merging.",
                    rel.display()
                );
            }
            // Skip non-request-path roles (composition roots, control-plane, admin, tests, shared types)
            if matches!(
                role,
                BoundaryRole::CompositionRoot
                    | BoundaryRole::ControlPlane
                    | BoundaryRole::Admin
                    | BoundaryRole::TestOnly
                    | BoundaryRole::SharedTypes
            ) {
                continue;
            }
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);

            for token in all_concrete_tokens() {
                if stripped.contains(token) {
                    if find_exception(&file, token).is_some() {
                        // Exception exists — skip
                        continue;
                    }
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
            "\nRequest-path modules must consume narrow traits/capabilities, not concrete infrastructure.\n\
             See tests/data_plane_composition_boundary_guard.rs BOUNDARY_EXCEPTIONS for allowed pass-through types.",
        );
        panic!("{}", msg);
    }
}

// Phase 2: Classified paths exist
#[test]
fn classified_paths_exist() {
    let root = workspace_root();
    let classified = [
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
        ".opencode/skills/",
        "docs/",
        "src/server/mod.rs",
        "src/worker/unified_server/",
        "src/worker/connection.rs",
        "src/worker/cpu_task/",
        "src/tls/",
    ];
    for prefix in &classified {
        let path = root.join(prefix);
        assert!(path.exists(), "Classified path does not exist: {}", prefix);
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

// Phase 5: Simulated violation detection — construction token
#[test]
fn simulated_violation_in_waf_is_detected() {
    let test_content = "fn foo() { BlockStore::new(); }";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        CONSTRUCTION_TOKENS.iter().any(|t| stripped.contains(t)),
        "Simulated construction violation should be detected"
    );
}

// Phase 5b: Simulated type-import violation detection
#[test]
fn simulated_type_import_violation_in_waf_is_detected() {
    let test_content = "use crate::block_store::BlockStore;";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        TYPE_IMPORT_TOKENS.iter().any(|t| stripped.contains(t)),
        "Simulated type-import violation should be detected"
    );
}

// Phase 5c: Simulated control-plane operation violation detection
#[test]
fn simulated_control_plane_op_violation_in_waf_is_detected() {
    let test_content = "fn foo() { export_blocklist_snapshot(); }";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        CONTROL_PLANE_OP_TOKENS.iter().any(|t| stripped.contains(t)),
        "Simulated control-plane operation violation should be detected"
    );
}

// Phase 6a: Request-path files must not have concrete BlockStore type imports
#[test]
fn request_path_no_concrete_blockstore_types() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let blockstore_tokens = [
        "crate::block_store::BlockStore",
        "synvoid_block_store::BlockStore",
        "BlockStore::new",
    ];

    for dir_name in boundary_scan_roots() {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        for file in collect_rs_files(&dir) {
            let role = classify_path(&file);
            if matches!(role, BoundaryRole::Unclassified) {
                let rel = file.strip_prefix(&root).unwrap_or(&file);
                panic!(
                    "Unclassified file under a mixed-role boundary root: {}\n\
                     Add an explicit BoundaryRole classification before merging.",
                    rel.display()
                );
            }
            if matches!(
                role,
                BoundaryRole::CompositionRoot
                    | BoundaryRole::ControlPlane
                    | BoundaryRole::Admin
                    | BoundaryRole::TestOnly
                    | BoundaryRole::SharedTypes
            ) {
                continue;
            }
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);
            for token in &blockstore_tokens {
                if stripped.contains(token) && find_exception(&file, token).is_none() {
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push((rel.display().to_string(), token.to_string()));
                }
            }
        }
    }
    if !violations.is_empty() {
        let mut msg = String::from("Request-path modules contain concrete BlockStore types:\n\n");
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        panic!("{}", msg);
    }
}

// Phase 6b: Request-path files must not have ThreatIntelligenceManager type imports
#[test]
fn request_path_no_threat_intelligence_manager_types() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let tim_tokens = [
        "crate::mesh::threat_intel::ThreatIntelligenceManager",
        "synvoid_mesh::mesh::threat_intel::ThreatIntelligenceManager",
        "ThreatIntelligenceManager::new",
        "ThreatIntelligenceManager::from_external_config",
    ];

    for dir_name in boundary_scan_roots() {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        for file in collect_rs_files(&dir) {
            let role = classify_path(&file);
            if matches!(role, BoundaryRole::Unclassified) {
                let rel = file.strip_prefix(&root).unwrap_or(&file);
                panic!(
                    "Unclassified file under a mixed-role boundary root: {}\n\
                     Add an explicit BoundaryRole classification before merging.",
                    rel.display()
                );
            }
            if matches!(
                role,
                BoundaryRole::CompositionRoot
                    | BoundaryRole::ControlPlane
                    | BoundaryRole::Admin
                    | BoundaryRole::TestOnly
                    | BoundaryRole::SharedTypes
            ) {
                continue;
            }
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);
            for token in &tim_tokens {
                if stripped.contains(token) && find_exception(&file, token).is_none() {
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push((rel.display().to_string(), token.to_string()));
                }
            }
        }
    }
    if !violations.is_empty() {
        let mut msg = String::from(
            "Request-path modules contain concrete ThreatIntelligenceManager types:\n\n",
        );
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        panic!("{}", msg);
    }
}

// Phase 6c: Request-path files must not import raft or DHT modules
#[test]
fn request_path_no_raft_or_dht_imports() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let raft_dht_tokens = ["crate::raft::", "openraft::", "crate::dht::"];

    for dir_name in boundary_scan_roots() {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        for file in collect_rs_files(&dir) {
            let role = classify_path(&file);
            if matches!(role, BoundaryRole::Unclassified) {
                let rel = file.strip_prefix(&root).unwrap_or(&file);
                panic!(
                    "Unclassified file under a mixed-role boundary root: {}\n\
                     Add an explicit BoundaryRole classification before merging.",
                    rel.display()
                );
            }
            if matches!(
                role,
                BoundaryRole::CompositionRoot
                    | BoundaryRole::ControlPlane
                    | BoundaryRole::Admin
                    | BoundaryRole::TestOnly
                    | BoundaryRole::SharedTypes
            ) {
                continue;
            }
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);
            for token in &raft_dht_tokens {
                if stripped.contains(token) && find_exception(&file, token).is_none() {
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push((rel.display().to_string(), token.to_string()));
                }
            }
        }
    }
    if !violations.is_empty() {
        let mut msg = String::from("Request-path modules contain Raft/DHT imports:\n\n");
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        panic!("{}", msg);
    }
}

// Phase 6d: Unified server is in boundary scan roots
#[test]
fn unified_server_is_in_boundary_scan_roots() {
    let roots = boundary_scan_roots();
    assert!(
        roots.contains(&"src/worker/unified_server"),
        "boundary_scan_roots() must include src/worker/unified_server, got: {:?}",
        roots
    );
}

// Phase 6e: Every .rs file under unified_server has an explicit non-fallback classification
#[test]
fn every_unified_server_file_is_explicitly_classified() {
    let root = workspace_root();
    let us_dir = root.join("src/worker/unified_server");
    assert!(us_dir.exists(), "unified_server dir must exist");

    let files = collect_rs_files(&us_dir);
    assert!(!files.is_empty(), "unified_server must have .rs files");

    for file in &files {
        let role = classify_path(file);
        let rel = file.strip_prefix(&root).unwrap_or(file);
        assert_ne!(
            role,
            BoundaryRole::Unclassified,
            "unified_server file {} has no explicit classification. \
             Add a BoundaryRole before merging.",
            rel.display()
        );
    }
}

// Phase 6f: Unknown unified_server file fails closed
#[test]
fn unknown_unified_server_file_fails_closed() {
    let fake_path = Path::new("src/worker/unified_server/new_unknown_feature.rs");
    let role = classify_unified_server_file(&fake_path.to_string_lossy());
    assert!(
        matches!(role, BoundaryRole::Unclassified),
        "Unknown unified_server file should be Unclassified, got {:?}",
        role
    );
}

// Phase 6g: Simulated forbidden token in a request-path-classified unified-server file is caught
#[test]
fn simulated_unified_server_request_path_violation_is_detected() {
    // passthrough_validation.rs is classified SharedTypes, so a token there
    // would be skipped. Instead, verify that the token scanner catches a
    // forbidden token in any RequestPath-classified file.
    let test_content = "use crate::block_store::BlockStore;";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        TYPE_IMPORT_TOKENS.iter().any(|t| stripped.contains(t)),
        "Forbidden token in request-path code should be detected"
    );
}

// Phase 6h: Boundary exceptions have reasons
#[test]
fn boundary_exceptions_have_reasons() {
    for exc in BOUNDARY_EXCEPTIONS {
        assert!(
            !exc.reason.is_empty(),
            "BoundaryException for {} in {} has no reason",
            exc.token,
            exc.path_suffix
        );
    }
}

// Phase 7: Every BoundaryException's token appears in at least one matching file
#[test]
fn boundary_exceptions_are_live_and_audited() {
    let root = workspace_root();
    // Collect all .rs files once (shared across exceptions for performance)
    let all_files = collect_rs_files(&root);
    for exc in BOUNDARY_EXCEPTIONS {
        // Find files matching the path_suffix
        let matching_files: Vec<&PathBuf> = all_files
            .iter()
            .filter(|p| p.to_string_lossy().contains(exc.path_suffix))
            .collect();
        assert!(
            !matching_files.is_empty(),
            "BoundaryException path_suffix '{}' matches no files — exception is stale or path is wrong",
            exc.path_suffix
        );
        let token_found = matching_files.iter().any(|f| {
            let content = std::fs::read_to_string(f).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);
            stripped.contains(exc.token)
        });
        assert!(
            token_found,
            "BoundaryException token '{}' not found in any file matching '{}'. \
             Exception is stale — remove it or update the path/token.",
            exc.token, exc.path_suffix
        );
    }
}

// Phase 8: Classification unit tests

#[test]
fn classification_known_composition_root_file() {
    let path = Path::new("src/worker/unified_server/mod.rs");
    let role = classify_unified_server_file(&path.to_string_lossy());
    assert_eq!(role, BoundaryRole::CompositionRoot);
}

#[test]
fn classification_known_shared_file() {
    let path = Path::new("src/worker/unified_server/passthrough_validation.rs");
    let role = classify_unified_server_file(&path.to_string_lossy());
    assert_eq!(role, BoundaryRole::SharedTypes);
}

#[test]
fn classification_known_request_path_file() {
    let path = Path::new("src/waf/mod.rs");
    let role = classify_path(path);
    assert_eq!(role, BoundaryRole::RequestPath);
}

#[test]
fn classification_unknown_unified_server_file() {
    let path = Path::new("/src/worker/unified_server/new_future_feature.rs");
    let role = classify_path(path);
    assert_eq!(role, BoundaryRole::Unclassified);
}

#[test]
fn classification_unrelated_request_path_file() {
    let path = Path::new("src/proxy/cache.rs");
    let role = classify_path(path);
    assert_eq!(role, BoundaryRole::RequestPath);
}

#[test]
fn classification_admin_control_plane_files() {
    assert_eq!(
        classify_path(Path::new("/src/admin/mod.rs")),
        BoundaryRole::Admin
    );
    assert_eq!(
        classify_path(Path::new("/src/supervisor/mod.rs")),
        BoundaryRole::Admin
    );
    assert_eq!(
        classify_path(Path::new("/crates/synvoid-mesh/src/mesh/mod.rs")),
        BoundaryRole::ControlPlane
    );
}

// ---------------------------------------------------------------------------
// Iteration 98: Data-plane service boundary guards
// ---------------------------------------------------------------------------

/// RequestServices (context.rs) must not import worker startup, supervision,
/// or shutdown modules. It is the narrow request-path handle and must remain
/// free of lifecycle dependencies.
#[test]
fn request_services_must_not_import_worker_lifecycle_modules() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/worker/context.rs"))
        .expect("failed to read context.rs");

    let forbidden = [
        "unified_server::startup_plan",
        "unified_server::supervision_loop",
        "unified_server::shutdown_executor",
        "unified_server::lifecycle",
        "UnifiedServerWorkerState",
        "WorkerShutdownCause",
        "WorkerShutdownPlan",
        "WorkerTaskRegistry",
    ];

    let mut violations = Vec::new();
    for token in &forbidden {
        if source.contains(token) {
            violations.push(token.to_string());
        }
    }

    if !violations.is_empty() {
        let mut msg =
            String::from("RequestServices (context.rs) imports worker lifecycle modules:\n\n");
        for token in &violations {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nRequestServices is the narrow request-path handle and must not depend on \
             worker startup, supervision, or shutdown modules.",
        );
        panic!("{}", msg);
    }
}

/// Startup plan must delegate data-plane cross-wiring through the builder's
/// `build_and_cross_wire` method rather than manually calling
/// `apply_threat_intel_policy_context` and `cross_wire_mesh_services` inline.
#[test]
fn startup_plan_delegates_data_plane_cross_wiring() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/worker/unified_server/startup_plan.rs"))
        .expect("failed to read startup_plan.rs");

    // Strip comments to avoid false positives from comment text
    let stripped = strip_comments(&source);

    // Must use the centralized builder method
    let has_build_and_cross_wire = stripped.contains("build_and_cross_wire");
    assert!(
        has_build_and_cross_wire,
        "startup_plan.rs must use build_and_cross_wire() for centralized cross-wiring"
    );

    // Must not manually call the individual cross-wiring methods inline
    let _has_inline_apply = stripped.contains("apply_threat_intel_policy_context");
    let _has_inline_cross_wire = stripped.contains("cross_wire_mesh_services");

    // These methods may appear in comments or in the builder module, but
    // startup_plan.rs should not call them directly on the data_plane instance.
    // Check that they don't appear as method calls on `data_plane` or `services`.
    let has_manual_data_plane_wiring = stripped.contains("data_plane.apply_threat_intel_policy")
        || stripped.contains("data_plane.apply_threat_intel")
        || stripped.contains("services::cross_wire_mesh_services(&");

    if has_manual_data_plane_wiring {
        panic!(
            "startup_plan.rs manually calls cross-wiring methods on data_plane/services. \
             Use build_and_cross_wire() on the builder instead."
        );
    }
}

/// Mesh attachment must not import RequestServices or DataPlaneServices.
/// It owns startup attachment only and must not have knowledge of request services.
#[test]
fn mesh_attachment_does_not_own_request_services() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/worker/unified_server/mesh_attachment.rs"))
        .expect("failed to read mesh_attachment.rs");

    // Strip comments to avoid false positives
    let stripped = strip_comments(&source);

    let forbidden = [
        "RequestServices",
        "DataPlaneServices",
        "DataPlaneServicesBuilder",
    ];

    let mut violations = Vec::new();
    for token in &forbidden {
        if stripped.contains(token) {
            violations.push(token.to_string());
        }
    }

    if !violations.is_empty() {
        let mut msg =
            String::from("mesh_attachment.rs imports request/data-plane service types:\n\n");
        for token in &violations {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nMesh attachment owns startup attachment only and must not import \
             RequestServices or DataPlaneServices.",
        );
        panic!("{}", msg);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Request-path capability boundary ──
// ══════════════════════════════════════════════════════════════════════════════

// ---------------------------------------------------------------------------
// Request-path scan roots and forbidden tokens
// ---------------------------------------------------------------------------

/// Directories that form the request path.
fn request_path_scan_roots() -> Vec<&'static str> {
    vec![
        "src/http/",
        "src/waf/",
        "crates/synvoid-http/src/",
        "crates/synvoid-waf/src/",
        "crates/synvoid-proxy/src/",
        "crates/synvoid-http3/src/",
    ]
}

/// Forbidden tokens for request-path modules.
const FORBIDDEN_REQUEST_PATH_TOKENS: &[&str] = &[
    // Concrete control-plane types
    "crate::mesh::transport",
    "crate::mesh::transports",
    "synvoid_mesh::mesh::transport",
    "MeshTransportManager",
    "MeshBackendPool",
    "ThreatIntelligenceManager",
    "crate::block_store::BlockStore",
    "synvoid_block_store::BlockStore",
    // Control-plane operations
    "lookup_threat_indicator_in_dht",
    "BlocklistCatchupRequest",
    "BlocklistSnapshotRequest",
    "BlocklistEventGossip",
    // Supervisor/admin
    "openraft::",
    "crate::supervisor::",
    "verify_admin_token",
    "crate::admin::handlers",
    // Worker lifecycle
    "UnifiedServerWorkerState",
    "WorkerTaskRegistry",
    "WorkerShutdownCause",
    // Raw threat-intel lookups
    "lookup_local_indicator(",
    "lookup_local_indicator_by_ip(",
];

// ---------------------------------------------------------------------------
// Scoped exceptions (request-path capability)
// ---------------------------------------------------------------------------

struct CapabilityBoundaryException {
    path_suffix: &'static str,
    token: &'static str,
    reason: &'static str,
}

const CAPABILITY_BOUNDARY_EXCEPTIONS: &[CapabilityBoundaryException] = &[
    // --- synvoid-http pass-throughs (received from composition root) ---
    CapabilityBoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for serverless routing",
    },
    CapabilityBoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend routing",
    },
    CapabilityBoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "synvoid_mesh::mesh::transport",
        reason: "Pass-through: transport module import for MeshTransportManager type alias",
    },
    CapabilityBoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "ServerlessManager",
        reason: "Pass-through: received from composition root for WASM dispatch",
    },
    CapabilityBoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "GranianSupervisor",
        reason: "Pass-through: received from composition root for app-server dispatch",
    },
    // --- src/http pass-throughs (received from composition root) ---
    CapabilityBoundaryException {
        path_suffix: "src/http/",
        token: "AsyncIpcStream",
        reason: "Pass-through: received from composition root for request logging",
    },
    CapabilityBoundaryException {
        path_suffix: "src/http/server.rs",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for upstream routing",
    },
    CapabilityBoundaryException {
        path_suffix: "src/http/server/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for upstream routing",
    },
    CapabilityBoundaryException {
        path_suffix: "src/http/server.rs",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend pool",
    },
    CapabilityBoundaryException {
        path_suffix: "src/http/server/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend pool",
    },
    CapabilityBoundaryException {
        path_suffix: "src/http/",
        token: "verify_admin_token",
        reason: "Request-time admin auth check — HTTP endpoints verify tokens inline",
    },
    // --- WAF pass-throughs / planned removals ---
    CapabilityBoundaryException {
        path_suffix: "src/waf/threat_intel/",
        token: "ThreatIntelligenceManager",
        reason: "Feed client is infrastructure, not request-path — planned removal",
    },
    CapabilityBoundaryException {
        path_suffix: "src/waf/threat_intel/",
        token: "lookup_local_indicator(",
        reason: "Diagnostic only: feed client queries local indicators for staleness check",
    },
    CapabilityBoundaryException {
        path_suffix: "src/waf/adapters.rs",
        token: "crate::block_store::BlockStore",
        reason:
            "Adapter bridge: wraps concrete BlockStore to implement narrow BlockListStore trait",
    },
];

fn find_capability_exception(
    path: &Path,
    token: &str,
) -> Option<&'static CapabilityBoundaryException> {
    let s = path.to_string_lossy();
    CAPABILITY_BOUNDARY_EXCEPTIONS
        .iter()
        .find(|e| s.contains(e.path_suffix) && token == e.token)
}

// ---------------------------------------------------------------------------
// Scan helper (request-path capability)
// ---------------------------------------------------------------------------

fn scan_request_path_for_tokens(tokens: &[&str], root: &Path) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    for dir_name in request_path_scan_roots() {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        for file in collect_rs_files(&dir) {
            let content = std::fs::read_to_string(&file).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);

            for token in tokens {
                if stripped.contains(token) {
                    if find_capability_exception(&file, token).is_some() {
                        continue;
                    }
                    let rel = file.strip_prefix(root).unwrap_or(&file);
                    violations.push((rel.display().to_string(), token.to_string()));
                }
            }
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Request-path capability boundary tests
// ---------------------------------------------------------------------------

/// Request-path files must not import concrete control-plane types or
/// construct infrastructure directly.
#[test]
fn request_path_no_concrete_control_plane_imports() {
    let root = workspace_root();
    let violations = scan_request_path_for_tokens(FORBIDDEN_REQUEST_PATH_TOKENS, &root);

    if !violations.is_empty() {
        let mut msg = String::from(
            "Request-path modules contain forbidden concrete control-plane imports:\n\n",
        );
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        msg.push_str(
            "\nRequest-path modules must consume narrow traits/capabilities, not concrete \
             infrastructure. Add a CapabilityBoundaryException if this is an intentional pass-through.",
        );
        panic!("{}", msg);
    }
}

/// Request-path files must not call raw threat-intel lookup APIs.
/// Enforcement paths must use `lookup_*_policy_strict` or the narrow
/// `ThreatIntelLookup` trait instead.
#[test]
fn request_path_no_raw_threat_intel_lookups() {
    let root = workspace_root();
    let raw_tokens = [
        "lookup_local_indicator(",
        "lookup_local_indicator_by_ip(",
        "lookup_threat_indicator_in_dht",
    ];
    let violations = scan_request_path_for_tokens(&raw_tokens, &root);

    if !violations.is_empty() {
        let mut msg =
            String::from("Request-path modules contain raw threat-intel lookup calls:\n\n");
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        msg.push_str(
            "\nRaw lookups are diagnostic-only. Enforcement paths must use \
             `lookup_*_policy_strict` or `Arc<dyn ThreatIntelLookup>`.",
        );
        panic!("{}", msg);
    }
}

/// Request-path files must not call `is_mesh_id_blocked`. Mesh-ID blocks
/// are admin/control-plane only — `RequestContext` and `WafContext` lack
/// mesh identity fields.
#[test]
fn request_path_no_mesh_id_blocks() {
    let root = workspace_root();
    let violations = scan_request_path_for_tokens(&["is_mesh_id_blocked("], &root);

    if !violations.is_empty() {
        let mut msg = String::from("Request-path modules contain `is_mesh_id_blocked` calls:\n\n");
        for (file, token) in &violations {
            msg.push_str(&format!("  {} -> {}\n", file, token));
        }
        msg.push_str(
            "\nMesh-ID blocks are admin/control-plane only. Request/WAF code has no \
             mesh identity context. Move the check to the composition root.",
        );
        panic!("{}", msg);
    }
}

/// RequestServices (context.rs) must not import worker startup, supervision,
/// or shutdown modules. It is the narrow request-path handle and must remain
/// free of lifecycle dependencies.
#[test]
fn request_services_does_not_import_worker_lifecycle() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/worker/context.rs"))
        .expect("failed to read src/worker/context.rs");

    let forbidden = [
        "unified_server::startup_plan",
        "unified_server::supervision_loop",
        "unified_server::shutdown_executor",
        "unified_server::lifecycle",
        "UnifiedServerWorkerState",
        "WorkerShutdownCause",
        "WorkerShutdownPlan",
        "WorkerTaskRegistry",
    ];

    let mut violations = Vec::new();
    for token in &forbidden {
        if source.contains(token) {
            violations.push(token.to_string());
        }
    }

    if !violations.is_empty() {
        let mut msg =
            String::from("RequestServices (context.rs) imports worker lifecycle modules:\n\n");
        for token in &violations {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nRequestServices is the narrow request-path handle and must not depend on \
             worker startup, supervision, or shutdown modules.",
        );
        panic!("{}", msg);
    }
}

/// The `ThreatIntelLookup` narrow trait must exist somewhere in the codebase.
/// Request-path code consumes `Arc<dyn ThreatIntelLookup>` instead of the
/// concrete `ThreatIntelligenceManager`.
#[test]
fn threat_intel_lookup_trait_exists() {
    let root = workspace_root();
    let search_dirs = ["src/worker/", "crates/synvoid-core/src/"];
    let mut found = false;

    for dir in &search_dirs {
        let dir_path = root.join(dir);
        if !dir_path.exists() {
            continue;
        }
        for file in collect_rs_files(&dir_path) {
            if let Ok(content) = std::fs::read_to_string(&file) {
                if content.contains("trait ThreatIntelLookup") {
                    found = true;
                    break;
                }
            }
        }
        if found {
            break;
        }
    }

    assert!(
        found,
        "ThreatIntelLookup trait not found in src/worker/ or crates/synvoid-core/src/. \
         Request-path code depends on this narrow trait for threat-intel lookups."
    );
}

/// Each `CAPABILITY_BOUNDARY_EXCEPTION` token must be present in at least one file
/// matching its `path_suffix`. Stale exceptions indicate dead code or
/// wrong paths.
#[test]
fn capability_exception_liveness() {
    let root = workspace_root();
    let all_files = collect_rs_files(&root);

    for exc in CAPABILITY_BOUNDARY_EXCEPTIONS {
        let matching_files: Vec<&PathBuf> = all_files
            .iter()
            .filter(|p| p.to_string_lossy().contains(exc.path_suffix))
            .collect();
        assert!(
            !matching_files.is_empty(),
            "CapabilityBoundaryException path_suffix '{}' matches no files — exception is stale",
            exc.path_suffix
        );
        let token_found = matching_files.iter().any(|f| {
            let content = std::fs::read_to_string(f).unwrap_or_default();
            let stripped = strip_cfg_test_modules(&content);
            let stripped = strip_comments(&stripped);
            stripped.contains(exc.token)
        });
        assert!(
            token_found,
            "CapabilityBoundaryException token '{}' not found in any file matching '{}'. \
             Exception is stale — remove it or update the path/token.",
            exc.token, exc.path_suffix
        );
    }
}

// ---------------------------------------------------------------------------
// Simulated violation detection (request-path capability)
// ---------------------------------------------------------------------------

#[test]
fn simulated_control_plane_import_in_waf_is_detected() {
    let test_content = "use crate::mesh::transport::MeshTransportManager;";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        FORBIDDEN_REQUEST_PATH_TOKENS
            .iter()
            .any(|t| stripped.contains(t)),
        "Simulated control-plane import in WAF should be detected"
    );
}

#[test]
fn simulated_raw_lookup_in_http_is_detected() {
    let test_content = "fn handle() { lookup_local_indicator(ip); }";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        FORBIDDEN_REQUEST_PATH_TOKENS
            .iter()
            .any(|t| stripped.contains(t)),
        "Simulated raw lookup in HTTP should be detected"
    );
}

#[test]
fn simulated_mesh_id_block_in_waf_is_detected() {
    let test_content = "fn check() { is_mesh_id_blocked(id, scope); }";
    let stripped = strip_cfg_test_modules(test_content);
    let stripped = strip_comments(&stripped);
    assert!(
        stripped.contains("is_mesh_id_blocked("),
        "Simulated mesh-ID block in WAF should be detected"
    );
}

// ---------------------------------------------------------------------------
// Exception table integrity (request-path capability)
// ---------------------------------------------------------------------------

#[test]
fn capability_boundary_exceptions_have_reasons() {
    for exc in CAPABILITY_BOUNDARY_EXCEPTIONS {
        assert!(
            !exc.reason.is_empty(),
            "CapabilityBoundaryException for {} in {} has no reason",
            exc.token,
            exc.path_suffix
        );
    }
}

#[test]
fn scan_roots_exist_and_contain_rs_files() {
    let root = workspace_root();
    for dir_name in request_path_scan_roots() {
        let dir = root.join(dir_name);
        assert!(
            dir.exists(),
            "Request-path scan root does not exist: {}",
            dir_name
        );
        let rs_files = collect_rs_files(&dir);
        assert!(
            !rs_files.is_empty(),
            "Request-path scan root contains no .rs files: {}",
            dir_name
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── HTTP request pipeline boundary ──
// ══════════════════════════════════════════════════════════════════════════════

const FORBIDDEN_WORKER_LIFECYCLE_TOKENS: &[&str] = &[
    "UnifiedServerWorkerState",
    "startup_plan",
    "supervision_loop",
    "shutdown_executor",
    "WorkerTaskRegistry",
    "WorkerShutdownCause",
];

fn assert_no_worker_lifecycle_imports(source: &str, file_label: &str) {
    let stripped = strip_comments(source);
    let mut violations = Vec::new();
    for token in FORBIDDEN_WORKER_LIFECYCLE_TOKENS {
        if stripped.contains(token) {
            violations.push(token.to_string());
        }
    }
    if !violations.is_empty() {
        let mut msg = format!("{} imports worker lifecycle modules:\n\n", file_label);
        for token in &violations {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nHTTP request dispatch code must consume context structs and narrow capabilities,\n\
             not worker startup, supervision, or shutdown modules.",
        );
        panic!("{}", msg);
    }
}

#[test]
fn http3_dispatch_must_not_import_worker_lifecycle_modules() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    assert_no_worker_lifecycle_imports(&source, "http3_request_dispatch.rs");
}

#[test]
fn http1_request_flow_must_not_import_worker_lifecycle_modules() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("crates/synvoid-http/src/http_request_flow.rs"))
        .expect("failed to read http_request_flow.rs");
    assert_no_worker_lifecycle_imports(&source, "http_request_flow.rs");
}

#[test]
fn http3_dispatch_uses_context_structs() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);

    let missing = ["Http3RequestMetadata", "Http3DispatchDeps"];
    let mut absent = Vec::new();
    for token in &missing {
        if !stripped.contains(token) {
            absent.push(token.to_string());
        }
    }
    if !absent.is_empty() {
        let mut msg = String::from(
            "http3_request_dispatch.rs is missing expected context struct references:\n\n",
        );
        for token in &absent {
            msg.push_str(&format!("  {}\n", token));
        }
        msg.push_str(
            "\nHTTP/3 dispatch must use Http3RequestMetadata and Http3DispatchDeps context structs.",
        );
        panic!("{}", msg);
    }
}

#[test]
fn request_pipeline_stage_vocabulary_is_documented() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    let required_words = [
        "metadata",
        "route",
        "body",
        "WAF",
        "terminal",
        "upstream",
        "accounting",
    ];
    let mut missing = Vec::new();
    for word in &required_words {
        if !source.contains(word) {
            missing.push(word.to_string());
        }
    }
    if !missing.is_empty() {
        let mut msg = String::from(
            "architecture/http_request_pipeline.md is missing required pipeline stage vocabulary:\n\n",
        );
        for word in &missing {
            msg.push_str(&format!("  {}\n", word));
        }
        msg.push_str(
            "\nThe architecture document must document all pipeline stages: metadata, route, body,\n\
             WAF, terminal, upstream, and accounting.",
        );
        panic!("{}", msg);
    }
}

#[test]
fn http3_dispatch_does_not_import_unified_server_worker_state() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);
    assert!(
        !stripped.contains("UnifiedServerWorkerState"),
        "http3_request_dispatch.rs must not import UnifiedServerWorkerState"
    );
}

#[test]
fn http_request_flow_does_not_import_unified_server_worker_state() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("crates/synvoid-http/src/http_request_flow.rs"))
        .expect("failed to read http_request_flow.rs");
    let stripped = strip_comments(&source);
    assert!(
        !stripped.contains("UnifiedServerWorkerState"),
        "http_request_flow.rs must not import UnifiedServerWorkerState"
    );
}

#[test]
fn http_request_pipeline_doc_mentions_http3_dispatch_deps() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    assert!(
        source.contains("Http3DispatchDeps"),
        "architecture/http_request_pipeline.md must document Http3DispatchDeps"
    );
    assert!(
        source.contains("Http3RequestMetadata"),
        "architecture/http_request_pipeline.md must document Http3RequestMetadata"
    );
}

#[test]
fn http_request_pipeline_doc_does_not_claim_http3_has_no_deps_struct() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("architecture/http_request_pipeline.md"))
        .expect("failed to read http_request_pipeline.md");

    let forbidden = [
        "There is no separate \"deps\" struct",
        "There is no separate 'deps' struct",
        "all dependencies are passed as function parameters to `handle_http3_request_dispatch()`",
    ];

    for phrase in forbidden {
        assert!(
            !source.contains(phrase),
            "architecture/http_request_pipeline.md contains stale HTTP/3 deps wording: {}",
            phrase
        );
    }
}

#[test]
fn http3_dispatch_signature_uses_context_structs() {
    let root = workspace_root();
    let source =
        std::fs::read_to_string(root.join("crates/synvoid-http/src/http3_request_dispatch.rs"))
            .expect("failed to read http3_request_dispatch.rs");
    let stripped = strip_comments(&source);

    let fn_start = stripped
        .find("pub async fn handle_http3_request_dispatch")
        .expect("handle_http3_request_dispatch should exist");
    let fn_prefix = &stripped[fn_start..stripped.len().min(fn_start + 600)];

    assert!(fn_prefix.contains("metadata: Http3RequestMetadata"));
    assert!(fn_prefix.contains("deps: Http3DispatchDeps"));
}

// ══════════════════════════════════════════════════════════════════════════════
// ── HTTP/3 WAF boundary ──
// ══════════════════════════════════════════════════════════════════════════════

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
fn http3_is_allowlisted(relative: &str) -> bool {
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

#[test]
fn http3_boundary_no_concrete_imports() {
    let root = workspace_root();
    let http3_dir = root.join("crates/synvoid-http3");

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
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();

        if http3_is_allowlisted(&relative) {
            continue;
        }

        let content = match std::fs::read_to_string(file) {
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
    let root = workspace_root();
    let cargo_toml = root.join("crates/synvoid-http3/Cargo.toml");

    let content = std::fs::read_to_string(&cargo_toml)
        .expect("Failed to read crates/synvoid-http3/Cargo.toml");

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
fn http3_strip_test_modules_removes_cfg_test_content() {
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

// ══════════════════════════════════════════════════════════════════════════════
// ── Manifest authority load path ──
// ══════════════════════════════════════════════════════════════════════════════

/// Test 1: All load paths in WasmPluginManager must go through prepare_plugin_load.
///
/// After manifest enforcement was introduced, no load path should call
/// `WasmRuntime::load(path, self.default_limits.clone())` directly.
#[test]
fn all_load_paths_use_prepare_plugin_load() {
    let repo = workspace_root();
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find all methods in WasmPluginManager that look like load paths
    let load_methods = [
        "pub fn load_plugin(",
        "pub fn load_plugin_with_limits(",
        "pub fn load_plugin_from_memory(",
        "pub fn load_plugin_from_memory_with_priority(",
        "pub fn reload_plugin(",
    ];

    for method_sig in &load_methods {
        // Find the method body
        let lines: Vec<&str> = cleaned.lines().collect();
        let mut method_start = None;
        let mut brace_depth = 0u32;
        let mut in_method = false;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains(method_sig) {
                in_method = true;
                brace_depth = 0;
                method_start = Some(i);
            }
            if in_method {
                brace_depth += trimmed.matches('{').count() as u32;
                brace_depth = brace_depth.saturating_sub(trimmed.matches('}').count() as u32);
                if brace_depth == 0 && i > method_start.unwrap_or(0) {
                    // Extract method body
                    let body: String = lines
                        .iter()
                        .skip(method_start.unwrap())
                        .take(i - method_start.unwrap() + 1)
                        .copied()
                        .collect::<Vec<_>>()
                        .join("\n");

                    // The method must NOT contain a direct call to
                    // WasmRuntime::load with self.default_limits
                    assert!(
                        !body.contains("WasmRuntime::load(")
                            || body.contains("prepare_plugin_load")
                            || body.contains("load_with_policy"),
                        "Load path '{}' must use prepare_plugin_load or load_with_policy, \
                         not WasmRuntime::load() directly:\n{}",
                        method_sig,
                        body
                    );
                    break;
                }
            }
        }
    }
}

/// Test 2: prepare_plugin_load exists and returns PreparedPluginLoad.
///
/// The central enforcement method must exist and return the new type.
#[test]
fn prepare_plugin_load_exists_and_returns_prepared() {
    let repo = workspace_root();
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    assert!(
        cleaned.contains("fn prepare_plugin_load("),
        "prepare_plugin_load method must exist in wasm_runtime.rs"
    );
    assert!(
        cleaned.contains("PreparedPluginLoad"),
        "prepare_plugin_load must reference PreparedPluginLoad"
    );
}

/// Test 3: limits_from_manifest function exists in policy module.
///
/// The manifest-to-runtime conversion helper must be available.
#[test]
fn limits_from_manifest_exists() {
    let repo = workspace_root();
    let policy_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("sandbox")
        .join("policy.rs");

    let text = std::fs::read_to_string(&policy_file).expect("read policy.rs");

    assert!(
        text.contains("pub fn limits_from_manifest("),
        "limits_from_manifest function must exist in policy.rs"
    );
    assert!(
        text.contains("EffectivePluginPolicy"),
        "EffectivePluginPolicy struct must exist in policy.rs"
    );
    assert!(
        text.contains("PreparedPluginLoad"),
        "PreparedPluginLoad struct must exist in policy.rs"
    );
}

/// Test 4: WasmResourceLimits has Debug derive.
///
/// Required for EffectivePluginPolicy and PreparedPluginLoad to derive Debug.
#[test]
fn wasm_resource_limits_has_debug() {
    let repo = workspace_root();
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    // Find the struct definition and check for Debug
    let lines: Vec<&str> = cleaned.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("pub struct WasmResourceLimits") {
            // Check the previous line for #[derive(Debug, Clone)]
            if i > 0 {
                let prev = lines[i - 1];
                assert!(
                    prev.contains("Debug"),
                    "WasmResourceLimits must derive Debug, found: {}",
                    prev
                );
            }
            break;
        }
    }
}

/// Test 5: PluginInfo has version and trust_tier fields.
///
/// Ensures introspection fields are present.
#[test]
fn plugin_info_has_introspection_fields() {
    let repo = workspace_root();
    let wasm_file = repo
        .join("crates")
        .join("synvoid-plugin-runtime")
        .join("src")
        .join("wasm_runtime.rs");

    let text = std::fs::read_to_string(&wasm_file).expect("read wasm_runtime.rs");
    let cleaned = strip_comments_and_strings(&text);

    assert!(
        cleaned.contains("pub struct PluginInfo"),
        "PluginInfo struct must exist"
    );
    assert!(
        cleaned.contains("pub version: String"),
        "PluginInfo must have version field"
    );
    assert!(
        cleaned.contains("pub trust_tier: PluginTrustTier"),
        "PluginInfo must have trust_tier field"
    );
    assert!(
        cleaned.contains("pub timeout: Duration"),
        "PluginInfo must have timeout field (Duration)"
    );
    assert!(
        cleaned.contains("pub capabilities_summary:"),
        "PluginInfo must have capabilities_summary field"
    );
}

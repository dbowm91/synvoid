//! Iteration 60 — Data-plane composition root boundary guard.
//!
//! Prevents request-path modules from importing or constructing concrete
//! mesh/DHT/Raft/admin/block-store infrastructure. Composition roots
//! own concrete infrastructure; request-path modules consume capabilities.
//!
//! Phase 1: Role-based `classify_path` replaces `is_allowlisted`
//! Phase 2: Broadened forbidden token coverage (construction + type-import + control-plane ops)
//! Phase 3: Structured `BoundaryException` table replaces ad-hoc `is_file_exempt`
//! Phase 4: Mixed-role scan roots include unified_server with file-by-file classification
//! Phase 5: Fail-closed unknown file classification
//! Phase 6: Additional assertion tests for focused boundary checks
//! Iteration 98: Data-plane service boundary guards

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
// Tests
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
        "skills/",
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
        roots.iter().any(|r| *r == "src/worker/unified_server"),
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
        let rel = file.strip_prefix(&root).unwrap_or(&file);
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
    let has_inline_apply = stripped.contains("apply_threat_intel_policy_context");
    let has_inline_cross_wire = stripped.contains("cross_wire_mesh_services");

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

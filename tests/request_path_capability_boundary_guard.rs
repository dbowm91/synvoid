//! Request-path capability boundary guard.
//!
//! Prevents request-path modules from importing or constructing concrete
//! control-plane infrastructure (mesh transport, supervisor, admin handlers,
//! worker lifecycle, raw threat-intel lookups). Request-path code must
//! consume narrow traits, not concrete infrastructure types.
//!
//! Mirrors the structure of `data_plane_composition_boundary_guard.rs` but
//! focuses on capability-level violations specific to request dispatch.

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
// Scoped exceptions
// ---------------------------------------------------------------------------

struct BoundaryException {
    path_suffix: &'static str,
    token: &'static str,
    reason: &'static str,
}

const BOUNDARY_EXCEPTIONS: &[BoundaryException] = &[
    // --- synvoid-http pass-throughs (received from composition root) ---
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for serverless routing",
    },
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend routing",
    },
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "synvoid_mesh::mesh::transport",
        reason: "Pass-through: transport module import for MeshTransportManager type alias",
    },
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "ServerlessManager",
        reason: "Pass-through: received from composition root for WASM dispatch",
    },
    BoundaryException {
        path_suffix: "crates/synvoid-http/src/",
        token: "GranianSupervisor",
        reason: "Pass-through: received from composition root for app-server dispatch",
    },
    // --- src/http pass-throughs (received from composition root) ---
    BoundaryException {
        path_suffix: "src/http/",
        token: "AsyncIpcStream",
        reason: "Pass-through: received from composition root for request logging",
    },
    BoundaryException {
        path_suffix: "src/http/server.rs",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for upstream routing",
    },
    BoundaryException {
        path_suffix: "src/http/server/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for upstream routing",
    },
    BoundaryException {
        path_suffix: "src/http/server.rs",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend pool",
    },
    BoundaryException {
        path_suffix: "src/http/server/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend pool",
    },
    BoundaryException {
        path_suffix: "src/http/",
        token: "verify_admin_token",
        reason: "Request-time admin auth check — HTTP endpoints verify tokens inline",
    },
    // --- WAF pass-throughs / planned removals ---
    BoundaryException {
        path_suffix: "src/waf/",
        token: "BehavioralIntelligenceManager",
        reason: "Concrete type in WAF attack detection — planned trait extraction",
    },
    BoundaryException {
        path_suffix: "src/waf/threat_intel/",
        token: "ThreatIntelligenceManager",
        reason: "Feed client is infrastructure, not request-path — planned removal",
    },
    BoundaryException {
        path_suffix: "src/waf/mod.rs",
        token: "ThreatIntelligenceManager",
        reason: "Wiring function receives TIM from composition root for trait dispatch",
    },
    BoundaryException {
        path_suffix: "src/waf/threat_intel/",
        token: "lookup_local_indicator(",
        reason: "Diagnostic only: feed client queries local indicators for staleness check",
    },
    BoundaryException {
        path_suffix: "src/waf/adapters.rs",
        token: "crate::block_store::BlockStore",
        reason:
            "Adapter bridge: wraps concrete BlockStore to implement narrow BlockListStore trait",
    },
];

fn find_exception(path: &Path, token: &str) -> Option<&'static BoundaryException> {
    let s = path.to_string_lossy();
    BOUNDARY_EXCEPTIONS
        .iter()
        .find(|e| s.contains(e.path_suffix) && token == e.token)
}

// ---------------------------------------------------------------------------
// Scan helper
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
                    if find_exception(&file, token).is_some() {
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
// Tests
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
             infrastructure. Add a BoundaryException if this is an intentional pass-through.",
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

/// Each `BOUNDARY_EXCEPTION` token must be present in at least one file
/// matching its `path_suffix`. Stale exceptions indicate dead code or
/// wrong paths.
#[test]
fn exception_liveness() {
    let root = workspace_root();
    let all_files = collect_rs_files(&root);

    for exc in BOUNDARY_EXCEPTIONS {
        let matching_files: Vec<&PathBuf> = all_files
            .iter()
            .filter(|p| p.to_string_lossy().contains(exc.path_suffix))
            .collect();
        assert!(
            !matching_files.is_empty(),
            "BoundaryException path_suffix '{}' matches no files — exception is stale",
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

// ---------------------------------------------------------------------------
// Simulated violation detection
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
// Exception table integrity
// ---------------------------------------------------------------------------

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

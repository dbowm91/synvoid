//! Static guards for composition boundaries.
//!
//! Ensures request-path modules do not import concrete infrastructure
//! (BlockStore, ThreatIntelligenceManager, Raft, DHT, mesh handles).

use std::fs;
use synvoid_repo_guards::{collect_rs_files, prepare_for_scanning, workspace_root, Violations};

// Request-path directories that must NOT import concrete infrastructure
const REQUEST_PATH_DIRS: &[&str] = &[
    "src/waf/",
    "src/proxy/",
    "crates/synvoid-waf/",
    "crates/synvoid-proxy/",
];

/// Forbidden concrete type imports in request-path code
const FORBIDDEN_TYPES: &[&str] = &[
    "BlockStore",
    "ThreatIntelligenceManager",
    "RaftHandle",
    "DhtHandle",
    "MeshState",
    "MeshHandle",
    "PeerAuth",
    "PeerAuthenticator",
];

/// Scoped exceptions for pass-through concrete types that are intentionally
/// threaded through request dispatch contexts.
#[allow(dead_code)]
struct BoundaryException {
    path_suffix: &'static str,
    token: &'static str,
    reason: &'static str,
}

const BOUNDARY_EXCEPTIONS: &[BoundaryException] = &[
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
    BoundaryException {
        path_suffix: "src/waf/threat_intel/feed_client.rs",
        token: "MeshMessageSigner",
        reason: "Crypto verification only: used for feed signature check, not infrastructure ownership",
    },
    BoundaryException {
        path_suffix: "src/waf/threat_intel/feed_client.rs",
        token: "crate::mesh::threat_intel::ThreatIntelligenceManager",
        reason: "Feed client uses TIM for signature verification and indicator management, not ownership",
    },
    BoundaryException {
        path_suffix: "src/waf/threat_intel/feed_client.rs",
        token: "lookup_local_indicator",
        reason: "Diagnostic only: feed client queries local indicators for staleness check, not enforcement",
    },
    BoundaryException {
        path_suffix: "src/waf/adapters.rs",
        token: "crate::block_store::BlockStore",
        reason: "Adapter bridge: wraps concrete BlockStore to implement narrow BlockListStore trait",
    },
];

fn find_exception(rel_str: &str, token: &str) -> Option<&'static BoundaryException> {
    BOUNDARY_EXCEPTIONS
        .iter()
        .find(|e| rel_str.contains(e.path_suffix) && e.token.contains(token))
}

// ---------------------------------------------------------------------------
// data_plane_composition_boundary_guard
// ---------------------------------------------------------------------------

#[test]
fn request_path_does_not_import_concrete_infrastructure() {
    let repo = workspace_root();
    let mut violations = Violations::new();

    for dir in REQUEST_PATH_DIRS {
        let full_dir = repo.join(dir);
        let files = collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            let content = std::fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("use ") {
                    for forbidden in FORBIDDEN_TYPES {
                        if trimmed.contains(forbidden) {
                            if find_exception(&rel_str, forbidden).is_some() {
                                continue;
                            }
                            violations.push(format!(
                                "{}:{}: imports forbidden concrete type '{}' (request-path must use narrow traits)",
                                rel_str,
                                line_no + 1,
                                forbidden
                            ));
                        }
                    }
                }
            }
        }
    }

    violations.assert_ok("data_plane_composition_boundary_guard");
}

// ---------------------------------------------------------------------------
// request_path_capability_boundary_guard
// ---------------------------------------------------------------------------

/// Forbidden control-plane imports in request-path code.
const FORBIDDEN_CONTROL_PLANE_IMPORTS: &[&str] = &[
    "synvoid_mesh::",
    "synvoid_block_store::",
    "raft::",
    "openraft::",
];

#[allow(dead_code)]
struct ControlPlaneException {
    path_suffix: &'static str,
    token: &'static str,
    reason: &'static str,
}

const CONTROL_PLANE_EXCEPTIONS: &[ControlPlaneException] = &[
    ControlPlaneException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for serverless routing",
    },
    ControlPlaneException {
        path_suffix: "crates/synvoid-http/src/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend routing",
    },
    ControlPlaneException {
        path_suffix: "crates/synvoid-http/src/",
        token: "synvoid_mesh::mesh::transport",
        reason: "Pass-through: transport module import for MeshTransportManager type alias",
    },
    ControlPlaneException {
        path_suffix: "crates/synvoid-http/src/",
        token: "ServerlessManager",
        reason: "Pass-through: received from composition root for WASM dispatch",
    },
    ControlPlaneException {
        path_suffix: "crates/synvoid-http/src/",
        token: "GranianSupervisor",
        reason: "Pass-through: received from composition root for app-server dispatch",
    },
    ControlPlaneException {
        path_suffix: "src/http/",
        token: "AsyncIpcStream",
        reason: "Pass-through: received from composition root for request logging",
    },
    ControlPlaneException {
        path_suffix: "src/http/server.rs",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for upstream routing",
    },
    ControlPlaneException {
        path_suffix: "src/http/server/",
        token: "MeshTransportManager",
        reason: "Pass-through: received from composition root for upstream routing",
    },
    ControlPlaneException {
        path_suffix: "src/http/server.rs",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend pool",
    },
    ControlPlaneException {
        path_suffix: "src/http/server/",
        token: "MeshBackendPool",
        reason: "Pass-through: received from composition root for backend pool",
    },
    ControlPlaneException {
        path_suffix: "src/http/",
        token: "verify_admin_token",
        reason: "Request-time admin auth check — HTTP endpoints verify tokens inline",
    },
    ControlPlaneException {
        path_suffix: "src/waf/threat_intel/",
        token: "ThreatIntelligenceManager",
        reason: "Feed client is infrastructure, not request-path — planned removal",
    },
    ControlPlaneException {
        path_suffix: "src/waf/threat_intel/",
        token: "lookup_local_indicator(",
        reason: "Diagnostic only: feed client queries local indicators for staleness check",
    },
    ControlPlaneException {
        path_suffix: "src/waf/adapters.rs",
        token: "crate::block_store::BlockStore",
        reason:
            "Adapter bridge: wraps concrete BlockStore to implement narrow BlockListStore trait",
    },
];

fn find_control_plane_exception(
    rel_str: &str,
    token: &str,
) -> Option<&'static ControlPlaneException> {
    CONTROL_PLANE_EXCEPTIONS
        .iter()
        .find(|e| rel_str.contains(e.path_suffix) && token == e.token)
}

#[test]
fn request_path_avoids_control_plane_imports() {
    let repo = workspace_root();
    let mut violations = Violations::new();

    for dir in REQUEST_PATH_DIRS {
        let full_dir = repo.join(dir);
        let files = collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            let content = std::fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("use ") || trimmed.starts_with("extern crate ") {
                    for forbidden in FORBIDDEN_CONTROL_PLANE_IMPORTS {
                        if trimmed.contains(forbidden) {
                            if find_control_plane_exception(&rel_str, forbidden).is_some() {
                                continue;
                            }
                            violations.push(format!(
                                "{}:{}: control-plane import '{}' in request-path code",
                                rel_str,
                                line_no + 1,
                                forbidden
                            ));
                        }
                    }
                }
            }
        }
    }

    violations.assert_ok("request_path_capability_boundary_guard");
}

// ---------------------------------------------------------------------------
// http_request_pipeline_boundary_guard
// ---------------------------------------------------------------------------

/// Forbidden worker lifecycle tokens in HTTP handler code.
const FORBIDDEN_WORKER_LIFECYCLE_TOKENS: &[&str] = &[
    "UnifiedServerWorkerState",
    "startup_plan",
    "supervision_loop",
    "shutdown_executor",
    "WorkerTaskRegistry",
    "WorkerShutdownCause",
];

#[test]
fn http_handlers_avoid_lifecycle_imports() {
    let repo = workspace_root();
    let http_dirs = &["src/http/", "crates/synvoid-http/"];
    let mut violations = Violations::new();

    for dir in http_dirs {
        let full_dir = repo.join(dir);
        let files = collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            let content = std::fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for token in FORBIDDEN_WORKER_LIFECYCLE_TOKENS {
                if scanned.contains(token) {
                    violations.push(format!(
                        "{}: imports worker lifecycle token '{}'",
                        rel_str, token
                    ));
                }
            }
        }
    }

    violations.assert_ok("http_request_pipeline_boundary_guard");
}

// ---------------------------------------------------------------------------
// http3_waf_boundary_guard
// ---------------------------------------------------------------------------

#[test]
fn http3_crate_avoids_forbidden_imports() {
    let repo = workspace_root();
    let http3_dirs = &["crates/synvoid-http3/", "src/http3/"];
    let mut violations = Violations::new();

    for dir in http3_dirs {
        let full_dir = repo.join(dir);
        let files = collect_rs_files(&full_dir);

        for file in &files {
            let rel = file.strip_prefix(&repo).unwrap_or(file);
            let rel_str = rel.to_string_lossy().to_string();

            let content = fs::read_to_string(file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);

            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("use ") {
                    for forbidden in FORBIDDEN_TYPES {
                        if trimmed.contains(forbidden) {
                            violations.push(format!(
                                "{}:{}: forbidden concrete type '{}' in HTTP/3 crate",
                                rel_str,
                                line_no + 1,
                                forbidden
                            ));
                        }
                    }
                }
            }
        }
    }

    violations.assert_ok("http3_waf_boundary_guard");
}

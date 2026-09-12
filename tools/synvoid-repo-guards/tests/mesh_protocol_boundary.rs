//! Phase 27 mesh-protocol contract extraction guards.
//!
//! Pins the low-capability boundary: `synvoid-mesh-protocol` must stay free of
//! control-plane dependencies, `synvoid-mesh` must depend downward on it, and
//! cross-boundary consumers must prefer the protocol crate for verification
//! primitives over full `synvoid-mesh`.

use std::fs;
use synvoid_repo_guards::{collect_rs_files, prepare_for_scanning, workspace_root, Violations};

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    fs::read_to_string(repo.join(rel)).unwrap_or_else(|_| panic!("read {rel}"))
}

fn manifest_declares(manifest: &str, needle: &str) -> bool {
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let code = t.split('#').next().unwrap_or("").trim();
        if !code.contains('=') {
            continue;
        }
        // Match the dependency name as a discrete token: `needle` must appear
        // and must not be a prefix of a longer crate name (e.g. `synvoid-mesh`
        // must not match `synvoid-mesh-protocol`). Check the character after
        // each occurrence.
        let mut search_from = 0;
        while let Some(pos) = code[search_from..].find(needle) {
            let abs = search_from + pos;
            let after = abs + needle.len();
            let next_is_continuation = code[after..]
                .chars()
                .next()
                .is_some_and(|c| c == '-' || c == '_' || c.is_alphanumeric());
            if !next_is_continuation {
                return true;
            }
            search_from = after;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// protocol crate dependency budget
// ---------------------------------------------------------------------------

const PROHIBITED_PROTOCOL_DEPS: &[&str] = &[
    "synvoid-mesh",
    "openraft",
    "rusqlite",
    "quinn",
    "hyper",
    "axum",
    "tonic",
    "yara-x",
    "synvoid-proxy",
    "synvoid-tunnel",
    "synvoid-serverless",
    "synvoid-block-store",
    "synvoid-config",
    "pqc",
];

#[test]
fn mesh_protocol_dependency_budget() {
    let manifest = read_repo("crates/synvoid-mesh-protocol/Cargo.toml");
    let mut violations = Violations::new();
    for dep in PROHIBITED_PROTOCOL_DEPS {
        if manifest_declares(&manifest, dep) {
            violations.push(format!(
                "crates/synvoid-mesh-protocol/Cargo.toml declares prohibited dep '{dep}' \
                 (Phase 27 budget: wire/identity semantics only)"
            ));
        }
    }
    violations.assert_ok("mesh_protocol_dependency_budget");
}

#[test]
fn mesh_protocol_imports_stay_low_capability() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-mesh-protocol/src");
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    let forbidden_tokens = [
        "synvoid_mesh",
        "synvoid-mesh",
        "openraft",
        "rusqlite",
        "quinn::",
        "hyper::",
        "axum::",
        "tonic::",
        "yara",
        "CryptoVerificationPool",
        "MeshMlDsa",
        "RecordStoreManager",
        "RaftHandle",
        "ThreatIntelligenceManager",
    ];
    for file in &files {
        let rel = file
            .strip_prefix(&repo)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        let content = fs::read_to_string(file).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for (line_no, line) in scanned.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("use ") {
                for token in &forbidden_tokens {
                    if trimmed.contains(token) {
                        violations.push(format!(
                            "{rel}:{}: forbidden control-plane import '{token}' in protocol crate",
                            line_no + 1
                        ));
                    }
                }
            }
        }
    }
    violations.assert_ok("mesh_protocol_imports_stay_low_capability");
}

// ---------------------------------------------------------------------------
// dependency direction: mesh depends downward, never the reverse
// ---------------------------------------------------------------------------

#[test]
fn mesh_depends_downward_on_protocol() {
    let mesh_manifest = read_repo("crates/synvoid-mesh/Cargo.toml");
    assert!(
        manifest_declares(&mesh_manifest, "synvoid-mesh-protocol"),
        "synvoid-mesh must depend on synvoid-mesh-protocol (Phase 27 downward dep)"
    );
    let proto_manifest = read_repo("crates/synvoid-mesh-protocol/Cargo.toml");
    assert!(
        !manifest_declares(&proto_manifest, "synvoid-mesh"),
        "synvoid-mesh-protocol must not depend on synvoid-mesh (no cycles)"
    );
}

// ---------------------------------------------------------------------------
// consumer guard: protocol-only users must not pull full mesh for the signer
// ---------------------------------------------------------------------------

#[test]
fn protocol_consumers_avoid_full_mesh_signer() {
    let repo = workspace_root();
    let mut violations = Violations::new();
    // Request-path + feed verification must use the protocol crate signer.
    // Full-mesh `MeshMessageSigner` remains for mesh runtime services only.
    let scan_roots = ["src/waf/threat_intel", "crates/synvoid-waf/src"];
    for root in scan_roots {
        let dir = repo.join(root);
        for file in collect_rs_files(&dir) {
            let rel = file
                .strip_prefix(&repo)
                .unwrap_or(&file)
                .to_string_lossy()
                .to_string();
            let content = fs::read_to_string(&file).unwrap_or_default();
            let scanned = prepare_for_scanning(&content);
            for (line_no, line) in scanned.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("use ") && trimmed.contains("MeshMessageSigner") {
                    violations.push(format!(
                        "{rel}:{}: use protocol-crate signer (`synvoid_mesh_protocol::signer`) \
                         instead of full-mesh MeshMessageSigner (Phase 27 consumer migration)",
                        line_no + 1
                    ));
                }
            }
        }
    }
    violations.assert_ok("protocol_consumers_avoid_full_mesh_signer");
}

//! Root-test ownership: STATIC_POLICY
//! Rationale: Phase 74 transport-neutral inbound boundary. The canonical
//! `synvoid-http` request pipeline must consume the neutral
//! `InboundRequest`/`InboundBody`/`UpgradeCapability` boundary; concrete
//! Hyper ingress types may appear only in the explicit transport adapter,
//! and EggServe must not enter `synvoid-http` at all.
//!
//! Guards:
//!
//! - no `hyper::body::Incoming` in canonical request-policy modules
//!   (only `crates/synvoid-http/src/hyper_adapter.rs`);
//! - no `hyper::upgrade::OnUpgrade` in canonical request/backend/WebSocket
//!   dispatch APIs (only `hyper_adapter.rs`);
//! - no `eggserve` references anywhere under `crates/synvoid-http/src`;
//! - the neutral boundary modules exist and the canonical flow entry
//!   consumes `InboundRequest`.

use std::path::{Path, PathBuf};

fn read(repo: &Path, rel: &str) -> String {
    std::fs::read_to_string(repo.join(rel)).expect("read source file")
}

fn crate_src_files(repo: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = repo.join("crates/synvoid-http/src");
    for entry in std::fs::read_dir(&dir).expect("read synvoid-http src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn file_name(path: &Path) -> &str {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

/// The single module allowed to name Hyper ingress types.
fn is_transport_adapter(name: &str) -> bool {
    name == "hyper_adapter.rs"
}

#[test]
fn no_hyper_ingress_body_outside_transport_adapter() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for path in crate_src_files(repo) {
        let name = file_name(&path).to_string();
        if is_transport_adapter(&name) {
            continue;
        }
        let content = read(repo, &format!("crates/synvoid-http/src/{name}"));
        if content.contains("hyper::body::Incoming") {
            violations.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "hyper::body::Incoming outside hyper_adapter.rs: {violations:?}"
    );
}

#[test]
fn no_hyper_upgrade_outside_transport_adapter() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for path in crate_src_files(repo) {
        let name = file_name(&path).to_string();
        if is_transport_adapter(&name) {
            continue;
        }
        let content = read(repo, &format!("crates/synvoid-http/src/{name}"));
        if content.contains("hyper::upgrade::OnUpgrade") {
            violations.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "hyper::upgrade::OnUpgrade outside hyper_adapter.rs: {violations:?}"
    );
}

#[test]
fn no_eggserve_inside_synvoid_http() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for path in crate_src_files(repo) {
        let name = file_name(&path).to_string();
        let content = read(repo, &format!("crates/synvoid-http/src/{name}"));
        if content.to_ascii_lowercase().contains("eggserve") {
            violations.push(name);
        }
    }
    assert!(
        violations.is_empty(),
        "eggserve reference inside crates/synvoid-http/src: {violations:?}"
    );
}

#[test]
fn neutral_boundary_modules_and_entry_exist() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let inbound = read(repo, "crates/synvoid-http/src/inbound.rs");
    for token in [
        "pub struct InboundBody",
        "pub enum InboundBodyError",
        "pub struct InboundRequest",
        "pub trait UpgradeCapability",
        "fn accept",
        "pub struct UpgradeHandshake",
    ] {
        assert!(inbound.contains(token), "inbound.rs missing {token}");
    }
    let adapter = read(repo, "crates/synvoid-http/src/hyper_adapter.rs");
    assert!(
        adapter.contains("pub fn adapt_hyper_request"),
        "hyper_adapter.rs missing adapt_hyper_request"
    );
    let flow = read(repo, "crates/synvoid-http/src/http_request_flow.rs");
    assert!(
        flow.contains("InboundRequest"),
        "canonical flow entry must consume InboundRequest"
    );
}

// --- Phase 77: TLS convergence transport guards ---

#[test]
fn tls_h2_branch_stays_hyper() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tls = read(repo, "src/tls/server.rs");
    // ALPN h2 is served by the Hyper H2 builder; the EggServe H1 driver
    // appears exactly once (the ALPN-http/1.1 branch).
    assert!(
        tls.contains("http2_server::Builder"),
        "TLS H2 branch must keep the Hyper H2 builder"
    );
    assert_eq!(
        tls.matches("serve_http1_connection_with_policy").count(),
        1,
        "exactly one EggServe H1 call site allowed in the TLS server (ALPN http/1.1)"
    );
}

#[test]
fn plaintext_has_no_h2() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in [
        "src/http/server/accept_loop.rs",
        "src/http/service_core.rs",
        "src/http/eggserve_h1.rs",
    ] {
        let content = read(repo, rel);
        let lower = content.to_ascii_lowercase();
        assert!(!lower.contains("h2c"), "{rel} must not add h2c");
        assert!(!lower.contains("http2"), "{rel} must not reference H2");
    }
}

#[test]
fn http3_independent_of_eggserve() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = repo.join("crates/synvoid-http3/src");
    let mut violations = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read synvoid-http3 src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("read file");
        if content.to_ascii_lowercase().contains("eggserve") {
            violations.push(path);
        }
    }
    assert!(
        violations.is_empty(),
        "HTTP/3 must not depend on the EggServe runtime: {violations:?}"
    );
}

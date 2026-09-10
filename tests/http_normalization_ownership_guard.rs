//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 20 HTTP normalization ownership convergence
//! plus Phase 01 TLS request-flow convergence
//!
//! Guards for `architecture/http_ownership_convergence.md`:
//!
//! - no second parser/normalizer under root `src/http` / `src/tls`
//!   (canonical: `synvoid_http::{early_parse, framing, headers, body_policy,
//!   request_parse}`)
//! - every root `src/http` dispatch shim delegates to `synvoid-http`
//!   (application handlers and the `HttpServer` composition root exempted)
//! - no duplicate WAF-decision mapping tables under root `src/http`
//!   (canonical: `synvoid_http::{waf_decision, streaming_waf_decision,
//!   http3_waf_dispatch}`)
//! - every `pub use synvoid_http::…` facade resolves to a real module in
//!   `crates/synvoid-http/src` (prevents facade drift)
//! - Phase 01: `src/tls/server.rs` composes the canonical
//!   `prepare_http_request_flow` / `handle_http_request_postlude` stages and
//!   must not reacquire its own request-policy pipeline (routing, body
//!   collection, WAF-decision mapping, challenge rendering, upstream
//!   dispatch, proxy-cache dispatch)

use std::path::{Path, PathBuf};

fn read(repo: &Path, rel: &str) -> String {
    std::fs::read_to_string(repo.join(rel)).expect("read source file")
}

fn root_http_files(repo: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = repo.join("src/http");
    for entry in std::fs::read_dir(&dir).expect("read src/http") {
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

/// Root-owned application code exempt from the delegate-to-crate rule.
///
/// - `mod.rs`: module hub only
/// - `server.rs` + `server/`: `HttpServer` application composition root
/// - `directory_viewer` / `file_manager*` / `webdav`: application handlers
/// - `image_rights`: facade over `synvoid-static-files`, not `synvoid-http`
/// - `image_poisoning`: deprecated alias over `image_rights`
const NON_DELEGATING_MODULES: &[&str] = &[
    "mod.rs",
    "server.rs",
    "directory_viewer.rs",
    "file_manager.rs",
    "file_manager_ui.rs",
    "webdav.rs",
    "image_rights.rs",
    "image_poisoning.rs",
];

/// Root `src/http` must not implement its own parsing/normalization.
/// Hyper owns wire parsing; `synvoid-http` owns policy on top of it.
const FORBIDDEN_PARSER_TOKENS: &[&str] = &[
    "httparse::",
    "httparse::EMPTY_HEADER",
    "Status::Complete",
    "EarlyHttpParser",
];

#[test]
fn root_http_has_no_second_parser() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in root_http_files(&repo) {
        let text = std::fs::read_to_string(&path).expect("read root http file");
        for token in FORBIDDEN_PARSER_TOKENS {
            if text.contains(token) {
                offenders.push(format!(
                    "  {}: contains forbidden parser token `{token}` (canonical: synvoid-http)",
                    path.strip_prefix(&repo).unwrap().display()
                ));
            }
        }
    }
    for rel in ["src/tls/server.rs"] {
        let text = read(&repo, rel);
        for token in FORBIDDEN_PARSER_TOKENS {
            if text.contains(token) {
                offenders.push(format!(
                    "  {rel}: contains forbidden parser token `{token}` (canonical: synvoid-http)"
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "root must not implement a second HTTP parser/normalizer:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn root_http_dispatch_shims_delegate_to_crate() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in root_http_files(&repo) {
        let name = file_name(&path);
        if NON_DELEGATING_MODULES.contains(&name) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read root http file");
        if !text.contains("synvoid_http") {
            offenders.push(format!(
                "  {}: no `synvoid_http` delegation (move reusable logic to synvoid-http or document in http_ownership_convergence.md)",
                path.strip_prefix(&repo).unwrap().display()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "root http dispatch modules must delegate to the canonical crate:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn root_http_has_no_duplicate_waf_decision_tables() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `server.rs` is application composition (owns the service bundle that
    // invokes the canonical postlude); decision *mapping* tables must not
    // appear in any dispatch shim.
    let allowlist = ["server.rs"];
    let mut offenders = Vec::new();
    for path in root_http_files(&repo) {
        let name = file_name(&path).to_string();
        if allowlist.contains(&name.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read root http file");
        for variant in [
            "WafDecision::Drop",
            "WafDecision::Block",
            "WafDecision::Stall",
            "WafDecision::Tarpit",
            "WafDecision::Challenge",
            "WafDecision::Pass",
        ] {
            if text.contains(variant) {
                offenders.push(format!(
                    "  {}: matches on `{variant}` (canonical mapping: synvoid_http::waf_decision / streaming_waf_decision)",
                    path.strip_prefix(&repo).unwrap().display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "root http must not duplicate WAF-decision mapping tables:\n{}",
        offenders.join("\n")
    );
}

/// Phase 01 (TLS convergence): `HttpsServer` must compose the canonical
/// request-policy stages rather than maintaining its own pipeline.
/// TLS connection handling stays root-owned (handshake, ALPN, SNI/certs,
/// JA4 extraction, flood protection); request policy must not fork.
#[test]
fn tls_request_flow_stays_converged() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let text = read(&repo, "src/tls/server.rs");

    // Canonical composition must be present: both stages invoked.
    for required in [
        "prepare_http_request_flow",
        "handle_http_request_postlude",
        "ForwardedProtocol::Https",
        "ja4_hash",
    ] {
        assert!(
            text.contains(required),
            "src/tls/server.rs must compose canonical request policy (`{required}` missing)"
        );
    }

    // Duplicate request-policy pipeline tokens must not reappear.
    // (Each is owned by `synvoid-http` or the proxy/WAF crates.)
    let forbidden: &[&str] = &[
        "route_with_local_addr",
        "check_request_full(",
        "check_request_full_owned(",
        "collect_body_with_chunk_waf",
        "WafDecision::Drop",
        "WafDecision::Block",
        "WafDecision::Stall",
        "WafDecision::Tarpit",
        "WafDecision::Challenge",
        "WafDecision::Pass",
        "HONEYPOT_PREFIX",
        "generate_challenge_page",
        "record_css_asset_request",
        "ProxyServer::new_with_tls",
        "send_request_streaming",
        "StreamingWafBody::new",
        "build_forward_headers",
        "apply_security_headers",
        "INTERNAL_HEALTH_PATH",
        "INTERNAL_READY_PATH",
    ];
    let mut offenders = Vec::new();
    for token in forbidden {
        if text.contains(token) {
            offenders.push(format!(
                "  src/tls/server.rs: contains duplicate request-policy token `{token}` (canonical: synvoid-http / synvoid-proxy)"
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "HTTPS must not reacquire its own request-policy pipeline:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn root_http_facades_resolve_to_canonical_modules() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_src = repo.join("crates/synvoid-http/src");
    let lib_rs = read(&repo, "crates/synvoid-http/src/lib.rs");
    let mut offenders = Vec::new();
    for path in root_http_files(&repo) {
        let text = std::fs::read_to_string(&path).expect("read root http file");
        for line in text.lines() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("pub use synvoid_http::") else {
                continue;
            };
            // Module facades look like `pub use synvoid_http::<module>::…`;
            // bare item imports (`pub use synvoid_http::SomeType;`) are
            // checked against lib.rs re-exports instead.
            let Some((module, _)) = rest.split_once("::") else {
                let item = rest.trim_end_matches(';').trim();
                if !lib_rs.contains(item) {
                    offenders.push(format!(
                        "  {}: facade item `synvoid_http::{item}` is not re-exported by synvoid-http lib.rs",
                        path.strip_prefix(&repo).unwrap().display()
                    ));
                }
                continue;
            };
            let module = module.trim();
            if module.is_empty() {
                continue;
            }
            let module_file = crate_src.join(format!("{module}.rs"));
            if !module_file.exists() {
                offenders.push(format!(
                    "  {}: facade references missing canonical module `synvoid_http::{module}`",
                    path.strip_prefix(&repo).unwrap().display()
                ));
            }
            if !lib_rs.contains(&format!("pub mod {module}")) {
                offenders.push(format!(
                    "  {}: canonical module `{module}` is not declared in synvoid-http lib.rs",
                    path.strip_prefix(&repo).unwrap().display()
                ));
            }
        }
    }
    // Canonical normalization modules must exist regardless of facades.
    for module in [
        "framing",
        "early_parse",
        "headers",
        "body_policy",
        "request_parse",
        "request_preparation",
        "request_frontdoor",
        "waf_decision",
    ] {
        assert!(
            crate_src.join(format!("{module}.rs")).exists(),
            "canonical module crates/synvoid-http/src/{module}.rs is missing"
        );
    }
    assert!(
        offenders.is_empty(),
        "root http facades drifted from canonical modules:\n{}",
        offenders.join("\n")
    );
}

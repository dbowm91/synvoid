//! Phase 60-K: eggfetch compatibility-lane freeze guard.
//!
//! The legacy hyper transport (`HttpClient`, `StreamingHttpClient`,
//! `ErasedHttpClient`, `create_*`, `send_*`, erased pool/body types) is a
//! frozen compatibility surface owned by `synvoid-http-client`. All
//! production request paths run on the eggfetch lane
//! (`eggfetch_transport::EggfetchUpstreamClient`). This guard fails if any
//! production module outside `synvoid-http-client` drifts back to the
//! legacy lane.
//!
//! Intentionally out of scope (not violations):
//! - `crates/synvoid-http-client/**` itself (owns the frozen surface);
//! - integration tests under `*/tests/` (differential/parity harnesses
//!   exercise both lanes by design; unit tests inside `src/` are stripped
//!   via `prepare_for_scanning`);
//! - `StreamingWafBody` (lane-compatible request-body adapter in
//!   `synvoid-http`, not a transport);
//! - `UpstreamTlsConfig`, `HttpResponse`, `is_quictunnel_url` (shared
//!   policy/response vocabulary, transport-agnostic);
//! - `crate::http_client::send_request_via_quic_tunnel` (tunnel infra, not
//!   the legacy upstream lane).

use synvoid_repo_guards::{collect_source_files, prepare_for_scanning, workspace_root};

/// Legacy-lane tokens that must not appear in production code outside
/// `synvoid-http-client`. `http_client::`-qualified tokens cover both the
/// `synvoid_http_client::` and root-facade (`crate::http_client::`) paths.
const FORBIDDEN_TOKENS: &[&str] = &[
    "http_client::create_",
    "http_client::send_request",
    "http_client::send_unix",
    "http_client::get",
    "http_client::get_with_auth",
    "http_client::head_with_auth",
    "http_client::post_json",
    "HttpClient",
    "ErasedBody",
    "ErasedConnectionPool",
    "PoolKey",
    "from_hyper",
    "get_or_create_streaming",
];

/// Root-facade path that is only allowed for tunnel dispatch and the
/// entitled operator-lane adapter (`operator_lane_client`,
/// `EggfetchUpstreamClient` type).
const FACADE_PATH: &str = "crate::http_client::";

/// Facade uses that are not legacy-lane drift: tunnel dispatch plus the
/// Phase 60 operator-lane adapter owned by `src/http_client` (the entitled
/// composition module per `architecture/root_dependency_ownership.md`).
fn is_allowed_facade_use(line: &str) -> bool {
    line.contains("quic_tunnel")
        || line.contains("operator_lane_client")
        || line.contains("EggfetchUpstreamClient")
}

#[test]
fn eggfetch_lane_freeze_guard() {
    let root = workspace_root();
    let files = collect_source_files(&root);

    let mut violations = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&root).unwrap_or(&path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        // Owner crate + intentional dual-lane test harnesses + the frozen
        // root facade itself (production must not *use* it; the re-export
        // list naming the frozen surface is not a use).
        if rel_str.starts_with("crates/synvoid-http-client/") {
            continue;
        }
        if rel_str.starts_with("src/http_client/") {
            continue;
        }
        if rel_str.contains("/tests/") {
            continue;
        }
        // Only production trees: root `src/` and crate `src/`.
        let in_scope = rel_str.starts_with("src/")
            || (rel_str.starts_with("crates/") && rel_str.contains("/src/"));
        if !in_scope {
            continue;
        }

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let scanned = prepare_for_scanning(&content);
        for (i, line) in scanned.lines().enumerate() {
            // Tunnel dispatch is separate infra (still covered by the
            // facade-path rule below, which requires the quic_tunnel name).
            if !line.contains("quic_tunnel") {
                for token in FORBIDDEN_TOKENS {
                    if line.contains(token) {
                        violations.push(format!(
                            "  {}:{}: legacy lane token '{}': {}",
                            rel_str,
                            i + 1,
                            token,
                            line.trim()
                        ));
                    }
                }
            }
            if line.contains(FACADE_PATH) && !is_allowed_facade_use(line) {
                violations.push(format!(
                    "  {}:{}: root http_client facade use outside tunnel dispatch / operator lane: {}",
                    rel_str,
                    i + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eggfetch_lane_freeze_guard found {} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

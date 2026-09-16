//! Phase 35 crate-boundary reuse closeout guards.
//!
//! Pins the ownership contracts established by Phases 32-34:
//! - `synvoid-rate-limit` stays a std-only mechanism leaf (no domain deps,
//!   no WAF/policy vocabulary in code);
//! - `synvoid-http-client` stays policy-free transport (no config/core/metrics
//!   edges, no WAF body or site-TLS adapter reintroduction);
//! - reusable leaf crates never import the root `synvoid` facade;
//! - `src/utils/ratelimit` stays a thin compat re-export;
//! - `src/utils` carries no second URL-decoding implementation.

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
// synvoid-rate-limit dependency budget (Phase 33, re-pinned Phase 35)
// ---------------------------------------------------------------------------

const PROHIBITED_RATE_LIMIT_DEPS: &[&str] = &[
    "synvoid-waf",
    "synvoid-mesh",
    "synvoid-ipc",
    "synvoid-admin",
    "synvoid-config",
    "synvoid-core",
    "synvoid-utils",
    "synvoid-http-client",
    "hyper",
    "axum",
    "tonic",
    "metrics",
];

#[test]
fn rate_limit_dependency_budget() {
    let manifest = read_repo("crates/synvoid-rate-limit/Cargo.toml");
    let mut violations = Violations::new();
    for dep in PROHIBITED_RATE_LIMIT_DEPS {
        if manifest_declares(&manifest, dep) {
            violations.push(format!(
                "crates/synvoid-rate-limit/Cargo.toml declares prohibited dep '{dep}' \
                 (Phase 33 budget: std-only mechanism leaf)"
            ));
        }
    }
    violations.assert_ok("rate_limit_dependency_budget");
}

#[test]
fn rate_limit_imports_stay_mechanism_only() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-rate-limit/src");
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    // WAF/policy vocabulary must never appear in mechanism code (docs are
    // stripped by prepare_for_scanning, so only real code triggers).
    let forbidden = [
        "synvoid_waf",
        "synvoid_mesh",
        "synvoid_ipc",
        "synvoid_admin",
        "synvoid_config",
        "synvoid_core",
        "Blackholed",
        "blackhole",
    ];
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        for token in &forbidden {
            if code.contains(token) {
                violations.push(format!(
                    "{} contains domain/policy token '{token}' (mechanism only)",
                    file.display()
                ));
            }
        }
    }
    violations.assert_ok("rate_limit_imports_stay_mechanism_only");
}

#[test]
fn rate_limit_has_multiple_consumers() {
    // Retention bar (Phase 35): the crate must have at least two production
    // consumers (root WAF composition + mesh), not merely exist.
    let root_core = read_repo("src/waf/ratelimit/core.rs");
    let root_asn = read_repo("src/waf/asn_tracker.rs");
    let mesh_peer = read_repo("crates/synvoid-mesh/src/mesh/rate_limit.rs");
    let mesh_global = read_repo("crates/synvoid-mesh/src/mesh/transport_types.rs");
    let mut violations = Violations::new();
    if !root_core.contains("synvoid_rate_limit") {
        violations
            .push("src/waf/ratelimit/core.rs does not consume synvoid_rate_limit".to_string());
    }
    if !root_asn.contains("synvoid_rate_limit") {
        violations.push("src/waf/asn_tracker.rs does not consume synvoid_rate_limit".to_string());
    }
    if !mesh_peer.contains("synvoid_rate_limit") {
        violations.push(
            "crates/synvoid-mesh/src/mesh/rate_limit.rs does not consume synvoid_rate_limit"
                .to_string(),
        );
    }
    if !mesh_global.contains("synvoid_rate_limit") {
        violations.push(
            "crates/synvoid-mesh/src/mesh/transport_types.rs does not consume synvoid_rate_limit"
                .to_string(),
        );
    }
    violations.assert_ok("rate_limit_has_multiple_consumers");
}

// ---------------------------------------------------------------------------
// synvoid-http-client policy-free transport (Phase 34, re-pinned Phase 35)
// ---------------------------------------------------------------------------

const PROHIBITED_HTTP_CLIENT_DEPS: &[&str] = &[
    "synvoid-config",
    "synvoid-core",
    "synvoid-waf",
    "synvoid-mesh",
    "synvoid-admin",
    "metrics",
];

#[test]
fn http_client_dependency_budget() {
    let manifest = read_repo("crates/synvoid-http-client/Cargo.toml");
    let mut violations = Violations::new();
    for dep in PROHIBITED_HTTP_CLIENT_DEPS {
        if manifest_declares(&manifest, dep) {
            violations.push(format!(
                "crates/synvoid-http-client/Cargo.toml declares prohibited dep '{dep}' \
                 (Phase 34: policy-free transport; site→TLS lives in synvoid-upstream, WAF body in synvoid-http)"
            ));
        }
    }
    violations.assert_ok("http_client_dependency_budget");
}

#[test]
fn http_client_has_no_waf_policy() {
    let repo = workspace_root();
    let dir = repo.join("crates/synvoid-http-client/src");
    let files = collect_rs_files(&dir);
    let mut violations = Violations::new();
    // `StreamingWafBody`-style WAF policy must not be reintroduced into the
    // generic transport owner (doc mentions are stripped; only code counts).
    // `upstream_tls_from_site_config` is the site→TLS adapter owned by
    // `synvoid-upstream` and must not return here.
    let forbidden = [
        "StreamingWafBody",
        "StreamingWafScanner",
        "StreamingWafDecision",
        "upstream_tls_from_site_config",
        "synvoid_config",
        "synvoid_core",
        "synvoid_waf",
    ];
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_default();
        let code = prepare_for_scanning(&content);
        for token in &forbidden {
            if code.contains(token) {
                violations.push(format!(
                    "{} contains WAF/config policy token '{token}' (must live in synvoid-http/synvoid-upstream)",
                    file.display()
                ));
            }
        }
    }
    violations.assert_ok("http_client_has_no_waf_policy");
}

// ---------------------------------------------------------------------------
// reusable leaf crates never import the root facade
// ---------------------------------------------------------------------------

const REUSABLE_LEAF_CRATES: &[&str] = &[
    "crates/synvoid-platform/src",
    "crates/synvoid-rate-limit/src",
    "crates/synvoid-dnssec-keystore/src",
    "crates/synvoid-filter/src",
    "crates/synvoid-yara/src",
    "crates/synvoid-mesh-protocol/src",
    "crates/synvoid-http-client/src",
];

#[test]
fn reusable_leaf_crates_do_not_import_root() {
    let repo = workspace_root();
    let mut violations = Violations::new();
    for crate_dir in REUSABLE_LEAF_CRATES {
        let dir = repo.join(crate_dir);
        for file in collect_rs_files(&dir) {
            let rel = file
                .strip_prefix(&repo)
                .unwrap_or(&file)
                .to_string_lossy()
                .to_string();
            let content = fs::read_to_string(&file).unwrap_or_default();
            let code = prepare_for_scanning(&content);
            for (line_no, line) in code.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.contains("use synvoid::") {
                    violations.push(format!(
                        "{rel}:{}: reusable leaf imports root facade (must use narrow crates)",
                        line_no + 1
                    ));
                }
            }
        }
    }
    violations.assert_ok("reusable_leaf_crates_do_not_import_root");
}

// ---------------------------------------------------------------------------
// compat facades stay thin
// ---------------------------------------------------------------------------

#[test]
fn utils_ratelimit_compat_stays_thin() {
    let content = read_repo("src/utils/ratelimit/traits.rs");
    let code = prepare_for_scanning(&content);
    let mut violations = Violations::new();
    if !code.contains("pub use synvoid_rate_limit") {
        violations.push(
            "src/utils/ratelimit/traits.rs must re-export synvoid_rate_limit (compat only)"
                .to_string(),
        );
    }
    for token in ["struct ", "enum ", "trait ", "impl ", "fn "] {
        // `pub use` lines are re-exports; any other item is implementation.
        for (line_no, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("pub use ") || trimmed.starts_with("use ")
            {
                continue;
            }
            if trimmed.contains(token) {
                violations.push(format!(
                    "src/utils/ratelimit/traits.rs gained implementation at line {}: {trimmed}",
                    line_no + 1
                ));
                break;
            }
        }
    }
    violations.assert_ok("utils_ratelimit_compat_stays_thin");
}

#[test]
fn root_utils_has_no_second_url_implementation() {
    let content = read_repo("src/utils.rs");
    let code = prepare_for_scanning(&content);
    let mut violations = Violations::new();
    if !code.contains("pub use synvoid_core::url::") {
        violations.push(
            "src/utils.rs must re-export canonical synvoid_core::url (no second URL copy)"
                .to_string(),
        );
    }
    // A second `fn urlencoding_decode` or `fn url_decode_all` definition here
    // would recreate the Phase 35 duplicate (the old copy dropped `%`).
    for needle in ["fn urlencoding_decode", "fn url_decode_all"] {
        if code.contains(needle) {
            violations.push(format!(
                "src/utils.rs redefines '{needle}' (implement in synvoid-core, re-export here)"
            ));
        }
    }
    violations.assert_ok("root_utils_has_no_second_url_implementation");
}

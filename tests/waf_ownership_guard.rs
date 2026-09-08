//! Root-test ownership: STATIC_POLICY
//! Rationale: validates Phase 19 WAF ownership convergence (canonical
//! `synvoid-waf` engine vs root application composition)
//!
//! Guards the ownership model recorded in
//! `architecture/waf_ownership_convergence.md`:
//!
//! 1. `synvoid-waf` never imports the root `synvoid` crate.
//! 2. Root facade modules stay thin re-exports over the crate.
//! 3. Deleted duplicate/orphan implementations stay deleted.
//! 4. Removed hot-path placeholder checks stay out of the pipeline.
//! 5. Deprecated no-op compatibility shims gain no new production callers.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_to_string(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with("//")
}

fn walk_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn code_contains(path: &Path, needle: &str) -> bool {
    read_to_string(path)
        .lines()
        .any(|line| !is_comment_or_blank(line) && line.contains(needle))
}

/// 1. The domain engine must not depend on the root crate.
#[test]
fn waf_domain_crate_never_imports_root() {
    let root = workspace_root();
    let waf_dir = root.join("crates").join("synvoid-waf");
    let mut files = Vec::new();
    walk_rs_files(&waf_dir, &mut files);
    assert!(!files.is_empty(), "expected synvoid-waf sources");

    let mut offenders = Vec::new();
    for path in &files {
        for (line_num, line) in read_to_string(path).lines().enumerate() {
            if is_comment_or_blank(line) {
                continue;
            }
            // `crate::` inside the crate refers to synvoid-waf itself and is fine.
            // `synvoid::` would be the root application crate and is forbidden.
            if line.contains("use synvoid::") || line.contains(" synvoid::") {
                offenders.push(format!(
                    "{}:{}: {line}",
                    path.strip_prefix(&root).unwrap().display(),
                    line_num + 1
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "synvoid-waf must not import the root synvoid crate:\n{}",
        offenders.join("\n")
    );
}

/// 2. Root facades stay thin: they re-export the crate and hold no domain logic.
#[test]
fn root_waf_facades_remain_thin() {
    let root = workspace_root();
    let facades: &[(&str, &str)] = &[
        (
            "src/waf/probe_tracker.rs",
            "pub use synvoid_waf::probe_tracker::",
        ),
        (
            "src/waf/violation_tracker.rs",
            "pub use synvoid_waf::violation_tracker::",
        ),
        (
            "src/waf/attack_detection/mod.rs",
            "pub use synvoid_waf::attack_detection::",
        ),
        ("src/waf/flood/mod.rs", "pub use synvoid_waf::flood::"),
        (
            "src/waf/ratelimit/sliding.rs",
            "pub use synvoid_waf::ratelimit::sliding::",
        ),
    ];
    for (rel, marker) in facades {
        let path = root.join(rel);
        assert!(path.exists(), "facade missing: {rel}");
        let text = read_to_string(&path);
        assert!(
            text.lines()
                .any(|l| !is_comment_or_blank(l) && l.contains(marker)),
            "{rel} must re-export its canonical crate module ({marker})"
        );
        assert!(
            text.lines().count() <= 40,
            "{rel} must stay a thin facade (<=40 lines), got {}",
            text.lines().count()
        );
    }

    // traffic_shaper/mod.rs is a facade plus the root-owned `global` submodule.
    let ts = root.join("src/waf/traffic_shaper/mod.rs");
    let text = read_to_string(&ts);
    assert!(
        text.contains("pub use synvoid_waf::traffic_shaper::"),
        "traffic_shaper/mod.rs must re-export the canonical crate buckets/limiter"
    );
    assert!(
        text.contains("pub mod global;"),
        "traffic_shaper/mod.rs must retain the root-owned global submodule"
    );
    assert!(
        !ts.exists() || text.lines().count() <= 40,
        "traffic_shaper/mod.rs must stay thin"
    );

    // The canonical engine must retain its detector/policy modules.
    for module in [
        "pub mod attack_detection;",
        "pub mod bot;",
        "pub mod endpoints;",
        "pub mod enforcement;",
        "pub mod flood;",
        "pub mod primitives;",
        "pub mod probe_tracker;",
        "pub mod ratelimit;",
        "pub mod request_sanitization;",
        "pub mod traffic_shaper;",
        "pub mod traits;",
        "pub mod violation_tracker;",
    ] {
        assert!(
            code_contains(&root.join("crates/synvoid-waf/src/lib.rs"), module),
            "synvoid-waf/src/lib.rs must declare {module}"
        );
    }
}

/// 3. Deleted duplicates stay deleted.
#[test]
fn removed_duplicate_implementations_stay_deleted() {
    let root = workspace_root();
    let gone = [
        // Never-compiled root orphans shadowed by the crate re-export.
        "src/waf/flood/connection_limiter.rs",
        "src/waf/flood/syn_flood.rs",
        "src/waf/flood/udp_flood.rs",
        "src/waf/traffic_shaper/limiter.rs",
        // Stale crate copy: feed fetching needs the HTTP-client stack, so the
        // root feed integration is canonical (see waf_ownership_convergence.md).
        "crates/synvoid-waf/src/ip_feed.rs",
    ];
    let mut present = Vec::new();
    for rel in gone {
        if root.join(rel).exists() {
            present.push(rel.to_string());
        }
    }
    assert!(
        present.is_empty(),
        "removed duplicate implementations must stay deleted: {present:?}"
    );
}

/// 4. Removed hot-path placeholders stay out of the active pipeline.
#[test]
fn removed_hot_path_placeholders_stay_removed() {
    let root = workspace_root();
    let waf_mod = root.join("src/waf/mod.rs");
    for needle in [
        "check_block_store",
        "check_early",
        "block_ip_for_honeypot",
        "block_ip_with_threat_intel",
    ] {
        assert!(
            !code_contains(&waf_mod, needle),
            "src/waf/mod.rs must not contain removed placeholder `{needle}`"
        );
    }
    // The narrowed traits must not regain the removed no-op methods.
    let challenge_paths = root.join("crates/synvoid-http/src/challenge_paths.rs");
    assert!(
        !code_contains(&challenge_paths, "block_ip_for_honeypot"),
        "ChallengePathWaf must not regain block_ip_for_honeypot"
    );
    let upload_dispatch = root.join("crates/synvoid-http/src/upload_validation_dispatch.rs");
    assert!(
        !code_contains(&upload_dispatch, "block_ip_with_threat_intel"),
        "UploadValidationWaf must not regain block_ip_with_threat_intel"
    );
    let request_parse = root.join("crates/synvoid-http/src/request_parse.rs");
    assert!(
        !code_contains(&request_parse, "fn check_early"),
        "EarlyWafHooks must not regain check_early"
    );
}

/// 5. Deprecated no-op shims gain no new production callers.
///
/// Allowlist covers definitions, doc-comment mentions, the one retained
/// compatibility delegation (`UnifiedServer::reload_attack_detector`
/// forwards to the WAF handle), and the retained `early_waf_decision`
/// compatibility helper. Every other production file calling these shims
/// fails this guard.
#[test]
fn deprecated_noop_shims_gain_no_new_callers() {
    let root = workspace_root();
    let allow: &[(&str, &[&str])] = &[
        ("record_suspicious_words(", &["src/waf/mod.rs"]),
        ("set_request_services(", &["src/waf/mod.rs"]),
        (
            "reload_attack_detector(",
            &[
                "src/waf/mod.rs",
                "src/waf/rule_feed.rs",
                "src/server/mod.rs",
            ],
        ),
        (
            "early_waf_decision(",
            &[
                "crates/synvoid-http/src/request_parse.rs",
                "crates/synvoid-http/src/lib.rs",
            ],
        ),
    ];

    let mut search_roots = Vec::new();
    walk_rs_files(&root.join("src"), &mut search_roots);
    walk_rs_files(&root.join("crates"), &mut search_roots);

    let mut offenders = Vec::new();
    for path in &search_roots {
        let rel = path.strip_prefix(&root).unwrap().display().to_string();
        let text = read_to_string(path);
        for (needle, allowed_files) in allow {
            if !text
                .lines()
                .any(|l| !is_comment_or_blank(l) && l.contains(needle))
            {
                continue;
            }
            if allowed_files.iter().any(|a| rel == *a) {
                continue;
            }
            // Definitions of the compat helper itself are fine; call sites are not.
            if rel.ends_with("src/request_parse.rs") && needle.contains("early_waf_decision") {
                continue;
            }
            offenders.push(format!("{rel}: contains `{needle}`"));
        }
    }
    assert!(
        offenders.is_empty(),
        "deprecated no-op shims must gain no new production callers:\n{}",
        offenders.join("\n")
    );
}

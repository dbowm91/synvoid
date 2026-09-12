//! Phase 25 dependency-security guards: Wasmtime advisory baseline, advisory-ignore
//! metadata, verification-contract dependency policy, and root self-dev
//! feature-leak prevention.
//!
//! These guards keep `deny.toml`, `.cargo/audit.toml`,
//! `architecture/dependency_security_baseline_phase25.md`, `Cargo.toml`, and
//! `tools/xtask/src/verify.rs` mutually consistent so dependency policy cannot
//! silently drift.

use std::collections::BTreeSet;
use std::fs;
use synvoid_repo_guards::workspace_root;

fn read_repo(rel: &str) -> String {
    let repo = workspace_root();
    fs::read_to_string(repo.join(rel)).unwrap_or_else(|_| panic!("read {rel}"))
}

// ---------------------------------------------------------------------------
// wasmtime_baseline_guard (Phase 25 Part B)
// ---------------------------------------------------------------------------

fn guard_anchor(doc: &str, key: &str) -> Option<String> {
    for line in doc.lines() {
        let t = line.trim();
        let prefix = format!("<!-- guard-anchor: {key} = ");
        if let Some(rest) = t.strip_prefix(&prefix) {
            let value = rest.trim_end_matches(" -->").trim().trim_matches('"');
            return Some(value.to_string());
        }
    }
    None
}

#[test]
fn wasmtime_direct_version_matches_baseline() {
    let baseline = read_repo("architecture/dependency_security_baseline_phase25.md");
    let expected = guard_anchor(&baseline, "wasmtime-direct-version")
        .expect("baseline must anchor wasmtime-direct-version");

    // 1. Plugin-runtime manifest pins the documented direct version.
    let plugin_manifest = read_repo("crates/synvoid-plugin-runtime/Cargo.toml");
    assert!(
        plugin_manifest.contains(&format!("wasmtime = {{ version = \"{expected}\""))
            || plugin_manifest.contains(&format!("wasmtime={{\"version\":\"{expected}\""))
            || plugin_manifest.contains(&format!("version = \"{expected}\"")),
        "synvoid-plugin-runtime must pin wasmtime {expected} (baseline §1); \
         upgrade requires updating the baseline evidence first"
    );

    // 2. The [patch.crates-io] tag agrees (no silent dual-version direct runtime).
    let root_manifest = read_repo("Cargo.toml");
    assert!(
        root_manifest.contains(&format!("tag = \"v{expected}\"")),
        "root [patch.crates-io] wasmtime tag must be v{expected}"
    );

    // 3. 42.0.2 must never be described as patched for RUSTSEC-2026-0269.
    let deny = read_repo("deny.toml");
    let audit = read_repo(".cargo/audit.toml");
    for (name, content) in [
        ("deny.toml", deny.as_str()),
        (".cargo/audit.toml", audit.as_str()),
    ] {
        assert!(
            content.contains("RUSTSEC-2026-0269"),
            "{name} must track RUSTSEC-2026-0269 explicitly"
        );
    }
    assert!(
        !baseline.contains("42.0.2 is patched")
            && !baseline.contains("42.0.2 (patched")
            && !baseline.contains("patched for RUSTSEC-2026-0269"),
        "baseline must not describe 42.0.2 as patched for RUSTSEC-2026-0269"
    );
}

#[test]
fn wasmtime_wasi_stays_absent_without_exposure_update() {
    let baseline = read_repo("architecture/dependency_security_baseline_phase25.md");
    let lock = read_repo("Cargo.lock");
    let absent_claim = guard_anchor(&baseline, "wasmtime-wasi-absent-from-lock");
    let wasi_in_lock =
        lock.contains("name = \"wasmtime-wasi\"") || lock.contains("name = \"wasi-filesystem\"");
    match absent_claim.as_deref() {
        Some("true") => assert!(
            !wasi_in_lock,
            "wasmtime-wasi/wasi-filesystem appeared in Cargo.lock: update the baseline \
             exposure finding (§3) before this can land"
        ),
        _ => assert!(
            wasi_in_lock,
            "baseline no longer claims wasi absence but lock has no wasmtime-wasi — \
             re-anchor the baseline"
        ),
    }
}

// ---------------------------------------------------------------------------
// deny_ignore_metadata_guard (Phase 25 Part D)
// ---------------------------------------------------------------------------

/// Comment lines immediately preceding an ignored advisory ID carry its metadata.
/// A contiguous comment block preceding a RUN of consecutive IDs applies to the
/// whole run (grouped ignores share one rationale); a new comment block starts
/// a new run.
fn ignore_comment_blocks(deny: &str) -> std::collections::BTreeMap<String, String> {
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    let mut pending: Vec<&str> = Vec::new();
    let mut in_ignore = false;
    for line in deny.lines() {
        let t = line.trim();
        if t == "ignore = [" {
            in_ignore = true;
            continue;
        }
        if !in_ignore {
            continue;
        }
        if t.starts_with(']') {
            break;
        }
        if t.starts_with('#') {
            pending.push(t);
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if t.starts_with('"') {
            if let Some(q1) = t.find('"') {
                if let Some(q2) = t[q1 + 1..].find('"') {
                    let id = t[q1 + 1..q1 + 1 + q2].to_string();
                    map.insert(id, pending.join("\n"));
                    continue;
                }
            }
        }
        // Any other line ends the pending block without consuming it as metadata.
        pending.clear();
    }
    map
}

fn advisory_ids(deny: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut in_ignore = false;
    for line in deny.lines() {
        let t = line.trim();
        if t == "ignore = [" {
            in_ignore = true;
            continue;
        }
        if in_ignore {
            if t.starts_with(']') {
                break;
            }
            if let Some(q1) = t.find('"') {
                if let Some(q2) = t[q1 + 1..].find('"') {
                    ids.push(t[q1 + 1..q1 + 1 + q2].to_string());
                }
            }
        }
    }
    ids
}

/// Today's date as YYYY-MM-DD from the `SOURCE_DATE_EPOCH`-style environment is
/// unavailable in tests; instead compare against a fixed Phase 25 horizon that
/// maintainers bump deliberately. Any `Re-audit:`/`Remove-by:` date at or before
/// the horizon fails closed to force re-triage.
const REVIEW_HORIZON: &str = "2026-09-12";

#[test]
fn advisory_ignores_carry_owner_and_review_metadata() {
    let deny = read_repo("deny.toml");
    let ids = advisory_ids(&deny);
    assert!(
        !ids.is_empty(),
        "no advisory ignores parsed from deny.toml — schema changed?"
    );
    let mut violations = Vec::new();
    let blocks = ignore_comment_blocks(&deny);
    for id in &ids {
        let block = blocks.get(id).cloned().unwrap_or_default();
        let has_owner = block.contains("Owner:");
        let has_review = block.contains("Review:")
            || block.contains("Re-audit:")
            || block.contains("Remove-by:");
        if !has_owner || !has_review {
            violations.push(format!(
                "{id}: ignore lacks mandatory metadata (Owner: + Review:/Re-audit:/Remove-by:)"
            ));
            continue;
        }
        // Deadlines must lie strictly after the review horizon.
        for line in block.lines() {
            let t = line.trim_start_matches('#').trim();
            if t.starts_with("Re-audit:") || t.starts_with("Remove-by:") {
                // Extract the first YYYY-MM-DD token, if any.
                let mut found: Option<String> = None;
                let bytes = t.as_bytes();
                let mut i = 0;
                while i + 10 <= bytes.len() {
                    let cand = &t[i..i + 10];
                    if cand.as_bytes()[4] == b'-'
                        && cand.as_bytes()[7] == b'-'
                        && cand[..4].chars().all(|c| c.is_ascii_digit())
                        && cand[5..7].chars().all(|c| c.is_ascii_digit())
                        && cand[8..].chars().all(|c| c.is_ascii_digit())
                    {
                        found = Some(cand.to_string());
                        break;
                    }
                    i += 1;
                }
                if let Some(date) = found {
                    if date.as_str() <= REVIEW_HORIZON {
                        violations.push(format!(
                            "{id}: review deadline {date} reached (horizon {REVIEW_HORIZON}) — re-triage and bump"
                        ));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "deny.toml advisory-ignore metadata violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn audit_config_mirrors_deny_ignores() {
    // cargo-audit does not read deny.toml: the blocking `cargo audit` gate needs
    // the same narrow exceptions in `.cargo/audit.toml`, or release verification
    // fails on intentionally-accepted transitive findings.
    let deny = read_repo("deny.toml");
    let audit = read_repo(".cargo/audit.toml");
    let deny_ids: BTreeSet<String> = advisory_ids(&deny).into_iter().collect();
    let mut missing = Vec::new();
    for id in &deny_ids {
        if !audit.contains(id.as_str()) {
            missing.push(id.clone());
        }
    }
    assert!(
        missing.is_empty(),
        ".cargo/audit.toml missing ignores present in deny.toml:\n{}",
        missing.join("\n")
    );
}

// ---------------------------------------------------------------------------
// verify_contract_dependency_policy_guard (Phase 25 Part C)
// ---------------------------------------------------------------------------

#[test]
fn verify_contract_runs_dependency_policy() {
    let verify = read_repo("tools/xtask/src/verify.rs");
    // Routine `verify` must gate on dependency policy (blocking).
    assert!(
        verify.contains("\"cargo deny check\""),
        "verify.rs must run `cargo deny check` in the routine contract"
    );
    // Release qualification must repeat both checks (deny + audit).
    assert!(
        verify.contains("\"cargo audit\""),
        "verify.rs must run `cargo audit` in release qualification"
    );
    // The frozen contract doc must agree with the executable steps.
    let contract = read_repo("docs/testing/verification-contract.md");
    for needle in ["cargo deny check", "cargo audit"] {
        assert!(
            contract.contains(needle),
            "verification-contract.md must document `{needle}`"
        );
    }
}

// ---------------------------------------------------------------------------
// root_no_default_feature_leak_guard (Phase 25 Part G)
// ---------------------------------------------------------------------------

fn test_target_required_features(manifest: &str, target: &str) -> Option<String> {
    let mut current: Option<String> = None;
    let mut features: Option<String> = None;
    let mut in_test = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with("[[test]]") {
            if current.as_deref() == Some(target) {
                return features;
            }
            current = None;
            features = None;
            in_test = true;
            continue;
        }
        if t.starts_with('[') {
            if in_test && current.as_deref() == Some(target) {
                return features;
            }
            in_test = false;
            continue;
        }
        if in_test {
            if t.starts_with("name") {
                if let Some(v) = t.split('=').nth(1) {
                    current = Some(v.trim().trim_matches('"').to_string());
                }
            } else if t.starts_with("required-features") {
                features = Some(t.to_string());
            }
        }
    }
    if current.as_deref() == Some(target) {
        return features;
    }
    None
}

fn strip_line_comments(content: &str) -> String {
    content
        .lines()
        .map(|l| {
            //naive `//` strip that respects `://` (URLs) — good enough for `use` scans
            if let Some(idx) = l.find("//") {
                if !l[..idx].ends_with(':') {
                    return l[..idx].to_string();
                }
            }
            l.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn inside_string(line: &str, pos: usize) -> bool {
    let mut quotes = 0u32;
    let mut escaped = false;
    for b in line.as_bytes().iter().take(pos) {
        if escaped {
            escaped = false;
            continue;
        }
        if *b == b'\\' {
            escaped = true;
            continue;
        }
        if *b == b'"' {
            quotes += 1;
        }
    }
    quotes % 2 == 1
}

/// Track `#[cfg(feature = "..")]`-gated scopes by brace depth. Returns the set
/// of feature names whose cfg gates enclose each byte offset of a mesh/dns `use`.
fn gated_use_ok(content: &str, use_pos: usize) -> bool {
    // Walk lines up to use_pos, maintaining (depth, gated_features) stack.
    let upto = &content[..use_pos];
    let mut depth: i32 = 0;
    // stack of (depth_at_open, features or None)
    let mut stack: Vec<(i32, Option<String>)> = Vec::new();
    let mut pending_cfg: Option<String> = None;
    for line in upto.lines() {
        let t = line.trim();
        if t.starts_with("#[cfg(") || t.starts_with("#![cfg(") {
            // extract feature = "x" occurrences
            let mut feats = Vec::new();
            let mut s = t;
            while let Some(idx) = s.find("feature = \"") {
                let rest = &s[idx + 11..];
                if let Some(end) = rest.find('"') {
                    feats.push(rest[..end].to_string());
                }
                s = &rest[1.min(rest.len())..];
            }
            if t.starts_with("#![cfg(") {
                // file-level gate applies to everything after it
                if feats.iter().any(|f| f == "mesh" || f == "dns") {
                    return true;
                }
            } else if !feats.is_empty() {
                pending_cfg = Some(feats.join(","));
            }
            continue;
        }
        // item opens a scope: `mod x {`, `fn x() {`, etc. Consecutive attribute
        // lines (e.g. #[cfg] + #[test]) accumulate onto the same item.
        let opens = line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if t.starts_with('#') || t.is_empty() {
            // attribute or blank line: keep any pending cfg for the next item
        } else if t.starts_with("mod ")
            || t.starts_with("pub mod ")
            || t.contains(" fn ")
            || t.starts_with("fn ")
        {
            stack.push((depth, pending_cfg.take()));
        } else if pending_cfg.is_some() && opens > 0 {
            stack.push((depth, pending_cfg.take()));
        } else {
            pending_cfg = None;
        }
        depth += opens;
        while stack.last().map(|(d, _)| *d >= depth).unwrap_or(false) {
            stack.pop();
        }
    }
    stack.iter().any(|(_, f)| {
        f.as_ref()
            .map(|s| s.contains("mesh") || s.contains("dns"))
            .unwrap_or(false)
    })
}

#[test]
fn root_self_dev_edge_stays_minimal() {
    let manifest = read_repo("Cargo.toml");
    // 1. The self dev-edge must not re-enable default features.
    let mut in_dev = false;
    let mut edge_ok = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_dev = t == "[dev-dependencies]";
            continue;
        }
        if in_dev && t.starts_with("synvoid =") {
            assert!(
                t.contains("default-features = false"),
                "root [dev-dependencies] self edge must keep default-features = false"
            );
            edge_ok = true;
        }
    }
    assert!(edge_ok, "root self dev-dependency edge missing");

    // 2. Test targets importing mesh-gated items at top level need
    // `required-features` so minimal runs skip instead of failing to compile.
    let req = test_target_required_features(&manifest, "mesh_startup_rollback");
    assert!(
        req.map(|s| s.contains("mesh")).unwrap_or(false),
        "[[test]] mesh_startup_rollback must declare required-features mesh"
    );
}

#[test]
fn mesh_dns_test_imports_are_gated_or_declared() {
    let repo = workspace_root();
    let manifest = read_repo("Cargo.toml");
    let mut violations = Vec::new();
    let entries = fs::read_dir(repo.join("tests")).expect("read tests/");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let content = fs::read_to_string(&path).unwrap_or_default();
        let code = strip_line_comments(&content);
        // required-features declared for this target (if any).
        let declared = test_target_required_features(&manifest, &name).unwrap_or_default();
        let declares_mesh = declared.contains("mesh");
        let declares_dns = declared.contains("dns");
        for (idx, line) in code.lines().enumerate() {
            let t = line.trim();
            if !(t.starts_with("use synvoid::mesh::")
                || t.starts_with("use synvoid::dns::")
                || t.starts_with("use synvoid_mesh::")
                || t.starts_with("use synvoid_dns::"))
            {
                continue;
            }
            // String-literal fixtures must not count (checked positionally).
            if let Some(pos) = line.find("use syn") {
                if inside_string(line, pos) {
                    continue;
                }
            }
            let needs_mesh = t.contains("mesh");
            let covered = (needs_mesh && declares_mesh)
                || (!needs_mesh && declares_dns)
                || gated_use_ok(&code, code.lines().take(idx).map(|l| l.len() + 1).sum());
            if !covered {
                violations.push(format!(
                    "{}:{}: ungated feature import `{}` (gate with #[cfg(feature)] or required-features)",
                    path.display(),
                    idx + 1,
                    t
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "mesh/dns test imports must be feature-gated:\n{}",
        violations.join("\n")
    );
}

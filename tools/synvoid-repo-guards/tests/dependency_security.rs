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

/// Effective review date for advisory `Re-audit:` deadlines (corrective pass).
///
/// Production uses the current UTC civil date so an exception expires
/// automatically — no source-constant bump is required. Tests and release
/// tooling may pin a deterministic date via
/// `SYNVOID_SECURITY_REVIEW_AS_OF=YYYY-MM-DD`; a malformed override fails
/// closed. `SOURCE_DATE_EPOCH` is deliberately ignored here: reproducible
/// builds must not back-date security-review time (see
/// `docs/testing/verification-contract.md`).
pub fn effective_review_date() -> chrono::NaiveDate {
    if let Ok(override_date) = std::env::var("SYNVOID_SECURITY_REVIEW_AS_OF") {
        let trimmed = override_date.trim().to_string();
        return parse_ymd(&trimmed).unwrap_or_else(|| {
            panic!(
                "SYNVOID_SECURITY_REVIEW_AS_OF={trimmed:?} is not a valid YYYY-MM-DD date — failing closed"
            )
        });
    }
    chrono::Utc::now().date_naive()
}

/// Parse a strict `YYYY-MM-DD` calendar date. Returns `None` for malformed
/// values (wrong shape, out-of-range month/day, non-leap Feb 29, etc.).
/// Uses chrono so leap years and month lengths are correct.
pub fn parse_ymd(s: &str) -> Option<chrono::NaiveDate> {
    if s.len() != 10 {
        return None;
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

/// Extract every `Re-audit: YYYY-MM-DD` date token from a deny.toml comment
/// block, in order. A `Re-audit:` marker anywhere in a comment line counts
/// (both `# Re-audit: 2026-10-01.` on its own line and inline
/// `# Owner: security. Re-audit: 2026-10-01.` forms). A marker without a
/// parseable date yields `Err(malformed-line)`.
pub fn re_audit_dates_in_block(block: &str) -> Result<Vec<chrono::NaiveDate>, String> {
    let mut dates = Vec::new();
    for line in block.lines() {
        let t = line.trim_start_matches('#').trim();
        let mut search = t;
        while let Some(pos) = search.find("Re-audit:") {
            let rest = search[pos + "Re-audit:".len()..].trim_start();
            // First whitespace/comma/semicolon-delimited token is the date.
            let token: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != ',' && *c != ';')
                .collect::<String>()
                .trim_end_matches('.')
                .to_string();
            match parse_ymd(&token) {
                Some(d) => dates.push(d),
                None => return Err(format!("malformed Re-audit date {token:?} in {t:?}")),
            }
            search = &rest[token.len()..];
        }
    }
    Ok(dates)
}

/// Evaluate one advisory metadata block against an explicit `as_of` date.
/// Returns violation strings (empty = ok). Pure and unit-testable.
pub fn evaluate_advisory_block(id: &str, block: &str, as_of: chrono::NaiveDate) -> Vec<String> {
    let mut violations = Vec::new();
    if !block.contains("Owner:") {
        violations.push(format!("{id}: ignore lacks mandatory `Owner:` metadata"));
    }
    let dates = match re_audit_dates_in_block(block) {
        Ok(d) => d,
        Err(e) => {
            violations.push(format!("{id}: {e}"));
            return violations;
        }
    };
    if dates.is_empty() {
        violations.push(format!(
            "{id}: ignore lacks mandatory machine-readable `Re-audit: YYYY-MM-DD` deadline"
        ));
        return violations;
    }
    let first = dates[0];
    for d in &dates[1..] {
        if *d != first {
            violations.push(format!(
                "{id}: conflicting Re-audit dates in one metadata block ({} vs {})",
                first.format("%Y-%m-%d"),
                d.format("%Y-%m-%d")
            ));
        }
    }
    if first <= as_of {
        violations.push(format!(
            "{id}: Re-audit {} reached (as of {}) — re-triage and bump",
            first.format("%Y-%m-%d"),
            as_of.format("%Y-%m-%d")
        ));
    }
    violations
}

#[test]
fn advisory_ignores_carry_owner_and_review_metadata() {
    let deny = read_repo("deny.toml");
    let ids = advisory_ids(&deny);
    assert!(
        !ids.is_empty(),
        "no advisory ignores parsed from deny.toml — schema changed?"
    );
    let as_of = effective_review_date();
    let mut violations = Vec::new();
    let blocks = ignore_comment_blocks(&deny);
    for id in &ids {
        let block = blocks.get(id).cloned().unwrap_or_default();
        violations.extend(evaluate_advisory_block(id, &block, as_of));
    }
    assert!(
        violations.is_empty(),
        "deny.toml advisory-ignore metadata violations (as of {}):\n{}",
        as_of.format("%Y-%m-%d"),
        violations.join("\n")
    );
}

#[test]
fn audit_config_mirrors_deny_ignores() {
    // cargo-audit does not read deny.toml: the blocking `cargo audit` gate needs
    // the same narrow exceptions in `.cargo/audit.toml`, or release verification
    // fails on intentionally-accepted transitive findings. The sets must match
    // in both directions so neither tool silently accepts more than the other.
    let deny = read_repo("deny.toml");
    let audit = read_repo(".cargo/audit.toml");
    let deny_ids: BTreeSet<String> = advisory_ids(&deny).into_iter().collect();
    let audit_ids: BTreeSet<String> = advisory_ids(&audit).into_iter().collect();
    let mut violations = Vec::new();
    for id in deny_ids.difference(&audit_ids) {
        violations.push(format!(
            ".cargo/audit.toml missing ignore present in deny.toml: {id}"
        ));
    }
    for id in audit_ids.difference(&deny_ids) {
        violations.push(format!(
            "deny.toml missing ignore present in .cargo/audit.toml: {id}"
        ));
    }
    assert!(
        violations.is_empty(),
        "advisory ignore set mismatch:\n{}",
        violations.join("\n")
    );
}

#[cfg(test)]
mod re_audit_unit_tests {
    use super::{evaluate_advisory_block, parse_ymd, re_audit_dates_in_block};

    fn date(s: &str) -> chrono::NaiveDate {
        parse_ymd(s).expect("test date must parse")
    }

    #[test]
    fn parses_valid_dates_including_leap_day() {
        assert!(parse_ymd("2026-10-01").is_some());
        assert!(parse_ymd("2024-02-29").is_some()); // leap year
        assert!(parse_ymd("2026-12-31").is_some());
        assert!(parse_ymd("2026-01-01").is_some());
    }

    #[test]
    fn rejects_malformed_dates() {
        assert!(parse_ymd("2026-13-01").is_none()); // month 13
        assert!(parse_ymd("2026-00-10").is_none());
        assert!(parse_ymd("2025-02-29").is_none()); // non-leap Feb 29
        assert!(parse_ymd("2026-02-30").is_none());
        assert!(parse_ymd("2026-9-1").is_none()); // wrong shape
        assert!(parse_ymd("not-a-date").is_none());
        assert!(parse_ymd("").is_none());
        assert!(parse_ymd("2026/10/01").is_none());
    }

    #[test]
    fn year_boundary_comparison() {
        let new_years_eve = date("2026-12-31");
        let new_year = date("2027-01-01");
        assert!(new_year > new_years_eve);
        assert!(date("2026-10-01") > date("2026-09-13"));
        assert!(date("2026-10-01") == date("2026-10-01"));
    }

    #[test]
    fn deadline_before_on_after() {
        let block = "# Owner: security.\n# Reviewed: 2026-09-13.\n# Re-audit: 2026-10-01.\n# Remove condition: test.";
        assert!(evaluate_advisory_block("TEST-1", block, date("2026-09-13")).is_empty());
        assert!(evaluate_advisory_block("TEST-1", block, date("2026-09-30")).is_empty());
        // On the deadline day the exception has expired (fail closed).
        assert_eq!(
            evaluate_advisory_block("TEST-1", block, date("2026-10-01")).len(),
            1
        );
        assert_eq!(
            evaluate_advisory_block("TEST-1", block, date("2026-10-02")).len(),
            1
        );
    }

    #[test]
    fn missing_owner_or_deadline_fails() {
        let no_owner = "# Re-audit: 2026-10-01.";
        assert!(
            evaluate_advisory_block("TEST-2", no_owner, date("2026-09-13"))
                .iter()
                .any(|v| v.contains("Owner"))
        );
        let no_deadline = "# Owner: security.\n# Reviewed: 2026-09-13.";
        assert!(
            evaluate_advisory_block("TEST-3", no_deadline, date("2026-09-13"))
                .iter()
                .any(|v| v.contains("Re-audit"))
        );
    }

    #[test]
    fn malformed_and_conflicting_dates_fail() {
        let malformed = "# Owner: security.\n# Re-audit: not-a-date.";
        assert!(!evaluate_advisory_block("TEST-4", malformed, date("2026-09-13")).is_empty());
        let conflicting = "# Owner: security.\n# Re-audit: 2026-10-01.\n# Re-audit: 2026-11-01.";
        assert!(
            evaluate_advisory_block("TEST-5", conflicting, date("2026-09-13"))
                .iter()
                .any(|v| v.contains("conflicting"))
        );
        // Duplicate identical dates are tolerated (grouped-block rewrites).
        let duplicate_same = "# Owner: security.\n# Re-audit: 2026-10-01.\n# Re-audit: 2026-10-01.";
        assert!(evaluate_advisory_block("TEST-6", duplicate_same, date("2026-09-13")).is_empty());
    }

    #[test]
    fn re_audit_extraction_ignores_reviewed_and_remove_condition() {
        let block = "# Owner: security.\n# Reviewed: 2026-07-07.\n# Re-audit: 2026-10-01.\n# Remove condition: yara-x moves off wasmtime 40.x.";
        let dates = re_audit_dates_in_block(block).expect("must parse");
        assert_eq!(dates.len(), 1);
        assert_eq!(dates[0], date("2026-10-01"));
    }
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

//! Reachability and truthfulness gates for the DNS geo firewall.
//!
//! Registered by `plans/dns_geo_firewall_residual_closure.md`. Three defects are
//! pinned here, one per gate:
//!
//! 1. **F-3** — `GeoLocation::from_str` could not fail, so a malformed geo target
//!    degraded into a rule that matched nothing, and an unparseable ASN was
//!    *silently dropped*, widening an ASN-scoped rule to country-only. A parser
//!    that cannot fail cannot report a typo.
//! 2. **P-2** — `create_default_firewall_rules` and `create_rate_limit_rules` were
//!    dead `pub` builders with **zero callers** whose rule sets were not a stale
//!    copy of the live one but a *divergent* one. They were deleted rather than
//!    corrected, because a second copy of the internal-IP rule set is a subtler
//!    trap than the divergent one it replaces.
//! 3. **Stale status lines** — two `plans/` status lines claimed work was pending
//!    after it completed, one of which simultaneously claimed a campaign was
//!    `ACTIVE` and complete.
//!
//! Every gate here was mutation-tested against the exact regression it exists to
//! catch. A gate that cannot fail is worse than no gate, because it is read as
//! evidence.

use std::path::Path;

use synvoid_repo_guards::{collect_rs_files, workspace_root, Violations};

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// `source` with whole-line comments (`//`, `///`, `//!`) removed.
///
/// The parser legitimately *names* the patterns it rejects in prose — "a
/// non-empty field that is not a number is an error" is the opposite of a
/// violation. Only real code lines are gated.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of `impl std::str::FromStr for GeoLocation`, from its `impl` header
/// to the next top-level `impl` or `pub fn`.
///
/// Scoped deliberately: the gate is about *this* parser. `TimeWindow::from_str`
/// has its own parse-error handling and must not be dragged in by accident.
fn geo_location_from_str(source: &str) -> Option<String> {
    let start = source.find("impl std::str::FromStr for GeoLocation")?;
    let body = &source[start..];
    let end = body
        .find("\nimpl ")
        .or_else(|| body.find("\npub fn "))
        .unwrap_or(body.len());
    Some(body[..end].to_string())
}

/// Whether `code` names `symbol` as a whole identifier.
///
/// Whole-token, because substring matching cannot express the intent here.
fn mentions_symbol(code: &str, symbol: &str) -> bool {
    code.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == symbol)
}

/// Whether `code` calls `receiver.method(...)`, tolerating whitespace around the
/// dot so a rustfmt line break cannot hide it.
///
/// Needed because a loose `is_empty` check cannot tell `parts.is_empty()` — the
/// unreachable branch this gate exists to catch — from `country.is_empty()`, which
/// is the *fix*. An earlier version of this gate used the loose form and failed on
/// correct code.
fn method_called_on(code: &str, receiver: &str, method: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    let method_len = method.chars().count();
    if method_len == 0 || chars.len() < method_len + 1 {
        return false;
    }
    for i in method_len..=chars.len().saturating_sub(method_len) {
        if chars[i - 1] != '.' {
            continue;
        }
        if chars[i..i + method_len].iter().collect::<String>() != method {
            continue;
        }
        // Walk back over whitespace, then over the receiver identifier.
        let mut dot = i - 1;
        while dot > 0 && chars[dot - 1].is_whitespace() {
            dot -= 1;
        }
        let mut start = dot;
        while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
            start -= 1;
        }
        let ident: String = chars[start..dot].iter().collect();
        if ident.trim() == receiver {
            return true;
        }
    }
    false
}

/// **Gate 1.** `GeoLocation::from_str` must be able to fail, and must not discard
/// a malformed field.
///
/// Three regressions are gated:
/// - a **missing country** must be rejected (the old `parts.is_empty()` branch was
///   unreachable, because `"".split(',')` always yields one element);
/// - an ASN parse error must **not** be discarded via `.ok()` / `unwrap_or`, which
///   silently broadened the rule;
/// - the unreachable `parts.is_empty()` guard must not return.
///
/// The empty-ASN placeholder case is deliberately still legal, so the gate accepts
/// `None | Some("") => None` and rejects only a discard of a parse *result*.
#[test]
fn geo_firewall_target_parsing_is_not_silently_permissive() {
    let root = workspace_root();
    let firewall = root.join("crates/synvoid-dns/src/firewall.rs");
    let mut violations = Violations::new();

    if !firewall.exists() {
        violations.push(
            "`crates/synvoid-dns/src/firewall.rs` no longer exists. F-3 pinned the geo \
             target parser there; if it moved, re-measure and update this gate."
                .to_string(),
        );
    } else {
        let source = read(&firewall);
        match geo_location_from_str(&source) {
            None => violations.push(
                "`impl std::str::FromStr for GeoLocation` is gone from \
                 `crates/synvoid-dns/src/firewall.rs`. A geo target must not become \
                 parseable by another route without re-measuring F-3."
                    .to_string(),
            ),
            Some(body) => {
                let code = code_only(&body);

                // The missing-country rejection must still be here. This is the
                // *positive* shape; the unreachable `parts.is_empty()` shape is
                // checked separately below.
                if !method_called_on(&code, "country", "is_empty") {
                    violations.push(
                        "F-3 regression: `GeoLocation::from_str` no longer rejects an \
                         empty country. Without that rejection a spec with no country \
                         parses into a rule that matches nothing and reports nothing."
                            .to_string(),
                    );
                }

                // The silent-discard shape. `parse::<u32>().ok()` and
                // `.unwrap_or(None)` both turn a typo into a *broader* rule; only an
                // explicit `map_err(..)?` (or a match returning `Err`) reports it.
                for discard in [".parse::<u32>().ok()", ".unwrap_or(None)"] {
                    if code.contains(discard) {
                        violations.push(format!(
                            "F-3 regression: `GeoLocation::from_str` contains \
                             `{discard}`. That discards an ASN parse error and silently \
                             broadens an ASN-scoped rule to country-only — for an `Allow` \
                             action, a silent widening of the grant."
                        ));
                    }
                }

                // The unreachable-guard shape the residual actually named. Scoped to
                // `parts` specifically: `country.is_empty()` is the fix, not the defect.
                if method_called_on(&code, "parts", "is_empty") {
                    violations.push(
                        "F-3 regression: `GeoLocation::from_str` checks whether `parts` \
                         is empty. `\"\".split(',')` always yields one element, so that \
                         branch is unreachable and the parser is infallible again."
                            .to_string(),
                    );
                }
            }
        }
    }

    violations.assert_ok("F-3 geo firewall target parsing must not be silently permissive");
}

/// **Gate 2.** The internal-IP block rule set must have exactly one definition.
///
/// P-2 recorded `create_default_firewall_rules` as an unverified parallel helper.
/// Measuring it showed it was not a stale copy but a **divergent** one: it shipped
/// `block_multicast`, `block_reserved_domains`, `block_example_domains`,
/// `block_zone_transfer`, and `block_ixfr` — none of which the live path installs —
/// while omitting loopback, link-local, and every IPv6 internal range. A reader who
/// trusted it would conclude that multicast and IXFR are blocked in production and
/// that loopback is not.
///
/// The fix was deletion, so this gate stops any builder-shaped reappearance in
/// `synvoid-dns`, and pins that the live definition still exists where it is
/// claimed to be.
#[test]
fn internal_ip_rules_have_exactly_one_definition() {
    let root = workspace_root();
    let dns_src = root.join("crates/synvoid-dns/src");
    let mut violations = Violations::new();

    for file in collect_rs_files(&dns_src) {
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        // `server/mod.rs` holds the live, config-driven definition.
        if name == "mod.rs" {
            continue;
        }
        let code = code_only(&read(&file));
        for builder in ["create_default_firewall_rules", "create_rate_limit_rules"] {
            if mentions_symbol(&code, builder) {
                violations.push(format!(
                    "P-2 regression: `{name}` names `{builder}`. The live internal-IP rules \
                     are config-driven and built only in \
                     `crates/synvoid-dns/src/server/mod.rs`. A second builder is either a \
                     divergent duplicate that misleads a reader, or a copy that must be \
                     synchronised by hand forever."
                ));
            }
        }
    }

    // The live definition must still be present, or this gate would pass vacuously
    // against a deleted posture.
    //
    // Whole-token, not substring: `block_loopback` is a prefix of any renamed
    // variant, so a `contains` check passes on `block_loopback_removed`. That was
    // not hypothetical — it is how mutation M5 slipped past the first version of
    // this gate.
    let live = code_only(&read(&dns_src.join("server/mod.rs")));
    for id in [
        "block_internal_ips",
        "block_loopback",
        "block_ipv6_loopback",
    ] {
        if !mentions_symbol(&live, id) {
            violations.push(format!(
                "the live internal-IP rule set no longer defines `{id}`. `block_internal_ips` \
                 is the posture `docs/FEATURE_STATUS.md` documents; if it changed, update the \
                 doc and this gate together"
            ));
        }
    }

    violations.assert_ok("the internal-IP rule set must have exactly one definition");
}

/// **Gate 3.** A `plans/` status line may not claim a campaign is open after
/// claiming it is closed.
///
/// Two real instances were corrected: `plans/roadmap.md` declared the DNS
/// residual-truthfulness campaign `ACTIVE` and then, two sentences later, that it
/// was "complete; no phase remains registered"; and
/// `plans/runtime_dependency_security_followup_roadmap.md` still read "Phase 38
/// pending" after Phase 38 completed and `deny.toml` was re-audited.
///
/// Scoped per file, and a file only counts once it actually *has* a status line, so
/// the gate cannot fire on prose that merely discusses the word "ACTIVE". A
/// corpus-wide counter turns a silently-empty scan into a failure rather than a
/// pass.
#[test]
fn no_plan_status_line_claims_a_closed_campaign_is_open() {
    let root = workspace_root();
    let plans = root.join("plans");
    let mut violations = Violations::new();

    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&plans)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();

    let mut checked = 0usize;
    for path in &files {
        let source = read(path);
        // Only files that actually carry a status line are in scope.
        let Some(status_line) = source
            .lines()
            .find(|line| line.trim_start().starts_with("Status:"))
        else {
            continue;
        };
        checked += 1;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        let claims_closed = status_line.contains("CLOSED")
            || status_line.contains("COMPLETE")
            || status_line.contains("complete");
        let claims_open =
            status_line.contains("**ACTIVE**") || status_line.to_lowercase().contains("pending");

        if claims_closed && claims_open {
            violations.push(format!(
                "`plans/{name}` has a status line claiming both closure and openness: \
                 `{status_line}`. A reader cannot tell whether the work is scheduled."
            ));
        }
    }

    violations.assert_ok("no plan status line may claim a closed campaign is open");

    // Vacuity check: an empty scan proves nothing, so a guard that stopped seeing the
    // corpus must fail rather than pass. Evaluated after `assert_ok` so a real
    // violation is reported as a violation.
    assert!(
        checked > 50,
        "the status-line scan only inspected {checked} of {} plan files, so it is not \
         actually scanning `plans/`. A guard that stops seeing its corpus is worse than \
         no guard.",
        files.len()
    );
}

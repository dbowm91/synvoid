//! Phase 140 — `prefer_post_quantum` must never be documented as a gate.
//!
//! ## The defect this pins
//!
//! `prefer_post_quantum` is a `TlsConfig` field that selects nothing. Availability
//! of hybrid post-quantum key exchange comes from the compiled-in rustls
//! `prefer-post-quantum` feature, which `synvoid-tls` enables unconditionally.
//! `prefer_post_quantum_does_not_gate_the_hybrid_key_exchange`
//! (`crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs`) already pins
//! the *behaviour* with a real handshake, and Phase 140 left that test unmodified.
//!
//! What it did not pin was the **wording**. Phase 140 found the field described as
//! a functional switch in eight places across five documents, including the
//! operator-facing `docs/CONFIGURATION.md` ("Use hybrid PQ KEX", "protects against
//! future quantum computers", "disable it for legacy clients") and the
//! `tls_termination` skill ("honors `prefer_post_quantum`"). One document also
//! carried a second error: `docs/HTTP3.md` listed the default as `false` when
//! `synvoid-config` defaults it to `true`.
//!
//! A behavioural pin cannot catch wording, and wording is what misleads. These
//! gates read prose and require it to agree with the behaviour pin.

use std::fs;
use std::path::Path;

use synvoid_repo_guards::{workspace_root, Violations};

/// Documents that mention the field and are therefore in scope.
///
/// Deliberately an explicit list rather than a repo-wide scan: an open-ended scan
/// would also match the closeouts and plans that *describe the defect*, which is
/// the opposite of a violation.
const IN_SCOPE_DOCS: &[&str] = &[
    "docs/CONFIGURATION.md",
    "docs/HTTP3.md",
    "architecture/tls.md",
    "architecture/config.md",
    "architecture/dns_config_runtime_matrix.md",
    ".opencode/skills/tls_termination/SKILL.md",
];

/// Phrasings that assert the field changes behaviour.
const FUNCTIONAL_CLAIMS: &[&str] = &[
    "enable post-quantum key exchange",
    "use hybrid post-quantum",
    "uses hybrid pq",
    "enabling hybrid",
    "honors `prefer_post_quantum`",
    "honours `prefer_post_quantum`",
    "if `prefer_post_quantum` is set",
    "via `prefer_post_quantum`",
    "requires a --features post-quantum",
    "only takes effect in `--features post-quantum`",
    "only activates in builds compiled",
    "needs the `post-quantum` feature at build",
];

fn read(rel: &str) -> String {
    let root = workspace_root();
    fs::read_to_string(root.join(rel)).unwrap_or_default()
}

/// Only the prose of a line counts. A markdown table row or comment that says
/// "corrected in Phase 140" quotes the bad phrasing to disown it, and a guard that
/// fired on that would punish the correction.
fn prose(line: &str) -> &str {
    let trimmed = line.trim_start();
    // `//` and `<!--` are comment syntax in Rust and HTML; in markdown a cell can
    // legitimately begin with them too.
    if trimmed.starts_with("//") || trimmed.starts_with("<!--") {
        return "";
    }
    trimmed
}

/// Phase 140 acceptance criterion: *"no doc claims a post-quantum preference is
/// honored by this setting."* This is the mechanical form of that criterion.
#[test]
fn no_in_scope_document_claims_the_setting_is_functional() {
    let mut violations = Violations::new();

    for doc in IN_SCOPE_DOCS {
        let path = workspace_root().join(doc);
        if !Path::new(&path).exists() {
            violations.push(format!(
                "{doc} is in the Phase 140 guard's scope list but no longer exists; \
                 re-scope this gate rather than letting it silently stop covering it"
            ));
            continue;
        }
        for (index, line) in read(doc).lines().enumerate() {
            let text = prose(line).to_lowercase();
            if text.is_empty() {
                continue;
            }
            // Only lines that actually talk about *this setting* are in scope.
            // Without this, a correct sentence elsewhere in the same document —
            // "listeners negotiate a hybrid PQ key exchange because …" — reads as a
            // violation, and a gate that punishes accuracy gets worked around rather
            // than satisfied.
            if !text.contains("prefer_post_quantum") {
                continue;
            }
            for claim in FUNCTIONAL_CLAIMS {
                if text.contains(&claim.to_lowercase()) {
                    violations.push(format!(
                        "{doc}:{} asserts that `prefer_post_quantum` is functional \
                         (`{claim}`). It selects nothing — hybrid PQ key exchange comes \
                         from the compiled-in rustls `prefer-post-quantum` feature. \
                         Describe it as telemetry",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("no_in_scope_document_claims_the_setting_is_functional");
}

/// The banner previously interpolated the inert field into an operator-facing log,
/// directly beneath a truthful `#[cfg(feature = "post-quantum")]` line. Reintroducing
/// it would restore the contradiction.
#[test]
fn the_startup_banner_does_not_read_the_inert_field() {
    let server = read("src/tls/server.rs");

    let mut violations = Violations::new();

    // Statement-scoped, not line-scoped. rustfmt breaks a `tracing::info!` call
    // across lines, so the macro name and the interpolated field routinely sit on
    // different lines — a line-scoped check silently passes the exact regression it
    // exists to catch. Each `tracing::` call is therefore scanned as a whole,
    // from the macro token to its closing `);`.
    let mut checked_spans = 0usize;
    let mut cursor = 0usize;
    while let Some(offset) = server[cursor..].find("tracing::") {
        let start = cursor + offset;
        let end = server[start..]
            .find(");")
            .map(|len| start + len + 2)
            .unwrap_or(server.len());
        checked_spans += 1;

        let statement = &server[start..end];
        if statement.contains("prefer_post_quantum") {
            let line = server[..start].lines().count();
            violations.push(format!(
                "src/tls/server.rs:{} logs the inert `prefer_post_quantum` field. The \
                 startup profile must be derived from `tls_1_3_only` / \
                 `enable_tls_12_fallback` and the compiled-in feature — a field that \
                 selects nothing must not appear in an operator-facing log",
                line
            ));
        }
        cursor = end;
    }

    if checked_spans == 0 {
        violations.push(
            "no `tracing::` statement was found in src/tls/server.rs; this gate would \
             pass vacuously against a rewritten banner. Re-scope it rather than \
             trusting a zero-match run"
                .to_string(),
        );
    }

    violations.assert_ok("the_startup_banner_does_not_read_the_inert_field");
}

/// Both definitions must say "telemetry" where a reader will actually see it.
///
/// The persisted schema is where an operator's editor resolves the key, so a rustdoc
/// sentence on the internal struct alone does not cover the real surface.
#[test]
fn both_definitions_document_the_setting_as_telemetry() {
    let mut violations = Violations::new();

    for (rel, marker) in [
        ("crates/synvoid-config/src/tls.rs", "Telemetry only"),
        ("crates/synvoid-tls/src/config.rs", "Telemetry only"),
    ] {
        let source = read(rel);
        if !source.contains(marker) {
            violations.push(format!(
                "{rel} must document `prefer_post_quantum` as \"{marker}\". Without it \
                 at the definition, the next reader has only the field name to go on"
            ));
        }
    }

    violations.assert_ok("both_definitions_document_the_setting_as_telemetry");
}

/// The behavioural pin must survive. Phase 140's rejection criteria bar modifying
/// or deleting it, and it is the only thing that proves the setting is inert —
/// every other gate here reads prose.
#[test]
fn the_handshake_pin_still_exists_and_is_unmodified_in_spirit() {
    let evidence = read("crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs");

    let mut violations = Violations::new();

    for required in [
        "fn prefer_post_quantum_does_not_gate_the_hybrid_key_exchange(",
        "X25519MLKEM768",
        "config.prefer_post_quantum = false;",
    ] {
        if !evidence.contains(required) {
            violations.push(format!(
                "`crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs` must still \
                 contain `{required}`. This test is the behavioural proof that the \
                 setting is telemetry; Phase 140 is forbidden from weakening it"
            ));
        }
    }

    violations.assert_ok("the_handshake_pin_still_exists_and_is_unmodified_in_spirit");
}

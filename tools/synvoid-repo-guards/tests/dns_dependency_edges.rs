//! Dependency-edge gates for the `synvoid-dns` runtime-DTO campaign.
//!
//! Phases 125–130 progressively remove `synvoid-dns`'s edges to the
//! persistence and shared-utility crates, so that the DNS crate depends only
//! on its DNS-owned runtime vocabulary plus genuine providers.
//!
//! These gates read `crates/synvoid-dns/Cargo.toml` rather than counting
//! source references: a dependency edge is a manifest fact, and a source scan
//! cannot distinguish "the crate may name this type" from "the crate links
//! this crate". Each gate is added by the phase that owns the removal, so a
//! regression is attributed to the phase that introduced it.
//!
//! | Edge | Removed by | Gate |
//! |------|-----------|------|
//! | `synvoid-config` | Phase 128 | `synvoid_dns_has_no_config_edge` |
//! | `synvoid-core` | Phase 129 | `synvoid_dns_has_no_core_edge` |
//! | `synvoid-utils` | Phase 129 | `synvoid_dns_has_no_utils_edge` |

use std::path::Path;

use synvoid_repo_guards::{workspace_root, Violations};

/// Sections of `Cargo.toml` that can declare a dependency edge. A crate may
/// name `synvoid-config` in `[dev-dependencies]` for an owned test, but the
/// campaign's goal is that the *crate itself* carries no edge, so every
/// section is checked.
const DEPENDENCY_SECTIONS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

fn read_manifest(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Whether `manifest` declares `edge` (a bare SynVoid crate name) in any
/// dependency section.
///
/// Matching is whole-token on the key so `synvoid-dnssec-keystore` is never
/// mistaken for `synvoid-dns`, and so a path-style entry
/// (`synvoid-core = { path = ... }`) is matched exactly like a version-style
/// one.
fn declares_edge(manifest: &str, edge: &str) -> bool {
    let mut in_section = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let name = trimmed.trim_matches(['[', ']']);
            in_section = DEPENDENCY_SECTIONS.iter().any(|s| {
                *s == name
                    || name
                        .strip_prefix(s)
                        .is_some_and(|rest| rest.starts_with('.'))
            });
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, _)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() == edge {
            return true;
        }
    }
    false
}

fn assert_no_edge(edge: &str, context: &str) {
    let root = workspace_root();
    let manifest_path = root.join("crates/synvoid-dns/Cargo.toml");
    let manifest = read_manifest(&manifest_path);

    let mut violations = Violations::new();

    if declares_edge(&manifest, edge) {
        violations.push(format!(
            "crates/synvoid-dns/Cargo.toml declares `{edge}`; the DNS runtime crate \
             must depend only on its own runtime vocabulary and genuine providers. \
             Persisted schema is converted by `src/server/dns_runtime_config.rs`"
        ));
    }

    violations.assert_ok(context);
}

#[test]
fn synvoid_dns_has_no_config_edge() {
    // Phase 128: every persisted DNS section (`dnssec`, `zones`, TSIG, HSM,
    // anycast) is converted to DNS-owned runtime values, so the crate no
    // longer links the crate that owns the persisted schema.
    assert_no_edge("synvoid-config", "synvoid_dns_has_no_config_edge");
}

#[test]
#[ignore = "Phase 129 owns the `synvoid-core` removal; this gate goes live with it"]
fn synvoid_dns_has_no_core_edge() {
    // Phase 129: timestamps and net helpers move to `std` / crate-local code.
    assert_no_edge("synvoid-core", "synvoid_dns_has_no_core_edge");
}

#[test]
#[ignore = "Phase 129 owns the `synvoid-utils` removal; this gate goes live with it"]
fn synvoid_dns_has_no_utils_edge() {
    // Phase 129: the shared utility helpers are inlined or replaced with
    // library equivalents.
    assert_no_edge("synvoid-utils", "synvoid_dns_has_no_utils_edge");
}

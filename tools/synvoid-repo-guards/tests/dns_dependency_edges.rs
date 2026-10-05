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
//!
//! All three are live as of Phase 129. The DNS crate now depends only on its
//! own runtime vocabulary plus genuine providers (`synvoid-tls`,
//! `synvoid-geoip`, `synvoid-dnssec-keystore`) and the optional `synvoid-mesh`.
//! Provider inversion remains out of scope for Phases 125-130, so this set is
//! the qualification target Phase 130 measures against.
//!
//! Section 5 (Phase 133) gates the *provider seams* rather than the dependency
//! edges: the TLS seam must stay one-way for key custody and provider-internal
//! for reload, and the GeoIP seam must stay exactly two methods wide. Those
//! gates are what make Phases 134 and 135 mechanical rather than exploratory.

use std::path::Path;

use synvoid_repo_guards::{collect_rs_files, workspace_root, Violations};

/// Sections of `Cargo.toml` that can declare a dependency edge. A crate may
/// name `synvoid-config` in `[dev-dependencies]` for an owned test, but the
/// campaign's goal is that the *crate itself* carries no edge, so every
/// section is checked.
const DEPENDENCY_SECTIONS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

fn read_manifest(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn read(path: &Path) -> String {
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
fn synvoid_dns_has_no_core_edge() {
    // Phase 129: timestamps and net helpers move to `std` / crate-local code.
    assert_no_edge("synvoid-core", "synvoid_dns_has_no_core_edge");
}

#[test]
fn synvoid_dns_has_no_utils_edge() {
    // Phase 129: the shared utility helpers are inlined or replaced with
    // library equivalents.
    assert_no_edge("synvoid-utils", "synvoid_dns_has_no_utils_edge");
}

// ---------------------------------------------------------------------------
// 4. Source-level gate: the neutralized helpers stay DNS-owned
// ---------------------------------------------------------------------------

/// The manifest gates prove the *edge* is gone. This gate proves the crate did
/// not keep calling the removed helpers through a re-export, a `use` alias, or
/// a dev-dependency escape hatch.
///
/// Mesh-gated code is included on purpose: Phase 129 Workstream D requires
/// that the optional mesh feature cannot restore the utils dependency.
#[test]
fn production_source_names_neither_neutralized_helper_crate() {
    let root = workspace_root();
    let src = root.join("crates/synvoid-dns/src");
    let files = collect_rs_files(&src);

    let mut violations = Violations::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();
        for (index, line) in read(&file).lines().enumerate() {
            let trimmed = line.trim_start();
            // Comments and doc comments legitimately name the predecessors:
            // the module docs record what each helper replaced.
            if trimmed.starts_with("//") {
                continue;
            }
            for forbidden in [
                "synvoid_core",
                "synvoid_utils",
                "synvoid-core",
                "synvoid-utils",
            ] {
                if !trimmed.contains(forbidden) {
                    continue;
                }
                // A bare doc line is fine; a `use` or a call path is not.
                if trimmed.starts_with("use ") || trimmed.contains("::") {
                    violations.push(format!(
                        "{rel}:{} references `{forbidden}`; after the Phase 129 \
                         cutover `synvoid-dns` owns its time, restricted-IP, and \
                         lifecycle helpers. Use `crate::time`, `crate::net_policy`, \
                         and `crate::lifecycle`",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("production_source_names_neither_neutralized_helper_crate");
}

// ---------------------------------------------------------------------------
// 5. Provider-seam gates (Phase 133 evidence)
// ---------------------------------------------------------------------------
//
// Phase 133 adds the evidence that Phases 134 and 135 invert against. These
// gates pin the *seam's* shape, not just the dependency edge, so a widened
// surface is attributed to the phase that widened it.

/// Phase 133 A-3: private-key custody is one-way. `synvoid-tls` reads, validates,
/// and loads key material; `synvoid-dns` may only ever receive
/// `Arc<rustls::ServerConfig>`. If DNS can name key material, the DNSSEC-style
/// one-way custody rule is broken for the TLS path too.
#[test]
fn dns_never_names_tls_private_key_material() {
    let root = workspace_root();
    let files = collect_rs_files(&root.join("crates/synvoid-dns/src"));

    let mut violations = Violations::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();
        for (index, line) in read(&file).lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for forbidden in [
                "PrivateKeyDer",
                "CertifiedKey",
                "load_private_key",
                "secret_pkcs1_der",
                "secret_pkcs8_der",
                "key_provider",
            ] {
                if trimmed.contains(forbidden) {
                    violations.push(format!(
                        "{rel}:{} names `{forbidden}`; TLS private-key custody is \
                         one-way through `synvoid-tls`, which is also the DNSSEC \
                         custody rule. `synvoid-dns` may only hold an \
                         `Arc<rustls::ServerConfig>`",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("dns_never_names_tls_private_key_material");
}

/// Phase 133 A-2: certificate reload is entirely provider-internal. The
/// broadcast channel, the filesystem watcher, and the load entry point are all
/// `synvoid-tls` / composition concerns. If DNS reaches any of them, then a
/// DNS-owned trait in Phase 134 would have to model reload as well, which is
/// exactly the coupling this gate forbids.
#[test]
fn dns_does_not_drive_certificate_reload() {
    let root = workspace_root();
    let files = collect_rs_files(&root.join("crates/synvoid-dns/src"));

    let mut violations = Violations::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();
        for (index, line) in read(&file).lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for forbidden in ["reload_tx", "watch_for_cert_changes", "load_certificates"] {
                if trimmed.contains(forbidden) {
                    violations.push(format!(
                        "{rel}:{} references `{forbidden}`; certificate reload is \
                         `synvoid-tls`-internal. `synvoid-dns` consumes a built \
                         `ServerConfig` and must not participate in reloading",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("dns_does_not_drive_certificate_reload");
}

/// Phase 133 B-6: the GeoIP provider surface is exactly two methods,
/// `get_country_info` and `get_asn_info`. A third call would silently widen the
/// trait that Phase 135 introduces, so the seam is pinned as a set rather than
/// as an absence.
#[test]
fn dns_names_exactly_the_two_geoip_provider_methods() {
    let root = workspace_root();
    let files = collect_rs_files(&root.join("crates/synvoid-dns/src"));

    let mut seen: Vec<String> = Vec::new();
    let mut violations = Violations::new();

    for file in files {
        for (index, line) in read(&file).lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            // Provider methods are reached as `geoip.<method>(` or
            // `manager.<method>(`. Only a fixed allow-list may appear.
            for method in [
                "get_country_info",
                "get_asn_info",
                "get_continent_code",
                "check_ip",
                "lookup_country",
                "lookup_asn",
                "status",
            ] {
                let needle = format!(".{method}(");
                if !trimmed.contains(&needle) {
                    continue;
                }
                // `check_ip` and `status` are legitimate on DNS-owned types
                // (the rate limiter and the firewall stats); only flag them when
                // they sit on a geoip handle, which is checked separately below.
                if method == "check_ip" || method == "status" {
                    continue;
                }
                if !seen.contains(&method.to_string()) {
                    seen.push(method.to_string());
                }
                if method == "get_continent_code" || method.starts_with("lookup_") {
                    let rel = file
                        .strip_prefix(&root)
                        .unwrap_or(&file)
                        .display()
                        .to_string();
                    violations.push(format!(
                        "{rel}:{} calls `{method}`; the DNS GeoIP provider surface is \
                         `get_country_info` and `get_asn_info` only. Anything else \
                         must be justified and the Phase 135 trait re-scoped",
                        index + 1
                    ));
                }
            }
        }
    }

    seen.sort();
    assert_eq!(
        seen,
        vec!["get_asn_info".to_string(), "get_country_info".to_string()],
        "the GeoIP provider surface reached from synvoid-dns"
    );
    violations.assert_ok("dns_names_exactly_the_two_geoip_provider_methods");
}

/// Phase 133 A-6: the encrypted-transport TLS contract is **duplicated**, not
/// shared. DoT and DoH go through `SecureDnsServerBase::create_tls_acceptor`;
/// DoQ is QUIC and has its own `DoqServer::create_tls_config`, because `quinn`
/// needs a `QuicServerConfig` and `DoqRuntimeConfig` does not implement
/// `DnsServerConfig`.
///
/// Both copies hardcode the same two literals, and both call the same single
/// provider method. Phase 134 replaces that method with a trait, and an
/// inversion that updates one copy and not the other would silently give DoQ
/// different diagnostics from DoT and DoH. This gate keeps the two in step.
#[test]
fn encrypted_transport_error_contract_is_duplicated_consistently() {
    let root = workspace_root();
    let base = read(&root.join("crates/synvoid-dns/src/secure_server.rs"));
    let doq = read(&root.join("crates/synvoid-dns/src/doq.rs"));

    let mut violations = Violations::new();

    for literal in [
        "No TLS certificate resolver available",
        "Failed to build TLS config: ",
    ] {
        let in_base = base.contains(literal);
        let in_doq = doq.contains(literal);
        assert_eq!(
            in_base, in_doq,
            "the encrypted-transport error literal `{literal}` must appear in \
             both `secure_server.rs` and `doq.rs`, or in neither"
        );
        if !in_base {
            violations.push(format!(
                "the literal `{literal}` disappeared from both encrypted-transport \
                 TLS paths; a DNS-owned trait must keep reproducing it"
            ));
        }
    }

    // The provider seam itself is one method in both copies.
    for (name, source) in [("secure_server.rs", &base), ("doq.rs", &doq)] {
        let calls = source.matches(".build_server_config()").count();
        assert_eq!(
            calls, 1,
            "{name} must call the provider exactly once, found {calls}"
        );
    }

    violations.assert_ok("encrypted_transport_error_contract_is_duplicated_consistently");
}

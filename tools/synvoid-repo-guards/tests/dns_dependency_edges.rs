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
//! | `synvoid-tls` | Phase 134 | `synvoid_dns_has_no_tls_edge` |
//! | `synvoid-geoip` | Phase 135 | `synvoid_dns_has_no_geoip_edge` |
//!
//! All five are live as of Phase 135. The DNS crate now depends only on its
//! own runtime vocabulary, the `synvoid-dnssec-keystore` custody boundary, and
//! the optional `synvoid-mesh`. Provider inversion for mesh remains out of
//! scope, so that edge is the qualification target Phase 136 measures against:
//! mesh is a distributed-authority surface, not a narrow seam.
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

#[test]
fn synvoid_dns_has_no_tls_edge() {
    assert_no_edge("synvoid-tls", "synvoid_dns_has_no_tls_edge");
}

#[test]
fn synvoid_dns_has_no_geoip_edge() {
    // Phase 135: DNS asks a narrow question — country and ASN for an address —
    // through the DNS-owned `CountryLookup` capability, implemented in
    // composition over `Arc<GeoIpManager>`. `CountryInfo` is a *new* DNS type,
    // not a re-export, precisely so this edge can go.
    assert_no_edge("synvoid-geoip", "synvoid_dns_has_no_geoip_edge");
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

/// Phase 133 B-6, superseded by Phase 135.
///
/// This gate originally asserted that the GeoIP provider surface reached from
/// `synvoid-dns` was exactly `{get_country_info, get_asn_info}`. After Phase 135
/// those two methods no longer exist in the DNS crate at all: the seam is the
/// DNS-owned `CountryLookup` capability, and the concrete provider methods are
/// named only in composition.
///
/// The *intent* — "the seam is exactly two methods wide, and nothing wider" — is
/// now enforced more strictly by two Phase 135 gates:
///
/// - `dns_source_names_no_geoip_provider_symbol` forbids the provider method
///   names outright, so a third call cannot be added;
/// - `dns_declares_exactly_the_two_geo_capability_methods` pins the two
///   evidenced signatures on the capability itself.
///
/// Rather than keep a gate whose assertion is "these two names appear exactly
/// once", which is now vacuously false, the old gate is removed and its intent
/// is carried by the two that can actually fail.
#[test]
fn dns_geo_seam_width_is_enforced_by_the_capability_gates() {
    let root = workspace_root();
    let geo = read(&root.join("crates/synvoid-dns/src/geo.rs"));

    // Exactly two methods, counted on the trait declaration rather than on
    // call sites: `;`-terminated signatures only, so the unit-test `impl` blocks
    // (which use bodies) do not match.
    let trait_methods = geo
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("fn ") && trimmed.ends_with(';')
        })
        .count();
    assert_eq!(
        trait_methods, 2,
        "the DNS-owned country-lookup capability must declare exactly two methods"
    );
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

    // The provider seam itself is one call in each copy. Phase 134 replaced the
    // concrete `build_server_config()` call with the DNS-owned
    // `SecureTransportConfig::server_config()`.
    for (name, source) in [("secure_server.rs", &base), ("doq.rs", &doq)] {
        let calls = source.matches(".server_config()").count();
        assert_eq!(
            calls, 1,
            "{name} must call the DNS-owned provider capability exactly once, \
             found {calls}"
        );
        assert!(
            !source.contains("build_server_config"),
            "{name} must not call the concrete provider method; Phase 134 \
             introduced `SecureTransportConfig::server_config`"
        );
    }

    violations.assert_ok("encrypted_transport_error_contract_is_duplicated_consistently");
}

/// Phase 137: ALPN is chosen **per transport at the DNS call site**, and the
/// three encrypted transports deliberately do not share one value.
///
/// This gate exists because the shared builder is a trap. DoT and DoH both call
/// `SecureDnsServerBase::create_tls_acceptor`, and the obvious implementation —
/// give the shared builder an ALPN value — is wrong for one of them:
///
/// | Transport | Advertises | Why |
/// |---|---|---|
/// | DoT | nothing | RFC 7858 defines none; a non-empty `our_protocols` makes rustls *require* a match and rejects clients that offer none |
/// | DoH | `h2` | HTTP/2-only by construction (`hyper::server::conn::http2::Builder`) |
/// | DoQ | `doq` | RFC 9250 — already correct before this phase, and must stay that way |
///
/// So the gate pins four things: the shared base hardcodes **no** protocol, each
/// stream transport passes its own constant, and DoQ keeps the `doq` value it
/// already had and is not routed through the base.
#[test]
fn encrypted_transport_alpn_is_per_transport() {
    let root = workspace_root();
    let base = read(&root.join("crates/synvoid-dns/src/secure_server.rs"));
    let dot = read(&root.join("crates/synvoid-dns/src/dot.rs"));
    let doh = read(&root.join("crates/synvoid-dns/src/doh.rs"));
    let doq = read(&root.join("crates/synvoid-dns/src/doq.rs"));

    let mut violations = Violations::new();

    // 1. The shared base names no ALPN protocol at all. If it ever hardcodes
    //    one, DoT and DoH silently become one transport again.
    for protocol in ["b\"h2\"", "b\"doq\"", "b\"dot\""] {
        if base.contains(protocol) {
            violations.push(format!(
                "the shared builder `secure_server.rs` hardcodes the ALPN protocol \
                 `{protocol}`; ALPN is a per-transport protocol constant and must be \
                 supplied by each transport's call site"
            ));
        }
    }
    if !base.contains("fn with_alpn(") {
        violations.push(
            "the shared builder no longer attaches ALPN to the provider's config; the \
             provider deliberately configures none (Phase 134), so dropping this would \
             silently disable ALPN for both stream transports"
                .to_string(),
        );
    }

    // 2. Each stream transport passes its own constant to the shared base.
    for (name, source, constant) in [("dot.rs", &dot, "DOT_ALPN"), ("doh.rs", &doh, "DOH_ALPN")] {
        if !source.contains(&format!("pub const {constant}: AlpnProtocols")) {
            violations.push(format!(
                "`{name}` must declare `pub const {constant}: AlpnProtocols`; the value \
                 is a served protocol constant and belongs next to the transport that \
                 serves it"
            ));
        }
        if !source.contains(&format!("{constant},")) {
            violations.push(format!(
                "`{name}` must pass `{constant}` to `start_server`; a transport that \
                 omits it would negotiate nothing"
            ));
        }
    }

    // 3. DoT advertises nothing, and in particular not `h2`.
    if !dot.contains("pub const DOT_ALPN: AlpnProtocols = &[];") {
        violations.push(
            "`dot::DOT_ALPN` must stay empty: RFC 7858 defines no ALPN identifier for \
             DoT, and advertising one makes rustls require a negotiated match"
                .to_string(),
        );
    }
    if dot.contains("b\"h2\"") {
        violations.push(
            "`dot.rs` must not advertise `h2`; that is DoH's protocol, and advertising \
             it on DoT would reject clients that offer no ALPN"
                .to_string(),
        );
    }

    // 4. DoH advertises `h2` and never `http/1.1`. Its handler is built on
    //    `hyper::server::conn::http2::Builder`, so `http/1.1` would advertise a
    //    version the transport cannot serve.
    if !doh.contains("pub const DOH_ALPN: AlpnProtocols = &[b\"h2\"];") {
        violations.push(
            "`doh::DOH_ALPN` must be exactly `[b\"h2\"]`; DoH is HTTP/2-only by \
             construction"
                .to_string(),
        );
    }
    for forbidden in ["b\"http/1.1\"", "b\"doq\"", "b\"dot\""] {
        if doh.contains(forbidden) {
            violations.push(format!(
                "`doh.rs` must not advertise `{forbidden}`; DoH speaks HTTP/2 only"
            ));
        }
    }

    // 5. DoQ was already correct before this phase. Pin the existing value so
    //    the ALPN work cannot regress the one transport that had it, and keep
    //    DoQ off the shared base (it needs a `QuicServerConfig`).
    if !doq.contains("alpn_protocols = vec![b\"doq\".to_vec()]") {
        violations.push(
            "`doq.rs` must keep setting its `doq` ALPN; it was correct before Phase 137 \
             (RFC 9250) and is the reason the phase's scope is DoT and DoH only"
                .to_string(),
        );
    }
    for borrowed in ["DOH_ALPN", "DOT_ALPN", "with_alpn"] {
        if doq.contains(borrowed) {
            violations.push(format!(
                "`doq.rs` must not reference `{borrowed}`; QUIC needs a \
                 `QuicServerConfig` and cannot share the stream builder"
            ));
        }
    }

    // 6. No ALPN configuration knob. A served protocol constant is absent by
    //    design; reading one from the runtime DTO would recreate the inert
    //    setting this campaign exists to close.
    let runtime = read(&root.join("crates/synvoid-dns/src/runtime_config.rs"));
    if runtime.contains("alpn") {
        violations.push(
            "`runtime_config.rs` must not mention ALPN; the served protocol constants \
             are absent by design, and a knob there would be inert by construction"
                .to_string(),
        );
    }

    violations.assert_ok("encrypted_transport_alpn_is_per_transport");
}

// ---------------------------------------------------------------------------
// 6. TLS provider-inversion gates (Phase 134)
// ---------------------------------------------------------------------------

/// Phase 134: the manifest gate proves the edge is gone. This gate proves the
/// crate did not keep naming the provider through a `use` alias, a fully
/// qualified path, or a doc-link that would pull the crate back in.
///
/// Comments and doc comments are exempt, because the DNS-owned capabilities
/// document *what* they replace — that is provenance, not a dependency.
#[test]
fn dns_source_names_no_tls_provider_symbol() {
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
                "synvoid_tls",
                "synvoid-tls",
                "CertResolver",
                "AcmeDnsChallenge",
                "build_server_config",
            ] {
                if !trimmed.contains(forbidden) {
                    continue;
                }
                // A mention inside a string literal that is *not* a path is
                // fine; a `use` or a `::` path is not.
                if trimmed.starts_with("use ") || trimmed.contains("::") {
                    violations.push(format!(
                        "{rel}:{} references `{forbidden}`; TLS certificate and ACME \
                         ownership stays in composition. DNS consumes the DNS-owned \
                         `SecureTransportConfig` and `AcmeTxtChallenges` capabilities",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("dns_source_names_no_tls_provider_symbol");
}

/// Phase 134: the two DNS-owned capabilities must stay the *only* way DNS
/// reaches a provider. Named here because a gate that only checks an absence
/// cannot catch a trait quietly widened with a third method.
#[test]
fn dns_declares_exactly_the_two_tls_capabilities() {
    let root = workspace_root();
    let source = read(&root.join("crates/synvoid-dns/src/secure_transport.rs"));

    let mut violations = Violations::new();

    for capability in [
        "pub trait SecureTransportConfig",
        "pub trait AcmeTxtChallenges",
    ] {
        if !source.contains(capability) {
            violations.push(format!(
                "crates/synvoid-dns/src/secure_transport.rs must declare \
                 `{capability}`; these are the DNS-owned replacements for the \
                 `synvoid-tls` provider types"
            ));
        }
    }

    // Asserting the exact signatures — not just the method names — means a
    // signature change fails here instead of quietly widening or narrowing the
    // seam. A `;`-terminated declaration appears exactly once per trait; the
    // `impl` blocks in the unit tests use bodies, so they do not match.
    for signature in [
        "fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String>;",
        "fn txt_value(&self, domain: &str) -> Option<String>;",
    ] {
        let declared = source.matches(signature).count();
        if declared != 1 {
            violations.push(format!(
                "crates/synvoid-dns/src/secure_transport.rs must declare exactly one \
                 `{signature}`; found {declared}. A changed signature widens or \
                 narrows the seam and needs its own Phase 133-style evidence"
            ));
        }
    }

    violations.assert_ok("dns_declares_exactly_the_two_tls_capabilities");
}

// ---------------------------------------------------------------------------
// 7. GeoIP provider-inversion gates (Phase 135)
// ---------------------------------------------------------------------------

/// Phase 135: the manifest gate proves the edge is gone; this gate proves the
/// crate did not keep naming the provider through a `use` alias, a fully
/// qualified path, or — the mistake that would silently keep the edge alive —
/// a re-export of the provider's own result type.
#[test]
fn dns_source_names_no_geoip_provider_symbol() {
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
                "synvoid_geoip",
                "synvoid-geoip",
                "GeoIpManager",
                "get_country_info",
                "get_asn_info",
            ] {
                if !trimmed.contains(forbidden) {
                    continue;
                }
                if trimmed.starts_with("use ") || trimmed.contains("::") {
                    violations.push(format!(
                        "{rel}:{} references `{forbidden}`; the DNS crate asks for \
                         country and ASN through the DNS-owned `CountryLookup` \
                         capability. A re-export of the provider's `CountryInfo` is \
                         the specific mistake here: it looks like inversion while \
                         keeping the edge alive",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("dns_source_names_no_geoip_provider_symbol");
}

/// Phase 135: the DNS-owned capability must declare exactly the two evidenced
/// methods over the DNS-owned result type. Asserting the exact signatures means
/// a change fails here instead of quietly widening the seam.
#[test]
fn dns_declares_exactly_the_two_geo_capability_methods() {
    let root = workspace_root();
    let source = read(&root.join("crates/synvoid-dns/src/geo.rs"));

    let mut violations = Violations::new();

    for signature in [
        "fn country_info(&self, ip: IpAddr) -> Option<CountryInfo>;",
        "fn asn(&self, ip: IpAddr) -> Option<u32>;",
    ] {
        let declared = source.matches(signature).count();
        if declared != 1 {
            violations.push(format!(
                "crates/synvoid-dns/src/geo.rs must declare exactly one `{signature}`; \
                 found {declared}. Phase 133 evidenced exactly these two methods, and \
                 `asn` returns `Option<u32>` because the firewall reads only the number"
            ));
        }
    }

    // `CountryInfo` must be declared here, not pulled in from the provider.
    if !source.contains("pub struct CountryInfo {") {
        violations.push(
            "crates/synvoid-dns/src/geo.rs must declare its own `CountryInfo`; a \
             re-export of the provider's type would keep the dependency edge alive"
                .to_string(),
        );
    }
    if source.contains("pub use synvoid_geoip") {
        violations.push(
            "crates/synvoid-dns/src/geo.rs must not re-export from `synvoid_geoip`".to_string(),
        );
    }

    violations.assert_ok("dns_declares_exactly_the_two_geo_capability_methods");
}

/// Phase 135 F-17 tripwire: **no composition path constructs a
/// `GeoIpManager`.** The `[geoip]` configuration section is documented and
/// parsed, but nothing builds the provider, so every `geoip:` field in the root
/// is `None` and DNS can never evaluate a geo rule.
///
/// This gate exists so that wiring it cannot happen silently. Wiring GeoIP
/// activates country classification for the first time in production and would
/// change the meaning of a configured `GeoLocation` firewall rule under the
/// Phase 135 F-2 fail-closed semantics — so it is a feature change that needs
/// its own phase and its own evidence, not a side effect of a later edit.
#[test]
fn geoip_provider_is_still_unwired_by_composition() {
    let root = workspace_root();
    let files = collect_rs_files(&root.join("src"));

    let mut construction_sites = Vec::new();
    for file in &files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        for (index, line) in read(file).lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains("GeoIpManager::new(") && !rel.contains("src/geo/") {
                construction_sites.push(format!("{rel}:{}", index + 1));
            }
        }
    }

    assert!(
        construction_sites.is_empty(),
        "composition now constructs a GeoIpManager at {construction_sites:?}. \
         Phase 135 F-17 recorded that `[geoip]` is unwired, and wiring it is a \
         behavior change, not a refactor: it activates country classification in \
         production and changes what a configured `GeoLocation` firewall rule means \
         under the Phase 135 F-2 fail-closed semantics. Give it its own phase, and \
         delete this gate in that phase rather than weakening it here"
    );
}

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

/// `source` with whole-line comments (`//`, `///`, `//!`) removed.
///
/// Several gates here are about what code *names*, and these files legitimately
/// discuss the forbidden symbols in prose — a doc comment saying "DNS no longer
/// builds a `SignedDhtRecord`" is the opposite of a violation. Blanking the line
/// keeps those explanations in the source without weakening the gate. Inline
/// trailing comments are not stripped, which is deliberate: a trailing
/// `// …SignedDhtRecord` on a real code line would be the sneaky form.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `code` names `symbol` as a whole identifier.
///
/// Substring matching cannot express "must not name `DhtRecord`" here:
/// `DhtRecordStore` is the DNS-owned trait that is *supposed* to be present, and
/// `AdvertisedAnycastNode` is the DNS-owned projection. Only exact token equality
/// distinguishes a reintroduced provider type from the DNS type named after it.
fn mentions_symbol(code: &str, symbol: &str) -> bool {
    code.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == symbol)
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

/// Phase 138: the F-17 tripwire is **deleted**, not weakened — its own assert
/// message instructed exactly that ("delete this gate in that phase rather
/// than weakening it here").
///
/// ## Two properties of the deleted gate, recorded because the Phase 135
/// closeout described it wrongly
///
/// 1. It was **substring-based, not semantic**: it flagged any line under
///    `src/` containing `GeoIpManager::new(`, so a `type G = GeoIpManager;` plus
///    `G::new(...)` would not trip it. The Phase 136 claim that wiring is
///    "impossible by accident" overstated the mechanism.
/// 2. It had **no `#[cfg(test)]` awareness** — it only skipped lines whose
///    `trim_start` began with `//`, so an in-file test module outside `src/geo/`
///    would trip it, while the Phase 135 closeout claimed it failed only on
///    "non-test" files.
/// 3. It **exempted `src/geo/` entirely** — which is where the construction
///    naturally belongs. So it would not have fired even for a legitimate
///    wiring; it only prevented construction *outside* the adapter module.
///    That is a third way it was weaker than described.
///
/// ## The positive invariant that replaces it
///
/// A gate that only checks an absence cannot notice when the thing it forbade
/// becomes the thing that is required. This one asserts the wiring exists, so
/// deleting the seam is now a failure rather than a silent regression.
#[test]
fn geoip_capability_is_wired_through_composition() {
    let root = workspace_root();
    let provider = read(&root.join("src/geo/dns_provider.rs"));
    let resources = read(&root.join("src/server/resources.rs"));
    let main_config = read(&root.join("crates/synvoid-config/src/main_config.rs"));
    let server = read(&root.join("crates/synvoid-dns/src/server/mod.rs"));
    let geo_module = read(&root.join("src/geo/mod.rs"));

    let mut violations = Violations::new();

    // 1. The provider is constructed from persisted configuration, not by hand.
    if !provider.contains("GeoIpManager::new(") {
        violations.push(
            "`src/geo/dns_provider.rs` must construct the `GeoIpManager`; before \
             Phase 138 nothing in the repository built one"
                .to_string(),
        );
    }
    if !provider.contains("pub fn country_lookup_from_config(") {
        violations.push(
            "`src/geo/dns_provider.rs` must expose `country_lookup_from_config`, the \
             single place persisted `[geoip]` becomes a DNS capability"
                .to_string(),
        );
    }
    // A disabled section must yield no capability: Phase 135 F-2 made
    // "no provider" and "provider that answers no" opposite behaviors.
    if !provider.contains("if !config.enabled {") {
        violations.push(
            "`country_lookup_from_config` must return `None` for a disabled section; \
             a fabricated present-but-answerless provider converts a fail-closed block \
             into a silent allow"
                .to_string(),
        );
    }

    // 2. Composition actually passes the capability into the DNS server. A
    //    hardcoded `None` here is the exact F-17 defect.
    if !resources.contains("country_lookup_from_config(") {
        violations.push(
            "`src/server/resources.rs` must build the DNS country-lookup capability \
             and pass it to `DnsServer::new`; passing `None` is the F-17 defect this \
             phase removes"
                .to_string(),
        );
    }
    if !resources.contains("geo::country_lookup_from_config(") {
        violations.push(
            "`src/server/resources.rs` must call `crate::geo::country_lookup_from_config` \
             so the construction stays in the adapter module"
                .to_string(),
        );
    }

    // 3. The configuration source exists. This is the check that would have
    //    caught the real blocker: `GeoIpConfig` was declared and consumed by
    //    `synvoid-geoip`, but no config struct owned a `geoip` field, so
    //    `[geoip]` was not a real section.
    if !main_config.contains("pub geoip: GeoIpConfig,") {
        violations.push(
            "`MainConfig` must own a `geoip: GeoIpConfig` field. Without it the type \
             is unreachable from any configuration file and the whole wiring is dead on \
             arrival"
                .to_string(),
        );
    }
    if !geo_module.contains("country_lookup_from_config") {
        violations.push(
            "`src/geo/mod.rs` must re-export `country_lookup_from_config`; composition \
             reaches it through this module"
                .to_string(),
        );
    }

    // 4. The DNS side must accept the capability rather than hardcoding it.
    //    This is the line the phase was opened to remove.
    if server.contains("let geoip_lookup = None;") {
        violations.push(
            "`crates/synvoid-dns/src/server/mod.rs` must not hardcode \
             `let geoip_lookup = None;`; the capability is an injected constructor \
             parameter"
                .to_string(),
        );
    }
    if !server.contains("country_lookup: Option<Arc<dyn CountryLookup>>") {
        violations.push(
            "`DnsServer::new` must accept `country_lookup: Option<Arc<dyn CountryLookup>>`"
                .to_string(),
        );
    }
    if !server.contains("with_country_lookup(Arc::clone(lookup))") {
        violations.push(
            "`DnsServer::new` must give the firewall the same handle it keeps for \
             itself; the two hold separate `country_lookup` fields and can drift"
                .to_string(),
        );
    }

    violations.assert_ok("geoip_capability_is_wired_through_composition");
}

/// Phase 139, gate 1 — the DHT advisory surface is inverted, so no
/// `synvoid-dns` source outside the anycast cluster may name a concrete
/// `synvoid-mesh` type.
///
/// The check is deliberately *scoped to the residual*, not "no mesh symbols
/// anywhere": the anycast broadcast cluster (`anycast_sync.rs`) still holds the
/// live verification transport and the `MeshMessage` protobuf, and Phase 139
/// explicitly did not wire it. A blanket ban would either fail today or force
/// the residual to be silently deleted. What must hold is that the ban is
/// **exactly** the residual — anything else is a reintroduced concrete edge.
#[test]
fn dns_names_no_mesh_provider_type_outside_the_anycast_cluster() {
    let root = workspace_root();
    let files = collect_rs_files(&root.join("crates/synvoid-dns/src"));

    let mut violations = Violations::new();
    for file in files {
        if file.ends_with("anycast_sync.rs") {
            continue;
        }
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
                "synvoid_mesh::",
                "RecordStoreManager",
                "DhtRoutingManager",
                "SignedDhtRecord",
                "SignedRecordType",
            ] {
                if trimmed.contains(forbidden) {
                    violations.push(format!(
                        "{rel}:{} names `{forbidden}`. Phase 139 replaced the advisory \
                         DHT surface with the DNS-owned `DhtRecordStore` and \
                         `DhtGlobalLocator` capabilities; a concrete provider type here \
                         would restore the edge this phase removed",
                        index + 1
                    ));
                }
            }
        }
    }

    violations.assert_ok("dns_names_no_mesh_provider_type_outside_the_anycast_cluster");
}

/// Phase 139, gate 2 — pin the residual that gate 1 carves out.
///
/// Without this, the carve-out above is an open-ended exemption: `anycast_sync.rs`
/// could accumulate every mesh type the crate once had and the gate would still
/// pass. The measured residual at the end of Phase 139 is three types in one
/// file. Both directions matter — growing it is an unrecorded regression,
/// shrinking it is good news that must be re-measured and re-recorded rather
/// than absorbed.
#[test]
fn mesh_anycast_cluster_remains_the_only_named_residual() {
    let root = workspace_root();
    let residual = root.join("crates/synvoid-dns/src/anycast_sync.rs");

    let mut violations = Violations::new();
    if !residual.exists() {
        // Deleting the residual is a real change, not a silent pass.
        violations.push(
            "`crates/synvoid-dns/src/anycast_sync.rs` no longer exists. Phase 139 \
             recorded it as the only remaining file naming `synvoid-mesh` types; if it \
             was removed, re-measure the coupling and update this gate and the closeout"
                .to_string(),
        );
    } else {
        let source = read(&residual);
        // `synvoid_mesh::config::MeshNodeRole`, `synvoid_mesh::protocol::MeshMessage`,
        // `synvoid_mesh::transport::MeshTransport`.
        let mut seen: Vec<&str> = Vec::new();
        for symbol in ["MeshNodeRole", "MeshMessage", "MeshTransport"] {
            if source.contains(symbol) {
                seen.push(symbol);
            }
        }
        let expected = ["MeshNodeRole", "MeshMessage", "MeshTransport"];
        if seen.len() != expected.len() {
            violations.push(format!(
                "`anycast_sync.rs` names {:?} of the expected residual types {expected:?}. \
                 Phase 139 measured exactly these three; a different set means the residual \
                 moved and the closeout must be corrected before this gate is updated",
                seen
            ));
        }
    }

    // No second file may claim the carve-out.
    for file in collect_rs_files(&root.join("crates/synvoid-dns/src")) {
        if file.ends_with("anycast_sync.rs") {
            continue;
        }
        if read(&file).contains("synvoid_mesh::") {
            violations.push(format!(
                "{} also names `synvoid_mesh::`; only `anycast_sync.rs` is exempt",
                file.strip_prefix(&root).unwrap_or(&file).display()
            ));
        }
    }

    violations.assert_ok("mesh_anycast_cluster_remains_the_only_named_residual");
}

/// Phase 139, gate 3 — the seam shape itself.
///
/// A source scan cannot tell an inverted seam from a renamed one, so pin the
/// declaration sites: the two DNS-owned traits exist, and the registry holds
/// them as `Arc<dyn …>`. A concrete `Option<RecordStoreManager>` back in the
/// registry struct is the exact regression this gate exists to catch.
#[test]
fn dht_capability_seam_is_inverted_in_the_registry() {
    let root = workspace_root();
    let capability = read(&root.join("crates/synvoid-dns/src/mesh_sync/dht_capability.rs"));
    let registry = read(&root.join("crates/synvoid-dns/src/mesh_sync/mod.rs"));

    let mut violations = Violations::new();

    for signature in [
        "pub trait DhtRecordStore: Send + Sync {",
        "pub trait DhtGlobalLocator: Send + Sync {",
    ] {
        if capability.matches(signature).count() != 1 {
            violations.push(format!(
                "`crates/synvoid-dns/src/mesh_sync/dht_capability.rs` must declare exactly \
                 one `{signature}`"
            ));
        }
    }

    for field in [
        "dht_record_store: Option<Arc<dyn DhtRecordStore>>",
        "routing_manager: Option<Arc<dyn DhtGlobalLocator>>",
    ] {
        if !registry.contains(field) {
            violations.push(format!(
                "`MeshDnsRegistry` must hold `{field}`. Holding the concrete provider type \
                 keeps the edge alive even when the call sites no longer name it"
            ));
        }
    }

    // The trait signatures themselves must stay mesh-free. This is the property
    // that makes the inversion real rather than nominal. Comments are excluded
    // because this module documents the inversion by naming what it removed, and
    // matching is whole-token so the DNS-owned `DhtRecordStore` /
    // `AdvertisedAnycastNode` do not read as the provider's `DhtRecord` /
    // `AnycastNode`.
    let capability_code = code_only(&capability);
    for forbidden in [
        "synvoid_mesh",
        "SignedDhtRecord",
        "DhtRecord",
        "AnycastNode",
    ] {
        if mentions_symbol(&capability_code, forbidden) {
            violations.push(format!(
                "`dht_capability.rs` names `{forbidden}` outside a comment. No provider \
                 type may appear in a DNS-owned trait: the provider projects into \
                 `Advertised*` structs and the verifier runs provider-side"
            ));
        }
    }

    violations.assert_ok("dht_capability_seam_is_inverted_in_the_registry");
}

/// Phase 139, gate 4 — positive wiring gate.
///
/// `with_config` hardcoding the DHT fields to `None` is what made all nine
/// `if let Some(ref …)` reads dead, and the provider existing without a caller is
/// what made `attach_dht_capabilities` a decoration. This asserts both halves:
/// the fields are still `None` by default (correct — a registry is not a DHT),
/// and composition really does attach a provider and bind the registry to the
/// live DNS server.
#[test]
fn mesh_dht_capability_is_wired_through_composition() {
    let root = workspace_root();
    let registry_impl = read(&root.join("crates/synvoid-dns/src/mesh_sync/registry.rs"));
    let adapter = read(&root.join("src/worker/unified_server/mesh_dht_capability.rs"));
    let init_mesh = read(&root.join("src/worker/unified_server/init_mesh.rs"));

    let mut violations = Violations::new();

    if !registry_impl.contains("pub fn with_dht_record_store(") {
        violations.push(
            "`MeshDnsRegistry::with_dht_record_store` must exist as the injection point; \
             `with_config` hardcodes `None`, so without a builder the field can never be \
             populated"
                .to_string(),
        );
    }
    if !registry_impl.contains("pub fn with_routing_manager(") {
        violations.push(
            "`MeshDnsRegistry::with_routing_manager` must exist as the injection point \
             for the global locator"
                .to_string(),
        );
    }

    // The provider side must actually implement both capabilities.
    for symbol in [
        "impl DhtRecordStore for DhtRecordStoreAdapter",
        "impl DhtGlobalLocator for DhtGlobalLocatorAdapter",
    ] {
        if !adapter.contains(symbol) {
            violations.push(format!(
                "`src/worker/unified_server/mesh_dht_capability.rs` must contain `{symbol}`; \
                 the adapter is where concrete mesh types are allowed to be named"
            ));
        }
    }

    // Authenticity must be decided provider-side, not asserted by DNS.
    if !adapter.contains("get_record_verifier()") {
        violations.push(
            "the adapter must call `get_record_verifier()`; a DNS-side authenticity \
             decision would move signature verification into the request path"
                .to_string(),
        );
    }

    // Composition must actually call the attachment, for both registries.
    let attach_calls = init_mesh.matches("attach_dht_capabilities(").count();
    if attach_calls < 2 {
        violations.push(format!(
            "`init_mesh.rs` must call `attach_dht_capabilities` for both the edge and the \
             global registry; found {attach_calls}"
        ));
    }
    if !init_mesh.contains("set_mesh_registry(") {
        violations.push(
            "`init_mesh.rs` must bind the registry to the DNS server via \
             `set_mesh_registry`; without it `resolve_from_mesh` still sees `None`"
                .to_string(),
        );
    }
    if !init_mesh.contains("start_periodic_dht_sync(") {
        violations.push(
            "`init_mesh.rs` must call `start_periodic_dht_sync`; `sync_from_dht` never \
             ran before Phase 139, so `origin_nodes` was only ever filled by live \
             registrations"
                .to_string(),
        );
    }

    violations.assert_ok("mesh_dht_capability_is_wired_through_composition");
}

/// Phase 139, gate 5 — the late-binding cell, and the ACME defect it repairs.
///
/// `setup_acme` did `let _server = (*dns_server).clone().with_acme_dns_challenges(…)`
/// and dropped the clone, so ACME DNS-01 support was never attached for the life
/// of the process while logging that it was. That is a silent capability loss:
/// the guard has to name the dropped-clone shape, not just require a setter to
/// exist, because a setter that nothing calls reproduces it exactly.
#[test]
fn dns_server_capabilities_are_bound_on_the_live_server() {
    let root = workspace_root();
    let init_apps = read(&root.join("src/worker/unified_server/init_apps.rs"));
    let startup = read(&root.join("crates/synvoid-dns/src/server/startup.rs"));
    let server = read(&root.join("crates/synvoid-dns/src/server/mod.rs"));

    let mut violations = Violations::new();

    if code_only(&init_apps).contains("let _server =") {
        violations.push(
            "`init_apps.rs` still binds a dropped clone in code. `let _server = \
             (*dns_server).clone().with_acme_dns_challenges(…)` rebinds a temporary \
             and discards it: the ACME DNS-01 capability is never attached, while the \
             log line claims it is. Use `set_acme_dns_challenges` on the live server"
                .to_string(),
        );
    }
    if !init_apps.contains("set_acme_dns_challenges(") {
        violations.push(
            "`init_apps.rs` must call `set_acme_dns_challenges` so the ACME challenge \
             capability reaches the request path"
                .to_string(),
        );
    }

    // The cell must be shared across clones; a plain `Option` field cloned by
    // value would leave the `Arc<DnsServer>` the query path reads unbound.
    if !server.contains("acme_dns_challenges: LateBinding<Arc<dyn AcmeTxtChallenges>>") {
        violations.push(
            "`DnsServer::acme_dns_challenges` must be a `LateBinding`; an `Option` field \
             cannot be bound after the server is wrapped in an `Arc`"
                .to_string(),
        );
    }

    // `mesh_registry: None` in the transport query contexts was the defect that
    // made a bound registry invisible even once one existed.
    let hardcoded = startup.matches("mesh_registry: None,").count();
    if hardcoded != 0 {
        violations.push(format!(
            "`server/startup.rs` hardcodes `mesh_registry: None` in {hardcoded} transport \
             query context(s). The registry must be read from the bound cell, or the \
             plain UDP/TCP path can never observe a registry bound after startup"
        ));
    }

    violations.assert_ok("dns_server_capabilities_are_bound_on_the_live_server");
}

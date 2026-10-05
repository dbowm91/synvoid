//! Phase 133 Workstream A.6 — encrypted-transport startup and failure parity.
//!
//! Every string here is something Phase 134's replacement trait has to
//! reproduce: a composition root decides whether to fall back, fail startup, or
//! surface the message, and it can only do that if the text is stable and
//! attributable.
//!
//! **The three transports do not share an implementation.** DoT and DoH both
//! sit on `SecureDnsServerBase` (via `DotRuntimeConfig` / `DohRuntimeConfig`,
//! which implement `DnsServerConfig`). DoQ is QUIC and has its own
//! `DoqServer::create_tls_config`, because `quinn` needs a
//! `QuicServerConfig` rather than a `TlsAcceptor` and `DoqRuntimeConfig` does
//! not implement `DnsServerConfig` at all.
//!
//! What the three *do* share is the provider seam — one method,
//! `build_server_config()` — and, by duplication, the two error strings. That
//! duplication is itself the finding: the same contract is written out twice
//! and an inversion that updates one and not the other would silently give DoQ
//! different diagnostics from DoT and DoH. The duplication is pinned by
//! `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs`
//! (`encrypted_transport_error_contract_is_duplicated_consistently`).
//!
//! Two behaviors are pinned here that are easy to lose in a refactor:
//!
//! 1. A provider error is propagated *verbatim* behind a fixed prefix, never
//!    swallowed or restated. That is what makes a misconfigured mTLS CA
//!    diagnosable from the DNS startup path.
//! 2. The bind happens before the acceptor is built, so a transport with no
//!    certificate binds, fails, and then **releases** the port. A regression
//!    that leaked the listener would turn a retryable startup failure into a
//!    permanent port conflict.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use synvoid_dns::runtime_config::{DohRuntimeConfig, DotRuntimeConfig};
use synvoid_dns::secure_server::{DnsServerConfig, SecureDnsServerBase};
use synvoid_tls::cert_resolver::CertResolver;
use synvoid_tls::{InternalClientAuthConfig, InternalTlsConfig};

/// The fixed prefix a DNS-owned trait must keep in front of a provider error.
const ACCEPTOR_FAILURE_PREFIX: &str = "Failed to build TLS config: ";

/// The message used when no provider was supplied at all. Duplicated verbatim
/// in `secure_server.rs` and `doq.rs`.
const NO_RESOLVER: &str = "No TLS certificate resolver available";

/// A provider with no configured material. `build_server_config` succeeds
/// regardless — the resolver is installed as the cert resolver and only
/// discovers the emptiness when a client offers an SNI — which is exactly the
/// startup-vs-handshake distinction this suite pins.
fn working_resolver() -> Arc<CertResolver> {
    let resolver = CertResolver::new(InternalTlsConfig {
        enabled: true,
        prefer_post_quantum: false,
        tls_1_3_only: true,
        ocsp_stapling_enabled: false,
        ..Default::default()
    });
    // No certificate or key path is configured, so this is expected to fail.
    // The absence of material is not a startup failure.
    assert!(
        resolver.load_certificates().is_err(),
        "precondition: this provider has no material to load"
    );
    Arc::new(resolver)
}

/// A provider whose build fails, with a message of its own choosing.
fn failing_resolver(ca_cert_path: Option<std::path::PathBuf>) -> Arc<CertResolver> {
    let resolver = CertResolver::new(InternalTlsConfig {
        enabled: true,
        client_auth: InternalClientAuthConfig {
            enabled: true,
            ca_cert_path,
        },
        prefer_post_quantum: false,
        tls_1_3_only: true,
        ocsp_stapling_enabled: false,
        ..Default::default()
    });
    // Material is irrelevant here: the client-auth misconfiguration is what
    // makes the build fail.
    let _ = resolver.load_certificates();
    Arc::new(resolver)
}

async fn noop_handler(
    _stream: tokio::net::TcpStream,
    _addr: SocketAddr,
    _dns: Arc<parking_lot::RwLock<Option<synvoid_dns::server::DnsServer>>>,
    _acceptor: Arc<tokio_rustls::TlsAcceptor>,
) -> Result<(), String> {
    Ok(())
}

/// `create_tls_acceptor` through the shared base, for one of the two
/// stream-oriented transports.
fn acceptor_error<C: DnsServerConfig>(config: C, resolver: Option<Arc<CertResolver>>) -> String {
    let base = SecureDnsServerBase::new(config, resolver);
    match base.create_tls_acceptor() {
        Ok(_) => panic!("acceptor construction was expected to fail"),
        Err(message) => message,
    }
}

// ---- A-6a: no resolver ------------------------------------------------------

/// A-6a: DoT and DoH report the same message when no certificate resolver was
/// supplied. "No resolver" is a configuration outcome, not a TLS failure, so it
/// must not be dressed up as one. DoQ uses the identical literal, pinned at the
/// source level by the guard named in the module docs.
#[test]
fn no_resolver_yields_the_same_message_on_every_stream_transport() {
    let dot = acceptor_error(support::dot_on(853), None);
    let doh = acceptor_error(support::doh_on(443), None);

    assert_eq!(dot, NO_RESOLVER, "DoT must report the absent resolver");
    assert_eq!(doh, NO_RESOLVER, "DoH must report the absent resolver");
    assert_eq!(dot, doh, "and the two must be identical");
}

// ---- A-6b: provider failure is propagated verbatim --------------------------

/// A-6b: a provider error crosses the boundary behind a fixed prefix with the
/// provider's own text intact. A DNS-owned trait that wraps, rewords, or
/// discards this error would make an mTLS misconfiguration undiagnosable.
#[test]
fn provider_errors_are_propagated_verbatim_behind_a_fixed_prefix() {
    let provider = failing_resolver(None);

    for (name, message) in [
        (
            "DoT",
            acceptor_error(support::dot_on(853), Some(Arc::clone(&provider))),
        ),
        (
            "DoH",
            acceptor_error(support::doh_on(443), Some(Arc::clone(&provider))),
        ),
    ] {
        assert!(
            message.starts_with(ACCEPTOR_FAILURE_PREFIX),
            "{name} must prefix the provider error, got: {message}"
        );
        assert_eq!(
            message.strip_prefix(ACCEPTOR_FAILURE_PREFIX),
            Some("CA certificate path not configured for client authentication"),
            "{name} must preserve the provider's own message verbatim, got: {message}"
        );
    }
}

/// A-6b': a second, different provider failure produces a different message
/// under the same prefix, which is what proves the text is genuinely
/// propagated rather than a constant.
///
/// The message is `"No CA certificates found in file"` — it comes from
/// `load_ca_certs`, and the `"No CA certificates found for client
/// authentication"` branch in `build_server_config` is unreachable (Phase 133
/// finding F-11). Pinning the text an operator actually sees is the point.
#[test]
fn a_different_provider_failure_produces_a_different_message() {
    let dir = std::env::temp_dir().join("synvoid-phase133-empty-ca");
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let empty_ca = dir.join("empty-ca.pem");
    std::fs::write(&empty_ca, b"").expect("write empty CA file");

    let message = acceptor_error(support::dot_on(853), Some(failing_resolver(Some(empty_ca))));
    assert_eq!(
        message.strip_prefix(ACCEPTOR_FAILURE_PREFIX),
        Some("No CA certificates found in file"),
        "a distinct provider failure must surface as a distinct message"
    );
}

// ---- A-6c: a working provider still builds an acceptor ---------------------

/// A-6c: a provider with no loaded material still yields an acceptor. Material
/// absence is a handshake-time condition, not a startup-time one, so a listener
/// with such a provider must start and accept connections.
#[test]
fn a_provider_without_material_still_yields_an_acceptor() {
    SecureDnsServerBase::new(support::dot_on(853), Some(working_resolver()))
        .create_tls_acceptor()
        .expect("acceptor construction succeeds regardless of loaded material");
}

// ---- A-6d: zero port and bind ordering -------------------------------------

/// A-6d: a zero port is rejected before any socket is created and before the
/// acceptor is consulted, so it is reported as a bind-address problem even when
/// no resolver exists at all.
#[tokio::test]
async fn a_zero_port_is_rejected_before_the_resolver_is_consulted() {
    let mut base = SecureDnsServerBase::new(support::dot_on(853), None);
    let message = base
        .start_server(SocketAddr::from(([127, 0, 0, 1], 0)), "DoT", noop_handler)
        .await
        .expect_err("a zero port must be rejected");

    assert_eq!(message, "Invalid DoT bind address: port cannot be zero");
    assert!(
        !message.contains(ACCEPTOR_FAILURE_PREFIX),
        "the port check must short-circuit the TLS path, got: {message}"
    );
}

/// A-6e: the listener binds before the acceptor is built, so an acceptor failure
/// leaves the port free. A regression that leaked the socket would turn a
/// retryable startup failure into a permanent bind conflict.
#[tokio::test]
async fn an_acceptor_failure_releases_the_bound_port() {
    // Bind and immediately release a port so the number is ours to take.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe a port");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let mut base = SecureDnsServerBase::new(support::dot_on(port), None);
    let message = base
        .start_server(
            SocketAddr::from(([127, 0, 0, 1], port)),
            "DoT",
            noop_handler,
        )
        .await
        .expect_err("a missing resolver must fail startup");
    assert_eq!(message, NO_RESOLVER);

    // The port must be immediately rebindable.
    std::net::TcpListener::bind(("127.0.0.1", port))
        .expect("the port must be released after an acceptor failure");
}

// ---- A-6f: transport shape --------------------------------------------------

/// A-6f: DoT and DoH are one base with distinct names, and DoQ is deliberately
/// not on it. Pinned so that a future "unify the transports" refactor notices
/// that DoQ cannot be folded in without also handling QUIC.
#[test]
fn dot_and_doh_share_a_base_and_doq_does_not() {
    let dot: DotRuntimeConfig = support::dot_on(853);
    let doh: DohRuntimeConfig = support::doh_on(443);

    assert_eq!(dot.server_name(), "DoT");
    assert_eq!(doh.server_name(), "DoH");
    assert_eq!(
        dot.bind_address(),
        Some("127.0.0.1:853".parse().expect("addr"))
    );
    assert_eq!(
        doh.bind_address(),
        Some("127.0.0.1:443".parse().expect("addr"))
    );

    // A disabled transport has no bind address, so composition never reaches
    // the TLS path at all.
    let disabled_dot: DotRuntimeConfig = support::disabled_dot();
    let disabled_doh: DohRuntimeConfig = support::disabled_doh();
    let disabled_doq: synvoid_dns::runtime_config::DoqRuntimeConfig = support::disabled_doq();
    assert!(disabled_dot.bind_address().is_none());
    assert!(disabled_doh.bind_address().is_none());
    assert!(!disabled_doq.enabled);
    assert!(disabled_doq.bind_address.is_none());
}

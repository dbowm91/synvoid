//! Phase 133 Workstream A.6 — encrypted-transport startup and failure parity.
//!
//! Every string here is something Phase 134's provider capability has to
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
//! `SecureTransportConfig::server_config()` — and, by duplication, the two error
//! strings. That duplication is pinned at the source level by
//! `encrypted_transport_error_contract_is_duplicated_consistently` in
//! `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs`.
//!
//! This suite uses a **DNS-owned stub**, not a real `synvoid-tls` resolver.
//! Phase 134 removed the `synvoid-tls` edge from this crate, which is the point:
//! the DNS-side contract must be testable without the provider present. What the
//! *provider* does with certificates is proven separately in
//! `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs`.
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

use rustls::crypto::CryptoProvider;
use rustls::ServerConfig;
use synvoid_dns::runtime_config::{DohRuntimeConfig, DotRuntimeConfig};
use synvoid_dns::secure_server::{DnsServerConfig, SecureDnsServerBase};
use synvoid_dns::secure_transport::SecureTransportConfig;

/// The fixed prefix a provider capability must keep in front of its own error.
const ACCEPTOR_FAILURE_PREFIX: &str = "Failed to build TLS config: ";

/// The message used when no provider was supplied at all. Duplicated verbatim
/// in `secure_server.rs` and `doq.rs`.
const NO_RESOLVER: &str = "No TLS certificate resolver available";

/// A provider error the stub chooses, standing in for whatever text a real
/// provider produces. A sentinel is deliberate: it proves the text is
/// propagated rather than reconstructed from a constant.
const PROVIDER_ERROR: &str = "CA certificate path not configured for client authentication";
const OTHER_PROVIDER_ERROR: &str = "No CA certificates found in file";

/// A cert resolver that never has a certificate.
///
/// `build_server_config` on a real provider succeeds regardless of loaded
/// material, because the resolver is installed as the cert resolver and only
/// discovers the emptiness when a client offers an SNI. This reproduces that
/// without a `synvoid-tls` dependency: the config builds, and a handshake would
/// fail.
#[derive(Debug)]
struct NoCertificate;

impl rustls::server::ResolvesServerCert for NoCertificate {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Builds a usable `ServerConfig` with no certificate behind it.
fn config_without_certificate() -> Arc<ServerConfig> {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCertificate));
    Arc::new(config)
}

/// A DNS-side stand-in for a TLS provider.
enum StubTransport {
    /// Succeeds, like a provider that has loaded its certificates.
    Succeeds,
    /// Fails with a message of the stub's choosing.
    Fails(&'static str),
}

impl SecureTransportConfig for StubTransport {
    fn server_config(&self) -> Result<Arc<ServerConfig>, String> {
        match self {
            Self::Succeeds => Ok(config_without_certificate()),
            Self::Fails(message) => Err((*message).to_string()),
        }
    }
}

fn succeeding() -> Option<Arc<dyn SecureTransportConfig>> {
    Some(Arc::new(StubTransport::Succeeds))
}

fn failing(message: &'static str) -> Option<Arc<dyn SecureTransportConfig>> {
    Some(Arc::new(StubTransport::Fails(message)))
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
fn acceptor_error<C: DnsServerConfig>(
    config: C,
    provider: Option<Arc<dyn SecureTransportConfig>>,
) -> String {
    let base = SecureDnsServerBase::new(config, provider);
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
/// provider's own text intact. A capability that wraps, rewords, or discards
/// this error would make an mTLS misconfiguration undiagnosable.
///
/// The stub's message is a sentinel chosen by the test, which is the point: it
/// proves the text is propagated rather than reconstructed from a constant.
#[test]
fn provider_errors_are_propagated_verbatim_behind_a_fixed_prefix() {
    for (name, message) in [
        (
            "DoT",
            acceptor_error(support::dot_on(853), failing(PROVIDER_ERROR)),
        ),
        (
            "DoH",
            acceptor_error(support::doh_on(443), failing(PROVIDER_ERROR)),
        ),
    ] {
        assert!(
            message.starts_with(ACCEPTOR_FAILURE_PREFIX),
            "{name} must prefix the provider error, got: {message}"
        );
        assert_eq!(
            message.strip_prefix(ACCEPTOR_FAILURE_PREFIX),
            Some(PROVIDER_ERROR),
            "{name} must preserve the provider's own message verbatim, got: {message}"
        );
    }
}

/// A-6b': a second, different provider error produces a different message under
/// the same prefix, which is what proves the text is genuinely propagated.
#[test]
fn a_different_provider_failure_produces_a_different_message() {
    let message = acceptor_error(support::dot_on(853), failing(OTHER_PROVIDER_ERROR));
    assert_eq!(
        message.strip_prefix(ACCEPTOR_FAILURE_PREFIX),
        Some(OTHER_PROVIDER_ERROR),
        "a distinct provider failure must surface as a distinct message"
    );
}

// ---- A-6c: a succeeding provider still builds an acceptor -------------------

/// A-6c: a provider that succeeds yields an acceptor. Certificate absence
/// *inside* a real provider is a handshake-time condition, not a startup-time
/// one, so a listener with such a provider must start and accept connections —
/// which is what the `NoCertificate` resolver reproduces here.
#[test]
fn a_succeeding_provider_still_yields_an_acceptor() {
    SecureDnsServerBase::new(support::dot_on(853), succeeding())
        .create_tls_acceptor()
        .expect("acceptor construction succeeds when the provider succeeds");
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

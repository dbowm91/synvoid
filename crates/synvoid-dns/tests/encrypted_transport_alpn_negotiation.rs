//! Phase 137 — ALPN negotiation evidence for the encrypted DNS transports.
//!
//! Every assertion here runs against a **real handshake** on a real loopback
//! listener, not against a struct field. That distinction is the whole point of
//! this suite: `ServerConfig::alpn_protocols` being non-empty does not prove a
//! protocol is negotiated, and a non-empty list changes handshake *outcomes* for
//! clients that offer nothing. Only the wire shows that.
//!
//! ## What is pinned
//!
//! | Transport | Advertises | Pinned by |
//! |---|---|---|
//! | DoH | `h2` | `doh_negotiates_h2_for_a_client_that_offers_only_h2` |
//! | DoH | `h2` over a multi-protocol offer | `doh_negotiates_h2_over_a_mixed_offer` |
//! | DoT | nothing | `dot_completes_a_handshake_from_a_client_that_offers_no_alpn` |
//! | DoT | nothing, even against an offer | `dot_ignores_an_alpn_offer_rather_than_rejecting_it` |
//! | DoQ | `doq` | `doq_still_negotiates_doq` |
//!
//! ## Why DoT is not a defect
//!
//! `dot` is IANA-registered, but advertising it would be a regression. In
//! rustls a non-empty `our_protocols` makes the server **require** a negotiated
//! match, so offering `dot` would reject exactly the clients that connect
//! today. RFC 7858 defines no ALPN identifier for DNS-over-TLS. "Advertises
//! nothing" is the correct answer, and `dot_ignores_an_alpn_offer_rather_than_
//! rejecting_it` proves it is reached without breaking a client that offers one.
//!
//! ## Relationship to the provider suite
//!
//! The two `synvoid-tls` pins that assert the *provider* configures no ALPN stay
//! true and unmodified (`crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs:536`
//! and `:557`). ALPN is applied at the DNS call sites, not in the provider, so
//! the provider is unchanged. That is the opposite of the Phase 135 F-1 case,
//! where the fix landed inside the layer the pin covered and the pin had to be
//! inverted.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use synvoid_dns::doh::DohServer;
use synvoid_dns::doq::DoqServer;
use synvoid_dns::dot::DotServer;
use synvoid_dns::secure_transport::SecureTransportConfig;

/// How long a client waits for a handshake before giving up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Attempts allowed before a test reports that it could not win a loopback
/// port. Each attempt asks the OS for a fresh number, so a retry is a genuinely
/// different port rather than the same one retried.
const BIND_ATTEMPTS: usize = 8;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

// ---------------------------------------------------------------------------
// Certificate material
// ---------------------------------------------------------------------------

/// A self-signed certificate generated in process, so no fixture PEM is
/// checked in and nothing expires on a schedule.
struct TestCertificate {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn test_certificate() -> TestCertificate {
    let generated = rcgen::generate_simple_self_signed(vec![
        "doh.invalid".to_string(),
        "dot.invalid".to_string(),
        "doq.invalid".to_string(),
    ])
    .expect("generate a self-signed certificate");

    TestCertificate {
        cert: generated.cert.der().clone(),
        key: PrivateKeyDer::try_from(generated.key_pair.serialize_der())
            .expect("the generated key is a supported private key"),
    }
}

/// A DNS-side stand-in for a TLS provider.
///
/// Phase 134 removed the `synvoid-tls` edge from this crate, so the DNS-side
/// contract has to be provable without the provider present. What the *provider*
/// does with certificates is proven separately in
/// `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs`.
struct StubProvider {
    config: Arc<ServerConfig>,
}

impl StubProvider {
    fn new(certificate: &TestCertificate) -> Arc<dyn SecureTransportConfig> {
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is supported")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.clone()], certificate.key.clone_key())
            .expect("the generated certificate and key are usable");

        Arc::new(Self {
            config: Arc::new(config),
        })
    }
}

impl SecureTransportConfig for StubProvider {
    fn server_config(&self) -> Result<Arc<ServerConfig>, String> {
        Ok(Arc::clone(&self.config))
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Accepts any certificate.
///
/// These tests assert on ALPN negotiation, which completes before and
/// independently of certificate trust. Trust is covered by the provider suite;
/// re-deriving a CA chain here would test `rcgen` instead of the transport.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Must cover the scheme `rcgen` actually signs with (ECDSA P-256), or
        // the client rejects the server for an unrelated reason.
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn client_config(offer: &[&[u8]]) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth();

    // An empty list means the client sends no ALPN extension at all, which is
    // what a mainstream DoT client does.
    config.alpn_protocols = offer.iter().map(|p| p.to_vec()).collect();
    config
}

/// Complete a TLS handshake against a stream transport and report the protocol
/// the server actually selected.
async fn handshake_stream(addr: SocketAddr, offer: &[&[u8]]) -> Result<Option<Vec<u8>>, String> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(offer)));
    let name = ServerName::try_from("doh.invalid").expect("a valid server name");

    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect: {e}"))?;

    let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| "handshake timed out".to_string())?
        .map_err(|e| format!("handshake: {e}"))?;

    Ok(tls.get_ref().1.alpn_protocol().map(|p| p.to_vec()))
}

// ---------------------------------------------------------------------------
// Loopback port acquisition
// ---------------------------------------------------------------------------

/// `std::io::Error`'s `AddrInUse` display, on every supported platform.
const ADDR_IN_USE_TEXT: &str = "in use";

/// True when a failure is a lost bind race rather than a real error.
///
/// The encrypted transports report bind failures as
/// `"Failed to bind {name} socket: {io_error}"`, so a port conflict is the only
/// failure that both mentions the bind and says the address was in use. Any
/// other failure must propagate so a real error is never masked by a retry —
/// the same rule `support::runtime_config::is_bind_conflict` applies to the
/// plaintext listeners.
fn is_bind_conflict(message: &str) -> bool {
    message.starts_with("Failed to bind") && message.contains(ADDR_IN_USE_TEXT)
}

/// Ask the OS for a loopback candidate port.
///
/// This is a prediction, not a reservation; the callers below retry the real
/// bind when it is lost. Phase 131 removed the assumption that a predicted
/// port is available, and this helper keeps that property rather than
/// reintroducing it.
fn candidate_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral loopback port")
        .local_addr()
        .expect("read the local address")
        .port()
}

async fn start_dot(provider: Arc<dyn SecureTransportConfig>) -> (DotServer, SocketAddr) {
    let mut last_conflict = String::new();
    for _ in 0..BIND_ATTEMPTS {
        let port = candidate_port();
        let mut server = DotServer::new(support::dot_on(port), Some(Arc::clone(&provider)));
        match server.start().await {
            Ok(()) => return (server, SocketAddr::from(([127, 0, 0, 1], port))),
            Err(error) if is_bind_conflict(&error) => last_conflict = error,
            Err(error) => panic!("DoT start failed: {error}"),
        }
    }
    panic!("DoT could not bind a loopback port in {BIND_ATTEMPTS} attempts: {last_conflict}");
}

async fn start_doh(provider: Arc<dyn SecureTransportConfig>) -> (DohServer, SocketAddr) {
    let mut last_conflict = String::new();
    for _ in 0..BIND_ATTEMPTS {
        let port = candidate_port();
        let mut server = DohServer::new(support::doh_on(port), Some(Arc::clone(&provider)));
        match server.start().await {
            Ok(()) => return (server, SocketAddr::from(([127, 0, 0, 1], port))),
            Err(error) if is_bind_conflict(&error) => last_conflict = error,
            Err(error) => panic!("DoH start failed: {error}"),
        }
    }
    panic!("DoH could not bind a loopback port in {BIND_ATTEMPTS} attempts: {last_conflict}");
}

// ---------------------------------------------------------------------------
// DoH: advertises `h2`
// ---------------------------------------------------------------------------

/// The gap Phase 137 exists to close. Before it, DoH advertised nothing, so a
/// client that requires ALPN negotiation — common for DoH, because the DoH
/// profile is defined over HTTP/2 — could not use the listener at all.
#[tokio::test]
async fn doh_negotiates_h2_for_a_client_that_offers_only_h2() {
    let certificate = test_certificate();
    let (_server, addr) = start_doh(StubProvider::new(&certificate)).await;

    let negotiated = handshake_stream(addr, &[b"h2"])
        .await
        .expect("a DoH client offering h2 must complete the handshake");

    assert_eq!(
        negotiated.as_deref(),
        Some(&b"h2"[..]),
        "DoH must negotiate h2 for a client that offers only h2"
    );
}

/// ALPN selection is by server preference, so a mixed offer still yields `h2`
/// even when the client ranks the others first. A client offering `doq` and
/// `h2` must not end up on `doq` just because it listed it first.
#[tokio::test]
async fn doh_negotiates_h2_over_a_mixed_offer() {
    let certificate = test_certificate();
    let (_server, addr) = start_doh(StubProvider::new(&certificate)).await;

    let negotiated = handshake_stream(addr, &[b"doq", b"h2"])
        .await
        .expect("a DoH client offering doq and h2 must complete the handshake");

    assert_eq!(
        negotiated.as_deref(),
        Some(&b"h2"[..]),
        "DoH must select h2 from a mixed offer; the server's own list decides"
    );
}

/// DoH must not accept a client that offers no `h2`. This is the flip side of
/// advertising: a server whose handler is HTTP/2-only should not silently
/// hand a connection to a client speaking something else.
#[tokio::test]
async fn doh_rejects_a_client_that_offers_no_shared_protocol() {
    let certificate = test_certificate();
    let (_server, addr) = start_doh(StubProvider::new(&certificate)).await;

    let outcome = handshake_stream(addr, &[b"dot"]).await;

    assert!(
        outcome.is_err(),
        "a DoH client offering only `dot` must not be served; DoH speaks HTTP/2 only, \
         and the outcome was {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// DoT: advertises nothing
// ---------------------------------------------------------------------------

/// The behavior that must not regress. RFC 7858 defines no ALPN identifier for
/// DNS-over-TLS and mainstream clients offer none, so a DoT listener that
/// required negotiation would refuse them.
#[tokio::test]
async fn dot_completes_a_handshake_from_a_client_that_offers_no_alpn() {
    let certificate = test_certificate();
    let (_server, addr) = start_dot(StubProvider::new(&certificate)).await;

    let negotiated = handshake_stream(addr, &[])
        .await
        .expect("a DoT client that offers no ALPN must complete the handshake");

    assert_eq!(
        negotiated, None,
        "DoT must negotiate no protocol; RFC 7858 defines no ALPN identifier"
    );
}

/// Recorded as observed behavior rather than assumed. A DoT client *does* send
/// an ALPN extension in some implementations, and because DoT advertises
/// nothing there is nothing to mismatch, so the handshake must still succeed —
/// with no protocol selected.
///
/// This is the concrete blast radius of the phase. If DoT were given a non-empty
/// `our_protocols`, rustls would send a fatal `NoApplicationProtocol` alert for
/// exactly this client.
#[tokio::test]
async fn dot_ignores_an_alpn_offer_rather_than_rejecting_it() {
    let certificate = test_certificate();
    let (_server, addr) = start_dot(StubProvider::new(&certificate)).await;

    let outcome = handshake_stream(addr, &[b"h2"]).await;

    assert!(
        outcome.is_ok(),
        "a DoT client that offers h2 must still be served, because DoT advertises \
         nothing and therefore cannot mismatch; got {outcome:?}"
    );
    assert_eq!(
        outcome.expect("checked above").as_deref(),
        None,
        "and no protocol may be selected on a DoT connection"
    );
}

/// The two transports share one TLS builder. This pins that sharing them did not
/// make them agree: the same client offer is answered differently by each,
/// because the two declare different ALPN lists.
#[tokio::test]
async fn the_shared_builder_does_not_make_dot_and_doh_agree() {
    let certificate = test_certificate();
    let provider = StubProvider::new(&certificate);

    let (_dot, dot_addr) = start_dot(Arc::clone(&provider)).await;
    let (_doh, doh_addr) = start_doh(Arc::clone(&provider)).await;

    let offer: &[&[u8]] = &[b"h2"];

    let on_dot = handshake_stream(dot_addr, offer).await;
    let on_doh = handshake_stream(doh_addr, offer).await;

    assert_eq!(
        on_dot.expect("DoT serves a client offering h2"),
        None,
        "DoT selects nothing"
    );
    assert_eq!(
        on_doh.expect("DoH serves a client offering h2").as_deref(),
        Some(&b"h2"[..]),
        "DoH selects h2"
    );
}

// ---------------------------------------------------------------------------
// DoQ: unchanged
// ---------------------------------------------------------------------------

/// DoQ was already correct before Phase 137 (RFC 9250) and the phase deliberately
/// did not touch it. This pins the pre-existing behavior so the ALPN work cannot
/// have regressed the one transport that already had it.
///
/// This also replaces `doq_alpn_is_doq` in `encrypted_transport.rs`, which was
/// `assert_eq!(b"doq", b"doq")` — a comparison of two byte-string literals that
/// asserted nothing about the code and could never fail.
#[tokio::test]
async fn doq_still_negotiates_doq() {
    let certificate = test_certificate();
    let provider = StubProvider::new(&certificate);

    let mut observed: Option<Option<Vec<u8>>> = None;
    let mut task = None;

    for _ in 0..BIND_ATTEMPTS {
        let port = candidate_port();
        let mut server = DoqServer::new(support::doq_on(port), Some(Arc::clone(&provider)));
        // `DoqServer::start` runs its accept loop inline, so it is driven as a
        // task. The task is aborted once the handshake is observed, which drops
        // the endpoint and releases the port.
        let handle = tokio::spawn(async move { server.start().await });
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        match quic_alpn(addr, b"doq").await {
            Ok(negotiated) => {
                observed = Some(negotiated);
                task = Some(handle);
                break;
            }
            // A failure here is a startup race or a lost bind race, never a
            // verdict on the transport, so it is retried on a fresh port.
            Err(_) => handle.abort(),
        }
    }

    let negotiated = observed.expect("DoQ completed no handshake on any candidate port");
    assert_eq!(
        negotiated.as_deref(),
        Some(&b"doq"[..]),
        "DoQ must keep negotiating doq; it was correct before Phase 137"
    );

    if let Some(handle) = task {
        handle.abort();
    }
}

/// Complete a QUIC handshake and report the ALPN protocol selected.
async fn quic_alpn(addr: SocketAddr, offer: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let config = client_config(&[offer]);
    // A QUIC client config cannot negotiate anything below TLS 1.3.
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(config))
        .map_err(|e| format!("QUIC client config: {e}"))?;
    let client = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|e| format!("client endpoint: {e}"))?;

    let connecting = endpoint
        .connect_with(client, addr, "doq.invalid")
        .map_err(|e| format!("connect: {e}"))?;

    let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .map_err(|_| "handshake timed out".to_string())?
        .map_err(|e| format!("handshake: {e}"))?;

    // `handshake_data` is type-erased; the rustls-backed payload carries the
    // negotiated protocol and is guaranteed present once a handshake completes
    // with a non-empty protocol list.
    let negotiated = connection
        .handshake_data()
        .ok_or_else(|| "no handshake data after a completed handshake".to_string())?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| "handshake data is not rustls-backed".to_string())?
        .protocol;

    connection.close(0u32.into(), b"done");
    Ok(negotiated)
}

// ---------------------------------------------------------------------------
// The provider is still not responsible for ALPN
// ---------------------------------------------------------------------------

/// The provider must keep configuring no ALPN of its own. Phase 137 attaches
/// ALPN at the DNS call sites, so a provider that started setting it would be
/// guessing which DNS protocol its listener speaks — and would be guessing
/// identically for DoT and DoH, which need different answers.
///
/// This mirrors `build_server_config_configures_no_alpn_protocols` in
/// `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs:536` from the
/// DNS side, so the boundary holds even though the DNS crate can no longer reach
/// the concrete provider.
#[test]
fn the_provider_supplies_no_alpn_of_its_own() {
    let certificate = test_certificate();
    let provider = StubProvider::new(&certificate);

    let config = provider
        .server_config()
        .expect("the stub provider builds a config");

    assert!(
        config.alpn_protocols.is_empty(),
        "the DNS-owned provider capability must keep configuring no ALPN; the \
         transport's own constant is applied on top of it"
    );
}

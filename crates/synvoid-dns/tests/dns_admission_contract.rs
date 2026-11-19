//! Admission contract: every transport applies the same packet checks.
//!
//! Phase 03 removed the remote-panic class in the EDNS and TSIG parsers and
//! moved validation, the DNS firewall, and request rate limiting into one
//! function (`admit`) that UDP, TCP, DoT, DoH, and DoQ all call. This suite
//! pins the observable consequences:
//!
//! | Case | What it proves |
//! |---|---|
//! | 30-byte EDNS packet (audit D3) | a lying RDLENGTH gets FORMERR, no panic |
//! | 40-byte off-by-one packet (D15) | an incomplete OPT fixed header is an error |
//! | ECS prefix 255 (D16) | the option body is validated, not sliced |
//! | `QR=1` | no response on UDP/TCP (D14) |
//! | firewall block | identical REFUSED on all five transports (D12b) |
//! | rate limit | identical REFUSED on all five transports |
//! | encrypted cap | DoT refuses the N+1th connection and recovers (D33) |
//! | TSIG name at EOF (D12) | bounded parser rejects, does not panic |
//!
//! The encrypted half uses real TLS/QUIC handshakes with an in-process
//! certificate; the same harness pattern as
//! `encrypted_transport_alpn_negotiation.rs`.

mod support;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use synvoid_dns::cache::{CacheKey, DnsCache, TransportClass};
use synvoid_dns::doh::DohServer;
use synvoid_dns::doq::DoqServer;
use synvoid_dns::dot::DotServer;
use synvoid_dns::firewall::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};
use synvoid_dns::parsed_query::ParsedDnsQuery;
use synvoid_dns::runtime_config::{DnsRateLimitModeRuntime, DnsRateLimitRuntimeConfig};
use synvoid_dns::secure_transport::SecureTransportConfig;
use synvoid_dns::server::DnsServer;
use synvoid_dns::{admit, Admission, TransportKind, RCODE_FORMERR, RCODE_REFUSED};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use support::query::{build_query, build_query_with_edns_options};
use support::response::{response_ancount, response_qdcount, response_rcode};

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Long enough that a local listener has answered, short enough that an
/// intentional non-response does not stall the suite.
const NO_RESPONSE_WINDOW: Duration = Duration::from_millis(400);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BIND_ATTEMPTS: usize = 8;
const ORIGIN: &str = "example.com";

// ---------------------------------------------------------------------------
// Query builders
// ---------------------------------------------------------------------------

fn a_query(id: u16, name: &str) -> Vec<u8> {
    build_query(id, name, 1)
}

fn set_qr(query: &mut [u8]) {
    query[2] |= 0x80;
}

/// The exact 30-byte packet from the capability audit (D3): one-label
/// question plus an OPT fixed header whose RDLENGTH claims 65535 bytes.
fn audit_thirty_byte_packet() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&0x3030u16.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    q.extend_from_slice(&[1, b'a', 0]); // question name "a."
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    q.push(0); // OPT owner root
    q.extend_from_slice(&41u16.to_be_bytes());
    q.extend_from_slice(&4096u16.to_be_bytes());
    q.extend_from_slice(&0u32.to_be_bytes());
    q.extend_from_slice(&0xFFFFu16.to_be_bytes()); // lying RDLENGTH
    assert_eq!(q.len(), 30, "the audit packet is exactly 30 bytes");
    q
}

/// The 40-byte off-by-one packet (D15): the OPT fixed header starts 10 bytes
/// before the end, one byte short of its 11 bytes.
fn off_by_one_forty_byte_packet() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&0x4040u16.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    q.push(12);
    q.extend_from_slice(b"aaaaaaaaaaaa");
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    q.push(0); // OPT owner root
    q.extend_from_slice(&41u16.to_be_bytes());
    q.extend_from_slice(&4096u16.to_be_bytes());
    q.extend_from_slice(&0u32.to_be_bytes());
    q.push(0); // first RDLENGTH byte only
    assert_eq!(q.len(), 40, "the D15 packet is exactly 40 bytes");
    q
}

/// A well-formed OPT record whose CLIENT-SUBNET option declares family 1 and
/// a prefix of 255 (D16).
fn ecs_prefix_255_query() -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&8u16.to_be_bytes()); // option code
    rdata.extend_from_slice(&36u16.to_be_bytes()); // option length
    rdata.extend_from_slice(&1u16.to_be_bytes()); // family IPv4
    rdata.push(255); // source prefix
    rdata.push(0); // scope prefix
    rdata.extend_from_slice(&[0xFF; 32]);

    let mut query = build_query_with_edns_options(0x5050, "www.example.com", 1, 4096, 0, false, 1);
    let rdlength_at = query.len() - 2;
    query[rdlength_at..].copy_from_slice(&(rdata.len() as u16).to_be_bytes());
    query.extend_from_slice(&rdata);
    query
}

// ---------------------------------------------------------------------------
// Plain listeners
// ---------------------------------------------------------------------------

struct UdpClient {
    socket: tokio::net::UdpSocket,
}

impl UdpClient {
    async fn new() -> Self {
        Self {
            socket: tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind UDP client"),
        }
    }

    /// Send one datagram and wait up to `wait` for a response.
    async fn send(&self, port: u16, query: &[u8], wait: Duration) -> Option<Vec<u8>> {
        self.socket
            .send_to(query, ("127.0.0.1", port))
            .await
            .expect("send datagram");
        let mut buf = [0u8; 65535];
        match tokio::time::timeout(wait, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Some(buf[..len].to_vec()),
            _ => None,
        }
    }
}

async fn tcp_connect(port: u16) -> Result<tokio::net::TcpStream, String> {
    tokio::time::timeout(
        QUERY_TIMEOUT,
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "TCP connect timed out".to_string())?
    .map_err(|e| format!("TCP connect: {e}"))
}

async fn write_frame(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    query: &[u8],
) -> Result<(), String> {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(query)
        .await
        .map_err(|e| format!("write body: {e}"))
}

/// Write a framed query and return the next frame, or `None` on EOF.
async fn tcp_exchange(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    query: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    write_frame(stream, query).await?;
    let mut length = [0u8; 2];
    let first = tokio::time::timeout(QUERY_TIMEOUT, stream.read(&mut length))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    if first == 0 {
        return Ok(None);
    }
    if first != 2 {
        // A short read is possible on a stream; finish the prefix.
        tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut length[first..]))
            .await
            .map_err(|_| "read timed out".to_string())?
            .map_err(|e| format!("read length: {e}"))?;
    }
    let len = u16::from_be_bytes(length) as usize;
    let mut body = vec![0u8; len];
    tokio::time::timeout(QUERY_TIMEOUT, stream.read_exact(&mut body))
        .await
        .map_err(|_| "read body timed out".to_string())?
        .map_err(|e| format!("read body: {e}"))?;
    Ok(Some(body))
}

// ---------------------------------------------------------------------------
// TLS / QUIC client material
// ---------------------------------------------------------------------------

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

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

struct StubProvider {
    config: Arc<ServerConfig>,
}

impl StubProvider {
    fn from_certificate(certificate: &TestCertificate) -> Arc<dyn SecureTransportConfig> {
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
    config.alpn_protocols = offer.iter().map(|p| p.to_vec()).collect();
    config
}

type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

async fn tls_connect(addr: SocketAddr, offer: &[&[u8]]) -> Result<TlsStream, String> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(offer)));
    let name = ServerName::try_from("dot.invalid").expect("a valid server name");
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "TLS connect timed out".to_string())?
        .map_err(|e| format!("TLS connect: {e}"))?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| format!("TLS handshake: {e}"))
}

// ---------------------------------------------------------------------------
// Listener startup
// ---------------------------------------------------------------------------

fn candidate_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral loopback port")
        .local_addr()
        .expect("read the local address")
        .port()
}

fn is_bind_conflict(message: &str) -> bool {
    message.starts_with("Failed to bind") && message.contains("in use")
}

async fn start_dot(
    provider: Arc<dyn SecureTransportConfig>,
    runtime: synvoid_dns::DnsRuntimeConfig,
) -> (DotServer, SocketAddr) {
    let mut last_conflict = String::new();
    for _ in 0..BIND_ATTEMPTS {
        let port = candidate_port();
        let mut server = DotServer::new(support::dot_on(port), Some(Arc::clone(&provider)));
        server.set_dns_server(encrypted_dns_server(&runtime));
        match server.start().await {
            Ok(()) => return (server, SocketAddr::from(([127, 0, 0, 1], port))),
            Err(error) if is_bind_conflict(&error) => last_conflict = error,
            Err(error) => panic!("DoT start failed: {error}"),
        }
    }
    panic!("DoT could not bind in {BIND_ATTEMPTS} attempts: {last_conflict}");
}

async fn start_doh(
    provider: Arc<dyn SecureTransportConfig>,
    runtime: synvoid_dns::DnsRuntimeConfig,
) -> (DohServer, SocketAddr) {
    let mut last_conflict = String::new();
    for _ in 0..BIND_ATTEMPTS {
        let port = candidate_port();
        let mut server = DohServer::new(support::doh_on(port), Some(Arc::clone(&provider)));
        server.set_dns_server(encrypted_dns_server(&runtime));
        match server.start().await {
            Ok(()) => return (server, SocketAddr::from(([127, 0, 0, 1], port))),
            Err(error) if is_bind_conflict(&error) => last_conflict = error,
            Err(error) => panic!("DoH start failed: {error}"),
        }
    }
    panic!("DoH could not bind in {BIND_ATTEMPTS} attempts: {last_conflict}");
}

fn quic_client_config() -> quinn::ClientConfig {
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_config(&[b"doq"])))
            .expect("QUIC client config");
    quinn::ClientConfig::new(Arc::new(crypto))
}

struct QuicClient {
    /// Kept alive for the connection's lifetime: dropping the endpoint closes
    /// every connection it owns.
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl QuicClient {
    async fn connect(addr: SocketAddr) -> Result<Self, String> {
        let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|e| format!("client endpoint: {e}"))?;
        let connecting = endpoint
            .connect_with(quic_client_config(), addr, "doq.invalid")
            .map_err(|e| format!("QUIC connect: {e}"))?;
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_string())?
            .map_err(|e| format!("QUIC handshake: {e}"))?;
        Ok(Self {
            _endpoint: endpoint,
            connection,
        })
    }

    async fn query(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;
        send.write_all(&(query.len() as u16).to_be_bytes())
            .await
            .map_err(|e| format!("write length: {e}"))?;
        send.write_all(query)
            .await
            .map_err(|e| format!("write body: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let mut length = [0u8; 2];
        tokio::time::timeout(QUERY_TIMEOUT, recv.read_exact(&mut length))
            .await
            .map_err(|_| "QUIC read length timed out".to_string())?
            .map_err(|e| format!("QUIC read length: {e}"))?;
        let len = u16::from_be_bytes(length) as usize;
        let mut body = vec![0u8; len];
        tokio::time::timeout(QUERY_TIMEOUT, recv.read_exact(&mut body))
            .await
            .map_err(|_| "QUIC read body timed out".to_string())?
            .map_err(|e| format!("QUIC read body: {e}"))?;
        Ok(body)
    }
}

/// Start DoQ (whose `start` runs the accept loop inline) and wait until it
/// completes one handshake, so the port is genuinely serving before a test
/// uses it.
async fn start_doq(
    provider: Arc<dyn SecureTransportConfig>,
    runtime: synvoid_dns::DnsRuntimeConfig,
) -> (tokio::task::JoinHandle<()>, SocketAddr) {
    for _ in 0..BIND_ATTEMPTS {
        let port = candidate_port();
        let mut server = DoqServer::new(support::doq_on(port), Some(Arc::clone(&provider)));
        server.set_dns_server(encrypted_dns_server(&runtime));
        let handle = tokio::spawn(async move {
            let _ = server.start().await;
        });
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        // Poll for readiness with a real handshake instead of sleeping. A
        // successful probe means the endpoint is bound and accepting; the
        // probe's own client is dropped immediately, so it never holds a
        // connection permit.
        for _ in 0..40 {
            match tokio::time::timeout(Duration::from_millis(250), QuicClient::connect(addr)).await
            {
                Ok(Ok(client)) => {
                    drop(client);
                    return (handle, addr);
                }
                _ => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        handle.abort();
    }
    panic!("DoQ could not serve a handshake after {BIND_ATTEMPTS} attempts");
}

// ---------------------------------------------------------------------------
// DnsServer fixtures
// ---------------------------------------------------------------------------

fn runtime_with(
    mutate: impl FnOnce(&mut synvoid_dns::DnsRuntimeConfig),
) -> synvoid_dns::DnsRuntimeConfig {
    let mut runtime = support::dns_runtime();
    // Never dial this socket: the fixture only builds a `DnsServer`.
    runtime.authoritative.bind_address =
        SocketAddr::from(([127, 0, 0, 1], support::UNBOUND_TEST_PORT));
    runtime.recursive.enabled = false;
    mutate(&mut runtime);
    runtime
}

/// A `DnsServer` for the encrypted listeners: same runtime as the test, with
/// the test zone loaded so an admitted query has something to answer.
fn encrypted_dns_server(runtime: &synvoid_dns::DnsRuntimeConfig) -> DnsServer {
    let server = DnsServer::new(runtime.clone(), None, None);
    server
        .load_zones(vec![support::zone_spec(ORIGIN)])
        .expect("load the test zone");
    server
}

fn dedicated_rate_limit(runtime: &mut synvoid_dns::DnsRuntimeConfig) {
    runtime.authoritative.rate_limit = DnsRateLimitRuntimeConfig {
        mode: DnsRateLimitModeRuntime::Dedicated,
        // Burst is 2 * per_second: the third immediate query is refused.
        per_second: 1,
    };
}

// ---------------------------------------------------------------------------
// 1-3: hostile packets become error responses, never panics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_audit_thirty_byte_packet_is_a_formerr_and_the_listener_survives() {
    let mut bound = support::start_bound_dns_server(|_| {}).await;
    let client = UdpClient::new().await;

    let response = client
        .send(bound.port, &audit_thirty_byte_packet(), QUERY_TIMEOUT)
        .await
        .expect("the hostile packet must be answered with an error, not drop the listener");
    assert_eq!(
        response_rcode(&response),
        RCODE_FORMERR,
        "a lying RDLENGTH is a malformed message"
    );
    assert_eq!(
        u16::from_be_bytes([response[0], response[1]]),
        0x3030,
        "the error response must echo the query ID"
    );

    // The listener task is still alive: a normal query is answered.
    let normal = client
        .send(
            bound.port,
            &a_query(0x3031, "www.example.com"),
            QUERY_TIMEOUT,
        )
        .await
        .expect("the listener must still answer after the hostile packet");
    assert_eq!(u16::from_be_bytes([normal[0], normal[1]]), 0x3031);

    bound.server.shutdown_runtime();
}

#[tokio::test]
async fn the_forty_byte_off_by_one_packet_is_a_formerr() {
    let mut bound = support::start_bound_dns_server(|_| {}).await;
    let client = UdpClient::new().await;

    let response = client
        .send(bound.port, &off_by_one_forty_byte_packet(), QUERY_TIMEOUT)
        .await
        .expect("the D15 packet must be answered with an error, not panic");
    assert_eq!(response_rcode(&response), RCODE_FORMERR);

    let normal = client
        .send(
            bound.port,
            &a_query(0x4041, "www.example.com"),
            QUERY_TIMEOUT,
        )
        .await
        .expect("the listener must still answer");
    assert_eq!(u16::from_be_bytes([normal[0], normal[1]]), 0x4041);

    bound.server.shutdown_runtime();
}

#[tokio::test]
async fn an_ecs_prefix_above_the_family_width_is_a_formerr() {
    let mut bound = support::start_bound_dns_server(|_| {}).await;
    let client = UdpClient::new().await;

    let response = client
        .send(bound.port, &ecs_prefix_255_query(), QUERY_TIMEOUT)
        .await
        .expect("an invalid ECS option must be answered with an error");
    assert_eq!(
        response_rcode(&response),
        RCODE_FORMERR,
        "RFC 7871 §6: a prefix wider than the family is malformed"
    );
    assert_eq!(
        response_qdcount(&response),
        1,
        "the error response echoes the question"
    );

    bound.server.shutdown_runtime();
}

// ---------------------------------------------------------------------------
// 4: QR=1 is dropped
// ---------------------------------------------------------------------------

#[tokio::test]
async fn qr_set_produces_no_response_on_udp_and_tcp() {
    let mut bound = support::start_bound_dns_server(|_| {}).await;

    // UDP: no datagram within the window.
    let client = UdpClient::new().await;
    let mut response_query = a_query(0x6001, "www.example.com");
    set_qr(&mut response_query);
    assert!(
        client
            .send(bound.port, &response_query, NO_RESPONSE_WINDOW)
            .await
            .is_none(),
        "a QR=1 packet must not be answered (D14)"
    );

    // The socket is alive and answers a real query afterwards.
    let answered = client
        .send(
            bound.port,
            &a_query(0x6002, "www.example.com"),
            QUERY_TIMEOUT,
        )
        .await
        .expect("the listener must still answer real queries");
    assert_eq!(u16::from_be_bytes([answered[0], answered[1]]), 0x6002);

    // TCP: the server closes the connection without a frame.
    let mut stream = tcp_connect(bound.port).await.expect("connect");
    let mut response_query = a_query(0x6003, "www.example.com");
    set_qr(&mut response_query);
    let outcome = tcp_exchange(&mut stream, &response_query)
        .await
        .expect("the exchange itself must not fail");
    assert!(
        outcome.is_none(),
        "a QR=1 frame must be answered with EOF, not a DNS response"
    );

    bound.server.shutdown_runtime();
}

// ---------------------------------------------------------------------------
// 5: the firewall refuses identically on every transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_firewall_block_is_the_same_refused_on_every_transport() {
    let certificate = test_certificate();
    let provider = StubProvider::from_certificate(&certificate);

    // Control: the same query, the same zone, no firewall → not REFUSED.
    let mut open = support::start_bound_dns_server(|runtime| {
        runtime.authoritative.firewall.enabled = false;
    })
    .await;
    open.server
        .load_zones(vec![support::zone_spec(ORIGIN)])
        .expect("load the test zone");
    let control = UdpClient::new().await;
    let control_response = control
        .send(
            open.port,
            &a_query(0x7000, "www.example.com"),
            QUERY_TIMEOUT,
        )
        .await
        .expect("the zone must answer when no firewall is configured");
    assert_ne!(
        response_rcode(&control_response),
        RCODE_REFUSED,
        "the control query must reach the zone; a REFUSED would make the test vacuous"
    );
    open.server.shutdown_runtime();

    // Firewall enabled installs the loopback subnet rule, so every transport
    // sees the same block for a loopback client.
    let mut blocked = support::start_bound_dns_server(|runtime| {
        runtime.authoritative.firewall.enabled = true;
        runtime.authoritative.firewall.block_internal_ips = true;
    })
    .await;
    blocked
        .server
        .load_zones(vec![support::zone_spec(ORIGIN)])
        .expect("load the test zone");

    let udp = UdpClient::new().await;
    let udp_response = udp
        .send(
            blocked.port,
            &a_query(0x7001, "www.example.com"),
            QUERY_TIMEOUT,
        )
        .await
        .expect("UDP firewall refusal is a response, not a drop");

    let mut tcp = tcp_connect(blocked.port).await.expect("connect TCP");
    let tcp_response = tcp_exchange(&mut tcp, &a_query(0x7002, "www.example.com"))
        .await
        .expect("TCP exchange")
        .expect("TCP firewall refusal is a response, not a drop");

    let encrypted_runtime = runtime_with(|runtime| {
        runtime.authoritative.firewall.enabled = true;
        runtime.authoritative.firewall.block_internal_ips = true;
    });

    let (_dot, dot_addr) = start_dot(Arc::clone(&provider), encrypted_runtime.clone()).await;
    let mut dot_stream = tls_connect(dot_addr, &[]).await.expect("DoT handshake");
    let dot_response = tcp_exchange(&mut dot_stream, &a_query(0x7003, "www.example.com"))
        .await
        .expect("DoT exchange")
        .expect("DoT firewall refusal is a response");

    let (_doh, doh_addr) = start_doh(Arc::clone(&provider), encrypted_runtime.clone()).await;
    let (doh_status, doh_body) = doh_query(doh_addr, &a_query(0x7004, "www.example.com"))
        .await
        .expect("DoH exchange");
    assert_eq!(doh_status, StatusCode::OK, "a DNS error is still HTTP 200");
    let doh_response = doh_body;

    let (doq_handle, doq_addr) = start_doq(Arc::clone(&provider), encrypted_runtime.clone()).await;
    let (quic_client, doq_response) = doq_query_once(doq_addr, &a_query(0x7005, "www.example.com"))
        .await
        .expect("DoQ exchange");
    drop(quic_client);

    for (transport, response) in [
        ("UDP", &udp_response),
        ("TCP", &tcp_response),
        ("DoT", &dot_response),
        ("DoH", &doh_response),
        ("DoQ", &doq_response),
    ] {
        assert_eq!(
            response_rcode(response),
            RCODE_REFUSED,
            "{transport} must return the same REFUSED the firewall produces on UDP"
        );
        assert_eq!(
            response_qdcount(response),
            1,
            "{transport} must echo the question like every other transport"
        );
        assert_eq!(
            response_ancount(response),
            0,
            "{transport} must answer nothing when the firewall blocks"
        );
    }

    blocked.server.shutdown_runtime();
    doq_handle.abort();
}

/// A firewall rule that blocks a qname is evaluated before the cache, so a
/// warm (or poisoned) cache entry can never be served for a blocked name.
///
/// This is a unit-level admission test because the runtime firewall has no
/// qname rule source (it is populated by admin/composition), while the subnet
/// rules used by the listener test above are only installable from config.
#[test]
fn a_blocked_qname_is_refused_before_the_cache_is_consulted() {
    use parking_lot::RwLock;
    use std::sync::Arc as StdArc;

    let (zones, zone_trie, ecs) = support::setup();
    let cache = StdArc::new(DnsCache::new(100, 3600, 0));

    let query = a_query(0x7100, "www.test.local");
    let parsed = ParsedDnsQuery::parse(&query).expect("a well-formed query");
    let key = CacheKey::from_parsed_authoritative(
        &parsed,
        IpAddr::from([127, 0, 0, 1]),
        TransportClass::Udp512,
    );

    // A real answer generated by the handler, then inserted into the cache the
    // admission gate would consult if it ran after a lookup.
    let handler_ctx = support::make_ctx(&zones, &zone_trie, &ecs);
    let answer = DnsServer::handle_query(&handler_ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("the zone answers www.test.local");
    cache.insert(key.clone(), answer.as_ref().clone(), 300);
    assert!(
        cache.get(&key).is_some(),
        "the cached answer must be present for this test to mean anything"
    );

    let mut firewall = DnsFirewall::new();
    firewall
        .add_rule(DnsFirewallRule {
            id: "block-www".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "www.test.local".to_string(),
            ttl: 300,
            created_at: 0,
            expires_at: None,
            enabled: true,
        })
        .expect("add a block rule");
    let firewall = StdArc::new(RwLock::new(firewall));

    let context = synvoid_dns::server::QueryContext {
        zones: &zones,
        zone_trie: &zone_trie,
        geoip_lookup: None,
        min_geo_ttl: 0,
        negative_cache_ttl: 300,
        cache: Some(&cache),
        dnssec: None,
        signer_name: None,
        query_validator: None,
        firewall: Some(&firewall),
        connection_limits: None,
        max_idle_time: None,
        zone_transfer: None,
        ecs_filter_config: &ecs,
        rate_limiter: None,
        rrl_enabled: false,
        update_handler: None,
        notify_handler: None,
        query_coalescer: None,
        dns64_translator: None,
        acme_dns_challenges: None,
        cookie_server: None,
        #[cfg(feature = "mesh")]
        mesh_registry: None,
    };

    match admit(
        &query,
        IpAddr::from([127, 0, 0, 1]),
        TransportKind::Udp,
        &context,
    ) {
        Admission::Reply(reply) => {
            assert_eq!(
                response_rcode(&reply),
                RCODE_REFUSED,
                "the firewall must win over a cache hit"
            );
            assert_ne!(
                reply,
                answer.as_ref().clone(),
                "the cached answer must not be returned for a blocked qname"
            );
        }
        _ => panic!("a firewall-blocked qname must be refused, not allowed or dropped"),
    }

    assert!(
        cache.get(&key).is_some(),
        "admission must not mutate the cache"
    );
}

// ---------------------------------------------------------------------------
// 6: the rate limiter applies on every transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rate_limited_client_is_refused_on_every_transport() {
    // UDP
    {
        let mut bound = support::start_bound_dns_server(dedicated_rate_limit).await;
        bound
            .server
            .load_zones(vec![support::zone_spec(ORIGIN)])
            .expect("load zone");
        let client = UdpClient::new().await;
        for (index, id) in [0x8000u16, 0x8001, 0x8002].iter().enumerate() {
            let response = client
                .send(bound.port, &a_query(*id, "rate.example.com"), QUERY_TIMEOUT)
                .await
                .expect("every rate-limited query gets a response");
            if index < 2 {
                assert_ne!(
                    response_rcode(&response),
                    RCODE_REFUSED,
                    "query {index} is within the burst and must reach the zone"
                );
            } else {
                assert_eq!(
                    response_rcode(&response),
                    RCODE_REFUSED,
                    "the third query exceeds the burst (D12b parity)"
                );
            }
        }
        bound.server.shutdown_runtime();
    }

    // TCP
    {
        let mut bound = support::start_bound_dns_server(dedicated_rate_limit).await;
        bound
            .server
            .load_zones(vec![support::zone_spec(ORIGIN)])
            .expect("load zone");
        let mut stream = tcp_connect(bound.port).await.expect("connect");
        for (index, id) in [0x8100u16, 0x8101, 0x8102].iter().enumerate() {
            let response = tcp_exchange(&mut stream, &a_query(*id, "rate.example.com"))
                .await
                .expect("exchange")
                .expect("TCP refusal is a response");
            if index < 2 {
                assert_ne!(response_rcode(&response), RCODE_REFUSED);
            } else {
                assert_eq!(response_rcode(&response), RCODE_REFUSED);
            }
        }
        bound.server.shutdown_runtime();
    }

    // DoT
    {
        let certificate = test_certificate();
        let provider = StubProvider::from_certificate(&certificate);
        let runtime = runtime_with(dedicated_rate_limit);
        let (_dot, addr) = start_dot(Arc::clone(&provider), runtime).await;
        let mut stream = tls_connect(addr, &[]).await.expect("DoT handshake");
        for (index, id) in [0x8200u16, 0x8201, 0x8202].iter().enumerate() {
            let response = tcp_exchange(&mut stream, &a_query(*id, "rate.example.com"))
                .await
                .expect("exchange")
                .expect("DoT refusal is a response");
            if index < 2 {
                assert_ne!(response_rcode(&response), RCODE_REFUSED);
            } else {
                assert_eq!(response_rcode(&response), RCODE_REFUSED);
            }
        }
    }

    // DoH
    {
        let certificate = test_certificate();
        let provider = StubProvider::from_certificate(&certificate);
        let runtime = runtime_with(dedicated_rate_limit);
        let (_doh, addr) = start_doh(Arc::clone(&provider), runtime).await;
        let (mut sender, driver) = doh_connect(addr).await.expect("DoH handshake");
        for (index, id) in [0x8300u16, 0x8301, 0x8302].iter().enumerate() {
            let (status, body) = doh_send(&mut sender, &a_query(*id, "rate.example.com"))
                .await
                .expect("DoH request");
            assert_eq!(status, StatusCode::OK);
            let rcode = response_rcode(&body);
            if index < 2 {
                assert_ne!(rcode, RCODE_REFUSED, "DoH query {index} is within burst");
            } else {
                assert_eq!(
                    rcode, RCODE_REFUSED,
                    "DoH must enforce the same rate limit as UDP"
                );
            }
        }
        driver.abort();
    }

    // DoQ
    {
        let certificate = test_certificate();
        let provider = StubProvider::from_certificate(&certificate);
        let runtime = runtime_with(dedicated_rate_limit);
        let (handle, addr) = start_doq(Arc::clone(&provider), runtime).await;
        let client = QuicClient::connect(addr).await.expect("DoQ handshake");
        for (index, id) in [0x8400u16, 0x8401, 0x8402].iter().enumerate() {
            let response = client
                .query(&a_query(*id, "rate.example.com"))
                .await
                .expect("DoQ response");
            if index < 2 {
                assert_ne!(response_rcode(&response), RCODE_REFUSED);
            } else {
                assert_eq!(
                    response_rcode(&response),
                    RCODE_REFUSED,
                    "DoQ must enforce the same rate limit as UDP"
                );
            }
        }
        drop(client);
        handle.abort();
    }
}

// ---------------------------------------------------------------------------
// 7: encrypted connection cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_encrypted_connection_cap_refuses_the_n_plus_first_and_recovers() {
    let certificate = test_certificate();
    let provider = StubProvider::from_certificate(&certificate);
    let runtime = runtime_with(|runtime| {
        runtime.authoritative.limits.max_encrypted_connections = 1;
        // A cached response carries the ID of the query that produced it, so
        // keep the cache out of this test and assert the live path directly.
        runtime.authoritative.cache.enabled = false;
    });
    let (_dot, addr) = start_dot(Arc::clone(&provider), runtime).await;

    // First connection holds the only permit and is served.
    let mut first = tls_connect(addr, &[]).await.expect("first DoT handshake");
    let first_response = tcp_exchange(&mut first, &a_query(0x9000, "www.example.com"))
        .await
        .expect("first exchange")
        .expect("the first connection must be answered");
    assert_eq!(
        u16::from_be_bytes([first_response[0], first_response[1]]),
        0x9000
    );

    // Second connection is refused: the accept loop drops the TCP stream
    // before the TLS handshake, so the client sees a handshake failure.
    let second = tokio::time::timeout(HANDSHAKE_TIMEOUT, tls_connect(addr, &[])).await;
    if let Ok(Ok(_)) = second {
        panic!("the N+1th DoT connection must not be accepted");
    }

    // Closing the first releases the permit; poll until the listener accepts
    // again rather than sleeping a fixed amount.
    drop(first);
    let mut recovered = None;
    for _ in 0..100 {
        match tokio::time::timeout(Duration::from_millis(500), tls_connect(addr, &[])).await {
            Ok(Ok(stream)) => {
                recovered = Some(stream);
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut recovered = recovered.expect("the listener must accept after the permit is released");
    let response = tcp_exchange(&mut recovered, &a_query(0x9001, "www.example.com"))
        .await
        .expect("recovered exchange")
        .expect("the server must still answer after the cap releases");
    assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x9001);
}

// ---------------------------------------------------------------------------
// 8: the TSIG parser rejects a name that ends on the final byte
// ---------------------------------------------------------------------------

#[test]
fn a_tsig_name_ending_on_the_final_byte_is_rejected_by_the_public_parser() {
    // Header + one question, then an additional RR whose owner name's
    // terminating zero is the last byte of the packet.
    let mut query = a_query(0xA000, "example.com");
    query[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
    let qd_end = query.len();
    query.extend_from_slice(&[5, b'm', b'y', b'k', b'e', b'y', 0]);
    assert_eq!(*query.last().expect("non-empty"), 0);

    assert!(
        synvoid_dns::parse_tsig_from_query(&query, qd_end).is_err(),
        "an incomplete TSIG RR must be rejected, not indexed past the packet"
    );
}

// ---------------------------------------------------------------------------
// DoH client
// ---------------------------------------------------------------------------

type DohSender = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

async fn doh_connect(
    addr: SocketAddr,
) -> Result<(DohSender, tokio::task::JoinHandle<Result<(), hyper::Error>>), String> {
    let tls = tls_connect(addr, &[b"h2"]).await?;
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .map_err(|e| format!("DoH HTTP/2 handshake: {e}"))?;
    let driver = tokio::spawn(connection);
    Ok((sender, driver))
}

async fn doh_send(sender: &mut DohSender, query: &[u8]) -> Result<(StatusCode, Vec<u8>), String> {
    let request = Request::builder()
        .method("POST")
        .uri("https://doh.invalid/dns-query")
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(query.to_vec())))
        .map_err(|e| format!("build request: {e}"))?;
    let response = tokio::time::timeout(QUERY_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| "DoH request timed out".to_string())?
        .map_err(|e| format!("DoH request: {e}"))?;
    let status = response.status();
    let body = tokio::time::timeout(QUERY_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "DoH body timed out".to_string())?
        .map_err(|e| format!("DoH body: {e}"))?
        .to_bytes()
        .to_vec();
    Ok((status, body))
}

/// One DoH request over a fresh connection.
async fn doh_query(addr: SocketAddr, query: &[u8]) -> Result<(StatusCode, Vec<u8>), String> {
    let (mut sender, driver) = doh_connect(addr).await?;
    let result = doh_send(&mut sender, query).await;
    driver.abort();
    result
}

/// One DoQ request over a fresh connection, returning the client so the caller
/// decides when to close it.
async fn doq_query_once(addr: SocketAddr, query: &[u8]) -> Result<(QuicClient, Vec<u8>), String> {
    let client = QuicClient::connect(addr).await?;
    let response = client.query(query).await?;
    Ok((client, response))
}

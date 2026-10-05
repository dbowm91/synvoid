//! Phase 133 Workstream A — TLS **provider** evidence for `CertResolver`.
//!
//! Phase 130 recorded that DNS calls *zero* methods on `CertResolver` and
//! left the inversion target unproven. That is wrong: DNS calls exactly one —
//! `build_server_config()`, which returns a rustls `ServerConfig`. This suite
//! pins what that one call actually produces, because every one of those
//! behaviors is what a DNS-owned trait in Phase 134 would have to reproduce
//! byte for byte.
//!
//! Everything here runs against a real rustls handshake rather than by
//! inspecting struct fields alone, so the SNI, ALPN, and protocol-version
//! claims are observed rather than inferred.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, ServerConfig,
};
use rustls::{SignatureScheme, StreamOwned};
use rustls_pki_types::pem::PemObject;
use synvoid_tls::cert_resolver::CertResolver;
use synvoid_tls::{InternalClientAuthConfig, InternalTlsConfig};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

// ---- certificate material --------------------------------------------------

struct Pki {
    dir: PathBuf,
    default_pem: String,
    example_pem: String,
    wildcard_pem: String,
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("synvoid-phase133-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    dir
}

fn self_signed(names: &[&str]) -> (String, String) {
    let generated =
        rcgen::generate_simple_self_signed(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .expect("generate self-signed certificate");
    (generated.cert.pem(), generated.key_pair.serialize_pem())
}

/// A CA plus a leaf certificate actually signed by it, so a
/// `WebPkiClientVerifier` built from that CA accepts the leaf. A self-signed
/// leaf is not enough: the chain has to terminate at the CA the verifier was
/// built with, otherwise the handshake fails with `BadSignature`.
///
/// Returns the CA and the leaf as PEM, which is all the tests need.
fn ca_and_signed_leaf() -> ((String, String), (String, String)) {
    let ca_key = rcgen::KeyPair::generate().expect("generate CA key");
    let ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("build CA parameters")
        .self_signed(&ca_key)
        .expect("self-sign the CA");
    let ca = (ca_params.pem(), ca_key.serialize_pem());

    let subject_key = rcgen::KeyPair::generate().expect("generate leaf key");
    let subject_params = rcgen::CertificateParams::new(vec!["client.invalid".to_string()])
        .expect("build leaf parameters");
    let leaf = subject_params
        .signed_by(&subject_key, &ca_params, &ca_key)
        .expect("sign the leaf with the CA");
    let leaf = (leaf.pem(), subject_key.serialize_pem());

    (ca, leaf)
}

/// Three server certificates with distinct keys (so the presented chain
/// identifies which one was selected), plus a client certificate and a CA.
fn pki(name: &str) -> Pki {
    let dir = temp_dir(name);
    let (default_pem, default_key) = self_signed(&["default.invalid"]);
    let (example_pem, example_key) = self_signed(&["example.com"]);
    let (wildcard_pem, wildcard_key) = self_signed(&["*.example.com"]);
    let ((ca_pem, ca_key_pem), (client_pem, client_key)) = ca_and_signed_leaf();

    std::fs::write(dir.join("default.pem"), &default_pem).expect("write default cert");
    std::fs::write(dir.join("default.key"), &default_key).expect("write default key");

    // The watch directory keys its map by file stem, so these file names are
    // themselves the SNI routing table.
    for (stem, cert, key) in [
        ("example.com", &example_pem, example_key),
        ("*.example.com", &wildcard_pem, wildcard_key),
    ] {
        std::fs::write(dir.join(format!("{stem}.pem")), cert).expect("write watched cert");
        std::fs::write(dir.join(format!("{stem}.key")), key).expect("write watched key");
    }

    std::fs::write(dir.join("client.pem"), &client_pem).expect("write client cert");
    std::fs::write(dir.join("client.key"), &client_key).expect("write client key");
    std::fs::write(dir.join("ca.pem"), &ca_pem).expect("write CA cert");
    std::fs::write(dir.join("ca.key"), &ca_key_pem).expect("write CA key");

    Pki {
        dir,
        default_pem,
        example_pem,
        wildcard_pem,
    }
}

fn leaf_der(pem: &str) -> Vec<u8> {
    let certs = synvoid_tls::load_cert_from_pem(pem.as_bytes()).expect("PEM parses");
    certs[0].as_ref().to_vec()
}

// ---- handshake harness -----------------------------------------------------

/// A verifier that records the presented leaf instead of validating it, so the
/// suite can assert *which* certificate the resolver selected.
struct Capture {
    leaf: Arc<Mutex<Option<Vec<u8>>>>,
    provider: Arc<CryptoProvider>,
}

impl Capture {
    fn new() -> (Self, Arc<Mutex<Option<Vec<u8>>>>) {
        let leaf = Arc::new(Mutex::new(None));
        (
            Self {
                leaf: Arc::clone(&leaf),
                provider: provider(),
            },
            leaf,
        )
    }
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Ok(mut slot) = self.leaf.lock() {
            *slot = Some(end_entity.as_ref().to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct ClientOptions<'a> {
    server_name: &'a str,
    versions: Vec<&'static rustls::SupportedProtocolVersion>,
    alpn: Vec<Vec<u8>>,
    kx_groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>,
    client_auth: Option<(&'a str, &'a str)>,
}

impl Default for ClientOptions<'_> {
    fn default() -> Self {
        Self {
            server_name: "example.com",
            versions: vec![&rustls::version::TLS13],
            alpn: Vec::new(),
            kx_groups: None,
            client_auth: None,
        }
    }
}

/// Bounded I/O for every socket in the harness.
///
/// Without this the suite can deadlock rather than fail: a rejected handshake
/// leaves one side blocked in `accept`, `complete_io`, or the echo read while
/// the other has already given up. A test that hangs is a test that never
/// reports, so both sides get a deadline.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn bound(socket: &TcpStream) {
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout is settable");
    socket
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("write timeout is settable");
}

struct Handshake {
    server: Result<(), String>,
    client: Result<(), String>,
    leaf: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
}

/// Run one handshake. The server side is driven on a thread so both
/// termination paths — a server-side rejection and a client-side success — are
/// observable, which TLS 1.3 requires because the client's certificate request
/// arrives after the client considers the handshake finished.
///
/// The connection is always established, even on the paths that cannot
/// complete a handshake, so the server never waits forever in `accept`.
fn handshake(server_config: Arc<ServerConfig>, options: ClientOptions<'_>) -> Handshake {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr: SocketAddr = listener.local_addr().expect("local addr");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(drive_server(&listener, server_config));
    });

    let (capture, leaf) = Capture::new();
    let crypto = match &options.kx_groups {
        Some(groups) => {
            let mut customized = (*provider()).clone();
            customized.kx_groups = groups.clone();
            Arc::new(customized)
        }
        None => provider(),
    };

    let socket = match TcpStream::connect(addr) {
        Ok(socket) => {
            bound(&socket);
            socket
        }
        Err(e) => {
            let server = rx
                .recv_timeout(IO_TIMEOUT)
                .unwrap_or_else(|_| Err("server thread did not report".to_string()));
            return Handshake {
                server,
                client: Err(format!("connect: {e}")),
                leaf: None,
                alpn: None,
            };
        }
    };

    let wants_cert = ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(&options.versions)
        .expect("client protocol versions are supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(capture));

    let mut config: ClientConfig = match &options.client_auth {
        Some((cert_path, key_path)) => {
            let certs = CertificateDer::pem_file_iter(Path::new(cert_path))
                .expect("read client cert")
                .collect::<Result<Vec<_>, _>>()
                .expect("parse client cert");
            let key = PrivateKeyDer::from_pem_file(Path::new(key_path)).expect("read client key");
            wants_cert
                .with_client_auth_cert(certs, key)
                .expect("client certificate and key are usable")
        }
        None => wants_cert.with_no_client_auth(),
    };

    config.alpn_protocols = options.alpn.clone();
    config.enable_sni = true;

    let (client, alpn) = match ServerName::try_from(options.server_name.to_string()) {
        Ok(name) => match ClientConnection::new(Arc::new(config), name) {
            Ok(connection) => {
                // `StreamOwned` takes the connection by value; passing `&mut`
                // would leave the `Deref<Target = ConnectionCommon<_>>` bound
                // unsatisfied.
                let mut stream = StreamOwned::new(connection, socket);
                let outcome = {
                    let StreamOwned { conn, sock } = &mut stream;
                    conn.complete_io(sock)
                };
                match outcome {
                    Ok(_) => {
                        // The echo is best effort: a rejected handshake may
                        // have already torn the connection down, and this suite
                        // asserts on the handshake, not on the echo.
                        let _ = stream.write_all(b"ping");
                        let _ = stream.flush();
                        let mut buf = [0u8; 4];
                        let _ = stream.read_exact(&mut buf);
                        let alpn = stream.conn.alpn_protocol().map(|p| p.to_vec());
                        (Ok(()), alpn)
                    }
                    Err(e) => (Err(format!("client io: {e}")), None),
                }
            }
            Err(e) => (Err(format!("client connection: {e}")), None),
        },
        Err(e) => (Err(format!("server name: {e}")), None),
    };

    let server = rx
        .recv_timeout(IO_TIMEOUT)
        .unwrap_or_else(|_| Err("server thread did not report in time".to_string()));
    let leaf = leaf.lock().ok().and_then(|guard| guard.clone());

    Handshake {
        server,
        client,
        leaf,
        alpn,
    }
}

/// Accept one connection, complete the server handshake, and echo 4 bytes.
fn drive_server(listener: &TcpListener, config: Arc<ServerConfig>) -> Result<(), String> {
    let (socket, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    bound(&socket);
    let connection =
        rustls::ServerConnection::new(config).map_err(|e| format!("server connection: {e}"))?;
    let mut stream = StreamOwned::new(connection, socket);
    {
        let StreamOwned { conn, sock } = &mut stream;
        conn.complete_io(sock)
            .map_err(|e| format!("server io: {e}"))?;
    }

    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("server read: {e}"))?;
    stream
        .write_all(&buf)
        .map_err(|e| format!("server write: {e}"))
}

fn tls_config(pki: &Pki, mutate: impl FnOnce(&mut InternalTlsConfig)) -> InternalTlsConfig {
    let mut config = InternalTlsConfig {
        enabled: true,
        cert_path: Some(pki.dir.join("default.pem")),
        key_path: Some(pki.dir.join("default.key")),
        // The watch directory populates the SNI map keyed by file stem.
        watch_dir: Some(pki.dir.clone()),
        // Keep the fixture deterministic: the real default is `true` for both.
        prefer_post_quantum: false,
        tls_1_3_only: true,
        enable_tls_12_fallback: false,
        ocsp_stapling_enabled: false,
        ..Default::default()
    };
    mutate(&mut config);
    config
}

fn loaded_resolver(pki: &Pki, mutate: impl FnOnce(&mut InternalTlsConfig)) -> CertResolver {
    let resolver = CertResolver::new(tls_config(pki, mutate));
    resolver
        .load_certificates()
        .expect("fixture certificates load");
    resolver
}

// ---- Workstream A.1 — SNI selection ----------------------------------------

/// A-1a: an exact SNI match selects that domain's certificate. The presented
/// leaf is compared byte for byte against the on-disk certificate for
/// `example.com`, so this distinguishes selection from fallback.
#[test]
fn exact_sni_match_selects_that_domain_certificate() {
    let pki = pki("sni-exact");
    let resolver = loaded_resolver(&pki, |_| {});
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let handshake = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            ..Default::default()
        },
    );

    handshake
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("client handshake must succeed: {e}"));
    handshake
        .server
        .as_ref()
        .unwrap_or_else(|e| panic!("server handshake must succeed: {e}"));
    assert_eq!(
        handshake.leaf.as_deref(),
        Some(leaf_der(&pki.example_pem).as_slice()),
        "SNI example.com must select the example.com certificate"
    );
}

/// A-1b: a name covered only by a wildcard certificate selects it. The resolver
/// derives `*.example.com` from the SNI by discarding the leading label.
#[test]
fn unmatched_label_falls_back_to_the_wildcard_certificate() {
    let pki = pki("sni-wildcard");
    let resolver = loaded_resolver(&pki, |_| {});
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let handshake = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "shop.example.com",
            ..Default::default()
        },
    );

    handshake
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("client handshake must succeed: {e}"));
    assert_eq!(
        handshake.leaf.as_deref(),
        Some(leaf_der(&pki.wildcard_pem).as_slice()),
        "shop.example.com must select the *.example.com certificate"
    );
}

/// A-1c: a name matching neither the map nor a wildcard falls back to the
/// default certificate rather than failing the handshake. This is the
/// behavior that lets a single listener serve unrelated names.
#[test]
fn unknown_sni_falls_back_to_the_default_certificate() {
    let pki = pki("sni-unknown");
    let resolver = loaded_resolver(&pki, |_| {});
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let handshake = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "unrelated.test",
            ..Default::default()
        },
    );

    handshake
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("client handshake must succeed: {e}"));
    assert_eq!(
        handshake.leaf.as_deref(),
        Some(leaf_der(&pki.default_pem).as_slice()),
        "an unknown name must be served the default certificate"
    );
}

/// A-1d: with no certificate loaded at all there is nothing to fall back to,
/// so the handshake fails. `build_server_config` still succeeds, because the
/// resolver is installed as the cert resolver and only discovers the emptiness
/// when a client actually offers an SNI.
#[test]
fn a_resolver_with_no_certificates_fails_the_handshake() {
    // No `load_certificates()` call, and no `cert_path` at all.
    let resolver = CertResolver::new(InternalTlsConfig {
        enabled: true,
        prefer_post_quantum: false,
        tls_1_3_only: true,
        ocsp_stapling_enabled: false,
        ..Default::default()
    });
    let server_config = resolver
        .build_server_config()
        .expect("config builds regardless");

    let handshake = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            ..Default::default()
        },
    );

    assert!(
        handshake.server.is_err(),
        "the server must reject a handshake it has no certificate for"
    );
}

// ---- Workstream A.4 — ALPN -------------------------------------------------

/// A-4a (F-6): `build_server_config` configures protocol versions, an optional
/// client verifier, and the certificate resolver — and **no ALPN**. The
/// configured list is empty, so rustls performs no ALPN negotiation at all.
#[test]
fn build_server_config_configures_no_alpn_protocols() {
    let pki = pki("alpn-config");
    let resolver = loaded_resolver(&pki, |_| {});
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    assert!(
        server_config.alpn_protocols.is_empty(),
        "no ALPN protocol is configured, so none is advertised"
    );
}

/// A-4b: the absence is observable on the wire. Even a client that offers
/// `h2` and `doq` receives no negotiated protocol.
///
/// Consequence for the encrypted transports, recorded rather than changed:
/// DoT and DoQ are connection-oriented and DoH is HTTP/2-based, so a client
/// that requires ALPN negotiation cannot use this listener. Adding ALPN here
/// would be a protocol behavior change and belongs in its own phase, not in
/// an evidence gate.
#[test]
fn no_alpn_is_negotiated_even_when_the_client_offers_one() {
    let pki = pki("alpn-wire");
    let resolver = loaded_resolver(&pki, |_| {});
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let handshake = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            alpn: vec![b"h2".to_vec(), b"doq".to_vec()],
            ..Default::default()
        },
    );

    handshake
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("client handshake must succeed: {e}"));
    assert_eq!(
        handshake.alpn, None,
        "the server must select no ALPN protocol"
    );
}

// ---- Workstream A.7 — protocol version policy ------------------------------

/// A-7a: `tls_1_3_only = true` admits TLS 1.3 and refuses TLS 1.2. Asserted
/// at the handshake rather than by field inspection, because `ServerConfig`
/// does not expose its enabled version list.
#[test]
fn tls_1_3_only_admits_1_3_and_refuses_1_2() {
    let pki = pki("versions-13-only");
    let resolver = loaded_resolver(&pki, |config| config.tls_1_3_only = true);
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let admitted = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            versions: vec![&rustls::version::TLS13],
            ..Default::default()
        },
    );
    admitted
        .server
        .as_ref()
        .unwrap_or_else(|e| panic!("TLS 1.3 must be admitted: {e}"));

    let refused = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            versions: vec![&rustls::version::TLS12],
            ..Default::default()
        },
    );
    assert!(
        refused.server.is_err(),
        "TLS 1.2 must be refused when tls_1_3_only is set"
    );
}

/// A-7b: `enable_tls_12_fallback = true` admits both.
#[test]
fn tls_1_2_fallback_admits_both_versions() {
    let pki = pki("versions-fallback");
    let resolver = loaded_resolver(&pki, |config| {
        config.tls_1_3_only = false;
        config.enable_tls_12_fallback = true;
    });
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    for (label, versions) in [
        ("TLS 1.3", vec![&rustls::version::TLS13]),
        ("TLS 1.2", vec![&rustls::version::TLS12]),
    ] {
        let attempt = handshake(
            Arc::clone(&server_config),
            ClientOptions {
                server_name: "example.com",
                versions,
                ..Default::default()
            },
        );
        attempt
            .server
            .as_ref()
            .unwrap_or_else(|e| panic!("{label} must be admitted when fallback is on: {e}"));
    }
}

/// A-7c: with **neither** flag set, `build_server_config` takes its final
/// `else` branch and admits both versions, logging a backward-compatibility
/// warning. That branch is only reachable through explicit configuration,
/// because `InternalTlsConfig::default()` sets `tls_1_3_only = true` (A-7e).
/// The distinction matters: "neither flag" is not "the default".
#[test]
fn neither_version_flag_admits_both_versions() {
    let pki = pki("versions-backcompat");
    let resolver = loaded_resolver(&pki, |config| {
        config.tls_1_3_only = false;
        config.enable_tls_12_fallback = false;
    });
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    for versions in [vec![&rustls::version::TLS13], vec![&rustls::version::TLS12]] {
        handshake(
            Arc::clone(&server_config),
            ClientOptions {
                server_name: "example.com",
                versions,
                ..Default::default()
            },
        )
        .server
        .as_ref()
        .unwrap_or_else(|e| panic!("both versions must be admitted when neither flag is set: {e}"));
    }
}

/// A-7e: the type's own default is TLS 1.3 only, with post-quantum preference
/// on and OCSP stapling on. Pinned so that a change to `Default` — which every
/// composition root inherits when it does not spell the field out — cannot
/// quietly relax the version floor.
#[test]
fn the_internal_tls_config_default_is_tls_1_3_only() {
    let config = InternalTlsConfig::default();
    assert!(config.tls_1_3_only, "the default must enforce TLS 1.3");
    assert!(!config.enable_tls_12_fallback);
    assert!(config.prefer_post_quantum);
    assert!(config.ocsp_stapling_enabled);
    assert!(!config.client_auth.enabled, "client auth must stay opt-in");
    assert!(
        !config.enabled,
        "TLS must stay opt-in; the default is inert"
    );
}

/// A-7d (F-7): `prefer_post_quantum` is not a gate. It only emits a debug log
/// and a counter; it does not select key-exchange groups. A client that offers
/// *only* the hybrid group still completes a handshake against a server built
/// with the flag off, because the compiled-in `prefer-post-quantum` rustls
/// feature — not this setting — determines the group's availability.
///
/// A DNS-owned trait in Phase 134 must therefore not be described as
/// "honouring a post-quantum preference": there is no preference to honour.
#[test]
fn prefer_post_quantum_does_not_gate_the_hybrid_key_exchange() {
    use rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768;

    let pki = pki("versions-pq");
    let resolver = loaded_resolver(&pki, |config| {
        config.prefer_post_quantum = false;
        config.tls_1_3_only = true;
    });
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let handshake = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            versions: vec![&rustls::version::TLS13],
            // `X25519MLKEM768` is already a `&'static dyn SupportedKxGroup`.
            kx_groups: Some(vec![X25519MLKEM768]),
            ..Default::default()
        },
    );

    handshake
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("hybrid-only client must connect: {e}"));
    handshake
        .server
        .as_ref()
        .unwrap_or_else(|e| panic!("server must accept the hybrid group: {e}"));
}

// ---- Workstream A.5 — mTLS failure paths -----------------------------------

/// A-5a: client auth enabled with no `ca_cert_path` is a hard error, and the
/// message is the provider's own. A DNS-owned trait must not swallow or
/// restate it.
#[test]
fn client_auth_without_a_ca_path_is_a_hard_error_with_a_stable_message() {
    let pki = pki("mtls-no-ca");
    let resolver = loaded_resolver(&pki, |config| {
        config.client_auth = InternalClientAuthConfig {
            enabled: true,
            ca_cert_path: None,
        };
    });

    let error = resolver
        .build_server_config()
        .expect_err("client auth without a CA must fail");
    assert_eq!(
        error.to_string(),
        "CA certificate path not configured for client authentication"
    );
}

/// A-5b (F-11): a CA file containing no certificates is a hard error, and the
/// message comes from `load_ca_certs`, not from `build_server_config`.
///
/// That makes the `"No CA certificates found for client authentication"` branch
/// in `build_server_config` **dead**: `load_ca_certs` returns
/// `Err("No CA certificates found in file")` before it can return an empty
/// `RootCertStore`, so the `if !ca_certs.is_empty()` guard is always true by
/// the time it is reached. The message an operator actually sees is the
/// `load_ca_certs` one, so that is what is pinned here.
#[test]
fn client_auth_with_an_empty_ca_file_is_a_hard_error() {
    let pki = pki("mtls-empty-ca");
    let empty_ca = pki.dir.join("empty-ca.pem");
    std::fs::write(&empty_ca, b"").expect("write empty CA file");

    let resolver = loaded_resolver(&pki, |config| {
        config.client_auth = InternalClientAuthConfig {
            enabled: true,
            ca_cert_path: Some(empty_ca),
        };
    });

    let error = resolver
        .build_server_config()
        .expect_err("an empty CA file must fail");
    assert_eq!(error.to_string(), "No CA certificates found in file");
}

/// A-5b': a CA file that exists but is not a certificate fails the same way, so
/// the empty-file message is not specific to emptiness.
#[test]
fn a_malformed_ca_file_is_rejected_before_the_verifier_is_built() {
    let pki = pki("mtls-malformed-ca");
    let garbage_ca = pki.dir.join("garbage-ca.pem");
    std::fs::write(&garbage_ca, b"-----BEGIN CERTIFICATE-----\nnot base64\n")
        .expect("write malformed CA file");

    let resolver = loaded_resolver(&pki, |config| {
        config.client_auth = InternalClientAuthConfig {
            enabled: true,
            ca_cert_path: Some(garbage_ca),
        };
    });

    let error = resolver
        .build_server_config()
        .expect_err("a malformed CA file must fail");
    // The PEM iterator yields no certificates, so this is the same path as the
    // empty file.
    assert_eq!(error.to_string(), "No CA certificates found in file");
}

/// A-5b'': a `ca_cert_path` that does not exist is a distinct, more useful
/// error, because it names the file that could not be opened.
#[test]
fn a_missing_ca_file_reports_the_io_failure() {
    let resolver = CertResolver::new(InternalTlsConfig {
        enabled: true,
        client_auth: InternalClientAuthConfig {
            enabled: true,
            ca_cert_path: Some(std::env::temp_dir().join("synvoid-phase133-no-such-ca.pem")),
        },
        prefer_post_quantum: false,
        tls_1_3_only: true,
        ocsp_stapling_enabled: false,
        ..Default::default()
    });

    let error = resolver
        .build_server_config()
        .expect_err("a missing CA file must fail");
    assert!(
        error.to_string().contains("No such file or directory"),
        "an unreadable CA path must surface the IO error, got: {error}"
    );
}

/// A-5c: with a valid CA the client verifier is actually installed — a client
/// presenting no certificate is rejected, while one presenting a certificate
/// signed by that CA is admitted.
#[test]
fn a_valid_ca_installs_a_working_client_verifier() {
    let pki = pki("mtls-valid-ca");
    let resolver = loaded_resolver(&pki, |config| {
        config.client_auth = InternalClientAuthConfig {
            enabled: true,
            ca_cert_path: Some(pki.dir.join("ca.pem")),
        };
    });
    let server_config = resolver.build_server_config().expect("valid CA builds");

    let anonymous = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            ..Default::default()
        },
    );
    assert!(
        anonymous.server.is_err(),
        "mTLS must reject a client with no certificate"
    );

    let identified = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "example.com",
            client_auth: Some((
                pki.dir.join("client.pem").to_str().expect("utf-8 path"),
                pki.dir.join("client.key").to_str().expect("utf-8 path"),
            )),
            ..Default::default()
        },
    );
    identified
        .server
        .as_ref()
        .unwrap_or_else(|e| panic!("a signed client certificate must be accepted: {e}"));
}

// ---- Workstream A.2 — reload semantics -------------------------------------

/// A-2a: loading certificates emits exactly one reload event. The reload
/// channel is the provider's own; nothing in the DNS crate subscribes to it
/// (pinned by a repo guard), so the sender and receiver are both inside
/// `synvoid-tls` / composition.
#[test]
fn loading_certificates_emits_one_reload_event() {
    let pki = pki("reload-success");
    let resolver = CertResolver::new(tls_config(&pki, |_| {}));
    let mut events = resolver.reload_tx().subscribe();

    resolver.load_certificates().expect("load succeeds");
    // The broadcast send happens inside `load_certificates`, so the event is
    // already queued; `try_recv` avoids needing a runtime for these tests.
    events
        .try_recv()
        .expect("a reload event must be emitted on a successful load");
    assert!(events.try_recv().is_err(), "exactly one event per load");
}

/// A-2b: a failed load emits nothing, so a failed reload cannot be mistaken
/// for a successful one. The message is the provider's own.
#[test]
fn a_failed_load_emits_no_reload_event() {
    let resolver = CertResolver::new(InternalTlsConfig {
        enabled: true,
        // No certificate path at all.
        cert_path: None,
        key_path: None,
        prefer_post_quantum: false,
        tls_1_3_only: true,
        ocsp_stapling_enabled: false,
        ..Default::default()
    });
    let mut events = resolver.reload_tx().subscribe();

    let error = resolver
        .load_certificates()
        .expect_err("loading with no path must fail");
    assert_eq!(error.to_string(), "No certificate path configured");
    assert!(
        events.try_recv().is_err(),
        "a failed load must not emit a reload event"
    );
}

/// A-2c: a reload is visible through an **already-built** `ServerConfig`. The
/// config holds `Arc<dyn ResolvesServerCert>` over a clone of the resolver, and
/// the resolver's certificate map is interior-mutable, so replacing the on-disk
/// material and reloading changes what a live listener serves without any
/// rebuild.
///
/// This is the mechanism a DNS-owned trait in Phase 134 must preserve: whatever
/// replaces `CertResolver` has to stay clone-cheap and keep that same
/// indirection, or encrypted-transport reload stops working.
#[test]
fn a_reload_is_visible_through_an_already_built_server_config() {
    let pki = pki("reload-in-place");
    // No watch directory: the default certificate is the only source, so
    // rewriting it is the only way to change what is served.
    let resolver = CertResolver::new(tls_config(&pki, |config| config.watch_dir = None));
    resolver.load_certificates().expect("initial load succeeds");
    let server_config = resolver
        .build_server_config()
        .expect("server config builds");

    let first = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "unrelated.test",
            ..Default::default()
        },
    );
    first
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("client handshake must succeed: {e}"));
    assert_eq!(
        first.leaf.as_deref(),
        Some(leaf_der(&pki.default_pem).as_slice()),
        "precondition: the original default certificate is served"
    );

    // Replace the on-disk default with a different certificate and key, then
    // reload through the same resolver the live config is already using.
    let (replacement_pem, replacement_key) = self_signed(&["replacement.invalid"]);
    std::fs::write(pki.dir.join("default.pem"), &replacement_pem).expect("swap certificate");
    std::fs::write(pki.dir.join("default.key"), &replacement_key).expect("swap key");
    resolver.load_certificates().expect("reload succeeds");

    let second = handshake(
        Arc::clone(&server_config),
        ClientOptions {
            server_name: "unrelated.test",
            ..Default::default()
        },
    );
    second
        .client
        .as_ref()
        .unwrap_or_else(|e| panic!("client handshake must succeed after reload: {e}"));
    assert_eq!(
        second.leaf.as_deref(),
        Some(leaf_der(&replacement_pem).as_slice()),
        "the live ServerConfig must serve the reloaded certificate without being rebuilt"
    );
}

// ---- Workstream A.3 — private-key ownership --------------------------------

/// A-3: private-key material is read, validated, and loaded entirely inside
/// `synvoid-tls`, and the only thing that crosses the boundary is
/// `Arc<rustls::ServerConfig>`.
///
/// The seam is pinned here at the type level by writing out the exact
/// signature. The source-level half of this invariant — that `synvoid-dns`
/// never names `PrivateKeyDer`, `CertifiedKey`, or `load_private_key` — is
/// gated in `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs`
/// (`dns_never_names_tls_private_key_material`), because a guard that reads a
/// sibling crate's source belongs in the crate that knows about both, not in
/// `synvoid-tls`'s test suite.
#[test]
fn the_provider_boundary_exposes_only_an_arc_server_config() {
    /// The seam's exact shape, named so a signature change fails to compile
    /// here rather than silently widening the boundary.
    type BuildServerConfig =
        fn(&CertResolver) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>>;

    let build: BuildServerConfig = CertResolver::build_server_config;
    let _ = build;
}

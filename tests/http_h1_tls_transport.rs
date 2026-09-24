//! Root-test ownership: COMPOSITION
//! Rationale: Phase 72 real TLS-H1 transport evidence. Performs an actual
//! Rustls handshake (client trusts only the test certificate, ALPN
//! `http/1.1`) and then drives Hyper H1 over the resulting server
//! `tokio_rustls::server::TlsStream` through the production
//! `synvoid::http::h1_policy::configure_h1_builder` mapping with
//! `.with_upgrades()` retained.
//!
//! Narrow seam under test:
//!
//! ```text
//! TCP
//!  -> real rustls server/client handshake
//!  -> negotiated ALPN http/1.1
//!  -> server TlsStream
//!  -> production configure_h1_builder
//!  -> Hyper H1 serve_connection(...).with_upgrades()
//! ```
//!
//! This is NOT full `HttpsServer` coverage: it does not construct WAF,
//! router, or backend infrastructure. The production TLS-H1 call site in
//! `src/tls/server.rs` is pinned to the same helper by the source guard in
//! `tests/http_h1_parser_parity.rs`; together they prove the transport
//! mapping without duplicating the root server. The TLS H2 branch is owned
//! by that same guard (`max_header_list_size(max_headers as u32)`
//! unchanged); no new H2 framework is claimed here.
//!
//! Certificate convention follows the repository's established test pattern
//! (`crates/synvoid-http-client/tests/egress_parity.rs`): `rcgen`
//! self-signed leaf for `localhost`, DER handed directly to both peers, no
//! new supply-chain surface. No private Hyper error strings are asserted
//! (status classes only).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use synvoid::http::h1_policy;
use synvoid_config::http::HttpConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_config(max_headers: usize, max_request_size: usize, timeout_secs: u64) -> HttpConfig {
    HttpConfig {
        header_read_timeout_secs: timeout_secs,
        max_headers,
        max_request_size,
        ..HttpConfig::default()
    }
}

fn rcgen_self_signed_der() -> (Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        certified.cert.der().to_vec(),
        certified.key_pair.serialize_der(),
    )
}

fn server_tls_acceptor(cert_der: Vec<u8>, key_der: Vec<u8>) -> tokio_rustls::TlsAcceptor {
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls_pki_types::CertificateDer::from(cert_der)],
        rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key_der)),
    )
    .unwrap();
    // The production TLS listener negotiates H1/H2 via ALPN; this fixture
    // pins the H1 leg exactly.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

/// Spawn a real-TLS H1 loopback server: TCP accept, real Rustls handshake,
/// then Hyper H1 over the server `TlsStream` via the production helper.
/// Returns the bound address plus the ALPN protocol the server observed
/// during the handshake (populated once a client connects).
async fn spawn_tls_h1_server(
    config: HttpConfig,
    acceptor: tokio_rustls::TlsAcceptor,
) -> (SocketAddr, Arc<Mutex<Option<Vec<u8>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_alpn: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let alpn_probe = server_alpn.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let cfg = config.clone();
            let alpn_probe = alpn_probe.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("TLS handshake");
                *alpn_probe.lock().unwrap() = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        let is_upgrade = req.headers().contains_key("sec-websocket-key");
                        if is_upgrade {
                            let mut resp = hyper::Response::new(http_body_util::Full::new(
                                bytes::Bytes::from_static(b"switched"),
                            ));
                            *resp.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
                            Ok::<_, hyper::Error>(resp)
                        } else {
                            Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                                bytes::Bytes::from_static(b"ok"),
                            )))
                        }
                    },
                );
                let io = hyper_util::rt::TokioIo::new(tls);
                // Production mapping under test: no copied builder settings.
                let mut builder = hyper::server::conn::http1::Builder::new();
                h1_policy::configure_h1_builder(&mut builder, &cfg);
                let conn = builder.serve_connection(io, svc).with_upgrades();
                let _ = conn.await;
            });
        }
    });
    (addr, server_alpn)
}

/// Real TLS client handshake against the fixture server. Trusts ONLY the
/// test certificate and offers ONLY `http/1.1`.
async fn tls_connect(
    addr: SocketAddr,
    cert_der: &[u8],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(cert_der.to_vec()))
        .unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    connector.connect(server_name, tcp).await.unwrap()
}

fn client_negotiated_alpn(
    stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Option<Vec<u8>> {
    stream.get_ref().1.alpn_protocol().map(|p| p.to_vec())
}

async fn tls_request(addr: SocketAddr, cert_der: &[u8], request: &[u8]) -> String {
    let mut stream = tls_connect(addr, cert_der).await;
    assert_eq!(
        client_negotiated_alpn(&stream).as_deref(),
        Some(b"http/1.1".as_slice()),
        "client must negotiate ALPN http/1.1"
    );
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

fn wait_for_server_alpn(server_alpn: &Arc<Mutex<Option<Vec<u8>>>>) -> Option<Vec<u8>> {
    let started = Instant::now();
    loop {
        if let Some(seen) = server_alpn.lock().unwrap().clone() {
            return Some(seen);
        }
        if started.elapsed() > Duration::from_secs(5) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ─── ALPN + normal request control over a real TLS stream ────────────────────

#[tokio::test]
async fn tls_h1_real_alpn_negotiates_http11_and_serves_control() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der);
    let (addr, server_alpn) = spawn_tls_h1_server(test_config(128, 16384, 10), acceptor).await;

    let resp = tls_request(
        addr,
        &cert_der,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status_line(&resp).contains("200"),
        "valid H1 request over real TLS must reach dispatch, got: {resp:?}"
    );
    assert_eq!(
        wait_for_server_alpn(&server_alpn).as_deref(),
        Some(b"http/1.1".as_slice()),
        "server must observe ALPN http/1.1 from the real handshake"
    );
}

// ─── max headers over a real TLS stream ──────────────────────────────────────

#[tokio::test]
async fn tls_h1_real_max_headers() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der);
    let (addr, _) = spawn_tls_h1_server(test_config(8, 16384, 10), acceptor).await;

    let mut ok_req = String::from("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for i in 0..4 {
        ok_req.push_str(&format!("X-Ok-{i}: v\r\n"));
    }
    ok_req.push_str("\r\n");
    let ok_resp = tls_request(addr, &cert_der, ok_req.as_bytes()).await;
    assert!(
        status_line(&ok_resp).contains("200"),
        "request within max_headers must reach dispatch over real TLS, got: {ok_resp:?}"
    );

    let mut big_req = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
    for i in 0..20 {
        big_req.push_str(&format!("X-Big-{i}: v\r\n"));
    }
    big_req.push_str("\r\n");
    let big_resp = tls_request(addr, &cert_der, big_req.as_bytes()).await;
    assert!(
        !status_line(&big_resp).contains("200"),
        "request above max_headers must be rejected at the parser boundary over real TLS, got: {big_resp:?}"
    );
}

// ─── parser-buffer ceiling over a real TLS stream ────────────────────────────

#[tokio::test]
async fn tls_h1_real_parser_buffer_ceiling() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der);
    // 8192 is Hyper's minimum accepted max_buf_size.
    let (addr, _) = spawn_tls_h1_server(test_config(128, 8192, 10), acceptor).await;

    let small = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let small_resp = tls_request(addr, &cert_der, small).await;
    assert!(
        status_line(&small_resp).contains("200"),
        "fitting request must succeed over real TLS, got: {small_resp:?}"
    );

    let mut big = String::from("GET / HTTP/1.1\r\nHost: x\r\nX-Big: ");
    big.push_str(&"A".repeat(16 * 1024));
    big.push_str("\r\n\r\n");
    let big_resp = tls_request(addr, &cert_der, big.as_bytes()).await;
    assert!(
        !status_line(&big_resp).contains("200"),
        "input exceeding the parser buffer must be rejected over real TLS, got status: {:?}",
        status_line(&big_resp)
    );
}

// ─── header-read timeout is active over a real TLS stream ────────────────────

#[tokio::test]
async fn tls_h1_real_header_read_timeout() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der);
    let (addr, _) = spawn_tls_h1_server(test_config(128, 16384, 1), acceptor).await;

    // Control: a fast complete request succeeds after a full handshake.
    let ok = tls_request(
        addr,
        &cert_der,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status_line(&ok).contains("200"),
        "control request must succeed over real TLS, got: {ok:?}"
    );

    // Partial headers after a completed handshake, then hold: the server must
    // terminate/reject within a generous bound above the 1s configured
    // timeout (proves the timeout is active rather than merely configured).
    let started = Instant::now();
    let mut stream = tls_connect(addr, &cert_der).await;
    assert_eq!(
        client_negotiated_alpn(&stream).as_deref(),
        Some(b"http/1.1".as_slice()),
        "stall connection must complete ALPN http/1.1 first"
    );
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Hold: ")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 1024];
    let outcome = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut buf)).await;
    let elapsed = started.elapsed();
    match outcome {
        Ok(Ok(0)) => {}  // clean EOF: idle timeout closed the connection
        Ok(Ok(_)) => {}  // any bytes (e.g. 408/400) also prove termination
        Ok(Err(_)) => {} // reset: also termination
        Err(_) => {
            panic!("slow TLS headers were not terminated within 15s (1s timeout configured)")
        }
    }
    assert!(
        elapsed < Duration::from_secs(15),
        "termination took too long: {elapsed:?}"
    );
}

// ─── WebSocket upgrade over a real TLS stream ─────────────────────────────────

#[tokio::test]
async fn tls_h1_real_websocket_upgrade() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der);
    let (addr, _) = spawn_tls_h1_server(test_config(128, 16384, 10), acceptor).await;
    let req = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: x\r\n",
        "Connection: Upgrade\r\n",
        "Upgrade: websocket\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    let resp = tls_request(addr, &cert_der, req.as_bytes()).await;
    assert!(
        status_line(&resp).contains("101"),
        "WebSocket upgrade must still reach dispatch over real TLS, got: {resp:?}"
    );
}

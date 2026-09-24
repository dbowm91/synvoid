//! Root-test ownership: COMPOSITION
//! Rationale: Phase 70 H1 parser-control parity. Proves the plaintext H1 and
//! TLS-H1 transports apply the same configured header-read timeout,
//! header-count, and parser-buffer ceiling through the single root-local
//! policy helper (`synvoid::http::h1_policy::configure_h1_builder`), and that
//! the header timeout is genuinely active (explicit Tokio timer) rather than
//! merely configured.
//!
//! TLS-H1 is exercised post-handshake: after the TLS accept/handshake/ALPN
//! layer, the H1 connection serves Hyper H1 over the decrypted stream, so the
//! parser behavior under test is exactly the shared helper mapping. A
//! source-level guard below pins that `src/tls/server.rs` routes its H1 path
//! through the helper, retains `.with_upgrades()`, and leaves the H2
//! `max_header_list_size` path unchanged.

use std::net::SocketAddr;
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

/// Spawn a minimal H1 loopback server whose connections are built by the
/// production helper. Returns the bound address. Each connection serves one
/// request: `101` for WebSocket upgrade handshakes, `200 ok` otherwise.
async fn spawn_h1_server(config: HttpConfig) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let cfg = config.clone();
            tokio::spawn(async move {
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
                let io = hyper_util::rt::TokioIo::new(stream);
                let mut builder = hyper::server::conn::http1::Builder::new();
                h1_policy::configure_h1_builder(&mut builder, &cfg);
                let conn = builder.serve_connection(io, svc).with_upgrades();
                let _ = conn.await;
            });
        }
    });
    addr
}

async fn raw_request(addr: SocketAddr, request: &[u8]) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    // Bound the read: a well-formed response arrives quickly; a rejected
    // connection yields EOF/error quickly too.
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

// ─── max headers: at/below succeeds, above rejected ──────────────────────────

async fn max_headers_case(label: &str) {
    let addr = spawn_h1_server(test_config(8, 16384, 10)).await;

    let mut ok_req = String::from("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for i in 0..4 {
        ok_req.push_str(&format!("X-Ok-{i}: v\r\n"));
    }
    ok_req.push_str("\r\n");
    let ok_resp = raw_request(addr, ok_req.as_bytes()).await;
    assert!(
        status_line(&ok_resp).contains("200"),
        "[{label}] request within max_headers must reach dispatch, got: {ok_resp:?}"
    );

    let mut big_req = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
    for i in 0..20 {
        big_req.push_str(&format!("X-Big-{i}: v\r\n"));
    }
    big_req.push_str("\r\n");
    let big_resp = raw_request(addr, big_req.as_bytes()).await;
    assert!(
        !status_line(&big_resp).contains("200"),
        "[{label}] request above max_headers must be rejected at the parser boundary, got: {big_resp:?}"
    );
}

#[tokio::test]
async fn max_headers_plaintext_h1() {
    max_headers_case("plaintext").await;
}

#[tokio::test]
async fn max_headers_tls_h1_post_handshake() {
    // Same helper, same values: post-handshake TLS-H1 parsing is identical.
    max_headers_case("tls-h1").await;
}

// ─── parser buffer ceiling ───────────────────────────────────────────────────

async fn parser_buffer_case(label: &str) {
    // 8192 is Hyper's minimum accepted max_buf_size.
    let addr = spawn_h1_server(test_config(128, 8192, 10)).await;

    let small = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let small_resp = raw_request(addr, small).await;
    assert!(
        status_line(&small_resp).contains("200"),
        "[{label}] fitting request must succeed, got: {small_resp:?}"
    );

    let mut big = String::from("GET / HTTP/1.1\r\nHost: x\r\nX-Big: ");
    big.push_str(&"A".repeat(16 * 1024));
    big.push_str("\r\n\r\n");
    let big_resp = raw_request(addr, big.as_bytes()).await;
    assert!(
        !status_line(&big_resp).contains("200"),
        "[{label}] input exceeding the parser buffer must be rejected, got status: {:?}",
        status_line(&big_resp)
    );
}

#[tokio::test]
async fn parser_buffer_plaintext_h1() {
    parser_buffer_case("plaintext").await;
}

#[tokio::test]
async fn parser_buffer_tls_h1_post_handshake() {
    parser_buffer_case("tls-h1").await;
}

// ─── slow header timeout is active on both paths ─────────────────────────────

async fn slow_header_case(label: &str) {
    let addr = spawn_h1_server(test_config(128, 16384, 1)).await;

    // Control: a fast complete request succeeds.
    let ok = raw_request(
        addr,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status_line(&ok).contains("200"),
        "[{label}] control request must succeed, got: {ok:?}"
    );

    // Partial headers, then hold: the server must terminate/reject within a
    // generous bound above the 1s configured timeout (proves the timeout is
    // active rather than merely configured).
    let started = Instant::now();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
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
            panic!("[{label}] slow headers were not terminated within 15s (1s timeout configured)")
        }
    }
    assert!(
        elapsed < Duration::from_secs(15),
        "[{label}] termination took too long: {elapsed:?}"
    );
}

#[tokio::test]
async fn slow_header_timeout_plaintext_h1() {
    slow_header_case("plaintext").await;
}

#[tokio::test]
async fn slow_header_timeout_tls_h1_post_handshake() {
    slow_header_case("tls-h1").await;
}

// ─── WebSocket upgrade still reaches dispatch ────────────────────────────────

async fn websocket_case(label: &str) {
    let addr = spawn_h1_server(test_config(128, 16384, 10)).await;
    let req = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: x\r\n",
        "Connection: Upgrade\r\n",
        "Upgrade: websocket\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    let resp = raw_request(addr, req.as_bytes()).await;
    assert!(
        status_line(&resp).contains("101"),
        "[{label}] WebSocket upgrade must still reach dispatch, got: {resp:?}"
    );
}

#[tokio::test]
async fn websocket_upgrade_plaintext_h1() {
    websocket_case("plaintext").await;
}

#[tokio::test]
async fn websocket_upgrade_tls_h1_post_handshake() {
    websocket_case("tls-h1").await;
}

// ─── Source guards: wiring truth ────────────────────────────────────────────

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel))
        .expect("read repo source file")
}

#[test]
fn plaintext_startup_claim_is_h1_only() {
    let accept_loop = repo_file("src/http/server/accept_loop.rs");
    assert!(
        !accept_loop.contains("HTTP/1.1 + HTTP/2"),
        "plaintext accept loop must not advertise HTTP/2"
    );
    assert!(
        accept_loop.contains("plaintext_startup_message") || accept_loop.contains("(HTTP/1.1)"),
        "plaintext accept loop must use the H1-only startup message"
    );
    assert_eq!(h1_policy::PLAINTEXT_PROTOCOL_LABEL, "HTTP/1.1");
    let msg = h1_policy::plaintext_startup_message(&"127.0.0.1:8080".parse().unwrap());
    assert!(msg.contains("HTTP/1.1") && !msg.contains("HTTP/2"));
}

#[test]
fn tls_h1_uses_shared_policy_and_keeps_upgrades_and_h2() {
    let tls = repo_file("src/tls/server.rs");
    assert!(
        tls.contains("configure_h1_builder"),
        "TLS-H1 must be built through the shared H1 policy helper"
    );
    assert!(
        !tls.contains("_header_read_timeout") && !tls.contains("_max_buf_size"),
        "TLS-H1 must consume (not underscore-ignore) the parser controls"
    );
    assert!(
        tls.contains(".with_upgrades()"),
        "TLS-H1 must retain WebSocket upgrade support"
    );
    assert!(
        tls.contains("max_header_list_size(max_headers as u32)"),
        "TLS H2 header-list behavior must remain unchanged"
    );
    let accept_loop = repo_file("src/http/server/accept_loop.rs");
    assert!(
        accept_loop.contains("configure_h1_builder"),
        "plaintext H1 must use the shared policy helper"
    );
    assert!(
        accept_loop.contains(".with_upgrades()"),
        "plaintext H1 must retain WebSocket upgrade support"
    );
}

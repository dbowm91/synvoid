//! Black-box egress parity suite (Phase 34 Part G).
//!
//! Covers the required behaviors of the generic transport core without
//! touching SynVoid policy layers: HTTP/1.1 keepalive + reuse, HTTP/2,
//! TLS trust roots + invalid-certificate failure, timeouts, body size
//! limits, streaming bodies, custom headers/auth helpers, Unix-socket HTTP,
//! post-quantum feature compile behavior, closed-upstream errors, pool
//! saturation/eviction, and error mapping.
//!
//! All fixtures are hermetic (loopback TCP / Unix sockets in a tempdir).
//! No external network access.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use synvoid_http_client::{
    create_http_client_with_config, create_simple_http_client, create_unix_http_client,
    create_upstream_client, get_with_auth, get_with_timeout, head_with_auth,
    send_request_streaming, send_request_with_body_and_timeout_with_limit,
    send_request_with_timeout_and_headers, ErasedConnectionPool, HttpResponse, PoolKey,
    UpstreamTlsConfig,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct H1Fixture {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
}

async fn spawn_h1(
    handler: impl Fn(Request<Incoming>) -> Response<Full<Bytes>> + Send + Sync + 'static,
) -> H1Fixture {
    let handler = Arc::new(handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let accepts = Arc::new(AtomicUsize::new(0));
    let (req_clone, acc_clone) = (requests.clone(), accepts.clone());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            acc_clone.fetch_add(1, Ordering::SeqCst);
            let handler = handler.clone();
            let req_clone = req_clone.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    req_clone.fetch_add(1, Ordering::SeqCst);
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req)) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    H1Fixture {
        addr,
        requests,
        accepts,
    }
}

fn ok_response(body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

// ---------------------------------------------------------------------------
// HTTP/1.1 keepalive and connection reuse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h1_keepalive_reuses_single_connection() {
    let fx = spawn_h1(|_| ok_response("hello")).await;
    let url = format!("http://{}/", fx.addr);
    let client =
        create_http_client_with_config(Duration::from_secs(5), 10, Duration::from_secs(30));

    for _ in 0..2 {
        let resp = get_with_timeout(&client, &url, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(resp.status_code(), 200);
        assert_eq!(resp.body.as_ref(), b"hello");
    }
    assert_eq!(fx.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        fx.accepts.load(Ordering::SeqCst),
        1,
        "keepalive must reuse one TCP connection"
    );
}

// ---------------------------------------------------------------------------
// HTTP/2 + custom CA + invalid-certificate failure (local TLS, rcgen)
// ---------------------------------------------------------------------------

fn rcgen_self_signed() -> (String, Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = certified.cert.pem();
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();
    (cert_pem, cert_der, key_der)
}

async fn spawn_tls_h2() -> (
    SocketAddr,
    tempfile::NamedTempFile,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let (cert_pem, cert_der, key_der) = rcgen_self_signed();
    let ca_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(ca_file.path(), cert_pem.as_bytes()).unwrap();

    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key_der,
        )),
    )
    .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let versions = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let versions_clone = versions.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let versions_clone = versions_clone.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    versions_clone.store(req.version() == http::Version::HTTP_2, Ordering::SeqCst);
                    async move { Ok::<_, Infallible>(ok_response("h2-ok")) }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (addr, ca_file, versions)
}

fn custom_ca_tls_config(ca_file: &tempfile::NamedTempFile) -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        verify: true,
        ca_cert_path: Some(ca_file.path().to_string_lossy().into_owned()),
        server_name: None,
        skip_verify: false,
        skip_verify_reason: None,
        allow_plaintext: false,
    }
}

#[tokio::test]
async fn h2_request_with_custom_ca_succeeds() {
    let (addr, ca_file, versions) = spawn_tls_h2().await;
    let tls = custom_ca_tls_config(&ca_file);
    let client = create_upstream_client(Duration::from_secs(5), 10, Duration::from_secs(30), &tls);
    let url = format!("https://localhost:{}/", addr.port());
    let resp = get_with_timeout(&client, &url, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.body.as_ref(), b"h2-ok");
    assert!(
        versions.load(Ordering::SeqCst),
        "upstream must negotiate HTTP/2"
    );
}

#[tokio::test]
async fn invalid_certificate_fails_closed() {
    let (addr, _ca_file, _versions) = spawn_tls_h2().await;
    // Default client trusts only native/WebPKI roots: the rcgen self-signed
    // chain must fail instead of being silently accepted.
    let client = create_simple_http_client(Duration::from_secs(10));
    let url = format!("https://localhost:{}/", addr.port());
    let err = get_with_timeout(&client, &url, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert!(
        !err.is_empty(),
        "TLS verification failure must surface an error"
    );
}

// ---------------------------------------------------------------------------
// Timeout expiration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn configured_timeout_expires() {
    let fx = spawn_h1(|_| ok_response("slow")).await;
    // Slow handler variant: sleep before responding.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    Ok::<_, Infallible>(ok_response("slow"))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    let _ = fx;
    let client = create_simple_http_client(Duration::from_secs(5));
    let url = format!("http://{addr}/");
    let err = get_with_timeout(&client, &url, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(
        err.contains("timed out"),
        "expected timeout error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Body size limits + streaming behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn response_size_limit_truncates_to_empty() {
    let big = spawn_h1(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(vec![b'x'; 64 * 1024])))
            .unwrap()
    })
    .await;
    let url = format!("http://{}/", big.addr);
    let client = create_simple_http_client(Duration::from_secs(5));
    let resp = send_request_with_body_and_timeout_with_limit(
        &client,
        Method::GET,
        &url,
        None,
        Some(Duration::from_secs(5)),
        Some(1024),
    )
    .await
    .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert!(
        resp.body.is_empty(),
        "oversized body must be limited, got {} bytes",
        resp.body.len()
    );
}

#[tokio::test]
async fn streaming_body_roundtrips_without_buffering_assumption() {
    let fx = spawn_h1(|_| ok_response("stream-me")).await;
    let url = format!("http://{}/", fx.addr);
    let client = create_simple_http_client(Duration::from_secs(5));
    let raw = send_request_streaming(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(raw.status(), StatusCode::OK);
    let body = raw.collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"stream-me");
}

// ---------------------------------------------------------------------------
// Custom headers + Basic-auth helpers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn custom_headers_and_basic_auth_reach_upstream() {
    let fx = spawn_h1(|req: Request<Incoming>| {
        let probe = req
            .headers()
            .get("x-parity-probe")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let authed = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            == "Basic dXNlcjpwYXNz";
        let mut resp = ok_response(if authed { "authed" } else { "noauth" });
        resp.headers_mut().insert(
            "x-probe-echo",
            probe.parse().unwrap_or_else(|_| "".parse().unwrap()),
        );
        resp
    })
    .await;
    let url = format!("http://{}/", fx.addr);
    let client = create_simple_http_client(Duration::from_secs(5));

    let mut headers = http::HeaderMap::new();
    headers.insert("x-parity-probe", "probe-1".parse().unwrap());
    let resp = send_request_with_timeout_and_headers(
        &client,
        Method::GET,
        &url,
        headers,
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(resp.header("x-probe-echo"), Some("probe-1"));

    let authed = get_with_auth(&client, &url, "user", "pass", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(authed.body.as_ref(), b"authed");

    let head = head_with_auth(&client, &url, "user", "pass", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(head.status_code(), 200);
}

// ---------------------------------------------------------------------------
// Unix-socket HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unix_socket_request_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("parity.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(ok_response("unix-ok"))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let client = create_unix_http_client();
    let resp = synvoid_http_client::send_unix_request_with_body(
        &client,
        &sock.to_string_lossy(),
        "/health",
        Method::GET,
        None,
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.body.as_ref(), b"unix-ok");
    assert!(synvoid_http_client::is_unix_socket_url(&sock.to_string_lossy()).is_some());
}

// ---------------------------------------------------------------------------
// Post-quantum feature compile behavior
// ---------------------------------------------------------------------------

#[cfg(feature = "post-quantum")]
#[tokio::test]
async fn post_quantum_feature_client_serves_plain_h1() {
    let fx = spawn_h1(|_| ok_response("pq")).await;
    let url = format!("http://{}/", fx.addr);
    let client = create_simple_http_client(Duration::from_secs(5));
    let resp = get_with_timeout(&client, &url, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(resp.body.as_ref(), b"pq");
}

// ---------------------------------------------------------------------------
// Cancellation / closed upstream + error mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn closed_upstream_maps_to_error_not_panic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let client = create_simple_http_client(Duration::from_secs(2));
    let url = format!("http://{addr}/");
    let err = get_with_timeout(&client, &url, Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(!err.is_empty());
}

#[tokio::test]
async fn invalid_url_maps_to_error() {
    let client = create_simple_http_client(Duration::from_secs(2));
    let err = get_with_timeout(&client, "http://[::1", Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(!err.is_empty());
}

// ---------------------------------------------------------------------------
// Pool saturation / eviction semantics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn erased_pool_evicts_beyond_max_idle() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    // Keep the listener alive: checkout only needs TCP + client handshake.
    let pool = ErasedConnectionPool::new(1);
    let key = PoolKey {
        authority: addr.to_string(),
        is_http2: false,
    };
    let c1 = pool.checkout(key.clone()).await.unwrap();
    let c2 = pool.checkout(key.clone()).await.unwrap();
    pool.checkin(key.clone(), c1).await;
    assert_eq!(pool.idle_count(&key).await, 1);
    // Pool is full: the extra connection is dropped, not retained.
    pool.checkin(key.clone(), c2).await;
    assert_eq!(pool.idle_count(&key).await, 1);
}

#[tokio::test]
async fn erased_pool_reuses_checked_in_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let pool = ErasedConnectionPool::new(10);
    let key = PoolKey {
        authority: addr.to_string(),
        is_http2: false,
    };
    let conn = pool.checkout(key.clone()).await.unwrap();
    assert!(conn.is_connected());
    pool.checkin(key.clone(), conn).await;
    assert_eq!(pool.idle_count(&key).await, 1);
    let reused = pool.checkout(key.clone()).await.unwrap();
    assert!(reused.is_connected());
    assert_eq!(pool.idle_count(&key).await, 0);
}

// ---------------------------------------------------------------------------
// HttpResponse helpers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_response_helpers_expose_status_and_headers() {
    let fx = spawn_h1(|_| {
        Response::builder()
            .status(StatusCode::CREATED)
            .header("x-parity", "yes")
            .body(Full::new(Bytes::from_static(b"created")))
            .unwrap()
    })
    .await;
    let url = format!("http://{}/", fx.addr);
    let client = create_simple_http_client(Duration::from_secs(5));
    let resp: HttpResponse = get_with_timeout(&client, &url, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 201);
    assert_eq!(resp.header("x-parity"), Some("yes"));
    assert_ne!(resp.headers_iter().count(), 0);
}

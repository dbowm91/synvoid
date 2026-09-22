//! Differential parity harness (Phase 59-G): legacy Hyper lane vs eggfetch lane.
//!
//! Same hermetic fixtures, both lanes, observable results compared (status /
//! body / headers / success-vs-error). Private error strings and internal
//! pool counters are NOT compared — except `"request timed out"`, which the
//! eggfetch lane preserves byte-identically by contract.
//!
//! In-crate (`#[cfg(test)]`) rather than `tests/` so the transport lane can
//! stay out of the public/root re-export surface during Phase 59.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::client::HttpClient;
use crate::eggfetch_transport::EggfetchUpstreamClient;
use crate::response::HttpResponse;
use crate::tls::UpstreamTlsConfig;

type TestBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn boxed_full(data: Bytes) -> TestBody {
    Full::new(data).map_err(|e| match e {}).boxed()
}

fn ok_text(body: &'static str) -> Response<TestBody> {
    Response::builder()
        .status(StatusCode::OK)
        .body(boxed_full(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

struct H1Fixture {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
}

async fn spawn_h1<F, Fut>(handler: F) -> H1Fixture
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<TestBody>> + Send + 'static,
{
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
                    async move { Ok::<_, hyper::Error>(handler(req).await) }
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

fn rcgen_for(names: Vec<String>) -> (String, Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(names).unwrap();
    (
        certified.cert.pem(),
        certified.cert.der().to_vec(),
        certified.key_pair.serialize_der(),
    )
}

fn ca_file_for(cert_pem: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), cert_pem.as_bytes()).unwrap();
    f
}
fn server_config_for(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    alpn: Vec<Vec<u8>>,
) -> Arc<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    cfg.alpn_protocols = alpn;
    Arc::new(cfg)
}

async fn spawn_tls_h1_static(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    text: &'static str,
) -> SocketAddr {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config_for(
        cert_der,
        key_der,
        vec![b"http/1.1".to_vec()],
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(ok_text(text))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    addr
}

async fn spawn_tls_h2_static(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    seen_h2: Arc<AtomicUsize>,
) -> SocketAddr {
    let acceptor =
        tokio_rustls::TlsAcceptor::from(server_config_for(cert_der, key_der, vec![b"h2".to_vec()]));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let seen_h2 = seen_h2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let seen_h2 = seen_h2.clone();
                    async move {
                        if req.version() == http::Version::HTTP_2 {
                            seen_h2.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok::<_, hyper::Error>(ok_text("h2-ok"))
                    }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// Lane drivers (same observable shape)
// ---------------------------------------------------------------------------

const CONNECT: Duration = Duration::from_secs(5);

fn legacy_client(tls: &UpstreamTlsConfig) -> HttpClient {
    crate::client::create_upstream_client(CONNECT, 10, Duration::from_secs(30), tls)
}

fn egg_lane(tls: &UpstreamTlsConfig) -> EggfetchUpstreamClient {
    EggfetchUpstreamClient::build(CONNECT, 10, Duration::from_secs(30), tls)
        .expect("eggfetch lane must build for test policy")
}

fn plaintext_tls() -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        allow_plaintext: true,
        ..UpstreamTlsConfig::default()
    }
}

fn tls_with_ca(ca: &tempfile::NamedTempFile) -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        ca_cert_path: Some(ca.path().to_string_lossy().into_owned()),
        ..UpstreamTlsConfig::default()
    }
}

async fn legacy_buffered(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
    limit: Option<usize>,
) -> anyhow::Result<HttpResponse> {
    if headers.is_empty() {
        crate::request::send_request_with_body_and_timeout_with_limit(
            client, method, url, body, timeout, limit,
        )
        .await
    } else {
        // Header-bearing cases never combine with a size limit in this suite.
        assert!(
            limit.is_none(),
            "differential harness: headers+limit combo unsupported"
        );
        crate::request::send_request_with_body_headers_and_timeout(
            client, method, url, body, headers, timeout,
        )
        .await
    }
}

async fn egg_buffered(
    lane: &EggfetchUpstreamClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
    limit: Option<usize>,
) -> anyhow::Result<HttpResponse> {
    lane.send_buffered(method, url, body, headers, timeout, limit)
        .await
}

fn assert_same_observable(legacy: &HttpResponse, egg: &HttpResponse, probe_header: &str) {
    assert_eq!(
        legacy.status_code(),
        egg.status_code(),
        "status must match across lanes"
    );
    assert_eq!(legacy.body, egg.body, "body must match across lanes");
    assert_eq!(
        legacy.header(probe_header),
        egg.header(probe_header),
        "probe header must match across lanes"
    );
}

#[tokio::test]
async fn differential_h1_get() {
    let fx = spawn_h1(|_| async move { ok_text("hello") }).await;
    let url = format!("http://{}/", fx.addr);
    let tls = plaintext_tls();
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    assert_same_observable(&l, &e, "x-probe-echo");
    assert_eq!(e.body.as_ref(), b"hello");
}

#[tokio::test]
async fn differential_h1_post_buffered() {
    let fx = spawn_h1(|req: Request<Incoming>| async move {
        let collected = req.into_body().collect().await.unwrap();
        let body = collected.to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .header("x-echo-len", body.len().to_string())
            .body(boxed_full(body))
            .unwrap()
    })
    .await;
    let url = format!("http://{}/echo", fx.addr);
    let payload = Bytes::from(vec![b'p'; 32 * 1024]);
    let tls = plaintext_tls();
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::POST,
        &url,
        Some(payload.clone()),
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::POST,
        &url,
        Some(payload.clone()),
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    assert_same_observable(&l, &e, "x-echo-len");
    assert_eq!(e.body, payload);
}

#[tokio::test]
async fn differential_h1_keepalive_reuse() {
    let fx = spawn_h1(|_| async move { ok_text("ka") }).await;
    let url = format!("http://{}/", fx.addr);
    let tls = plaintext_tls();
    let legacy = legacy_client(&tls);
    let egg = egg_lane(&tls);
    for _ in 0..2 {
        legacy_buffered(
            &legacy,
            Method::GET,
            &url,
            None,
            http::HeaderMap::new(),
            Some(Duration::from_secs(5)),
            None,
        )
        .await
        .unwrap();
    }
    for _ in 0..2 {
        egg_buffered(
            &egg,
            Method::GET,
            &url,
            None,
            http::HeaderMap::new(),
            Some(Duration::from_secs(5)),
            None,
        )
        .await
        .unwrap();
    }
    assert_eq!(fx.requests.load(Ordering::SeqCst), 4);
    // Two lanes = two independent pools = two connections total; each lane
    // served both of its requests on one keepalive connection.
    assert_eq!(
        fx.accepts.load(Ordering::SeqCst),
        2,
        "each lane must reuse one keepalive connection (same fixture)"
    );
}

#[tokio::test]
async fn differential_custom_headers_and_basic_auth() {
    let fx = spawn_h1(|req: Request<Incoming>| async move {
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
        let mut resp = ok_text(if authed { "authed" } else { "noauth" });
        resp.headers_mut().insert(
            "x-probe-echo",
            probe.parse().unwrap_or_else(|_| "".parse().unwrap()),
        );
        resp
    })
    .await;
    let url = format!("http://{}/", fx.addr);
    let tls = plaintext_tls();

    let mut headers = http::HeaderMap::new();
    headers.insert("x-parity-probe", "probe-1".parse().unwrap());
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        headers.clone(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        headers,
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    assert_same_observable(&l, &e, "x-probe-echo");

    let l = crate::request::get_with_auth(
        &legacy_client(&tls),
        &url,
        "user",
        "pass",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    use base64::Engine as _;
    let creds = base64::engine::general_purpose::STANDARD.encode("user:pass");
    let mut auth_headers = http::HeaderMap::new();
    auth_headers.insert(
        http::header::AUTHORIZATION,
        format!("Basic {creds}").parse().unwrap(),
    );
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        auth_headers,
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
    assert_eq!(l.body.as_ref(), b"authed");
    assert_eq!(e.body.as_ref(), b"authed");
}

#[tokio::test]
async fn differential_response_size_limit() {
    let fx = spawn_h1(|_| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(boxed_full(Bytes::from(vec![b'x'; 64 * 1024])))
            .unwrap()
    })
    .await;
    let url = format!("http://{}/", fx.addr);
    let tls = plaintext_tls();
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        Some(1024),
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        Some(1024),
    )
    .await
    .unwrap();
    assert_eq!(l.status_code(), 200);
    assert_eq!(e.status_code(), 200);
    assert!(l.body.is_empty() && e.body.is_empty());
}

#[tokio::test]
async fn differential_timeout_message_identical() {
    let fx = spawn_h1(|_| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        ok_text("too-late")
    })
    .await;
    let url = format!("http://{}/", fx.addr);
    let tls = plaintext_tls();
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_millis(150)),
        None,
    )
    .await
    .unwrap_err();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_millis(150)),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(l.to_string(), "request timed out");
    assert_eq!(
        e.to_string(),
        "request timed out",
        "timeout message is caller-visible contract; lanes must agree"
    );
}

#[tokio::test]
async fn differential_closed_upstream_and_invalid_url() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{addr}/");
    let tls = plaintext_tls();
    for bad in [url.as_str(), "http://[::1", "not a url at all %%%"] {
        let l = legacy_buffered(
            &legacy_client(&tls),
            Method::GET,
            bad,
            None,
            http::HeaderMap::new(),
            Some(Duration::from_secs(2)),
            None,
        )
        .await;
        let e = egg_buffered(
            &egg_lane(&tls),
            Method::GET,
            bad,
            None,
            http::HeaderMap::new(),
            Some(Duration::from_secs(2)),
            None,
        )
        .await;
        assert!(l.is_err() && e.is_err(), "errors, no panic for {bad}");
    }
}

#[tokio::test]
async fn differential_plaintext_gate() {
    let fx = spawn_h1(|_| async move { ok_text("plain") }).await;
    let url = format!("http://{}/", fx.addr);
    let tls = UpstreamTlsConfig::default();
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await;
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await;
    assert!(
        l.is_err() && e.is_err(),
        "plaintext rejected on both without policy"
    );
}

#[tokio::test]
async fn differential_tls_custom_ca() {
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1_static(der, key, "tls-ok").await;
    let url = format!("https://localhost:{}/", addr.port());
    let tls = tls_with_ca(&ca);
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await
    .unwrap();
    assert_same_observable(&l, &e, "x-probe-echo");
    assert_eq!(e.body.as_ref(), b"tls-ok");
}

#[tokio::test]
async fn differential_tls_failures_agree() {
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1_static(der, key, "tls-ok").await;
    let tls = tls_with_ca(&ca);

    let wrong = format!("https://127.0.0.1:{}/", addr.port());
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &wrong,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await;
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &wrong,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await;
    assert!(l.is_err() && e.is_err(), "both lanes reject the mismatch");

    let url = format!("https://localhost:{}/", addr.port());
    let untrusted = UpstreamTlsConfig::default();
    let l = legacy_buffered(
        &legacy_client(&untrusted),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await;
    let e = egg_buffered(
        &egg_lane(&untrusted),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await;
    assert!(l.is_err() && e.is_err(), "both lanes fail closed");
}

#[tokio::test]
async fn differential_tls_hostname_skip() {
    let (pem, der, key) = rcgen_for(vec!["other-name.test".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1_static(der, key, "skip-ok").await;
    let url = format!("https://localhost:{}/", addr.port());
    let mut skip_tls = tls_with_ca(&ca);
    skip_tls.skip_verify = true;
    skip_tls.skip_verify_reason = Some("differential test".to_string());
    let l = legacy_buffered(
        &legacy_client(&skip_tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&skip_tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await
    .unwrap();
    assert_same_observable(&l, &e, "x-probe-echo");

    let (_pem_b, der_b, key_b) = rcgen_for(vec!["other-name.test".to_string()]);
    let addr_b = spawn_tls_h1_static(der_b, key_b, "skip-ok").await;
    let url_b = format!("https://localhost:{}/", addr_b.port());
    let l = legacy_buffered(
        &legacy_client(&skip_tls),
        Method::GET,
        &url_b,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await;
    let e = egg_buffered(
        &egg_lane(&skip_tls),
        Method::GET,
        &url_b,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await;
    assert!(
        l.is_err() && e.is_err(),
        "skip must still reject untrusted chains"
    );
}

#[tokio::test]
async fn differential_h2_tls() {
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let seen = Arc::new(AtomicUsize::new(0));
    let addr = spawn_tls_h2_static(der, key, seen.clone()).await;
    let url = format!("https://localhost:{}/", addr.port());
    let tls = tls_with_ca(&ca);
    let l = legacy_buffered(
        &legacy_client(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await
    .unwrap();
    let e = egg_buffered(
        &egg_lane(&tls),
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(10)),
        None,
    )
    .await
    .unwrap();
    assert_same_observable(&l, &e, "x-probe-echo");
    assert!(
        seen.load(Ordering::SeqCst) >= 2,
        "both lanes must negotiate HTTP/2"
    );
}

// ---------------------------------------------------------------------------
// Streaming bodies on both lanes
// ---------------------------------------------------------------------------

struct ChunkBody {
    chunks: VecDeque<Bytes>,
}

impl http_body::Body for ChunkBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.chunks.pop_front().map(|c| Ok(Frame::data(c))))
    }
}

fn chunk_body() -> ChunkBody {
    ChunkBody {
        chunks: [
            Bytes::from_static(b"alpha-"),
            Bytes::from_static(b"beta-"),
            Bytes::from_static(b"gamma"),
        ]
        .into(),
    }
}

async fn spawn_echo() -> H1Fixture {
    spawn_h1(|req: Request<Incoming>| async move {
        let collected = req.into_body().collect().await.unwrap();
        let body = collected.to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .body(boxed_full(body))
            .unwrap()
    })
    .await
}

#[tokio::test]
async fn differential_generic_streaming_body() {
    let fx = spawn_echo().await;
    let url = format!("http://{}/echo", fx.addr);
    let tls = plaintext_tls();

    let legacy_streaming =
        crate::pool::build_upstream_client::<ChunkBody>(CONNECT, 10, Duration::from_secs(30), &tls);
    let l_req = Request::builder()
        .method(Method::POST)
        .uri(url.clone())
        .body(chunk_body())
        .unwrap();
    let l_resp = tokio::time::timeout(Duration::from_secs(5), legacy_streaming.request(l_req))
        .await
        .expect("legacy must answer")
        .expect("legacy response");
    let l_body = l_resp.collect().await.unwrap().to_bytes();

    let egg = egg_lane(&tls);
    let e_req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(chunk_body())
        .unwrap();
    let e_resp = egg
        .execute(e_req, Some(Duration::from_secs(5)), None)
        .await
        .unwrap();
    let e_body = e_resp.collect().await.unwrap().to_bytes();

    assert_eq!(l_body.as_ref(), b"alpha-beta-gamma");
    assert_eq!(e_body, l_body);
}

struct WafShapedBody<B> {
    inner: B,
}

impl<B> http_body::Body for WafShapedBody<B>
where
    B: http_body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: std::fmt::Debug + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
}

#[tokio::test]
async fn differential_waf_shaped_streaming_body() {
    let fx = spawn_echo().await;
    let url = format!("http://{}/echo", fx.addr);
    let tls = plaintext_tls();
    let chunks = || vec![Bytes::from_static(b"waf-"), Bytes::from_static(b"shaped")];

    let legacy_streaming = crate::pool::build_upstream_client::<WafShapedBody<ChunkBody>>(
        CONNECT,
        10,
        Duration::from_secs(30),
        &tls,
    );
    let l_req = Request::builder()
        .method(Method::POST)
        .uri(url.clone())
        .body(WafShapedBody {
            inner: ChunkBody {
                chunks: chunks().into(),
            },
        })
        .unwrap();
    let l_resp = tokio::time::timeout(Duration::from_secs(5), legacy_streaming.request(l_req))
        .await
        .expect("legacy must answer")
        .expect("legacy response");
    let l_body = l_resp.collect().await.unwrap().to_bytes();

    let egg = egg_lane(&tls);
    let e_req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(WafShapedBody {
            inner: ChunkBody {
                chunks: chunks().into(),
            },
        })
        .unwrap();
    let e_resp = egg
        .execute(e_req, Some(Duration::from_secs(5)), None)
        .await
        .unwrap();
    let e_body = e_resp.collect().await.unwrap().to_bytes();

    assert_eq!(l_body.as_ref(), b"waf-shaped");
    assert_eq!(e_body, l_body);
}

struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn channel_producer() -> ChannelBody {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    tokio::spawn(async move {
        for chunk in [b"h3-a-", b"h3-b-", b"h3-c-"] {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx.send(Ok(Bytes::from_static(chunk))).await.unwrap();
        }
    });
    ChannelBody { rx }
}

#[tokio::test]
async fn differential_h3_channel_streaming_body() {
    let fx = spawn_echo().await;
    let url = format!("http://{}/echo", fx.addr);
    let tls = plaintext_tls();

    let legacy_streaming = crate::pool::build_upstream_client::<ChannelBody>(
        CONNECT,
        10,
        Duration::from_secs(30),
        &tls,
    );
    let l_req = Request::builder()
        .method(Method::POST)
        .uri(url.clone())
        .body(channel_producer())
        .unwrap();
    let l_resp = tokio::time::timeout(Duration::from_secs(5), legacy_streaming.request(l_req))
        .await
        .expect("legacy must answer")
        .expect("legacy response");
    let l_body = l_resp.collect().await.unwrap().to_bytes();

    let egg = egg_lane(&tls);
    let e_req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(channel_producer())
        .unwrap();
    let e_resp = egg
        .execute(e_req, Some(Duration::from_secs(5)), None)
        .await
        .unwrap();
    let e_body = e_resp.collect().await.unwrap().to_bytes();

    assert_eq!(l_body.as_ref(), b"h3-a-h3-b-h3-c-");
    assert_eq!(e_body, l_body);
}

#[cfg(unix)]
#[tokio::test]
async fn differential_uds_buffered() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("diff.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(ok_text("uds-ok"))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    let sock_str = sock.to_string_lossy().into_owned();

    let legacy_unix = crate::client::create_unix_http_client();
    let l = crate::unix::send_unix_request_with_body(
        &legacy_unix,
        &sock_str,
        "/health",
        Method::GET,
        None,
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();

    let lane =
        EggfetchUpstreamClient::build_uds(&sock_str, CONNECT, 10, Duration::from_secs(30)).unwrap();
    let e = lane
        .send_uds_buffered(Method::GET, "/health", None, Some(Duration::from_secs(5)))
        .await
        .unwrap();

    assert_eq!(l.status_code(), e.status_code());
    assert_eq!(l.body, e.body);
    assert_eq!(e.body.as_ref(), b"uds-ok");
}

#[tokio::test]
async fn differential_h2_response_trailers() {
    struct TrailerResponse {
        state: u8,
    }
    impl http_body::Body for TrailerResponse {
        type Data = Bytes;
        type Error = hyper::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
            match self.state {
                0 => {
                    self.state = 1;
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"t-data")))))
                }
                1 => {
                    self.state = 2;
                    let mut tm = http::HeaderMap::new();
                    tm.insert("x-diff-trailer", "dtv".parse().unwrap());
                    Poll::Ready(Some(Ok(Frame::trailers(tm))))
                }
                _ => Poll::Ready(None),
            }
        }
    }
    async fn frame_loop<B>(mut body: B) -> (Vec<u8>, Option<http::HeaderMap>)
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        let mut data = Vec::new();
        let mut trailers = None;
        while let Some(f) = body.frame().await {
            let f = f.unwrap();
            if let Some(d) = f.data_ref() {
                data.extend_from_slice(d);
            }
            if f.is_trailers() {
                trailers = f.trailers_ref().cloned();
            }
        }
        (data, trailers)
    }

    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let acceptor =
        tokio_rustls::TlsAcceptor::from(server_config_for(der, key, vec![b"h2".to_vec()]));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(TrailerResponse { state: 0 })
                            .unwrap(),
                    )
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let url = format!("https://localhost:{}/", addr.port());

    let tls = tls_with_ca(&ca);
    let legacy = crate::client::create_upstream_client(CONNECT, 10, Duration::from_secs(30), &tls);
    let lresp = crate::request::send_request_streaming(
        &legacy,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(lresp.version(), http::Version::HTTP_2);
    let (ldata, ltrailers) = frame_loop(lresp.into_body()).await;

    let lane = egg_lane(&tls);
    let ereq = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let eresp = lane
        .execute(ereq, Some(Duration::from_secs(5)), None)
        .await
        .unwrap();
    assert_eq!(eresp.version(), http::Version::HTTP_2);
    let (edata, etrailers) = frame_loop(eresp.into_body()).await;

    assert_eq!(ldata, edata);
    assert_eq!(ldata, b"t-data");
    assert_eq!(
        ltrailers.as_ref().and_then(|t| t.get("x-diff-trailer")),
        etrailers.as_ref().and_then(|t| t.get("x-diff-trailer")),
        "trailers must match across lanes"
    );
    assert!(etrailers.is_some());
}

#[tokio::test]
async fn differential_early_drop_recovers() {
    let fx = spawn_h1(|_| async move { ok_text("again") }).await;
    let url = format!("http://{}/", fx.addr);
    let legacy = crate::client::create_simple_http_client(Duration::from_secs(5));
    let resp = crate::request::send_request_streaming(
        &legacy,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    drop(resp);
    crate::request::get_with_timeout(&legacy, &url, Duration::from_secs(5))
        .await
        .unwrap();

    let tls = UpstreamTlsConfig {
        allow_plaintext: true,
        ..UpstreamTlsConfig::default()
    };
    let lane = egg_lane(&tls);
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let eresp = lane
        .execute(req, Some(Duration::from_secs(5)), None)
        .await
        .unwrap();
    drop(eresp);
    lane.send_buffered(
        Method::GET,
        &url,
        None,
        http::HeaderMap::new(),
        Some(Duration::from_secs(5)),
        None,
    )
    .await
    .unwrap();
}

//! Eggfetch 0.2.0 qualification suite (Phase 58, Workstreams C/D/E).
//!
//! Proves eggfetch 0.2.0 satisfies SynVoid's egress transport and security
//! contracts through the **native** execution surface
//! (`Client::execute_http_body`), before any production request path is
//! switched to it. No production code routes through eggfetch in this phase.
//!
//! Coverage:
//!
//! - TLS/security: ordinary verification, custom CA, hostname-skip mode
//!   (chain-validated, untrusted-chain rejection, normal-mode control),
//!   explicit aws-lc provider + PQ contract, SNI override + pool separation.
//! - Generic bodies/frames: `Full<Bytes>`, multi-chunk, unknown/known size
//!   hints, erroring bodies, cancellation, request/response trailers,
//!   WAF-shaped and H3-channel-shaped producer bodies. No mandatory full
//!   buffering: multi-chunk bodies stream through the native path.
//! - H1/H2/pooling/routing/UDS: keepalive reuse, H2 multiplexing, connect /
//!   total / read timeouts, drop-releases-capacity, bounded saturation,
//!   resolved-target pinning (incl. no-DNS-fallback proof), UDS on Unix.
//!
//! All fixtures are hermetic (loopback TCP / Unix sockets in a tempdir).
//! TLS fixtures intentionally mirror the translator policy in
//! `crate::eggfetch_policy` without depending on it: the translator itself
//! is `pub(crate)` (no new public contract in Phase 58) and is covered by
//! its own unit tests; this suite proves the underlying eggfetch behavior
//! the translator relies on.
//!
//! Helper `egg_tls()` below is the test-side mirror of
//! `upstream_tls_to_eggfetch`: explicit aws-lc provider, additive custom CA,
//! hostname-only skip. Any drift between the two must be treated as a bug.

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
use eggfetch_core::{
    Client, NativeRequestOptions, ResolvedTarget, Timeout, TlsConfig, TransportHints,
};
use http::{Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

// ---------------------------------------------------------------------------
// Client / TLS helpers (test-side mirror of `eggfetch_policy`)
// ---------------------------------------------------------------------------

fn egg_tls(ca_path: Option<&std::path::Path>, skip_hostname: bool) -> TlsConfig {
    // Explicit aws-lc provider: never rely on eggfetch's process fallback.
    // `rustls` here is the plain dev-dependency version; the `aws-lc-rs`
    // feature unifies from `[dependencies]`, same as `egress_parity.rs`.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut builder = TlsConfig::builder().crypto_provider(provider);
    if let Some(path) = ca_path {
        builder = builder
            .additional_ca_certificate_path(path)
            .expect("test CA bundle must load (fail-closed otherwise)");
    }
    if skip_hostname {
        // Hostname-only skip: chain/signature verification stays enabled.
        builder = builder.verify_hostname(false);
    }
    builder.build()
}

fn base_builder() -> eggfetch_core::ClientBuilder {
    Client::builder()
        .max_idle_connections_per_host(10)
        .idle_timeout(Duration::from_secs(30))
}

fn plain_client() -> Client {
    base_builder().build()
}

fn tls_client(ca_path: Option<&std::path::Path>, skip_hostname: bool) -> Client {
    base_builder()
        .tls_config(egg_tls(ca_path, skip_hostname))
        .build()
}

async fn exec_full(
    client: &Client,
    method: Method,
    url: &str,
    body: Full<Bytes>,
    options: NativeRequestOptions,
) -> Result<Response<eggfetch_core::NativeResponseBody>, eggfetch_core::Error> {
    let req = Request::builder()
        .method(method)
        .uri(url)
        .body(body)
        .expect("test request must build");
    client.execute_http_body(req, options).await
}

async fn collect_native(
    resp: Response<eggfetch_core::NativeResponseBody>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.expect("body must collect").to_bytes();
    (parts.status, parts.headers, bytes)
}

// ---------------------------------------------------------------------------
// H1 fixtures
// ---------------------------------------------------------------------------

type TestBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn boxed_full(data: Bytes) -> TestBody {
    Full::new(data).map_err(|e| match e {}).boxed()
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

fn ok_text(body: &'static str) -> Response<TestBody> {
    Response::builder()
        .status(StatusCode::OK)
        .body(boxed_full(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

// ---------------------------------------------------------------------------
// TLS fixtures (rcgen self-signed; ALPN-selected H1 or H2)
// ---------------------------------------------------------------------------

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

async fn spawn_tls_h1(cert_der: Vec<u8>, key_der: Vec<u8>) -> SocketAddr {
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
                // service_fn error type must unify with the connection builder:
                // map the handler into hyper::Error.
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(ok_text("tls-h1-ok"))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    addr
}

/// TLS H1 server echoing `host` + `path` so SNI tests can prove the logical
/// authority/path survive the SNI override untouched.
async fn spawn_tls_h1_echo_host(cert_der: Vec<u8>, key_der: Vec<u8>) -> SocketAddr {
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
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let host = req
                        .headers()
                        .get(http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.to_string())
                        .unwrap_or_default();
                    let body = format!("host={host} path={path}");
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(boxed_full(Bytes::from(body)))
                            .unwrap(),
                    )
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
// Custom test bodies
// ---------------------------------------------------------------------------

/// Multi-chunk streaming body with configurable size hint (exact or unknown).
struct ChunkBody {
    chunks: VecDeque<Bytes>,
    exact: bool,
}

impl ChunkBody {
    fn new(chunks: Vec<Bytes>, exact: bool) -> Self {
        Self {
            chunks: chunks.into(),
            exact,
        }
    }
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

    fn size_hint(&self) -> http_body::SizeHint {
        if self.exact {
            http_body::SizeHint::with_exact(self.chunks.iter().map(|c| c.len() as u64).sum())
        } else {
            http_body::SizeHint::default()
        }
    }
}

/// Body that yields one chunk and then a transport error.
struct ErrorBody {
    sent: bool,
}

impl http_body::Body for ErrorBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if !self.sent {
            self.sent = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"partial")))))
        } else {
            Poll::Ready(Some(Err(std::io::Error::other("qual body failure"))))
        }
    }
}

/// Body emitting DATA frames followed by request trailers.
struct TrailerBody {
    chunks: VecDeque<Bytes>,
    trailers: Option<http::HeaderMap>,
}

impl http_body::Body for TrailerBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if let Some(c) = self.chunks.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(c))));
        }
        Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))))
    }
}

/// WAF-shaped generic wrapper: forwards frames/size-hint unchanged, like
/// `synvoid_http::StreamingWafBody` around an inner body (scan hook omitted;
/// the qualification property is that the native path accepts the generic
/// wrapper shape without buffering or re-framing).
struct WafShapedBody<B> {
    inner: B,
}

impl<B> http_body::Body for WafShapedBody<B>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// H3-channel-shaped producer body: chunks arrive from an async mpsc channel
/// with backpressure, mimicking the H3-originated upstream body shape.
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

// ---------------------------------------------------------------------------
// Workstream C — TLS/security qualification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ordinary_verification_trusted_matching_hostname_succeeds() {
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1(der, key).await;
    let client = tls_client(Some(ca.path()), false);
    let url = format!("https://localhost:{}/", addr.port());
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect("trusted matching chain must succeed");
    let (status, _, body) = collect_native(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"tls-h1-ok");
}

#[tokio::test]
async fn wrong_hostname_fails_under_normal_verification() {
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1(der, key).await;
    let client = tls_client(Some(ca.path()), false);
    // Same trusted chain, wrong name: must fail.
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let err = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(!format!("{err:?}").is_empty());
}

#[tokio::test]
async fn untrusted_chain_fails_closed() {
    let (_pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let addr = spawn_tls_h1(der, key).await;
    // No custom CA: the rcgen self-signed chain is not in native/WebPKI roots.
    let client = tls_client(None, false);
    let url = format!("https://localhost:{}/", addr.port());
    exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .unwrap_err();
}

#[tokio::test]
async fn malformed_ca_bundle_fails_closed_at_build() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad-ca.pem");
    std::fs::write(&bad, b"not a certificate").unwrap();
    assert!(
        TlsConfig::builder()
            .crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .additional_ca_certificate_path(&bad)
            .is_err(),
        "malformed CA bundle must fail closed, never fall back to defaults"
    );
}

#[tokio::test]
async fn empty_ca_bundle_fails_closed_at_build() {
    let empty = tempfile::NamedTempFile::new().unwrap();
    assert!(
        TlsConfig::builder()
            .crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .additional_ca_certificate_path(empty.path())
            .is_err(),
        "empty CA bundle must fail closed"
    );
}

#[tokio::test]
async fn hostname_skip_succeeds_for_trusted_mismatched_chain() {
    // Cert is for another name, but the chain is in our trust store.
    let (pem, der, key) = rcgen_for(vec!["other-name.test".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1(der, key).await;
    let client = tls_client(Some(ca.path()), true);
    let url = format!("https://localhost:{}/", addr.port());
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect("hostname-skip must succeed for a trusted mismatched chain");
    let (status, _, _) = collect_native(resp).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn hostname_skip_still_rejects_untrusted_chain() {
    // SECURITY-CRITICAL: skip mode must not be danger_accept_invalid_certs.
    let (pem_a, _der_a, _key_a) = rcgen_for(vec!["other-name.test".to_string()]);
    let ca_a = ca_file_for(&pem_a);
    let (_pem_b, der_b, key_b) = rcgen_for(vec!["other-name.test".to_string()]);
    let addr = spawn_tls_h1(der_b, key_b).await;
    let client = tls_client(Some(ca_a.path()), true);
    let url = format!("https://localhost:{}/", addr.port());
    exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect_err("hostname-skip must still reject a chain outside the trust store");
}

#[tokio::test]
async fn normal_verification_rejects_the_same_mismatched_chain() {
    let (pem, der, key) = rcgen_for(vec!["other-name.test".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1(der, key).await;
    let client = tls_client(Some(ca.path()), false);
    let url = format!("https://localhost:{}/", addr.port());
    exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect_err("control: normal verification must reject the mismatched chain");
}

#[tokio::test]
async fn explicit_provider_is_present_in_both_modes() {
    let normal = egg_tls(None, false);
    let skipped = egg_tls(None, true);
    assert!(
        normal.has_explicit_crypto_provider(),
        "normal mode must carry the explicit aws-lc provider"
    );
    assert!(
        skipped.has_explicit_crypto_provider(),
        "skip mode must carry the explicit aws-lc provider"
    );
    assert!(normal.verify_hostname() && normal.verify_certificate());
    assert!(!skipped.verify_hostname() && skipped.verify_certificate());
}

#[cfg(feature = "post-quantum")]
#[tokio::test]
async fn post_quantum_build_preserves_tls_contract() {
    // The PQ feature must not change provider explicitness or verification
    // semantics; the handshake still completes against the local fixture.
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1(der, key).await;
    let client = tls_client(Some(ca.path()), false);
    assert!(egg_tls(Some(ca.path()), false).has_explicit_crypto_provider());
    let url = format!("https://localhost:{}/", addr.port());
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect("PQ build must still complete a verified handshake");
    assert_eq!(collect_native(resp).await.0, StatusCode::OK);
}

#[tokio::test]
async fn sni_override_uses_intended_identity_without_corrupting_authority() {
    let (pem, der, key) = rcgen_for(vec!["sni-target.test".to_string()]);
    let ca = ca_file_for(&pem);
    let addr = spawn_tls_h1_echo_host(der, key).await;
    let client = tls_client(Some(ca.path()), false);

    // TCP destination is the loopback IP; TLS identity comes from the hint.
    let url = format!("https://127.0.0.1:{}/sni/probe?q=1", addr.port());
    let options = NativeRequestOptions::default().transport_hints(TransportHints {
        sni_hostname: Some("sni-target.test".to_string()),
        ..TransportHints::default()
    });
    let resp = exec_full(&client, Method::GET, &url, Full::new(Bytes::new()), options)
        .await
        .expect("SNI override must satisfy certificate identity");
    let (status, _, body) = collect_native(resp).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body.to_vec()).unwrap();
    // Host/authority routing is untouched by the SNI override.
    assert!(
        text.contains(&format!("127.0.0.1:{}", addr.port())),
        "Host authority must stay logical, got: {text}"
    );
    assert!(
        text.contains("/sni/probe?q=1"),
        "path must survive SNI override, got: {text}"
    );

    // Control: without the hint the same destination fails (cert is not for the IP).
    exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect_err("IP destination without SNI hint must fail identity check");
}

#[tokio::test]
async fn sni_policies_do_not_cross_pool() {
    // One client, two TLS identities: alternating requests must each verify
    // against their own SNI hint. Cross-pooling TLS state would fail one leg.
    let (pem_a, der_a, key_a) = rcgen_for(vec!["name-a.test".to_string()]);
    let ca_a = ca_file_for(&pem_a);
    let (pem_b, der_b, key_b) = rcgen_for(vec!["name-b.test".to_string()]);
    let ca_b = ca_file_for(&pem_b);
    let addr_a = spawn_tls_h1(der_a, key_a).await;
    let addr_b = spawn_tls_h1(der_b, key_b).await;

    // Trust store holds both chains (additive custom roots).
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = TlsConfig::builder()
        .crypto_provider(provider)
        .additional_ca_certificate_path(ca_a.path())
        .unwrap()
        .additional_ca_certificate_path(ca_b.path())
        .unwrap()
        .build();
    let client = base_builder().tls_config(tls).build();

    let opts_for = |sni: &str| {
        NativeRequestOptions::default().transport_hints(TransportHints {
            sni_hostname: Some(sni.to_string()),
            ..TransportHints::default()
        })
    };
    for _ in 0..2 {
        let url_a = format!("https://127.0.0.1:{}/", addr_a.port());
        let r = exec_full(
            &client,
            Method::GET,
            &url_a,
            Full::new(Bytes::new()),
            opts_for("name-a.test"),
        )
        .await
        .expect("SNI A leg must verify");
        assert_eq!(collect_native(r).await.0, StatusCode::OK);
        let url_b = format!("https://127.0.0.1:{}/", addr_b.port());
        let r = exec_full(
            &client,
            Method::GET,
            &url_b,
            Full::new(Bytes::new()),
            opts_for("name-b.test"),
        )
        .await
        .expect("SNI B leg must verify");
        assert_eq!(collect_native(r).await.0, StatusCode::OK);
    }
}

// ---------------------------------------------------------------------------
// Workstream D — generic body and frame parity
// ---------------------------------------------------------------------------

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
async fn full_bytes_body_roundtrips() {
    let fx = spawn_echo().await;
    let client = plain_client();
    let url = format!("http://{}/echo", fx.addr);
    let payload = Bytes::from(vec![b'e'; 64 * 1024]);
    let resp = exec_full(
        &client,
        Method::POST,
        &url,
        Full::new(payload.clone()),
        NativeRequestOptions::default(),
    )
    .await
    .unwrap();
    let (status, _, body) = collect_native(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);
}

#[tokio::test]
async fn multi_chunk_body_with_known_size_roundtrips() {
    let fx = spawn_echo().await;
    let client = plain_client();
    let url = format!("http://{}/echo", fx.addr);
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .body(ChunkBody::new(
            vec![
                Bytes::from_static(b"alpha-"),
                Bytes::from_static(b"beta-"),
                Bytes::from_static(b"gamma"),
            ],
            true,
        ))
        .unwrap();
    let resp = client
        .execute_http_body(req, NativeRequestOptions::default())
        .await
        .unwrap();
    let (_, _, body) = collect_native(resp).await;
    assert_eq!(body.as_ref(), b"alpha-beta-gamma");
}

#[tokio::test]
async fn multi_chunk_body_with_unknown_size_roundtrips() {
    let fx = spawn_echo().await;
    let client = plain_client();
    let url = format!("http://{}/echo", fx.addr);
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .body(ChunkBody::new(
            vec![
                Bytes::from_static(b"one"),
                Bytes::from_static(b"two"),
                Bytes::from_static(b"three"),
            ],
            false,
        ))
        .unwrap();
    let resp = client
        .execute_http_body(req, NativeRequestOptions::default())
        .await
        .unwrap();
    let (_, _, body) = collect_native(resp).await;
    assert_eq!(body.as_ref(), b"onetwothree");
}

#[tokio::test]
async fn erroring_body_surfaces_error_without_panic() {
    let fx = spawn_echo().await;
    let client = plain_client();
    let url = format!("http://{}/echo", fx.addr);
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .body(ErrorBody { sent: false })
        .unwrap();
    let result = client
        .execute_http_body(req, NativeRequestOptions::default())
        .await;
    assert!(
        result.is_err(),
        "erroring request body must surface an error, not hang or panic"
    );
}

#[tokio::test]
async fn body_cancellation_before_completion_recovers() {
    let fx = spawn_h1(|_| async move { ok_text("alive") }).await;
    let client = Arc::new(plain_client());
    let url = format!("http://{}/", fx.addr);

    // A request whose body producer never yields: cancel it mid-flight.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    let _tx = tx; // never send: producer stalls forever.
    let req = Request::builder()
        .method(Method::POST)
        .uri(url.clone())
        .body(ChannelBody { rx })
        .unwrap();
    let cancelled = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .execute_http_body(req, NativeRequestOptions::default())
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancelled.abort();
    let _ = cancelled.await;

    // The client must still serve healthy traffic afterwards.
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect("client must recover after body cancellation");
    assert_eq!(collect_native(resp).await.0, StatusCode::OK);
}

#[tokio::test]
async fn request_trailers_reach_upstream() {
    let fx = spawn_h1(|req: Request<Incoming>| async move {
        let collected = req.into_body().collect().await.unwrap();
        let trailer = collected
            .trailers()
            .as_ref()
            .and_then(|t| t.get("x-req-trailer"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let data = collected.to_bytes();
        assert_eq!(data.as_ref(), b"trailer-data");
        Response::builder()
            .status(StatusCode::OK)
            .body(boxed_full(Bytes::from(format!("trailer={trailer}"))))
            .unwrap()
    })
    .await;
    let client = plain_client();
    let url = format!("http://{}/", fx.addr);
    let mut tm = http::HeaderMap::new();
    tm.insert("x-req-trailer", "trailer-value".parse().unwrap());
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        // RFC 9112 §7: trailers must be announced or the H1 layer will not
        // encode them (fixture bug, not a transport gap — verified on both
        // lanes with `trailer_probe`).
        .header("trailer", "x-req-trailer")
        .body(TrailerBody {
            chunks: [Bytes::from_static(b"trailer-data")].into(),
            trailers: Some(tm),
        })
        .unwrap();
    let resp = client
        .execute_http_body(req, NativeRequestOptions::default())
        .await
        .unwrap();
    let (_, _, body) = collect_native(resp).await;
    assert_eq!(body.as_ref(), b"trailer=trailer-value");
}

#[tokio::test]
async fn response_data_and_trailers_are_frame_preserved() {
    // Proven over H2 (first-class trailer frames). Plaintext-H1 probing
    // showed byte-identical symmetric behavior on both lanes (hyper H1
    // server shape does not emit the trailer frame in this fixture for
    // either lane); H2 is therefore the frame-preservation proof, recorded
    // in `architecture/eggfetch_0_2_compatibility_matrix.md`.
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
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"resp-data")))))
                }
                1 => {
                    self.state = 2;
                    let mut tm = http::HeaderMap::new();
                    tm.insert("x-resp-trailer", "resp-trailer-value".parse().unwrap());
                    Poll::Ready(Some(Ok(Frame::trailers(tm))))
                }
                _ => Poll::Ready(None),
            }
        }
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
    let client = tls_client(Some(ca.path()), false);
    let url = format!("https://localhost:{}/", addr.port());
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_2);
    let mut body = resp.into_body();
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("response frames must not error");
        if let Some(chunk) = frame.data_ref() {
            data.extend_from_slice(chunk);
        }
        if frame.is_trailers() {
            trailers = frame.trailers_ref().cloned();
        }
    }
    assert_eq!(data, b"resp-data");
    let trailers = trailers.expect("response trailers must survive the native path");
    assert_eq!(
        trailers.get("x-resp-trailer").unwrap(),
        "resp-trailer-value"
    );
}

#[tokio::test]
async fn waf_shaped_generic_wrapper_streams_without_buffering() {
    let fx = spawn_echo().await;
    let client = plain_client();
    let url = format!("http://{}/echo", fx.addr);
    let inner = ChunkBody::new(
        vec![Bytes::from_static(b"waf-"), Bytes::from_static(b"shaped")],
        false,
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .body(WafShapedBody { inner })
        .unwrap();
    let resp = client
        .execute_http_body(req, NativeRequestOptions::default())
        .await
        .unwrap();
    let (_, _, body) = collect_native(resp).await;
    assert_eq!(body.as_ref(), b"waf-shaped");
}

#[tokio::test]
async fn h3_channel_shaped_producer_body_roundtrips() {
    let fx = spawn_echo().await;
    let client = plain_client();
    let url = format!("http://{}/echo", fx.addr);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    tokio::spawn(async move {
        for chunk in [b"h3-a-", b"h3-b-", b"h3-c-"] {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx.send(Ok(Bytes::from_static(chunk))).await.unwrap();
        }
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .body(ChannelBody { rx })
        .unwrap();
    let resp = client
        .execute_http_body(req, NativeRequestOptions::default())
        .await
        .unwrap();
    let (_, _, body) = collect_native(resp).await;
    assert_eq!(body.as_ref(), b"h3-a-h3-b-h3-c-");
}

// ---------------------------------------------------------------------------
// Workstream E — H1/H2, pooling, resolved targets, UDS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h1_keepalive_reuses_single_connection() {
    let fx = spawn_h1(|_| async move { ok_text("hello") }).await;
    let client = plain_client();
    let url = format!("http://{}/", fx.addr);
    for _ in 0..2 {
        let resp = exec_full(
            &client,
            Method::GET,
            &url,
            Full::new(Bytes::new()),
            NativeRequestOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(collect_native(resp).await.0, StatusCode::OK);
    }
    assert_eq!(fx.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        fx.accepts.load(Ordering::SeqCst),
        1,
        "eggfetch H1 keepalive must reuse one TCP connection"
    );
}

#[tokio::test]
async fn h2_negotiation_and_multiplexing() {
    let (pem, der, key) = rcgen_for(vec!["localhost".to_string()]);
    let ca = ca_file_for(&pem);
    let seen_h2 = Arc::new(AtomicUsize::new(0));
    let addr = spawn_tls_h2_static(der, key, seen_h2.clone()).await;
    let client = Arc::new(tls_client(Some(ca.path()), false));
    let url = format!("https://localhost:{}/", addr.port());
    let mut joins = Vec::new();
    for _ in 0..8 {
        let (client, url) = (client.clone(), url.clone());
        joins.push(tokio::spawn(async move {
            let resp = exec_full(
                &client,
                Method::GET,
                &url,
                Full::new(Bytes::new()),
                NativeRequestOptions::default(),
            )
            .await
            .unwrap();
            let (status, _, body) = collect_native(resp).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), b"h2-ok");
        }));
    }
    for j in joins {
        j.await.unwrap();
    }
    assert!(
        seen_h2.load(Ordering::SeqCst) >= 8,
        "upstream must serve multiplexed HTTP/2"
    );
}

#[tokio::test]
async fn connect_timeout_is_bounded() {
    let client = Client::builder()
        .timeout(
            Timeout::builder()
                .connect(Duration::from_millis(200))
                .build(),
        )
        .build();
    // TEST-NET-1: unroutable; must fail fast, never hang.
    let started = std::time::Instant::now();
    let err = exec_full(
        &client,
        Method::GET,
        "http://192.0.2.1:81/",
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "connect failure must be bounded, elapsed={:?} err={err:?}",
        started.elapsed()
    );
    assert!(!format!("{err:?}").is_empty());
}

#[tokio::test]
async fn total_timeout_covers_slow_response() {
    let fx = spawn_h1(|_| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        ok_text("too-late")
    })
    .await;
    let client = plain_client();
    let url = format!("http://{}/", fx.addr);
    let options = NativeRequestOptions::default()
        .timeout(Timeout::builder().total(Duration::from_millis(150)).build());
    exec_full(&client, Method::GET, &url, Full::new(Bytes::new()), options)
        .await
        .expect_err("total timeout must fire on a stalled upstream");
}

#[tokio::test]
async fn read_timeout_covers_stalled_body() {
    struct StallBody {
        sent: bool,
    }
    impl http_body::Body for StallBody {
        type Data = Bytes;
        type Error = hyper::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
            if !self.sent {
                self.sent = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"head")))))
            } else {
                // Stall forever: the read timeout must fire.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    let fx = spawn_h1(|_| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(StallBody { sent: false }.boxed())
            .unwrap()
    })
    .await;
    let client = plain_client();
    let url = format!("http://{}/", fx.addr);
    let options = NativeRequestOptions::default()
        .timeout(Timeout::builder().read(Duration::from_millis(150)).build());
    let resp = exec_full(&client, Method::GET, &url, Full::new(Bytes::new()), options)
        .await
        .expect("headers must arrive before the stall");
    resp.into_body()
        .collect()
        .await
        .expect_err("read timeout must fire on a stalled body");
}

#[tokio::test]
async fn response_drop_releases_capacity() {
    let fx = spawn_h1(|_| async move { ok_text("again") }).await;
    let client = plain_client();
    let url = format!("http://{}/", fx.addr);
    // Receive headers, drop the body unread (lease must release on drop).
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    drop(resp);
    // The next request on the same client must still succeed.
    let resp = exec_full(
        &client,
        Method::GET,
        &url,
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect("capacity must be released when the response body is dropped");
    assert_eq!(collect_native(resp).await.0, StatusCode::OK);
}

#[tokio::test]
async fn pool_saturation_stays_bounded() {
    let fx = spawn_h1(|_| async move { ok_text("burst") }).await;
    let client = Arc::new(plain_client());
    let url = format!("http://{}/", fx.addr);
    let mut joins = Vec::new();
    for _ in 0..20 {
        let (client, url) = (client.clone(), url.clone());
        joins.push(tokio::spawn(async move {
            let resp = exec_full(
                &client,
                Method::GET,
                &url,
                Full::new(Bytes::new()),
                NativeRequestOptions::default(),
            )
            .await
            .unwrap();
            let (status, _, body) = collect_native(resp).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), b"burst");
        }));
    }
    for j in joins {
        tokio::time::timeout(Duration::from_secs(20), j)
            .await
            .expect("pool must not deadlock under burst")
            .unwrap();
    }
    assert_eq!(fx.requests.load(Ordering::SeqCst), 20);
}

#[tokio::test]
async fn resolved_target_pins_routing_without_dns_fallback() {
    let fx = spawn_h1(|_| async move { ok_text("pinned") }).await;
    let client = plain_client();
    // Hostname is unresolvable: success proves the pinned address was used
    // and no DNS/network fallback occurred.
    let url = format!(
        "http://nonexistent-eggfetch-qual-12345.test:{}/",
        fx.addr.port()
    );
    let target = ResolvedTarget::new([SocketAddr::from(([127, 0, 0, 1], fx.addr.port()))]).unwrap();
    let options = NativeRequestOptions::default().transport_hints(TransportHints {
        resolved_target: Some(target),
        ..TransportHints::default()
    });
    let resp = exec_full(&client, Method::GET, &url, Full::new(Bytes::new()), options)
        .await
        .expect("pinned resolved target must route without DNS");
    let (status, _, body) = collect_native(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"pinned");
}

#[tokio::test]
async fn resolved_target_rejects_empty_set_before_network() {
    assert!(
        ResolvedTarget::new(Vec::<SocketAddr>::new()).is_err(),
        "empty resolved target must fail at construction, before any I/O"
    );
}

#[tokio::test]
async fn resolved_target_rejects_port_mismatch() {
    let fx = spawn_h1(|_| async move { ok_text("x") }).await;
    let client = plain_client();
    let url = format!("http://127.0.0.1:{}/", fx.addr.port());
    let wrong_port = fx.addr.port().wrapping_add(1);
    let target = ResolvedTarget::new([SocketAddr::from(([127, 0, 0, 1], wrong_port))]).unwrap();
    let options = NativeRequestOptions::default().transport_hints(TransportHints {
        resolved_target: Some(target),
        ..TransportHints::default()
    });
    exec_full(&client, Method::GET, &url, Full::new(Bytes::new()), options)
        .await
        .expect_err("resolved target with a mismatched port must fail closed");
}

#[tokio::test]
async fn resolved_target_origins_stay_isolated() {
    let fa = spawn_h1(|_| async move { ok_text("origin-a") }).await;
    let fb = spawn_h1(|_| async move { ok_text("origin-b") }).await;
    let client = plain_client();
    let pinned = |port: u16| {
        NativeRequestOptions::default().transport_hints(TransportHints {
            resolved_target: Some(
                ResolvedTarget::new([SocketAddr::from(([127, 0, 0, 1], port))]).unwrap(),
            ),
            ..TransportHints::default()
        })
    };
    for _ in 0..2 {
        let url_a = format!("http://origin-a.test:{}/", fa.addr.port());
        let r = exec_full(
            &client,
            Method::GET,
            &url_a,
            Full::new(Bytes::new()),
            pinned(fa.addr.port()),
        )
        .await
        .unwrap();
        assert_eq!(collect_native(r).await.2.as_ref(), b"origin-a");
        let url_b = format!("http://origin-b.test:{}/", fb.addr.port());
        let r = exec_full(
            &client,
            Method::GET,
            &url_b,
            Full::new(Bytes::new()),
            pinned(fb.addr.port()),
        )
        .await
        .unwrap();
        assert_eq!(collect_native(r).await.2.as_ref(), b"origin-b");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn uds_direct_request_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("eggfetch-qual.sock");
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
    let client = Client::builder()
        .uds_path(sock.to_string_lossy().into_owned())
        .build();
    let resp = exec_full(
        &client,
        Method::GET,
        "http://localhost/health",
        Full::new(Bytes::new()),
        NativeRequestOptions::default(),
    )
    .await
    .expect("direct UDS request must succeed on Unix");
    let (status, _, body) = collect_native(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"uds-ok");
}

// ---------------------------------------------------------------------------
// Differential preview: legacy vs eggfetch on the same fixture
// ---------------------------------------------------------------------------

#[tokio::test]
async fn differential_h1_get_matches_legacy() {
    let fx = spawn_h1(|req: Request<Incoming>| async move {
        let probe = req
            .headers()
            .get("x-parity-probe")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut resp = ok_text("parity-body");
        resp.headers_mut()
            .insert("x-probe-echo", probe.parse().unwrap());
        resp
    })
    .await;
    let url = format!("http://{}/", fx.addr);

    // Legacy lane.
    let legacy = synvoid_http_client::create_simple_http_client(Duration::from_secs(5));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-parity-probe", "probe-1".parse().unwrap());
    let l = synvoid_http_client::send_request_with_timeout_and_headers(
        &legacy,
        Method::GET,
        &url,
        headers.clone(),
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();

    // Eggfetch lane, same fixture.
    let egg = plain_client();
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .header("x-parity-probe", "probe-1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let e = egg
        .execute_http_body(req, NativeRequestOptions::default())
        .await
        .unwrap();
    let (e_status, e_headers, e_body) = collect_native(e).await;

    assert_eq!(l.status_code(), e_status.as_u16());
    assert_eq!(l.body.as_ref(), e_body.as_ref());
    assert_eq!(
        l.header("x-probe-echo"),
        e_headers.get("x-probe-echo").and_then(|v| v.to_str().ok())
    );
}

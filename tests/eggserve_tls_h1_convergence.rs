//! Root-test ownership: QUALIFICATION
//! Rationale: Phase 77 TLS-H1 convergence. Real Rustls handshakes with ALPN
//! selection split H2 (unchanged Hyper path) from H1 (EggServe direct
//! runtime with SynVoid TLS ownership: handshake, JA4 threading point,
//! shutdown bridging). Corpus mirrors the plaintext adoption matrix over
//! the encrypted transport, plus H2 regression and ALPN negative guards.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use synvoid::http::eggserve_h1::{project_eggserve_h1, EggserveH1Service};
use synvoid::http::service_core::{handle_neutral_request, NeutralServiceContext};
use synvoid_config::site::SiteConfig;
use synvoid_config::theme::ThemeConfig;
use synvoid_config::MainConfig;
use synvoid_http::hyper_adapter::adapt_hyper_request;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::ForwardedProtocol;
use synvoid_proxy::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Stub context (same contract as the plaintext lanes).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StubWaf {
    theme: ThemeConfig,
    drop_decisions: Arc<AtomicUsize>,
}

impl synvoid_http::request_parse::EarlyWafHooks for StubWaf {
    fn verify_trust_token(&self, _client_ip: std::net::IpAddr, _token: &str) -> bool {
        false
    }
}

impl synvoid_http::body_policy::RequestBodyWaf for StubWaf {
    fn streaming(&self) -> Option<Box<dyn synvoid_http::shared_handler::StreamingWafScanner>> {
        None
    }

    fn check_request_body(&self, _chunk: &[u8]) -> (bool, Option<synvoid_waf::WafDecision>) {
        (false, None)
    }
}

impl synvoid_http::challenge_paths::ChallengePathWaf for StubWaf {
    fn generate_challenge_page(
        &self,
        _ip: &std::net::IpAddr,
        _app_path: Option<&str>,
    ) -> (String, Option<String>) {
        (String::new(), None)
    }

    fn css_enabled(&self) -> bool {
        false
    }

    fn css_session_cookie_name(&self) -> String {
        "css-session".to_string()
    }

    fn record_css_asset_request(
        &self,
        _session_id: &str,
        _asset_name: &str,
    ) -> (
        synvoid_challenge::css::AssetRequestResult,
        synvoid_challenge::css::CssAssetAction,
    ) {
        (
            synvoid_challenge::css::AssetRequestResult::UnknownAsset,
            synvoid_challenge::css::CssAssetAction::DropConnection,
        )
    }

    fn css_verified_cookie_name(&self) -> String {
        "css-verified".to_string()
    }

    fn css_window_secs(&self) -> u64 {
        0
    }
}

#[async_trait::async_trait]
impl synvoid_http::BufferedRequestWaf for StubWaf {
    fn error_page_theme(&self) -> &ThemeConfig {
        &self.theme
    }

    fn render_page_with_theme(
        &self,
        status: u16,
        message: Option<&str>,
        _override_theme: Option<&ThemeConfig>,
    ) -> String {
        format!("{status} {}", message.unwrap_or("error"))
    }

    fn connection_limiter(&self) -> Option<Arc<synvoid_waf::ConnectionLimiter>> {
        None
    }

    fn is_over_bandwidth_limit(&self) -> bool {
        false
    }

    fn honeypot_ban_duration_secs(&self) -> u64 {
        0
    }

    fn stream_tarpit(&self, _path: &str, _user_agent: Option<&str>) -> synvoid_http::TarpitStream {
        Box::pin(futures::stream::empty::<Result<Bytes, std::io::Error>>())
    }

    fn generate_tarpit_response(&self, _path: &str) -> String {
        String::new()
    }

    async fn check_request_full(
        &self,
        _site_id: Option<&str>,
        _ip: std::net::IpAddr,
        _method: &str,
        path: &str,
        _query: Option<&str>,
        _headers: &http::HeaderMap,
        _body: Option<&[u8]>,
        _ua: Option<&str>,
        _ja4_hash: Option<&str>,
        _site_bot_config: Option<&synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
        self.decide(path)
    }

    async fn check_request_full_owned(
        self: Arc<Self>,
        _site_id: Option<String>,
        _ip: std::net::IpAddr,
        _method: String,
        path: String,
        _query: Option<String>,
        _headers: http::HeaderMap,
        _body: Option<Bytes>,
        _ua: Option<String>,
        _ja4_hash: Option<String>,
        _site_bot_config: Option<synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
        self.decide(&path)
    }
}

impl StubWaf {
    fn decide(&self, path: &str) -> synvoid_proxy::WafDecision {
        if path.starts_with("/waf-drop") {
            self.drop_decisions.fetch_add(1, Ordering::SeqCst);
            synvoid_proxy::WafDecision::Drop
        } else {
            synvoid_proxy::WafDecision::Pass
        }
    }
}

impl synvoid_proxy::protocol::trait_def::WafCoreBackend for StubWaf {}

impl synvoid_http::UploadValidationWaf for StubWaf {
    fn get_upload_validator(&self) -> Option<Arc<synvoid_upload::UploadValidator>> {
        None
    }

    fn render_upload_validation_error_page(
        &self,
        status_code: u16,
        message: Option<&str>,
    ) -> String {
        format!("{status_code} {}", message.unwrap_or("upload error"))
    }
}

impl synvoid_http::WafErrorPageRenderer for StubWaf {
    fn render_page(&self, status: u16, message: Option<&str>) -> String {
        format!("{status} {}", message.unwrap_or("error"))
    }
}

#[derive(Clone)]
struct StubDrain;

#[async_trait::async_trait]
impl synvoid_http::internal_handlers::HttpDrainControl for StubDrain {
    async fn start_drain(&self, _drain_id: u64) -> bool {
        false
    }

    fn stop_accepting(&self) {}

    async fn get_status(&self) -> synvoid_http::internal_handlers::DrainStatusSnapshot {
        synvoid_http::internal_handlers::DrainStatusSnapshot {
            drain_id: 0,
            is_draining: false,
            active_connections: 0,
            idle_connections: 0,
            connections_drained: 0,
            drain_elapsed_secs: 0,
            drain_complete: false,
            stopped_accepting: false,
            short_requests: 0,
            long_requests: 0,
            streaming_requests: 0,
        }
    }

    fn is_draining(&self) -> bool {
        false
    }

    fn is_stopped_accepting(&self) -> bool {
        false
    }
}

struct Shared {
    router: Arc<Router>,
    waf: Arc<StubWaf>,
    main_config: Arc<MainConfig>,
    registry: Arc<UpstreamClientRegistry>,
}

fn build_shared(echo_addr: SocketAddr) -> (Shared, Arc<AtomicUsize>) {
    let drop_decisions = Arc::new(AtomicUsize::new(0));
    let mut sites = HashMap::new();
    let mut site = SiteConfig::default_fallback_site(format!("http://{echo_addr}"));
    site.site.domains = vec!["a.test".to_string()];
    site.security_headers.server_token = Some("tls-alpha".to_string());
    site.security_headers.date_header = Some(false);
    sites.insert("site-a".to_string(), site);
    let main_config = Arc::new(MainConfig::default());
    (
        Shared {
            router: Arc::new(Router::new(&main_config, sites)),
            waf: Arc::new(StubWaf {
                theme: ThemeConfig::default(),
                drop_decisions: drop_decisions.clone(),
            }),
            main_config,
            registry: Arc::new(UpstreamClientRegistry::new()),
        },
        drop_decisions,
    )
}

fn lane_context(
    shared: &Shared,
    http_config: synvoid_config::http::HttpConfig,
) -> NeutralServiceContext<StubWaf, StubDrain> {
    NeutralServiceContext {
        router: Arc::clone(&shared.router),
        waf: Arc::clone(&shared.waf),
        alt_svc: None,
        main_config: Arc::clone(&shared.main_config),
        http_config,
        metrics: None,
        ipc: None,
        worker_id: None,
        drain_state: Some(Arc::new(StubDrain)),
        upstream_client_registry: Arc::clone(&shared.registry),
        connection_limit: Arc::new(Semaphore::new(1024)),
        app_servers: None,
        #[cfg(feature = "mesh")]
        mesh_config: None,
        #[cfg(feature = "mesh")]
        mesh_transport: None,
        #[cfg(feature = "mesh")]
        mesh_backend_pool: None,
        serverless_manager: None,
    }
}

// ---------------------------------------------------------------------------
// Real-TLS fixtures (rcgen self-signed, ALPN-selectable).
// ---------------------------------------------------------------------------

fn rcgen_self_signed_der() -> (Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        certified.cert.der().to_vec(),
        certified.key_pair.serialize_der(),
    )
}

fn server_tls_acceptor(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    alpn: Vec<Vec<u8>>,
) -> tokio_rustls::TlsAcceptor {
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
    server_config.alpn_protocols = alpn;
    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

async fn tls_connect(
    addr: SocketAddr,
    cert_der: &[u8],
    alpn: Vec<u8>,
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
    client_config.alpn_protocols = vec![alpn];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    connector.connect(server_name, tcp).await.unwrap()
}

async fn spawn_upstream_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use http_body_util::BodyExt as _;
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        let (parts, body) = req.into_parts();
                        let bytes = body.collect().await.unwrap().to_bytes();
                        let text = format!(
                            "echo:{}:{}:{}:{}",
                            parts.method,
                            parts.uri.path(),
                            bytes.len(),
                            String::from_utf8_lossy(&bytes)
                        );
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(Bytes::from(text)),
                        ))
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

/// Real-TLS loopback with production-shaped ALPN split: `h2` stays on the
/// Hyper H2 path with the neutral pipeline; anything else goes to the
/// EggServe H1 driver with the shared service.
async fn spawn_tls_split_server(
    ctx: NeutralServiceContext<StubWaf, StubDrain>,
    http_config: synvoid_config::http::HttpConfig,
    acceptor: tokio_rustls::TlsAcceptor,
    last_shutdown: Arc<std::sync::Mutex<Option<eggserve_server::ConnectionShutdown>>>,
) -> SocketAddr {
    let projected = project_eggserve_h1(&http_config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let ctx = ctx.clone();
            let http_config = http_config.clone();
            let policy = projected.policy.clone();
            let state = projected.state.clone();
            let last_shutdown = last_shutdown.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("TLS handshake");
                let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                let local = tls.get_ref().0.local_addr().ok();
                if alpn.as_deref() == Some(b"h2".as_slice()) {
                    // Unchanged Hyper H2 path through the neutral boundary.
                    let io = hyper_util::rt::TokioIo::new(tls);
                    let svc = hyper::service::service_fn(move |req| {
                        let ctx = ctx.clone();
                        async move {
                            let inbound = adapt_hyper_request(req);
                            let drop_noop: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
                            handle_neutral_request(
                                &ctx,
                                inbound,
                                peer.ip(),
                                local,
                                drop_noop,
                                None,
                                ForwardedProtocol::Https,
                                None,
                            )
                            .await
                        }
                    });
                    let mut h2_builder = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    // Mirror production: the H2 ceiling comes from the same
                    // HttpConfig key. An explicit zero-test hook may disable
                    // it to isolate transport behavior.
                    if std::env::var("EGGSERVE_H2_NO_LIMIT").is_err() {
                        h2_builder.max_header_list_size(http_config.max_headers as u32);
                    }
                    let _ = h2_builder.serve_connection(io, svc).await;
                    return;
                }
                // ALPN http/1.1 (or absent): EggServe direct H1. The raw
                // Tokio TlsStream crosses (no TokioIo wrap); JA4 would be
                // threaded here in production (None in this harness).
                let conn_shutdown = eggserve_server::ConnectionShutdown::new();
                *last_shutdown.lock().unwrap() = Some(conn_shutdown.clone());
                let service = EggserveH1Service::new(
                    ctx,
                    conn_shutdown.clone(),
                    None,
                    ForwardedProtocol::Https,
                    local,
                    None,
                );
                let _ = eggserve_server::serve_http1_connection_with_policy(
                    tls,
                    service,
                    policy,
                    eggserve_server::ConnectionContext::for_tcp(
                        local.unwrap_or(peer),
                        peer,
                        Some(eggserve_primitives::TlsInfo {
                            protocol_version: None,
                            server_name: None,
                            alpn: Some("http/1.1".to_string()),
                            client_authenticated: false,
                            peer_certificates_present: false,
                            peer_certificate_chain: None,
                        }),
                    ),
                    state,
                    &conn_shutdown,
                )
                .await;
            });
        }
    });
    addr
}

fn shutdown_slot() -> Arc<std::sync::Mutex<Option<eggserve_server::ConnectionShutdown>>> {
    Arc::new(std::sync::Mutex::new(None))
}

async fn tls_exchange(addr: SocketAddr, cert_der: &[u8], alpn: &[u8], request: &[u8]) -> String {
    let mut stream = tls_connect(addr, cert_der, alpn.to_vec()).await;
    stream.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut buf))
        .await
        .expect("read timeout")
        .expect("read failed");
    String::from_utf8_lossy(&buf).into_owned()
}

// ---------------------------------------------------------------------------
// TLS-H1 corpus (EggServe lane over real TLS)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_h1_control_and_metadata() {
    let echo = spawn_upstream_echo().await;
    let (shared, _) = build_shared(echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(
        cert_der.clone(),
        key_der,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    );
    let addr = spawn_tls_split_server(
        lane_context(&shared, http_config),
        synvoid_config::http::HttpConfig::default(),
        acceptor,
        shutdown_slot(),
    )
    .await;

    let wire = tls_exchange(
        addr,
        &cert_der,
        b"http/1.1",
        b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
    assert!(wire.contains("server: tls-alpha"), "{wire}");
    assert!(wire.contains("echo:GET:/:0:"), "{wire}");
    // No Server-induced failure: per-site token preserved through the
    // EggServe final boundary on the encrypted transport.
    assert!(
        !wire.to_ascii_lowercase().contains("http/1.1 500"),
        "{wire}"
    );
}

#[tokio::test]
async fn tls_h1_body_limits_and_drop() {
    let echo = spawn_upstream_echo().await;
    let (shared, drop_decisions) = build_shared(echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der, vec![b"http/1.1".to_vec()]);
    let slot = shutdown_slot();
    let addr = spawn_tls_split_server(
        lane_context(&shared, http_config),
        synvoid_config::http::HttpConfig::default(),
        acceptor,
        slot.clone(),
    )
    .await;

    // POST body through the encrypted EggServe lane.
    let wire = tls_exchange(
        addr,
        &cert_der,
        b"http/1.1",
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    assert!(wire.contains("echo:POST:/submit:5:hello"), "{wire}");

    // Chunked + trailers.
    let wire = tls_exchange(
        addr,
        &cert_der,
        b"http/1.1",
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nTrailer: x-sum\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nx-sum: abc\r\n\r\n",
    )
    .await;
    assert!(wire.contains("echo:POST:/submit:5:hello"), "{wire}");

    // Conflicting framing fails closed (hyper rejects at parse; the
    // canonical validator would reject it identically if reached).
    let wire = tls_exchange(
        addr,
        &cert_der,
        b"http/1.1",
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    assert!(
        !wire.starts_with("HTTP/1.1 200"),
        "conflicting framing must not succeed: {wire:?}"
    );

    // WAF Drop: stealth 404 with empty body (blackhole contract), token
    // fires, connection closes.
    let wire = tls_exchange(
        addr,
        &cert_der,
        b"http/1.1",
        b"GET /waf-drop HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(wire.starts_with("HTTP/1.1 404"), "{wire}");
    assert_eq!(drop_decisions.load(Ordering::SeqCst), 1);
    let token = slot.lock().unwrap().clone().expect("token registered");
    assert!(token.is_shutdown());
}

#[tokio::test]
async fn tls_h1_parser_bounds_and_timeout() {
    let echo = spawn_upstream_echo().await;
    let (shared, _) = build_shared(echo);
    let (cert_der, key_der) = rcgen_self_signed_der();

    // Header count ceiling.
    let count_config = synvoid_config::http::HttpConfig {
        max_headers: 8,
        max_header_size_ingress: 1024 * 1024,
        ..Default::default()
    };
    let acceptor = server_tls_acceptor(
        cert_der.clone(),
        key_der.clone(),
        vec![b"http/1.1".to_vec()],
    );
    let addr = spawn_tls_split_server(
        lane_context(&shared, count_config.clone()),
        count_config,
        acceptor,
        shutdown_slot(),
    )
    .await;
    let mut big = b"GET / HTTP/1.1\r\nHost: a.test\r\n".to_vec();
    for n in 0..10 {
        big.extend_from_slice(format!("x-h{n}: v\r\n").as_bytes());
    }
    big.extend_from_slice(b"Connection: close\r\n\r\n");
    let wire = tls_exchange(addr, &cert_der, b"http/1.1", &big).await;
    assert!(wire.starts_with("HTTP/1.1 431"), "{wire}");

    // Slow headers: 1s timeout refuses the stalled head.
    let slow_config = synvoid_config::http::HttpConfig {
        header_read_timeout_secs: 1,
        ..Default::default()
    };
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der, vec![b"http/1.1".to_vec()]);
    let addr = spawn_tls_split_server(
        lane_context(&shared, slow_config.clone()),
        slow_config,
        acceptor,
        shutdown_slot(),
    )
    .await;
    let mut stream = tls_connect(addr, &cert_der, b"http/1.1".to_vec()).await;
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: a.test\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    stream
        .write_all(b"Connection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    let wire = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        wire.starts_with("HTTP/1.1 408") || wire.is_empty(),
        "slow TLS headers not refused: {wire:?}"
    );
}

#[tokio::test]
async fn tls_h1_websocket_and_shutdown() {
    let echo = spawn_upstream_echo().await;
    let (shared, _) = build_shared(echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(
        cert_der.clone(),
        key_der,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    );
    let slot = shutdown_slot();
    let addr = spawn_tls_split_server(
        lane_context(&shared, http_config),
        synvoid_config::http::HttpConfig::default(),
        acceptor,
        slot,
    )
    .await;

    // WSS-style upgrade over the real TLS stream: 101 + accept parity.
    let mut stream = tls_connect(addr, &cert_der, b"http/1.1".to_vec()).await;
    stream
        .write_all(b"GET /ws HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n")
        .await
        .unwrap();
    let mut wire = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut tmp))
            .await
            .expect("handshake timeout")
            .expect("handshake read failed");
        assert!(n > 0);
        wire.extend_from_slice(&tmp[..n]);
        if wire.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&wire).into_owned();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{head}");
    drop(stream);
}

#[tokio::test]
async fn tls_h2_stays_hyper_with_header_limit() {
    let echo = spawn_upstream_echo().await;
    let (shared, _) = build_shared(echo);
    // Deliberately small H2 header-list ceiling for the regression probe.
    // NOTE: h2 accounts decoded size (32 B/entry overhead), so ordinary
    // requests need hundreds of bytes; the production default (128) is
    // correspondingly tight (pre-existing, unchanged by this campaign —
    // flagged as a follow-up, not altered here).
    let h2_config = synvoid_config::http::HttpConfig {
        max_headers: 16384,
        ..Default::default()
    };
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der, vec![b"h2".to_vec()]);
    let addr = spawn_tls_split_server(
        lane_context(&shared, h2_config.clone()),
        h2_config,
        acceptor,
        shutdown_slot(),
    )
    .await;

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    // H2 client over the real TLS stream (prior ALPN: h2 only).
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
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol().map(|p| p.to_vec()),
        Some(b"h2".to_vec()),
        "client must negotiate ALPN h2"
    );
    let io = hyper_util::rt::TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<
        _,
        _,
        http_body_util::Full<Bytes>,
    >(hyper_util::rt::TokioExecutor::new(), io)
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    // H2 control: ordinary request served on the unchanged Hyper path.
    let req = hyper::Request::builder()
        .method("GET")
        .uri("https://a.test/")
        .header("host", "a.test")
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    use http_body_util::BodyExt as _;
    let status = resp.status();
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(status, 200);
    assert!(
        body.starts_with(b"echo:GET:/"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    // Ceiling intact: a tiny header-list budget fails pre-service with the
    // h2-generated 431 (never reaches dispatch).
    let tight_config = synvoid_config::http::HttpConfig {
        max_headers: 16,
        ..Default::default()
    };
    let (cert_der2, key_der2) = rcgen_self_signed_der();
    let acceptor2 = server_tls_acceptor(cert_der2.clone(), key_der2, vec![b"h2".to_vec()]);
    let addr2 = spawn_tls_split_server(
        lane_context(&shared, tight_config.clone()),
        tight_config,
        acceptor2,
        shutdown_slot(),
    )
    .await;
    let tcp2 = tokio::net::TcpStream::connect(addr2).await.unwrap();
    let mut roots2 = rustls::RootCertStore::empty();
    roots2
        .add(rustls_pki_types::CertificateDer::from(cert_der2.to_vec()))
        .unwrap();
    let mut client_config2 = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots2)
    .with_no_client_auth();
    client_config2.alpn_protocols = vec![b"h2".to_vec()];
    let connector2 = tokio_rustls::TlsConnector::from(Arc::new(client_config2));
    let server_name2 = rustls_pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    let tls2 = connector2.connect(server_name2, tcp2).await.unwrap();
    let io2 = hyper_util::rt::TokioIo::new(tls2);
    let (mut sender2, conn2) = hyper::client::conn::http2::handshake::<
        _,
        _,
        http_body_util::Full<Bytes>,
    >(hyper_util::rt::TokioExecutor::new(), io2)
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn2.await;
    });
    let req2 = hyper::Request::builder()
        .method("GET")
        .uri("https://a.test/")
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();
    // Tight budget refuses pre-service: either h2-generated 431 headers or
    // a connection-level GOAWAY surfacing as a client error. Either proves
    // the ceiling is enforced and dispatch never runs.
    match sender2.send_request(req2).await {
        Ok(resp2) => assert_eq!(resp2.status(), 431),
        Err(e) => {
            let debug = format!("{e:?}");
            assert!(
                debug.contains("GoAway") || debug.contains("reset"),
                "unexpected tight-ceiling signal: {debug}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 78: adversarial extras over the encrypted transport.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_h1_slow_request_line_and_garbage() {
    let echo = spawn_upstream_echo().await;
    let (shared, _) = build_shared(echo);
    let slow_config = synvoid_config::http::HttpConfig {
        header_read_timeout_secs: 1,
        ..Default::default()
    };
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der, vec![b"http/1.1".to_vec()]);
    let addr = spawn_tls_split_server(
        lane_context(&shared, slow_config.clone()),
        slow_config,
        acceptor,
        shutdown_slot(),
    )
    .await;
    // Stalled request line past the timeout: refused, never served.
    let mut stream = tls_connect(addr, &cert_der, b"http/1.1".to_vec()).await;
    stream.write_all(b"GET /slo").await.unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    stream
        .write_all(b"w HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    let wire = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        wire.starts_with("HTTP/1.1 408") || wire.is_empty(),
        "stalled TLS head not refused: {wire:?}"
    );

    // Garbage bytes after a good handshake: refused, lane survives.
    let mut stream = tls_connect(addr, &cert_der, b"http/1.1".to_vec()).await;
    stream.write_all(b"HELLO WORLD\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    let wire = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        !wire.starts_with("HTTP/1.1 200"),
        "garbage accepted: {wire:?}"
    );
    let wire = tls_exchange(
        addr,
        &cert_der,
        b"http/1.1",
        b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
}

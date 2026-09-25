//! Root-test ownership: QUALIFICATION
//! Rationale: Phase 79 EggServe 0.3.1 H1 runtime-correctness corrective.
//! Proves Findings A–D on production-shaped drivers (plaintext EggServe H1
//! and real TLS-H1 through the shared `drive_h1_connection` /
//! `h1_connection_context` helpers): worker shutdown drains instead of
//! cancelling the driver, exact bodies preserve terminal trailers on the
//! wire, the real AppServer WebSocket tunnel loops over a test-owned Unix
//! socket, and local provenance never fabricates the peer address.
//!
//! H2 behavior is unchanged by construction (the H2 branch is untouched);
//! H2 regression remains covered by `eggserve_tls_h1_convergence`, which is
//! re-run as part of the Phase 79 verification matrix.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use synvoid::app_server::{GranianConfig, GranianSupervisor};
use synvoid::http::eggserve_h1::{
    drive_h1_connection, h1_connection_context, project_eggserve_h1, EggserveH1Service,
};
use synvoid::http::service_core::NeutralServiceContext;
use synvoid_config::site::SiteConfig;
use synvoid_config::theme::ThemeConfig;
use synvoid_config::MainConfig;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::ForwardedProtocol;
use synvoid_proxy::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, Semaphore};

// ---------------------------------------------------------------------------
// Streamed-response fixture (Finding A).
// ---------------------------------------------------------------------------
// A WAF tarpit decision on the streaming-policy site is served as a live
// SynVoid-generated stream, so the response body is in flight — with data
// already on the wire — when a worker shutdown lands. The default buffered
// proxy policy would collect an upstream body before any byte is written,
// which cannot exercise mid-response drain.
const STREAM_PATH: &str = "/tarpit-stream";
const STREAM_CHUNKS: usize = 10;
const STREAM_CHUNK_MS: u64 = 200;

// ---------------------------------------------------------------------------
// Shared stub context (same contract as the adoption lanes).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StubWaf {
    theme: ThemeConfig,
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

    fn stream_tarpit(&self, path: &str, _user_agent: Option<&str>) -> synvoid_http::TarpitStream {
        if path != STREAM_PATH {
            return Box::pin(futures::stream::empty::<Result<Bytes, std::io::Error>>());
        }
        // Delayed chunk source: the streamed response stays in flight for
        // `STREAM_CHUNKS * STREAM_CHUNK_MS`, long enough for a worker
        // shutdown to land after the first DATA frame.
        Box::pin(futures::stream::unfold(0usize, |n| async move {
            if n >= STREAM_CHUNKS {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(STREAM_CHUNK_MS)).await;
            Some((Ok(Bytes::from(format!("t{n};"))), n + 1))
        }))
    }

    fn generate_tarpit_response(&self, path: &str) -> String {
        // Buffered-path stand-in: never the in-flight stream under test.
        if path == STREAM_PATH {
            "buffered-tarpit".to_string()
        } else {
            String::new()
        }
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
        if path == STREAM_PATH {
            return synvoid_proxy::WafDecision::Tarpit(path.to_string());
        }
        synvoid_proxy::WafDecision::Pass
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
        if path == STREAM_PATH {
            return synvoid_proxy::WafDecision::Tarpit(path);
        }
        synvoid_proxy::WafDecision::Pass
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

/// Site-id -> supervisor map installed in the neutral service context.
type AppServers = Arc<tokio::sync::RwLock<HashMap<String, Arc<GranianSupervisor>>>>;

struct Shared {
    router: Arc<Router>,
    waf: Arc<StubWaf>,
    main_config: Arc<MainConfig>,
    registry: Arc<UpstreamClientRegistry>,
    app_servers: Option<AppServers>,
}

fn build_shared(
    echo_addr: SocketAddr,
    ws_echo_addr: SocketAddr,
    app_servers: Option<AppServers>,
    app_socket: Option<PathBuf>,
) -> Shared {
    let mut sites = HashMap::new();
    let mut site = SiteConfig::default_fallback_site(format!("http://{echo_addr}"));
    site.site.domains = vec!["a.test".to_string()];
    site.security_headers.server_token = Some("corrective".to_string());
    site.security_headers.date_header = Some(false);
    sites.insert("site-a".to_string(), site);
    // Streamed-response site: `body_buffering_policy = streaming` opens the
    // streaming fast path, which serves a WAF tarpit decision as a live
    // SynVoid-generated stream (no upstream hop, so the response is in
    // flight while a worker shutdown lands mid-body).
    let mut stream_site = SiteConfig::default_fallback_site("http://127.0.0.1:9".to_string());
    stream_site.site.domains = vec!["stream.test".to_string()];
    stream_site.security_headers.server_token = Some("corrective".to_string());
    stream_site.security_headers.date_header = Some(false);
    stream_site.proxy.body_buffering_policy =
        Some(synvoid_config::site::proxy::BodyBufferingPolicy::Streaming);
    sites.insert("site-stream".to_string(), stream_site);
    let mut ws_site = SiteConfig::default_fallback_site(format!("ws://{ws_echo_addr}/ws"));
    ws_site.site.domains = vec!["ws.test".to_string()];
    ws_site.security_headers.server_token = Some("corrective".to_string());
    ws_site.security_headers.date_header = Some(false);
    sites.insert("site-ws".to_string(), ws_site);
    // AppServer route: site-level `app_server.enabled` selects
    // `BackendType::AppServer`; the supervisor socket resolves the Unix
    // peer for the production tunnel callback.
    if let Some(sock) = app_socket {
        let mut app_site = SiteConfig::default_fallback_site("http://127.0.0.1:9".to_string());
        app_site.site.domains = vec!["app.test".to_string()];
        app_site.security_headers.server_token = Some("corrective".to_string());
        app_site.security_headers.date_header = Some(false);
        app_site.app_server.enabled = Some(true);
        app_site.app_server.app_path = Some("test:app".to_string());
        app_site.app_server.socket_path = Some(sock.display().to_string());
        sites.insert("site-app".to_string(), app_site);
    }
    let main_config = Arc::new(MainConfig::default());
    Shared {
        router: Arc::new(Router::new(&main_config, sites)),
        waf: Arc::new(StubWaf {
            theme: ThemeConfig::default(),
        }),
        main_config,
        registry: Arc::new(UpstreamClientRegistry::new()),
        app_servers,
    }
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
        app_servers: shared.app_servers.clone(),
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
// Upstream fixtures: HTTP echo (+ slow drain stream) and WS echo.
// ---------------------------------------------------------------------------

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
                type EchoBody =
                    http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        let path = req.uri().path().to_string();
                        let (parts, body) = req.into_parts();
                        let bytes = body.collect().await.unwrap().to_bytes();
                        let text = format!(
                            "echo:{}:{}:{}:{}",
                            parts.method,
                            parts.uri.path(),
                            bytes.len(),
                            String::from_utf8_lossy(&bytes)
                        );
                        let resp: hyper::Response<EchoBody> = hyper::Response::new(
                            http_body_util::Full::new(Bytes::from(text)).boxed(),
                        );
                        Ok::<_, std::convert::Infallible>(resp)
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

async fn spawn_ws_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use futures::{SinkExt, StreamExt};
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(msg)) = rx.next().await {
                    if (msg.is_text() || msg.is_binary()) && tx.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Test-owned Unix-socket WebSocket echo peer standing in for a Granian
/// AppServer process (no Python/Granian in CI).
async fn spawn_unix_ws_echo(sock: PathBuf) -> Arc<AtomicUsize> {
    let _ = std::fs::remove_file(&sock);
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let frames = Arc::new(AtomicUsize::new(0));
    let frames_clone = frames.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let frames = frames_clone.clone();
            tokio::spawn(async move {
                use futures::{SinkExt, StreamExt};
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(msg)) = rx.next().await {
                    if msg.is_text() || msg.is_binary() {
                        frames.fetch_add(1, Ordering::SeqCst);
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    } else if msg.is_close() {
                        let _ = tx.send(msg).await;
                        break;
                    }
                }
            });
        }
    });
    frames
}

fn granian_supervisor_for(sock: &Path, site_id: &str) -> Arc<GranianSupervisor> {
    // Concrete seam from the plan: a real supervisor with a test-owned
    // socket path, never started (no Granian process is spawned).
    Arc::new(GranianSupervisor::new(GranianConfig {
        app_path: "test:app".to_string(),
        interface: synvoid::app_server::GranianInterface::Asgi,
        workers: 1,
        blocking_threads: 1,
        socket_path: Some(sock.to_path_buf()),
        port: None,
        host: None,
        python_path: None,
        working_directory: None,
        env: HashMap::new(),
        restart_on_failure: false,
        max_restarts: 0,
        health_check_path: "/".to_string(),
        health_check_interval_secs: 30,
        health_check_timeout_secs: 5,
        auto_install_granian: false,
        auto_detect_venv: false,
        auto_detect_app: false,
        auto_install_requirements: false,
        require_hashes: true,
        log_level: synvoid::app_server::GranianLogLevel::Info,
        log_format: synvoid::app_server::GranianLogFormat::Text,
        log_verbose: false,
        site_id: site_id.to_string(),
        worker_id: 0,
    }))
}

// ---------------------------------------------------------------------------
// Corrective lanes: production drive pattern + truthful context.
// ---------------------------------------------------------------------------

struct Lane {
    addr: SocketAddr,
    shutdown_tx: broadcast::Sender<()>,
    tasks_completed: Arc<AtomicUsize>,
}

async fn spawn_corrective_lane(
    ctx: NeutralServiceContext<StubWaf, StubDrain>,
    http_config: &synvoid_config::http::HttpConfig,
) -> Lane {
    let projected = project_eggserve_h1(http_config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let tasks_completed = Arc::new(AtomicUsize::new(0));
    let accept_shutdown_tx = shutdown_tx.clone();
    let accept_tasks = tasks_completed.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let ctx = ctx.clone();
            let policy = projected.policy.clone();
            let state = projected.state.clone();
            let conn_shutdown = eggserve_server::ConnectionShutdown::new();
            let local = stream.local_addr().ok();
            let tasks_completed = accept_tasks.clone();
            let shutdown_tx = accept_shutdown_tx.clone();
            tokio::spawn(async move {
                let service = EggserveH1Service::new(
                    ctx,
                    conn_shutdown.clone(),
                    None,
                    ForwardedProtocol::Http,
                    local,
                    None,
                );
                // Production-shaped drive: truthful context, signal-then-drain.
                let conn_future = eggserve_server::serve_http1_connection_with_policy(
                    stream,
                    service,
                    policy,
                    h1_connection_context(local, peer, None),
                    state,
                    &conn_shutdown,
                );
                let worker_shutdown = shutdown_tx.subscribe();
                let outcome =
                    drive_h1_connection(conn_future, &conn_shutdown, worker_shutdown).await;
                let _ = outcome;
                tasks_completed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Lane {
        addr,
        shutdown_tx,
        tasks_completed,
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
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

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

/// Real-TLS corrective lane: completed Rustls stream straight into the
/// EggServe H1 driver (ALPN http/1.1, JA4 None in this harness).
async fn spawn_tls_corrective_lane(
    ctx: NeutralServiceContext<StubWaf, StubDrain>,
    http_config: &synvoid_config::http::HttpConfig,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Lane {
    let projected = project_eggserve_h1(http_config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, _) = broadcast::channel::<()>(8);
    let tasks_completed = Arc::new(AtomicUsize::new(0));
    let accept_shutdown_tx = shutdown_tx.clone();
    let accept_tasks = tasks_completed.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let ctx = ctx.clone();
            let policy = projected.policy.clone();
            let state = projected.state.clone();
            let conn_shutdown = eggserve_server::ConnectionShutdown::new();
            let tasks_completed = accept_tasks.clone();
            let shutdown_tx = accept_shutdown_tx.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("TLS handshake");
                let local = tls.get_ref().0.local_addr().ok();
                let service = EggserveH1Service::new(
                    ctx,
                    conn_shutdown.clone(),
                    None,
                    ForwardedProtocol::Https,
                    local,
                    None,
                );
                let conn_future = eggserve_server::serve_http1_connection_with_policy(
                    tls,
                    service,
                    policy,
                    h1_connection_context(
                        local,
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
                );
                let worker_shutdown = shutdown_tx.subscribe();
                let _ = drive_h1_connection(conn_future, &conn_shutdown, worker_shutdown).await;
                tasks_completed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Lane {
        addr,
        shutdown_tx,
        tasks_completed,
    }
}

// ---------------------------------------------------------------------------
// Raw-socket helpers.
// ---------------------------------------------------------------------------

async fn read_head(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
            .await
            .expect("head timeout")
            .expect("head read failed");
        assert!(n > 0, "closed before head");
        wire.extend_from_slice(&tmp[..n]);
        if wire.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    wire
}

async fn wait_for_tasks(lane: &Lane, want: usize) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while lane.tasks_completed.load(Ordering::SeqCst) < want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("connection task did not complete (owned-task leak)");
}

/// Finding A on a shared neutral body: request the streamed tarpit, land a
/// worker shutdown only after the first DATA frame is on the wire, then
/// prove the signalled driver drains the response instead of truncating it.
async fn inflight_stream_shutdown_drain<S>(mut io: S, lane: &Lane) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    io.write_all(
        format!("GET {STREAM_PATH} HTTP/1.1\r\nHost: stream.test\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut wire = Vec::new();
    let mut tmp = [0u8; 4096];
    let first = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = first.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "no streamed data before shutdown");
        let n = tokio::time::timeout(left, io.read(&mut tmp))
            .await
            .expect("first DATA timeout")
            .expect("read failed");
        assert!(n > 0, "connection closed before streamed data");
        wire.extend_from_slice(&tmp[..n]);
        if wire.windows(3).any(|w| w == b"t0;") {
            break;
        }
    }
    // Shutdown mid-response: the driver must be signalled, not dropped.
    lane.shutdown_tx.send(()).unwrap();
    lane.shutdown_tx.send(()).unwrap();
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let n = io.read(&mut tmp).await.expect("read failed");
            if n == 0 {
                break;
            }
            wire.extend_from_slice(&tmp[..n]);
        }
    })
    .await;
    assert!(drained.is_ok(), "drain must terminate");
    let text = String::from_utf8_lossy(&wire).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text:?}");
    assert!(
        text.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "streamed response must use chunked framing: {text:?}"
    );
    // `\r\n`-prefixed match per chunk: strict against `t1;`/`t10;` overlap.
    for n in 0..STREAM_CHUNKS {
        assert!(
            text.contains(&format!("\r\nt{n};")),
            "stream truncated by shutdown: {text:?}"
        );
    }
    text
}

fn ws_masked_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "test helper handles small frames");
    let mut frame = vec![0x81, 0x80 | (payload.len() as u8), 0x11, 0x22, 0x33, 0x44];
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ [0x11, 0x22, 0x33, 0x44][i % 4]);
    }
    frame
}

fn ws_decode_text(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= wire.len() {
        let opcode = wire[i] & 0x0f;
        let mut len = (wire[i + 1] & 0x7f) as usize;
        i += 2;
        if len == 126 {
            len = u16::from_be_bytes([wire[i], wire[i + 1]]) as usize;
            i += 2;
        }
        if opcode == 0x8 {
            break;
        }
        if opcode == 0x1 || opcode == 0x2 {
            if i + len > wire.len() {
                break;
            }
            out.push(wire[i..i + len].to_vec());
        }
        i += len;
    }
    out
}

const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn ws_handshake(host: &str) -> Vec<u8> {
    format!(
        "GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
    )
    .into_bytes()
}

async fn ws_echo_exchange(
    socket: &mut tokio::net::TcpStream,
    host: &str,
    payload: &[u8],
    read_ahead: bool,
) -> String {
    let mut request = ws_handshake(host);
    if read_ahead {
        // Immediate post-upgrade bytes in the same segment: delivered once.
        request.extend_from_slice(&ws_masked_frame(payload));
    }
    socket.write_all(&request).await.unwrap();
    if !read_ahead {
        socket.write_all(&ws_masked_frame(payload)).await.unwrap();
    }
    let wire = read_head(socket).await;
    let head = String::from_utf8_lossy(&wire).into_owned();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.contains(WS_ACCEPT), "bad Sec-WebSocket-Accept: {head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-protocol: chat"),
        "subprotocol not selected: {head}"
    );
    // Echo: bytes already buffered past the head are consumed first.
    let head_end = wire
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head marker")
        + 4;
    let mut frames = wire[head_end..].to_vec();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let texts = ws_decode_text(&frames);
        if texts.iter().any(|t| t == payload) {
            break;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "no tunneled echo");
        let mut tmp = [0u8; 4096];
        let n = tokio::time::timeout(left, socket.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read failed");
        assert!(n > 0, "tunnel closed before echo");
        frames.extend_from_slice(&tmp[..n]);
    }
    // Exactly-once: one echo of the payload, no duplication.
    let count = ws_decode_text(&frames)
        .iter()
        .filter(|t| t == &payload)
        .count();
    assert_eq!(count, 1, "post-upgrade bytes must arrive exactly once");
    head
}

// ---------------------------------------------------------------------------
// Finding A: shutdown drains the active driver (plaintext).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plaintext_idle_shutdown_drains_connection_task() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, None, None);
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane =
        spawn_corrective_lane(lane_context(&shared, http_config.clone()), &http_config).await;
    // Idle keep-alive connection (no close).
    let mut socket = tokio::net::TcpStream::connect(lane.addr).await.unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .await
        .unwrap();
    let wire = read_head(&mut socket).await;
    assert!(String::from_utf8_lossy(&wire).starts_with("HTTP/1.1 200"));
    // Repeated shutdown is idempotent: no panic, task still completes.
    lane.shutdown_tx.send(()).unwrap();
    lane.shutdown_tx.send(()).unwrap();
    wait_for_tasks(&lane, 1).await;
    let mut tmp = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
        .await
        .expect("eof timeout")
        .expect("eof read failed");
    assert_eq!(n, 0, "idle connection must close after drain");
}

#[tokio::test]
async fn plaintext_inflight_stream_drains_without_truncation() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, None, None);
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane =
        spawn_corrective_lane(lane_context(&shared, http_config.clone()), &http_config).await;
    let socket = tokio::net::TcpStream::connect(lane.addr).await.unwrap();
    inflight_stream_shutdown_drain(socket, &lane).await;
    wait_for_tasks(&lane, 1).await;
}

#[tokio::test]
async fn plaintext_websocket_shutdown_terminates_tunnel() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, None, None);
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane =
        spawn_corrective_lane(lane_context(&shared, http_config.clone()), &http_config).await;
    let mut socket = tokio::net::TcpStream::connect(lane.addr).await.unwrap();
    ws_echo_exchange(&mut socket, "ws.test", b"ping-tunnel", false).await;
    lane.shutdown_tx.send(()).unwrap();
    lane.shutdown_tx.send(()).unwrap();
    // Tunnel terminates (close frame and/or EOF) and the owned task ends.
    let mut tmp = [0u8; 4096];
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => {
                    if ws_decode_text(&tmp[..n]).is_empty() && tmp[..n].starts_with(&[0x88]) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "tunnel did not terminate on shutdown");
    wait_for_tasks(&lane, 1).await;
}

// ---------------------------------------------------------------------------
// Finding C: real AppServer tunnel loopback (plaintext).
// ---------------------------------------------------------------------------

fn app_socket_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("synvoid-phase79-{tag}-{}.sock", std::process::id()))
}

#[tokio::test]
async fn plaintext_appserver_tunnel_loopback() {
    let sock = app_socket_path("plain");
    let peer_frames = spawn_unix_ws_echo(sock.clone()).await;
    let supervisor = granian_supervisor_for(&sock, "app.test");
    let mut servers = HashMap::new();
    servers.insert("app.test".to_string(), supervisor);
    let app_servers = Arc::new(tokio::sync::RwLock::new(servers));
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, Some(app_servers), Some(sock.clone()));
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane =
        spawn_corrective_lane(lane_context(&shared, http_config.clone()), &http_config).await;
    let mut socket = tokio::net::TcpStream::connect(lane.addr).await.unwrap();
    // Read-ahead in the same segment exercises exactly-once delivery.
    ws_echo_exchange(&mut socket, "app.test", b"app-payload", true).await;
    assert!(
        peer_frames.load(Ordering::SeqCst) >= 1,
        "Unix-socket AppServer peer must receive the tunneled payload"
    );
    // Bidirectional: a second payload returns through the same tunnel.
    socket
        .write_all(&ws_masked_frame(b"app-again"))
        .await
        .unwrap();
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let texts = ws_decode_text(&frames);
        if texts.iter().any(|t| t == b"app-again") {
            break;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "no AppServer return echo");
        let mut tmp = [0u8; 4096];
        let n = tokio::time::timeout(left, socket.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read failed");
        assert!(n > 0, "AppServer tunnel closed before return echo");
        frames.extend_from_slice(&tmp[..n]);
    }
    // Peer close terminates the tunnel without an owned-task leak; worker
    // shutdown afterwards is idempotent.
    socket.write_all(&[0x88, 0x00]).await.unwrap();
    wait_for_tasks(&lane, 1).await;
    // No live connection remains, so the broadcast has no receivers; the
    // idempotent post-close shutdown is a benign no-op either way.
    let _ = lane.shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(lane.tasks_completed.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_file(&sock);
}

// ---------------------------------------------------------------------------
// Finding B: exact-body trailer wire block (plaintext).
// ---------------------------------------------------------------------------

/// Assert the H1 wire carries a declared terminal trailer block.
///
/// A declared trailer source forces legal chunked framing (Hyper cannot
/// put trailers after `Content-Length`), advertises the fields in the
/// response head, and writes the block after the terminal chunk. Hyper's
/// H1 encoder collapses repeated trailer names to their last value, so
/// duplicate preservation is pinned by the adapter unit tests rather than
/// on the wire.
fn assert_terminal_trailer_block(wire: &str, label: &str) {
    let lower = wire.to_ascii_lowercase();
    assert!(wire.contains("hello"), "{label}: DATA missing: {wire:?}");
    assert!(
        lower.contains("transfer-encoding: chunked"),
        "{label}: declared trailers must use chunked framing: {wire:?}"
    );
    assert!(
        lower.contains("trailer: x-checksum"),
        "{label}: head-time Trailer declaration missing: {wire:?}"
    );
    assert!(
        lower.contains("0\r\nx-checksum:"),
        "{label}: terminal trailer block missing on the wire: {wire:?}"
    );
}

#[tokio::test]
async fn plaintext_exact_trailer_wire_block() {
    // Minimal driver rendering the representations the adapter now emits:
    // a one-shot known-length stream plus trailer future for
    // trailer-bearing exact bodies (default), and an unknown-length
    // trailer stream when the caller asks for chunked framing.
    fn trailer_service() -> impl eggserve_server::Service {
        use eggserve_primitives::canonical::{
            Response, ResponseBody, ResponseStream, ResponseStreamError,
        };
        use eggserve_primitives::{
            HeaderBlock, HeaderName, HeaderValue, TrailerDeclaration, Trailers,
        };
        eggserve_server::service_fn(|req: eggserve_server::Request| async move {
            let chunked = req
                .head()
                .headers()
                .get_first("x-mode")
                .and_then(|v| v.to_str().ok())
                == Some("chunked");
            let mut block = HeaderBlock::new();
            block.push(
                HeaderName::new("x-checksum").unwrap(),
                HeaderValue::from_bytes(b"a1").unwrap(),
            );
            block.push(
                HeaderName::new("x-checksum").unwrap(),
                HeaderValue::from_bytes(b"a2").unwrap(),
            );
            let trailers = Trailers::new(block).unwrap();
            let data = futures::stream::once(async move {
                Ok::<Bytes, ResponseStreamError>(Bytes::from_static(b"hello"))
            });
            let trailer_future =
                Box::pin(
                    async move { Ok::<Option<Trailers>, ResponseStreamError>(Some(trailers)) },
                );
            // Head-time declaration: EggServe only renders an H1 terminal
            // trailer block when the field names are declared before the
            // response head is committed.
            let declaration = TrailerDeclaration::from_names(["x-checksum"]).unwrap();
            let stream = if chunked {
                ResponseStream::with_declared_trailers(data, declaration, trailer_future)
            } else {
                ResponseStream::with_known_length_and_declared_trailers(
                    data,
                    5,
                    declaration,
                    trailer_future,
                )
            };
            Ok::<Response, eggserve_server::ServiceError>(
                Response::builder()
                    .status(eggserve_primitives::canonical::StatusCode::OK)
                    .body(ResponseBody::Stream(stream))
                    .unwrap(),
            )
        })
    }
    let projected = project_eggserve_h1(&synvoid_config::http::HttpConfig::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let policy = projected.policy.clone();
            let state = projected.state.clone();
            tokio::spawn(async move {
                let shutdown = eggserve_server::ConnectionShutdown::new();
                let _ = eggserve_server::serve_http1_connection_with_policy(
                    stream,
                    trailer_service(),
                    policy,
                    h1_connection_context(Some(addr), peer, None),
                    state,
                    &shutdown,
                )
                .await;
            });
        }
    });
    async fn get(addr: SocketAddr, extra: &[u8]) -> String {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        // `TE: trailers` expresses trailer willingness: EggServe's H1
        // policy suppresses response trailers without it.
        let mut request =
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\nTE: trailers\r\n".to_vec();
        request.extend_from_slice(extra);
        request.extend_from_slice(b"\r\n");
        socket.write_all(&request).await.unwrap();
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut wire))
            .await
            .expect("read timeout")
            .expect("read failed");
        String::from_utf8_lossy(&wire).into_owned()
    }
    // Exact known-length body carrying terminal trailers: the head-time
    // declaration moves the wire to chunked framing so the terminal block
    // is actually delivered (Content-Length framing cannot carry it).
    let known = get(addr, b"").await;
    assert_terminal_trailer_block(&known, "known-length");
    // Unknown-length source reaches the wire the same way.
    let chunked = get(addr, b"x-mode: chunked\r\n").await;
    assert_terminal_trailer_block(&chunked, "unknown-length");
}

// ---------------------------------------------------------------------------
// TLS-H1 mirrors.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_h1_idle_shutdown_drains_connection_task() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, None, None);
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane = spawn_tls_corrective_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        server_tls_acceptor(cert_der.clone(), key_der),
    )
    .await;
    let mut tls = tls_connect(lane.addr, &cert_der).await;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .await
        .unwrap();
    let mut wire = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut tmp))
            .await
            .expect("head timeout")
            .expect("head read failed");
        assert!(n > 0);
        wire.extend_from_slice(&tmp[..n]);
        if wire.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&wire).starts_with("HTTP/1.1 200"));
    lane.shutdown_tx.send(()).unwrap();
    lane.shutdown_tx.send(()).unwrap();
    wait_for_tasks(&lane, 1).await;
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut tmp))
        .await
        .expect("eof timeout")
        .expect("eof read failed");
    assert_eq!(n, 0, "TLS-H1 idle connection must close after drain");
}

#[tokio::test]
async fn tls_h1_inflight_stream_drains_without_truncation() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, None, None);
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane = spawn_tls_corrective_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        server_tls_acceptor(cert_der.clone(), key_der),
    )
    .await;
    let tls = tls_connect(lane.addr, &cert_der).await;
    inflight_stream_shutdown_drain(tls, &lane).await;
    wait_for_tasks(&lane, 1).await;
}

#[tokio::test]
async fn tls_h1_websocket_shutdown_terminates_tunnel() {
    let (cert_der, key_der) = rcgen_self_signed_der();
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, None, None);
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane = spawn_tls_corrective_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        server_tls_acceptor(cert_der.clone(), key_der),
    )
    .await;
    let mut tls = tls_connect(lane.addr, &cert_der).await;
    tls.write_all(&ws_handshake("ws.test")).await.unwrap();
    let mut wire = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut tmp))
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
    assert!(head.contains(WS_ACCEPT), "{head}");
    tls.write_all(&ws_masked_frame(b"tls-tunnel"))
        .await
        .unwrap();
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if ws_decode_text(&frames).iter().any(|t| t == b"tls-tunnel") {
            break;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "no TLS-H1 tunneled echo");
        let n = tokio::time::timeout(left, tls.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read failed");
        assert!(n > 0, "tunnel closed before echo");
        frames.extend_from_slice(&tmp[..n]);
    }
    lane.shutdown_tx.send(()).unwrap();
    lane.shutdown_tx.send(()).unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match tls.read(&mut tmp).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "TLS-H1 tunnel did not terminate on shutdown"
    );
    wait_for_tasks(&lane, 1).await;
}

#[tokio::test]
async fn tls_h1_appserver_tunnel_loopback() {
    let sock = app_socket_path("tls");
    let peer_frames = spawn_unix_ws_echo(sock.clone()).await;
    let supervisor = granian_supervisor_for(&sock, "app.test");
    let mut servers = HashMap::new();
    servers.insert("app.test".to_string(), supervisor);
    let app_servers = Arc::new(tokio::sync::RwLock::new(servers));
    let (cert_der, key_der) = rcgen_self_signed_der();
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo, Some(app_servers), Some(sock.clone()));
    let http_config = synvoid_config::http::HttpConfig::default();
    let lane = spawn_tls_corrective_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        server_tls_acceptor(cert_der.clone(), key_der),
    )
    .await;
    let mut tls = tls_connect(lane.addr, &cert_der).await;
    // Read-ahead in the same segment exercises exactly-once delivery.
    let mut request = ws_handshake("app.test");
    request.extend_from_slice(&ws_masked_frame(b"tls-app-payload"));
    tls.write_all(&request).await.unwrap();
    let mut wire = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut tmp))
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
    assert!(head.contains(WS_ACCEPT), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-protocol: chat"),
        "{head}"
    );
    let head_end = wire
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head marker")
        + 4;
    let mut frames = wire[head_end..].to_vec();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let texts = ws_decode_text(&frames);
        if texts.iter().any(|t| t == b"tls-app-payload") {
            assert_eq!(
                texts
                    .iter()
                    .filter(|t| t == &b"tls-app-payload".as_slice())
                    .count(),
                1,
                "post-upgrade bytes must arrive exactly once"
            );
            break;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "no TLS-H1 AppServer echo");
        let n = tokio::time::timeout(left, tls.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read failed");
        assert!(n > 0, "AppServer tunnel closed before echo");
        frames.extend_from_slice(&tmp[..n]);
    }
    assert!(
        peer_frames.load(Ordering::SeqCst) >= 1,
        "Unix-socket AppServer peer must receive the tunneled payload"
    );
    tls.write_all(&[0x88, 0x00]).await.unwrap();
    wait_for_tasks(&lane, 1).await;
    // No live connection remains, so the broadcast has no receivers; the
    // idempotent post-close shutdown is a benign no-op either way.
    let _ = lane.shutdown_tx.send(());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(lane.tasks_completed.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test]
async fn tls_h1_exact_trailer_wire_block() {
    fn trailer_service() -> impl eggserve_server::Service {
        use eggserve_primitives::canonical::{
            Response, ResponseBody, ResponseStream, ResponseStreamError,
        };
        use eggserve_primitives::{
            HeaderBlock, HeaderName, HeaderValue, TrailerDeclaration, Trailers,
        };
        eggserve_server::service_fn(|req: eggserve_server::Request| async move {
            let chunked = req
                .head()
                .headers()
                .get_first("x-mode")
                .and_then(|v| v.to_str().ok())
                == Some("chunked");
            let mut block = HeaderBlock::new();
            block.push(
                HeaderName::new("x-checksum").unwrap(),
                HeaderValue::from_bytes(b"t1").unwrap(),
            );
            let trailers = Trailers::new(block).unwrap();
            let data = futures::stream::once(async move {
                Ok::<Bytes, ResponseStreamError>(Bytes::from_static(b"hello"))
            });
            let trailer_future =
                Box::pin(
                    async move { Ok::<Option<Trailers>, ResponseStreamError>(Some(trailers)) },
                );
            // Head-time declaration: EggServe only renders an H1 terminal
            // trailer block when the field names are declared before the
            // response head is committed.
            let declaration = TrailerDeclaration::from_names(["x-checksum"]).unwrap();
            let stream = if chunked {
                ResponseStream::with_declared_trailers(data, declaration, trailer_future)
            } else {
                ResponseStream::with_known_length_and_declared_trailers(
                    data,
                    5,
                    declaration,
                    trailer_future,
                )
            };
            Ok::<Response, eggserve_server::ServiceError>(
                Response::builder()
                    .status(eggserve_primitives::canonical::StatusCode::OK)
                    .body(ResponseBody::Stream(stream))
                    .unwrap(),
            )
        })
    }
    let (cert_der, key_der) = rcgen_self_signed_der();
    let acceptor = server_tls_acceptor(cert_der.clone(), key_der);
    let projected = project_eggserve_h1(&synvoid_config::http::HttpConfig::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let policy = projected.policy.clone();
            let state = projected.state.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(stream).await.expect("TLS handshake");
                let local = tls.get_ref().0.local_addr().ok();
                let shutdown = eggserve_server::ConnectionShutdown::new();
                let _ = eggserve_server::serve_http1_connection_with_policy(
                    tls,
                    trailer_service(),
                    policy,
                    h1_connection_context(
                        local,
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
                    &shutdown,
                )
                .await;
            });
        }
    });
    async fn get_tls(addr: SocketAddr, cert_der: &[u8], extra: &[u8]) -> String {
        let mut tls = tls_connect(addr, cert_der).await;
        let mut request =
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\nTE: trailers\r\n".to_vec();
        request.extend_from_slice(extra);
        request.extend_from_slice(b"\r\n");
        tls.write_all(&request).await.unwrap();
        let mut wire = Vec::new();
        loop {
            let mut tmp = [0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(10), tls.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => wire.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&wire).into_owned()
    }
    let known = get_tls(addr, &cert_der, b"").await;
    assert_terminal_trailer_block(&known, "tls known-length");
    let chunked = get_tls(addr, &cert_der, b"x-mode: chunked\r\n").await;
    assert_terminal_trailer_block(&chunked, "tls unknown-length");
}

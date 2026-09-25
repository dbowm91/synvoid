//! Root-test ownership: QUALIFICATION
//! Rationale: Phase 76 plaintext production adoption loopback. Covers the
//! matrix items beyond the Phase 75 differential: slow-header timeout
//! parity, parser maxima parity, streamed upstream parity, slow-drip
//! resilience, client disconnect, server shutdown, and end-to-end
//! tunneled WebSocket echo through the real pipeline on both lanes.
//!
//! The Hyper lane here is the narrow test-only differential lane (Track H),
//! removable at Phase 78; production plaintext is EggServe-driven.

use std::collections::HashMap;
use std::net::SocketAddr;
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
// Shared stub context (mirrors the differential harness with stub WAF).
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
        _path: &str,
        _query: Option<&str>,
        _headers: &http::HeaderMap,
        _body: Option<&[u8]>,
        _ua: Option<&str>,
        _ja4_hash: Option<&str>,
        _site_bot_config: Option<&synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
        synvoid_proxy::WafDecision::Pass
    }

    async fn check_request_full_owned(
        self: Arc<Self>,
        _site_id: Option<String>,
        _ip: std::net::IpAddr,
        _method: String,
        _path: String,
        _query: Option<String>,
        _headers: http::HeaderMap,
        _body: Option<Bytes>,
        _ua: Option<String>,
        _ja4_hash: Option<String>,
        _site_bot_config: Option<synvoid_config::site::SiteBotConfig>,
    ) -> synvoid_proxy::WafDecision {
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

struct Shared {
    router: Arc<Router>,
    waf: Arc<StubWaf>,
    main_config: Arc<MainConfig>,
    registry: Arc<UpstreamClientRegistry>,
}

fn build_shared(echo_addr: SocketAddr, ws_echo_addr: SocketAddr) -> Shared {
    let mut sites = HashMap::new();
    let mut site = SiteConfig::default_fallback_site(format!("http://{echo_addr}"));
    site.site.domains = vec!["a.test".to_string()];
    site.security_headers.server_token = Some("adopt".to_string());
    site.security_headers.date_header = Some(false);
    sites.insert("site-a".to_string(), site);
    // WebSocket upstream route for tunneled-echo parity.
    let mut ws_site = SiteConfig::default_fallback_site(format!("ws://{ws_echo_addr}/ws"));
    ws_site.site.domains = vec!["ws.test".to_string()];
    ws_site.security_headers.server_token = Some("adopt".to_string());
    ws_site.security_headers.date_header = Some(false);
    sites.insert("site-ws".to_string(), ws_site);
    let main_config = Arc::new(MainConfig::default());
    Shared {
        router: Arc::new(Router::new(&main_config, sites)),
        waf: Arc::new(StubWaf {
            theme: ThemeConfig::default(),
        }),
        main_config,
        registry: Arc::new(UpstreamClientRegistry::new()),
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
                        if path == "/stream" {
                            // Unknown-length chunked drip: three delayed frames.
                            let stream = futures::stream::unfold(0, |n| async move {
                                if n >= 3 {
                                    None
                                } else {
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                    Some((
                                        Ok::<_, std::convert::Infallible>(http_body::Frame::data(
                                            Bytes::from(format!("f{n};")),
                                        )),
                                        n + 1,
                                    ))
                                }
                            });
                            let resp: hyper::Response<EchoBody> = hyper::Response::builder()
                                .status(200)
                                .body(http_body_util::StreamBody::new(stream).boxed())
                                .unwrap();
                            return Ok::<_, std::convert::Infallible>(resp);
                        }
                        if path == "/drip" {
                            // Slow unbounded drip for disconnect resilience.
                            let stream = futures::stream::unfold(0u64, |n| async move {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                Some((
                                    Ok::<_, std::convert::Infallible>(http_body::Frame::data(
                                        Bytes::from(format!("d{n};")),
                                    )),
                                    n + 1,
                                ))
                            });
                            let resp: hyper::Response<EchoBody> = hyper::Response::builder()
                                .status(200)
                                .body(http_body_util::StreamBody::new(stream).boxed())
                                .unwrap();
                            return Ok::<_, std::convert::Infallible>(resp);
                        }
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

async fn spawn_hyper_lane(ctx: NeutralServiceContext<StubWaf, StubDrain>) -> SocketAddr {
    spawn_hyper_lane_with(ctx, synvoid_config::http::HttpConfig::default()).await
}

async fn spawn_hyper_lane_with(
    ctx: NeutralServiceContext<StubWaf, StubDrain>,
    http_config: synvoid_config::http::HttpConfig,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let ctx = ctx.clone();
            let http_config = http_config.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let ctx = ctx.clone();
                        async move {
                            let inbound = adapt_hyper_request(req);
                            let drop_noop: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
                            handle_neutral_request(
                                &ctx,
                                inbound,
                                peer.ip(),
                                Some(addr),
                                drop_noop,
                                None,
                                ForwardedProtocol::Http,
                                None,
                            )
                            .await
                        }
                    },
                );
                // Test-only Hyper lane keeps the production H1 policy helper.
                let mut builder = hyper::server::conn::http1::Builder::new();
                synvoid::http::h1_policy::configure_h1_builder(&mut builder, &http_config);
                // Test-only Hyper lane keeps upgrades enabled like production.
                let _ = builder.serve_connection(io, svc).with_upgrades().await;
            });
        }
    });
    addr
}

async fn spawn_eggserve_lane(
    ctx: NeutralServiceContext<StubWaf, StubDrain>,
    http_config: &synvoid_config::http::HttpConfig,
    last_shutdown: Arc<std::sync::Mutex<Option<eggserve_server::ConnectionShutdown>>>,
) -> SocketAddr {
    let projected = project_eggserve_h1(http_config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let ctx = ctx.clone();
            let policy = projected.policy.clone();
            let state = projected.state.clone();
            let conn_shutdown = eggserve_server::ConnectionShutdown::new();
            *last_shutdown.lock().unwrap() = Some(conn_shutdown.clone());
            tokio::spawn(async move {
                let service = EggserveH1Service::new(
                    ctx,
                    conn_shutdown.clone(),
                    None,
                    ForwardedProtocol::Http,
                    Some(addr),
                    None,
                );
                let _ = eggserve_server::serve_http1_connection_with_policy(
                    stream,
                    service,
                    policy,
                    eggserve_server::ConnectionContext::for_tcp(addr, peer, None),
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

async fn raw_exchange(addr: SocketAddr, request: &[u8]) -> String {
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), socket.read_to_end(&mut buf))
        .await
        .expect("read timeout")
        .expect("read failed");
    String::from_utf8_lossy(&buf).into_owned()
}

fn normalize_wire(wire: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut headers: Vec<&str> = Vec::new();
    let mut in_headers = false;
    for line in wire.lines() {
        if line.starts_with("HTTP/") {
            in_headers = true;
            out.push(line.to_string());
            continue;
        }
        if in_headers {
            if line.is_empty() {
                headers.sort_unstable();
                out.extend(headers.drain(..).map(str::to_string));
                out.push(String::new());
                in_headers = false;
            } else if line.contains(':') && !line.to_ascii_lowercase().starts_with("date:") {
                headers.push(line);
            } else if !line.to_ascii_lowercase().starts_with("date:") {
                out.push(line.to_string());
            }
        } else {
            out.push(line.to_string());
        }
    }
    if in_headers {
        headers.sort_unstable();
        out.extend(headers.drain(..).map(str::to_string));
    }
    out.join("\n")
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn slow_header_timeout_parity() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig {
        header_read_timeout_secs: 1,
        ..Default::default()
    };
    let hyper_addr = spawn_hyper_lane_with(
        lane_context(&shared, http_config.clone()),
        http_config.clone(),
    )
    .await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        shutdown_slot(),
    )
    .await;
    for addr in [hyper_addr, egg_addr] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /slow HTTP/1.1\r\nHost: a.test\r\n")
            .await
            .unwrap();
        // Stall past the 1s header timeout, then finish.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        socket
            .write_all(b"Connection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf)).await;
        let wire = String::from_utf8_lossy(&buf).into_owned();
        // Both lanes must refuse to serve a timed-out head: 408 or close.
        let timed_out = wire.starts_with("HTTP/1.1 408") || wire.is_empty();
        assert!(timed_out, "slow headers not refused: {wire:?}");
    }
}

#[tokio::test]
async fn parser_maxima_parity() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    // Header count ceiling well below SynVoid default, ingress ceiling wide
    // open to isolate the count parser bound.
    let count_config = synvoid_config::http::HttpConfig {
        max_headers: 8,
        max_header_size_ingress: 1024 * 1024,
        ..Default::default()
    };
    let hyper_addr = spawn_hyper_lane_with(
        lane_context(&shared, count_config.clone()),
        count_config.clone(),
    )
    .await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, count_config.clone()),
        &count_config,
        shutdown_slot(),
    )
    .await;
    let mut request = b"GET / HTTP/1.1\r\nHost: a.test\r\n".to_vec();
    for n in 0..10 {
        request.extend_from_slice(format!("x-h{n}: v\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    for addr in [hyper_addr, egg_addr] {
        let wire = raw_exchange(addr, &request).await;
        assert!(
            wire.starts_with("HTTP/1.1 431"),
            "header-count ceiling not enforced: {wire:?}"
        );
    }

    // Parser buffer ceiling: minimum 8 KiB buffer with a 16 KiB header
    // (mirrors the established parser-parity ratio).
    let buf_config = synvoid_config::http::HttpConfig {
        max_request_size: 8192,
        max_header_size_ingress: 1024 * 1024,
        ..Default::default()
    };
    let hyper_addr = spawn_hyper_lane_with(
        lane_context(&shared, buf_config.clone()),
        buf_config.clone(),
    )
    .await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, buf_config.clone()),
        &buf_config,
        shutdown_slot(),
    )
    .await;
    let big = format!(
        "GET / HTTP/1.1\r\nHost: a.test\r\nx-big: {}\r\nConnection: close\r\n\r\n",
        "z".repeat(16 * 1024)
    );
    // Buffer overflow kills the connection at the parser (RST/empty is a
    // rejection); assert per-lane refusal rather than a specific status.
    for addr in [hyper_addr, egg_addr] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket.write_all(big.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(15), socket.read_to_end(&mut buf)).await;
        let refused = match read {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok(_)) => {
                let wire = String::from_utf8_lossy(&buf).into_owned();
                !wire.starts_with("HTTP/1.1 200")
            }
        };
        assert!(refused, "parser-buffer ceiling not enforced");
    }
}

#[tokio::test]
async fn streamed_upstream_parity() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(lane_context(&shared, http_config.clone())).await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        shutdown_slot(),
    )
    .await;
    let request = b"GET /stream HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n";
    let hyper_wire = raw_exchange(hyper_addr, request).await;
    let egg_wire = raw_exchange(egg_addr, request).await;
    assert!(hyper_wire.contains("f0;f1;f2;"), "{hyper_wire}");
    assert_eq!(normalize_wire(&hyper_wire), normalize_wire(&egg_wire));
}

#[tokio::test]
async fn client_disconnect_resilience() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    for lane in ["hyper", "eggserve"] {
        let addr = if lane == "hyper" {
            spawn_hyper_lane(lane_context(&shared, http_config.clone())).await
        } else {
            spawn_eggserve_lane(
                lane_context(&shared, http_config.clone()),
                &http_config,
                shutdown_slot(),
            )
            .await
        };
        // Abrupt mid-body disconnect, then a slow-drip read abandoned
        // halfway, then proof the lane still serves.
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 100\r\n\r\npartia",
            )
            .await
            .unwrap();
        drop(socket);
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /drip HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut tmp)).await;
        drop(socket);
        let wire = raw_exchange(
            addr,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
    }
}

#[tokio::test]
async fn server_shutdown_closes_idle_connection() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let slot = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        slot.clone(),
    )
    .await;
    // Idle keep-alive connection (no close).
    let mut socket = tokio::net::TcpStream::connect(egg_addr).await.unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .await
        .unwrap();
    let mut tmp = [0u8; 4096];
    let mut head = Vec::new();
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read failed");
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    // Worker shutdown fires the connection token: EOF follows.
    let token = slot
        .lock()
        .unwrap()
        .clone()
        .expect("connection registered a token");
    token.shutdown();
    let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
        .await
        .expect("eof timeout")
        .expect("eof read failed");
    assert_eq!(n, 0, "idle connection must close on worker shutdown");
}

fn ws_masked_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "test helper handles small frames");
    let mut frame = vec![0x81, 0x80 | (payload.len() as u8), 0x11, 0x22, 0x33, 0x44];
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ [0x11, 0x22, 0x33, 0x44][i % 4]);
    }
    frame
}

fn ws_masked_frame_big(payload: &[u8]) -> Vec<u8> {
    // 16-bit extended length client frame.
    assert!(payload.len() < 65536);
    let len = payload.len() as u16;
    let mut frame = vec![
        0x81,
        0x80 | 126,
        (len >> 8) as u8,
        (len & 0xff) as u8,
        0x11,
        0x22,
        0x33,
        0x44,
    ];
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
            out.push(wire[i..i + len].to_vec());
        }
        i += len;
    }
    out
}

#[tokio::test]
async fn tunneled_websocket_echo_parity() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(lane_context(&shared, http_config.clone())).await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        shutdown_slot(),
    )
    .await;
    for addr in [hyper_addr, egg_addr] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
            )
            .await
            .unwrap();
        let mut wire = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
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
        // Full tunneled echo through the upstream WS server.
        socket
            .write_all(&ws_masked_frame(b"ping-tunnel"))
            .await
            .unwrap();
        let mut frames = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let texts = loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(!left.is_zero(), "echo timeout without frames");
            let mut tmp = [0u8; 4096];
            let n = tokio::time::timeout(left, socket.read(&mut tmp))
                .await
                .expect("echo timeout")
                .expect("echo read failed");
            assert!(n > 0, "tunnel closed before echo");
            frames.extend_from_slice(&tmp[..n]);
            let texts = ws_decode_text(&frames);
            if !texts.is_empty() {
                break texts;
            }
        };
        assert!(
            texts.iter().any(|t| t == b"ping-tunnel"),
            "no tunneled echo"
        );
        drop(socket);
    }
}

async fn ws_tunnel_echo(addr: SocketAddr, payload: &[u8], big: bool) -> Vec<Vec<u8>> {
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
        )
        .await
        .unwrap();
    let mut wire = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
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
    let frame = if big {
        ws_masked_frame_big(payload)
    } else {
        ws_masked_frame(payload)
    };
    socket.write_all(&frame).await.unwrap();
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "echo timeout without frames");
        let n = tokio::time::timeout(left, socket.read(&mut tmp))
            .await
            .expect("echo timeout")
            .expect("echo read failed");
        assert!(n > 0, "tunnel closed before echo");
        frames.extend_from_slice(&tmp[..n]);
        let texts = ws_decode_text(&frames);
        if !texts.is_empty() {
            return texts;
        }
    }
}

#[tokio::test]
async fn tunneled_large_message_parity() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(lane_context(&shared, http_config.clone())).await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone()),
        &http_config,
        shutdown_slot(),
    )
    .await;
    // 60 KiB message across the 64 KiB WAF scan chunking (16-bit lengths
    // both ways; the test decoder handles 126, not 127).
    let big = vec![b'm'; 60 * 1024];
    for addr in [hyper_addr, egg_addr] {
        let texts = ws_tunnel_echo(addr, &big, true).await;
        assert!(texts.iter().any(|t| t == &big), "no large tunneled echo");
    }
}

#[tokio::test]
async fn tunneled_half_close_and_resilience() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    for addr in [
        spawn_hyper_lane(lane_context(&shared, http_config.clone())).await,
        spawn_eggserve_lane(
            lane_context(&shared, http_config.clone()),
            &http_config,
            shutdown_slot(),
        )
        .await,
    ] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        let mut wire = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
                .await
                .expect("handshake timeout")
                .expect("read failed");
            assert!(n > 0);
            wire.extend_from_slice(&tmp[..n]);
            if wire.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&wire).starts_with("HTTP/1.1 101"));
        // Client close frame: tunnel must end without hanging the lane.
        socket
            .write_all(&[0x88, 0x80, 0x11, 0x22, 0x33, 0x44])
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf)).await;
        // Lane survives: fresh exchange works.
        let wire = raw_exchange(
            addr,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
    }
}

#[tokio::test]
async fn tunneled_concurrent_tunnels() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    for addr in [
        spawn_hyper_lane(lane_context(&shared, http_config.clone())).await,
        spawn_eggserve_lane(
            lane_context(&shared, http_config.clone()),
            &http_config,
            shutdown_slot(),
        )
        .await,
    ] {
        let mut handles = Vec::new();
        for n in 0..3u8 {
            let payload = vec![b't' + n; 32];
            handles.push(tokio::spawn(async move {
                let texts = ws_tunnel_echo(addr, &payload, false).await;
                assert!(texts.iter().any(|t| t == &payload));
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }
}

#[tokio::test]
async fn slow_reader_gets_full_stream() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    for addr in [
        spawn_hyper_lane(lane_context(&shared, http_config.clone())).await,
        spawn_eggserve_lane(
            lane_context(&shared, http_config.clone()),
            &http_config,
            shutdown_slot(),
        )
        .await,
    ] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /stream HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .unwrap();
        // One byte at a time with pauses: backpressure must not corrupt.
        let mut out = Vec::new();
        let mut one = [0u8; 1];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(!left.is_zero(), "stream stall");
            let n = tokio::time::timeout(left, socket.read(&mut one))
                .await
                .expect("read timeout")
                .expect("read failed");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&one[..n]);
            if out.len() > 9 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("f0;f1;f2;"), "{text}");
        drop(socket);
    }
}

#[tokio::test]
async fn drip_disconnect_resilience() {
    let echo = spawn_upstream_echo().await;
    let ws_echo = spawn_ws_echo().await;
    let shared = build_shared(echo, ws_echo);
    let http_config = synvoid_config::http::HttpConfig::default();
    for addr in [
        spawn_hyper_lane(lane_context(&shared, http_config.clone())).await,
        spawn_eggserve_lane(
            lane_context(&shared, http_config.clone()),
            &http_config,
            shutdown_slot(),
        )
        .await,
    ] {
        // Abandon a slow drip mid-response; lane must keep serving.
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /drip HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut tmp)).await;
        drop(socket);
        let wire = raw_exchange(
            addr,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
    }
}

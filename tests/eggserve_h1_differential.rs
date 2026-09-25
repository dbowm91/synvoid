//! Root-test ownership: QUALIFICATION
//! Rationale: Phase 75 Track K differential qualification. The same scripted
//! corpus runs through the Hyper H1 lane and the EggServe direct H1 lane,
//! both sharing the neutral pipeline via `service_core`; only transport
//! capture differs. Production stays on Hyper throughout.
//!
//! Note (Phase 76 Track H): the Hyper lane harness here doubles as the
//! narrow test-only differential lane for the adoption phases; it is not
//! an operator config, flag, fallback, or second listener, and is removable
//! at Phase 78 after final A/B evidence is captured.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
// Scripted stub WAF: deterministic Pass plus scripted Block/Drop paths.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StubWaf {
    theme: ThemeConfig,
    drop_decisions: Arc<AtomicUsize>,
}

impl synvoid_http::request_parse::EarlyWafHooks for StubWaf {
    fn verify_trust_token(&self, _client_ip: IpAddr, _token: &str) -> bool {
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
        _ip: &IpAddr,
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
        _ip: IpAddr,
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
        _ip: IpAddr,
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
        if path.starts_with("/waf-block") {
            synvoid_proxy::WafDecision::Block(403, "stub blocked".to_string())
        } else if path.starts_with("/waf-drop") {
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

// ---------------------------------------------------------------------------
// Shared context: two sites (upstream echo + distinct Date/Server policy)
// ---------------------------------------------------------------------------

struct SharedParts {
    router: Arc<Router>,
    waf: Arc<StubWaf>,
    main_config: Arc<MainConfig>,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
}

fn site_with_policy(
    domains: Vec<String>,
    upstream: String,
    server_token: Option<String>,
    date_header: Option<bool>,
) -> SiteConfig {
    let mut site = SiteConfig::default_fallback_site(upstream);
    site.site.domains = domains;
    site.security_headers.server_token = server_token;
    // Note: `date_header = false` governs SynVoid-generated Date output;
    // relayed upstream Date values pass through untouched in production on
    // both lanes (pinned by this corpus).
    site.security_headers.date_header = date_header;
    site.security_headers.content_security_policy = Some("default-src 'none'".to_string());
    site.security_headers.enabled = Some(true);
    site
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
                        let mut resp =
                            hyper::Response::new(http_body_util::Full::new(Bytes::from(text)));
                        resp.headers_mut()
                            .append("set-cookie", "e1=1".parse::<http::HeaderValue>().unwrap());
                        resp.headers_mut()
                            .append("set-cookie", "e2=2".parse::<http::HeaderValue>().unwrap());
                        resp.headers_mut().insert(
                            "last-modified",
                            "Sun, 06 Nov 1994 08:49:37 GMT"
                                .parse::<http::HeaderValue>()
                                .unwrap(),
                        );
                        resp.headers_mut().insert(
                            "cache-control",
                            "no-store".parse::<http::HeaderValue>().unwrap(),
                        );
                        Ok::<_, std::convert::Infallible>(resp)
                    },
                );
                // Wide-open parser: the echo must accept whatever the lanes
                // forward, so rejections differentially attribute to the
                // lanes under test, never to this fixture.
                let mut builder = hyper::server::conn::http1::Builder::new();
                builder.max_buf_size(16 * 1024 * 1024);
                builder.max_headers(100_000);
                let _ = builder.serve_connection(io, svc).await;
            });
        }
    });
    addr
}

fn build_shared(echo_addr: SocketAddr, drop_decisions: Arc<AtomicUsize>) -> SharedParts {
    let upstream = format!("http://{echo_addr}");
    let mut sites = HashMap::new();
    sites.insert(
        "site-a".to_string(),
        site_with_policy(
            vec!["a.test".to_string()],
            upstream.clone(),
            Some("diff-alpha".to_string()),
            Some(false),
        ),
    );
    sites.insert(
        "site-b".to_string(),
        site_with_policy(
            vec!["b.test".to_string()],
            upstream,
            Some("diff-beta".to_string()),
            Some(true),
        ),
    );
    // No-token site for metadata-absence parity.
    sites.insert(
        "site-c".to_string(),
        site_with_policy(
            vec!["c.test".to_string()],
            format!("http://{echo_addr}"),
            None,
            Some(false),
        ),
    );
    // Dead upstream for failure parity (port 1 is closed).
    sites.insert(
        "site-dead".to_string(),
        site_with_policy(
            vec!["dead.test".to_string()],
            "http://127.0.0.1:1".to_string(),
            None,
            Some(false),
        ),
    );
    let main_config = Arc::new(MainConfig::default());
    let router = Arc::new(Router::new(&main_config, sites));
    SharedParts {
        router,
        waf: Arc::new(StubWaf {
            theme: ThemeConfig::default(),
            drop_decisions,
        }),
        main_config,
        upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
    }
}

fn lane_context(
    shared: &SharedParts,
    http_config: synvoid_config::http::HttpConfig,
    permits: usize,
) -> NeutralServiceContext<StubWaf, StubDrain> {
    NeutralServiceContext {
        router: Arc::clone(&shared.router),
        waf: Arc::clone(&shared.waf),
        alt_svc: Some("h3=\":443\"".to_string()),
        main_config: Arc::clone(&shared.main_config),
        http_config,
        metrics: None,
        ipc: None,
        worker_id: None,
        drain_state: Some(Arc::new(StubDrain)),
        upstream_client_registry: Arc::clone(&shared.upstream_client_registry),
        connection_limit: Arc::new(Semaphore::new(permits)),
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
// Lanes
// ---------------------------------------------------------------------------

async fn spawn_hyper_lane(
    ctx: NeutralServiceContext<StubWaf, StubDrain>,
    hyper_drops: Arc<AtomicUsize>,
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
            let hyper_drops = hyper_drops.clone();
            let http_config = http_config.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let ctx = ctx.clone();
                        let hyper_drops = hyper_drops.clone();
                        async move {
                            let inbound = adapt_hyper_request(req);
                            let request_drop: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                                hyper_drops.fetch_add(1, Ordering::SeqCst);
                            });
                            handle_neutral_request(
                                &ctx,
                                inbound,
                                peer.ip(),
                                Some(addr),
                                request_drop,
                                None,
                                ForwardedProtocol::Http,
                                None,
                            )
                            .await
                        }
                    },
                );
                // Test-only lane keeps the production H1 policy mapping so
                // parser bounds match the EggServe-projected lane.
                let mut builder = hyper::server::conn::http1::Builder::new();
                synvoid::http::h1_policy::configure_h1_builder(&mut builder, &http_config);
                let _ = builder.serve_connection(io, svc).await;
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

// Helper: fresh per-test shutdown capture for the EggServe lane.
fn shutdown_slot() -> Arc<std::sync::Mutex<Option<eggserve_server::ConnectionShutdown>>> {
    Arc::new(std::sync::Mutex::new(None))
}

// ---------------------------------------------------------------------------
// Corpus runner with date-stripped normalization
// ---------------------------------------------------------------------------

async fn raw_exchange(addr: SocketAddr, request: &[u8]) -> String {
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf))
        .await
        .expect("read timeout")
        .expect("read failed");
    String::from_utf8_lossy(&buf).into_owned()
}

fn normalize_wire(wire: &str) -> String {
    // Adjudicated normalization (Track K): header ORDER is allowed to
    // differ (EggServe's final boundary applies Date/Server at a different
    // stage than Hyper's send path) and `date` values are per-second live
    // data. Status, header multiset, body bytes, and close behavior must
    // match exactly.
    //
    // Pipelined responses share lines with the previous body
    // ("...body...HTTP/1.1 200 OK"); split blocks at embedded status
    // lines first. Corpus bodies never contain "HTTP/1.1 " themselves.
    let mut blocks: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in wire.lines() {
        let mut rest = line;
        loop {
            match rest.find("HTTP/1.1 ") {
                Some(0) => {
                    current.push_str(rest);
                    current.push('\n');
                    break;
                }
                Some(pos) => {
                    current.push_str(&rest[..pos]);
                    blocks.push(std::mem::take(&mut current));
                    rest = &rest[pos..];
                }
                None => {
                    current.push_str(rest);
                    current.push('\n');
                    break;
                }
            }
        }
    }
    blocks.push(current);
    blocks
        .into_iter()
        .map(|block| normalize_response_block(&block))
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_response_block(block: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut headers: Vec<&str> = Vec::new();
    let mut in_headers = false;
    let flush_headers = |out: &mut Vec<String>, headers: &mut Vec<&str>| {
        headers.sort_unstable();
        out.extend(headers.drain(..).map(str::to_string));
    };
    for line in block.lines() {
        if line.starts_with("HTTP/") {
            in_headers = true;
            out.push(line.to_string());
            continue;
        }
        if in_headers {
            if line.is_empty() {
                flush_headers(&mut out, &mut headers);
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
        flush_headers(&mut out, &mut headers);
    }
    out.join("\n")
}

async fn assert_lane_parity(hyper_addr: SocketAddr, egg_addr: SocketAddr, request: &[u8]) {
    let hyper_wire = raw_exchange(hyper_addr, request).await;
    let egg_wire = raw_exchange(egg_addr, request).await;
    assert_eq!(
        normalize_wire(&hyper_wire),
        normalize_wire(&egg_wire),
        "lane divergence\n--- hyper ---\n{hyper_wire}\n--- eggserve ---\n{egg_wire}"
    );
}

fn httpdate_valid(wire: &str) -> bool {
    // Header names match case-insensitively; the value must parse in its
    // original case (month/day names are case-sensitive).
    let mut found = false;
    for line in wire.lines() {
        if line.to_ascii_lowercase().starts_with("date:") {
            found = true;
            if httpdate::parse_http_date(line["date:".len()..].trim()).is_err() {
                return false;
            }
        }
    }
    found
}

fn get(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[tokio::test]
async fn differential_core_corpus() {
    let echo = spawn_upstream_echo().await;
    let drop_decisions = Arc::new(AtomicUsize::new(0));
    let hyper_drops = Arc::new(AtomicUsize::new(0));
    let shared = build_shared(echo, drop_decisions.clone());
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(
        lane_context(&shared, http_config.clone(), 1024),
        hyper_drops,
        http_config.clone(),
    )
    .await;
    let egg_shutdown = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        egg_shutdown,
    )
    .await;

    // Ordinary upstream echo.
    assert_lane_parity(hyper_addr, egg_addr, &get("a.test", "/")).await;
    // Internal endpoint (no upstream, no body).
    assert_lane_parity(hyper_addr, egg_addr, &get("a.test", "/__internal__/health")).await;
    // Small fixed body round-trips through body policy + upstream echo.
    assert_lane_parity(
        hyper_addr,
        egg_addr,
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
    )
    .await;
    // Chunked/unknown-length body.
    assert_lane_parity(
        hyper_addr,
        egg_addr,
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .await;
    // Chunked body with terminal trailers.
    assert_lane_parity(
        hyper_addr,
        egg_addr,
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nTrailer: x-sum\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nx-sum: abc\r\n\r\n",
    )
    .await;
    // HEAD: status/headers parity, empty bodies.
    assert_lane_parity(
        hyper_addr,
        egg_addr,
        b"HEAD / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    // Framing fails closed identically.
    assert_lane_parity(
        hyper_addr,
        egg_addr,
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    // WAF block renders identically.
    assert_lane_parity(hyper_addr, egg_addr, &get("a.test", "/waf-block")).await;
    // 1 MiB streamed body.
    let mut big = b"POST /big HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n".to_vec();
    big.extend(std::iter::repeat_n(b'x', 1048576));
    assert_lane_parity(hyper_addr, egg_addr, &big).await;
}

#[tokio::test]
async fn differential_site_metadata() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(
        lane_context(&shared, http_config.clone(), 1024),
        Arc::new(AtomicUsize::new(0)),
        http_config.clone(),
    )
    .await;
    let egg_shutdown = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        egg_shutdown,
    )
    .await;

    // Upstream echo carries Date/duplicate Set-Cookie/Last-Modified/
    // Cache-Control; the pipeline relays them and injects site policy.
    // Date values are live data (stripped only for equality).
    let hyper_a = raw_exchange(hyper_addr, &get("a.test", "/")).await;
    let egg_a = raw_exchange(egg_addr, &get("a.test", "/")).await;
    assert_eq!(normalize_wire(&hyper_a), normalize_wire(&egg_a));
    for (name, wire) in [("hyper", &hyper_a), ("eggserve", &egg_a)] {
        let lower = wire.to_ascii_lowercase();
        assert!(lower.contains("server: diff-alpha"), "{name}: {wire}");
        assert!(lower.contains("\ndate:"), "{name}: {wire}");
        assert!(httpdate_valid(wire), "{name}: {wire}");
        // Pinned current behavior: the response-header filter uses
        // `insert`, so only the last duplicate survives — identically on
        // both lanes (any correction belongs to a separate plan).
        let cookies: Vec<_> = lower
            .lines()
            .filter(|l| l.starts_with("set-cookie:"))
            .collect();
        assert_eq!(cookies, vec!["set-cookie: e2=2"], "{name}: {wire}");
        assert!(
            lower.contains("content-security-policy: default-src 'none'"),
            "{name}: {wire}"
        );
        assert!(lower.contains("cache-control: no-store"), "{name}: {wire}");
        assert!(lower.contains("last-modified:"), "{name}: {wire}");
    }

    // Site B: distinct token, Date enabled. The single-Date invariant
    // (relayed upstream date superseded by the site date) holds on both.
    let hyper_b = raw_exchange(hyper_addr, &get("b.test", "/")).await;
    let egg_b = raw_exchange(egg_addr, &get("b.test", "/")).await;
    for (name, wire) in [("hyper", &hyper_b), ("eggserve", &egg_b)] {
        let lower = wire.to_ascii_lowercase();
        assert!(lower.contains("\ndate:"), "{name}: {wire}");
        assert_eq!(
            lower.lines().filter(|l| l.starts_with("date:")).count(),
            1,
            "{name}: {wire}"
        );
        assert!(httpdate_valid(wire), "{name}: {wire}");
        assert!(lower.contains("server: diff-beta"), "{name}: {wire}");
        assert!(!lower.contains("diff-alpha"), "{name}: {wire}");
    }
    assert_eq!(normalize_wire(&hyper_b), normalize_wire(&egg_b));
}

#[tokio::test]
async fn differential_aggregate_header_431() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let http_config = synvoid_config::http::HttpConfig {
        max_header_size_ingress: 64,
        ..Default::default()
    };
    let hyper_addr = spawn_hyper_lane(
        lane_context(&shared, http_config.clone(), 1024),
        Arc::new(AtomicUsize::new(0)),
        http_config.clone(),
    )
    .await;
    let egg_shutdown = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        egg_shutdown,
    )
    .await;
    let big_header = format!(
        "GET / HTTP/1.1\r\nHost: a.test\r\nx-big: {}\r\nConnection: close\r\n\r\n",
        "y".repeat(200)
    );
    assert_lane_parity(hyper_addr, egg_addr, big_header.as_bytes()).await;
    let hyper_wire = raw_exchange(hyper_addr, big_header.as_bytes()).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 431"), "{hyper_wire}");
    // Generated errors carry no Server token and advertise Alt-Svc on both.
    let lower = hyper_wire.to_ascii_lowercase();
    assert!(!lower.contains("server:"), "{hyper_wire}");
    assert!(lower.contains("alt-svc:"), "{hyper_wire}");
    let egg_wire = raw_exchange(egg_addr, big_header.as_bytes()).await;
    assert!(normalize_wire(&hyper_wire).contains("alt-svc:"));
    assert_eq!(normalize_wire(&hyper_wire), normalize_wire(&egg_wire));
}

#[tokio::test]
async fn differential_waf_drop() {
    let echo = spawn_upstream_echo().await;
    let drop_decisions = Arc::new(AtomicUsize::new(0));
    let hyper_drops = Arc::new(AtomicUsize::new(0));
    let shared = build_shared(echo, drop_decisions.clone());
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(
        lane_context(&shared, http_config.clone(), 1024),
        hyper_drops.clone(),
        http_config.clone(),
    )
    .await;
    let egg_shutdown = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        egg_shutdown.clone(),
    )
    .await;

    let hyper_wire = raw_exchange(hyper_addr, &get("a.test", "/waf-drop")).await;
    let egg_wire = raw_exchange(egg_addr, &get("a.test", "/waf-drop")).await;
    assert_eq!(
        normalize_wire(&hyper_wire),
        normalize_wire(&egg_wire),
        "drop response divergence"
    );
    // Both lanes reached the Drop decision and invoked the lane callback:
    // Hyper via its counted closure, EggServe via its shutdown token.
    assert_eq!(drop_decisions.load(Ordering::SeqCst), 2);
    assert_eq!(hyper_drops.load(Ordering::SeqCst), 1);
    let token = egg_shutdown
        .lock()
        .unwrap()
        .clone()
        .expect("eggserve lane accepted the drop connection");
    assert!(token.is_shutdown());
}

#[tokio::test]
async fn differential_websocket_handshake() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(
        lane_context(&shared, http_config.clone(), 1024),
        Arc::new(AtomicUsize::new(0)),
        http_config.clone(),
    )
    .await;
    let egg_shutdown = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        egg_shutdown,
    )
    .await;

    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\nConnection: close\r\n\r\n"
    );
    let hyper_wire = raw_exchange(hyper_addr, request.as_bytes()).await;
    let egg_wire = raw_exchange(egg_addr, request.as_bytes()).await;
    for (name, wire) in [("hyper", &hyper_wire), ("eggserve", &egg_wire)] {
        let lower = wire.to_ascii_lowercase();
        assert!(lower.contains("http/1.1 101"), "{name}: {wire}");
        assert!(
            wire.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "{name}: {wire}"
        );
        assert!(
            lower.contains("sec-websocket-protocol: chat"),
            "{name}: {wire}"
        );
    }
    assert_eq!(normalize_wire(&hyper_wire), normalize_wire(&egg_wire));
}

#[tokio::test]
async fn differential_keepalive_sequence() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let http_config = synvoid_config::http::HttpConfig::default();
    let hyper_addr = spawn_hyper_lane(
        lane_context(&shared, http_config.clone(), 1024),
        Arc::new(AtomicUsize::new(0)),
        http_config.clone(),
    )
    .await;
    let egg_shutdown = shutdown_slot();
    let egg_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        egg_shutdown,
    )
    .await;

    async fn two_gets(addr: SocketAddr) -> String {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /one HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .await
            .unwrap();
        let first = read_response(&mut socket).await;
        socket
            .write_all(b"GET /two HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let second = read_response(&mut socket).await;
        format!("{first}\n{second}")
    }

    assert_eq!(two_gets(hyper_addr).await, two_gets(egg_addr).await);
}

async fn read_response(socket: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read failed");
        assert!(n > 0, "closed mid-response");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head_end = pos + 4;
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let len: usize = head
                .to_ascii_lowercase()
                .lines()
                .find(|l| l.starts_with("content-length:"))
                .and_then(|l| l["content-length:".len()..].trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < head_end + len {
                let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut tmp))
                    .await
                    .expect("body timeout")
                    .expect("body read failed");
                assert!(n > 0, "truncated body");
                buf.extend_from_slice(&tmp[..n]);
            }
            return normalize_wire(&String::from_utf8_lossy(&buf[..head_end + len]));
        }
    }
}

#[tokio::test]
async fn placeholder_invariance_under_external_ownership() {
    // Track H: inert EggServe numerics must not affect wire behavior when
    // ownership is External.
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let http_config = synvoid_config::http::HttpConfig::default();
    let base_addr = spawn_eggserve_lane(
        lane_context(&shared, http_config.clone(), 1024),
        &http_config,
        shutdown_slot(),
    )
    .await;

    let tweaked = eggserve_server::RuntimeConfig::builder()
        .header_read_timeout(std::time::Duration::from_secs(30))
        .max_header_bytes(1024 * 1024)
        .max_request_body_bytes(1024 * 1024)
        .max_in_flight_requests(1024)
        .max_active_tunnels(1024)
        .handler_timeout(std::time::Duration::from_secs(60))
        .body_read_timeout(std::time::Duration::from_secs(60))
        .keep_alive_idle_timeout(std::time::Duration::from_secs(120))
        .response_write_timeout(std::time::Duration::from_secs(60))
        .graceful_shutdown_timeout(std::time::Duration::from_secs(20))
        .max_connections(256)
        .max_file_streams(64)
        .disable_connection_total_timeout()
        .http1_request_target_mode(eggserve_server::Http1RequestTargetMode::OriginOnly)
        .policy_ownership(synvoid::http::eggserve_h1::external_ownership_profile().0)
        .admission_ownership(synvoid::http::eggserve_h1::external_ownership_profile().1)
        .runtime_rejection_presenter(std::sync::Arc::new(
            synvoid::http::eggserve_h1::SynVoidRejectionPresenter,
        ))
        .build()
        .unwrap();
    tweaked.validate().unwrap();
    let tweaked_policy = std::sync::Arc::new(
        tweaked
            .h1_connection_policy()
            .unwrap()
            .with_request_header_bytes_owner(eggserve_server::PolicyOwner::External)
            .with_response_metadata_ownership(eggserve_server::ResponseMetadataOwnership {
                date: eggserve_server::PolicyOwner::External,
                server: eggserve_server::PolicyOwner::External,
            }),
    );
    let tweaked_state =
        std::sync::Arc::new(eggserve_server::RuntimeState::try_new(&tweaked).unwrap());
    let tweaked_ctx = lane_context(&shared, http_config.clone(), 1024);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tweaked_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let tweaked_ctx = tweaked_ctx.clone();
            let tweaked_policy = tweaked_policy.clone();
            let tweaked_state = tweaked_state.clone();
            let conn_shutdown = eggserve_server::ConnectionShutdown::new();
            tokio::spawn(async move {
                let service = EggserveH1Service::new(
                    tweaked_ctx,
                    conn_shutdown.clone(),
                    None,
                    ForwardedProtocol::Http,
                    Some(tweaked_addr),
                    None,
                );
                let _ = eggserve_server::serve_http1_connection_with_policy(
                    stream,
                    service,
                    tweaked_policy,
                    eggserve_server::ConnectionContext::for_tcp(tweaked_addr, peer, None),
                    tweaked_state,
                    &conn_shutdown,
                )
                .await;
            });
        }
    });

    let base = raw_exchange(base_addr, &get("a.test", "/")).await;
    let tweaked_wire = raw_exchange(tweaked_addr, &get("a.test", "/")).await;
    assert_eq!(
        base, tweaked_wire,
        "inert placeholders changed wire behavior"
    );
}

// ---------------------------------------------------------------------------
// Phase 78 closeout matrix: adversarial framing (B), full valid-config
// space (C), metadata residuals (D). Both lanes share the pipeline; these
// cases pin transport-level parity and fail-closed behavior at and beyond
// the legacy EggServe 0.3.0 bounds.
// ---------------------------------------------------------------------------

struct LanePair {
    hyper_addr: SocketAddr,
    egg_addr: SocketAddr,
}

async fn lane_pair_for(
    shared: &SharedParts,
    http_config: synvoid_config::http::HttpConfig,
    permits: usize,
) -> LanePair {
    let hyper_addr = spawn_hyper_lane(
        lane_context(shared, http_config.clone(), permits),
        Arc::new(AtomicUsize::new(0)),
        http_config.clone(),
    )
    .await;
    let egg_addr = spawn_eggserve_lane(
        lane_context(shared, http_config.clone(), permits),
        &http_config,
        shutdown_slot(),
    )
    .await;
    LanePair {
        hyper_addr,
        egg_addr,
    }
}

async fn assert_both(lanes: &LanePair, request: &[u8]) -> (String, String) {
    let hyper_wire = raw_exchange(lanes.hyper_addr, request).await;
    let egg_wire = raw_exchange(lanes.egg_addr, request).await;
    assert_eq!(
        normalize_wire(&hyper_wire),
        normalize_wire(&egg_wire),
        "lane divergence"
    );
    (hyper_wire, egg_wire)
}

#[tokio::test]
async fn adversarial_slow_request_line() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let http_config = synvoid_config::http::HttpConfig {
        header_read_timeout_secs: 1,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, http_config, 1024).await;
    for addr in [lanes.hyper_addr, lanes.egg_addr] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket.write_all(b"GET /slo").await.unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        socket
            .write_all(b"w HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf)).await;
        let wire = String::from_utf8_lossy(&buf).into_owned();
        assert!(
            wire.starts_with("HTTP/1.1 408") || wire.is_empty(),
            "stalled request line not refused: {wire:?}"
        );
    }
}

#[tokio::test]
async fn adversarial_invalid_host_and_garbage() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    // Space in Host value: EggServe's pre-service authority validation
    // fail-closes to 400 while Hyper routes to 404. Both deny with 4xx;
    // the stricter parse-time rejection is the approved EggServe semantic
    // (documented in the adoption closeout).
    let hyper_wire = raw_exchange(
        lanes.hyper_addr,
        b"GET / HTTP/1.1\r\nHost: bad host!\r\nConnection: close\r\n\r\n",
    )
    .await;
    let egg_wire = raw_exchange(
        lanes.egg_addr,
        b"GET / HTTP/1.1\r\nHost: bad host!\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(hyper_wire.starts_with("HTTP/1.1 404"), "{hyper_wire}");
    assert!(egg_wire.starts_with("HTTP/1.1 400"), "{egg_wire}");
    assert!(egg_wire.contains("400 Bad Request"), "{egg_wire}");
    // Garbage start bytes: lanes must agree on refusal.
    let (hyper_wire, _) = assert_both(&lanes, b"HELLO WORLD\r\n\r\n").await;
    assert!(
        !hyper_wire.starts_with("HTTP/1.1 200"),
        "garbage accepted: {hyper_wire:?}"
    );
}

#[tokio::test]
async fn adversarial_obs_text_header() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    // obs-text (0x80+) is legal in field values; lanes must agree.
    let mut request =
        b"GET / HTTP/1.1\r\nHost: a.test\r\nx-obs: \xc3\xa9\r\nConnection: close\r\n\r\n".to_vec();
    let _ = &mut request;
    assert_both(&lanes, &request).await;
}

#[tokio::test]
async fn adversarial_oversized_body() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    // Default 10 MiB streaming ceiling: 12 MiB must be refused on both.
    // The server refuses early and resets the stalled upload, so the
    // client writes tolerantly and then reads the verdict.
    let mut request =
        b"POST /big HTTP/1.1\r\nHost: a.test\r\nContent-Length: 12582912\r\nConnection: close\r\n\r\n"
            .to_vec();
    request.extend(std::iter::repeat_n(b'y', 12 * 1024 * 1024));
    async fn post_big(addr: SocketAddr, request: &[u8]) -> String {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut sent = 0;
        while sent < request.len() {
            match socket.write(&request[sent..]).await {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(_) => break,
            }
        }
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(15), socket.read_to_end(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    }
    let hyper_wire = post_big(lanes.hyper_addr, &request).await;
    let egg_wire = post_big(lanes.egg_addr, &request).await;
    assert_eq!(
        normalize_wire(&hyper_wire),
        normalize_wire(&egg_wire),
        "lane divergence"
    );
    // Pinned current behavior: declared-length oversize fails on the chunk
    // path, which body_policy maps to BlockedByWaf (403); unknown-length
    // oversize maps to BodyTooLarge (413). Identical on both lanes;
    // relabeling belongs to a separate plan.
    assert!(hyper_wire.starts_with("HTTP/1.1 403"), "{hyper_wire}");
}

#[tokio::test]
async fn adversarial_early_eof_then_resilience() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    for addr in [lanes.hyper_addr, lanes.egg_addr] {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                b"POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Length: 100\r\n\r\npartial",
            )
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut buf)).await;
        // Lane survives the truncation: fresh exchange works.
        let wire = raw_exchange(addr, &get("a.test", "/")).await;
        assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
    }
}

#[tokio::test]
async fn adversarial_pipelined_sequence() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    let pipelined = b"GET /one HTTP/1.1\r\nHost: a.test\r\n\r\nGET /two HTTP/1.1\r\nHost: a.test\r\n\r\nGET /three HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n";
    let (hyper_wire, _) = assert_both(&lanes, pipelined).await;
    assert_eq!(
        hyper_wire.matches("HTTP/1.1 200").count(),
        3,
        "{hyper_wire}"
    );
}

#[tokio::test]
async fn adversarial_upgrade_variants() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    // Upgrade token without Connection: upgrade stays ordinary HTTP.
    let (hyper_wire, _) = assert_both(
        &lanes,
        b"GET /ws HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(!hyper_wire.contains("101"), "{hyper_wire}");
    // Missing key: tokens validate, so 101 still offered (key validity is
    // the upstream's business); lanes agree.
    let (hyper_wire, _) = assert_both(
        &lanes,
        b"GET /ws HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(hyper_wire.contains("101"), "{hyper_wire}");
}

#[tokio::test]
async fn config_big_buffer_range() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    // 5 MiB parser buffer + 6 MiB ingress ceiling: beyond every legacy
    // EggServe 0.3.0 maximum, valid in SynVoid.
    let http_config = synvoid_config::http::HttpConfig {
        max_request_size: 5 * 1024 * 1024,
        max_header_size_ingress: 6 * 1024 * 1024,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, http_config, 1024).await;
    let big = format!(
        "GET / HTTP/1.1\r\nHost: a.test\r\nx-big: {}\r\nConnection: close\r\n\r\n",
        "q".repeat(5 * 1024 * 1024)
    );
    let (hyper_wire, _) = assert_both(&lanes, big.as_bytes()).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 200"), "{hyper_wire}");
}

#[tokio::test]
async fn config_many_headers_range() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    // 10,001 header fields: beyond the legacy 10,000 cap, valid in SynVoid.
    let http_config = synvoid_config::http::HttpConfig {
        max_request_size: 2 * 1024 * 1024,
        max_headers: 20_000,
        max_header_size_ingress: 2 * 1024 * 1024,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, http_config, 1024).await;
    let mut request = b"GET / HTTP/1.1\r\nHost: a.test\r\n".to_vec();
    for n in 0..10_001 {
        request.extend_from_slice(format!("x-h{n}: v\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    let (hyper_wire, _) = assert_both(&lanes, &request).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 200"), "{hyper_wire}");
}

#[tokio::test]
async fn config_big_ingress_range() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    // 1.5 MiB aggregate headers: beyond the legacy 1 MiB EggServe ceiling,
    // enforced canonically by SynVoid under External ownership.
    let http_config = synvoid_config::http::HttpConfig {
        max_request_size: 2 * 1024 * 1024,
        max_header_size_ingress: 2 * 1024 * 1024,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, http_config, 1024).await;
    let big = format!(
        "GET / HTTP/1.1\r\nHost: a.test\r\nx-big: {}\r\nConnection: close\r\n\r\n",
        "w".repeat((1.5 * 1024.0 * 1024.0) as usize)
    );
    let (hyper_wire, _) = assert_both(&lanes, big.as_bytes()).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 200"), "{hyper_wire}");
}

#[tokio::test]
async fn config_low_ingress_and_body_bounds() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    // Low aggregate ceiling (1..1023 also valid in SynVoid): small fits,
    // 200 B does not.
    let http_config = synvoid_config::http::HttpConfig {
        max_header_size_ingress: 100,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, http_config, 1024).await;
    let (hyper_wire, _) = assert_both(&lanes, &get("a.test", "/")).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 200"), "{hyper_wire}");
    let big = format!(
        "GET / HTTP/1.1\r\nHost: a.test\r\nx-big: {}\r\nConnection: close\r\n\r\n",
        "y".repeat(200)
    );
    let (hyper_wire, _) = assert_both(&lanes, big.as_bytes()).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 431"), "{hyper_wire}");

    // Streaming body boundary: declared small bodies take the buffered
    // path (bounded by the 256 KiB chunk threshold itself); unknown-length
    // bodies enforce `max_streaming_body_size` on the chunk path.
    let body_config = synvoid_config::http::HttpConfig {
        max_streaming_body_size: 1024,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, body_config, 1024).await;
    let mut request =
        b"POST /submit HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n800\r\n"
            .to_vec();
    request.extend(std::iter::repeat_n(b'z', 2048));
    request.extend_from_slice(b"\r\n0\r\n\r\n");
    let (hyper_wire, _) = assert_both(&lanes, &request).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 413"), "{hyper_wire}");
}

#[tokio::test]
async fn config_deprecated_keys_stay_compatible() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    // Deprecated compat keys parse and ordinary traffic is unaffected.
    let http_config = synvoid_config::http::HttpConfig {
        keep_alive_timeout_secs: 3,
        max_request_line_size: 4096,
        max_header_size_egress: 8192,
        pipeline_limit: 4,
        ..Default::default()
    };
    let lanes = lane_pair_for(&shared, http_config, 1024).await;
    let (hyper_wire, _) = assert_both(&lanes, &get("a.test", "/")).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 200"), "{hyper_wire}");
}

#[tokio::test]
async fn config_admission_queues() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1).await;
    // Single permit: concurrent exchanges all succeed via queueing.
    let mut handles = Vec::new();
    for lane in [
        lanes.hyper_addr,
        lanes.egg_addr,
        lanes.hyper_addr,
        lanes.egg_addr,
    ] {
        handles.push(tokio::spawn(async move {
            raw_exchange(lane, &get("a.test", "/")).await
        }));
    }
    for handle in handles {
        let wire = handle.await.unwrap();
        assert!(wire.starts_with("HTTP/1.1 200"), "{wire}");
    }
}

#[tokio::test]
async fn metadata_no_token_site() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    let (hyper_wire, _) = assert_both(&lanes, &get("c.test", "/")).await;
    assert!(
        !hyper_wire.to_ascii_lowercase().contains("server:"),
        "{hyper_wire}"
    );
}

#[tokio::test]
async fn preservice_target_no_ceiling() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    // 9 KiB target exceeds the EggServe default 8 KiB scalar, but
    // `request_target_ceiling = External` disables enforcement — matching
    // SynVoid's unenforced deprecated request-line key. Both lanes serve;
    // the fixed 414 presenter remains for residual rejections only.
    let big_target = format!(
        "GET /{} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
        "t".repeat(9 * 1024)
    );
    let (hyper_wire, _) = assert_both(&lanes, big_target.as_bytes()).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 200"), "{hyper_wire}");
}

#[tokio::test]
async fn dead_upstream_502_parity() {
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo, Arc::new(AtomicUsize::new(0)));
    let lanes = lane_pair_for(&shared, synvoid_config::http::HttpConfig::default(), 1024).await;
    let (hyper_wire, _) = assert_both(&lanes, &get("dead.test", "/")).await;
    assert!(hyper_wire.starts_with("HTTP/1.1 502"), "{hyper_wire}");
}

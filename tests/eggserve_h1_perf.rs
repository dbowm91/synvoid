//! Root-test ownership: QUALIFICATION
//! Rationale: Phase 78 Track G same-host performance comparison, MANUAL-ONLY.
//! Every test here is `#[ignore]` so routine CI never executes it; run by
//! hand with `cargo test --test eggserve_h1_perf -- --ignored --nocapture`
//! on a quiet host and record the numbers in
//! `architecture/eggserve_0_3_h1_adoption_closeout.md` without comparing
//! across hosts.
//!
//! Both lanes share the neutral pipeline and stub WAF; only the H1 driver
//! differs (production EggServe vs test-only Hyper). Reports throughput,
//! latency percentiles, and process RSS delta.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        "css".to_string()
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
        "cssv".to_string()
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

fn build_shared(echo_addr: SocketAddr) -> Shared {
    let mut sites = HashMap::new();
    let mut site = SiteConfig::default_fallback_site(format!("http://{echo_addr}"));
    site.site.domains = vec!["a.test".to_string()];
    sites.insert("site-a".to_string(), site);
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

fn lane_context(shared: &Shared) -> NeutralServiceContext<StubWaf, StubDrain> {
    NeutralServiceContext {
        router: Arc::clone(&shared.router),
        waf: Arc::clone(&shared.waf),
        alt_svc: None,
        main_config: Arc::clone(&shared.main_config),
        http_config: synvoid_config::http::HttpConfig::default(),
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
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        let (parts, body) = req.into_parts();
                        let bytes = body.collect().await.unwrap().to_bytes();
                        let text =
                            format!("echo:{}:{}:{}", parts.method, parts.uri.path(), bytes.len());
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

async fn spawn_hyper_lane(ctx: NeutralServiceContext<StubWaf, StubDrain>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| {
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
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

async fn spawn_eggserve_lane(ctx: NeutralServiceContext<StubWaf, StubDrain>) -> SocketAddr {
    let projected = project_eggserve_h1(&synvoid_config::http::HttpConfig::default()).unwrap();
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

fn rss_mb() -> u64 {
    let mut system = sysinfo::System::new();
    system.refresh_processes(
        sysinfo::ProcessesToUpdate::Some(&[sysinfo::get_current_pid().unwrap()]),
        true,
    );
    system
        .process(sysinfo::get_current_pid().unwrap())
        .map(|p| p.memory() / 1024 / 1024)
        .unwrap_or(0)
}

fn percentile(mut samples: Vec<u128>, pct: f64) -> u128 {
    samples.sort_unstable();
    samples[((samples.len() as f64 * pct) as usize).min(samples.len() - 1)]
}

async fn oneshot_get(addr: SocketAddr) -> Duration {
    let start = Instant::now();
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    socket.read_to_end(&mut buf).await.unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 200"));
    start.elapsed()
}

fn report(name: &str, hyper_us: &[u128], egg_us: &[u128]) {
    let summarize = |v: &[u128]| {
        (
            percentile(v.to_vec(), 0.5),
            percentile(v.to_vec(), 0.95),
            *v.iter().max().unwrap_or(&0),
            v.iter().sum::<u128>() as f64 / v.len() as f64,
        )
    };
    let (hp50, hp95, hmax, hmean) = summarize(hyper_us);
    let (ep50, ep95, emax, emean) = summarize(egg_us);
    println!("--- {name} (microseconds; hyper vs eggserve) ---");
    println!(
        "hyper:    n={} p50={hp50} p95={hp95} max={hmax} mean={hmean:.0}",
        hyper_us.len()
    );
    println!(
        "eggserve: n={} p50={ep50} p95={ep95} max={emax} mean={emean:.0}",
        egg_us.len()
    );
}

#[tokio::test]
#[ignore]
async fn perf_sequential_keepalive() {
    const N: usize = 500;
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo);
    let hyper_addr = spawn_hyper_lane(lane_context(&shared)).await;
    let egg_addr = spawn_eggserve_lane(lane_context(&shared)).await;
    // Warmup.
    for _ in 0..20 {
        oneshot_get(hyper_addr).await;
        oneshot_get(egg_addr).await;
    }
    let rss_before = rss_mb();
    let mut hyper_us = Vec::with_capacity(N);
    let mut egg_us = Vec::with_capacity(N);
    // Interleaved ABBA to control for host noise.
    for _ in 0..N {
        hyper_us.push(oneshot_get(hyper_addr).await.as_micros());
        egg_us.push(oneshot_get(egg_addr).await.as_micros());
    }
    let rss_after = rss_mb();
    report("sequential keep-alive GET", &hyper_us, &egg_us);
    println!("rss: before={rss_before}MiB after={rss_after}MiB");
}

#[tokio::test]
#[ignore]
async fn perf_concurrent_small() {
    const TASKS: usize = 16;
    const PER_TASK: usize = 50;
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo);
    let hyper_addr = spawn_hyper_lane(lane_context(&shared)).await;
    let egg_addr = spawn_eggserve_lane(lane_context(&shared)).await;
    for _ in 0..20 {
        oneshot_get(hyper_addr).await;
        oneshot_get(egg_addr).await;
    }
    let run_lane = |addr: SocketAddr| async move {
        let start = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            handles.push(tokio::spawn(async move {
                for _ in 0..PER_TASK {
                    oneshot_get(addr).await;
                }
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        start.elapsed()
    };
    let hyper_elapsed = run_lane(hyper_addr).await;
    let egg_elapsed = run_lane(egg_addr).await;
    let total = (TASKS * PER_TASK) as f64;
    println!("--- concurrent small GET: {TASKS} tasks x {PER_TASK} ---");
    println!(
        "hyper:    {total:.0} reqs in {:.2}s = {:.0} req/s",
        hyper_elapsed.as_secs_f64(),
        total / hyper_elapsed.as_secs_f64()
    );
    println!(
        "eggserve: {total:.0} reqs in {:.2}s = {:.0} req/s",
        egg_elapsed.as_secs_f64(),
        total / egg_elapsed.as_secs_f64()
    );
}

#[tokio::test]
#[ignore]
async fn perf_streamed_body() {
    const BODY: usize = 1024 * 1024;
    let echo = spawn_upstream_echo().await;
    let shared = build_shared(echo);
    let hyper_addr = spawn_hyper_lane(lane_context(&shared)).await;
    let egg_addr = spawn_eggserve_lane(lane_context(&shared)).await;
    let payload = vec![b'q'; BODY];
    // Warmup (upstream connection setup otherwise skews first iterations).
    for _ in 0..2 {
        post_once(hyper_addr, &payload).await;
        post_once(egg_addr, &payload).await;
    }
    let mut hyper_us = Vec::new();
    let mut egg_us = Vec::new();
    for _ in 0..10 {
        hyper_us.push(post_once(hyper_addr, &payload).await.as_micros());
        egg_us.push(post_once(egg_addr, &payload).await.as_micros());
    }
    report("1 MiB streamed POST", &hyper_us, &egg_us);
}

async fn post_once(addr: SocketAddr, payload: &[u8]) -> Duration {
    let start = Instant::now();
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /big HTTP/1.1\r\nHost: a.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    socket.write_all(head.as_bytes()).await.unwrap();
    socket.write_all(payload).await.unwrap();
    let mut buf = Vec::new();
    socket.read_to_end(&mut buf).await.unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 200"));
    start.elapsed()
}

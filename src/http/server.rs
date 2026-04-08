#![allow(
    clippy::type_complexity,
    clippy::collapsible_match,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    clippy::field_reassign_with_default,
    clippy::collapsible_if
)]

use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use hex;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use metrics::counter;
use sha2::Digest;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Role, WebSocketStream};

static WHITELIST_REGEX_CACHE: LazyLock<DashMap<String, Option<regex::Regex>>> =
    LazyLock::new(DashMap::new);

static IMAGE_PROTECTION_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\.(?:jpe?g|png|gif|webp|bmp|svg|ico)(?:\?|$)").unwrap());

fn get_cached_regex(pattern: &str) -> Option<regex::Regex> {
    WHITELIST_REGEX_CACHE
        .entry(pattern.to_string())
        .or_insert_with(|| regex::Regex::new(pattern).ok())
        .value()
        .clone()
}

const IMAGE_POISON_CACHE_MAX_CAPACITY: u64 = 1000;
const IMAGE_POISON_CACHE_TTL_SECS: u64 = 3600;

static IMAGE_POISON_CACHE: LazyLock<Cache<String, Vec<u8>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(IMAGE_POISON_CACHE_MAX_CAPACITY)
        .time_to_live(Duration::from_secs(IMAGE_POISON_CACHE_TTL_SECS))
        .build()
});

use crate::challenge::HONEYPOT_PREFIX;
use crate::config::site::{ProxyHeadersConfig, SiteWebSocketConfig};
use crate::config::HttpConfig;
use crate::config::MainConfig;
use crate::http::headers::{
    compute_websocket_accept_key, generate_stealth_timestamp, inject_security_headers,
    is_websocket_upgrade,
};
use crate::http_client::{
    create_http_client_with_config, create_upstream_client, send_request_streaming,
    send_request_with_body_and_timeout, HttpClient, UpstreamTlsConfig,
};
use crate::mesh::config::MeshConfig;
use crate::mesh::transports::MeshTransportManager;
use crate::metrics::bandwidth::{BandwidthProtocol, EgressDirection};
use crate::metrics::WorkerMetrics;
use crate::process::{current_timestamp, RequestLogPayload};
use crate::protocol::trait_def::{ProtocolHandler, WafAction};
use crate::protocol::types::{ProtocolRequest, ProtocolType};
use crate::protocol::websocket::WebSocketHandler;
use crate::proxy::{build_forward_headers, build_headers_to_filter, filter_response_headers};
use crate::router::Router;
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::worker::drain_state::WorkerDrainState;
use crate::RunningFlag;
use moka::sync::Cache;
use parking_lot::Mutex;
use tokio::sync::RwLock;

static REQUEST_LOG_RATE_LIMITER: AtomicU32 = AtomicU32::new(0);
static REQUEST_LOG_RATE_LIMITER_RESET: AtomicU64 = AtomicU64::new(0);

struct HttpConnection {
    io: Mutex<Option<TokioIo<tokio::net::TcpStream>>>,
    drop_requested: RunningFlag,
}

impl HttpConnection {
    fn new(stream: tokio::net::TcpStream) -> Self {
        Self {
            io: Mutex::new(Some(TokioIo::new(stream))),
            drop_requested: RunningFlag::new(),
        }
    }

    fn request_drop(&self) {
        self.drop_requested.stop();
    }

    fn should_drop(&self) -> bool {
        !self.drop_requested.is_running()
    }

    fn take_stream(&self) -> Option<TokioIo<tokio::net::TcpStream>> {
        self.io.lock().take()
    }
}

struct DrainGuard {
    state: Option<Arc<WorkerDrainState>>,
}

impl DrainGuard {
    fn new(state: Option<Arc<WorkerDrainState>>) -> Self {
        if let Some(ref ds) = state {
            ds.increment_active();
        }
        Self { state }
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        if let Some(ref state) = self.state {
            state.decrement_active();
        }
    }
}

const INTERNAL_DRAIN_PATH: &str = "/__internal__/drain";
const INTERNAL_DRAIN_STATUS_PATH: &str = "/__internal__/drain-status";
const INTERNAL_HEALTH_PATH: &str = "/__internal__/health";
const INTERNAL_READY_PATH: &str = "/__internal__/ready";

pub struct HttpServer {
    addr: SocketAddr,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    shutdown_rx: broadcast::Receiver<()>,
    http_config: HttpConfig,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    drain_state: Option<Arc<WorkerDrainState>>,
    mesh_config: Option<Arc<MeshConfig>>,
    mesh_transport: Option<Arc<MeshTransportManager>>,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    connection_limit: Arc<Semaphore>,
    app_servers: Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
}

impl HttpServer {
    pub fn new(
        addr: SocketAddr,
        router: Router,
        waf: Arc<WafCore>,
        http_config: HttpConfig,
        shutdown_rx: broadcast::Receiver<()>,
        main_config: MainConfig,
    ) -> Self {
        let client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            100,
            std::time::Duration::from_secs(30),
        );

        let max_connections = http_config.max_connections as usize;

        Self {
            addr,
            router: Arc::new(router),
            waf,
            flood_protector: None,
            client,
            shutdown_rx,
            http_config,
            alt_svc: None,
            main_config: Arc::new(main_config),
            drain_state: None,
            mesh_config: None,
            mesh_transport: None,
            metrics: None,
            ipc: None,
            worker_id: None,
            serverless_manager: None,
            connection_limit: Arc::new(Semaphore::new(max_connections)),
            app_servers: None,
        }
    }

    pub fn with_serverless_manager(
        mut self,
        manager: Arc<crate::serverless::manager::ServerlessManager>,
    ) -> Self {
        self.serverless_manager = Some(manager);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_ipc(
        mut self,
        ipc: Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>,
        worker_id: crate::process::ipc::WorkerId,
    ) -> Self {
        self.ipc = Some(ipc);
        self.worker_id = Some(worker_id);
        self
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_alt_svc(mut self, alt_svc: String) -> Self {
        self.alt_svc = Some(alt_svc);
        self
    }

    pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self {
        self.drain_state = Some(drain_state);
        self
    }

    pub fn with_mesh_config(mut self, mesh_config: Option<Arc<MeshConfig>>) -> Self {
        self.mesh_config = mesh_config;
        self
    }

    pub fn with_mesh_transport(mut self, transport: Option<Arc<MeshTransportManager>>) -> Self {
        self.mesh_transport = transport;
        self
    }

    pub fn with_app_servers(
        mut self,
        app_servers: Option<
            Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        >,
    ) -> Self {
        self.app_servers = app_servers;
        self
    }

    pub async fn serve(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!("HTTP server listening on {} (HTTP/1.1 + HTTP/2)", self.addr);

        let router = self.router.clone();
        let waf = self.waf.clone();
        let client = self.client.clone();
        let flood_protector = self.flood_protector.clone();
        let http_config = self.http_config.clone();
        let alt_svc = self.alt_svc.clone();
        let main_config = self.main_config.clone();
        let drain_state = self.drain_state.clone();
        let mesh_config = self.mesh_config.clone();
        let mesh_transport = self.mesh_transport.clone();
        let metrics = self.metrics.clone();
        let worker_id = self.worker_id;
        let serverless_manager = self.serverless_manager.clone();
        let connection_limit = self.connection_limit.clone();
        let app_servers = self.app_servers.clone();

        let header_read_timeout = Duration::from_secs(self.http_config.header_read_timeout_secs);
        let max_headers = self.http_config.max_headers;
        let max_buf_size = self.http_config.max_request_size;

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    tracing::info!("HTTP server received shutdown signal");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            let client_ip = client_addr.ip();

                            let local_addr = stream.local_addr().ok();

                            if let Some(ref fp) = flood_protector {
                                match fp.check_tcp_connection(client_ip) {
                                    FloodDecision::Blackholed => {
                                        counter!("maluwaf.http.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("maluwaf.http.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                            }

                            let router = router.clone();
                            let waf = waf.clone();
                            let client = client.clone();
                            let alt_svc = alt_svc.clone();
                            let main_config = main_config.clone();
                            let drain_state = drain_state.clone();
                            let http_config = http_config.clone();
                            let mesh_config = mesh_config.clone();
                            let mesh_transport = mesh_transport.clone();
                            let metrics = metrics.clone();
                            let ipc = self.ipc.clone();
                            let serverless_manager = serverless_manager.clone();
                            let connection_limit = connection_limit.clone();
                            let app_servers = app_servers.clone();

                            let http_conn = Arc::new(HttpConnection::new(stream));
                            let http_conn_clone = http_conn.clone();

                            let io = match http_conn.io.lock().take() {
                                Some(io) => io,
                                None => {
                                    tracing::error!("Failed to take IO from HTTP connection");
                                    continue;
                                }
                            };

                            let conn = hyper::server::conn::http1::Builder::new()
                                .header_read_timeout(header_read_timeout)
                                .max_headers(max_headers)
                                .max_buf_size(max_buf_size)
                                .serve_connection(io, hyper::service::service_fn(move |req| {
                                    let router = router.clone();
                                    let waf = waf.clone();
                                    let client = client.clone();
                                    let alt_svc = alt_svc.clone();
                                    let main_config = main_config.clone();
                                    let local_addr = local_addr;
                                    let drain_state = drain_state.clone();
                                    let http_config = http_config.clone();
                                    let mesh_config = mesh_config.clone();
                                    let mesh_transport = mesh_transport.clone();
                                    let metrics = metrics.clone();
                                    let http_conn = http_conn_clone.clone();
                                    let ipc_for_request = ipc.clone();
                                    let worker_id_for_request = worker_id;
                                    let serverless_manager = serverless_manager.clone();
                                    let connection_limit = connection_limit.clone();
                                    let app_servers = app_servers.clone();
                                    async move {
                                        Self::handle_request(req, client_addr, local_addr, router, waf, client, alt_svc, main_config, drain_state, http_config, mesh_config, mesh_transport, metrics, http_conn, ipc_for_request, worker_id_for_request, serverless_manager, connection_limit, app_servers).await
                                    }
                                }))
                                .with_upgrades();

                            tokio::spawn(async move {
                                if let Err(e) = conn.await {
                                    tracing::debug!("HTTP connection error: {}", e);
                                }
                                if http_conn.should_drop() {
                                    if let Some(stream) = http_conn.take_stream() {
                                        drop(stream);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
            }
        }

        tracing::info!("HTTP server shutdown");

        Ok(())
    }

    async fn handle_request(
        mut req: hyper::Request<hyper::body::Incoming>,
        client_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        client: HttpClient,
        alt_svc: Option<String>,
        main_config: Arc<MainConfig>,
        drain_state: Option<Arc<WorkerDrainState>>,
        http_config: HttpConfig,
        mesh_config: Option<Arc<MeshConfig>>,
        mesh_transport: Option<Arc<MeshTransportManager>>,
        metrics: Option<Arc<WorkerMetrics>>,
        http_conn: Arc<HttpConnection>,
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
        connection_limit: Arc<Semaphore>,
        app_servers: Option<
            Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        >,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let _permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("Connection limit semaphore closed");
                return Ok(Self::build_response_with_alt_svc(
                    503,
                    "Service Unavailable".to_string(),
                    "text/plain",
                    &None,
                    &main_config,
                ));
            }
        };

        let start = std::time::Instant::now();
        let client_ip = client_addr.ip();

        // Sanitize X-Forwarded-For headers based on trusted proxies
        let client_ip = {
            let sanitizer =
                crate::waf::RequestSanitizer::new(main_config.server.trusted_proxies.clone(), true);
            sanitizer.sanitize_request_headers(req.headers_mut(), client_ip);
            sanitizer
                .get_real_ip(req.headers(), client_ip)
                .unwrap_or(client_ip)
        };

        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.path())
            .unwrap_or("/");

        if let Some(ref state) = drain_state {
            let is_localhost = matches!(client_ip, IpAddr::V4(ip) if ip.is_loopback())
                || matches!(client_ip, IpAddr::V6(ip) if ip.is_loopback());

            if is_localhost {
                if path == INTERNAL_DRAIN_PATH {
                    return Self::handle_drain_request(req, state, &alt_svc, &main_config);
                }

                if path == INTERNAL_DRAIN_STATUS_PATH {
                    return Self::handle_drain_status_request(req, state, &alt_svc, &main_config);
                }
            }

            if path == INTERNAL_HEALTH_PATH {
                return Self::handle_health_request(&drain_state, &alt_svc, &main_config);
            }

            if path == INTERNAL_READY_PATH {
                return Self::handle_ready_request(&drain_state, &alt_svc, &main_config);
            }
        } else if path == INTERNAL_HEALTH_PATH || path == INTERNAL_READY_PATH {
            return Self::handle_health_request(&drain_state, &alt_svc, &main_config);
        }

        // Handle key exchange requests for global nodes
        if path.starts_with("/key-") || path == "/health" {
            if let Some(ref mesh_cfg) = mesh_config {
                if mesh_cfg.role.is_global()
                    && mesh_cfg.global_node.key_exchange_enabled
                    && mesh_cfg.origin_signing_key.is_some()
                {
                    return Self::handle_key_exchange_request(
                        req,
                        mesh_cfg,
                        &alt_svc,
                        &main_config,
                        client_ip,
                        mesh_transport,
                    )
                    .await;
                }
            }
        }

        let connection_token = if let Some(ref conn_limiter) = waf.connection_limiter {
            match conn_limiter.try_acquire("_http_", client_ip).await {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                    counter!("maluwaf.traffic.connection_limited").increment(1);
                    let ipc_clone = ipc.clone();
                    let worker_id_clone = worker_id;
                    Self::send_request_log_if_enabled(
                        ipc_clone,
                        worker_id_clone,
                        &main_config,
                        client_ip,
                        "UNKNOWN".to_string(),
                        path.to_string(),
                        503,
                        start.elapsed().as_millis() as u64,
                        "internal".to_string(),
                        None,
                        true,
                    );
                    return Ok(Self::build_response_with_alt_svc(
                        503,
                        "Too Many Connections".to_string(),
                        "application/json",
                        &alt_svc,
                        &main_config,
                    ));
                }
            }
        } else {
            None
        };

        let _conn_token = connection_token;

        if let Some(result) = Self::check_bandwidth_limit(
            &waf,
            client_ip,
            path,
            start,
            ipc.clone(),
            worker_id,
            &main_config,
            &alt_svc,
        ) {
            return result;
        }

        let is_ws_upgrade = Self::is_websocket_upgrade(req.headers());
        let on_upgrade = if is_ws_upgrade {
            Some(hyper::upgrade::on(&mut req))
        } else {
            None
        };

        let (parts, body) = req.into_parts();
        let method = parts.method.clone();
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".to_string());
        let host = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let user_agent = parts
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let cookies = parts.headers.get("cookie").and_then(|v| v.to_str().ok());

        let early_decision = waf.check_early(client_ip, &path, cookies);
        match early_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("maluwaf.http.early_drop").increment(1);
                http_conn.request_drop();
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    0,
                    start.elapsed().as_millis() as u64,
                    "unknown".to_string(),
                    user_agent.clone(),
                    false,
                );
                let resp = Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                return Ok(resp);
            }
            crate::proxy::WafDecision::ChallengeWithCookie {
                html,
                session_cookie_name,
                session_cookie_value,
                session_cookie_max_age,
            } => {
                let cookie = format!(
                    "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                    session_cookie_name, session_cookie_value, session_cookie_max_age
                );
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    200,
                    start.elapsed().as_millis() as u64,
                    "unknown".to_string(),
                    user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                    &alt_svc,
                    &main_config,
                ));
            }
            crate::proxy::WafDecision::Challenge(html) => {
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    200,
                    start.elapsed().as_millis() as u64,
                    "unknown".to_string(),
                    user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    &alt_svc,
                    &main_config,
                ));
            }
            crate::proxy::WafDecision::Block(status, message) => {
                let body =
                    waf.error_page_manager
                        .render_page_with_theme(status, Some(&message), None);
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    status,
                    start.elapsed().as_millis() as u64,
                    "unknown".to_string(),
                    user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_alt_svc(
                    status,
                    body,
                    "text/html",
                    &alt_svc,
                    &main_config,
                ));
            }
            crate::proxy::WafDecision::Pass
            | crate::proxy::WafDecision::Stall
            | crate::proxy::WafDecision::Tarpit(_) => {
                // Proceed to full body collection and full WAF check
            }
        }

        let mut request_body_size: u64 = 0;
        const MAX_WAF_BODY_SIZE: usize = 1024 * 1024; // 1MB limit for WAF inspection
        const CHUNK_WAF_THRESHOLD: usize = 256 * 1024; // 256KB - run WAF on chunks above this size

        let content_length: Option<usize> = parts
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let full_body: Bytes = if let Some(cl) = content_length {
            if cl > CHUNK_WAF_THRESHOLD {
                match Self::collect_body_with_chunk_waf(
                    body,
                    &waf,
                    client_ip,
                    &mut request_body_size,
                )
                .await
                {
                    Ok(body) => body,
                    Err(()) => {
                        return Ok(Self::build_response_with_alt_svc(
                            403,
                            "Request blocked by WAF".to_string(),
                            "text/plain",
                            &alt_svc,
                            &main_config,
                        ));
                    }
                }
            } else {
                match body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(_) => Bytes::new(),
                }
            }
        } else {
            match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            }
        };
        request_body_size = full_body.len() as u64;
        const CHUNK_WAF_SCAN_SIZE: usize = 64 * 1024; // 64KB chunks for full body scan

        let full_body_arc = Arc::new(full_body);
        let (body_slice, needs_full_scan) = if full_body_arc.is_empty() {
            (None, false)
        } else if full_body_arc.len() > MAX_WAF_BODY_SIZE {
            (Some(full_body_arc.clone()), true)
        } else {
            (Some(full_body_arc.clone()), false)
        };

        if needs_full_scan && !full_body_arc.is_empty() {
            let body_len = full_body_arc.len();
            for offset in (0..body_len).step_by(CHUNK_WAF_SCAN_SIZE) {
                let end = std::cmp::min(offset + CHUNK_WAF_SCAN_SIZE, body_len);
                let chunk = &full_body_arc[offset..end];
                if let Some(
                    crate::proxy::WafDecision::Drop | crate::proxy::WafDecision::Block(_, _),
                ) = waf.check_request_body(chunk)
                {
                    tracing::warn!(
                        client_ip = %client_ip,
                        offset = offset,
                        size = body_len,
                        "Large request body blocked by WAF at offset {}",
                        offset
                    );
                    counter!("maluwaf.http.large_body_blocked").increment(1);
                    return Ok(Self::build_response_with_alt_svc(
                        403,
                        "Request blocked by WAF".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }
            }
            tracing::debug!(
                client_ip = %client_ip,
                size = body_len,
                "Large request body scanned by WAF ({} chunks)",
                (body_len + CHUNK_WAF_SCAN_SIZE - 1) / CHUNK_WAF_SCAN_SIZE
            );
        }

        let body_slice_ref: Option<&[u8]> = body_slice.as_ref().map(|v| v.as_ref() as &[u8]);
        if let Some(ref m) = metrics {
            if let Some(content_length) = parts.headers.get("content-length") {
                if let Ok(len_str) = content_length.to_str() {
                    if let Ok(len) = len_str.parse::<u64>() {
                        request_body_size = len;
                        m.bandwidth.record_ingress(len, BandwidthProtocol::Http);
                        m.bandwidth.record_site_ingress(&host, len);
                    }
                }
            }
        }

        if path.starts_with(HONEYPOT_PREFIX) {
            counter!("maluwaf.honeypot.hit").increment(1);
            tracing::info!("HTTP honeypot accessed: {} by {}", path, client_ip);
            let ipc_clone = ipc.clone();
            let worker_id_clone = worker_id;
            Self::send_request_log_if_enabled(
                ipc_clone,
                worker_id_clone,
                &main_config,
                client_ip,
                method.to_string(),
                path.clone(),
                408,
                start.elapsed().as_millis() as u64,
                "internal".to_string(),
                user_agent.clone(),
                true,
            );
            return Ok(Self::build_response_with_alt_svc(
                408,
                "Request timeout".to_string(),
                "text/plain",
                &alt_svc,
                &main_config,
            ));
        }

        if path.starts_with("/_waf_css_challenge") {
            let (html, _) = waf.challenge_manager.generate_challenge_page(&client_ip);
            let ipc_clone = ipc.clone();
            let worker_id_clone = worker_id;
            Self::send_request_log_if_enabled(
                ipc_clone,
                worker_id_clone,
                &main_config,
                client_ip,
                method.to_string(),
                path.clone(),
                200,
                start.elapsed().as_millis() as u64,
                "internal".to_string(),
                user_agent.clone(),
                true,
            );
            return Ok(Self::build_response_with_alt_svc(
                200,
                html,
                "text/html",
                &alt_svc,
                &main_config,
            ));
        }

        if path.starts_with("/_waf_assets") {
            let asset_name = match path.strip_prefix("/_waf_assets/rnd-") {
                Some(name) => name.strip_suffix(".png").unwrap_or(name),
                None => {
                    let ipc_clone = ipc.clone();
                    let worker_id_clone = worker_id;
                    Self::send_request_log_if_enabled(
                        ipc_clone,
                        worker_id_clone,
                        &main_config,
                        client_ip,
                        method.to_string(),
                        path.clone(),
                        204,
                        start.elapsed().as_millis() as u64,
                        "internal".to_string(),
                        user_agent.clone(),
                        true,
                    );
                    let mut resp = Response::builder()
                        .status(http::StatusCode::NO_CONTENT)
                        .body(Full::new(Bytes::new()).boxed())
                        .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                    resp.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                    return Ok(resp);
                }
            };

            if !waf.challenge_manager.css_enabled() {
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    404,
                    start.elapsed().as_millis() as u64,
                    "internal".to_string(),
                    user_agent.clone(),
                    true,
                );
                return Ok(Self::build_response_with_alt_svc(
                    404,
                    "Not Found".to_string(),
                    "text/plain",
                    &alt_svc,
                    &main_config,
                ));
            }

            let cookie_name = waf.challenge_manager.css_session_cookie_name();
            let session_id = parts
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookie_str| {
                    cookie_str
                        .split(';')
                        .find(|c| c.trim().starts_with(&format!("{}=", cookie_name)))
                        .map(|c| c.trim()[cookie_name.len() + 1..].to_string())
                });

            let session_id = match session_id {
                Some(sid) => sid,
                None => {
                    let ipc_clone = ipc.clone();
                    let worker_id_clone = worker_id;
                    Self::send_request_log_if_enabled(
                        ipc_clone,
                        worker_id_clone,
                        &main_config,
                        client_ip,
                        method.to_string(),
                        path.clone(),
                        204,
                        start.elapsed().as_millis() as u64,
                        "internal".to_string(),
                        user_agent.clone(),
                        true,
                    );
                    let mut resp = Response::builder()
                        .status(http::StatusCode::NO_CONTENT)
                        .body(Full::new(Bytes::new()).boxed())
                        .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                    resp.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                    return Ok(resp);
                }
            };

            let (_, action) = waf
                .challenge_manager
                .record_css_asset_request(&session_id, asset_name);

            match action {
                crate::challenge::CssAssetAction::RedirectWithCookie => {
                    let verified_cookie_name = waf.challenge_manager.css_verified_cookie_name();
                    let window_secs = waf.challenge_manager.css_window_secs();
                    let cookie = format!(
                        "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                        verified_cookie_name, "verified", window_secs
                    );
                    let response = Response::builder()
                        .status(http::StatusCode::FOUND)
                        .header(http::header::LOCATION, "/")
                        .header(http::header::SET_COOKIE, cookie)
                        .body(Full::new(Bytes::new()).boxed())
                        .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                    return Ok(response);
                }
                crate::challenge::CssAssetAction::DropConnection => {
                    let mut resp = Response::builder()
                        .status(http::StatusCode::NO_CONTENT)
                        .body(Full::new(Bytes::new()).boxed())
                        .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                    resp.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                    return Ok(resp);
                }
            }
        }

        let _drain_guard = DrainGuard::new(drain_state.clone());

        let query_string = parts.uri.query();

        let route = router.route_with_local_addr(&host, &path, local_addr);

        let target = match route {
            crate::router::RouteResult::Found(target) => target,
            crate::router::RouteResult::NotFound(msg) => {
                tracing::debug!("Route not found: {} for host: {}", msg, host);
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    404,
                    start.elapsed().as_millis() as u64,
                    host.clone(),
                    user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_alt_svc(
                    404,
                    "Not Found".to_string(),
                    "text/plain",
                    &alt_svc,
                    &main_config,
                ));
            }
            crate::router::RouteResult::Error(msg) => {
                tracing::error!("Router error: {}", msg);
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method.to_string(),
                    path.clone(),
                    500,
                    start.elapsed().as_millis() as u64,
                    host.clone(),
                    user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_alt_svc(
                    500,
                    crate::http::reason_phrase(500).to_string(),
                    "text/plain",
                    &alt_svc,
                    &main_config,
                ));
            }
        };

        let site_id = target.site_id.clone();
        if let Some(ref metrics) = metrics {
            metrics.record_site_request_start(&site_id);
        }

        let method_str = method.to_string();
        let waf_decision = waf
            .check_request_full(
                client_ip,
                method_str.as_str(),
                &path,
                query_string,
                &parts.headers,
                body_slice_ref,
                user_agent.as_deref(),
            )
            .await;

        let response = match waf_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("maluwaf.http.blackhole_drop").increment(1);
                http_conn.request_drop();
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method_str.clone(),
                    path.clone(),
                    0,
                    start.elapsed().as_millis() as u64,
                    site_id.to_string(),
                    user_agent.clone(),
                    false,
                );
                let resp = Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                return Ok(resp);
            }
            crate::proxy::WafDecision::Stall => {
                counter!("maluwaf.http.stalled").increment(1);
                let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
                tokio::select! {
                    _ = tokio::time::sleep(stall_timeout) => {
                        let latency_ms = stall_timeout.as_millis() as u64;
                        let ipc_clone = ipc.clone();
                        let worker_id_clone = worker_id;
                        Self::send_request_log_if_enabled(
                            ipc_clone, worker_id_clone, &main_config,
                            client_ip, method_str.clone(), path.clone(),
                            408, latency_ms, site_id.to_string(), user_agent.clone(),
                            false,
                        );
                        Ok(Self::build_response_with_alt_svc(408, "Request timeout".to_string(), "text/plain", &alt_svc, &main_config))
                    }
                }
            }
            crate::proxy::WafDecision::Block(status, message) => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_blocked(&site_id);
                }
                let site_theme =
                    target
                        .site_config
                        .error_pages
                        .theme
                        .as_ref()
                        .map(|theme_config| {
                            theme_config.to_theme_config(waf.error_page_manager.theme())
                        });
                let body = waf.error_page_manager.render_page_with_theme(
                    status,
                    Some(&message),
                    site_theme.as_ref(),
                );
                let body_len = body.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(
                        body_len,
                        BandwidthProtocol::Http,
                        EgressDirection::Blocked,
                    );
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method_str.clone(),
                    path.clone(),
                    status,
                    start.elapsed().as_millis() as u64,
                    site_id.to_string(),
                    user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_alt_svc(
                    status,
                    body,
                    "text/html",
                    &alt_svc,
                    &main_config,
                ))
            }
            crate::proxy::WafDecision::Challenge(html) => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_challenged(&site_id);
                }
                let body_len = html.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(
                        body_len,
                        BandwidthProtocol::Http,
                        EgressDirection::Challenged,
                    );
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method_str.clone(),
                    path.clone(),
                    200,
                    start.elapsed().as_millis() as u64,
                    site_id.to_string(),
                    user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    &alt_svc,
                    &main_config,
                ))
            }
            crate::proxy::WafDecision::ChallengeWithCookie {
                html,
                session_cookie_name,
                session_cookie_value,
                session_cookie_max_age,
            } => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_challenged(&site_id);
                }
                let body_len = html.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(
                        body_len,
                        BandwidthProtocol::Http,
                        EgressDirection::Challenged,
                    );
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let cookie = format!(
                    "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                    session_cookie_name, session_cookie_value, session_cookie_max_age
                );
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method_str.clone(),
                    path.clone(),
                    200,
                    start.elapsed().as_millis() as u64,
                    site_id.to_string(),
                    user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                    &alt_svc,
                    &main_config,
                ))
            }
            crate::proxy::WafDecision::Tarpit(tar_path) => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_blocked(&site_id);
                }
                let html = waf.generate_tarpit_response(&tar_path);
                let body_len = html.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(
                        body_len,
                        BandwidthProtocol::Http,
                        EgressDirection::Blocked,
                    );
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id;
                Self::send_request_log_if_enabled(
                    ipc_clone,
                    worker_id_clone,
                    &main_config,
                    client_ip,
                    method_str.clone(),
                    path.clone(),
                    200,
                    start.elapsed().as_millis() as u64,
                    site_id.to_string(),
                    user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_alt_svc(
                    200,
                    html,
                    "text/html",
                    &alt_svc,
                    &main_config,
                ))
            }
            crate::proxy::WafDecision::Pass => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_proxied(&site_id);
                }
                if let Some(upgraded) = on_upgrade {
                    let ws_config = target.site_config.websocket.clone();
                    let target_clone = target.clone();
                    let path_clone = path.clone();
                    let waf_clone = waf.clone();

                    tracing::info!(
                        client_ip = %client_ip,
                        path = %path_clone,
                        upstream = %target_clone.upstream,
                        "WebSocket upgrade request accepted"
                    );

                    tokio::spawn(async move {
                        Self::handle_websocket_tunnel(
                            upgraded,
                            target_clone,
                            path_clone,
                            waf_clone,
                            client_ip,
                            ws_config,
                        )
                        .await;
                    });

                    return Ok(Self::build_websocket_response(&parts.headers));
                }

                // Check for AxumDynamic plugin backend
                if matches!(target.backend_type, crate::router::BackendType::AxumDynamic) {
                    if let Some(pm) = router.plugin_manager() {
                        if let Some(plugin_router) = pm.get_axum_router() {
                            tracing::debug!(
                                "Routing to AxumDynamic plugin for site {} path {}",
                                site_id,
                                path
                            );
                            // Build request for plugin router from available parts
                            let mut plugin_req_builder = http::Request::builder()
                                .method(parts.method.clone())
                                .uri(parts.uri.clone());
                            for (name, value) in parts.headers.iter() {
                                plugin_req_builder = plugin_req_builder.header(name, value);
                            }
                            let plugin_req = plugin_req_builder
                                .body(axum::body::Body::empty())
                                .unwrap_or_else(|_| http::Request::new(axum::body::Body::empty()));

                            return Self::handle_axum_dynamic_request(
                                plugin_req,
                                plugin_router,
                                &alt_svc,
                                &main_config,
                            )
                            .await;
                        }
                    }
                    tracing::warn!(
                        "AxumDynamic backend for site {} but no plugin loaded, falling back to upstream",
                        site_id
                    );
                }

                // Handle static file serving
                if matches!(target.backend_type, crate::router::BackendType::Static) {
                    if let Some(ref static_handler) = target.static_handler {
                        let accept_encoding = parts
                            .headers
                            .get("accept-encoding")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        let if_none_match = parts
                            .headers
                            .get("if-none-match")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        let if_modified_since = parts
                            .headers
                            .get("if-modified-since")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        let range_header = parts
                            .headers
                            .get("range")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());

                        match static_handler
                            .serve(
                                &path,
                                &method,
                                accept_encoding.as_deref(),
                                if_none_match.as_deref(),
                                if_modified_since.as_deref(),
                                range_header.as_deref(),
                            )
                            .await
                        {
                            Ok(response) => {
                                let mut builder = http::Response::builder().status(response.status);
                                for (name, value) in response.headers {
                                    builder = builder.header(&name, &value);
                                }
                                match response.body {
                                    crate::static_files::StaticResponseBody::InMemory(body) => {
                                        return Ok(builder
                                            .body(Full::new(body).boxed())
                                            .unwrap_or_else(|_| {
                                                crate::http::fallback_error_boxed()
                                            }));
                                    }
                                    crate::static_files::StaticResponseBody::Buffered(path) => {
                                        tracing::debug!(
                                            "Zero-copy streaming for {}",
                                            path.display()
                                        );
                                        let file = match tokio::fs::File::open(&path).await {
                                            Ok(f) => f,
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to open {}: {}",
                                                    path.display(),
                                                    e
                                                );
                                                return Ok(Response::builder()
                                                    .status(500)
                                                    .body(
                                                        Full::new(Bytes::from_static(
                                                            b"Internal Server Error",
                                                        ))
                                                        .boxed(),
                                                    )
                                                    .unwrap_or_else(|_| {
                                                        crate::http::fallback_error_boxed()
                                                    }));
                                            }
                                        };
                                        use futures::StreamExt;
                                        use http_body_util::StreamBody;
                                        use tokio_util::io::ReaderStream;
                                        let stream = ReaderStream::new(file);
                                        let mut body = StreamBody::new(stream);
                                        let mut body_bytes = Vec::new();
                                        while let Some(chunk) = body.next().await {
                                            match chunk {
                                                Ok(bytes) => body_bytes.extend_from_slice(&bytes),
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "Failed to read body chunk: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        let body = Bytes::from(body_bytes);
                                        return Ok(builder
                                            .body(Full::new(body).boxed())
                                            .unwrap_or_else(|_| {
                                                crate::http::fallback_error_boxed()
                                            }));
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Static file error for {}: {}", path, e);
                            }
                        }
                    }
                }

                // Serverless function dispatch
                if matches!(target.backend_type, crate::router::BackendType::Serverless) {
                    if let Some(ref sm) = serverless_manager {
                        let body_bytes_for_serverless: Bytes = full_body_arc.as_ref().clone();
                        match crate::serverless::manager::handle_serverless_function(
                            sm,
                            &method,
                            &path,
                            &parts.headers,
                            Some(body_bytes_for_serverless),
                        )
                        .await
                        {
                            Ok(response) => {
                                let status = response.status();
                                Self::send_request_log_if_enabled(
                                    ipc.clone(),
                                    worker_id,
                                    &main_config,
                                    client_ip,
                                    method_str.clone(),
                                    path.clone(),
                                    status.as_u16(),
                                    start.elapsed().as_millis() as u64,
                                    site_id.to_string(),
                                    user_agent.clone(),
                                    false,
                                );
                                return Ok(Response::builder()
                                    .status(status)
                                    .body(Full::new(response.into_body()).boxed())
                                    .unwrap_or_else(|_| crate::http::fallback_error_boxed()));
                            }
                            Err(e) => {
                                tracing::warn!("Serverless function error for {}: {}", path, e);
                                return Ok(Self::build_response_with_alt_svc(
                                    502,
                                    format!("Serverless Error: {}", e),
                                    "text/plain",
                                    &alt_svc,
                                    &main_config,
                                ));
                            }
                        }
                    }
                    tracing::warn!(
                        "Serverless backend for site {} but no serverless manager",
                        site_id
                    );
                    return Ok(Self::build_response_with_alt_svc(
                        502,
                        "Serverless backend misconfigured: no runtime available".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }

                // FastCGI and PHP backend dispatch
                if matches!(
                    target.backend_type,
                    crate::router::BackendType::FastCgi | crate::router::BackendType::Php
                ) {
                    if let Some(ref socket) = target.backend_socket {
                        let body_bytes_for_fcgi: Bytes = full_body_arc.as_ref().clone();

                        if matches!(target.backend_type, crate::router::BackendType::Php) {
                            if let Some(php_client) =
                                crate::php::create_php_client(&target.site_config)
                            {
                                match php_client
                                    .execute(
                                        &method,
                                        &parts.uri,
                                        &parts.headers,
                                        body_bytes_for_fcgi,
                                    )
                                    .await
                                {
                                    Ok(response) => {
                                        return Ok(response
                                            .into_http_response()
                                            .map(|b| Full::new(b).boxed()));
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "PHP backend error for site {} path {}: {}",
                                            site_id,
                                            path,
                                            e
                                        );
                                        return Ok(Self::build_response_with_alt_svc(
                                            502,
                                            format!("Backend Error: {}", e),
                                            "text/plain",
                                            &alt_svc,
                                            &main_config,
                                        ));
                                    }
                                }
                            }
                        }

                        let fcgi_config =
                            target.site_config.proxy.fastcgi.clone().unwrap_or_default();

                        let client = crate::fastcgi::FastCgiClient::new(socket.to_string());
                        match client
                            .execute(
                                &method,
                                &parts.uri,
                                &parts.headers,
                                body_bytes_for_fcgi,
                                &fcgi_config,
                            )
                            .await
                        {
                            Ok(response) => {
                                return Ok(response
                                    .into_http_response()
                                    .map(|b| Full::new(b).boxed()));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "FastCGI error for site {} path {}: {}",
                                    site_id,
                                    path,
                                    e
                                );
                                return Ok(Self::build_response_with_alt_svc(
                                    502,
                                    format!("Backend Error: {}", e),
                                    "text/plain",
                                    &alt_svc,
                                    &main_config,
                                ));
                            }
                        }
                    }
                    tracing::warn!(
                        "FastCGI/PHP backend for site {} but no socket configured",
                        site_id
                    );
                    return Ok(Self::build_response_with_alt_svc(
                        502,
                        "Backend misconfigured: no socket configured".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }

                // CGI backend dispatch
                if matches!(target.backend_type, crate::router::BackendType::Cgi) {
                    if let Some(ref cgi_config) = target.site_config.proxy.cgi {
                        match crate::cgi::CgiHandler::new(cgi_config) {
                            Ok(handler) => {
                                let body_bytes_for_cgi: Bytes = full_body_arc.as_ref().clone();
                                match handler
                                    .execute(
                                        &method,
                                        &parts.uri,
                                        &parts.headers,
                                        body_bytes_for_cgi,
                                        Some(client_ip),
                                    )
                                    .await
                                {
                                    Ok(response) => {
                                        return Ok(response
                                            .into_http_response()
                                            .map(|b| Full::new(b).boxed()));
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "CGI error for site {} path {}: {}",
                                            site_id,
                                            path,
                                            e
                                        );
                                        let status = match &e {
                                            crate::cgi::CgiError::NotFound(_) => 404,
                                            crate::cgi::CgiError::Forbidden(_) => 403,
                                            crate::cgi::CgiError::Timeout => 504,
                                            _ => 502,
                                        };
                                        return Ok(Self::build_response_with_alt_svc(
                                            status,
                                            format!("CGI Error: {}", e),
                                            "text/plain",
                                            &alt_svc,
                                            &main_config,
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "CGI handler creation failed for site {} path {}: {}",
                                    site_id,
                                    path,
                                    e
                                );
                                return Ok(Self::build_response_with_alt_svc(
                                    500,
                                    format!("CGI Configuration Error: {}", e),
                                    "text/plain",
                                    &alt_svc,
                                    &main_config,
                                ));
                            }
                        }
                    }
                    tracing::warn!(
                        "CGI backend for site {} but no CGI config configured",
                        site_id
                    );
                    return Ok(Self::build_response_with_alt_svc(
                        502,
                        "Backend misconfigured: no CGI root configured".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }

                // AppServer (Granian) backend dispatch
                if matches!(target.backend_type, crate::router::BackendType::AppServer) {
                    if let Some(ref app_servers) = app_servers {
                        let app_servers_read = app_servers.read().await;
                        if let Some(supervisor) = app_servers_read.get(site_id.as_ref()) {
                            let socket_path = supervisor.config().resolve_socket_path();
                            let body_bytes_for_appserver: Bytes = full_body_arc.as_ref().clone();

                            let fcgi_config =
                                target.site_config.proxy.fastcgi.clone().unwrap_or_default();

                            let client = crate::fastcgi::FastCgiClient::new(
                                socket_path.to_string_lossy().to_string(),
                            );
                            match client
                                .execute(
                                    &method,
                                    &parts.uri,
                                    &parts.headers,
                                    body_bytes_for_appserver,
                                    &fcgi_config,
                                )
                                .await
                            {
                                Ok(response) => {
                                    return Ok(response
                                        .into_http_response()
                                        .map(|b| Full::new(b).boxed()));
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "AppServer (Granian) error for site {} path {}: {}",
                                        site_id,
                                        path,
                                        e
                                    );
                                    return Ok(Self::build_response_with_alt_svc(
                                        502,
                                        format!("Backend Error: {}", e),
                                        "text/plain",
                                        &alt_svc,
                                        &main_config,
                                    ));
                                }
                            }
                        }
                    }
                    tracing::warn!(
                        "AppServer backend for site {} but no app server running",
                        site_id
                    );
                    return Ok(Self::build_response_with_alt_svc(
                        502,
                        "Backend misconfigured: app server not available".to_string(),
                        "text/plain",
                        &alt_svc,
                        &main_config,
                    ));
                }

                // FastCGI, PHP, CGI, and AppServer backends fall through to upstream proxy
                // The RouteTarget has the appropriate socket configured in backend_socket
                if let Some(pm) = router.plugin_manager() {
                    // Use truncated body for WAF inspection (WASM filters)
                    let body_bytes: Bytes = body_slice
                        .as_ref()
                        .map(|b| b.to_vec().into())
                        .unwrap_or_default();

                    let mut filter_builder = http::Request::builder()
                        .method(method.clone())
                        .uri(&parts.uri);
                    for (name, value) in parts.headers.iter() {
                        filter_builder = filter_builder.header(name, value);
                    }
                    let filter_req = filter_builder.body(body_bytes.clone()).unwrap_or_else(|_| {
                        http::Request::builder()
                            .method(method.clone())
                            .body(Bytes::new())
                            .unwrap_or_else(|_| http::Request::new(Bytes::new()))
                    });

                    // Use per-site WASM plugins if configured, otherwise run all
                    let wasm_result =
                        if let Some(ref plugin_names) = target.site_config.proxy.wasm_plugins {
                            pm.apply_wasm_filters_with_plugins(
                                filter_req,
                                plugin_names,
                                std::collections::HashMap::new(),
                            )
                        } else {
                            pm.apply_wasm_filters(filter_req, std::collections::HashMap::new())
                        };

                    match wasm_result {
                        Ok(crate::plugin::WasmFilterResult::Pass) => {}
                        Ok(crate::plugin::WasmFilterResult::Block(status, msg)) => {
                            tracing::info!(
                                "WASM plugin blocked request to {} from {}: {}",
                                path,
                                client_ip,
                                msg
                            );
                            let body = waf
                                .error_page_manager
                                .render_page(status.as_u16(), Some(&msg));
                            Self::send_request_log_if_enabled(
                                ipc.clone(),
                                worker_id,
                                &main_config,
                                client_ip,
                                method_str.clone(),
                                path.clone(),
                                status.as_u16(),
                                start.elapsed().as_millis() as u64,
                                site_id.to_string(),
                                user_agent.clone(),
                                false,
                            );
                            return Ok(Self::build_response_with_alt_svc(
                                status.as_u16(),
                                body,
                                "text/html",
                                &alt_svc,
                                &main_config,
                            ));
                        }
                        Ok(crate::plugin::WasmFilterResult::Challenge(reason)) => {
                            tracing::info!(
                                "WASM plugin issued challenge for {} from {}: {}",
                                path,
                                client_ip,
                                reason
                            );
                            let escaped = reason
                                .replace('&', "&amp;")
                                .replace('<', "&lt;")
                                .replace('>', "&gt;")
                                .replace('"', "&quot;");
                            let html = format!(
                                "<html><body><h1>Challenge Required</h1><p>{}</p></body></html>",
                                escaped
                            );
                            Self::send_request_log_if_enabled(
                                ipc.clone(),
                                worker_id,
                                &main_config,
                                client_ip,
                                method_str.clone(),
                                path.clone(),
                                200,
                                start.elapsed().as_millis() as u64,
                                site_id.to_string(),
                                user_agent.clone(),
                                false,
                            );
                            return Ok(Self::build_response_with_alt_svc(
                                200,
                                html,
                                "text/html",
                                &alt_svc,
                                &main_config,
                            ));
                        }
                        Err(e) => {
                            tracing::error!("WASM plugin filter error: {}", e);
                            match target.site_config.proxy.wasm_on_error {
                                crate::config::site::WasmOnError::FailClosed => {
                                    let body = waf
                                        .error_page_manager
                                        .render_page(500, Some("WASM plugin error"));
                                    return Ok(Self::build_response_with_alt_svc(
                                        500,
                                        body,
                                        "text/html",
                                        &alt_svc,
                                        &main_config,
                                    ));
                                }
                                crate::config::site::WasmOnError::FailOpen => {
                                    // Continue to proxy on plugin error (fail-open)
                                }
                            }
                        }
                    }
                }

                // Validate upload if content-type indicates an upload
                let content_type = parts
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok());
                if let Some(ct) = content_type {
                    if crate::upload::is_upload_content_type(ct) {
                        if let Some(upload_validator) = crate::waf::get_upload_validator() {
                            let effective_config = upload_validator.get_effective_config(&path);
                            if effective_config.scan_with_yara
                                || effective_config.max_size_bytes > 0
                            {
                                match upload_validator.validate_bytes(&full_body_arc, &path).await {
                                    Ok(result) => {
                                        if !result.is_clean() {
                                            tracing::warn!(
                                                path = %path,
                                                mime_type = %result.mime_type,
                                                matches = ?result.yara_matches,
                                                "Upload blocked due to malware detection"
                                            );
                                            let body = waf.error_page_manager.render_page(
                                                403,
                                                Some("Upload blocked: malware detected"),
                                            );
                                            return Ok(Self::build_response_with_alt_svc(
                                                403,
                                                body,
                                                "text/html",
                                                &alt_svc,
                                                &main_config,
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            path = %path,
                                            error = %e,
                                            "Upload validation failed"
                                        );
                                        let (status, _message) = match &e {
                                            crate::upload::UploadValidationError::SizeExceeded { .. } => (
                                                413,
                                                "Upload size exceeds maximum allowed",
                                            ),
                                            crate::upload::UploadValidationError::TypeNotAllowed { .. } => (
                                                415,
                                                "Upload file type not allowed",
                                            ),
                                            _ => (
                                                400,
                                                "Upload validation failed",
                                            ),
                                        };
                                        let body = waf
                                            .error_page_manager
                                            .render_page(status, Some(&e.to_string()));
                                        return Ok(Self::build_response_with_alt_svc(
                                            status,
                                            body,
                                            "text/html",
                                            &alt_svc,
                                            &main_config,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                let target_url = format!("{}{}", target.upstream, path);

                let headers_to_filter = build_headers_to_filter(
                    &main_config.security.more_clear_headers,
                    &target
                        .site_config
                        .security
                        .more_clear_headers
                        .iter()
                        .chain(
                            target
                                .site_config
                                .security_headers
                                .more_clear_headers
                                .iter(),
                        )
                        .cloned()
                        .collect::<Vec<_>>(),
                );

                let site_tls_config = target
                    .site_config
                    .proxy
                    .upstream
                    .as_ref()
                    .and_then(|u| u.tls.as_ref())
                    .and_then(UpstreamTlsConfig::from_site_config);
                let site_client = site_tls_config.as_ref().map(|tls| {
                    create_upstream_client(
                        std::time::Duration::from_secs(5),
                        100,
                        std::time::Duration::from_secs(30),
                        tls,
                    )
                });
                let forwarding_client = site_client.as_ref().unwrap_or(&client);

                let needs_body_transform = router.plugin_manager().is_some()
                    || mesh_transport.is_some()
                    || target
                        .site_config
                        .r#static
                        .enable_minification
                        .unwrap_or(false)
                    || target.site_config.image_poison.enabled.unwrap_or(false)
                    || target
                        .site_config
                        .r#static
                        .enable_compression
                        .unwrap_or(false);

                if !needs_body_transform && !crate::http_client::is_quictunnel_url(&target.upstream)
                {
                    let mut forward_header_map = http::HeaderMap::new();
                    for (key, value) in &build_forward_headers(
                        client_ip,
                        &parts.headers,
                        target
                            .site_config
                            .proxy
                            .headers
                            .as_ref()
                            .unwrap_or(&ProxyHeadersConfig::default()),
                        true,
                    ) {
                        if let (Ok(name), Ok(val)) = (
                            key.parse::<http::HeaderName>(),
                            value.parse::<http::HeaderValue>(),
                        ) {
                            forward_header_map.insert(name, val);
                        }
                    }

                    match send_request_streaming(
                        forwarding_client,
                        method,
                        &target_url,
                        Some(full_body_arc.as_ref().clone()),
                        forward_header_map,
                        Some(std::time::Duration::from_secs(30)),
                    )
                    .await
                    {
                        Ok(upstream_resp) => {
                            if let Some(ref metrics) = metrics {
                                metrics.record_site_upstream_success(&site_id);
                            }
                            let (resp_parts, _upstream_body) = upstream_resp.into_parts();
                            let status = resp_parts.status.as_u16();

                            let body_len = resp_parts
                                .headers
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(0);

                            if let Some(ref m) = metrics {
                                m.bandwidth.record_proxied(
                                    request_body_size,
                                    body_len,
                                    &target.upstream,
                                );
                                m.bandwidth.record_site_proxied(
                                    &site_id,
                                    request_body_size,
                                    body_len,
                                );
                                m.bandwidth.record_egress(
                                    body_len,
                                    BandwidthProtocol::Http,
                                    EgressDirection::Proxied,
                                );
                                m.bandwidth.record_site_egress(&site_id, body_len);
                            }

                            let filtered_headers =
                                filter_response_headers(&resp_parts.headers, &headers_to_filter);

                            let mut builder = Response::builder().status(status);
                            for (key, value) in filtered_headers {
                                builder = builder.header(&key, &value);
                            }

                            if let Some(ref alt_svc) = alt_svc {
                                builder = builder.header("Alt-Svc", alt_svc.as_str());
                            }

                            if target.site_config.security_headers.enabled.unwrap_or(false)
                                || main_config.security.global_security_headers
                            {
                                builder = Self::inject_security_headers(
                                    builder,
                                    &target.site_config.security_headers,
                                );
                            }

                            if target
                                .site_config
                                .security_headers
                                .date_header
                                .unwrap_or(true)
                            {
                                let jitter = target
                                    .site_config
                                    .security_headers
                                    .date_jitter_seconds
                                    .unwrap_or(5);
                                builder =
                                    builder.header("Date", generate_stealth_timestamp(jitter));
                            }

                            if let Some(ref token) =
                                target.site_config.security_headers.server_token
                            {
                                builder = builder.header("Server", token.as_str());
                            }

                            return Ok(builder
                                .body(
                                    http_body_util::Full::new(full_body_arc.as_ref().clone())
                                        .boxed(),
                                )
                                .unwrap_or_else(|_| {
                                    Self::build_response_with_alt_svc(
                                        500,
                                        crate::http::reason_phrase(500).to_string(),
                                        "text/plain",
                                        &alt_svc,
                                        &main_config,
                                    )
                                }));
                        }
                        Err(e) => {
                            if let Some(ref metrics) = metrics {
                                metrics.record_site_upstream_failure(&site_id);
                            }
                            tracing::error!("Upstream streaming error: {}", e);
                            let error_body = "Bad Gateway".to_string();
                            let error_len = error_body.len() as u64;
                            if let Some(ref m) = metrics {
                                m.bandwidth.record_egress(
                                    error_len,
                                    BandwidthProtocol::Http,
                                    EgressDirection::Error,
                                );
                                m.bandwidth.record_site_egress(&site_id, error_len);
                            }
                            return Ok(Self::build_response_with_alt_svc(
                                502,
                                error_body,
                                "text/plain",
                                &alt_svc,
                                &main_config,
                            ));
                        }
                    }
                }

                let resp = if crate::http_client::is_quictunnel_url(&target.upstream) {
                    crate::http_client::send_request_via_quic_tunnel(
                        method,
                        &target_url,
                        Some(&parts.headers),
                        Some(full_body_arc.as_ref().clone()),
                        Some(std::time::Duration::from_secs(30)),
                    )
                    .await
                } else {
                    send_request_with_body_and_timeout(
                        forwarding_client,
                        method,
                        &target_url,
                        Some(full_body_arc.as_ref().clone()),
                        Some(std::time::Duration::from_secs(30)),
                    )
                    .await
                };

                match resp {
                    Ok(resp) => {
                        if let Some(ref metrics) = metrics {
                            metrics.record_site_upstream_success(&site_id);
                        }
                        let status = resp.status_code();

                        let content_type = resp
                            .headers
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());

                        let last_modified = resp
                            .headers
                            .get("last-modified")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());

                        let mut headers =
                            filter_response_headers(&resp.headers, &headers_to_filter);

                        let mut body = resp.body;
                        let mut body_len = body.len() as u64;

                        // Apply WASM response transforms
                        if let Some(pm) = router.plugin_manager() {
                            let body_for_transform = body.clone();
                            let wasm_resp = http::Response::builder()
                                .status(status)
                                .body(body_for_transform)
                                .unwrap_or_else(|_| {
                                    http::Response::builder()
                                        .status(status)
                                        .body(Bytes::new())
                                        .unwrap_or_else(|_| http::Response::new(Bytes::new()))
                                });
                            // Use per-site WASM plugins for response transforms if configured
                            let transform_result = if let Some(ref plugin_names) =
                                target.site_config.proxy.wasm_plugins
                            {
                                pm.apply_wasm_response_transforms_with_plugins(
                                    wasm_resp,
                                    plugin_names,
                                    std::collections::HashMap::new(),
                                )
                            } else {
                                pm.apply_wasm_response_transforms(
                                    wasm_resp,
                                    std::collections::HashMap::new(),
                                )
                            };
                            match transform_result {
                                Ok(transformed) => {
                                    body = transformed.into_body();
                                    body_len = body.len() as u64;
                                }
                                Err(e) => {
                                    tracing::error!("WASM response transform error: {}", e);
                                    // Keep original body (already cloned)
                                }
                            }
                        }

                        let accept_encoding: Option<&str> = parts
                            .headers
                            .get("accept-encoding")
                            .and_then(|v: &http::HeaderValue| v.to_str().ok());

                        if let Some(ref mt) = mesh_transport {
                            let (minification, image_protection, compression) = tokio::join!(
                                mt.get_minification_for_site(&site_id),
                                mt.get_image_protection_for_site(&site_id),
                                mt.get_compression_for_site(&site_id),
                            );

                            let config = crate::http::response_transform::ResponseTransformConfig::from_mesh_config(
                                minification.as_ref(),
                                image_protection.as_ref(),
                                compression.as_ref(),
                            );

                            if let Some(ref min_settings) = config.minification {
                                body = crate::http::response_transform::apply_minification(
                                    body,
                                    content_type.as_deref(),
                                    min_settings,
                                );
                                body_len = body.len() as u64;
                            }

                            if let Some(ref img_settings) = config.image_poisoning {
                                let mut is_image = content_type
                                    .as_ref()
                                    .map(|ct| ct.starts_with("image/"))
                                    .unwrap_or(false);
                                if !is_image {
                                    let path_str = path.to_string();
                                    is_image = IMAGE_PROTECTION_REGEX.is_match(&path_str);
                                }
                                let in_range = body_len >= img_settings.min_size;

                                if is_image && in_range {
                                    let path_str = path.to_string();
                                    let whitelisted = img_settings
                                        .whitelist_patterns
                                        .map(|patterns| {
                                            patterns.iter().any(|p| {
                                                if let Some(re) = get_cached_regex(p) {
                                                    re.is_match(&path_str)
                                                } else {
                                                    false
                                                }
                                            })
                                        })
                                        .unwrap_or(false);

                                    if !whitelisted {
                                        let site_id_for_poison = site_id.to_string();
                                        body = Self::apply_image_poisoning(
                                            body,
                                            site_id_for_poison,
                                            last_modified.clone(),
                                        )
                                        .await;
                                        body_len = body.len() as u64;
                                    }
                                }
                            }

                            if let Some(ref comp_settings) = config.compression {
                                let (compressed_body, encoding) =
                                    crate::http::response_transform::apply_compression(
                                        body.clone(),
                                        accept_encoding,
                                        comp_settings,
                                    );

                                if let Some(enc) = encoding {
                                    body = compressed_body;
                                    body_len = body.len() as u64;
                                    headers.retain(|(k, _)| k.to_lowercase() != "content-encoding");
                                    headers.push(("Content-Encoding".to_string(), enc));
                                }
                            }
                        } else {
                            let static_config = &target.site_config.r#static;
                            let image_poison_config = &target.site_config.image_poison;

                            let config = crate::http::response_transform::ResponseTransformConfig::from_static_config(
                                static_config,
                                image_poison_config,
                            );

                            if let Some(ref min_settings) = config.minification {
                                body = crate::http::response_transform::apply_minification(
                                    body,
                                    content_type.as_deref(),
                                    min_settings,
                                );
                                body_len = body.len() as u64;
                            }

                            if let Some(ref img_settings) = config.image_poisoning {
                                let mut is_image = content_type
                                    .as_ref()
                                    .map(|ct| ct.starts_with("image/"))
                                    .unwrap_or(false);
                                if !is_image {
                                    let path_str = path.to_string();
                                    is_image = IMAGE_PROTECTION_REGEX.is_match(&path_str);
                                }
                                let in_range = body_len >= img_settings.min_size;

                                if is_image && in_range {
                                    let path_str = path.to_string();
                                    let whitelisted = img_settings
                                        .whitelist_patterns
                                        .map(|patterns| {
                                            patterns.iter().any(|p| {
                                                if let Some(re) = get_cached_regex(p) {
                                                    re.is_match(&path_str)
                                                } else {
                                                    false
                                                }
                                            })
                                        })
                                        .unwrap_or(false);

                                    if !whitelisted {
                                        let site_id_for_poison = site_id.to_string();
                                        body = Self::apply_image_poisoning(
                                            body,
                                            site_id_for_poison,
                                            last_modified.clone(),
                                        )
                                        .await;
                                        body_len = body.len() as u64;
                                    }
                                }
                            }

                            if let Some(ref comp_settings) = config.compression {
                                let (compressed_body, encoding) =
                                    crate::http::response_transform::apply_compression(
                                        body.clone(),
                                        accept_encoding,
                                        comp_settings,
                                    );

                                if let Some(enc) = encoding {
                                    body = compressed_body;
                                    body_len = body.len() as u64;
                                    headers.retain(|(k, _)| k.to_lowercase() != "content-encoding");
                                    headers.push(("Content-Encoding".to_string(), enc));
                                }
                            }
                        }

                        if let Some(ref m) = metrics {
                            m.bandwidth.record_proxied(
                                request_body_size,
                                body_len,
                                &target.upstream,
                            );
                            m.bandwidth
                                .record_site_proxied(&site_id, request_body_size, body_len);
                            m.bandwidth.record_egress(
                                body_len,
                                BandwidthProtocol::Http,
                                EgressDirection::Proxied,
                            );
                            m.bandwidth.record_site_egress(&site_id, body_len);
                        }

                        let mut builder = Response::builder().status(status);
                        for (key, value) in headers {
                            builder = builder.header(&key, &value);
                        }

                        if let Some(ref alt_svc) = alt_svc {
                            builder = builder.header("Alt-Svc", alt_svc.as_str());
                        }

                        if target.site_config.security_headers.enabled.unwrap_or(false)
                            || main_config.security.global_security_headers
                        {
                            builder = Self::inject_security_headers(
                                builder,
                                &target.site_config.security_headers,
                            );
                        }

                        if target
                            .site_config
                            .security_headers
                            .date_header
                            .unwrap_or(true)
                        {
                            let jitter = target
                                .site_config
                                .security_headers
                                .date_jitter_seconds
                                .unwrap_or(5);
                            builder = builder.header("Date", generate_stealth_timestamp(jitter));
                        }

                        if let Some(ref token) = target.site_config.security_headers.server_token {
                            builder = builder.header("Server", token.as_str());
                        }

                        Ok(builder.body(Full::new(body).boxed()).unwrap_or_else(|_| {
                            Self::build_response_with_alt_svc(
                                500,
                                crate::http::reason_phrase(500).to_string(),
                                "text/plain",
                                &alt_svc,
                                &main_config,
                            )
                        }))
                    }
                    Err(e) => {
                        if let Some(ref metrics) = metrics {
                            metrics.record_site_upstream_failure(&site_id);
                        }
                        tracing::error!("Upstream error: {}", e);
                        let error_body = "Bad Gateway".to_string();
                        let error_len = error_body.len() as u64;
                        if let Some(ref m) = metrics {
                            m.bandwidth.record_egress(
                                error_len,
                                BandwidthProtocol::Http,
                                EgressDirection::Error,
                            );
                            m.bandwidth.record_site_egress(&site_id, error_len);
                        }
                        Ok(Self::build_response_with_alt_svc(
                            502,
                            error_body,
                            "text/plain",
                            &alt_svc,
                            &main_config,
                        ))
                    }
                }
            }
        };

        let latency_ms = start.elapsed().as_millis() as u64;
        if let Some(ref metrics) = metrics {
            metrics.record_site_request_end(&site_id, latency_ms);
        }

        let status = response.as_ref().map(|r| r.status().as_u16()).unwrap_or(0);
        let ipc_clone = ipc.clone();
        let worker_id_clone = worker_id;
        Self::send_request_log_if_enabled(
            ipc_clone,
            worker_id_clone,
            &main_config,
            client_ip,
            method_str,
            path.clone(),
            status,
            latency_ms,
            site_id.to_string(),
            user_agent.clone(),
            false,
        );

        response
    }

    fn inject_security_headers(
        builder: http::response::Builder,
        config: &crate::config::SiteSecurityHeadersConfig,
    ) -> http::response::Builder {
        inject_security_headers(builder, config)
    }

    fn handle_drain_request(
        _req: hyper::Request<hyper::body::Incoming>,
        drain_state: &Arc<WorkerDrainState>,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let drain_id = crate::utils::safe_unix_duration().as_millis() as u64;

        let accepted = drain_state.start_drain(drain_id);
        drain_state.stop_accepting();

        let status = drain_state.get_status();
        let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());

        let status_code = if accepted { 200 } else { 409 };
        Ok(Self::build_response_with_alt_svc(
            status_code,
            body,
            "application/json",
            alt_svc,
            main_config,
        ))
    }

    fn handle_drain_status_request(
        _req: hyper::Request<hyper::body::Incoming>,
        drain_state: &Arc<WorkerDrainState>,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let status = drain_state.get_status();
        let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());

        Ok(Self::build_response_with_alt_svc(
            200,
            body,
            "application/json",
            alt_svc,
            main_config,
        ))
    }

    fn handle_health_request(
        drain_state: &Option<Arc<WorkerDrainState>>,
        alt_svc: &Option<String>,
        _main_config: &Arc<MainConfig>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let (status_code, body) = if let Some(state) = drain_state {
            let status = state.get_status();
            if status.is_draining {
                let body = serde_json::json!({
                    "status": "draining",
                    "active_connections": status.active_connections,
                    "drain_elapsed_secs": status.drain_elapsed_secs,
                });
                (503, body.to_string())
            } else {
                let body = serde_json::json!({
                    "status": "healthy",
                });
                (200, body.to_string())
            }
        } else {
            let body = serde_json::json!({
                "status": "healthy",
            });
            (200, body.to_string())
        };

        let mut builder = Response::builder()
            .status(status_code)
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len());

        if status_code == 503 {
            builder = builder.header("Retry-After", "5");
        }

        if let Some(alt_svc) = alt_svc {
            builder = builder.header("Alt-Svc", alt_svc.as_str());
        }

        Ok(builder
            .body(Full::new(Bytes::from(body)).boxed())
            .unwrap_or_else(|_| crate::http::fallback_error_boxed()))
    }

    fn handle_ready_request(
        drain_state: &Option<Arc<WorkerDrainState>>,
        alt_svc: &Option<String>,
        _main_config: &Arc<MainConfig>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let (status_code, body) = if let Some(state) = drain_state {
            let status = state.get_status();
            if status.is_draining || status.stopped_accepting {
                let body = serde_json::json!({
                    "ready": false,
                    "reason": "draining",
                    "active_connections": status.active_connections,
                });
                (503, body.to_string())
            } else {
                let body = serde_json::json!({
                    "ready": true,
                });
                (200, body.to_string())
            }
        } else {
            let body = serde_json::json!({
                "ready": true,
            });
            (200, body.to_string())
        };

        let mut builder = Response::builder()
            .status(status_code)
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len());

        if status_code == 503 {
            builder = builder.header("Retry-After", "5");
        }

        if let Some(alt_svc) = alt_svc {
            builder = builder.header("Alt-Svc", alt_svc.as_str());
        }

        Ok(builder
            .body(Full::new(Bytes::from(body)).boxed())
            .unwrap_or_else(|_| crate::http::fallback_error_boxed()))
    }

    fn build_response_with_alt_svc(
        status: u16,
        body: String,
        content_type: &str,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        crate::http::response_builder::build_response_with_alt_svc(
            status,
            body,
            content_type,
            alt_svc,
            main_config,
        )
    }

    fn build_response_with_cookie(
        status: u16,
        body: String,
        content_type: &str,
        cookie: &str,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        crate::http::response_builder::build_response_with_cookie(
            status,
            body,
            content_type,
            cookie,
            alt_svc,
            main_config,
        )
    }

    async fn handle_websocket_tunnel(
        upgraded: hyper::upgrade::OnUpgrade,
        target: crate::router::RouteTarget,
        path: String,
        waf: Arc<WafCore>,
        client_ip: std::net::IpAddr,
        ws_config: SiteWebSocketConfig,
    ) {
        let upgraded = match upgraded.await {
            Ok(up) => up,
            Err(e) => {
                tracing::error!("WebSocket upgrade failed: {}", e);
                counter!("maluwaf.websocket.upgrade_failed").increment(1);
                return;
            }
        };

        counter!("maluwaf.websocket.connections").increment(1);

        let ws_stream =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;

        let (mut client_tx, mut client_rx) = ws_stream.split();

        let ws_handler = WebSocketHandler::new()
            .with_max_message_size(ws_config.max_message_size.unwrap_or(16 * 1024 * 1024))
            .with_mask_required(ws_config.mask_required.unwrap_or(false));

        let upstream_scheme =
            if target.upstream.starts_with("https://") || target.upstream.starts_with("wss://") {
                "wss"
            } else {
                "ws"
            };
        let upstream_host = target
            .upstream
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("ws://")
            .trim_start_matches("wss://");
        let upstream_url = format!("{}://{}{}", upstream_scheme, upstream_host, path);

        tracing::debug!(url = %upstream_url, "Connecting to upstream WebSocket");

        let (upstream_ws, _) = match connect_async(&upstream_url).await {
            Ok(ws) => ws,
            Err(e) => {
                tracing::error!("Failed to connect to upstream WebSocket: {}", e);
                counter!("maluwaf.websocket.upstream_failed").increment(1);
                return;
            }
        };

        counter!("maluwaf.websocket.upstream_connected").increment(1);

        let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

        let path_clone = path.clone();
        let waf_clone = waf.clone();
        let should_close = std::sync::Arc::new(RunningFlag::new());
        let should_close_clone = should_close.clone();

        let client_to_upstream = async {
            while let Some(msg_result) = client_rx.next().await {
                if !should_close_clone.is_running() {
                    break;
                }

                let msg: WsMessage = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("WebSocket client error: {}", e);
                        break;
                    }
                };

                let (method, body_vec) = match &msg {
                    WsMessage::Text(t) => ("TEXT", t.as_bytes().to_vec()),
                    WsMessage::Binary(b) => ("BINARY", b.to_vec()),
                    WsMessage::Close(_) => {
                        let _ = upstream_tx.send(WsMessage::Close(None)).await;
                        break;
                    }
                    WsMessage::Ping(data) => {
                        let _ = upstream_tx.send(WsMessage::Pong(data.clone())).await;
                        continue;
                    }
                    WsMessage::Pong(_) => continue,
                    WsMessage::Frame(_) => continue,
                };

                let mut proto_request = ProtocolRequest {
                    client_ip: SocketAddr::from((client_ip, 0)),
                    method: method.to_string(),
                    path: path_clone.clone(),
                    headers: HashMap::new(),
                    body: body_vec,
                    protocol: ProtocolType::WebSocket,
                    metadata: HashMap::new(),
                };

                let action = ws_handler.apply_waf(&mut proto_request, &waf_clone);
                match action {
                    WafAction::Block => {
                        tracing::warn!(
                            client_ip = %client_ip,
                            "WebSocket message blocked by WAF"
                        );
                        counter!("maluwaf.websocket.blocked").increment(1);
                        let _ = upstream_tx.close().await;
                        should_close_clone.stop();
                        break;
                    }
                    WafAction::LogOnly => {
                        tracing::debug!(
                            client_ip = %client_ip,
                            "WebSocket message logged by WAF"
                        );
                        counter!("maluwaf.websocket.logged").increment(1);
                    }
                    WafAction::Allow => {}
                    WafAction::Challenge | WafAction::Stall | WafAction::TarPit => {
                        tracing::debug!(
                            client_ip = %client_ip,
                            "WebSocket WAF action {:?} treated as allow",
                            action
                        );
                    }
                }

                if let Err(e) = upstream_tx.send(msg).await {
                    tracing::debug!("Upstream WebSocket send error: {}", e);
                    break;
                }
            }
        };

        let upstream_to_client = async {
            while let Some(msg_result) = upstream_rx.next().await {
                if !should_close.is_running() {
                    break;
                }

                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("WebSocket upstream error: {}", e);
                        break;
                    }
                };

                if let Err(e) = client_tx.send(msg).await {
                    tracing::debug!("Client WebSocket send error: {}", e);
                    break;
                }
            }
        };

        tokio::select! {
            _ = client_to_upstream => {}
            _ = upstream_to_client => {}
        }

        counter!("maluwaf.websocket.closed").increment(1);
        tracing::debug!("WebSocket connection closed");
    }

    fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
        is_websocket_upgrade(headers)
    }

    fn compute_websocket_accept_key(key: &str) -> String {
        compute_websocket_accept_key(key)
    }

    fn build_websocket_response(headers: &http::HeaderMap) -> Response<BoxBody<Bytes, Infallible>> {
        let ws_key = headers
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let ws_protocols = headers
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok());

        let accept_key = Self::compute_websocket_accept_key(ws_key);

        let mut builder = Response::builder()
            .status(101)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", accept_key);

        if let Some(protocols) = ws_protocols {
            builder = builder.header("Sec-WebSocket-Protocol", protocols);
        }

        builder
            .body(Full::new(Bytes::new()).boxed())
            .unwrap_or_else(|_| crate::http::fallback_error_boxed())
    }

    /// Handle requests routed to an AxumDynamic plugin backend.
    async fn handle_axum_dynamic_request(
        axum_req: http::Request<axum::body::Body>,
        plugin_router: Arc<axum::Router<()>>,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        use http_body_util::BodyExt;
        use tower::Service;

        // Call the plugin router
        let mut plugin_router_inner = (*plugin_router).clone();
        let response = plugin_router_inner.call(axum_req).await;

        match response {
            Ok(axum_resp) => {
                let (resp_parts, resp_body) = axum_resp.into_parts();
                let collected: Result<http_body_util::Collected<Bytes>, _> =
                    resp_body.collect().await;
                let resp_bytes = match collected {
                    Ok(c) => c.to_bytes(),
                    Err(_) => Bytes::new(),
                };
                Ok(Response::from_parts(
                    resp_parts,
                    Full::new(resp_bytes).boxed(),
                ))
            }
            Err(e) => Ok(Self::build_response_with_alt_svc(
                500,
                format!("Plugin error: {}", e),
                "text/plain",
                alt_svc,
                main_config,
            )),
        }
    }

    fn check_bandwidth_limit(
        waf: &Arc<WafCore>,
        client_ip: IpAddr,
        path: &str,
        start: std::time::Instant,
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        main_config: &Arc<MainConfig>,
        alt_svc: &Option<String>,
    ) -> Option<Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>> {
        if !waf.is_over_bandwidth_limit() {
            return None;
        }

        tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
        counter!("maluwaf.bandwidth.limit_exceeded").increment(1);

        let path_owned = path.to_string();
        let start_elapsed = start.elapsed().as_millis() as u64;
        let client_ip_str = client_ip.to_string();

        if let (Some(ref ipc_ref), Some(worker_id_value)) = (&ipc, worker_id) {
            let ipc_clone = ipc_ref.clone();
            tokio::spawn(async move {
                let log = crate::process::RequestLogPayload {
                    timestamp: current_timestamp(),
                    client_ip: client_ip_str,
                    method: "UNKNOWN".to_string(),
                    path: path_owned,
                    status: 503,
                    response_time_ms: start_elapsed as u32,
                    site_id: "internal".to_string(),
                    user_agent: None,
                    bytes_sent: 0,
                    bytes_received: 0,
                };
                let mut ipc_guard = ipc_clone.lock().await;
                let msg = crate::process::Message::WorkerRequestLog {
                    id: worker_id_value,
                    log,
                };
                if let Err(e) = ipc_guard.send(&msg).await {
                    tracing::warn!("Failed to send request log: {}", e);
                }
            });
        }

        Some(Ok(Self::build_response_with_alt_svc(
            503,
            "Monthly Bandwidth Limit Exceeded".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        )))
    }

    async fn handle_key_exchange_request(
        req: hyper::Request<hyper::body::Incoming>,
        mesh_config: &Arc<MeshConfig>,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
        client_ip: IpAddr,
        mesh_transport: Option<Arc<MeshTransportManager>>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        use crate::mesh::passover_key_exchange::KeyConfirmHttp;
        use axum::Json;
        use http::StatusCode;
        use http_body_util::BodyExt;

        // Extract parts first to avoid borrow issues
        let (parts, body) = req.into_parts();
        let path = parts.uri.path();
        let method = parts.method.clone();

        // Read body
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                return Ok(Self::build_response_with_alt_svc(
                    400,
                    format!("Failed to read request body: {}", e),
                    "application/json",
                    alt_svc,
                    main_config,
                ));
            }
        };

        let state =
            crate::mesh::passover_key_exchange::KeyExchangeHttpState::new(mesh_config.clone())
                .with_transport(mesh_transport);

        let response = if path == "/key-request-origin" && method == http::Method::POST {
            match serde_json::from_slice::<crate::mesh::passover_key_exchange::KeyRequestOriginHttp>(
                &body_bytes,
            ) {
                Ok(mut req_data) => {
                    // Pass client_ip to the request for edge token verification
                    req_data.client_ip = Some(client_ip.to_string());

                    let result = crate::mesh::passover_key_exchange::key_request_origin_http(
                        axum::extract::State(state),
                        Json(req_data),
                    )
                    .await;
                    match result {
                        Ok(Json(response)) => {
                            let json = serde_json::to_string(&response).unwrap_or_default();
                            (StatusCode::OK, json)
                        }
                        Err((status, err)) => (status, err),
                    }
                }
                Err(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
            }
        } else if path == "/key-confirm" && method == http::Method::POST {
            match serde_json::from_slice::<KeyConfirmHttp>(&body_bytes) {
                Ok(req_data) => {
                    let result = crate::mesh::passover_key_exchange::key_confirm_http(
                        axum::extract::State(state),
                        Json(req_data),
                    )
                    .await;
                    match result {
                        Ok(Json(response)) => {
                            let json = serde_json::to_string(&response).unwrap_or_default();
                            (StatusCode::OK, json)
                        }
                        Err((status, err)) => (status, err),
                    }
                }
                Err(e) => (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)),
            }
        } else if path == "/health" && method == http::Method::GET {
            (StatusCode::OK, "OK".to_string())
        } else {
            (StatusCode::NOT_FOUND, "Not Found".to_string())
        };

        Ok(Self::build_response_with_alt_svc(
            response.0.as_u16(),
            response.1,
            "application/json",
            alt_svc,
            main_config,
        ))
    }

    async fn apply_image_poisoning(
        body: Bytes,
        site_id: String,
        last_modified: Option<String>,
    ) -> Bytes {
        if body.is_empty() {
            return body;
        }

        let original_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&body);
            hex::encode(hasher.finalize())
        };

        let cache_key = format!("{}:{}", site_id, original_hash);

        if let Some(cached) = IMAGE_POISON_CACHE.get(&cache_key) {
            tracing::debug!("Image poison cache hit for {}", cache_key);
            return Bytes::from(cached.clone());
        }

        let static_worker_socket = std::env::var("STATIC_WORKER_SOCKET")
            .unwrap_or_else(|_| "/var/run/maluwaf-static-worker.sock".to_string());

        if static_worker_socket.is_empty() {
            return body;
        }

        let socket_path = std::path::PathBuf::from(&static_worker_socket);

        let client = crate::static_files::client::PoisonImageClient::new(socket_path);

        match client
            .poison_image(
                &site_id,
                body.to_vec(),
                last_modified,
                None,
                None,
                None,
                None,
                None,
            )
            .await
        {
            Ok(poisoned) => {
                IMAGE_POISON_CACHE.insert(cache_key, poisoned.clone());
                Bytes::from(poisoned)
            }
            Err(e) => {
                tracing::debug!("Image poisoning failed: {}", e);
                body
            }
        }
    }

    async fn collect_body_with_chunk_waf<B>(
        mut body: B,
        waf: &Arc<crate::waf::WafCore>,
        client_ip: IpAddr,
        request_body_size: &mut u64,
    ) -> Result<Bytes, ()>
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
        const MAX_ACCUMULATED_WAF: usize = 512 * 1024; // Run WAF on accumulated body up to 512KB

        let mut accumulated = Vec::new();
        let mut waf_checked_up_to: usize = 0;

        while let Some(frame_result) = body.frame().await {
            match frame_result {
                Ok(frame) => {
                    if let Ok(chunk) = frame.into_data() {
                        accumulated.extend_from_slice(&chunk);

                        if accumulated.len() - waf_checked_up_to >= CHUNK_SIZE {
                            let check_end = accumulated
                                .len()
                                .min(waf_checked_up_to + MAX_ACCUMULATED_WAF);
                            if check_end > waf_checked_up_to {
                                let chunk_to_check = &accumulated[waf_checked_up_to..check_end];
                                if let Some(
                                    crate::proxy::WafDecision::Drop
                                    | crate::proxy::WafDecision::Block(_, _),
                                ) = waf.check_request_body(chunk_to_check)
                                {
                                    tracing::warn!(
                                        client_ip = %client_ip,
                                        "Request blocked during streaming body WAF check"
                                    );
                                    counter!("maluwaf.http.streaming_body_blocked").increment(1);
                                    return Err(());
                                }
                                waf_checked_up_to = check_end;
                            }
                        }

                        if accumulated.len() > 100 * 1024 * 1024 {
                            tracing::warn!(
                                client_ip = %client_ip,
                                size = accumulated.len(),
                                "Request body exceeded 100MB limit during streaming"
                            );
                            counter!("maluwaf.http.streaming_body_too_large").increment(1);
                            *request_body_size = accumulated.len() as u64;
                            return Ok(Bytes::from(accumulated));
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Error reading body frame: {:?}", e);
                    break;
                }
            }
        }

        *request_body_size = accumulated.len() as u64;
        Ok(Bytes::from(accumulated))
    }

    #[allow(clippy::too_many_arguments)]
    fn send_request_log_if_enabled(
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        main_config: &Arc<MainConfig>,
        client_ip: IpAddr,
        method: String,
        path: String,
        status: u16,
        latency_ms: u64,
        site_id: String,
        user_agent: Option<String>,
        is_internal: bool,
    ) {
        let verbose_config = &main_config.logging.verbose_request_logging;
        if !verbose_config.enabled {
            return;
        }

        let should_log = if is_internal {
            verbose_config.log_internal
        } else {
            match status {
                0 => verbose_config.log_dropped,
                1..=399 => verbose_config.log_proxied,
                400..=599 => verbose_config.log_blocked,
                _ => false,
            }
        };

        if !should_log {
            return;
        }

        let max_per_second = verbose_config.max_logs_per_second;
        let now = crate::utils::safe_unix_timestamp();

        let last_reset = REQUEST_LOG_RATE_LIMITER_RESET.load(Ordering::Relaxed);
        if now != last_reset {
            // Only one thread should reset the counter per second.
            // compare_exchange ensures only the first caller resets.
            if REQUEST_LOG_RATE_LIMITER_RESET
                .compare_exchange(last_reset, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                REQUEST_LOG_RATE_LIMITER.store(0, Ordering::Relaxed);
            }
        }

        let current_count = REQUEST_LOG_RATE_LIMITER.fetch_add(1, Ordering::Relaxed);
        if current_count >= max_per_second {
            return;
        }

        if let (Some(ref ipc), Some(ref worker_id)) = (ipc, worker_id) {
            let log = RequestLogPayload {
                timestamp: current_timestamp(),
                client_ip: client_ip.to_string(),
                method,
                path,
                status,
                response_time_ms: latency_ms as u32,
                site_id,
                user_agent,
                bytes_sent: 0,
                bytes_received: 0,
            };
            let ipc = ipc.clone();
            let worker_id = *worker_id;
            tokio::spawn(async move {
                let mut ipc_guard = ipc.lock().await;
                let msg = crate::process::Message::WorkerRequestLog { id: worker_id, log };
                if let Err(e) = ipc_guard.send(&msg).await {
                    tracing::warn!("Failed to send request log: {}", e);
                }
            });
        }
    }
}

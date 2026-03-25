use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;
use http::Response;
use bytes::Bytes;
use http_body_util::Full;
use tokio::sync::broadcast;
use metrics::counter;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, WebSocketStream, tungstenite::protocol::Role};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::router::Router;
use crate::waf::{WafCore, FloodProtector, FloodDecision};
use crate::http_client::{create_http_client_with_config, send_request_with_timeout, HttpClient};
use crate::config::MainConfig;
use crate::RunningFlag;
use crate::config::HttpConfig;
use crate::config::site::SiteWebSocketConfig;
use crate::proxy::{filter_response_headers, build_headers_to_filter};
use crate::challenge::HONEYPOT_PREFIX;
use crate::protocol::websocket::WebSocketHandler;
use crate::protocol::trait_def::{ProtocolHandler, WafAction};
use crate::protocol::types::{ProtocolRequest, ProtocolType};
use crate::worker::drain_state::WorkerDrainState;
use crate::mesh::config::MeshConfig;
use crate::mesh::MeshNodeRole;
use crate::mesh::transports::MeshTransportManager;
use crate::http::headers::{inject_security_headers, is_websocket_upgrade, compute_websocket_accept_key, generate_stealth_timestamp};
use crate::metrics::bandwidth::{BandwidthProtocol, EgressDirection};
use crate::metrics::WorkerMetrics;
use crate::process::{current_timestamp, RequestLogPayload};
use parking_lot::Mutex;

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
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_ipc(mut self, ipc: Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>, worker_id: crate::process::ipc::WorkerId) -> Self {
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
        let worker_id = self.worker_id.clone();
        
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
                                    let worker_id_for_request = worker_id.clone();
                                    async move {
                                        Self::handle_request(req, client_addr, local_addr, router, waf, client, alt_svc, main_config, drain_state, http_config, mesh_config, mesh_transport, metrics, http_conn, ipc_for_request, worker_id_for_request).await
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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let start = std::time::Instant::now();
        let client_ip = client_addr.ip();

        let path = req.uri().path_and_query()
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
        } else {
            if path == INTERNAL_HEALTH_PATH || path == INTERNAL_READY_PATH {
                return Self::handle_health_request(&drain_state, &alt_svc, &main_config);
            }
        }

        // Handle key exchange requests for global nodes
        if path.starts_with("/key-") || path == "/health" {
            if let Some(ref mesh_cfg) = mesh_config {
                if mesh_cfg.role == MeshNodeRole::Global 
                    && mesh_cfg.global_node.key_exchange_enabled 
                    && mesh_cfg.origin_signing_key.is_some() 
                {
                    return Self::handle_key_exchange_request(req, mesh_cfg, &alt_svc, &main_config, client_ip, mesh_transport).await;
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
                    let worker_id_clone = worker_id.clone();
                    Self::send_request_log_if_enabled(
                        ipc_clone, worker_id_clone, &main_config,
                        client_ip, "UNKNOWN".to_string(), path.to_string(),
                        503, start.elapsed().as_millis() as u64, "internal".to_string(), None,
                        true,
                    );
                    return Ok(Self::build_response_with_alt_svc(503, "Too Many Connections".to_string(), "application/json", &alt_svc, &main_config));
                }
            }
        } else {
            None
        };

        let _conn_token = connection_token;

        if waf.is_over_bandwidth_limit() {
            tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
            counter!("maluwaf.bandwidth.limit_exceeded").increment(1);
            let ipc_clone = ipc.clone();
            let worker_id_clone = worker_id.clone();
            Self::send_request_log_if_enabled(
                ipc_clone, worker_id_clone, &main_config,
                client_ip, "UNKNOWN".to_string(), path.to_string(),
                503, start.elapsed().as_millis() as u64, "internal".to_string(), None,
                true,
            );
            return Ok(Self::build_response_with_alt_svc(
                503,
                "Monthly Bandwidth Limit Exceeded".to_string(),
                "text/plain",
                &alt_svc,
                &main_config,
            ));
        }

        let is_ws_upgrade = Self::is_websocket_upgrade(req.headers());
        let on_upgrade = if is_ws_upgrade {
            Some(hyper::upgrade::on(&mut req))
        } else {
            None
        };

        let (parts, _body) = req.into_parts();
        let method = parts.method.clone();
        let path = parts.uri.path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".to_string());
        let host = parts.headers.get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let user_agent = parts.headers.get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut request_body_size: u64 = 0;
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
            let worker_id_clone = worker_id.clone();
            Self::send_request_log_if_enabled(
                ipc_clone, worker_id_clone, &main_config,
                client_ip, method.to_string(), path.clone(),
                408, start.elapsed().as_millis() as u64, "internal".to_string(), user_agent.clone(),
                true,
            );
            return Ok(Self::build_response_with_alt_svc(408, "Request timeout".to_string(), "text/plain", &alt_svc, &main_config));
        }

        if path.starts_with("/_waf_css_challenge") {
            let (html, _) = waf.challenge_manager.generate_challenge_page(&client_ip);
            let ipc_clone = ipc.clone();
            let worker_id_clone = worker_id.clone();
            Self::send_request_log_if_enabled(
                ipc_clone, worker_id_clone, &main_config,
                client_ip, method.to_string(), path.clone(),
                200, start.elapsed().as_millis() as u64, "internal".to_string(), user_agent.clone(),
                true,
            );
            return Ok(Self::build_response_with_alt_svc(200, html, "text/html", &alt_svc, &main_config));
        }

        if path.starts_with("/_waf_assets") {
            let asset_name = match path.strip_prefix("/_waf_assets/rnd-") {
                Some(name) => name.strip_suffix(".png").unwrap_or(name),
                None => {
                    let ipc_clone = ipc.clone();
                    let worker_id_clone = worker_id.clone();
                    Self::send_request_log_if_enabled(
                        ipc_clone, worker_id_clone, &main_config,
                        client_ip, method.to_string(), path.clone(),
                        204, start.elapsed().as_millis() as u64, "internal".to_string(), user_agent.clone(),
                        true,
                    );
                    let mut resp = Response::new(Full::new(Bytes::new()));
                    *resp.status_mut() = http::StatusCode::NO_CONTENT;
                    resp.headers_mut().insert(http::header::CONNECTION, "close".parse().unwrap());
                    return Ok(resp);
                }
            };
            
            if !waf.challenge_manager.css_enabled() {
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method.to_string(), path.clone(),
                    404, start.elapsed().as_millis() as u64, "internal".to_string(), user_agent.clone(),
                    true,
                );
                return Ok(Self::build_response_with_alt_svc(404, "Not Found".to_string(), "text/plain", &alt_svc, &main_config));
            }
            
            let cookie_name = waf.challenge_manager.css_session_cookie_name();
            let session_id = parts.headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookie_str| {
                    cookie_str.split(';')
                        .find(|c| c.trim().starts_with(&format!("{}=", cookie_name)))
                        .map(|c| c.trim()[cookie_name.len() + 1..].to_string())
                });
            
            let session_id = match session_id {
                Some(sid) => sid,
                None => {
                    let ipc_clone = ipc.clone();
                    let worker_id_clone = worker_id.clone();
                    Self::send_request_log_if_enabled(
                        ipc_clone, worker_id_clone, &main_config,
                        client_ip, method.to_string(), path.clone(),
                        204, start.elapsed().as_millis() as u64, "internal".to_string(), user_agent.clone(),
                        true,
                    );
                    let mut resp = Response::new(Full::new(Bytes::new()));
                    *resp.status_mut() = http::StatusCode::NO_CONTENT;
                    resp.headers_mut().insert(http::header::CONNECTION, "close".parse().unwrap());
                    return Ok(resp);
                }
            };
            
            let (_, action) = waf.challenge_manager.record_css_asset_request(&session_id, asset_name);
            
            match action {
                crate::challenge::CssAssetAction::RedirectWithCookie => {
                    let verified_cookie_name = waf.challenge_manager.css_verified_cookie_name();
                    let window_secs = waf.challenge_manager.css_window_secs();
                    let cookie = format!(
                        "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                        verified_cookie_name,
                        "verified",
                        window_secs
                    );
                    let response = Response::builder()
                        .status(http::StatusCode::FOUND)
                        .header(http::header::LOCATION, "/")
                        .header(http::header::SET_COOKIE, cookie)
                        .body(Full::new(Bytes::new()))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                    return Ok(response);
                }
                crate::challenge::CssAssetAction::DropConnection => {
                    let mut resp = Response::new(Full::new(Bytes::new()));
                    *resp.status_mut() = http::StatusCode::NO_CONTENT;
                    resp.headers_mut().insert(http::header::CONNECTION, "close".parse().unwrap());
                    return Ok(resp);
                }
            }
        }

        let _drain_guard = DrainGuard::new(drain_state.clone());

        let query_string = parts.uri.query();
        
        let body_slice: Option<&[u8]> = None;

        let route = router.route_with_local_addr(&host, &path, local_addr);

        let target = match route {
            crate::router::RouteResult::Found(target) => target,
            crate::router::RouteResult::NotFound(msg) => {
                tracing::debug!("Route not found: {} for host: {}", msg, host);
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method.to_string(), path.clone(),
                    404, start.elapsed().as_millis() as u64, host.clone(), user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_alt_svc(404, "Not Found".to_string(), "text/plain", &alt_svc, &main_config));
            }
            crate::router::RouteResult::Error(msg) => {
                tracing::error!("Router error: {}", msg);
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method.to_string(), path.clone(),
                    500, start.elapsed().as_millis() as u64, host.clone(), user_agent.clone(),
                    false,
                );
                return Ok(Self::build_response_with_alt_svc(500, "Internal Server Error".to_string(), "text/plain", &alt_svc, &main_config));
            }
        };

        let site_id = target.site_id.clone();
        if let Some(ref metrics) = metrics {
            metrics.record_site_request_start(&site_id);
        }

        let method_str = method.to_string();
        let waf_decision = waf.check_request_full(
            client_ip,
            method_str.as_str(),
            &path,
            query_string,
            &parts.headers,
            body_slice,
            user_agent.as_deref(),
        ).await;

        let response = match waf_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("maluwaf.http.blackhole_drop").increment(1);
                http_conn.request_drop();
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method_str.clone(), path.clone(),
                    0, start.elapsed().as_millis() as u64, site_id.to_string(), user_agent.clone(),
                    false,
                );
                let resp = Response::new(Full::new(Bytes::new()));
                return Ok(resp);
            }
            crate::proxy::WafDecision::Stall => {
                counter!("maluwaf.http.stalled").increment(1);
                let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
                tokio::select! {
                    _ = tokio::time::sleep(stall_timeout) => {
                        let latency_ms = stall_timeout.as_millis() as u64;
                        let ipc_clone = ipc.clone();
                        let worker_id_clone = worker_id.clone();
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
                let site_theme = target.site_config.error_pages.theme.as_ref()
                    .map(|theme_config| theme_config.to_theme_config(waf.error_page_manager.theme()));
                let body = waf.error_page_manager.render_page_with_theme(status, Some(&message), site_theme.as_ref());
                let body_len = body.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(body_len, BandwidthProtocol::Http, EgressDirection::Blocked);
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method_str.clone(), path.clone(),
                    status, start.elapsed().as_millis() as u64, site_id.to_string(), user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_alt_svc(status, body, "text/html", &alt_svc, &main_config))
            }
            crate::proxy::WafDecision::Challenge(html) => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_challenged(&site_id);
                }
                let body_len = html.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(body_len, BandwidthProtocol::Http, EgressDirection::Challenged);
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method_str.clone(), path.clone(),
                    200, start.elapsed().as_millis() as u64, site_id.to_string(), user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_alt_svc(200, html, "text/html", &alt_svc, &main_config))
            }
            crate::proxy::WafDecision::ChallengeWithCookie { html, session_cookie_name, session_cookie_value, session_cookie_max_age } => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_challenged(&site_id);
                }
                let body_len = html.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(body_len, BandwidthProtocol::Http, EgressDirection::Challenged);
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let cookie = format!("{}={}; path=/; max-age={}; Secure; SameSite=Strict", session_cookie_name, session_cookie_value, session_cookie_max_age);
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method_str.clone(), path.clone(),
                    200, start.elapsed().as_millis() as u64, site_id.to_string(), user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_cookie(200, html, "text/html", &cookie, &alt_svc, &main_config))
            }
            crate::proxy::WafDecision::Tarpit(tar_path) => {
                if let Some(ref metrics) = metrics {
                    metrics.record_site_blocked(&site_id);
                }
                let html = waf.generate_tarpit_response(&tar_path);
                let body_len = html.len() as u64;
                if let Some(ref m) = metrics {
                    m.bandwidth.record_egress(body_len, BandwidthProtocol::Http, EgressDirection::Blocked);
                    m.bandwidth.record_site_egress(&site_id, body_len);
                }
                let ipc_clone = ipc.clone();
                let worker_id_clone = worker_id.clone();
                Self::send_request_log_if_enabled(
                    ipc_clone, worker_id_clone, &main_config,
                    client_ip, method_str.clone(), path.clone(),
                    200, start.elapsed().as_millis() as u64, site_id.to_string(), user_agent.clone(),
                    false,
                );
                Ok(Self::build_response_with_alt_svc(200, html, "text/html", &alt_svc, &main_config))
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
                        ).await;
                    });
                    
                    return Ok(Self::build_websocket_response(&parts.headers));
                }
                
                let target_url = format!("{}{}", target.upstream, path);
                
                let headers_to_filter = build_headers_to_filter(
                    &main_config.security.more_clear_headers,
                    &target.site_config.security.more_clear_headers.iter()
                        .chain(target.site_config.security_headers.more_clear_headers.iter())
                        .cloned()
                        .collect::<Vec<_>>(),
                );
                
                let resp = if crate::http_client::is_quictunnel_url(&target.upstream) {
                    crate::http_client::send_request_via_quic_tunnel(
                        method,
                        &target_url,
                        Some(&parts.headers),
                        None,
                        Some(std::time::Duration::from_secs(30)),
                    ).await
                } else {
                    send_request_with_timeout(&client, method, &target_url, Some(std::time::Duration::from_secs(30))).await
                };
                
                match resp {
                    Ok(resp) => {
                        if let Some(ref metrics) = metrics {
                            metrics.record_site_upstream_success(&site_id);
                        }
                        let status = resp.status_code();
                        
                        let content_type = resp.headers.get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        
                        let last_modified = resp.headers.get("last-modified")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        
                        let mut headers = filter_response_headers(&resp.headers, &headers_to_filter);
                        
                        let mut body = Bytes::from(resp.body);
                        let mut body_len = body.len() as u64;
                        
                        if let Some(ref mt) = mesh_transport {
                            let minification = mt.get_minification_for_site(&site_id).await;
                            if let Some(ref min_config) = minification {
                                if min_config.enabled.unwrap_or(false) {
                                    let ct = content_type.as_deref().unwrap_or("");
                                    if ct.contains("text/html") || ct.contains("text/css") || ct.contains("javascript") {
                                        let generator = crate::static_files::minifier::MinifierGenerator::new();
                                        
                                        if ct.contains("text/html") {
                                            if let Ok(text) = String::from_utf8(body.to_vec()) {
                                                if let Ok(minified) = generator.minify_html(&text) {
                                                    body = Bytes::from(minified);
                                                    body_len = body.len() as u64;
                                                }
                                            }
                                        } else if ct.contains("text/css") {
                                            if let Ok(text) = String::from_utf8(body.to_vec()) {
                                                if let Ok(minified) = generator.minify_css(&text) {
                                                    body = Bytes::from(minified);
                                                    body_len = body.len() as u64;
                                                }
                                            }
                                        } else if ct.contains("javascript") {
                                            if let Ok(text) = String::from_utf8(body.to_vec()) {
                                                if let Ok(minified) = generator.minify_js(&text) {
                                                    body = Bytes::from(minified);
                                                    body_len = body.len() as u64;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            let image_protection = mt.get_image_protection_for_site(&site_id).await;
                            
                            if let Some(ref config) = image_protection {
                                if config.enabled.unwrap_or(false) {
                                    let is_image = content_type.as_ref()
                                        .map(|ct| ct.starts_with("image/"))
                                        .unwrap_or(false);
                                    let min_size = config.min_size_bytes.unwrap_or(100 * 1024) as u64;
                                    let in_range = body_len >= min_size;
                                    let max_check = config.whitelist_patterns.as_ref()
                                        .map(|p| p.is_empty())
                                        .unwrap_or(true);
                                    
                                    if is_image && in_range && max_check {
                                        let path_str = path.to_string();
                                        let whitelisted = config.whitelist_patterns.as_ref()
                                            .map(|patterns| {
                                                patterns.iter().any(|p| {
                                                    if let Ok(re) = regex::Regex::new(p) {
                                                        re.is_match(&path_str)
                                                    } else {
                                                        false
                                                    }
                                                })
                                            })
                                            .unwrap_or(false);
                                        
                                        if !whitelisted {
                                            let site_id_for_poison = site_id.to_string();
                                            body = Self::apply_image_poisoning(body, site_id_for_poison, last_modified.clone()).await;
                                            body_len = body.len() as u64;
                                        }
                                    }
                                }
                            }
                            
                            let compression = mt.get_compression_for_site(&site_id).await;
                            if let Some(ref comp_config) = compression {
                                if comp_config.enabled.unwrap_or(false) {
                                    let accept_encoding: &str = parts.headers.get("accept-encoding")
                                        .and_then(|v: &http::HeaderValue| v.to_str().ok())
                                        .unwrap_or("");
                                    
                                    let generator = crate::static_files::minifier::MinifierGenerator::new();
                                    let gzip_level = comp_config.gzip_level.unwrap_or(6) as u32;
                                    
                                    if accept_encoding.contains("br") {
                                        if let Ok(compressed) = generator.compress_brotli(&body, comp_config.brotli_level.unwrap_or(6) as u32) {
                                            body = Bytes::from(compressed);
                                            body_len = body.len() as u64;
                                            let mut headers_clone = headers.clone();
                                            headers_clone.retain(|(k, _)| k.to_lowercase() != "content-encoding");
                                            headers_clone.push(("Content-Encoding".to_string(), "br".to_string()));
                                            headers = headers_clone;
                                        }
                                    } else if accept_encoding.contains("gzip") {
                                        if let Ok(compressed) = generator.compress_gzip(&body, gzip_level) {
                                            body = Bytes::from(compressed);
                                            body_len = body.len() as u64;
                                            let mut headers_clone = headers.clone();
                                            headers_clone.retain(|(k, _)| k.to_lowercase() != "content-encoding");
                                            headers_clone.push(("Content-Encoding".to_string(), "gzip".to_string()));
                                            headers = headers_clone;
                                        }
                                    }
                                }
                            }
                        }
                        
                        if let Some(ref m) = metrics {
                            m.bandwidth.record_proxied(request_body_size, body_len, &target.upstream);
                            m.bandwidth.record_site_proxied(&site_id, request_body_size, body_len);
                            m.bandwidth.record_egress(body_len, BandwidthProtocol::Http, EgressDirection::Proxied);
                            m.bandwidth.record_site_egress(&site_id, body_len);
                        }
                        
                        let mut builder = Response::builder().status(status);
                        for (key, value) in headers {
                            builder = builder.header(&key, &value);
                        }
                        
                        if let Some(ref alt_svc) = alt_svc {
                            builder = builder.header("Alt-Svc", alt_svc.as_str());
                        }
                        
                        if target.site_config.security_headers.enabled.unwrap_or(false) || main_config.security.global_security_headers {
                            builder = Self::inject_security_headers(builder, &target.site_config.security_headers);
                        }
                        
                        if target.site_config.security_headers.date_header.unwrap_or(true) {
                            let jitter = target.site_config.security_headers.date_jitter_seconds.unwrap_or(5);
                            builder = builder.header("Date", generate_stealth_timestamp(jitter));
                        }
                        
                        if let Some(ref token) = target.site_config.security_headers.server_token {
                            builder = builder.header("Server", token.as_str());
                        }
                        
                        Ok(builder
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| Self::build_response_with_alt_svc(500, "Internal Server Error".to_string(), "text/plain", &alt_svc, &main_config)))
                    }
                    Err(e) => {
                        if let Some(ref metrics) = metrics {
                            metrics.record_site_upstream_failure(&site_id);
                        }
                        tracing::error!("Upstream error: {}", e);
                        let error_body = "Bad Gateway".to_string();
                        let error_len = error_body.len() as u64;
                        if let Some(ref m) = metrics {
                            m.bandwidth.record_egress(error_len, BandwidthProtocol::Http, EgressDirection::Error);
                            m.bandwidth.record_site_egress(&site_id, error_len);
                        }
                        Ok(Self::build_response_with_alt_svc(502, error_body, "text/plain", &alt_svc, &main_config))
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
        let worker_id_clone = worker_id.clone();
        Self::send_request_log_if_enabled(
            ipc_clone, worker_id_clone, &main_config,
            client_ip, method_str, path.clone(),
            status, latency_ms, site_id.to_string(), user_agent.clone(),
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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let drain_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap()))
    }

    fn handle_ready_request(
        drain_state: &Option<Arc<WorkerDrainState>>,
        alt_svc: &Option<String>,
        _main_config: &Arc<MainConfig>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap()))
    }

    fn build_response_with_alt_svc(status: u16, body: String, content_type: &str, alt_svc: &Option<String>, main_config: &Arc<MainConfig>) -> Response<Full<Bytes>> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len());
        
        if let Some(alt_svc) = alt_svc {
            builder = builder.header("Alt-Svc", alt_svc.as_str());
        }
        
        if main_config.security.global_security_headers {
            builder = builder
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY");
        }
        
        builder = builder.header("Date", generate_stealth_timestamp(5));
        
        builder
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap())
    }

    fn build_response_with_cookie(status: u16, body: String, content_type: &str, cookie: &str, alt_svc: &Option<String>, main_config: &Arc<MainConfig>) -> Response<Full<Bytes>> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
            .header("Set-Cookie", cookie);
        
        if let Some(alt_svc) = alt_svc {
            builder = builder.header("Alt-Svc", alt_svc.as_str());
        }
        
        if main_config.security.global_security_headers {
            builder = builder
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY");
        }
        
        builder = builder.header("Date", generate_stealth_timestamp(5));
        
        builder
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap())
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

        let ws_stream = WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            Role::Server,
            None,
        ).await;

        let (mut client_tx, mut client_rx) = ws_stream.split();

        let ws_handler = WebSocketHandler::new()
            .with_max_message_size(ws_config.max_message_size.unwrap_or(16 * 1024 * 1024))
            .with_mask_required(ws_config.mask_required.unwrap_or(false));

        let upstream_scheme = if target.upstream.starts_with("https://") || target.upstream.starts_with("wss://") {
            "wss"
        } else {
            "ws"
        };
        let upstream_host = target.upstream
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

    fn build_websocket_response(headers: &http::HeaderMap) -> Response<Full<Bytes>> {
        let ws_key = headers.get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        let ws_protocols = headers.get("sec-websocket-protocol")
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
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(500)
                    .body(Full::new(Bytes::from("Internal Server Error")))
                    .unwrap()
            })
    }

    async fn handle_key_exchange_request(
        req: hyper::Request<hyper::body::Incoming>,
        mesh_config: &Arc<MeshConfig>,
        alt_svc: &Option<String>,
        main_config: &Arc<MainConfig>,
        client_ip: IpAddr,
        mesh_transport: Option<Arc<MeshTransportManager>>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
                    main_config
                ));
            }
        };

        let state = crate::mesh::passover_key_exchange::KeyExchangeHttpState::new(mesh_config.clone())
            .with_transport(mesh_transport);

        let response = if path == "/key-request-origin" && method == http::Method::POST {
            match serde_json::from_slice::<crate::mesh::passover_key_exchange::KeyRequestOriginHttp>(&body_bytes) {
                Ok(mut req_data) => {
                    // Pass client_ip to the request for edge token verification
                    req_data.client_ip = Some(client_ip.to_string());

                    let result = crate::mesh::passover_key_exchange::key_request_origin_http(
                        axum::extract::State(state),
                        Json(req_data),
                    ).await;
                    match result {
                        Ok(Json(response)) => {
                            let json = serde_json::to_string(&response).unwrap_or_default();
                            (StatusCode::OK, json)
                        }
                        Err((status, err)) => (status, err)
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
                    ).await;
                    match result {
                        Ok(Json(response)) => {
                            let json = serde_json::to_string(&response).unwrap_or_default();
                            (StatusCode::OK, json)
                        }
                        Err((status, err)) => (status, err)
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

        let static_worker_socket = std::env::var("STATIC_WORKER_SOCKET")
            .unwrap_or_else(|_| "/var/run/maluwaf-static-worker.sock".to_string());
        
        if static_worker_socket.is_empty() {
            return body;
        }

        let socket_path = std::path::PathBuf::from(&static_worker_socket);
        
        let client = crate::static_files::client::PoisonImageClient::new(socket_path);
        
        match client.poison_image(&site_id, body.to_vec(), last_modified).await {
            Ok(poisoned) => Bytes::from(poisoned),
            Err(e) => {
                tracing::debug!("Image poisoning failed: {}", e);
                body
            }
        }
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

        let max_per_second = verbose_config.max_logs_per_second as u32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u64)
            .unwrap_or(0);
        
        let last_reset = REQUEST_LOG_RATE_LIMITER_RESET.load(Ordering::Relaxed);
        if now != last_reset {
            REQUEST_LOG_RATE_LIMITER_RESET.store(now, Ordering::Relaxed);
            REQUEST_LOG_RATE_LIMITER.store(0, Ordering::Relaxed);
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
            let worker_id = worker_id.clone();
            tokio::spawn(async move {
                let mut ipc_guard = ipc.lock().await;
                let msg = crate::process::Message::WorkerRequestLog {
                    id: worker_id,
                    log,
                };
                if let Err(e) = ipc_guard.send(&msg).await {
                    tracing::warn!("Failed to send request log: {}", e);
                }
            });
        }
    }
}
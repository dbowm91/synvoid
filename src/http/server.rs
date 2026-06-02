#![allow(
    clippy::type_complexity,
    clippy::collapsible_match,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    clippy::field_reassign_with_default,
    clippy::collapsible_if
)]

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use metrics::counter;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::Semaphore;

use crate::http::app_server_backend_dispatch::maybe_handle_app_server_backend;
use crate::http::axum_dynamic_dispatch::maybe_handle_axum_dynamic_backend;
use crate::http::body_policy::{collect_and_scan_request_body, BodyPolicyError};
use crate::http::buffered_request_waf_dispatch::maybe_handle_buffered_request_waf;
use crate::http::cgi_backend_dispatch::maybe_handle_cgi_backend;
use crate::http::challenge_paths::maybe_handle_challenge_paths;
use crate::http::fastcgi_php_backend_dispatch::maybe_handle_fastcgi_or_php_backend;
use crate::http::internal_endpoint_dispatch::{
    dispatch_internal_endpoint, InternalEndpointDispatch,
};
#[cfg(feature = "mesh")]
use crate::http::mesh_backend_dispatch::maybe_handle_mesh_backend;
use crate::http::request_parse::{
    early_waf_decision, extract_request_metadata, should_skip_waf_from_trust_cookie,
};
#[cfg(feature = "mesh")]
use crate::http::serverless_backend_dispatch::maybe_handle_serverless_backend;
#[allow(unused_imports)]
use crate::http::shared_handler::SharedRequestHandler;
#[cfg(feature = "mesh")]
use crate::http::special_request_paths::{
    maybe_handle_special_request_paths, SpecialRequestDispatch,
};
use crate::http::spin_backend_dispatch::maybe_handle_spin_backend;
use crate::http::static_backend_dispatch::maybe_handle_static_backend;
use crate::http::streaming_request_fast_path::{
    maybe_handle_streaming_request_fast_path, StreamingRequestFastPathOutcome,
};
use crate::http::streaming_waf_decision::maybe_handle_streaming_waf_decision;
use crate::http::upload_validation_dispatch::maybe_handle_upload_validation;
use crate::http::upstream_buffered_dispatch::handle_buffered_upstream_request;
use crate::http::upstream_proxy_dispatch_plan::prepare_upstream_proxy_dispatch_plan;
use crate::http::upstream_streaming_dispatch::handle_streaming_upstream_response;
use crate::http::wasm_filter_dispatch::maybe_handle_wasm_request_filter;
use crate::http::websocket_dispatch::{handle_websocket_to_appserver, handle_websocket_tunnel};
use crate::http::websocket_upgrade_dispatch::maybe_handle_websocket_upgrade;
use crate::http_client::ErasedHttpClient;
use request_preparation::{
    prepare_request_before_buffered_waf, PreparedRequest, RequestPreparationContext,
    RequestPreparationOutcome,
};

use crate::waf::traffic_shaper::ConnectionLimiter;
use crate::waf::ConnectionToken;
use parking_lot::Mutex;

mod backend_dispatch;
mod request_preparation;
mod traffic_control;

struct ConnectionTokenGuard {
    limiter: Arc<ConnectionLimiter>,
    token: Arc<Mutex<Option<ConnectionToken>>>,
}

impl ConnectionTokenGuard {
    fn new(limiter: Arc<ConnectionLimiter>, token: ConnectionToken) -> Self {
        Self {
            limiter,
            token: Arc::new(Mutex::new(Some(token))),
        }
    }

    fn release_and_acquire(&self, new_token: ConnectionToken) -> Option<ConnectionToken> {
        let mut guard = self.token.lock();
        let old_token = guard.take();
        *guard = Some(new_token);
        old_token
    }
}

impl Drop for ConnectionTokenGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.lock().take() {
            self.limiter.release(token);
        }
    }
}

use crate::config::HttpConfig;
use crate::config::MainConfig;
#[allow(unused_imports)]
use crate::http::headers;
use crate::http::response_helpers::format_secure_http_only_cookie;
use crate::http::validation_helpers::validate_websocket_upgrade;
#[allow(unused_imports)]
use crate::http_client::{
    create_http_client_with_config, send_request_streaming, send_request_streaming_generic,
    ErasedBodyImpl, HttpClient, StreamingWafBody,
};
#[cfg(feature = "mesh")]
use crate::mesh::config::MeshConfig;
#[cfg(feature = "mesh")]
use crate::mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use crate::mesh::MeshBackendPool;
use crate::metrics::bandwidth::{BandwidthProtocol, EgressDirection};
use crate::metrics::{RequestLogPayload, WorkerInlineCpuPhase, WorkerMetrics};
use crate::process::current_timestamp;
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::router::Router;
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::worker::drain_state::WorkerDrainState;
use crate::RunningFlag;
use tokio::sync::RwLock;

static REQUEST_LOG_RATE_LIMITER: AtomicU32 = AtomicU32::new(0);
static REQUEST_LOG_RATE_LIMITER_RESET: AtomicU64 = AtomicU64::new(0);

const HTTP_VALID_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

fn is_valid_http_request_start(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    for method in HTTP_VALID_METHODS {
        let method_bytes = method.as_bytes();
        if bytes.len() > method_bytes.len()
            && bytes[..method_bytes.len()] == *method_bytes
            && bytes[method_bytes.len()] == b' '
        {
            return true;
        }
    }
    false
}

fn is_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && (bytes[2] <= 0x03)
}

struct ProtocolValidatingStream<S> {
    stream: S,
    initial_bytes: Option<Vec<u8>>,
}

impl<S> ProtocolValidatingStream<S> {
    fn new(stream: S, initial_bytes: Vec<u8>) -> Self {
        Self {
            stream,
            initial_bytes: Some(initial_bytes),
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ProtocolValidatingStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(bytes) = self.initial_bytes.take() {
            let len = bytes.len().min(buf.remaining());
            buf.put_slice(&bytes[..len]);
            if len < bytes.len() {
                self.initial_bytes = Some(bytes[len..].to_vec());
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ProtocolValidatingStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct HttpConnection {
    io: Mutex<Option<TokioIo<ProtocolValidatingStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
}

impl HttpConnection {
    fn new(stream: tokio::net::TcpStream, initial_bytes: Vec<u8>) -> Self {
        let stream = if initial_bytes.is_empty() {
            ProtocolValidatingStream::new(stream, vec![])
        } else {
            ProtocolValidatingStream::new(stream, initial_bytes)
        };
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

    fn take_stream(&self) -> Option<TokioIo<ProtocolValidatingStream<tokio::net::TcpStream>>> {
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

#[allow(dead_code)]
struct RequestMetrics {
    site_id: String,
    metrics: Arc<WorkerMetrics>,
}

struct PassBackendDispatchContext<'a> {
    app_servers:
        &'a Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
    site_id: &'a str,
    target: &'a crate::router::RouteTarget,
    path: &'a str,
    waf: &'a Arc<WafCore>,
    client_ip: IpAddr,
    router: &'a Arc<Router>,
    parts: &'a http::request::Parts,
    method: &'a http::Method,
    full_body_arc: &'a Arc<Bytes>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    main_config: &'a Arc<MainConfig>,
    method_str: &'a str,
    start: std::time::Instant,
    user_agent: Option<&'a str>,
    alt_svc: &'a Option<String>,
    req_metrics: &'a Option<RequestMetrics>,
    metrics: &'a Option<Arc<WorkerMetrics>>,
    request_body_size: u64,
    body_slice: &'a Option<Arc<Bytes>>,
    upstream_client_registry: &'a Arc<UpstreamClientRegistry>,
    client: &'a HttpClient,
    #[cfg(feature = "mesh")]
    serverless_manager: &'a Option<Arc<crate::serverless::manager::ServerlessManager>>,
    #[cfg(feature = "mesh")]
    mesh_transport: &'a Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    mesh_backend_pool: &'a Option<Arc<MeshBackendPool>>,
}

struct PassUpstreamProxyContext<'a> {
    target: &'a crate::router::RouteTarget,
    path: &'a str,
    main_config: &'a Arc<MainConfig>,
    router: &'a Arc<Router>,
    full_body_arc: &'a Arc<Bytes>,
    upstream_client_registry: &'a Arc<UpstreamClientRegistry>,
    client: &'a HttpClient,
    client_ip: IpAddr,
    parts: &'a http::request::Parts,
    method: &'a http::Method,
    req_metrics: &'a Option<RequestMetrics>,
    metrics: &'a Option<Arc<WorkerMetrics>>,
    request_body_size: u64,
    site_id: &'a str,
    alt_svc: &'a Option<String>,
    #[cfg(feature = "mesh")]
    mesh_transport: &'a Option<Arc<MeshTransportManager>>,
}

#[allow(dead_code)]
impl RequestMetrics {
    fn record_start(&self) {
        self.metrics.record_site_request_start(&self.site_id);
    }

    fn record_blocked(&self) {
        self.metrics.record_site_blocked(&self.site_id);
    }

    fn record_challenged(&self) {
        self.metrics.record_site_challenged(&self.site_id);
    }

    fn record_proxied(&self) {
        self.metrics.record_site_proxied(&self.site_id);
    }

    fn record_upstream_success(&self) {
        self.metrics.record_site_upstream_success(&self.site_id);
    }

    fn record_upstream_failure(&self) {
        self.metrics.record_site_upstream_failure(&self.site_id);
    }

    fn record_request_end(&self, latency_ms: u64) {
        self.metrics
            .record_site_request_end(&self.site_id, latency_ms);
    }

    fn record_egress(&self, bytes: u64, direction: EgressDirection) {
        self.metrics
            .bandwidth
            .record_egress(bytes, BandwidthProtocol::Http, direction);
        self.metrics
            .bandwidth
            .record_site_egress(&self.site_id, bytes);
    }
}

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
    #[cfg(feature = "mesh")]
    mesh_config: Option<Arc<MeshConfig>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<MeshTransportManager>>,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    connection_limit: Arc<Semaphore>,
    app_servers: Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
    #[cfg(feature = "mesh")]
    mesh_backend_pool: Option<Arc<MeshBackendPool>>,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    erased_http_client: ErasedHttpClient,
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
            #[cfg(feature = "mesh")]
            mesh_config: None,
            #[cfg(feature = "mesh")]
            mesh_transport: None,
            metrics: None,
            ipc: None,
            worker_id: None,
            serverless_manager: None,
            connection_limit: Arc::new(Semaphore::new(max_connections)),
            app_servers: None,
            #[cfg(feature = "mesh")]
            mesh_backend_pool: None,
            upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
            erased_http_client: ErasedHttpClient::new(100),
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

    #[cfg(feature = "mesh")]
    pub fn with_mesh_config(mut self, mesh_config: Option<Arc<MeshConfig>>) -> Self {
        self.mesh_config = mesh_config;
        self
    }

    #[cfg(feature = "mesh")]
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

    #[cfg(feature = "mesh")]
    pub fn with_mesh_backend_pool(mut self, pool: Option<Arc<MeshBackendPool>>) -> Self {
        self.mesh_backend_pool = pool;
        self
    }

    #[cfg(feature = "mesh")]
    pub async fn serve(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let std_listener = crate::platform::socket::bind_tcp_reuse(self.addr)?;
        let listener = TcpListener::from_std(std_listener)?;
        tracing::info!(
            "HTTP server listening on {} (HTTP/1.1 + HTTP/2) [SO_REUSEPORT]",
            self.addr
        );

        let router = self.router.clone();
        let waf = self.waf.clone();
        let client = self.client.clone();
        let flood_protector = self.flood_protector.clone();
        let http_config = self.http_config.clone();
        let alt_svc = self.alt_svc.clone();
        let main_config = self.main_config.clone();
        let drain_state = self.drain_state.clone();
        #[cfg(feature = "mesh")]
        let mesh_config = self.mesh_config.clone();
        #[cfg(feature = "mesh")]
        let mesh_transport = self.mesh_transport.clone();
        let metrics = self.metrics.clone();
        let worker_id = self.worker_id;
        let serverless_manager = self.serverless_manager.clone();
        let connection_limit = self.connection_limit.clone();
        let app_servers = self.app_servers.clone();
        #[cfg(feature = "mesh")]
        let mesh_backend_pool = self.mesh_backend_pool.clone();
        let upstream_client_registry = self.upstream_client_registry.clone();
        let erased_http_client = self.erased_http_client.clone();

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
                                        counter!("synvoid.http.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("synvoid.http.flood_limited").increment(1);
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
                            #[cfg(feature = "mesh")]
                            let mesh_config = mesh_config.clone();
                            #[cfg(feature = "mesh")]
                            let mesh_transport = mesh_transport.clone();
                            let metrics = metrics.clone();
                            let ipc = self.ipc.clone();
                            let serverless_manager = serverless_manager.clone();
                            let connection_limit = connection_limit.clone();
                            let app_servers = app_servers.clone();
                            #[cfg(feature = "mesh")]
                            let mesh_backend_pool = mesh_backend_pool.clone();
                            let upstream_client_registry = upstream_client_registry.clone();
                            let erased_http_client = erased_http_client.clone();

                            let (initial_bytes, stream_for_conn) = if http_config.strict_protocol_validation {
                                let mut peek_buf = [0u8; 16];
                                let mut stream_clone = stream;
                                match tokio::io::AsyncReadExt::read(&mut stream_clone, &mut peek_buf).await {
                                    Ok(n) => {
                                        if n == 0 {
                                            continue;
                                        }
                                        if is_tls_client_hello(&peek_buf[..n]) {
                                            counter!("synvoid.http.tls_on_http_port").increment(1);
                                            tracing::debug!(
                                                "Rejected TLS connection on HTTP port from {}",
                                                client_ip
                                            );
                                            continue;
                                        }
                                        if !is_valid_http_request_start(&peek_buf[..n]) {
                                            counter!("synvoid.http.invalid_protocol").increment(1);
                                            tracing::debug!(
                                                "Rejected non-HTTP connection on HTTP port from {}",
                                                client_ip
                                            );
                                            continue;
                                        }
                                        (peek_buf[..n].to_vec(), stream_clone)
                                    }
                                    Err(_) => {
                                        continue;
                                    }
                                }
                            } else {
                                (vec![], stream)
                            };

                            let http_conn = Arc::new(HttpConnection::new(stream_for_conn, initial_bytes));
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
                                    #[cfg(feature = "mesh")]
                                    let mesh_config = mesh_config.clone();
                                    #[cfg(feature = "mesh")]
                                    let mesh_transport = mesh_transport.clone();
                                    let metrics = metrics.clone();
                                    let http_conn = http_conn_clone.clone();
                                    let ipc_for_request = ipc.clone();
                                    let worker_id_for_request = worker_id;
                                    let serverless_manager = serverless_manager.clone();
                                    let connection_limit = connection_limit.clone();
                                    let app_servers = app_servers.clone();
                                    #[cfg(feature = "mesh")]
                                    let mesh_backend_pool = mesh_backend_pool.clone();
                                    let upstream_client_registry = upstream_client_registry.clone();
                                    let erased_http_client = erased_http_client.clone();
                                    async move {
                                        Self::handle_request(req, client_addr, local_addr, router, waf, client, alt_svc, main_config, drain_state, http_config, mesh_config, mesh_transport, metrics, http_conn, ipc_for_request, worker_id_for_request, serverless_manager, connection_limit, app_servers, mesh_backend_pool, upstream_client_registry, erased_http_client).await
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

    #[allow(unused_assignments)]
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
        #[cfg(feature = "mesh")] mesh_config: Option<Arc<MeshConfig>>,
        #[cfg(feature = "mesh")] mesh_transport: Option<Arc<MeshTransportManager>>,
        metrics: Option<Arc<WorkerMetrics>>,
        http_conn: Arc<HttpConnection>,
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
        connection_limit: Arc<Semaphore>,
        app_servers: Option<
            Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        >,
        #[cfg(feature = "mesh")] mesh_backend_pool: Option<Arc<MeshBackendPool>>,
        upstream_client_registry: Arc<UpstreamClientRegistry>,
        erased_http_client: ErasedHttpClient,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let request_queue_started_at = Instant::now();
        let _permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("Connection limit semaphore closed");
                return Ok(crate::http::response_builder::build_response_with_alt_svc(
                    503,
                    "Service Unavailable".to_string(),
                    "text/plain",
                    &alt_svc,
                    &main_config,
                ));
            }
        };
        let request_queue_time_ms = request_queue_started_at.elapsed().as_millis() as u64;
        if let Some(metrics) = &metrics {
            metrics.record_request_queue_time_ms(request_queue_time_ms);
        }

        let start = std::time::Instant::now();
        let request_preparation_started_at = Instant::now();
        let record_inline_phase = |phase: WorkerInlineCpuPhase, started_at: Instant| {
            if let Some(metrics) = &metrics {
                metrics.record_inline_cpu_phase_time_ms(
                    phase,
                    started_at.elapsed().as_millis() as u64,
                );
            }
        };
        let client_ip = client_addr.ip();
        // Sanitize X-Forwarded-For headers based on trusted proxies.
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
            .unwrap_or("/")
            .to_string();

        let req = {
            let req = match dispatch_internal_endpoint(
                req,
                &path,
                client_ip,
                &drain_state,
                &alt_svc,
                &main_config,
            )
            .await?
            {
                InternalEndpointDispatch::Handled(response) => {
                    record_inline_phase(
                        WorkerInlineCpuPhase::RequestPreparation,
                        request_preparation_started_at,
                    );
                    return Ok(response);
                }
                InternalEndpointDispatch::NotHandled(req) => req,
            };

            let req = {
                #[cfg(feature = "mesh")]
                {
                    match maybe_handle_special_request_paths(
                        req,
                        &path,
                        client_ip,
                        &alt_svc,
                        &main_config,
                        &mesh_config,
                        &mesh_transport,
                    )
                    .await?
                    {
                        SpecialRequestDispatch::Handled(response) => {
                            record_inline_phase(
                                WorkerInlineCpuPhase::RequestPreparation,
                                request_preparation_started_at,
                            );
                            return Ok(response);
                        }
                        SpecialRequestDispatch::NotHandled(req) => req,
                    }
                }
                #[cfg(not(feature = "mesh"))]
                {
                    req
                }
            };

            req
        };

        let conn_guard = match traffic_control::maybe_enforce_request_traffic_limits(
            &waf,
            client_ip,
            &path,
            start,
            &ipc,
            worker_id,
            &alt_svc,
            &main_config,
        )
        .await
        {
            traffic_control::TrafficControlOutcome::Continue { conn_guard } => conn_guard,
            traffic_control::TrafficControlOutcome::Respond(response) => {
                record_inline_phase(
                    WorkerInlineCpuPhase::RequestPreparation,
                    request_preparation_started_at,
                );
                return Ok(response);
            }
        };

        let prepared = match prepare_request_before_buffered_waf(RequestPreparationContext {
            req,
            client_ip,
            local_addr,
            router: &router,
            waf: &waf,
            alt_svc: &alt_svc,
            main_config: &main_config,
            http_config: &http_config,
            metrics: &metrics,
            http_conn: &http_conn,
            ipc: ipc.clone(),
            worker_id,
            start,
            upstream_client_registry: &upstream_client_registry,
            #[cfg(feature = "mesh")]
            serverless_manager: &serverless_manager,
            conn_guard: conn_guard.as_ref(),
        })
        .await?
        {
            RequestPreparationOutcome::Continue(prepared) => prepared,
            RequestPreparationOutcome::Respond(response) => {
                record_inline_phase(
                    WorkerInlineCpuPhase::RequestPreparation,
                    request_preparation_started_at,
                );
                return Ok(response);
            }
        };
        record_inline_phase(
            WorkerInlineCpuPhase::RequestPreparation,
            request_preparation_started_at,
        );

        let PreparedRequest {
            on_upgrade,
            target,
            parts,
            method,
            path,
            user_agent,
            skip_waf,
            full_body_arc,
            request_body_size,
            body_slice,
        } = prepared;
        let site_id = target.site_id.to_string();
        let query_string = parts.uri.query();
        let body_slice_ref = body_slice.as_ref().map(Arc::clone);
        let body_slice_ref: Option<&[u8]> = body_slice_ref.as_ref().map(|v| v.as_ref() as &[u8]);

        let _drain_guard = DrainGuard::new(drain_state);
        let req_metrics = metrics.as_ref().map(|m| RequestMetrics {
            site_id: site_id.to_string(),
            metrics: Arc::clone(m),
        });
        if let Some(ref rm) = req_metrics {
            rm.record_start();
        }
        if let Some(metrics) = &metrics {
            metrics.record_body_buffering_bytes(request_body_size);
        }
        let method_str = method.to_string();

        let response = {
            let buffered_waf_started_at = Instant::now();
            if let Some(response) = maybe_handle_buffered_request_waf(
                &waf,
                &target,
                skip_waf,
                &site_id,
                client_ip,
                &method_str,
                &path,
                query_string,
                &parts.headers,
                body_slice_ref,
                user_agent.as_deref(),
                &http_config,
                &alt_svc,
                &main_config,
                || http_conn.request_drop(),
                |status, latency_ms| {
                    Self::send_request_log_if_enabled(
                        ipc.clone(),
                        worker_id,
                        &main_config,
                        client_ip,
                        &method_str,
                        &path,
                        status,
                        latency_ms,
                        &site_id,
                        user_agent.as_deref(),
                        false,
                    )
                },
                || {
                    if let Some(rm) = &req_metrics {
                        rm.record_blocked();
                    }
                },
                |body_len| {
                    if let Some(rm) = &req_metrics {
                        rm.record_egress(body_len, EgressDirection::Blocked);
                    }
                    if let Some(m) = &metrics {
                        m.bandwidth.record_egress(
                            body_len,
                            BandwidthProtocol::Http,
                            EgressDirection::Blocked,
                        );
                        m.bandwidth.record_site_egress(&site_id, body_len);
                    }
                },
                |body_len| {
                    if let Some(rm) = &req_metrics {
                        rm.record_challenged();
                        rm.record_egress(body_len, EgressDirection::Challenged);
                    }
                },
                || start.elapsed().as_millis() as u64,
            )
            .await
            {
                record_inline_phase(WorkerInlineCpuPhase::BufferedWaf, buffered_waf_started_at);
                return Ok(response);
            }
            record_inline_phase(WorkerInlineCpuPhase::BufferedWaf, buffered_waf_started_at);

            let backend_dispatch_started_at = Instant::now();
            let dispatch_ctx = PassBackendDispatchContext {
                app_servers: &app_servers,
                site_id: &site_id,
                target: &target,
                path: &path,
                waf: &waf,
                client_ip,
                router: &router,
                parts: &parts,
                method: &method,
                full_body_arc: &full_body_arc,
                ipc: ipc.clone(),
                worker_id,
                main_config: &main_config,
                method_str: &method_str,
                start,
                user_agent: user_agent.as_deref(),
                alt_svc: &alt_svc,
                req_metrics: &req_metrics,
                metrics: &metrics,
                request_body_size,
                body_slice: &body_slice,
                upstream_client_registry: &upstream_client_registry,
                client: &client,
                #[cfg(feature = "mesh")]
                serverless_manager: &serverless_manager,
                #[cfg(feature = "mesh")]
                mesh_transport: &mesh_transport,
                #[cfg(feature = "mesh")]
                mesh_backend_pool: &mesh_backend_pool,
            };
            let response =
                backend_dispatch::handle_pass_backend_dispatch(on_upgrade, dispatch_ctx).await;
            record_inline_phase(
                WorkerInlineCpuPhase::BackendDispatch,
                backend_dispatch_started_at,
            );
            response
        };

        let latency_ms = start.elapsed().as_millis() as u64;
        if let Some(ref rm) = req_metrics {
            rm.record_request_end(latency_ms);
        }
        crate::metrics::record_http_request_latency(latency_ms);

        let status = response.as_ref().map(|r| r.status().as_u16()).unwrap_or(0);
        let ipc_clone = ipc.clone();
        Self::send_request_log_if_enabled(
            ipc_clone,
            worker_id,
            &main_config,
            client_ip,
            &method_str,
            &path,
            status,
            latency_ms,
            &site_id,
            user_agent.as_deref(),
            false,
        );

        response
    }

    #[allow(clippy::too_many_arguments)]
    fn send_request_log_if_enabled(
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        main_config: &Arc<MainConfig>,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        site_id: &str,
        user_agent: Option<&str>,
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
                method: method.to_string(),
                path: path.to_string(),
                status,
                response_time_ms: latency_ms as u32,
                site_id: site_id.to_string(),
                user_agent: user_agent.map(|s| s.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response_transform::path_looks_like_image;
    use crate::mesh::proxy::get_cached_regex;

    #[test]
    fn test_is_valid_http_request_start_valid_methods() {
        for method in HTTP_VALID_METHODS {
            let request = format!("{} / HTTP/1.1\r\n", method);
            assert!(
                is_valid_http_request_start(request.as_bytes()),
                "Should recognize valid method: {}",
                method
            );
        }
    }

    #[test]
    fn test_is_valid_http_request_start_invalid() {
        assert!(!is_valid_http_request_start(b""));
        assert!(!is_valid_http_request_start(b"GET"));
        assert!(!is_valid_http_request_start(b"GET/ HTTP/1.1"));
        assert!(!is_valid_http_request_start(b"INVALID / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_is_valid_http_request_start_with_query() {
        assert!(is_valid_http_request_start(
            b"POST /path?query=value HTTP/1.1\r\n"
        ));
        assert!(is_valid_http_request_start(
            b"GET /api/users?id=123 HTTP/1.0\r\n"
        ));
    }

    #[test]
    fn test_is_tls_client_hello_valid() {
        let tls_hello = [0x16, 0x03, 0x00];
        assert!(is_tls_client_hello(&tls_hello));

        let tls_hello = [0x16, 0x03, 0x01];
        assert!(is_tls_client_hello(&tls_hello));

        let tls_hello = [0x16, 0x03, 0x03];
        assert!(is_tls_client_hello(&tls_hello));
    }

    #[test]
    fn test_is_tls_client_hello_invalid() {
        assert!(!is_tls_client_hello(b"GET / HTTP/1.1"));
        assert!(!is_tls_client_hello(&[0x16, 0x03, 0x04]));
        assert!(!is_tls_client_hello(&[0x15]));
        assert!(!is_tls_client_hello(&[]));
        assert!(!is_tls_client_hello(&[0x16, 0x04]));
    }

    #[test]
    fn test_is_tls_client_hello_minimum_length() {
        assert!(!is_tls_client_hello(&[0x16, 0x03]));
        assert!(!is_tls_client_hello(&[0x16]));
        assert!(!is_tls_client_hello(&[]));
    }

    #[test]
    fn test_protocol_validating_stream_initial_bytes() {
        let stream = ProtocolValidatingStream::<std::io::Cursor<Vec<u8>>>::new(
            std::io::Cursor::new(vec![]),
            b"Hello World".to_vec(),
        );
        assert_eq!(stream.initial_bytes.as_ref().map(|s| s.len()), Some(11));
    }

    #[test]
    fn test_get_cached_regex_valid_pattern() {
        let pattern = r"\.(?:jpe?g|png|gif)$";
        let regex = get_cached_regex(pattern);
        assert!(regex.is_some());

        let regex2 = get_cached_regex(pattern);
        assert!(regex2.is_some());
    }

    #[test]
    fn test_get_cached_regex_invalid_pattern() {
        let pattern = r"[";
        let regex = get_cached_regex(pattern);
        assert!(regex.is_none());
    }

    #[test]
    fn test_get_cached_regex_caches_result() {
        let pattern = r"test\d+";
        let regex1 = get_cached_regex(pattern);
        let regex2 = get_cached_regex(pattern);
        assert!(regex1.is_some());
        assert!(regex2.is_some());
        assert_eq!(
            regex1.map(|r| r.as_str().to_string()),
            regex2.map(|r| r.as_str().to_string())
        );
    }

    #[test]
    fn test_image_protection_regex_matches() {
        assert!(path_looks_like_image("/image.jpg"));
        assert!(path_looks_like_image("/image.jpeg"));
        assert!(path_looks_like_image("/image.png"));
        assert!(path_looks_like_image("/image.gif"));
        assert!(path_looks_like_image("/image.webp"));
        assert!(path_looks_like_image("/image.bmp"));
        assert!(path_looks_like_image("/image.svg"));
        assert!(path_looks_like_image("/image.ico"));
        assert!(path_looks_like_image("/image.jpg?querystring"));
    }

    #[test]
    fn test_image_protection_regex_no_match() {
        assert!(!path_looks_like_image("/image.txt"));
        assert!(!path_looks_like_image("/image.html"));
        assert!(!path_looks_like_image("/image"));
        assert!(!path_looks_like_image("/jpeg"));
        assert!(!path_looks_like_image("/image.png#anchor"));
    }
}

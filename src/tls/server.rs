#![allow(
    dead_code,
    unused_mut,
    clippy::type_complexity,
    clippy::collapsible_match
)]

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1 as http1_server;
use hyper::server::conn::http2 as http2_server;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use metrics::counter;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

use crate::challenge::HONEYPOT_PREFIX;
use crate::config::site::ProxyHeadersConfig;
use crate::config::HttpConfig;
use crate::config::MainConfig;
use crate::http::headers::{generate_stealth_timestamp, inject_security_headers};
use crate::http::response_helpers::apply_security_headers;

use crate::http_client::{
    send_request_streaming, send_request_streaming_generic, ErasedBodyImpl, ErasedHttpClient,
    StreamingWafBody, UpstreamTlsConfig,
};
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::{
    build_forward_headers, build_headers_to_filter, filter_response_headers_buf, ForwardedProtocol,
    PreparedUpstreamTarget, ProxyServer,
};
use crate::proxy_cache::{ProxyCache, ProxyCacheSettings};
use crate::router::Router;
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::RunningFlag;

use super::cert_resolver::CertResolver;
use super::config::InternalTlsConfig;

const ALPN_HTTP2: &[u8] = b"h2";

use crate::tls::sni_peek::compute_ja4;

fn is_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && (bytes[2] <= 0x03)
}

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

struct HttpsConnection {
    io: Mutex<Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
    ja4_hash: Mutex<Option<String>>,
}

impl HttpsConnection {
    fn new(stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Self {
        let client_hello_bytes = extract_client_hello_bytes_from_stream(&stream);
        let ja4_hash = client_hello_bytes.and_then(|bytes| compute_ja4(&bytes));
        Self {
            io: Mutex::new(Some(TokioIo::new(stream))),
            drop_requested: RunningFlag::new(),
            ja4_hash: Mutex::new(ja4_hash),
        }
    }

    fn request_drop(&self) {
        self.drop_requested.stop();
    }

    fn should_drop(&self) -> bool {
        !self.drop_requested.is_running()
    }

    fn take_stream(
        &self,
    ) -> Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>> {
        self.io.lock().take()
    }

    fn get_ja4(&self) -> Option<String> {
        self.ja4_hash.lock().clone()
    }
}

const INTERNAL_HEALTH_PATH: &str = "/__internal__/health";
const INTERNAL_READY_PATH: &str = "/__internal__/ready";

pub struct HttpsServer {
    addr: SocketAddr,
    config: InternalTlsConfig,
    cert_resolver: Arc<CertResolver>,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    http_config: HttpConfig,
    main_config: Arc<MainConfig>,
    flood_protector: Option<Arc<FloodProtector>>,
    metrics: Option<Arc<crate::metrics::WorkerMetrics>>,
    shutdown_rx: broadcast::Receiver<()>,
    proxy_servers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<ProxyServer>>>>,
    drain_state: Option<Arc<crate::worker::drain_state::WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    mesh_config: Option<Arc<crate::mesh::config::MeshConfig>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    connection_limit: Arc<tokio::sync::Semaphore>,
    app_servers: Option<
        Arc<
            tokio::sync::RwLock<
                std::collections::HashMap<
                    String,
                    Arc<crate::app_server::granian::GranianSupervisor>,
                >,
            >,
        >,
    >,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    erased_http_client: ErasedHttpClient,
}

impl HttpsServer {
    pub fn new(
        addr: SocketAddr,
        config: InternalTlsConfig,
        cert_resolver: Arc<CertResolver>,
        router: Router,
        waf: Arc<WafCore>,
        http_config: HttpConfig,
        main_config: MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            addr,
            config,
            cert_resolver,
            router: Arc::new(router),
            waf,
            http_config,
            main_config: Arc::new(main_config),
            flood_protector: None,
            metrics: None,
            shutdown_rx,
            proxy_servers: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            drain_state: None,
            #[cfg(feature = "mesh")]
            mesh_config: None,
            #[cfg(feature = "mesh")]
            mesh_transport: None,
            ipc: None,
            worker_id: None,
            serverless_manager: None,
            connection_limit: Arc::new(tokio::sync::Semaphore::new(10000)),
            app_servers: None,
            upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
            erased_http_client: ErasedHttpClient::new(100),
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_drain_state(
        mut self,
        drain_state: Arc<crate::worker::drain_state::WorkerDrainState>,
    ) -> Self {
        self.drain_state = Some(drain_state);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_config(mut self, mesh_config: Arc<crate::mesh::config::MeshConfig>) -> Self {
        self.mesh_config = Some(mesh_config);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_transport(
        mut self,
        mesh_transport: Arc<crate::mesh::transports::MeshTransportManager>,
    ) -> Self {
        self.mesh_transport = Some(mesh_transport);
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

    pub fn with_serverless_manager(
        mut self,
        serverless_manager: Arc<crate::serverless::manager::ServerlessManager>,
    ) -> Self {
        self.serverless_manager = Some(serverless_manager);
        self
    }

    pub fn with_connection_limit(mut self, connection_limit: Arc<tokio::sync::Semaphore>) -> Self {
        self.connection_limit = connection_limit;
        self
    }

    pub fn with_app_servers(
        mut self,
        app_servers: Arc<
            tokio::sync::RwLock<
                std::collections::HashMap<
                    String,
                    Arc<crate::app_server::granian::GranianSupervisor>,
                >,
            >,
        >,
    ) -> Self {
        self.app_servers = Some(app_servers);
        self
    }

    pub async fn serve(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            tracing::info!("HTTPS server disabled");
            return Ok(());
        }

        #[cfg(feature = "post-quantum")]
        tracing::info!("Post-quantum cryptography: ENABLED");
        #[cfg(not(feature = "post-quantum"))]
        tracing::info!("Post-quantum cryptography: disabled (feature not enabled)");

        let server_config = self.cert_resolver.build_server_config()?;
        let acceptor = TlsAcceptor::from(server_config);

        let std_listener = crate::platform::socket::bind_tcp_reuse(self.addr)?;
        let listener = TcpListener::from_std(std_listener)?;
        tracing::info!(
            "HTTPS server listening on {} (TLS 1.3 {} PQC) (HTTP/1.1 + HTTP/2) [SO_REUSEPORT]",
            self.addr,
            if self.config.prefer_post_quantum {
                "with"
            } else {
                "without"
            }
        );

        if let Some(watch_dir) = &self.config.watch_dir {
            super::cert_resolver::watch_for_cert_changes(
                self.cert_resolver.clone(),
                watch_dir.clone(),
            );
        }

        let router = self.router.clone();
        let waf = self.waf.clone();
        let http_config = self.http_config.clone();
        let main_config = self.main_config.clone();
        let flood_protector = self.flood_protector.clone();
        let proxy_servers = self.proxy_servers.clone();
        let metrics = self.metrics.clone();
        let drain_state = self.drain_state.clone();
        #[cfg(feature = "mesh")]
        let mesh_config = self.mesh_config.clone();
        #[cfg(feature = "mesh")]
        let mesh_transport = self.mesh_transport.clone();
        let ipc = self.ipc.clone();
        let worker_id = self.worker_id;
        let serverless_manager = self.serverless_manager.clone();
        let app_servers = self.app_servers.clone();
        let upstream_client_registry = self.upstream_client_registry.clone();
        let erased_http_client = self.erased_http_client.clone();

        let _header_read_timeout = Duration::from_secs(self.http_config.header_read_timeout_secs);
        let max_headers = self.http_config.max_headers;
        let _max_buf_size = self.http_config.max_request_size;

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    tracing::info!("HTTPS server received shutdown signal");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            let client_ip = client_addr.ip();

                            // L3/L4 flood protection BEFORE TLS handshake (fixes bug
                            // where check was done after handshake)
                            if let Some(ref fp) = flood_protector {
                                match fp.check_tcp_connection(client_ip) {
                                    FloodDecision::Blackholed => {
                                        counter!("synvoid.tls.flood_blackhole").increment(1);
                                        tracing::debug!("TLS connection blackholed for {}", client_ip);
                                        drop(stream);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("synvoid.tls.flood_limited").increment(1);
                                        tracing::debug!("TLS connection rate limited for {}", client_ip);
                                        drop(stream);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                            }

                            let acceptor = acceptor.clone();
                            let router = router.clone();
                            let waf = waf.clone();
                            let http_config = http_config.clone();
                            let main_config = main_config.clone();
                            let proxy_servers = proxy_servers.clone();
                            let metrics_h2 = metrics.clone();
                            let metrics_h1 = metrics.clone();
                            let drain_state_h2 = drain_state.clone();
                            let drain_state_h1 = drain_state.clone();
                            let ipc_h2 = ipc.clone();
                            let ipc_h1 = ipc.clone();
                            let worker_id_h2 = worker_id;
                            let worker_id_h1 = worker_id;
                            #[cfg(feature = "mesh")]
                            let mesh_config_h2 = mesh_config.clone();
                            #[cfg(feature = "mesh")]
                            let mesh_config_h1 = mesh_config.clone();
                            #[cfg(feature = "mesh")]
                            let mesh_transport_h2 = mesh_transport.clone();
                            #[cfg(feature = "mesh")]
                            let mesh_transport_h1 = mesh_transport.clone();
                            let serverless_manager_h2 = serverless_manager.clone();
                            let serverless_manager_h1 = serverless_manager.clone();
                            let app_servers_h2 = app_servers.clone();
                            let app_servers_h1 = app_servers.clone();
                            let upstream_client_registry = upstream_client_registry.clone();
                            let erased_http_client = erased_http_client.clone();

                            if http_config.strict_protocol_validation {
                                let raw_fd = stream.as_raw_fd();
                                let socket = unsafe { std::net::TcpStream::from_raw_fd(raw_fd) };
                                socket.set_nonblocking(false).ok();
                                let mut peek_buf = [0u8; 16];
                                if let Ok(1..) = socket.peek(&mut peek_buf) {
                                    if is_valid_http_request_start(&peek_buf) {
                                        counter!("synvoid.tls.http_on_tls_port").increment(1);
                                        tracing::debug!(
                                            "Rejected HTTP connection on TLS port from {}",
                                            client_ip
                                        );
                                    }
                                }
                                socket.set_nonblocking(true).ok();
                                std::mem::forget(socket);
                            }

                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        counter!("synvoid.tls.handshakes").increment(1);
                                        counter!("synvoid.tls.handshakes", "result" => "success").increment(1);
                                        tracing::debug!(
                                            "TLS handshake completed for {}",
                                            client_addr
                                        );

                                        let alpn_protocol = tls_stream.get_ref().1.alpn_protocol();
                                        let is_http2 = alpn_protocol.map(|p| p == ALPN_HTTP2).unwrap_or(false);

                                        if is_http2 {
                                            tracing::debug!("Negotiated HTTP/2 for {}", client_addr);
                                            counter!("synvoid.tls.alpn", "protocol" => "h2").increment(1);

                                            let https_conn = Arc::new(HttpsConnection::new(tls_stream));
                                            let https_conn_clone = https_conn.clone();

                                            let io = match https_conn.io.lock().take() {
                                                Some(io) => io,
                                                None => {
                                                    tracing::error!("Failed to take IO from HTTPS connection");
                                                    return;
                                                }
                                            };

                                            let conn = http2_server::Builder::new(TokioExecutor::new())
                                                .max_header_list_size(max_headers as u32)
                                                .serve_connection(io, hyper::service::service_fn({
                                                    let ps = proxy_servers.clone();
                                                    let metrics = metrics_h2.clone();
                                                    let drain_state = drain_state_h2.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_config = mesh_config_h2.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_transport = mesh_transport_h2.clone();
                                                    let ipc = ipc_h2.clone();
                                                    let serverless_manager = serverless_manager_h2.clone();
                                                    let app_servers = app_servers_h2.clone();
                                                    let upstream_client_registry = upstream_client_registry.clone();
                                                    let erased_http_client = erased_http_client.clone();
                                                    move |req| {
                                                        let router = router.clone();
                                                        let waf = waf.clone();
                                                        let http_config = http_config.clone();
                                                        let main_config = main_config.clone();
                                                        let client_addr = client_addr;
                                                        let https_conn = https_conn_clone.clone();
                                                        let ps = ps.clone();
                                                        let metrics = metrics.clone();
                                                        let drain_state = drain_state.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_config = mesh_config.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_transport = mesh_transport.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let ipc = ipc.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let worker_id = worker_id_h2;
                                                        let serverless_manager = serverless_manager.clone();
                                                        let app_servers = app_servers.clone();
                                                        let upstream_client_registry = upstream_client_registry.clone();
                                                        let erased_http_client = erased_http_client.clone();
                                                        async move {
                                                            #[cfg(feature = "mesh")]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps, metrics, drain_state, mesh_config, mesh_transport, ipc, worker_id, serverless_manager, app_servers, upstream_client_registry, erased_http_client).await
                                                            }
                                                            #[cfg(not(feature = "mesh"))]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps, metrics, drain_state, serverless_manager, app_servers, upstream_client_registry, erased_http_client).await
                                                            }
                                                        }
                                                    }
                                                }));

                                            tokio::spawn(async move {
                                                if let Err(e) = conn.await {
                                                    tracing::debug!("HTTP/2 connection error: {}", e);
                                                }
                                                if https_conn.should_drop() {
                                                    if let Some(stream) = https_conn.take_stream() {
                                                        drop(stream);
                                                    }
                                                }
                                            });
                                        } else {
                                            counter!("synvoid.tls.alpn", "protocol" => "http1.1").increment(1);

                                            let https_conn = Arc::new(HttpsConnection::new(tls_stream));
                                            let https_conn_clone = https_conn.clone();

                                            let io = match https_conn.io.lock().take() {
                                                Some(io) => io,
                                                None => {
                                                    tracing::error!("Failed to take IO from HTTPS connection");
                                                    return;
                                                }
                                            };

                                            let conn = http1_server::Builder::new()
                                                .keep_alive(true)
                                                .serve_connection(io, hyper::service::service_fn({
                                                    let ps = proxy_servers.clone();
                                                    let metrics = metrics_h1.clone();
                                                    let drain_state = drain_state_h1.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_config = mesh_config_h1.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_transport = mesh_transport_h1.clone();
                                                    let ipc = ipc_h1.clone();
                                                    let serverless_manager = serverless_manager_h1.clone();
                                                    let app_servers = app_servers_h1.clone();
                                                    let upstream_client_registry = upstream_client_registry.clone();
                                                    let erased_http_client = erased_http_client.clone();
                                                    move |req| {
                                                        let router = router.clone();
                                                        let waf = waf.clone();
                                                        let http_config = http_config.clone();
                                                        let main_config = main_config.clone();
                                                        let client_addr = client_addr;
                                                        let https_conn = https_conn_clone.clone();
                                                        let ps = ps.clone();
                                                        let metrics = metrics.clone();
                                                        let drain_state = drain_state.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_config = mesh_config.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_transport = mesh_transport.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let ipc = ipc.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let worker_id = worker_id_h1;
                                                        let serverless_manager = serverless_manager.clone();
                                                        let app_servers = app_servers.clone();
                                                        let upstream_client_registry = upstream_client_registry.clone();
                                                        let erased_http_client = erased_http_client.clone();
                                                        async move {
                                                            #[cfg(feature = "mesh")]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps, metrics, drain_state, mesh_config, mesh_transport, ipc, worker_id, serverless_manager, app_servers, upstream_client_registry, erased_http_client).await
                                                            }
                                                            #[cfg(not(feature = "mesh"))]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps, metrics, drain_state, serverless_manager, app_servers, upstream_client_registry, erased_http_client).await
                                                            }
                                                        }
                                                    }
                                                }))
                                                .with_upgrades();

                                            tokio::spawn(async move {
                                                if let Err(e) = conn.await {
                                                    tracing::debug!("HTTPS connection error: {}", e);
                                                }
                                                if https_conn.should_drop() {
                                                    if let Some(stream) = https_conn.take_stream() {
                                                        drop(stream);
                                                    }
                                                }
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        counter!("synvoid.tls.handshakes").increment(1);
                                        counter!("synvoid.tls.handshakes", "result" => "failed").increment(1);

                                        let error_str = e.to_string().to_lowercase();
                                        if error_str.contains("version") || error_str.contains("protocol") {
                                            counter!("synvoid.tls.handshakes", "reason" => "version_mismatch").increment(1);
                                            tracing::warn!(
                                                "TLS handshake failed due to protocol version mismatch for {}: {}. \
                                                Consider enabling enable_tls_12_fallback if legacy clients need TLS 1.2 support.",
                                                client_addr,
                                                e
                                            );
                                        } else if error_str.contains("certificate") || error_str.contains("cert") {
                                            counter!("synvoid.tls.handshakes", "reason" => "certificate_error").increment(1);
                                        } else {
                                            counter!("synvoid.tls.handshakes", "reason" => "other").increment(1);
                                        }

                                        tracing::debug!(
                                            "TLS handshake failed for {}: {}",
                                            client_addr,
                                            e
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("HTTPS accept error: {}", e);
                        }
                    }
                }
            }
        }

        tracing::info!("HTTPS server shutdown complete");
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_request_with_cache(
        req: hyper::Request<hyper::body::Incoming>,
        client_addr: SocketAddr,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        http_config: HttpConfig,
        main_config: Arc<MainConfig>,
        http_conn: Arc<HttpsConnection>,
        proxy_servers: Arc<
            tokio::sync::RwLock<std::collections::HashMap<String, Arc<ProxyServer>>>,
        >,
        metrics: Option<Arc<crate::metrics::WorkerMetrics>>,
        _drain_state: Option<Arc<crate::worker::drain_state::WorkerDrainState>>,
        #[cfg(feature = "mesh")] mesh_config: Option<Arc<crate::mesh::config::MeshConfig>>,
        #[cfg(feature = "mesh")] mesh_transport: Option<
            Arc<crate::mesh::transports::MeshTransportManager>,
        >,
        #[cfg(feature = "mesh")] _ipc: Option<
            Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>,
        >,
        #[cfg(feature = "mesh")] _worker_id: Option<crate::process::ipc::WorkerId>,
        serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
        app_servers: Option<
            Arc<
                tokio::sync::RwLock<
                    std::collections::HashMap<
                        String,
                        Arc<crate::app_server::granian::GranianSupervisor>,
                    >,
                >,
            >,
        >,
        upstream_client_registry: Arc<UpstreamClientRegistry>,
        erased_http_client: ErasedHttpClient,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let client_ip = client_addr.ip();
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.path())
            .unwrap_or("/");

        if path == INTERNAL_HEALTH_PATH || path == INTERNAL_READY_PATH {
            return Self::handle_health_request(path, &main_config);
        }

        if waf.is_over_bandwidth_limit() {
            tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
            counter!("synvoid.bandwidth.limit_exceeded").increment(1);
            return Ok(Self::build_response(
                503,
                "Monthly Bandwidth Limit Exceeded".to_string(),
                "text/plain",
            ));
        }

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

        // Note: Site config not available yet at this point (routing happens later).
        // Site-specific bot config (enable_css_honeypot, etc.) will be used in check_challenge.
        let early_decision = waf.check_early(client_ip, &path, cookies, None);
        match early_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("synvoid.https.early_drop").increment(1);
                http_conn.request_drop();
                let resp = Response::new(Full::new(Bytes::from_static(&[])).boxed());
                return Ok(resp);
            }
            crate::proxy::WafDecision::ChallengeWithCookie {
                challenge_type: _,
                html,
                session_cookie_name,
                session_cookie_value,
                session_cookie_max_age,
            } => {
                let cookie = format!(
                    "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                    session_cookie_name, session_cookie_value, session_cookie_max_age
                );
                return Ok(Self::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                ));
            }
            crate::proxy::WafDecision::Challenge(_type, html) => {
                return Ok(Self::build_response(200, html, "text/html"));
            }
            crate::proxy::WafDecision::Block(status, message) => {
                let body =
                    waf.error_page_manager
                        .render_page_with_theme(status, Some(&message), None);
                return Ok(Self::build_response(status, body, "text/html"));
            }
            crate::proxy::WafDecision::Pass
            | crate::proxy::WafDecision::Stall
            | crate::proxy::WafDecision::Tarpit(_) => {
                // Proceed to full body collection and full WAF check
            }
        }

        let bandwidth = get_global_bandwidth_tracker_or_log();

        let mut request_body_size: u64 = 0;
        if let Some(content_length) = parts.headers.get("content-length") {
            if let Ok(len_str) = content_length.to_str() {
                if let Ok(len) = len_str.parse::<u64>() {
                    request_body_size = len;
                    if let Some(ref bw) = bandwidth {
                        bw.record_ingress(len, BandwidthProtocol::Https);
                        bw.record_site_ingress(&host, len);
                    }
                }
            }
        }

        if path.starts_with(HONEYPOT_PREFIX) {
            counter!("synvoid.honeypot.hit").increment(1);
            tracing::info!("HTTPS honeypot accessed: {} by {}", path, client_ip);
            waf.block_ip_for_honeypot(
                client_ip,
                "honeypot",
                waf.config.honeypot_ban_duration_secs,
                "global",
            );
            return Ok(Self::build_response(
                408,
                "Request timeout".to_string(),
                "text/plain",
            ));
        }

        if path.starts_with("/_waf_css_challenge") {
            let (html, _) = waf
                .challenge_manager
                .generate_challenge_page(&client_ip, None);
            return Ok(Self::build_response(200, html, "text/html"));
        }

        if path.starts_with("/_waf_assets") {
            let asset_name = match path.strip_prefix("/_waf_assets/rnd-") {
                Some(name) => name.strip_suffix(".png").unwrap_or(name),
                None => {
                    return Ok(Self::build_response(204, "".to_string(), "text/plain"));
                }
            };

            if !waf.challenge_manager.css_enabled() {
                return Ok(Self::build_response(
                    404,
                    "Not Found".to_string(),
                    "text/plain",
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
                    return Ok(Self::build_response(204, "".to_string(), "text/plain"));
                }
            };

            let (res, action) = waf
                .challenge_manager
                .record_css_asset_request(&session_id, asset_name);

            if res == crate::challenge::AssetRequestResult::InvalidAsset {
                tracing::warn!(
                    "Bot detected via CSS aspect-ratio trap (TLS): IP {}",
                    client_ip
                );
                waf.block_ip_for_honeypot(
                    client_ip,
                    "css_trap_hit",
                    waf.config.honeypot_ban_duration_secs,
                    "global",
                );
            }

            match action {
                crate::challenge::CssAssetAction::RedirectWithCookie => {
                    let verified_cookie_name = waf.challenge_manager.css_verified_cookie_name();
                    let window_secs = waf.challenge_manager.css_window_secs();
                    let cookie = format!(
                        "{}={}; path=/; max-age={}; Secure; SameSite=Strict; HttpOnly",
                        verified_cookie_name, "verified", window_secs
                    );
                    let mut resp = Response::builder()
                        .status(http::StatusCode::FOUND)
                        .header(http::header::LOCATION, "/")
                        .header(http::header::SET_COOKIE, cookie)
                        .body(Full::new(Bytes::from_static(&[])).boxed())
                        .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                    return Ok(resp);
                }
                crate::challenge::CssAssetAction::DropConnection => {
                    return Ok(Self::build_response(204, "".to_string(), "text/plain"));
                }
            }
        }

        let query_string = parts.uri.query();
        let route = router.route_with_local_addr(&host, &path, Some(client_addr));
        let target = match route {
            crate::router::RouteResult::Found(target) => target,
            crate::router::RouteResult::NotFound(msg) => {
                tracing::debug!("Route not found: {} for host: {}", msg, host);
                return Ok(Self::build_response(
                    404,
                    "Not Found".to_string(),
                    "text/plain",
                ));
            }
            crate::router::RouteResult::Error(msg) => {
                tracing::error!("Router error: {}", msg);
                return Ok(Self::build_response(
                    500,
                    "Internal Server Error".to_string(),
                    "text/plain",
                ));
            }
        };

        // Upstream-only request streaming fast path.
        let content_length_u64: Option<u64> = parts
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let needs_body_transform = target
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
        let use_cache = target
            .site_config
            .proxy
            .cache
            .as_ref()
            .and_then(|c| c.enable)
            .unwrap_or(false);
        let can_stream_request =
            matches!(target.backend_type, crate::router::BackendType::Upstream)
                && target.site_config.proxy.should_stream(
                    content_length_u64,
                    target.site_config.proxy.streaming_threshold_bytes,
                )
                && !needs_body_transform
                && !use_cache
                && !crate::http_client::is_quictunnel_url(&target.upstream);

        if can_stream_request {
            counter!("synvoid.https.request.streaming_path").increment(1);
            let ja4_hash = http_conn.get_ja4();
            let waf_decision = waf
                .check_request_full(
                    Some(&target.site_id),
                    client_ip,
                    method.as_str(),
                    &path,
                    query_string,
                    &parts.headers,
                    None,
                    user_agent.as_deref(),
                    ja4_hash.as_deref(),
                    Some(&target.site_config.bot),
                    None,
                )
                .await;

            if matches!(waf_decision, crate::proxy::WafDecision::Pass) {
                let upstream_target = PreparedUpstreamTarget::new(
                    &target.upstream,
                    &path,
                    Some(&target.site_config.proxy),
                );
                let headers_to_filter = crate::proxy::build_headers_to_filter_for_site(
                    &main_config.security.more_clear_headers,
                    &target.site_config.security.more_clear_headers,
                    &target.site_config.security_headers.more_clear_headers,
                );
                let forward_headers = build_forward_headers(
                    client_ip,
                    &parts.headers,
                    target
                        .site_config
                        .proxy
                        .headers
                        .as_ref()
                        .unwrap_or(&ProxyHeadersConfig::default()),
                    ForwardedProtocol::Https,
                );
                let tls_config = target
                    .site_config
                    .proxy
                    .upstream
                    .as_ref()
                    .and_then(|u| u.tls.as_ref())
                    .and_then(UpstreamTlsConfig::from_site_config);
                let streaming_client = upstream_client_registry
                    .get_or_create_streaming(&target.site_id, tls_config.as_ref());
                let streaming_waf = waf.streaming();
                let stream_body = StreamingWafBody::new(body, streaming_waf, client_ip);
                let erased_body = ErasedBodyImpl::new(stream_body);
                match send_request_streaming_generic(
                    streaming_client.as_ref(),
                    method.clone(),
                    &upstream_target.url,
                    erased_body,
                    forward_headers,
                    Some(upstream_target.timeout),
                )
                .await
                {
                    Ok(upstream_resp) => {
                        let (resp_parts, upstream_body) = upstream_resp.into_parts();
                        let status = resp_parts.status.as_u16();
                        let body_len = resp_parts
                            .headers
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(0);
                        if let Some(max_size) = upstream_target.max_response_size {
                            if body_len > 0 && body_len as usize > max_size {
                                return Ok(Self::build_response(
                                    502,
                                    "Bad Gateway".to_string(),
                                    "text/plain",
                                ));
                            }
                        }
                        let filtered_headers =
                            filter_response_headers_buf(&resp_parts.headers, &headers_to_filter);
                        let mut builder = Response::builder().status(status);
                        for (key, value) in filtered_headers.iter() {
                            if let Ok(v) = value.to_str() {
                                builder = builder.header(key.as_str(), v);
                            }
                        }
                        builder = apply_security_headers(builder, &target, &main_config);
                        return Ok(builder
                            .body(
                                upstream_body
                                    .map_err(|e| {
                                        tracing::warn!("Upstream body stream error: {}", e);
                                        unreachable!()
                                    })
                                    .boxed(),
                            )
                            .unwrap_or_else(|_| {
                                Self::build_response(
                                    500,
                                    "Internal Server Error".to_string(),
                                    "text/plain",
                                )
                            }));
                    }
                    Err(e) => {
                        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                            if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                                let body = waf.error_page_manager.render_page_with_theme(
                                    403,
                                    Some("Forbidden"),
                                    target
                                        .site_config
                                        .error_pages
                                        .theme
                                        .as_ref()
                                        .map(|theme_config| {
                                            theme_config
                                                .to_theme_config(waf.error_page_manager.theme())
                                        })
                                        .as_ref(),
                                );
                                return Ok(Self::build_response(403, body, "text/html"));
                            }
                        }
                        tracing::error!("Upstream streaming request error: {}", e);
                        return Ok(Self::build_response(
                            502,
                            "Bad Gateway".to_string(),
                            "text/plain",
                        ));
                    }
                }
            }
        }

        let max_body_size = http_config.max_request_size;
        const CHUNK_WAF_THRESHOLD: usize = 256 * 1024; // 256KB

        let content_length: Option<usize> = parts
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let body_bytes = if let Some(cl) = content_length {
            if cl > CHUNK_WAF_THRESHOLD {
                Self::collect_body_with_chunk_waf(
                    body,
                    &waf,
                    client_ip,
                    content_length,
                    http_config.max_streaming_body_size,
                )
                .await
            } else {
                match body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        tracing::warn!("Failed to collect request body: {}", e);
                        Bytes::from_static(&[])
                    }
                }
            }
        } else {
            match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    tracing::warn!("Failed to collect request body: {}", e);
                    Bytes::from_static(&[])
                }
            }
        };

        let body_slice: Option<&[u8]> = if body_bytes.is_empty() {
            None
        } else if body_bytes.len() > max_body_size {
            tracing::warn!(client = %client_ip, size = body_bytes.len(), "HTTPS request body exceeds max size");
            counter!("synvoid.https.request.body_too_large").increment(1);
            None
        } else {
            Some(&body_bytes)
        };

        tracing::trace!(client = %client_ip, method = %method, path = %path, body_size = body_bytes.len(), "HTTPS request body read");

        let method_str = method.to_string();
        let ja4_hash = http_conn.get_ja4();
        let waf_decision = waf
            .check_request_full(
                Some(&target.site_id),
                client_ip,
                method_str.as_str(),
                &path,
                query_string,
                &parts.headers,
                body_slice,
                user_agent.as_deref(),
                ja4_hash.as_deref(),
                Some(&target.site_config.bot),
                None,
            )
            .await;

        let site_id = target.site_id.clone();

        match waf_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("synvoid.https.blackhole_drop").increment(1);
                http_conn.request_drop();
                let resp = Response::new(Full::new(Bytes::from_static(&[])).boxed());
                Ok(resp)
            }
            crate::proxy::WafDecision::Stall => {
                counter!("synvoid.https.stalled").increment(1);
                let current_stalled = crate::metrics::get_active_stalled_requests();
                if current_stalled >= http_config.max_stalled_requests as u64 {
                    crate::metrics::record_stall_rejected();
                    tracing::warn!("HTTPS stall rejected due to concurrency cap");
                    return Ok(Self::build_response(
                        429,
                        "Too many requests".to_string(),
                        "text/plain",
                    ));
                }
                crate::metrics::record_stall_start();
                let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
                tokio::select! {
                    _ = tokio::time::sleep(stall_timeout) => {
                        crate::metrics::record_stall_end();
                        Ok(Self::build_response(408, "Request timeout".to_string(), "text/plain"))
                    }
                }
            }
            crate::proxy::WafDecision::Block(status, message) => {
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
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Https, EgressDirection::Blocked);
                    bw.record_site_egress(&site_id, body_len);
                }
                Ok(Self::build_response(status, body, "text/html"))
            }
            crate::proxy::WafDecision::Challenge(_type, html) => {
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(
                        body_len,
                        BandwidthProtocol::Https,
                        EgressDirection::Challenged,
                    );
                    bw.record_site_egress(&site_id, body_len);
                }
                Ok(Self::build_response(200, html, "text/html"))
            }
            crate::proxy::WafDecision::ChallengeWithCookie {
                challenge_type: _,
                html,
                session_cookie_name,
                session_cookie_value,
                session_cookie_max_age,
            } => {
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(
                        body_len,
                        BandwidthProtocol::Https,
                        EgressDirection::Challenged,
                    );
                    bw.record_site_egress(&site_id, body_len);
                }
                let cookie = format!(
                    "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                    session_cookie_name, session_cookie_value, session_cookie_max_age
                );
                Ok(Self::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                ))
            }
            crate::proxy::WafDecision::Tarpit(tar_path) => {
                let html = waf.generate_tarpit_response(&tar_path);
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Https, EgressDirection::Blocked);
                    bw.record_site_egress(&site_id, body_len);
                }
                Ok(Self::build_response(200, html, "text/html"))
            }
            crate::proxy::WafDecision::Pass => {
                let content_type = parts
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok());
                if let Some(ct) = content_type {
                    if crate::upload::is_upload_content_type(ct) {
                        if let Some(upload_validator) = waf.get_upload_validator() {
                            let effective_config = upload_validator.get_effective_config(&path);
                            if effective_config.scan_with_yara
                                || effective_config.max_size_bytes > 0
                            {
                                match upload_validator.validate_bytes(&body_bytes, &path).await {
                                    Ok(result) => {
                                        if !result.is_clean() {
                                            tracing::warn!(
                                                path = %path,
                                                client_ip = %client_ip,
                                                mime_type = %result.mime_type,
                                                matches = ?result.yara_matches,
                                                "Malware detected in upload, blocking client IP"
                                            );
                                            waf.block_ip_with_threat_intel(
                                                client_ip,
                                                "malware_upload",
                                                3600,
                                                &site_id,
                                            );
                                            let body = waf.error_page_manager.render_page(
                                                403,
                                                Some("Upload blocked: malware detected"),
                                            );
                                            return Ok(Self::build_response(
                                                403,
                                                body,
                                                "text/html",
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        let (status, message) = match &e {
                                            crate::upload::UploadValidationError::SizeExceeded { .. } => (
                                                413,
                                                "Upload size exceeds maximum allowed",
                                            ),
                                            crate::upload::UploadValidationError::TypeNotAllowed { .. } => (
                                                415,
                                                "Upload file type not allowed",
                                            ),
                                            crate::upload::UploadValidationError::MalwareDetected { matches } => {
                                                tracing::warn!(
                                                    path = %path,
                                                    client_ip = %client_ip,
                                                    matches = ?matches,
                                                    "Malware detected in upload, blocking client IP"
                                                );
                                                waf.block_ip_with_threat_intel(
                                                    client_ip,
                                                    "malware_upload",
                                                    3600,
                                                    &site_id,
                                                );
                                                (403, "Upload blocked: malware detected")
                                            }
                                            _ => (
                                                400,
                                                "Upload validation failed",
                                            ),
                                        };
                                        tracing::warn!(
                                            path = %path,
                                            error = %e,
                                            "Upload validation failed"
                                        );
                                        let body = waf
                                            .error_page_manager
                                            .render_page(status, Some(message));
                                        return Ok(Self::build_response(status, body, "text/html"));
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(ref m) = metrics {
                    m.record_site_proxied(&site_id);
                }

                // Static file serving
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
                                                Self::build_response(
                                                    500,
                                                    "Internal Server Error".to_string(),
                                                    "text/plain",
                                                )
                                            }));
                                    }
                                    crate::static_files::StaticResponseBody::Buffered(
                                        file_path,
                                    ) => {
                                        let file = match tokio::fs::File::open(&file_path).await {
                                            Ok(f) => f,
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to open {}: {}",
                                                    file_path.display(),
                                                    e
                                                );
                                                return Ok(Self::build_response(
                                                    500,
                                                    "Internal Server Error".to_string(),
                                                    "text/plain",
                                                ));
                                            }
                                        };
                                        use futures::StreamExt;
                                        use http_body_util::StreamBody;
                                        use tokio_util::io::ReaderStream;
                                        let stream = ReaderStream::new(file);
                                        let mut body = StreamBody::new(stream);
                                        let mut body_bytes = Vec::new();
                                        while let Some(chunk) = body.next().await {
                                            if let Ok(bytes) = chunk {
                                                body_bytes.extend_from_slice(&bytes);
                                            }
                                        }
                                        let body = Bytes::from(body_bytes);
                                        return Ok(builder
                                            .body(Full::new(body).boxed())
                                            .unwrap_or_else(|_| {
                                                Self::build_response(
                                                    500,
                                                    "Internal Server Error".to_string(),
                                                    "text/plain",
                                                )
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
                #[cfg(feature = "mesh")]
                if matches!(target.backend_type, crate::router::BackendType::Serverless) {
                    if let Some(ref sm) = serverless_manager {
                        let body_bytes_for_serverless: Bytes = body_bytes.clone();
                        match crate::serverless::manager::handle_serverless_function(
                            sm,
                            &method,
                            &path,
                            &parts.headers,
                            Some(body_bytes_for_serverless),
                            crate::serverless::manager::CallerContext::local(),
                        )
                        .await
                        {
                            Ok(response) => {
                                let status = response.status();
                                return Ok(Response::builder()
                                    .status(status)
                                    .body(Full::new(response.into_body()).boxed())
                                    .unwrap_or_else(|_| {
                                        Self::build_response(
                                            500,
                                            "Internal Server Error".to_string(),
                                            "text/plain",
                                        )
                                    }));
                            }
                            Err(e) => {
                                if let crate::serverless::manager::ServerlessError::RemoteExecutionRequired(ref upstream_id) = e {
                                    let function_name = upstream_id.strip_prefix("serverless:").unwrap_or(upstream_id);
                                    if let Some(ref mt) = mesh_transport {
                                        let body_bytes_retry: Bytes = body_bytes.clone();
                                        let mut proxy_req = http::Request::builder()
                                            .method(parts.method.clone())
                                            .uri(parts.uri.clone());
                                        for (name, value) in parts.headers.iter() {
                                            proxy_req = proxy_req.header(name.as_str(), value.to_str().unwrap_or(""));
                                        }
                                        let proxy_req = proxy_req.body(http_body_util::Full::new(body_bytes_retry)).unwrap_or_else(|_| {
                                            http::Request::new(http_body_util::Full::new(Bytes::new()))
                                        });

                                        let record_store = mt.get_record_store();
                                        let peer_node_id = record_store.as_ref().and_then(|rs| {
                                            rs.get_record(&format!("serverless_function:{}", function_name))
                                                .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.value).ok())
                                                .and_then(|v| v.get("node_id").and_then(|n| n.as_str()).map(|s| s.to_string()))
                                        });

                                        if let Some(node_id) = peer_node_id {
                                            match mt.proxy_serverless_request(function_name, &node_id, proxy_req).await {
                                                Ok(proxy_resp) => {
                                                    return Ok(proxy_resp);
                                                }
                                                Err(proxy_err) => {
                                                    tracing::warn!("Serverless mesh proxy failed for {}: {}", function_name, proxy_err);
                                                }
                                            }
                                        } else {
                                            tracing::warn!("No provider node found in DHT for serverless function: {}", function_name);
                                        }
                                    }
                                }
                                tracing::warn!("Serverless function error for {}: {}", path, e);
                                return Ok(Self::build_response(
                                    502,
                                    format!("Serverless Error: {}", e),
                                    "text/plain",
                                ));
                            }
                        }
                    }
                    tracing::warn!(
                        "Serverless backend for site {} but no serverless manager",
                        target.site_id
                    );
                    return Ok(Self::build_response(
                        502,
                        "Serverless backend misconfigured: no runtime available".to_string(),
                        "text/plain",
                    ));
                }

                // FastCGI and PHP backend dispatch
                if matches!(
                    target.backend_type,
                    crate::router::BackendType::FastCgi | crate::router::BackendType::Php
                ) {
                    if let Some(ref socket) = target.backend_socket {
                        let body_bytes_for_fcgi: Bytes = body_bytes.clone();

                        if matches!(target.backend_type, crate::router::BackendType::Php) {
                            if let Some(php_client) = crate::php::create_php_client(
                                &target.site_config,
                                target.php_location_config.as_ref(),
                            ) {
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
                                            target.site_id,
                                            path,
                                            e
                                        );
                                        return Ok(Self::build_response(
                                            502,
                                            format!("Backend Error: {}", e),
                                            "text/plain",
                                        ));
                                    }
                                }
                            }
                        }

                        let fcgi_config =
                            target.site_config.proxy.fastcgi.clone().unwrap_or_default();

                        let pool = crate::fastcgi::get_pool(socket, &fcgi_config);
                        match pool
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
                                    target.site_id,
                                    path,
                                    e
                                );
                                return Ok(Self::build_response(
                                    502,
                                    format!("Backend Error: {}", e),
                                    "text/plain",
                                ));
                            }
                        }
                    }
                    tracing::warn!(
                        "FastCGI/PHP backend for site {} but no socket configured",
                        target.site_id
                    );
                    return Ok(Self::build_response(
                        502,
                        "Backend misconfigured: no socket configured".to_string(),
                        "text/plain",
                    ));
                }

                // CGI backend dispatch
                if matches!(target.backend_type, crate::router::BackendType::Cgi) {
                    if let Some(ref cgi_config) = target.site_config.proxy.cgi {
                        match crate::cgi::CgiHandler::new(cgi_config) {
                            Ok(handler) => {
                                let body_bytes_for_cgi: Bytes = body_bytes.clone();
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
                                            target.site_id,
                                            path,
                                            e
                                        );
                                        let status = match &e {
                                            crate::cgi::CgiError::NotFound(_) => 404,
                                            crate::cgi::CgiError::Forbidden(_) => 403,
                                            crate::cgi::CgiError::Timeout => 504,
                                            _ => 502,
                                        };
                                        return Ok(Self::build_response(
                                            status,
                                            format!("CGI Error: {}", e),
                                            "text/plain",
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "CGI handler creation failed for site {} path {}: {}",
                                    target.site_id,
                                    path,
                                    e
                                );
                                return Ok(Self::build_response(
                                    500,
                                    format!("CGI Configuration Error: {}", e),
                                    "text/plain",
                                ));
                            }
                        }
                    }
                    tracing::warn!(
                        "CGI backend for site {} but no CGI config configured",
                        target.site_id
                    );
                    return Ok(Self::build_response(
                        502,
                        "Backend misconfigured: no CGI root configured".to_string(),
                        "text/plain",
                    ));
                }

                // AppServer (Granian) backend dispatch
                if matches!(target.backend_type, crate::router::BackendType::AppServer) {
                    if let Some(ref app_servers) = app_servers {
                        let app_servers_read = app_servers.read().await;
                        if let Some(supervisor) = app_servers_read.get(target.site_id.as_ref()) {
                            let body_bytes_for_appserver: Bytes = body_bytes.clone();

                            match supervisor
                                .forward_request(
                                    method,
                                    &parts.uri.to_string(),
                                    &parts.headers,
                                    body_bytes_for_appserver,
                                )
                                .await
                            {
                                Ok(response) => {
                                    return Ok(response.map(|b| Full::new(b).boxed()));
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "AppServer (Granian) error for site {} path {}: {}",
                                        target.site_id,
                                        path,
                                        e
                                    );
                                    return Ok(Self::build_response(
                                        502,
                                        format!("Backend Error: {}", e),
                                        "text/plain",
                                    ));
                                }
                            }
                        }
                    }
                    tracing::warn!(
                        "AppServer backend for site {} but no app server running",
                        target.site_id
                    );
                    return Ok(Self::build_response(
                        502,
                        "Backend misconfigured: app server not available".to_string(),
                        "text/plain",
                    ));
                }

                let cache_config = target.site_config.proxy.cache.as_ref();
                let use_cache = cache_config
                    .map(|c| c.enable.unwrap_or(false))
                    .unwrap_or(false);

                if use_cache {
                    if let Some(cache_cfg) = cache_config {
                        let site_id = target.site_id.to_string();
                        let proxy_servers_lock = proxy_servers.read().await;

                        let proxy_server = if let Some(existing) = proxy_servers_lock.get(&site_id)
                        {
                            Some(existing.clone())
                        } else {
                            drop(proxy_servers_lock);
                            let settings = ProxyCacheSettings::from_config(
                                cache_cfg.enable,
                                cache_cfg.path.clone(),
                                cache_cfg.max_size.clone(),
                                cache_cfg.inactive,
                                cache_cfg.use_temp_file,
                                cache_cfg.valid_status.clone(),
                                cache_cfg.methods.clone(),
                                cache_cfg.use_stale.clone(),
                                cache_cfg.min_uses,
                                cache_cfg.key.clone(),
                                cache_cfg.vary_by.clone(),
                                cache_cfg.memory_max.clone(),
                                cache_cfg.disk_max.clone(),
                                cache_cfg.stale_while_revalidate,
                                cache_cfg.stale_if_error,
                                None,
                                None,
                            );

                            let cache = Arc::new(ProxyCache::new(settings));
                            let tls_config = target
                                .site_config
                                .proxy
                                .upstream
                                .as_ref()
                                .and_then(|u| u.tls.as_ref())
                                .and_then(crate::http_client::UpstreamTlsConfig::from_site_config);
                            let ps = ProxyServer::new_with_tls(
                                target.upstream.to_string(),
                                waf.clone(),
                                main_config.proxy_limits.max_response_size,
                                waf.upstream_error_tracker.clone(),
                                site_id.clone(),
                                tls_config.as_ref(),
                            )
                            .with_cache(cache);

                            let ps = Arc::new(ps);
                            let mut proxy_servers_lock = proxy_servers.write().await;
                            proxy_servers_lock.insert(site_id, ps.clone());
                            Some(ps)
                        };

                        if let Some(proxy_server) = proxy_server {
                            match proxy_server
                                .handle_request_with_cache(
                                    method.clone(),
                                    &path,
                                    &host,
                                    &parts.headers,
                                    "https",
                                    Some(crate::http_client::ErasedBodyImpl::from_full(
                                        http_body_util::Full::new(body_bytes.clone()),
                                    )),
                                    client_ip,
                                )
                                .await
                            {
                                Ok(resp) => {
                                    let (parts, body) = resp.into_parts();
                                    let status = parts.status.as_u16();

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
                                    let filtered_headers = filter_response_headers_buf(
                                        &parts.headers,
                                        &headers_to_filter,
                                    );

                                    let mut builder = Response::builder().status(status);
                                    for (key, value) in filtered_headers.iter() {
                                        if let Ok(v) = value.to_str() {
                                            builder = builder.header(key.as_str(), v);
                                        }
                                    }

                                    if target.site_config.security_headers.enabled.unwrap_or(false)
                                        || main_config.security.global_security_headers
                                    {
                                        builder = inject_security_headers(
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
                                        builder = builder
                                            .header("Date", generate_stealth_timestamp(jitter));
                                    }

                                    return Ok(builder
                                        .body(
                                            body.map_err(|e| {
                                                tracing::warn!("Proxy body error: {}", e);
                                                // Infallible means we don't expect errors here,
                                                // but hyper will handle the underlying IO error
                                                unreachable!()
                                            })
                                            .boxed(),
                                        )
                                        .unwrap_or_else(|_| {
                                            Self::build_response(
                                                500,
                                                "Internal Server Error".to_string(),
                                                "text/plain",
                                            )
                                        }));
                                }
                                Err(e) => {
                                    tracing::error!("Proxy server error: {}", e);
                                    return Ok(Self::build_response(
                                        502,
                                        "Bad Gateway".to_string(),
                                        "text/plain",
                                    ));
                                }
                            }
                        }
                    }
                }

                let upstream_target = PreparedUpstreamTarget::new(
                    &target.upstream,
                    &path,
                    Some(&target.site_config.proxy),
                );

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

                let tls_config = target
                    .site_config
                    .proxy
                    .upstream
                    .as_ref()
                    .and_then(|u| u.tls.as_ref())
                    .and_then(UpstreamTlsConfig::from_site_config);

                let client =
                    upstream_client_registry.get_or_create(&target.site_id, tls_config.as_ref());

                let forward_headers = build_forward_headers(
                    client_ip,
                    &parts.headers,
                    target
                        .site_config
                        .proxy
                        .headers
                        .as_ref()
                        .unwrap_or(&ProxyHeadersConfig::default()),
                    ForwardedProtocol::Https,
                );

                let resp = send_request_streaming(
                    &client,
                    method.clone(),
                    &upstream_target.url,
                    Full::new(body_bytes.clone()),
                    forward_headers,
                    Some(upstream_target.timeout),
                )
                .await;

                match resp {
                    Ok(upstream_resp) => {
                        let (resp_parts, upstream_body) = upstream_resp.into_parts();
                        let status = resp_parts.status.as_u16();

                        let body_len = resp_parts
                            .headers
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(0);

                        if let Some(max_size) = upstream_target.max_response_size {
                            if body_len > 0 && body_len as usize > max_size {
                                return Ok(Self::build_response(
                                    502,
                                    "Bad Gateway".to_string(),
                                    "text/plain",
                                ));
                            }
                        }

                        if let Some(ref bw) = bandwidth {
                            bw.record_proxied(request_body_size, body_len, &target.upstream);
                            bw.record_site_proxied(&site_id, request_body_size, body_len);
                            bw.record_egress(
                                body_len,
                                BandwidthProtocol::Https,
                                EgressDirection::Proxied,
                            );
                            bw.record_site_egress(&site_id, body_len);
                        }

                        let filtered_headers =
                            filter_response_headers_buf(&resp_parts.headers, &headers_to_filter);

                        let mut builder = Response::builder().status(status);
                        for (key, value) in filtered_headers.iter() {
                            if let Ok(v) = value.to_str() {
                                builder = builder.header(key.as_str(), v);
                            }
                        }

                        if target.site_config.security_headers.enabled.unwrap_or(false)
                            || main_config.security.global_security_headers
                        {
                            builder = inject_security_headers(
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

                        Ok(builder
                            .body(
                                upstream_body
                                    .map_err(|e| {
                                        tracing::warn!("Upstream body stream error: {}", e);
                                        unreachable!()
                                    })
                                    .boxed(),
                            )
                            .unwrap_or_else(|_| {
                                Self::build_response(
                                    500,
                                    "Internal Server Error".to_string(),
                                    "text/plain",
                                )
                            }))
                    }
                    Err(e) => {
                        tracing::error!("Upstream error: {}", e);
                        let error_body = "Bad Gateway".to_string();
                        let error_len = error_body.len() as u64;
                        if let Some(ref bw) = bandwidth {
                            bw.record_egress(
                                error_len,
                                BandwidthProtocol::Https,
                                EgressDirection::Error,
                            );
                            bw.record_site_egress(&site_id, error_len);
                        }
                        Ok(Self::build_response(502, error_body, "text/plain"))
                    }
                }
            }
        }
    }

    fn handle_health_request(
        _path: &str,
        main_config: &Arc<MainConfig>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let body = serde_json::json!({
            "status": "healthy",
        })
        .to_string();

        let mut builder = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len())
            .header("Date", generate_stealth_timestamp(5));

        if main_config.security.global_security_headers {
            builder = builder
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY");
        }

        Ok(builder
            .body(Full::new(Bytes::from(body)).boxed())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(500)
                    .body(Full::new(Bytes::from("Internal Server Error")).boxed())
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(&[])).boxed()))
            }))
    }

    fn build_response(
        status: u16,
        body: String,
        content_type: &str,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
            .header("Date", generate_stealth_timestamp(5))
            .body(Full::new(Bytes::from(body)).boxed())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(500)
                    .body(Full::new(Bytes::from("Internal Server Error")).boxed())
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(&[])).boxed()))
            })
    }

    fn build_response_with_cookie(
        status: u16,
        body: String,
        content_type: &str,
        cookie: &str,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
            .header("Set-Cookie", cookie)
            .header("Date", generate_stealth_timestamp(5));

        builder
            .body(Full::new(Bytes::from(body)).boxed())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(500)
                    .body(Full::new(Bytes::from("Internal Server Error")).boxed())
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(&[])).boxed()))
            })
    }

    async fn collect_body_with_chunk_waf<B>(
        body: B,
        waf: &Arc<crate::waf::WafCore>,
        client_ip: std::net::IpAddr,
        content_length: Option<usize>,
        max_body_size: usize,
    ) -> Bytes
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        let streaming = crate::http::shared_handler::stream_body_with_waf(
            body,
            waf,
            client_ip,
            crate::http::shared_handler::BodyCollectionProtocol::Https,
            max_body_size,
        );
        use http_body_util::BodyExt;
        match streaming.collect().await {
            Ok(c) => Ok(c.to_bytes()),
            Err(_) => Err(()),
        }
        .unwrap_or_else(|_| Bytes::from_static(&[]))
    }
}

fn extract_client_hello_bytes_from_stream(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<Vec<u8>> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let tcp_stream = &stream.get_ref().0;
    let fd = tcp_stream.as_raw_fd();
    // SAFETY: fd is a valid TCP socket owned by the caller. The stream is used read-only for
    // peek() and is dropped immediately after. The original TlsStream is not consumed.
    let mut tcp_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    let mut peek_buf = vec![0u8; 4096];
    match tcp_stream.peek(&mut peek_buf) {
        Ok(n) if n > 5 => Some(peek_buf[..n].to_vec()),
        _ => None,
    }
}

pub fn create_tls_acceptor(
    _config: &InternalTlsConfig,
    cert_resolver: &CertResolver,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let server_config = cert_resolver.build_server_config()?;
    Ok(TlsAcceptor::from(server_config))
}

/// Proxy raw TCP between a client and upstream, used for TLS passthrough mode.
/// The initial client_hello_bytes are forwarded first, then bidirectional copy.
pub async fn proxy_raw_tcp(
    mut client_stream: tokio::net::TcpStream,
    upstream_addr: std::net::SocketAddr,
    client_hello_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut upstream = tokio::net::TcpStream::connect(upstream_addr).await?;
    counter!("synvoid.tls.passthrough.connection").increment(1);

    // Forward the already-read ClientHello to upstream
    upstream.write_all(&client_hello_bytes).await?;

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    // Bidirectional copy
    let client_to_upstream = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => return Ok::<_, std::io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            upstream_write.write_all(&buf[..n]).await?;
        }
    };

    let upstream_to_client = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match upstream_read.read(&mut buf).await {
                Ok(0) => return Ok::<_, std::io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            client_write.write_all(&buf[..n]).await?;
        }
    };

    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok(_) => {
            tracing::debug!("TLS passthrough connection completed");
        }
        Err(e) => {
            tracing::debug!("TLS passthrough connection error: {}", e);
        }
    }

    counter!("synvoid.tls.passthrough.completed").increment(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_alpn_http2_constant() {
        assert_eq!(ALPN_HTTP2, b"h2");
        assert_eq!(ALPN_HTTP2.len(), 2);
    }

    #[test]
    fn test_internal_paths_constants() {
        assert_eq!(INTERNAL_HEALTH_PATH, "/__internal__/health");
        assert_eq!(INTERNAL_READY_PATH, "/__internal__/ready");
    }

    #[test]
    fn test_http_valid_methods_complete() {
        assert_eq!(HTTP_VALID_METHODS.len(), 9);
        assert!(HTTP_VALID_METHODS.contains(&"GET"));
        assert!(HTTP_VALID_METHODS.contains(&"POST"));
        assert!(HTTP_VALID_METHODS.contains(&"PUT"));
        assert!(HTTP_VALID_METHODS.contains(&"DELETE"));
        assert!(HTTP_VALID_METHODS.contains(&"HEAD"));
        assert!(HTTP_VALID_METHODS.contains(&"OPTIONS"));
        assert!(HTTP_VALID_METHODS.contains(&"PATCH"));
        assert!(HTTP_VALID_METHODS.contains(&"CONNECT"));
        assert!(HTTP_VALID_METHODS.contains(&"TRACE"));
    }
}

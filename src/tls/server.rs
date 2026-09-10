#![allow(
    dead_code,
    unused_mut,
    clippy::type_complexity,
    clippy::collapsible_match
)]

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use hyper::server::conn::http1 as http1_server;
use hyper::server::conn::http2 as http2_server;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use metrics::counter;
use nix::sys::socket::{recv, MsgFlags};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

use crate::config::HttpConfig;
use crate::config::MainConfig;
use crate::http_client::ErasedHttpClient;
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::ProxyServer;
use crate::router::Router;
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::RunningFlag;

use synvoid_tls::CertResolver;
use synvoid_tls::InternalTlsConfig;

const ALPN_HTTP2: &[u8] = b"h2";

use synvoid_http::framing::is_valid_http_request_start;

pub(crate) struct HttpsConnection {
    io: Mutex<Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
    ja4_hash: Mutex<Option<String>>,
}

impl HttpsConnection {
    fn new(stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Self {
        let client_hello_bytes = extract_client_hello_bytes_from_stream(&stream);
        let ja4_hash =
            client_hello_bytes.and_then(|bytes| synvoid_tls::sni_peek::compute_ja4(&bytes));
        Self {
            io: Mutex::new(Some(TokioIo::new(stream))),
            drop_requested: RunningFlag::new(),
            ja4_hash: Mutex::new(ja4_hash),
        }
    }

    pub(crate) fn request_drop(&self) {
        self.drop_requested.stop();
    }

    pub(crate) fn should_drop(&self) -> bool {
        !self.drop_requested.is_running()
    }

    fn take_stream(
        &self,
    ) -> Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>> {
        self.io.lock().take()
    }

    pub(crate) fn get_ja4(&self) -> Option<String> {
        self.ja4_hash.lock().clone()
    }
}

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
    // Phase 01: retained for compatibility but no longer consulted by the
    // converged request path. Per-site proxy-cache dispatch now flows through
    // the same canonical `synvoid-http` backend stages as plaintext HTTP
    // (which never used this map). Kept as a field so existing builders keep
    // compiling; will be removed once external callers stop constructing it.
    proxy_servers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<ProxyServer>>>>,
    client: synvoid_http_client::HttpClient,
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
        let client = synvoid_http_client::create_http_client_with_config(
            std::time::Duration::from_secs(5),
            100,
            std::time::Duration::from_secs(30),
        );
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
            client,
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
            synvoid_tls::cert_resolver::watch_for_cert_changes(
                self.cert_resolver.clone(),
                watch_dir.clone(),
            );
        }

        let router = self.router.clone();
        let waf = self.waf.clone();
        let client = self.client.clone();
        let http_config = self.http_config.clone();
        let main_config = self.main_config.clone();
        let flood_protector = self.flood_protector.clone();
        let metrics = self.metrics.clone();
        let drain_state = self.drain_state.clone();
        #[cfg(feature = "mesh")]
        let mesh_config = self.mesh_config.clone();
        #[cfg(feature = "mesh")]
        let mesh_transport = self.mesh_transport.clone();
        let ipc = self.ipc.clone();
        let worker_id = self.worker_id;
        let serverless_manager = self.serverless_manager.clone();
        let connection_limit = self.connection_limit.clone();
        let app_servers = self.app_servers.clone();
        let upstream_client_registry = self.upstream_client_registry.clone();

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
                            let client = client.clone();
                            let http_config = http_config.clone();
                            let main_config = main_config.clone();
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
                            let connection_limit_h2 = connection_limit.clone();
                            let connection_limit_h1 = connection_limit.clone();
                            let app_servers_h2 = app_servers.clone();
                            let app_servers_h1 = app_servers.clone();
                            let upstream_client_registry = upstream_client_registry.clone();
                            // Phase 01: capture the local socket address for
                            // routing before the TLS handshake consumes the
                            // stream. Previously the peer address was passed
                            // as `local_addr`, breaking IP-based vhost
                            // selection on the HTTPS path.
                            let local_addr = stream.local_addr().ok();

                            if http_config.strict_protocol_validation {
                                let raw_fd = stream.as_raw_fd();
                                let mut peek_buf = [0u8; 16];
                                if let Ok(1..) = recv(
                                    raw_fd,
                                    &mut peek_buf,
                                    MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
                                ) {
                                    if is_valid_http_request_start(&peek_buf) {
                                        counter!("synvoid.tls.http_on_tls_port").increment(1);
                                        tracing::debug!(
                                            "Rejected HTTP connection on TLS port from {}",
                                            client_ip
                                        );
                                    }
                                }
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
                                                    let client = client.clone();
                                                    let metrics = metrics_h2.clone();
                                                    let drain_state = drain_state_h2.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_config = mesh_config_h2.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_transport = mesh_transport_h2.clone();
                                                    let ipc = ipc_h2.clone();
                                                    let serverless_manager = serverless_manager_h2.clone();
                                                    let connection_limit = connection_limit_h2.clone();
                                                    let app_servers = app_servers_h2.clone();
                                                    let upstream_client_registry = upstream_client_registry.clone();
                                                    move |req| {
                                                        let router = router.clone();
                                                        let waf = waf.clone();
                                                        let client = client.clone();
                                                        let http_config = http_config.clone();
                                                        let main_config = main_config.clone();
                                                        let client_addr = client_addr;
                                                        let local_addr = local_addr;
                                                        let https_conn = https_conn_clone.clone();
                                                        let metrics = metrics.clone();
                                                        let drain_state = drain_state.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_config = mesh_config.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_transport = mesh_transport.clone();
                                                        let ipc = ipc.clone();
                                                        let worker_id = worker_id_h2;
                                                        let serverless_manager = serverless_manager.clone();
                                                        let connection_limit = connection_limit.clone();
                                                        let app_servers = app_servers.clone();
                                                        let upstream_client_registry = upstream_client_registry.clone();
                                                        async move {
                                                            #[cfg(feature = "mesh")]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, local_addr, router, waf, client, http_config, main_config, https_conn, metrics, drain_state, mesh_config, mesh_transport, ipc, worker_id, serverless_manager, connection_limit, app_servers, upstream_client_registry).await
                                                            }
                                                            #[cfg(not(feature = "mesh"))]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, local_addr, router, waf, client, http_config, main_config, https_conn, metrics, drain_state, ipc, worker_id, serverless_manager, connection_limit, app_servers, upstream_client_registry).await
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
                                                    let client = client.clone();
                                                    let metrics = metrics_h1.clone();
                                                    let drain_state = drain_state_h1.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_config = mesh_config_h1.clone();
                                                    #[cfg(feature = "mesh")]
                                                    let mesh_transport = mesh_transport_h1.clone();
                                                    let ipc = ipc_h1.clone();
                                                    let serverless_manager = serverless_manager_h1.clone();
                                                    let connection_limit = connection_limit_h1.clone();
                                                    let app_servers = app_servers_h1.clone();
                                                    let upstream_client_registry = upstream_client_registry.clone();
                                                    move |req| {
                                                        let router = router.clone();
                                                        let waf = waf.clone();
                                                        let client = client.clone();
                                                        let http_config = http_config.clone();
                                                        let main_config = main_config.clone();
                                                        let client_addr = client_addr;
                                                        let local_addr = local_addr;
                                                        let https_conn = https_conn_clone.clone();
                                                        let metrics = metrics.clone();
                                                        let drain_state = drain_state.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_config = mesh_config.clone();
                                                        #[cfg(feature = "mesh")]
                                                        let mesh_transport = mesh_transport.clone();
                                                        let ipc = ipc.clone();
                                                        let worker_id = worker_id_h1;
                                                        let serverless_manager = serverless_manager.clone();
                                                        let connection_limit = connection_limit.clone();
                                                        let app_servers = app_servers.clone();
                                                        let upstream_client_registry = upstream_client_registry.clone();
                                                        async move {
                                                            #[cfg(feature = "mesh")]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, local_addr, router, waf, client, http_config, main_config, https_conn, metrics, drain_state, mesh_config, mesh_transport, ipc, worker_id, serverless_manager, connection_limit, app_servers, upstream_client_registry).await
                                                            }
                                                            #[cfg(not(feature = "mesh"))]
                                                            {
                                                                Self::handle_request_with_cache(req, client_addr, local_addr, router, waf, client, http_config, main_config, https_conn, metrics, drain_state, ipc, worker_id, serverless_manager, connection_limit, app_servers, upstream_client_registry).await
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

    #[allow(clippy::too_many_arguments, unused_variables)]
    async fn handle_request_with_cache(
        req: hyper::Request<hyper::body::Incoming>,
        client_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        client: synvoid_http_client::HttpClient,
        http_config: HttpConfig,
        main_config: Arc<MainConfig>,
        http_conn: Arc<HttpsConnection>,
        metrics: Option<Arc<crate::metrics::WorkerMetrics>>,
        drain_state: Option<Arc<crate::worker::drain_state::WorkerDrainState>>,
        #[cfg(feature = "mesh")] mesh_config: Option<Arc<crate::mesh::config::MeshConfig>>,
        #[cfg(feature = "mesh")] mesh_transport: Option<
            Arc<crate::mesh::transports::MeshTransportManager>,
        >,
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
        connection_limit: Arc<tokio::sync::Semaphore>,
        app_servers: Option<
            Arc<
                tokio::sync::RwLock<
                    HashMap<String, Arc<crate::app_server::granian::GranianSupervisor>>,
                >,
            >,
        >,
        upstream_client_registry: Arc<UpstreamClientRegistry>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        // Phase 01 (TLS convergence): converged request policy.
        //
        // Transport-specific work stays in `serve()` above: TCP accept,
        // L3/L4 flood protection, TLS handshake, ALPN negotiation,
        // certificate/SNI selection, JA4 extraction, and connection
        // lifecycle. Everything below is the same canonical composition as
        // `HttpServer::handle_request`:
        // `prepare_http_request_flow` (frontdoor + traffic control +
        // preflight + streaming fast path + body policy + challenge paths)
        // followed by `handle_http_request_postlude` (buffered WAF decision
        // mapping + backend dispatch + accounting).
        //
        // Transport adaptations at the boundary (documented, tested):
        // - `ForwardedProtocol::Https` so upstreams observe `X-Forwarded-Proto: https`;
        // - `ja4_hash` from the TLS handshake threaded into both the
        //   streaming fast-path header check (prelude) and the buffered WAF
        //   check (postlude); plaintext HTTP passes `None`;
        // - `alt_svc: None` (Alt-Svc advertisement remains an HTTP-plane
        //   concern; the canonical builder simply omits the header);
        // - `local_addr` captured before the handshake (previously the peer
        //   address was mis-passed as local, breaking IP-based vhost
        //   selection; now matches the HTTP accept-loop behavior);
        // - `mesh_backend_pool: None` (the TLS path never wired a mesh
        //   backend pool; preserved as-is rather than inventing one).
        //
        // Intentional convergences (behavior changes vs the old HTTPS-local
        // pipeline, each covered by the stage matrix in
        // `architecture/http_request_pipeline.md`):
        // - trusted-proxy client-IP resolution, internal drain endpoints,
        //   connection limiting, trust-token bypass, transfer-framing
        //   fail-closed validation, WebSocket upgrade validation/dispatch,
        //   canonical streaming fast-path conditions, body-policy 413
        //   fail-closed, canonical WAF-decision mapping/accounting, upload
        //   validation, WASM filter, and response transforms now match HTTP.
        // - The old per-site `ProxyServer` response-cache map is no longer
        //   consulted (plaintext HTTP never used it). If shared response
        //   caching returns, it must land in canonical `synvoid-http`
        //   backend dispatch so both transports inherit it together.
        // - Request byte/metric accounting uses the canonical
        //   `WorkerMetrics`/`BandwidthProtocol::Http` path. TLS-handshake,
        //   ALPN, and flood counters (`synvoid.tls.*`) remain
        //   transport-specific above.
        let alt_svc: Option<String> = None;
        let request_queue_started_at = Instant::now();
        let _permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("Connection limit semaphore closed");
                return Ok(synvoid_http::response_builder::build_response_with_alt_svc(
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

        let start = Instant::now();
        let ja4_hash = http_conn.get_ja4();
        let request_drop: Arc<dyn Fn() + Send + Sync> = {
            let http_conn = http_conn.clone();
            Arc::new(move || http_conn.request_drop())
        };
        let flow = synvoid_http::prepare_http_request_flow(
            req,
            client_addr.ip(),
            local_addr,
            drain_state.clone(),
            Arc::clone(&router),
            Arc::clone(&waf),
            alt_svc.clone(),
            Arc::clone(&main_config),
            http_config.clone(),
            metrics.clone(),
            ipc.clone(),
            worker_id,
            start,
            Arc::clone(&request_drop),
            crate::http::server::send_request_log_if_enabled,
            #[cfg(feature = "mesh")]
            mesh_config.clone(),
            #[cfg(feature = "mesh")]
            mesh_transport.clone(),
            #[cfg(feature = "mesh")]
            serverless_manager.clone(),
            Arc::clone(&upstream_client_registry),
            ja4_hash.clone(),
        )
        .await?;

        let client_ip = flow.client_ip;
        let prepared = match flow.outcome {
            synvoid_http::RequestPreparationOutcome::Continue(prepared) => *prepared,
            synvoid_http::RequestPreparationOutcome::Respond(response) => {
                return Ok(response);
            }
        };

        let _drain_guard = crate::http::server::DrainGuard::new(drain_state);
        let plugin_backend_arc: Option<Arc<dyn synvoid_http::WasmFilterBackend + Send + Sync>> =
            router
                .plugin_manager()
                .and_then(|pm| {
                    let arc_any: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(pm);
                    arc_any.downcast::<crate::plugin::PluginManager>().ok()
                })
                .map(|arc| arc as Arc<dyn synvoid_http::WasmFilterBackend + Send + Sync>);
        let axum_router_lookup_arc: Option<
            Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>,
        > = router
            .plugin_manager()
            .and_then(|pm| {
                let arc_any: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(pm);
                arc_any.downcast::<crate::plugin::PluginManager>().ok()
            })
            .map(|arc| arc as Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>);

        synvoid_http::handle_http_request_postlude(
            synvoid_http::HttpRequestPostludeContext {
                prepared,
                client_ip,
                router: Arc::clone(&router),
                waf: Arc::clone(&waf),
                client: client.clone(),
                alt_svc: alt_svc.clone(),
                main_config: Arc::clone(&main_config),
                http_config: http_config.clone(),
                metrics: metrics.clone(),
                ipc: ipc.clone(),
                worker_id,
                start,
                app_servers: app_servers.clone(),
                axum_router_lookup: axum_router_lookup_arc,
                plugin_backend: plugin_backend_arc,
                upstream_client_registry: Arc::clone(&upstream_client_registry),
                request_drop: Arc::clone(&request_drop),
                request_log: crate::http::server::send_request_log_if_enabled,
                ja4_hash,
                forwarded_protocol: synvoid_proxy::ForwardedProtocol::Https,
                #[cfg(feature = "mesh")]
                serverless_manager: serverless_manager.clone(),
                #[cfg(feature = "mesh")]
                mesh_transport: mesh_transport.clone(),
                #[cfg(feature = "mesh")]
                mesh_backend_pool: None,
            },
            |method, url, headers, body, timeout| {
                let url = url.to_string();
                Box::pin(async move {
                    crate::http_client::send_request_via_quic_tunnel(
                        method, &url, headers, body, timeout,
                    )
                    .await
                })
            },
            |body, site_id, last_modified, rights_config| async move {
                synvoid_static_files::image_rights::apply_image_rights_marking(
                    body,
                    site_id,
                    last_modified,
                    rights_config,
                )
                .await
            },
            synvoid_metrics::record_http_request_latency,
        )
        .await
    }
}

fn extract_client_hello_bytes_from_stream(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<Vec<u8>> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let tcp_stream = &stream.get_ref().0;
    let fd = tcp_stream.as_raw_fd();
    // Dup the fd so the temporary TcpStream owns a new descriptor; the original
    // TlsStream retains its fd. Without dup, from_raw_fd would close the live fd on drop.
    let dup_fd = nix::unistd::dup(fd).ok()?;
    // SAFETY: dup_fd is a valid fd from dup(); we transfer ownership to TcpStream.
    let mut tcp_stream = unsafe { std::net::TcpStream::from_raw_fd(dup_fd) };
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
    use synvoid_http::framing::{is_tls_client_hello, HTTP_VALID_METHODS};

    // Behavior tests for the sniff helpers live canonically in
    // `crates/synvoid-http/src/framing.rs`; this module only pins the
    // canonical constant and root-local constants.
    #[test]
    fn test_is_tls_client_hello_spot_check() {
        assert!(is_tls_client_hello(&[0x16, 0x03, 0x01]));
        assert!(!is_tls_client_hello(b"GET / HTTP/1.1"));
    }

    #[test]
    fn test_alpn_http2_constant() {
        assert_eq!(ALPN_HTTP2, b"h2");
        assert_eq!(ALPN_HTTP2.len(), 2);
    }

    #[test]
    fn test_internal_paths_are_canonical() {
        // Phase 01: internal health/ready/drain endpoints are handled by the
        // canonical `synvoid-http` frontdoor (`request_parse::
        // classify_internal_endpoint`), not by TLS-local constants. Pin the
        // canonical paths here so a drift is caught at the transport edge.
        assert_eq!(
            synvoid_http::request_parse::classify_internal_endpoint(
                "/__internal__/health",
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                true,
            ),
            synvoid_http::request_parse::InternalEndpointAction::Health
        );
        assert_eq!(
            synvoid_http::request_parse::classify_internal_endpoint(
                "/__internal__/ready",
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                true,
            ),
            synvoid_http::request_parse::InternalEndpointAction::Ready
        );
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

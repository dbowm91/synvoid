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
use crate::http_client::{create_upstream_client, send_request_streaming, UpstreamTlsConfig};
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
use crate::proxy::{
    build_forward_headers, build_headers_to_filter, filter_response_headers, ProxyServer,
};
use crate::proxy_cache::{ProxyCache, ProxyCacheSettings};
use crate::router::Router;
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::RunningFlag;

use super::cert_resolver::CertResolver;
use super::config::InternalTlsConfig;

const ALPN_HTTP2: &[u8] = b"h2";

struct HttpsConnection {
    io: Mutex<Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>,
    drop_requested: RunningFlag,
}

impl HttpsConnection {
    fn new(stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Self {
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

    fn take_stream(
        &self,
    ) -> Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>> {
        self.io.lock().take()
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
    mesh_config: Option<Arc<crate::mesh::config::MeshConfig>>,
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
            mesh_config: None,
            mesh_transport: None,
            ipc: None,
            worker_id: None,
            serverless_manager: None,
            connection_limit: Arc::new(tokio::sync::Semaphore::new(10000)),
            app_servers: None,
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

    pub fn with_mesh_config(mut self, mesh_config: Arc<crate::mesh::config::MeshConfig>) -> Self {
        self.mesh_config = Some(mesh_config);
        self
    }

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

        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!(
            "HTTPS server listening on {} (TLS 1.3 {} PQC) (HTTP/1.1 + HTTP/2)",
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
        let mesh_config = self.mesh_config.clone();
        let mesh_transport = self.mesh_transport.clone();
        let ipc = self.ipc.clone();
        let worker_id = self.worker_id;
        let serverless_manager = self.serverless_manager.clone();
        let app_servers = self.app_servers.clone();

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
                                        counter!("maluwaf.tls.flood_blackhole").increment(1);
                                        tracing::debug!("TLS connection blackholed for {}", client_ip);
                                        drop(stream);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("maluwaf.tls.flood_limited").increment(1);
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
                            let mesh_config_h2 = mesh_config.clone();
                            let mesh_config_h1 = mesh_config.clone();
                            let mesh_transport_h2 = mesh_transport.clone();
                            let mesh_transport_h1 = mesh_transport.clone();
                            let ipc_h2 = ipc.clone();
                            let ipc_h1 = ipc.clone();
                            let worker_id_h2 = worker_id;
                            let worker_id_h1 = worker_id;
                            let serverless_manager_h2 = serverless_manager.clone();
                            let serverless_manager_h1 = serverless_manager.clone();
                            let app_servers_h2 = app_servers.clone();
                            let app_servers_h1 = app_servers.clone();

                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        counter!("maluwaf.tls.handshakes").increment(1);
                                        counter!("maluwaf.tls.handshakes", "result" => "success").increment(1);
                                        tracing::debug!(
                                            "TLS handshake completed for {}",
                                            client_addr
                                        );

                                        let alpn_protocol = tls_stream.get_ref().1.alpn_protocol();
                                        let is_http2 = alpn_protocol.map(|p| p == ALPN_HTTP2).unwrap_or(false);

                                        if is_http2 {
                                            tracing::debug!("Negotiated HTTP/2 for {}", client_addr);
                                            counter!("maluwaf.tls.alpn", "protocol" => "h2").increment(1);

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
                                                    let mesh_config = mesh_config_h2.clone();
                                                    let mesh_transport = mesh_transport_h2.clone();
                                                    let ipc = ipc_h2.clone();
                                                    let serverless_manager = serverless_manager_h2.clone();
                                                    let app_servers = app_servers_h2.clone();
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
                                                        let mesh_config = mesh_config.clone();
                                                        let mesh_transport = mesh_transport.clone();
                                                        let ipc = ipc.clone();
                                                        let worker_id = worker_id_h2;
                                                        let serverless_manager = serverless_manager.clone();
                                                        let app_servers = app_servers.clone();
                                                        async move {
                                                            Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps, metrics, drain_state, mesh_config, mesh_transport, ipc, worker_id, serverless_manager, app_servers).await
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
                                            counter!("maluwaf.tls.alpn", "protocol" => "http1.1").increment(1);

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
                                                    let mesh_config = mesh_config_h1.clone();
                                                    let mesh_transport = mesh_transport_h1.clone();
                                                    let ipc = ipc_h1.clone();
                                                    let serverless_manager = serverless_manager_h1.clone();
                                                    let app_servers = app_servers_h1.clone();
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
                                                        let mesh_config = mesh_config.clone();
                                                        let mesh_transport = mesh_transport.clone();
                                                        let ipc = ipc.clone();
                                                        let worker_id = worker_id_h1;
                                                        let serverless_manager = serverless_manager.clone();
                                                        let app_servers = app_servers.clone();
                                                        async move {
                                                            Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps, metrics, drain_state, mesh_config, mesh_transport, ipc, worker_id, serverless_manager, app_servers).await
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
                                        counter!("maluwaf.tls.handshakes").increment(1);
                                        counter!("maluwaf.tls.handshakes", "result" => "failed").increment(1);

                                        let error_str = e.to_string().to_lowercase();
                                        if error_str.contains("version") || error_str.contains("protocol") {
                                            counter!("maluwaf.tls.handshakes", "reason" => "version_mismatch").increment(1);
                                            tracing::warn!(
                                                "TLS handshake failed due to protocol version mismatch for {}: {}. \
                                                Consider enabling enable_tls_12_fallback if legacy clients need TLS 1.2 support.",
                                                client_addr,
                                                e
                                            );
                                        } else if error_str.contains("certificate") || error_str.contains("cert") {
                                            counter!("maluwaf.tls.handshakes", "reason" => "certificate_error").increment(1);
                                        } else {
                                            counter!("maluwaf.tls.handshakes", "reason" => "other").increment(1);
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
        _mesh_config: Option<Arc<crate::mesh::config::MeshConfig>>,
        _mesh_transport: Option<Arc<crate::mesh::transports::MeshTransportManager>>,
        _ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        _worker_id: Option<crate::process::ipc::WorkerId>,
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
            counter!("maluwaf.bandwidth.limit_exceeded").increment(1);
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

        let early_decision = waf.check_early(client_ip, &path, cookies);
        match early_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("maluwaf.https.early_drop").increment(1);
                http_conn.request_drop();
                let resp = Response::new(Full::new(Bytes::new()).boxed());
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
                return Ok(Self::build_response_with_cookie(
                    200,
                    html,
                    "text/html",
                    &cookie,
                ));
            }
            crate::proxy::WafDecision::Challenge(html) => {
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
            counter!("maluwaf.honeypot.hit").increment(1);
            tracing::info!("HTTPS honeypot accessed: {} by {}", path, client_ip);
            return Ok(Self::build_response(
                408,
                "Request timeout".to_string(),
                "text/plain",
            ));
        }

        if path.starts_with("/_waf_css_challenge") {
            let (html, _) = waf.challenge_manager.generate_challenge_page(&client_ip);
            return Ok(Self::build_response(200, html, "text/html"));
        }

        if path.starts_with("/_waf_assets") {
            return Ok(Self::build_response(
                404,
                "Not Found".to_string(),
                "text/plain",
            ));
        }

        let query_string = parts.uri.query();

        let max_body_size = http_config.max_request_size;
        const CHUNK_WAF_THRESHOLD: usize = 256 * 1024; // 256KB

        let content_length: Option<usize> = parts
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let body_bytes = if let Some(cl) = content_length {
            if cl > CHUNK_WAF_THRESHOLD {
                Self::collect_body_with_chunk_waf(body, &waf, client_ip).await
            } else {
                match body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        tracing::warn!("Failed to collect request body: {}", e);
                        Bytes::new()
                    }
                }
            }
        } else {
            match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    tracing::warn!("Failed to collect request body: {}", e);
                    Bytes::new()
                }
            }
        };

        let body_slice: Option<&[u8]> = if body_bytes.is_empty() {
            None
        } else if body_bytes.len() > max_body_size {
            tracing::warn!(client = %client_ip, size = body_bytes.len(), "HTTPS request body exceeds max size");
            counter!("maluwaf.https.request.body_too_large").increment(1);
            None
        } else {
            Some(&body_bytes)
        };

        tracing::trace!(client = %client_ip, method = %method, path = %path, body_size = body_bytes.len(), "HTTPS request body read");

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

        let method_str = method.to_string();
        let waf_decision = waf
            .check_request_full(
                client_ip,
                method_str.as_str(),
                &path,
                query_string,
                &parts.headers,
                body_slice,
                user_agent.as_deref(),
            )
            .await;

        let site_id = target.site_id.clone();

        match waf_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("maluwaf.https.blackhole_drop").increment(1);
                http_conn.request_drop();
                let resp = Response::new(Full::new(Bytes::new()).boxed());
                Ok(resp)
            }
            crate::proxy::WafDecision::Stall => {
                counter!("maluwaf.https.stalled").increment(1);
                let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
                tokio::select! {
                    _ = tokio::time::sleep(stall_timeout) => {
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
            crate::proxy::WafDecision::Challenge(html) => {
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
                        if let Some(upload_validator) = crate::waf::get_upload_validator() {
                            let effective_config = upload_validator.get_effective_config(&path);
                            if effective_config.scan_with_yara
                                || effective_config.max_size_bytes > 0
                            {
                                match upload_validator.validate_bytes(&body_bytes, &path).await {
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
                                            return Ok(Self::build_response(
                                                403,
                                                body,
                                                "text/html",
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
                if matches!(target.backend_type, crate::router::BackendType::Serverless) {
                    if let Some(ref sm) = serverless_manager {
                        let body_bytes_for_serverless: Bytes = body_bytes.clone();
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
                            let socket_path = supervisor.config().resolve_socket_path();
                            let body_bytes_for_appserver: Bytes = body_bytes.clone();

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
                                    Some(body_bytes.clone()),
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
                                    let filtered_headers =
                                        filter_response_headers(&parts.headers, &headers_to_filter);

                                    let mut builder = Response::builder().status(status);
                                    for (key, value) in filtered_headers {
                                        builder = builder.header(&key, &value);
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
                                        .body(Full::new(body).boxed())
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

                let tls_config = target
                    .site_config
                    .proxy
                    .upstream
                    .as_ref()
                    .and_then(|u| u.tls.as_ref())
                    .and_then(UpstreamTlsConfig::from_site_config)
                    .unwrap_or_default();

                let client = create_upstream_client(
                    std::time::Duration::from_secs(5),
                    100,
                    std::time::Duration::from_secs(30),
                    &tls_config,
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
                    true,
                );

                let mut forward_header_map = http::HeaderMap::new();
                for (key, value) in &forward_headers {
                    if let (Ok(name), Ok(val)) = (
                        key.parse::<http::HeaderName>(),
                        value.parse::<http::HeaderValue>(),
                    ) {
                        forward_header_map.insert(name, val);
                    }
                }

                let resp = send_request_streaming(
                    &client,
                    method.clone(),
                    &target_url,
                    Some(body_bytes.clone()),
                    forward_header_map,
                    Some(std::time::Duration::from_secs(30)),
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

                        let headers =
                            filter_response_headers(&resp_parts.headers, &headers_to_filter);

                        let mut builder = Response::builder().status(status);
                        for (key, value) in headers {
                            builder = builder.header(&key, &value);
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
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
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
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
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
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
            })
    }

    async fn collect_body_with_chunk_waf<B>(
        mut body: B,
        waf: &Arc<crate::waf::WafCore>,
        client_ip: std::net::IpAddr,
    ) -> Bytes
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        const CHUNK_SIZE: usize = 64 * 1024;
        const MAX_ACCUMULATED_WAF: usize = 512 * 1024;

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
                                if let Some(decision) = waf.check_request_body(chunk_to_check) {
                                    match decision {
                                        crate::proxy::WafDecision::Drop
                                        | crate::proxy::WafDecision::Block(_, _) => {
                                            tracing::warn!(
                                                client_ip = %client_ip,
                                                "Request blocked during streaming body WAF check"
                                            );
                                            counter!("maluwaf.https.streaming_body_blocked")
                                                .increment(1);
                                            return Bytes::new();
                                        }
                                        _ => {}
                                    }
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
                            counter!("maluwaf.https.streaming_body_too_large").increment(1);
                            return Bytes::from(accumulated);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Error reading body frame: {:?}", e);
                    break;
                }
            }
        }

        Bytes::from(accumulated)
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
    counter!("maluwaf.tls.passthrough.connection").increment(1);

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

    counter!("maluwaf.tls.passthrough.completed").increment(1);
    Ok(())
}

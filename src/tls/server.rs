#![allow(unused_variables, dead_code, unused_mut)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioExecutor;
use hyper::server::conn::http1 as http1_server;
use hyper::server::conn::http2 as http2_server;
use http::Response;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use metrics::counter;
use parking_lot::Mutex;

use crate::router::Router;
use crate::RunningFlag;
use crate::waf::{WafCore, FloodProtector, FloodDecision};
use crate::config::MainConfig;
use crate::config::HttpConfig;
use crate::http_client::{create_http_client_with_config, send_request_with_timeout};
use crate::proxy::{filter_response_headers, build_headers_to_filter, ProxyServer};
use crate::proxy_cache::{ProxyCache, ProxyCacheSettings};
use crate::challenge::HONEYPOT_PREFIX;
use crate::http::headers::{inject_security_headers, generate_stealth_timestamp};
use crate::metrics::bandwidth::{get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection};

use super::config::InternalTlsConfig;
use super::cert_resolver::CertResolver;

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

    fn take_stream(&self) -> Option<TokioIo<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>> {
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

    pub async fn serve(
        mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            tracing::info!("HTTPS server disabled");
            return Ok(());
        }

        let server_config = self.cert_resolver.build_server_config()?;
        let acceptor = TlsAcceptor::from(server_config);

        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!(
            "HTTPS server listening on {} (TLS 1.3 {} PQC) (HTTP/1.1 + HTTP/2)",
            self.addr,
            if self.config.prefer_post_quantum { "with" } else { "without" }
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
                            let acceptor = acceptor.clone();
                            let router = router.clone();
                            let waf = waf.clone();
                            let http_config = http_config.clone();
                            let main_config = main_config.clone();
                            let flood_protector = flood_protector.clone();
                            
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        counter!("maluwaf.tls.handshakes").increment(1);
                                        counter!("maluwaf.tls.handshakes", "result" => "success").increment(1);
                                        tracing::debug!(
                                            "TLS handshake completed for {}",
                                            client_addr
                                        );
                                        
                                        let client_ip = client_addr.ip();
                                        
                                        if let Some(ref fp) = flood_protector {
                                            match fp.check_tcp_connection(client_ip) {
                                                FloodDecision::Blackholed => {
                                                    counter!("maluwaf.tls.flood_blackhole").increment(1);
                                                    tracing::debug!("TLS connection blackholed for {}", client_ip);
                                                    return;
                                                }
                                                FloodDecision::RateLimited => {
                                                    counter!("maluwaf.tls.flood_limited").increment(1);
                                                    tracing::debug!("TLS connection rate limited for {}", client_ip);
                                                    return;
                                                }
                                                FloodDecision::Allowed => {}
                                            }
                                        }
                                        
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
                                                    let proxy_servers = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
                                                    let ps = proxy_servers.clone();
                                                    move |req| {
                                                        let router = router.clone();
                                                        let waf = waf.clone();
                                                        let http_config = http_config.clone();
                                                        let main_config = main_config.clone();
                                                        let client_addr = client_addr;
                                                        let https_conn = https_conn_clone.clone();
                                                        let ps = ps.clone();
                                                        async move {
                                                            Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps).await
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
                                                    let proxy_servers = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
                                                    let ps = proxy_servers.clone();
                                                    move |req| {
                                                        let router = router.clone();
                                                        let waf = waf.clone();
                                                        let http_config = http_config.clone();
                                                        let main_config = main_config.clone();
                                                        let client_addr = client_addr;
                                                        let https_conn = https_conn_clone.clone();
                                                        let ps = ps.clone();
                                                        async move {
                                                            Self::handle_request_with_cache(req, client_addr, router, waf, http_config, main_config, https_conn, ps).await
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

    async fn handle_request_with_cache(
        req: hyper::Request<hyper::body::Incoming>,
        client_addr: SocketAddr,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        http_config: HttpConfig,
        main_config: Arc<MainConfig>,
        http_conn: Arc<HttpsConnection>,
        proxy_servers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<ProxyServer>>>>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let client_ip = client_addr.ip();
        let path = req.uri().path_and_query()
            .map(|pq| pq.path())
            .unwrap_or("/");

        if path == INTERNAL_HEALTH_PATH || path == INTERNAL_READY_PATH {
            return Self::handle_health_request(path, &main_config);
        }

        if waf.is_over_bandwidth_limit() {
            tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
            counter!("maluwaf.bandwidth.limit_exceeded").increment(1);
            return Ok(Self::build_response(503, "Monthly Bandwidth Limit Exceeded".to_string(), "text/plain"));
        }

        let (parts, body) = req.into_parts();
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
            return Ok(Self::build_response(408, "Request timeout".to_string(), "text/plain"));
        }

        if path.starts_with("/_waf_css_challenge") {
            let (html, _) = waf.challenge_manager.generate_challenge_page(&client_ip);
            return Ok(Self::build_response(200, html, "text/html"));
        }

        if path.starts_with("/_waf_assets") {
            return Ok(Self::build_response(404, "Not Found".to_string(), "text/plain"));
        }

        let query_string = parts.uri.query();
        
        let max_body_size = http_config.max_request_size;
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::warn!("Failed to collect request body: {}", e);
                Bytes::new()
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
                return Ok(Self::build_response(404, "Not Found".to_string(), "text/plain"));
            }
            crate::router::RouteResult::Error(msg) => {
                tracing::error!("Router error: {}", msg);
                return Ok(Self::build_response(500, "Internal Server Error".to_string(), "text/plain"));
            }
        };

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

        let site_id = target.site_id.clone();

        match waf_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("maluwaf.https.blackhole_drop").increment(1);
                http_conn.request_drop();
                let resp = Response::new(Full::new(Bytes::new()));
                return Ok(resp);
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
                let site_theme = target.site_config.error_pages.theme.as_ref()
                    .map(|theme_config| theme_config.to_theme_config(waf.error_page_manager.theme()));
                let body = waf.error_page_manager.render_page_with_theme(status, Some(&message), site_theme.as_ref());
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
                    bw.record_egress(body_len, BandwidthProtocol::Https, EgressDirection::Challenged);
                    bw.record_site_egress(&site_id, body_len);
                }
                Ok(Self::build_response(200, html, "text/html"))
            }
            crate::proxy::WafDecision::ChallengeWithCookie { html, session_cookie_name, session_cookie_value, session_cookie_max_age } => {
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Https, EgressDirection::Challenged);
                    bw.record_site_egress(&site_id, body_len);
                }
                let cookie = format!("{}={}; path=/; max-age={}; Secure; SameSite=Strict", session_cookie_name, session_cookie_value, session_cookie_max_age);
                Ok(Self::build_response_with_cookie(200, html, "text/html", &cookie))
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
                let cache_config = target.site_config.proxy.cache.as_ref();
                let use_cache = cache_config.map(|c| c.enable.unwrap_or(false)).unwrap_or(false);
                
                if use_cache {
                    if let Some(cache_cfg) = cache_config {
                        let site_id = target.site_id.to_string();
                        let proxy_servers_lock = proxy_servers.read().await;
                        
                        let proxy_server = if let Some(existing) = proxy_servers_lock.get(&site_id) {
                            Some(existing.clone())
                        } else {
                            drop(proxy_servers_lock);
                            let settings = ProxyCacheSettings::from_config(
                                cache_cfg.enable,
                                cache_cfg.path.clone(),
                                cache_cfg.max_size.clone(),
                                cache_cfg.inactive,
                                cache_cfg.use_temp_file.clone(),
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
                            let ps = ProxyServer::new(
                                target.upstream.to_string(),
                                waf.clone(),
                                main_config.proxy_limits.max_response_size,
                                waf.upstream_error_tracker.clone(),
                                site_id.clone(),
                            ).with_cache(cache);

                            let ps = Arc::new(ps);
                            let mut proxy_servers_lock = proxy_servers.write().await;
                            proxy_servers_lock.insert(site_id, ps.clone());
                            Some(ps)
                        };

                        if let Some(proxy_server) = proxy_server {
                            match proxy_server.handle_request_with_cache(
                                method.clone(),
                                &path,
                                &host,
                                &parts.headers,
                                "https",
                            ).await {
                                Ok(resp) => {
                                    let (parts, body) = resp.into_parts();
                                    let status = parts.status.as_u16();
                                    let body_bytes = Bytes::from(body);
                                    
                                    let headers_to_filter = build_headers_to_filter(
                                        &main_config.security.more_clear_headers,
                                        &target.site_config.security.more_clear_headers.iter()
                                            .chain(target.site_config.security_headers.more_clear_headers.iter())
                                            .cloned()
                                            .collect::<Vec<_>>(),
                                    );
                                    let filtered_headers = filter_response_headers(&parts.headers, &headers_to_filter);
                                    
                                    let mut builder = Response::builder().status(status);
                                    for (key, value) in filtered_headers {
                                        builder = builder.header(&key, &value);
                                    }
                                    
                                    if target.site_config.security_headers.enabled.unwrap_or(false) || main_config.security.global_security_headers {
                                        builder = inject_security_headers(builder, &target.site_config.security_headers);
                                    }
                                    
                                    if target.site_config.security_headers.date_header.unwrap_or(true) {
                                        let jitter = target.site_config.security_headers.date_jitter_seconds.unwrap_or(5);
                                        builder = builder.header("Date", generate_stealth_timestamp(jitter));
                                    }
                                    
                                    return Ok(builder
                                        .body(Full::new(body_bytes))
                                        .unwrap_or_else(|_| Self::build_response(500, "Internal Server Error".to_string(), "text/plain")));
                                }
                                Err(e) => {
                                    tracing::error!("Proxy server error: {}", e);
                                    return Ok(Self::build_response(502, "Bad Gateway".to_string(), "text/plain"));
                                }
                            }
                        }
                    }
                }
                
                let target_url = format!("{}{}", target.upstream, path);
                
                let headers_to_filter = build_headers_to_filter(
                    &main_config.security.more_clear_headers,
                    &target.site_config.security.more_clear_headers.iter()
                        .chain(target.site_config.security_headers.more_clear_headers.iter())
                        .cloned()
                        .collect::<Vec<_>>(),
                );
                
                let client = create_http_client_with_config(
                    std::time::Duration::from_secs(5),
                    100,
                    std::time::Duration::from_secs(30),
                );
                
                let resp = send_request_with_timeout(&client, method, &target_url, Some(std::time::Duration::from_secs(30))).await;
                
                match resp {
                    Ok(resp) => {
                        let status = resp.status_code();
                        let headers = filter_response_headers(&resp.headers, &headers_to_filter);
                        let body = resp.body;
                        let body_len = body.len() as u64;
                        
                        if let Some(ref bw) = bandwidth {
                            bw.record_proxied(request_body_size, body_len, &target.upstream);
                            bw.record_site_proxied(&site_id, request_body_size, body_len);
                            bw.record_egress(body_len, BandwidthProtocol::Https, EgressDirection::Proxied);
                            bw.record_site_egress(&site_id, body_len);
                        }
                        
                        let mut builder = Response::builder().status(status);
                        for (key, value) in headers {
                            builder = builder.header(&key, &value);
                        }
                        
                        if target.site_config.security_headers.enabled.unwrap_or(false) || main_config.security.global_security_headers {
                            builder = inject_security_headers(builder, &target.site_config.security_headers);
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
                            .unwrap_or_else(|_| Self::build_response(500, "Internal Server Error".to_string(), "text/plain")))
                    }
                    Err(e) => {
                        tracing::error!("Upstream error: {}", e);
                        let error_body = "Bad Gateway".to_string();
                        let error_len = error_body.len() as u64;
                        if let Some(ref bw) = bandwidth {
                            bw.record_egress(error_len, BandwidthProtocol::Https, EgressDirection::Error);
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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let body = serde_json::json!({
            "status": "healthy",
        }).to_string();

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
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap()))
    }

    fn build_response(status: u16, body: String, content_type: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
            .header("Date", generate_stealth_timestamp(5))
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap())
    }

    fn build_response_with_cookie(status: u16, body: String, content_type: &str, cookie: &str) -> Response<Full<Bytes>> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
            .header("Set-Cookie", cookie)
            .header("Date", generate_stealth_timestamp(5));

        builder
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap())
    }
}

pub fn create_tls_acceptor(
    _config: &InternalTlsConfig,
    cert_resolver: &CertResolver,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let server_config = cert_resolver.build_server_config()?;
    Ok(TlsAcceptor::from(server_config))
}

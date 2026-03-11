use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;
use http::Response;
use bytes::Bytes;
use http_body_util::Full;
use tokio::sync::broadcast;
use metrics::counter;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, WebSocketStream, tungstenite::protocol::Role};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::router::Router;
use crate::waf::{WafCore, FloodProtector, FloodDecision};
use crate::http_client::{create_http_client_with_config, send_request_with_timeout, HttpClient};
use crate::config::MainConfig;
use crate::config::main::HttpConfig;
use crate::config::site::SiteWebSocketConfig;
use crate::proxy::{HOP_BY_HOP_HEADERS, filter_response_headers};
use crate::challenge::HONEYPOT_PREFIX;
use crate::protocol::websocket::WebSocketHandler;
use crate::protocol::trait_def::{ProtocolHandler, WafAction};
use crate::protocol::types::{ProtocolRequest, ProtocolType};

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
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_alt_svc(mut self, alt_svc: String) -> Self {
        self.alt_svc = Some(alt_svc);
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

        let header_read_timeout = Duration::from_secs(http_config.header_read_timeout_secs);
        let max_headers = http_config.max_headers;
        let max_buf_size = http_config.max_request_size;
        
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
                                        counter!("rustwaf.http.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("rustwaf.http.flood_limited").increment(1);
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
                            let io = TokioIo::new(stream);
                            
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
                                    async move {
                                        Self::handle_request(req, client_addr, local_addr, router, waf, client, alt_svc, main_config).await
                                    }
                                }))
                                .with_upgrades();
                            
                            tokio::spawn(async move {
                                if let Err(e) = conn.await {
                                    tracing::debug!("HTTP connection error: {}", e);
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
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let client_ip = client_addr.ip();

        let connection_token = if let Some(ref conn_limiter) = waf.connection_limiter {
            match conn_limiter.try_acquire("_http_", client_ip).await {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                    counter!("rustwaf.traffic.connection_limited").increment(1);
                    return Ok(Self::build_response_with_alt_svc(503, "Too Many Connections".to_string(), "application/json", &alt_svc, &main_config));
                }
            }
        } else {
            None
        };

        let _conn_token = connection_token;

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

        if path.starts_with("/_waf_pow") || path.starts_with("/_waf_css_challenge") 
            || path.starts_with("/_waf_assets") || path.starts_with("/_waf_login") 
            || path.starts_with("/_waf_logout") || path.starts_with("/_waf_captcha") {
            return Ok(Self::build_response_with_alt_svc(404, "Not Found".to_string(), "text/plain", &alt_svc, &main_config));
        }

        if path.starts_with(HONEYPOT_PREFIX) {
            counter!("rustwaf.honeypot.hit").increment(1);
            tracing::info!("HTTP honeypot accessed: {} by {}", path, client_ip);
            return Ok(Self::build_response_with_alt_svc(408, "Request timeout".to_string(), "text/plain", &alt_svc, &main_config));
        }

        let query_string = parts.uri.query();
        
        let body_slice: Option<&[u8]> = None;

        let route = router.route_with_local_addr(&host, &path, local_addr);

        let target = match route {
            crate::router::RouteResult::Found(target) => target,
            crate::router::RouteResult::NotFound(msg) => {
                tracing::debug!("Route not found: {} for host: {}", msg, host);
                return Ok(Self::build_response_with_alt_svc(404, "Not Found".to_string(), "text/plain", &alt_svc, &main_config));
            }
            crate::router::RouteResult::Error(msg) => {
                tracing::error!("Router error: {}", msg);
                return Ok(Self::build_response_with_alt_svc(500, "Internal Server Error".to_string(), "text/plain", &alt_svc, &main_config));
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

        match waf_decision {
            crate::proxy::WafDecision::Drop => {
                counter!("rustwaf.http.blackhole_drop").increment(1);
                return Ok(Self::build_response_with_alt_svc(503, "Service Unavailable".to_string(), "text/plain", &alt_svc, &main_config));
            }
            crate::proxy::WafDecision::Stall => {
                counter!("rustwaf.http.stalled").increment(1);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        Ok(Self::build_response_with_alt_svc(408, "Request timeout".to_string(), "text/plain", &alt_svc, &main_config))
                    }
                }
            }
            crate::proxy::WafDecision::Block(status, message) => {
                let body = waf.error_page_manager.render_page(status, Some(&message));
                Ok(Self::build_response_with_alt_svc(status, body, "text/html", &alt_svc, &main_config))
            }
            crate::proxy::WafDecision::Challenge(html) => {
                Ok(Self::build_response_with_alt_svc(200, html, "text/html", &alt_svc, &main_config))
            }
            crate::proxy::WafDecision::Tarpit(tar_path) => {
                let html = waf.generate_tarpit_response(&tar_path);
                Ok(Self::build_response_with_alt_svc(200, html, "text/html", &alt_svc, &main_config))
            }
            crate::proxy::WafDecision::Pass => {
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
                
                let global_headers_to_remove: Vec<String> = main_config.security.more_clear_headers.iter()
                    .map(|s| s.to_lowercase())
                    .collect();
                
                let site_headers_to_remove: Vec<String> = target.site_config.security.more_clear_headers.iter()
                    .chain(target.site_config.security_headers.more_clear_headers.iter())
                    .map(|s| s.to_lowercase())
                    .collect();
                
                let mut headers_to_filter: Vec<String> = HOP_BY_HOP_HEADERS.iter()
                    .map(|s| s.to_string())
                    .collect();
                
                for h in global_headers_to_remove.iter() {
                    if !headers_to_filter.contains(h) {
                        headers_to_filter.push(h.clone());
                    }
                }
                
                for h in site_headers_to_remove.iter() {
                    if !headers_to_filter.contains(h) {
                        headers_to_filter.push(h.clone());
                    }
                }
                
                match send_request_with_timeout(&client, method, &target_url, Some(std::time::Duration::from_secs(30))).await {
                    Ok(resp) => {
                        let status = resp.status_code();
                        let headers = filter_response_headers(&resp.headers, &headers_to_filter);
                        
                        let body = resp.body;
                        
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
                        
                        Ok(builder
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| Self::build_response_with_alt_svc(500, "Internal Server Error".to_string(), "text/plain", &alt_svc, &main_config)))
                    }
                    Err(e) => {
                        tracing::error!("Upstream error: {}", e);
                        Ok(Self::build_response_with_alt_svc(502, "Bad Gateway".to_string(), "text/plain", &alt_svc, &main_config))
                    }
                }
            }
        }
    }

    fn inject_security_headers(
        builder: http::response::Builder,
        config: &crate::config::SiteSecurityHeadersConfig,
    ) -> http::response::Builder {
        let mut builder = builder;
        
        if let Some(ref hsts) = config.strict_transport_security {
            builder = builder.header("Strict-Transport-Security", hsts);
        }
        
        if let Some(ref csp) = config.content_security_policy {
            builder = builder.header("Content-Security-Policy", csp);
        }
        
        if let Some(ref xfo) = config.x_frame_options {
            builder = builder.header("X-Frame-Options", xfo);
        }
        
        if let Some(ref xcto) = config.x_content_type_options {
            builder = builder.header("X-Content-Type-Options", xcto);
        }
        
        if let Some(ref xxss) = config.x_xss_protection {
            builder = builder.header("X-XSS-Protection", xxss);
        }
        
        if let Some(ref rp) = config.referrer_policy {
            builder = builder.header("Referrer-Policy", rp);
        }
        
        if let Some(ref pp) = config.permissions_policy {
            builder = builder.header("Permissions-Policy", pp);
        }
        
        if let Some(ref cc) = config.cache_control {
            builder = builder.header("Cache-Control", cc);
        }
        
        if let Some(ref ect) = config.expect_ct {
            builder = builder.header("Expect-CT", ect);
        }
        
        if let Some(ref pcdp) = config.x_permitted_cross_domain_policies {
            builder = builder.header("X-Permitted-Cross-Domain-Policies", pcdp);
        }
        
        if let Some(ref xdo) = config.x_download_options {
            builder = builder.header("X-Download-Options", xdo);
        }
        
        if let Some(ref ct) = config.content_type {
            builder = builder.header("Content-Type", ct);
        }
        
        if config.cors.enabled.unwrap_or(false) {
            builder = Self::inject_cors_headers(builder, &config.cors);
        }
        
        builder
    }

    fn inject_cors_headers(
        builder: http::response::Builder,
        config: &crate::config::SiteCorsConfig,
    ) -> http::response::Builder {
        let mut builder = builder;
        
        if let Some(ref origin) = config.allow_origin {
            builder = builder.header("Access-Control-Allow-Origin", origin);
        }
        
        if let Some(ref methods) = config.allow_methods {
            builder = builder.header("Access-Control-Allow-Methods", methods.join(", "));
        }
        
        if let Some(ref headers) = config.allow_headers {
            builder = builder.header("Access-Control-Allow-Headers", headers.join(", "));
        }
        
        if config.allow_credentials.unwrap_or(false) {
            builder = builder.header("Access-Control-Allow-Credentials", "true");
        }
        
        if let Some(max_age) = config.max_age {
            builder = builder.header("Access-Control-Max-Age", max_age.to_string());
        }
        
        if let Some(ref headers) = config.expose_headers {
            builder = builder.header("Access-Control-Expose-Headers", headers.join(", "));
        }
        
        builder
    }

    fn build_response_with_alt_svc(status: u16, body: String, content_type: &str, alt_svc: &Option<String>, main_config: &Arc<MainConfig>) -> Response<Full<Bytes>> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len());
        
        if let Some(ref alt_svc) = alt_svc {
            builder = builder.header("Alt-Svc", alt_svc.as_str());
        }
        
        if main_config.security.global_security_headers {
            builder = builder
                .header("Cache-Control", "no-store, no-cache, must-revalidate")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY");
        }
        
        builder
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap())
    }

    fn build_response(status: u16, body: String, content_type: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len())
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
                counter!("rustwaf.websocket.upgrade_failed").increment(1);
                return;
            }
        };

        counter!("rustwaf.websocket.connections").increment(1);

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
                counter!("rustwaf.websocket.upstream_failed").increment(1);
                return;
            }
        };

        counter!("rustwaf.websocket.upstream_connected").increment(1);

        let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

        let path_clone = path.clone();
        let waf_clone = waf.clone();
        let should_close = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let should_close_clone = should_close.clone();
        
        let client_to_upstream = async {
            while let Some(msg_result) = client_rx.next().await {
                if should_close_clone.load(std::sync::atomic::Ordering::Relaxed) {
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
                    WsMessage::Binary(b) => ("BINARY", b.clone()),
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
                        counter!("rustwaf.websocket.blocked").increment(1);
                        let _ = upstream_tx.close().await;
                        should_close_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    WafAction::LogOnly => {
                        tracing::debug!(
                            client_ip = %client_ip,
                            "WebSocket message logged by WAF"
                        );
                        counter!("rustwaf.websocket.logged").increment(1);
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
                if should_close.load(std::sync::atomic::Ordering::Relaxed) {
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

        counter!("rustwaf.websocket.closed").increment(1);
        tracing::debug!("WebSocket connection closed");
    }

    fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
        let upgrade = headers.get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());
        
        let connection = headers.get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());
        
        let has_upgrade = upgrade.as_ref().map(|u| u == "websocket").unwrap_or(false);
        let has_connection_upgrade = connection
            .as_ref()
            .map(|c| c.contains("upgrade"))
            .unwrap_or(false);
        
        has_upgrade && has_connection_upgrade
    }

    fn compute_websocket_accept_key(key: &str) -> String {
        use sha2::{Sha256, Digest};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        
        const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{}{}", key, GUID);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        STANDARD.encode(result)
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
}
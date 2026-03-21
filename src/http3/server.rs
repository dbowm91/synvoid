use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

use bytes::Bytes;
use http::{StatusCode, header};
use metrics::{counter, histogram, gauge};

use crate::config::Http3Config;
use crate::proxy::WafDecision;
use crate::router::{Router, RouteResult};
use crate::waf::{WafCore, FloodProtector, FloodDecision};
use crate::http::headers::generate_stealth_timestamp;
use crate::metrics::bandwidth::{get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection};

pub struct Http3Server {
    addr: SocketAddr,
    config: Http3Config,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    #[allow(dead_code)]
    shutdown_rx: broadcast::Receiver<()>,
}

impl Http3Server {
    pub fn new(
        addr: SocketAddr,
        config: Http3Config,
        router: Router,
        waf: Arc<WafCore>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            addr,
            config,
            router: Arc::new(router),
            waf,
            flood_protector: None,
            shutdown_rx,
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub async fn serve(
        mut self,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            tracing::info!("HTTP/3 server disabled");
            return Ok(());
        }

        let mut server_crypto = (*tls_config).clone();
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("Failed to create QUIC server config: {}", e))?;
        
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        
        let transport_config = Arc::get_mut(&mut server_config.transport)
            .expect("Failed to get transport config");
        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_concurrent_bidi_streams(100_u32.into());
        
        let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .expect("Failed to create idle timeout");
        transport_config.max_idle_timeout(Some(idle_timeout));

        let endpoint = quinn::Endpoint::server(server_config, self.addr)
            .map_err(|e| format!("Failed to create QUIC endpoint: {}", e))?;

        tracing::info!("HTTP/3 server listening on {}", self.addr);

        let router = self.router.clone();
        let waf = self.waf.clone();
        let flood_protector = self.flood_protector.clone();
        let max_request_size = self.config.max_request_size;
        
        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(conn) => {
                            let router = router.clone();
                            let waf = waf.clone();
                            let flood_protector = flood_protector.clone();
                            let max_request_size = max_request_size;
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_quic_connection(conn, router, waf, flood_protector, max_request_size).await {
                                    tracing::debug!("HTTP/3 connection error: {}", e);
                                }
                            });
                        }
                        None => {
                            tracing::info!("HTTP/3 endpoint closed");
                            break;
                        }
                    }
                }
                _ = self.shutdown_rx.recv() => {
                    tracing::info!("HTTP/3 server received shutdown signal");
                    endpoint.close(0u32.into(), b"Server shutdown");
                    break;
                }
            }
        }

        tracing::info!("HTTP/3 server shutdown complete");
        Ok(())
    }

    async fn handle_quic_connection(
        incoming: quinn::Incoming,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        flood_protector: Option<Arc<FloodProtector>>,
        max_request_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connection = incoming.await
            .map_err(|e| {
                counter!("maluwaf.http3.connection.errors").increment(1);
                format!("Connection failed: {}", e)
            })?;

        let remote_addr = connection.remote_address();
        let client_ip = remote_addr.ip();
        
        tracing::debug!("HTTP/3 connection from {}", remote_addr);

        if let Some(ref fp) = flood_protector {
            match fp.check_tcp_connection(client_ip) {
                FloodDecision::Blackholed => {
                    counter!("maluwaf.http3.flood_blackhole").increment(1);
                    return Ok(());
                }
                FloodDecision::RateLimited => {
                    counter!("maluwaf.http3.flood_limited").increment(1);
                    return Ok(());
                }
                FloodDecision::Allowed => {}
            }
        }

        gauge!("maluwaf.http3.connections").increment(1.0);
        counter!("maluwaf.http3.connections.total").increment(1);

        let server_builder = h3::server::builder();
        let mut h3_conn = server_builder.build(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| {
                counter!("maluwaf.http3.connection.errors").increment(1);
                format!("Failed to create H3 connection: {}", e)
            })?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let router = router.clone();
                    let waf = waf.clone();
                    let max_request_size = max_request_size;
                    let _flood_protector = flood_protector.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(resolver, remote_addr, router, waf, max_request_size).await {
                            tracing::debug!("HTTP/3 request error: {}", e);
                        }
                    });
                }
                Ok(None) => {
                    tracing::debug!("HTTP/3 connection closed by peer");
                    break;
                }
                Err(e) => {
                    tracing::debug!("HTTP/3 accept error: {}", e);
                    counter!("maluwaf.http3.connection.errors").increment(1);
                    break;
                }
            }
        }

        gauge!("maluwaf.http3.connections").decrement(1.0);
        Ok(())
    }

    async fn handle_request(
        resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
        remote_addr: SocketAddr,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        max_request_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        
        let client_ip = remote_addr.ip();

        let connection_token = if let Some(ref conn_limiter) = waf.connection_limiter {
            match conn_limiter.try_acquire("_http3_", client_ip).await {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::warn!("HTTP/3 connection limit exceeded for {}: {}", client_ip, e);
                    counter!("maluwaf.http3.connection_limited").increment(1);
                    return Ok(());
                }
            }
        } else {
            None
        };

        if waf.is_over_bandwidth_limit() {
            tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
            counter!("maluwaf.bandwidth.limit_exceeded").increment(1);
            return Ok(());
        }

        let (request, mut request_stream) = resolver.resolve_request().await
            .map_err(|e| {
                counter!("maluwaf.http3.request.errors").increment(1);
                histogram!("maluwaf.http3.request.duration").record(start.elapsed().as_secs_f64());
                format!("Failed to resolve request: {}", e)
            })?;

        let method = request.method().clone();
        let uri = request.uri().clone();
        let path = uri.path().to_string();
        let method_str = method.as_str();
        let query_string = uri.query();
        
        tracing::trace!("HTTP/3 {} {} from {}", method, uri, remote_addr);

        let host = request.headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        
        let headers = request.headers().clone();
        
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let max_body_size = max_request_size;
        let mut body_bytes = Vec::new();
        while let Ok(Some(chunk)) = request_stream.recv_data().await {
            use bytes::Buf;
            let chunk_len = chunk.remaining();
            if body_bytes.len() + chunk_len > max_body_size {
                tracing::warn!(client = %client_ip, size = body_bytes.len(), "HTTP/3 request body exceeds max size");
                counter!("maluwaf.http3.request.body_too_large").increment(1);
                break;
            }
            let mut chunk = chunk;
            body_bytes.extend_from_slice(chunk.copy_to_bytes(chunk_len).as_ref());
        }

        let body_slice: Option<&[u8]> = if body_bytes.is_empty() {
            None
        } else {
            Some(&body_bytes)
        };

        let body_len = body_bytes.len() as u64;
        let bandwidth = get_global_bandwidth_tracker_or_log();
        if body_len > 0 {
            if let Some(ref bw) = bandwidth {
                bw.record_ingress(body_len, BandwidthProtocol::Http3);
                bw.record_site_ingress(&host, body_len);
            }
        }

        tracing::trace!(client = %client_ip, method = %method_str, path = %path, body_size = body_bytes.len(), "HTTP/3 request body read");

        let waf_decision = waf.check_request_full(
            client_ip,
            method_str,
            &path,
            query_string,
            &headers,
            body_slice,
            user_agent.as_deref(),
        ).await;

        match waf_decision {
            WafDecision::Stall => {
                counter!("maluwaf.http3.requests.stalled").increment(1);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        tracing::debug!("Stall timeout reached, dropping connection");
                    }
                }
            }
            WafDecision::Block(status, message) => {
                counter!("maluwaf.http3.requests.blocked").increment(1);
                let body = format!("{{\"error\":\"{}\"}}", message);
                let body_len = body.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Http3, EgressDirection::Blocked);
                    bw.record_site_egress(&host, body_len);
                }
                let response = http::Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .body(Bytes::from(body))
                    .map_err(|e| format!("Failed to build response: {}", e))?;
                
                let (parts, _body) = response.into_parts();
                request_stream.send_response(http::Response::from_parts(parts, ())).await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
            }
            WafDecision::Challenge(html) => {
                counter!("maluwaf.http3.requests.challenged").increment(1);
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Http3, EgressDirection::Challenged);
                    bw.record_site_egress(&host, body_len);
                }
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .body(Bytes::from(html))
                    .map_err(|e| format!("Failed to build response: {}", e))?;
                
                let (parts, body) = response.into_parts();
                request_stream.send_response(http::Response::from_parts(parts, ())).await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream.send_data(body).await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
            }
            WafDecision::ChallengeWithCookie { html, session_cookie_name, session_cookie_value, session_cookie_max_age } => {
                counter!("maluwaf.http3.requests.challenged").increment(1);
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Http3, EgressDirection::Challenged);
                    bw.record_site_egress(&host, body_len);
                }
                let cookie = format!("{}={}; path=/; max-age={}; Secure; SameSite=Strict", session_cookie_name, session_cookie_value, session_cookie_max_age);
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .header(header::SET_COOKIE, cookie)
                    .body(Bytes::from(html))
                    .map_err(|e| format!("Failed to build response: {}", e))?;
                
                let (parts, body) = response.into_parts();
                request_stream.send_response(http::Response::from_parts(parts, ())).await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream.send_data(body).await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
            }
            WafDecision::Tarpit(tar_path) => {
                counter!("maluwaf.http3.requests.tarpitted").increment(1);
                let html = waf.generate_tarpit_response(&tar_path);
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(body_len, BandwidthProtocol::Http3, EgressDirection::Blocked);
                    bw.record_site_egress(&host, body_len);
                }
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .body(Bytes::from(html))
                    .map_err(|e| format!("Failed to build response: {}", e))?;
                
                let (parts, body) = response.into_parts();
                request_stream.send_response(http::Response::from_parts(parts, ())).await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream.send_data(body).await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
            }
            WafDecision::Drop => {
                counter!("maluwaf.http3.blackhole_drop").increment(1);
                return Ok(());
            }
            WafDecision::Pass => {}
        }

        let route_result = router.route(&host, &path);

        match route_result {
            RouteResult::Found(route_target) => {
                let body = format!("HTTP/3 proxied to {} - path: {}", 
                    route_target.upstream,
                    path);
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .body(Bytes::from(body))
                    .map_err(|e| format!("Failed to build response: {}", e))?;
                
                let (parts, body) = response.into_parts();
                request_stream.send_response(http::Response::from_parts(parts, ())).await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream.send_data(body).await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
            }
            RouteResult::NotFound(e) | RouteResult::Error(e) => {
                tracing::debug!("Route not found: {} for host: {}", e, host);
                counter!("maluwaf.http3.requests.not_found").increment(1);
                let body = format!("Not Found: {}", e);
                let response = http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .body(Bytes::from(body))
                    .map_err(|e| format!("Failed to build response: {}", e))?;
                
                let (parts, _body) = response.into_parts();
                request_stream.send_response(http::Response::from_parts(parts, ())).await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
            }
        }

        request_stream.finish().await
            .map_err(|e| format!("Failed to finish stream: {}", e))?;

        histogram!("maluwaf.http3.request.duration").record(start.elapsed());
        counter!("maluwaf.http3.responses").increment(1);
        
        drop(connection_token);
        
        Ok(())
    }

    pub fn alt_svc_header(&self) -> String {
        if self.config.enabled {
            format!("h3=\":{}\"; ma={}", self.config.port, self.config.alt_svc_max_age)
        } else {
            String::new()
        }
    }
}

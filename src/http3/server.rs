use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use bytes::Bytes;
use http::{header, StatusCode};
use http_body_util::BodyExt;
use metrics::{counter, gauge, histogram};

use crate::config::{Http3Config, MainConfig};
use crate::http::headers::generate_stealth_timestamp;
use crate::http_client::{
    create_http_client_with_config, send_request_streaming, HttpClient,
};
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
use crate::metrics::WorkerMetrics;
use crate::proxy::{build_forward_headers, WafDecision};
use crate::router::{RouteResult, Router};
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::worker::drain_state::WorkerDrainState;
use crate::config::site::ProxyHeadersConfig;

pub struct Http3Server {
    addr: SocketAddr,
    config: Http3Config,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    drain_state: Option<Arc<WorkerDrainState>>,
    metrics: Option<Arc<WorkerMetrics>>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl Http3Server {
    pub fn new(
        addr: SocketAddr,
        config: Http3Config,
        router: Router,
        waf: Arc<WafCore>,
        _main_config: MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        let client = create_http_client_with_config(
            Duration::from_secs(5),
            100,
            Duration::from_secs(30),
        );

        Self {
            addr,
            config,
            router: Arc::new(router),
            waf,
            flood_protector: None,
            client,
            drain_state: None,
            metrics: None,
            shutdown_rx,
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self {
        self.drain_state = Some(drain_state);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn serve(
        self,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            return Ok(());
        }

        // Fix for quinn 0.11: use QuicServerConfig::try_from
        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| format!("Failed to create QUIC server config: {}", e))?;
        
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        
        let transport_config =
            Arc::get_mut(&mut server_config.transport).expect("Failed to get transport config");
        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_concurrent_bidi_streams(100_u32.into());

        let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .expect("Failed to create idle timeout");
        transport_config.max_idle_timeout(Some(idle_timeout));

        let endpoint = quinn::Endpoint::server(server_config, self.addr)
            .map_err(|e| format!("Failed to create QUIC endpoint: {}", e))?;

        tracing::info!("HTTP/3 server listening on {}", self.addr);

        let self_arc = Arc::new(self);
        let mut shutdown_rx = self_arc.shutdown_rx.resubscribe();

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(conn) => {
                            let s = self_arc.clone();
                            tokio::spawn(async move {
                                if let Err(e) = s.handle_quic_connection(conn).await {
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
                _ = shutdown_rx.recv() => {
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
        self: Arc<Self>,
        incoming: quinn::Incoming,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connection = incoming.await.map_err(|e| {
            counter!("maluwaf.http3.connection.errors").increment(1);
            format!("Connection failed: {}", e)
        })?;

        let remote_addr = connection.remote_address();
        let client_ip = remote_addr.ip();

        tracing::debug!("HTTP/3 connection from {}", remote_addr);

        if let Some(ref fp) = self.flood_protector {
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
        let mut h3_conn = server_builder
            .build(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| {
                counter!("maluwaf.http3.connection.errors").increment(1);
                format!("Failed to create H3 connection: {}", e)
            })?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let s = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = s.handle_request(resolver, remote_addr).await {
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
        self: Arc<Self>,
        resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
        remote_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        let client_ip = remote_addr.ip();
        let max_request_size = self.config.max_request_size;

        let mut connection_token = if let Some(ref conn_limiter) = self.waf.connection_limiter {
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

        if self.waf.is_over_bandwidth_limit() {
            tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
            counter!("maluwaf.bandwidth.limit_exceeded").increment(1);
            return Ok(());
        }

        let (request, mut request_stream) = resolver.resolve_request().await.map_err(|e| {
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

        let host = request
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let headers = request.headers().clone();

        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let mut body_bytes = Vec::new();
        while let Ok(Some(chunk)) = request_stream.recv_data().await {
            use bytes::Buf;
            let chunk_len = chunk.remaining();
            if body_bytes.len() + chunk_len > max_request_size {
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

        let waf_decision = self.waf
            .check_request_full(
                client_ip,
                method_str,
                &path,
                query_string,
                &headers,
                body_slice,
                user_agent.as_deref(),
                None,
                None,
            )
            .await;

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

                let (parts, body) = response.into_parts();
                request_stream
                    .send_response(http::Response::from_parts(parts, ()))
                    .await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream.send_data(body).await?;
                request_stream.finish().await?;
                return Ok(());
            }
            WafDecision::Challenge(html) => {
                counter!("maluwaf.http3.requests.challenged").increment(1);
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(
                        body_len,
                        BandwidthProtocol::Http3,
                        EgressDirection::Challenged,
                    );
                    bw.record_site_egress(&host, body_len);
                }
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .body(Bytes::from(html))
                    .map_err(|e| format!("Failed to build response: {}", e))?;

                let (parts, body) = response.into_parts();
                request_stream
                    .send_response(http::Response::from_parts(parts, ()))
                    .await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream
                    .send_data(body)
                    .await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
                request_stream.finish().await?;
                return Ok(());
            }
            WafDecision::ChallengeWithCookie {
                html,
                session_cookie_name,
                session_cookie_value,
                session_cookie_max_age,
            } => {
                counter!("maluwaf.http3.requests.challenged").increment(1);
                let body_len = html.len() as u64;
                if let Some(ref bw) = bandwidth {
                    bw.record_egress(
                        body_len,
                        BandwidthProtocol::Http3,
                        EgressDirection::Challenged,
                    );
                    bw.record_site_egress(&host, body_len);
                }
                let cookie = format!(
                    "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                    session_cookie_name, session_cookie_value, session_cookie_max_age
                );
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .header(header::DATE, generate_stealth_timestamp(5))
                    .header(header::SET_COOKIE, cookie)
                    .body(Bytes::from(html))
                    .map_err(|e| format!("Failed to build response: {}", e))?;

                let (parts, body) = response.into_parts();
                request_stream
                    .send_response(http::Response::from_parts(parts, ()))
                    .await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream
                    .send_data(body)
                    .await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
                request_stream.finish().await?;
                return Ok(());
            }
            WafDecision::Tarpit(tar_path) => {
                counter!("maluwaf.http3.requests.tarpitted").increment(1);
                let html = self.waf.generate_tarpit_response(&tar_path);
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
                request_stream
                    .send_response(http::Response::from_parts(parts, ()))
                    .await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream
                    .send_data(body)
                    .await
                    .map_err(|e| format!("Failed to send data: {}", e))?;
                request_stream.finish().await?;
                return Ok(());
            }
            WafDecision::Drop => {
                counter!("maluwaf.http3.blackhole_drop").increment(1);
                return Ok(());
            }
            WafDecision::Pass => {}
        }

        let route_result = self.router.route(&host, &path);

        match route_result {
            RouteResult::Found(route_target) => {
                let site_id = route_target.site_id.to_string();
                let site_traffic_config = &route_target.site_config.traffic_shaping.connection;
                let site_max_connections = site_traffic_config.max_connections;
                let site_max_per_ip = site_traffic_config.max_connections_per_ip;

                if site_max_connections.is_some() || site_max_per_ip.is_some() {
                    if let Some(ref conn_limiter) = self.waf.connection_limiter {
                        if let Some(token) = connection_token.take() {
                            conn_limiter.release(token);
                        }
                        match conn_limiter
                            .try_acquire_with_limits(
                                &site_id,
                                client_ip,
                                site_max_connections,
                                site_max_per_ip,
                            )
                            .await
                        {
                            Ok(new_token) => {
                                connection_token = Some(new_token);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "HTTP/3 per-site connection limit exceeded for site {}: {}",
                                    site_id,
                                    e
                                );
                                counter!("maluwaf.http3.connection_limited").increment(1);
                                request_stream.finish().await?;
                                return Ok(());
                            }
                        }
                    }
                }

                // Actual proxying logic
                let upstream_url = format!("{}{}", route_target.upstream.trim_end_matches('/'), path);
                
                static DEFAULT_HEADERS_CONFIG: ProxyHeadersConfig = ProxyHeadersConfig {
                    clear: Vec::new(),
                    set: Vec::new(),
                    forward: Vec::new(),
                    hide: Vec::new(),
                };

                let forward_headers = build_forward_headers(
                    client_ip,
                    &headers,
                    route_target.site_config.proxy.headers.as_ref().unwrap_or(&DEFAULT_HEADERS_CONFIG),
                    true, // HTTP/3 is always TLS
                );

                let body_to_send = if body_bytes.is_empty() {
                    None
                } else {
                    Some(Bytes::from(body_bytes))
                };

                let upstream_result = send_request_streaming(
                    &self.client,
                    method,
                    &upstream_url,
                    body_to_send,
                    forward_headers,
                    Some(Duration::from_secs(30)),
                ).await;

                match upstream_result {
                    Ok(upstream_resp) => {
                        let (parts, mut upstream_body) = upstream_resp.into_parts();
                        
                        let mut resp_builder = http::Response::builder()
                            .status(parts.status);
                        
                        for (name, value) in parts.headers.iter() {
                            if !crate::proxy::is_hop_by_hop_header_name(name) {
                                resp_builder = resp_builder.header(name, value);
                            }
                        }
                        
                        let response = resp_builder.body(())
                            .map_err(|e| format!("Failed to build response: {}", e))?;

                        request_stream.send_response(response).await?;

                        while let Some(chunk) = upstream_body.frame().await {
                            match chunk {
                                Ok(frame) => {
                                    if let Some(data) = frame.data_ref() {
                                        request_stream.send_data(data.clone()).await?;
                                        
                                        // Record egress bandwidth
                                        let data_len = data.len() as u64;
                                        if let Some(ref bw) = bandwidth {
                                            bw.record_egress(data_len, BandwidthProtocol::Http3, EgressDirection::Proxied);
                                            bw.record_site_egress(&host, data_len);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Error reading upstream body: {}", e);
                                    break;
                                }
                            }
                        }
                        
                        if let Some(ref metrics) = self.metrics {
                            metrics.record_site_upstream_success(&site_id);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Upstream error over HTTP/3: {}", e);
                        if let Some(ref metrics) = self.metrics {
                            metrics.record_site_upstream_failure(&site_id);
                        }
                        
                        let body = Bytes::from("Bad Gateway");
                        let response = http::Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header(header::CONTENT_TYPE, "text/plain")
                            .body(body)
                            .unwrap();
                        
                        let (parts, body) = response.into_parts();
                        request_stream.send_response(http::Response::from_parts(parts, ()))
                            .await?;
                        request_stream.send_data(body).await?;
                    }
                }
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

                let (parts, body) = response.into_parts();
                request_stream
                    .send_response(http::Response::from_parts(parts, ()))
                    .await
                    .map_err(|e| format!("Failed to send response: {}", e))?;
                request_stream.send_data(body).await?;
            }
        }

        request_stream
            .finish()
            .await
            .map_err(|e| format!("Failed to finish stream: {}", e))?;

        histogram!("maluwaf.http3.request.duration").record(start.elapsed());
        counter!("maluwaf.http3.responses").increment(1);

        drop(connection_token);

        Ok(())
    }

    pub fn alt_svc_header(&self) -> String {
        if self.config.enabled {
            format!(
                "h3=\":{}\"; ma={}",
                self.config.port, self.config.alt_svc_max_age
            )
        } else {
            String::new()
        }
    }
}

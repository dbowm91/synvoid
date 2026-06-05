use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use bytes::Bytes;
use http::{header, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use metrics::{counter, gauge, histogram};

use crate::config::site::ProxyHeadersConfig;
use crate::config::{Http3Config, MainConfig};
use crate::http::headers::generate_stealth_timestamp;
use crate::http::response_helpers::apply_security_headers;
use crate::http_client::{
    create_http_client_with_config, send_request_streaming, send_request_streaming_generic,
    ErasedBodyImpl, HttpClient, StreamingWafBody,
};
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
use crate::metrics::WorkerMetrics;
use crate::proxy::client_registry::UpstreamClientRegistry;
#[allow(unused_imports)]
use crate::proxy::{
    apply_response_size_limit, build_forward_headers, filter_response_headers_buf,
    ForwardedProtocol, PreparedUpstreamTarget, WafDecision,
};
use crate::router::{RouteResult, Router};
use crate::waf::attack_detection::StreamingWafDecision;
use crate::waf::{FloodDecision, FloodProtector, RequestSanitizer, WafCore};
use crate::worker::drain_state::WorkerDrainState;

pub struct Http3Server {
    addr: SocketAddr,
    config: Http3Config,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    drain_state: Option<Arc<WorkerDrainState>>,
    metrics: Option<Arc<WorkerMetrics>>,
    shutdown_rx: broadcast::Receiver<()>,
    trusted_proxies: Vec<IpAddr>,
    main_config: Arc<MainConfig>,
}

impl Http3Server {
    pub fn new(
        addr: SocketAddr,
        config: Http3Config,
        router: Router,
        waf: Arc<WafCore>,
        main_config: MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        let client =
            create_http_client_with_config(Duration::from_secs(5), 100, Duration::from_secs(30));

        let trusted_proxies: Vec<IpAddr> = main_config
            .server
            .trusted_proxies
            .iter()
            .filter_map(|p| p.parse().ok())
            .collect();

        Self {
            addr,
            config,
            router: Arc::new(router),
            waf,
            flood_protector: None,
            client,
            upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
            drain_state: None,
            metrics: None,
            shutdown_rx,
            trusted_proxies,
            main_config: Arc::new(main_config),
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

        let std_socket = crate::platform::socket::bind_udp_reuse(self.addr)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| format!("Failed to create QUIC endpoint: {}", e))?;

        tracing::info!("HTTP/3 server listening on {} [SO_REUSEPORT]", self.addr);

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
            counter!("synvoid.http3.connection.errors").increment(1);
            format!("Connection failed: {}", e)
        })?;

        let remote_addr = connection.remote_address();
        let client_ip = remote_addr.ip();

        tracing::debug!("HTTP/3 connection from {}", remote_addr);

        if let Some(ref fp) = self.flood_protector {
            match fp.check_tcp_connection(client_ip) {
                FloodDecision::Blackholed => {
                    counter!("synvoid.http3.flood_blackhole").increment(1);
                    return Ok(());
                }
                FloodDecision::RateLimited => {
                    counter!("synvoid.http3.flood_limited").increment(1);
                    return Ok(());
                }
                FloodDecision::Allowed => {}
            }
        }

        gauge!("synvoid.http3.connections").increment(1.0);
        counter!("synvoid.http3.connections.total").increment(1);

        let server_builder = h3::server::builder();
        let mut h3_conn = server_builder
            .build(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| {
                counter!("synvoid.http3.connection.errors").increment(1);
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
                    counter!("synvoid.http3.connection.errors").increment(1);
                    break;
                }
            }
        }

        gauge!("synvoid.http3.connections").decrement(1.0);
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
                    counter!("synvoid.http3.connection_limited").increment(1);
                    return Ok(());
                }
            }
        } else {
            None
        };

        let (request, mut request_stream) = resolver.resolve_request().await.map_err(|e| {
            counter!("synvoid.http3.request.errors").increment(1);
            histogram!("synvoid.http3.request.duration").record(start.elapsed().as_secs_f64());
            format!("Failed to resolve request: {}", e)
        })?;

        let client_ip = {
            let trusted_proxy_strings: Vec<String> = self
                .trusted_proxies
                .iter()
                .map(|ip| ip.to_string())
                .collect();
            let sanitizer = RequestSanitizer::new(trusted_proxy_strings, true);
            sanitizer
                .get_real_ip(request.headers(), client_ip)
                .unwrap_or(client_ip)
        };

        if self.waf.is_over_bandwidth_limit() {
            tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
            counter!("synvoid.bandwidth.limit_exceeded").increment(1);
            return Ok(());
        }

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

        let route_result = self.router.route(&host, &path);
        // Route-derived policy hint used to avoid duplicate full-body WAF scan when
        // streaming scan is already active for upstream-only proxying.
        let stream_scanned_upstream_mode = match &route_result {
            RouteResult::Found(route_target) => {
                let needs_body_transform = route_target
                    .site_config
                    .r#static
                    .enable_minification
                    .unwrap_or(false)
                    || route_target
                        .site_config
                        .image_poison
                        .enabled
                        .unwrap_or(false)
                    || route_target
                        .site_config
                        .r#static
                        .enable_compression
                        .unwrap_or(false);
                let content_length_u64: Option<u64> = headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok());
                matches!(
                    route_target.backend_type,
                    crate::router::BackendType::Upstream
                ) && route_target.site_config.proxy.should_stream(
                    content_length_u64,
                    route_target.site_config.proxy.streaming_threshold_bytes,
                ) && !needs_body_transform
                    && !crate::http_client::is_quictunnel_url(&route_target.upstream)
            }
            _ => false,
        };

        let mut body_bytes = Vec::new();
        let mut streaming_waf = self.waf.streaming();

        // HTTP/3 uses custom body collection with inline WAF scanning instead of
        // stream_body_with_waf() from shared_handler. This is intentional because:
        // 1. HTTP/3's QUIC-based recv_data() API is fundamentally different from HTTP/1.1's Body collect
        // 2. HTTP/3 has special stream_scanned_upstream_mode that bypasses body collection entirely
        // 3. The streaming WAF integration is tailored to QUIC's chunked delivery model
        // Note: request_body_size tracking differs from HTTP/1.1 (see server.rs:1579 vs 4693)

        if !stream_scanned_upstream_mode {
            while let Ok(Some(chunk)) = request_stream.recv_data().await {
                use bytes::Buf;
                let chunk_len = chunk.remaining();
                if body_bytes.len() + chunk_len > max_request_size {
                    tracing::warn!(client = %client_ip, size = body_bytes.len(), "HTTP/3 request body exceeds max size");
                    counter!("synvoid.http3.request.body_too_large").increment(1);

                    let body = "{\"error\":\"Request body too large\"}";
                    let response = http::Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::DATE, generate_stealth_timestamp(5))
                        .body(Bytes::from(body))
                        .map_err(|e| format!("Failed to build response: {}", e))?;

                    let (parts, body) = response.into_parts();
                    request_stream
                        .send_response(http::Response::from_parts(parts, ()))
                        .await?;
                    request_stream.send_data(body).await?;
                    request_stream.finish().await?;
                    return Ok(());
                }

                let mut chunk_to_scan = chunk;
                let chunk_bytes = chunk_to_scan.copy_to_bytes(chunk_len);

                // 1. Streaming scan
                if let Some(sw) = streaming_waf.as_mut() {
                    if let StreamingWafDecision::Block(status, message) =
                        sw.scan_chunk(&chunk_bytes)
                    {
                        counter!("synvoid.http3.requests.blocked").increment(1);
                        let body = format!("{{\"error\":\"{}\"}}", message);
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
                }

                body_bytes.extend_from_slice(chunk_bytes.as_ref());
            }
        }

        let body_slice: Option<&[u8]> = if body_bytes.is_empty() {
            None
        } else {
            Some(&body_bytes)
        };
        let waf_body_slice: Option<&[u8]> = if stream_scanned_upstream_mode {
            None
        } else {
            body_slice
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

        let (waf_site_id, waf_bot_config) = match &route_result {
            RouteResult::Found(route_target) => (
                Some(route_target.site_id.as_ref()),
                Some(&route_target.site_config.bot),
            ),
            _ => (Some(host.as_str()), None),
        };
        let waf_decision = self
            .waf
            .check_request_full(
                waf_site_id,
                client_ip,
                method_str,
                &path,
                query_string,
                &headers,
                waf_body_slice,
                user_agent.as_deref(),
                None,
                waf_bot_config,
                None,
            )
            .await;

        match waf_decision {
            WafDecision::Stall => {
                counter!("synvoid.http3.requests.stalled").increment(1);
                crate::metrics::record_stall_start();
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        crate::metrics::record_stall_end();
                        tracing::debug!("Stall timeout reached, dropping connection");
                    }
                }
            }
            WafDecision::Block(status, message) => {
                counter!("synvoid.http3.requests.blocked").increment(1);
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
            WafDecision::Challenge(_type, html) => {
                counter!("synvoid.http3.requests.challenged").increment(1);
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
                challenge_type: _,
                html,
                session_cookie_name,
                session_cookie_value,
                session_cookie_max_age,
            } => {
                counter!("synvoid.http3.requests.challenged").increment(1);
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
                    "{}={}; path=/; max-age={}; Secure; SameSite=Strict; HttpOnly",
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
                counter!("synvoid.http3.requests.tarpitted").increment(1);
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
                counter!("synvoid.http3.blackhole_drop").increment(1);
                return Ok(());
            }
            WafDecision::Pass => {}
        }

        if stream_scanned_upstream_mode {
            if let RouteResult::Found(route_target) = &route_result {
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
                                counter!("synvoid.http3.connection_limited").increment(1);
                                request_stream.finish().await?;
                                return Ok(());
                            }
                        }
                    }
                }

                counter!("synvoid.http3.request.streaming_path").increment(1);

                let upstream_target = PreparedUpstreamTarget::new(
                    &route_target.upstream,
                    &path,
                    Some(&route_target.site_config.proxy),
                );

                static DEFAULT_HEADERS_CONFIG: ProxyHeadersConfig = ProxyHeadersConfig {
                    clear: Vec::new(),
                    set: Vec::new(),
                    forward: Vec::new(),
                    hide: Vec::new(),
                };

                let forward_headers = build_forward_headers(
                    client_ip,
                    &headers,
                    route_target
                        .site_config
                        .proxy
                        .headers
                        .as_ref()
                        .unwrap_or(&DEFAULT_HEADERS_CONFIG),
                    ForwardedProtocol::Https,
                );
                let tls_config = route_target
                    .site_config
                    .proxy
                    .upstream
                    .as_ref()
                    .and_then(|u| u.tls.as_ref())
                    .and_then(crate::http_client::upstream_tls_from_site_config);
                let streaming_client = self
                    .upstream_client_registry
                    .get_or_create_streaming(&route_target.site_id, tls_config.as_ref());

                let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
                let streaming_body = H3ChannelBody::new(rx);
                // INTEGRATION: Use the unified StreamingWafBody for H3 as well.
                // This eliminates the manual scan loop below and consolidates logic.
                let streaming_waf = self.waf.streaming();
                let waf_body = StreamingWafBody::new(streaming_body, streaming_waf, client_ip);
                let erased_body = ErasedBodyImpl::new(waf_body);

                let upstream_task = tokio::spawn({
                    let streaming_client = streaming_client.clone();
                    let method = method.clone();
                    let url = upstream_target.url.clone();
                    async move {
                        send_request_streaming_generic(
                            streaming_client.as_ref(),
                            method,
                            &url,
                            erased_body,
                            forward_headers,
                            Some(upstream_target.timeout),
                        )
                        .await
                    }
                });

                let mut streamed_body_len: usize = 0;
                while let Ok(Some(mut chunk)) = request_stream.recv_data().await {
                    use bytes::Buf;
                    let chunk_len = chunk.remaining();
                    if streamed_body_len + chunk_len > max_request_size {
                        let body = "{\"error\":\"Request body too large\"}";
                        let response = http::Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
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
                        upstream_task.abort();
                        return Ok(());
                    }

                    let chunk_bytes = chunk.copy_to_bytes(chunk_len);

                    streamed_body_len += chunk_bytes.len();
                    if tx.send(Ok(chunk_bytes)).await.is_err() {
                        // If tx is closed, it means the upstream task failed (likely blocked by WAF)
                        break;
                    }
                }
                drop(tx);
                if streamed_body_len > 0 {
                    if let Some(ref bw) = bandwidth {
                        bw.record_ingress(streamed_body_len as u64, BandwidthProtocol::Http3);
                        bw.record_site_ingress(&host, streamed_body_len as u64);
                    }
                }

                let upstream_result = match upstream_task.await {
                    Ok(result) => result,
                    Err(e) => Err(anyhow::anyhow!("upstream task join error: {}", e)),
                };

                match upstream_result {
                    Ok(upstream_resp) => {
                        let (parts, mut upstream_body) = upstream_resp.into_parts();
                        let body_len = parts
                            .headers
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);

                        if upstream_target
                            .max_response_size
                            .map(|max| body_len > 0 && body_len as usize > max)
                            .unwrap_or(false)
                        {
                            let body = Bytes::from("Bad Gateway");
                            let response = http::Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .header(header::CONTENT_TYPE, "text/plain")
                                .body(())
                                .map_err(|e| format!("Failed to build response: {}", e))?;
                            request_stream.send_response(response).await?;
                            request_stream.send_data(body).await?;
                        } else {
                            let mut resp_builder = http::Response::builder().status(parts.status);
                            let headers_to_filter = crate::proxy::build_headers_to_filter_for_site(
                                &self.main_config.security.more_clear_headers,
                                &route_target.site_config.security.more_clear_headers,
                                &route_target.site_config.security_headers.more_clear_headers,
                            );
                            let filtered_headers =
                                filter_response_headers_buf(&parts.headers, &headers_to_filter);
                            for (name, value) in filtered_headers.iter() {
                                if let Ok(v) = value.to_str() {
                                    resp_builder = resp_builder.header(name.as_str(), v);
                                }
                            }
                            resp_builder = apply_security_headers(
                                resp_builder,
                                route_target,
                                &self.main_config,
                            );
                            let response = resp_builder
                                .body(())
                                .map_err(|e| format!("Failed to build response: {}", e))?;
                            request_stream.send_response(response).await?;

                            while let Some(chunk) = upstream_body.frame().await {
                                match chunk {
                                    Ok(frame) => {
                                        if let Some(data) = frame.data_ref() {
                                            request_stream.send_data(data.clone()).await?;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Error reading upstream body: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                            if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                                counter!("synvoid.http3.requests.blocked").increment(1);
                                let body =
                                    "{\"error\":\"Request blocked by WAF during streaming\"}";
                                let response = http::Response::builder()
                                    .status(StatusCode::FORBIDDEN)
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .header(header::DATE, generate_stealth_timestamp(5))
                                    .body(Bytes::from(body))
                                    .unwrap();
                                let (parts, body) = response.into_parts();
                                request_stream
                                    .send_response(http::Response::from_parts(parts, ()))
                                    .await?;
                                request_stream.send_data(body).await?;
                                request_stream.finish().await?;
                                return Ok(());
                            }
                        }
                        tracing::error!("Upstream error over HTTP/3 streaming: {}", e);
                        let body = Bytes::from("Bad Gateway");
                        let response = http::Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header(header::CONTENT_TYPE, "text/plain")
                            .body(body)
                            .unwrap();
                        let (parts, body) = response.into_parts();
                        request_stream
                            .send_response(http::Response::from_parts(parts, ()))
                            .await?;
                        request_stream.send_data(body).await?;
                    }
                }

                request_stream
                    .finish()
                    .await
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
                histogram!("synvoid.http3.request.duration").record(start.elapsed());
                counter!("synvoid.http3.responses").increment(1);
                drop(connection_token);
                return Ok(());
            }
        }

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
                                counter!("synvoid.http3.connection_limited").increment(1);
                                request_stream.finish().await?;
                                return Ok(());
                            }
                        }
                    }
                }

                // Actual proxying logic
                let upstream_target = PreparedUpstreamTarget::new(
                    &route_target.upstream,
                    &path,
                    Some(&route_target.site_config.proxy),
                );

                static DEFAULT_HEADERS_CONFIG: ProxyHeadersConfig = ProxyHeadersConfig {
                    clear: Vec::new(),
                    set: Vec::new(),
                    forward: Vec::new(),
                    hide: Vec::new(),
                };

                let forward_headers = build_forward_headers(
                    client_ip,
                    &headers,
                    route_target
                        .site_config
                        .proxy
                        .headers
                        .as_ref()
                        .unwrap_or(&DEFAULT_HEADERS_CONFIG),
                    ForwardedProtocol::Https, // HTTP/3 is always TLS
                );

                let body_to_send = if body_bytes.is_empty() {
                    Full::new(Bytes::new())
                } else {
                    Full::new(Bytes::from(body_bytes))
                };

                let upstream_result = send_request_streaming(
                    &self.client,
                    method,
                    &upstream_target.url,
                    body_to_send,
                    forward_headers,
                    Some(upstream_target.timeout),
                )
                .await;

                match upstream_result {
                    Ok(upstream_resp) => {
                        let (parts, mut upstream_body) = upstream_resp.into_parts();

                        let body_len = parts
                            .headers
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);

                        let size_exceeded = upstream_target
                            .max_response_size
                            .map(|max| body_len > 0 && body_len as usize > max)
                            .unwrap_or(false);

                        if size_exceeded {
                            let body = Bytes::from("Bad Gateway");
                            let response = http::Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .header(header::CONTENT_TYPE, "text/plain")
                                .body(())
                                .map_err(|e| format!("Failed to build response: {}", e))?;
                            request_stream.send_response(response).await?;
                            request_stream.send_data(body).await?;
                            if let Some(ref metrics) = self.metrics {
                                metrics.record_site_upstream_failure(&site_id);
                            }
                        } else {
                            let mut resp_builder = http::Response::builder().status(parts.status);

                            let headers_to_filter = crate::proxy::build_headers_to_filter_for_site(
                                &self.main_config.security.more_clear_headers,
                                &route_target.site_config.security.more_clear_headers,
                                &route_target.site_config.security_headers.more_clear_headers,
                            );

                            let filtered_headers =
                                filter_response_headers_buf(&parts.headers, &headers_to_filter);

                            for (name, value) in filtered_headers.iter() {
                                if let Ok(v) = value.to_str() {
                                    resp_builder = resp_builder.header(name.as_str(), v);
                                }
                            }

                            resp_builder = apply_security_headers(
                                resp_builder,
                                &route_target,
                                &self.main_config,
                            );

                            let response = resp_builder
                                .body(())
                                .map_err(|e| format!("Failed to build response: {}", e))?;

                            request_stream.send_response(response).await?;

                            while let Some(chunk) = upstream_body.frame().await {
                                match chunk {
                                    Ok(frame) => {
                                        if let Some(data) = frame.data_ref() {
                                            request_stream.send_data(data.clone()).await?;

                                            let data_len = data.len() as u64;
                                            if let Some(ref bw) = bandwidth {
                                                bw.record_egress(
                                                    data_len,
                                                    BandwidthProtocol::Http3,
                                                    EgressDirection::Proxied,
                                                );
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
                        request_stream
                            .send_response(http::Response::from_parts(parts, ()))
                            .await?;
                        request_stream.send_data(body).await?;
                    }
                }
            }
            RouteResult::NotFound(e) | RouteResult::Error(e) => {
                tracing::debug!("Route not found: {} for host: {}", e, host);
                counter!("synvoid.http3.requests.not_found").increment(1);
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

        histogram!("synvoid.http3.request.duration").record(start.elapsed());
        counter!("synvoid.http3.responses").increment(1);

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

struct H3ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl H3ChannelBody {
    fn new(rx: mpsc::Receiver<Result<Bytes, std::io::Error>>) -> Self {
        Self { rx }
    }
}

impl hyper::body::Body for H3ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

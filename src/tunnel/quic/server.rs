#![allow(unused_variables, dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use metrics::{counter, gauge, histogram};
use quinn::{Connection, RecvStream, SendStream};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, Semaphore};

use crate::buffer::BufferPool;
use crate::config::{PortMappingConfig, TunnelQuicConfig, TunnelQuicPeerConfig, VpnAccessLevel};
use crate::tunnel::quic::framing::{read_message, write_message};
use crate::tunnel::quic::health::QuicHealthMonitor;
use crate::tunnel::quic::messages::{
    DatagramCapabilities, DatagramMessage, PortMapping, TunnelMessage,
};
use crate::tunnel::quic::registry::{TunnelSessionInfo, QUIC_TUNNEL_REGISTRY};
use crate::tunnel::quic::runtime::{IncomingConnection, QuicConnection, QuicRuntime};
use crate::tunnel::quic::tls::QuicTlsConfig;
use crate::tunnel::quic::validation::{
    validate_client_id, validate_identifier, validate_peer_id, validate_port,
};

const DEFAULT_AUTH_WINDOW_SECS: u64 = 60;

struct AuthRateLimiter {
    attempts: DashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl AuthRateLimiter {
    fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: DashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }

    fn check_and_record(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut entry = self.attempts.entry(key.to_string()).or_default();
        entry.retain(|&t| now.duration_since(t) < self.window);
        if entry.len() >= self.max_attempts {
            return false;
        }
        entry.push(now);
        true
    }

    fn cleanup(&self) {
        let now = Instant::now();
        self.attempts.retain(|_, v| {
            v.retain(|&t| now.duration_since(t) < self.window);
            !v.is_empty()
        });
    }
}

pub struct QuicTunnelServer {
    config: TunnelQuicConfig,
    tls_config: QuicTlsConfig,
    runtime: Arc<QuicRuntime>,
    sessions: Arc<DashMap<String, QuicTunnelSession>>,
    shutdown_tx: broadcast::Sender<()>,
    proxy_sender: mpsc::Sender<TunnelProxyRequest>,
    connection_rx: Option<mpsc::Receiver<IncomingConnection>>,
    connection_limit: Arc<Semaphore>,
    health_monitor: Option<Arc<QuicHealthMonitor>>,
    auth_rate_limiter: Arc<AuthRateLimiter>,
}

#[derive(Clone)]
pub struct QuicTunnelSession {
    pub id: String,
    pub client_id: String,
    pub remote_addr: String,
    pub connected_at: std::time::Instant,
    pub mappings: HashMap<String, PortMappingConfig>,
    pub connection: Connection,
    pub active_streams: Arc<AtomicU32>,
    pub datagram_capabilities: DatagramCapabilities,
    pub access_level: VpnAccessLevel,
    pub allowed_ports_tcp: Vec<u16>,
    pub allowed_ports_udp: Vec<u16>,
    pub default_upstream_host: Option<String>,
    pub default_upstream_port: Option<u16>,
}

impl QuicTunnelSession {
    pub fn can_access_port(&self, port: u16, protocol: &str) -> bool {
        match self.access_level {
            VpnAccessLevel::Admin => true,
            VpnAccessLevel::General => {
                let allowed = if protocol.eq_ignore_ascii_case("udp") {
                    &self.allowed_ports_udp
                } else {
                    &self.allowed_ports_tcp
                };
                allowed.contains(&port)
            }
        }
    }
}

struct AuthResult {
    access_level: VpnAccessLevel,
    allowed_ports_tcp: Vec<u16>,
    allowed_ports_udp: Vec<u16>,
}

pub struct TunnelProxyRequest {
    pub session_id: String,
    pub identifier: String,
    pub port: u16,
    pub data: Vec<u8>,
    pub response_tx: mpsc::Sender<Result<Vec<u8>, String>>,
}

impl QuicTunnelServer {
    pub fn new(
        config: TunnelQuicConfig,
        runtime: Arc<QuicRuntime>,
        proxy_sender: mpsc::Sender<TunnelProxyRequest>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let tls_config = QuicTlsConfig::from_config(&config);
        let max_connections = config.server.max_connections.max(1);
        let connection_limit = Arc::new(Semaphore::new(max_connections));
        let health_monitor = runtime.health_monitor().cloned();

        let max_auth_attempts = config.server.auth_rate_limit_max_attempts.max(1);
        let auth_window_secs = config.server.auth_rate_limit_window_secs.max(10);

        tracing::info!(
            "Auth rate limiting configured: {} attempts per {} seconds",
            max_auth_attempts,
            auth_window_secs
        );

        let auth_rate_limiter = Arc::new(AuthRateLimiter::new(max_auth_attempts, auth_window_secs));

        Self {
            config,
            tls_config,
            runtime,
            sessions: Arc::new(DashMap::new()),
            shutdown_tx,
            proxy_sender,
            connection_rx: None,
            connection_limit,
            health_monitor,
            auth_rate_limiter,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.server.enabled {
            tracing::info!("QUIC tunnel server disabled");
            return Ok(());
        }

        tracing::info!(
            "Starting QUIC tunnel server on {}",
            self.runtime.bind_address()
        );

        let connection_rx = self.runtime.start_server().await?;
        self.connection_rx = Some(connection_rx);

        gauge!("synvoid.tunnel.quic.server.enabled").set(1.0);

        Ok(())
    }

    pub async fn run(&mut self) {
        if !self.config.server.enabled {
            return;
        }

        tracing::info!("QUIC tunnel server running");

        let connection_rx = match self.connection_rx.take() {
            Some(rx) => rx,
            None => {
                tracing::error!("QUIC server not started - call start() first");
                return;
            }
        };

        let sessions = self.sessions.clone();
        let config = self.config.clone();
        let connection_limit = self.connection_limit.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        let runtime = self.runtime.clone();
        let auth_rate_limiter = self.auth_rate_limiter.clone();

        tokio::spawn(async move {
            Self::connection_loop(
                connection_rx,
                sessions,
                config,
                shutdown_rx,
                connection_limit,
                runtime,
                auth_rate_limiter,
            )
            .await;
        });

        let mut rx = self.shutdown_tx.subscribe();
        rx.recv().await.ok();
    }

    async fn connection_loop(
        mut connection_rx: mpsc::Receiver<IncomingConnection>,
        sessions: Arc<DashMap<String, QuicTunnelSession>>,
        config: TunnelQuicConfig,
        mut shutdown_rx: broadcast::Receiver<()>,
        connection_limit: Arc<Semaphore>,
        runtime: Arc<QuicRuntime>,
        auth_rate_limiter: Arc<AuthRateLimiter>,
    ) {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                incoming = connection_rx.recv() => {
                    match incoming {
                        Some(incoming) => {
                            let permit = match connection_limit.clone().acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!("Connection limit semaphore closed, rejecting new connection");
                                    counter!("synvoid.tunnel.quic.server.rejected").increment(1);
                                    continue;
                                }
                            };

                            let sessions = sessions.clone();
                            let config = config.clone();
                            let remote_addr = incoming.remote_addr.to_string();
                            let runtime = runtime.clone();
                            let auth_rate_limiter = auth_rate_limiter.clone();
                            tokio::spawn(async move {
                                let result = Self::handle_connection(incoming, sessions, config, runtime, auth_rate_limiter).await;
                                drop(permit);
                                if let Err(e) = result {
                                    tracing::error!("QUIC connection handler error from {}: {}", remote_addr, e);
                                }
                            });
                        }
                        None => {
                            tracing::info!("QUIC connection receiver closed");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("QUIC server connection loop shutting down");
                    break;
                }
                _ = cleanup_interval.tick() => {
                    auth_rate_limiter.cleanup();
                }
            }
        }
    }

    async fn handle_connection(
        incoming: IncomingConnection,
        sessions: Arc<DashMap<String, QuicTunnelSession>>,
        config: TunnelQuicConfig,
        runtime: Arc<QuicRuntime>,
        auth_rate_limiter: Arc<AuthRateLimiter>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let remote_addr = incoming.remote_addr;
        let connection = incoming.connection;
        let max_message_size = config.max_message_size;
        let datagram_enabled = true;
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1200);
        const AUTH_TIMEOUT_SECS: u64 = 10;

        tracing::info!("New QUIC connection from {}", remote_addr);

        let (mut send_stream, mut recv_stream) = tokio::time::timeout(
            std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
            connection.accept_bi(),
        )
        .await
        .map_err(|_| "Timeout waiting for initial stream".to_string())?
        .map_err(|e| format!("Failed to accept stream: {}", e))?;

        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
            read_message(&mut recv_stream, max_message_size),
        )
        .await
        .map_err(|_| "Timeout waiting for authentication message".to_string())?
        .map_err(|e| format!("Failed to read auth message: {}", e))?;

        match msg {
            TunnelMessage::Hello {
                client_id,
                auth_token,
                mappings,
                ..
            } => {
                if let Err(e) = validate_client_id(&client_id) {
                    counter!("synvoid.tunnel.quic.server.validation_errors").increment(1);
                    let error = TunnelMessage::AuthFailure {
                        reason: format!("Invalid client_id: {}", e.reason),
                    };
                    write_message(&mut send_stream, &error).await?;
                    tracing::warn!("Invalid client_id from {}: {}", remote_addr, e);
                    return Ok(());
                }

                for identifier in mappings.keys() {
                    if let Err(e) = validate_identifier(identifier) {
                        counter!("synvoid.tunnel.quic.server.validation_errors").increment(1);
                        let error = TunnelMessage::AuthFailure {
                            reason: format!("Invalid mapping identifier: {}", e.reason),
                        };
                        write_message(&mut send_stream, &error).await?;
                        tracing::warn!("Invalid mapping identifier from {}: {}", remote_addr, e);
                        return Ok(());
                    }
                }

                for mapping in mappings.values() {
                    if let Err(e) = validate_port(mapping.port) {
                        counter!("synvoid.tunnel.quic.server.validation_errors").increment(1);
                        let error = TunnelMessage::AuthFailure {
                            reason: format!("Invalid port in mapping: {}", e.reason),
                        };
                        write_message(&mut send_stream, &error).await?;
                        tracing::warn!("Invalid port from {}: {}", remote_addr, e);
                        return Ok(());
                    }
                }

                if !auth_rate_limiter.check_and_record(&client_id) {
                    counter!("synvoid.tunnel.quic.server.auth_rate_limited").increment(1);
                    let error = TunnelMessage::AuthFailure {
                        reason: "Too many authentication attempts. Please try again later."
                            .to_string(),
                    };
                    write_message(&mut send_stream, &error).await?;
                    tracing::warn!("Authentication rate limited for client: {}", client_id);
                    return Ok(());
                }

                let auth_result = match Self::authenticate_client(&client_id, &auth_token, &config)
                {
                    Some(result) => result,
                    None => {
                        let error = TunnelMessage::AuthFailure {
                            reason: "Invalid credentials".to_string(),
                        };
                        write_message(&mut send_stream, &error).await?;
                        counter!("synvoid.tunnel.quic.server.auth_failures").increment(1);
                        return Ok(());
                    }
                };

                let session_id = uuid::Uuid::new_v4().to_string();
                let datagram_caps = DatagramCapabilities::new(datagram_enabled, max_datagram_size);

                let session = QuicTunnelSession {
                    id: session_id.clone(),
                    client_id: client_id.clone(),
                    remote_addr: remote_addr.to_string(),
                    connected_at: std::time::Instant::now(),
                    mappings: Self::convert_mappings(&mappings),
                    connection: connection.clone(),
                    active_streams: Arc::new(AtomicU32::new(0)),
                    datagram_capabilities: datagram_caps,
                    access_level: auth_result.access_level,
                    allowed_ports_tcp: auth_result.allowed_ports_tcp,
                    allowed_ports_udp: auth_result.allowed_ports_udp,
                    default_upstream_host: None,
                    default_upstream_port: None,
                };

                sessions.insert(session_id.clone(), session.clone());

                let registry_mappings: HashMap<String, u16> = session
                    .mappings
                    .iter()
                    .map(|(k, v)| (k.clone(), v.port))
                    .collect();
                QUIC_TUNNEL_REGISTRY
                    .register(TunnelSessionInfo {
                        session_id: session_id.clone(),
                        client_id: client_id.clone(),
                        peer_id: None,
                        remote_addr: remote_addr.to_string(),
                        mappings: registry_mappings.clone(),
                    })
                    .await;

                runtime
                    .add_session(QuicConnection {
                        remote_addr,
                        peer_id: None,
                        session_id: session_id.clone(),
                        client_id: client_id.clone(),
                        mappings: registry_mappings,
                        connection: Some(connection.clone()),
                        datagram_capabilities: datagram_caps,
                    })
                    .await;

                let ack = TunnelMessage::HelloAck {
                    server_session_id: session_id.clone(),
                    server_mappings: HashMap::new(),
                    supports_datagrams: datagram_enabled,
                    max_datagram_size,
                    access_level: Some(session.access_level.as_str().to_string()),
                };
                write_message(&mut send_stream, &ack).await?;
                let _ = send_stream.finish();

                counter!("synvoid.tunnel.quic.server.sessions").increment(1);
                gauge!("synvoid.tunnel.quic.server.active_sessions").increment(1.0);

                tracing::info!(
                    "QUIC session established: {} for client {} (access: {:?}, datagrams: {})",
                    session_id,
                    client_id,
                    session.access_level,
                    datagram_caps.supported
                );

                Self::session_loop(connection, session, sessions, max_message_size, runtime)
                    .await?;
            }
            TunnelMessage::PeerHello {
                peer_id,
                auth_token,
                ..
            } => {
                if let Err(e) = validate_peer_id(&peer_id) {
                    counter!("synvoid.tunnel.quic.server.validation_errors").increment(1);
                    let error = TunnelMessage::AuthFailure {
                        reason: format!("Invalid peer_id: {}", e.reason),
                    };
                    write_message(&mut send_stream, &error).await?;
                    tracing::warn!("Invalid peer_id from {}: {}", remote_addr, e);
                    return Ok(());
                }

                if !auth_rate_limiter.check_and_record(&peer_id) {
                    counter!("synvoid.tunnel.quic.server.peer_auth_rate_limited").increment(1);
                    let error = TunnelMessage::AuthFailure {
                        reason: "Too many authentication attempts. Please try again later."
                            .to_string(),
                    };
                    write_message(&mut send_stream, &error).await?;
                    tracing::warn!("Peer authentication rate limited for: {}", peer_id);
                    return Ok(());
                }

                let peer_config = match Self::authenticate_peer(&peer_id, &auth_token, &config) {
                    Some(config) => config,
                    None => {
                        let error = TunnelMessage::AuthFailure {
                            reason: "Invalid peer credentials".to_string(),
                        };
                        write_message(&mut send_stream, &error).await?;
                        counter!("synvoid.tunnel.quic.server.peer_auth_failures").increment(1);
                        return Ok(());
                    }
                };

                let session_id = uuid::Uuid::new_v4().to_string();
                let datagram_caps = DatagramCapabilities::new(datagram_enabled, max_datagram_size);

                let session = QuicTunnelSession {
                    id: session_id.clone(),
                    client_id: peer_id.clone(),
                    remote_addr: remote_addr.to_string(),
                    connected_at: std::time::Instant::now(),
                    mappings: HashMap::new(),
                    connection: connection.clone(),
                    active_streams: Arc::new(AtomicU32::new(0)),
                    datagram_capabilities: datagram_caps,
                    access_level: VpnAccessLevel::Admin,
                    allowed_ports_tcp: vec![],
                    allowed_ports_udp: vec![],
                    default_upstream_host: peer_config.upstream_host.clone(),
                    default_upstream_port: peer_config.upstream_port,
                };

                sessions.insert(session_id.clone(), session.clone());

                QUIC_TUNNEL_REGISTRY
                    .register(TunnelSessionInfo {
                        session_id: session_id.clone(),
                        client_id: peer_id.clone(),
                        peer_id: Some(peer_id.clone()),
                        remote_addr: remote_addr.to_string(),
                        mappings: HashMap::new(),
                    })
                    .await;

                runtime
                    .add_session(QuicConnection {
                        remote_addr,
                        peer_id: Some(peer_id.clone()),
                        session_id: session_id.clone(),
                        client_id: peer_id.clone(),
                        mappings: HashMap::new(),
                        connection: Some(connection.clone()),
                        datagram_capabilities: datagram_caps,
                    })
                    .await;

                let ack = TunnelMessage::PeerHelloAck {
                    session_id: session_id.clone(),
                    supports_datagrams: datagram_enabled,
                    max_datagram_size,
                };
                write_message(&mut send_stream, &ack).await?;
                let _ = send_stream.finish();

                counter!("synvoid.tunnel.quic.server.peer_sessions").increment(1);

                tracing::info!(
                    "QUIC peer session established: {} for peer {} (datagrams: {})",
                    session_id,
                    peer_id,
                    datagram_caps.supported
                );

                Self::session_loop(connection, session, sessions, max_message_size, runtime)
                    .await?;
            }
            _ => {
                tracing::warn!("Unexpected initial message from {}", remote_addr);
            }
        }

        Ok(())
    }

    async fn session_loop(
        connection: Connection,
        session: QuicTunnelSession,
        sessions: Arc<DashMap<String, QuicTunnelSession>>,
        max_message_size: usize,
        runtime: Arc<QuicRuntime>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_id = session.id.clone();

        let result = Self::session_loop_inner(
            connection,
            session.clone(),
            sessions.clone(),
            max_message_size,
        )
        .await;

        sessions.remove(&session_id);
        QUIC_TUNNEL_REGISTRY.unregister(&session_id).await;
        runtime.remove_session(&session_id).await;

        gauge!("synvoid.tunnel.quic.server.active_sessions").decrement(1.0);
        tracing::info!("Session {} ended", session_id);

        result
    }

    async fn session_loop_inner(
        connection: Connection,
        session: QuicTunnelSession,
        _sessions: Arc<DashMap<String, QuicTunnelSession>>,
        max_message_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            tokio::select! {
                stream_result = connection.accept_bi() => {
                    match stream_result {
                        Ok((send_stream, recv_stream)) => {
                            let session = session.clone();
                            session.active_streams.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let start = std::time::Instant::now();
                                if let Err(e) = Self::handle_stream(send_stream, recv_stream, session.clone(), max_message_size).await {
                                    tracing::debug!("Stream error: {}", e);
                                }
                                session.active_streams.fetch_sub(1, Ordering::Relaxed);
                                histogram!("synvoid.tunnel.quic.server.stream_duration").record(start.elapsed());
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                            tracing::info!("Session {} closed by client", session.id);
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Session {} connection error: {}", session.id, e);
                            break;
                        }
                    }
                }
                _ = connection.closed() => {
                    tracing::info!("Session {} connection closed", session.id);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_stream(
        send_stream: SendStream,
        recv_stream: RecvStream,
        session: QuicTunnelSession,
        max_message_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut send_stream = send_stream;
        let mut recv_stream = recv_stream;

        let msg = read_message(&mut recv_stream, max_message_size).await?;

        match msg {
            TunnelMessage::KeepAlive => {
                write_message(&mut send_stream, &TunnelMessage::KeepAliveAck).await?;
                send_stream
                    .finish()
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::StreamOpen {
                identifier,
                port,
                protocol,
                tls_passthrough,
            } => {
                tracing::debug!(
                    "Stream open request for {} ({}:{}) in session {} (tls_passthrough={})",
                    identifier,
                    protocol,
                    port,
                    session.id,
                    tls_passthrough
                );

                let upstream_host = session
                    .mappings
                    .get(&identifier)
                    .and_then(|m| m.upstream_host.clone())
                    .or_else(|| session.default_upstream_host.clone())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let upstream_port = session
                    .mappings
                    .get(&identifier)
                    .and_then(|m| m.upstream_port)
                    .or(session.default_upstream_port)
                    .unwrap_or(port);

                if !session.can_access_port(port, &protocol)
                    || !session.can_access_port(upstream_port, &protocol)
                {
                    tracing::warn!(
                        "Port access denied for session {} (client: {}, access: {:?}): requested={}, upstream={}",
                        session.id, session.client_id, session.access_level, port, upstream_port
                    );
                    counter!("synvoid.tunnel.quic.server.access_denied", 
                        "type" => "stream", "client" => session.client_id.clone())
                    .increment(1);

                    let denied_port = if !session.can_access_port(port, &protocol) {
                        port
                    } else {
                        upstream_port
                    };
                    let ack = TunnelMessage::StreamOpenAck {
                        identifier: identifier.clone(),
                        success: false,
                        message: Some(format!(
                            "Port {} not allowed for your access level",
                            denied_port
                        )),
                    };
                    write_message(&mut send_stream, &ack).await?;
                    send_stream
                        .finish()
                        .map_err(|e| format!("Failed to finish stream: {}", e))?;
                    return Ok(());
                }

                let upstream_addr = format!("{}:{}", upstream_host, upstream_port);

                let tcp_result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    TcpStream::connect(&upstream_addr),
                )
                .await;

                match tcp_result {
                    Ok(Ok(upstream_tcp)) => {
                        counter!("synvoid.tunnel.quic.server.streams.opened").increment(1);

                        let ack = TunnelMessage::StreamOpenAck {
                            identifier: identifier.clone(),
                            success: true,
                            message: None,
                        };
                        write_message(&mut send_stream, &ack).await?;

                        Self::proxy_bidirectional(
                            send_stream,
                            recv_stream,
                            upstream_tcp,
                            identifier,
                            max_message_size,
                        )
                        .await?;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "Failed to connect to upstream {} for {}: {}",
                            upstream_addr,
                            identifier,
                            e
                        );
                        counter!("synvoid.tunnel.quic.server.streams.upstream_failed").increment(1);

                        let ack = TunnelMessage::StreamOpenAck {
                            identifier: identifier.clone(),
                            success: false,
                            message: Some(format!("Upstream connection failed: {}", e)),
                        };
                        write_message(&mut send_stream, &ack).await?;
                        send_stream
                            .finish()
                            .map_err(|e| format!("Failed to finish stream: {}", e))?;
                    }
                    Err(_) => {
                        tracing::warn!(
                            "Timeout connecting to upstream {} for {}",
                            upstream_addr,
                            identifier
                        );
                        counter!("synvoid.tunnel.quic.server.streams.upstream_timeout")
                            .increment(1);

                        let ack = TunnelMessage::StreamOpenAck {
                            identifier: identifier.clone(),
                            success: false,
                            message: Some("Upstream connection timeout".to_string()),
                        };
                        write_message(&mut send_stream, &ack).await?;
                        send_stream
                            .finish()
                            .map_err(|e| format!("Failed to finish stream: {}", e))?;
                    }
                }
            }
            TunnelMessage::UdpTunnelOpen { identifier, port } => {
                tracing::debug!(
                    "UDP tunnel open request for {}:{} in session {}",
                    identifier,
                    port,
                    session.id
                );

                if !session.can_access_port(port, "udp") {
                    tracing::warn!(
                        "UDP port access denied for session {} (client: {}, access: {:?}): port={}",
                        session.id,
                        session.client_id,
                        session.access_level,
                        port
                    );
                    counter!("synvoid.tunnel.quic.server.access_denied", 
                        "type" => "udp", "client" => session.client_id.clone())
                    .increment(1);

                    let ack = TunnelMessage::UdpTunnelOpenAck {
                        identifier: identifier.clone(),
                        success: false,
                        message: Some(format!(
                            "UDP port {} not allowed for your access level",
                            port
                        )),
                    };
                    write_message(&mut send_stream, &ack).await?;
                    send_stream.finish()?;
                    return Ok(());
                }

                if !session.datagram_capabilities.supported {
                    let ack = TunnelMessage::UdpTunnelOpenAck {
                        identifier: identifier.clone(),
                        success: false,
                        message: Some("Datagrams not supported".to_string()),
                    };
                    write_message(&mut send_stream, &ack).await?;
                    send_stream.finish()?;
                    return Ok(());
                }

                counter!("synvoid.tunnel.quic.server.udp_tunnels.opened").increment(1);

                let ack = TunnelMessage::UdpTunnelOpenAck {
                    identifier: identifier.clone(),
                    success: true,
                    message: Some(format!("UDP tunnel opened for port {}", port)),
                };
                write_message(&mut send_stream, &ack).await?;

                let connection = session.connection.clone();
                Self::handle_udp_tunnel(connection, session, identifier, port, max_message_size)
                    .await?;
            }
            TunnelMessage::PortOpen {
                identifier,
                port,
                protocol,
            } => {
                tracing::debug!(
                    "Port open request for {} ({}:{}) in session {}",
                    identifier,
                    protocol,
                    port,
                    session.id
                );
                let ack = TunnelMessage::PortOpen {
                    identifier: identifier.clone(),
                    port,
                    protocol,
                };
                write_message(&mut send_stream, &ack).await?;
                send_stream
                    .finish()
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::StreamClose { identifier } => {
                tracing::debug!(
                    "Stream close request for {} in session {}",
                    identifier,
                    session.id
                );
                send_stream
                    .finish()
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::PortClose { identifier } => {
                tracing::debug!(
                    "Port close request for {} in session {}",
                    identifier,
                    session.id
                );
                send_stream
                    .finish()
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::PortData { identifier } => {
                tracing::trace!("Port data for {} in session {}", identifier, session.id);
                send_stream
                    .finish()
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            _ => {
                tracing::debug!("Unexpected stream message in session {}", session.id);
                send_stream
                    .finish()
                    .map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
        }

        Ok(())
    }

    async fn handle_udp_tunnel(
        connection: Connection,
        session: QuicTunnelSession,
        identifier: String,
        port: u16,
        _max_message_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = "0.0.0.0:0";
        let udp_socket = Arc::new(tokio::net::UdpSocket::bind(bind_addr).await?);
        let local_addr = udp_socket.local_addr()?;

        tracing::info!(
            "UDP tunnel {} bound to {}, forwarding to remote via QUIC (port {})",
            identifier,
            local_addr,
            port
        );

        let max_size = session.datagram_capabilities.max_size;

        const MAX_CLIENT_MAPPINGS: usize = 10000;
        const MAX_DNS_IDS: usize = 1000;
        const MAX_PENDING_DATAGRAMS: usize = 100;
        const CLIENT_TTL_SECS: u64 = 300;

        let client_map: Arc<DashMap<u64, SocketAddr>> = Arc::new(DashMap::new());
        let dns_id_map: Arc<DashMap<u16, SocketAddr>> = Arc::new(DashMap::new());
        let client_timestamps: Arc<DashMap<SocketAddr, std::time::Instant>> =
            Arc::new(DashMap::new());
        let datagram_semaphore: Arc<tokio::sync::Semaphore> =
            Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_DATAGRAMS));

        let connection_for_quic_send = connection.clone();
        let connection_for_quic_recv = connection.clone();
        let connection_for_closed = connection.clone();
        let identifier_for_local = identifier.clone();
        let identifier_for_quic_recv = identifier.clone();
        let identifier_for_cleanup = identifier.clone();
        let udp_for_local_recv = udp_socket.clone();
        let udp_for_send_to_client = udp_socket.clone();
        let client_map_for_local = client_map.clone();
        let client_map_for_quic = client_map.clone();
        let dns_id_map_for_local = dns_id_map.clone();
        let dns_id_map_for_quic = dns_id_map.clone();
        let timestamps_for_local = client_timestamps.clone();
        let semaphore_for_local = datagram_semaphore.clone();
        let _semaphore_for_quic = datagram_semaphore.clone();

        let mut sequence_counter: u64 = 0;

        let recv_from_local_client = async move {
            let recv_buffer_size = max_size.max(1200);
            let mut recv_pooled = BufferPool::acquire(recv_buffer_size);
            loop {
                match udp_for_local_recv
                    .recv_from(recv_pooled.as_mut_slice())
                    .await
                {
                    Ok((len, client_addr)) => {
                        let data = &recv_pooled.as_slice()[..len];

                        if client_map_for_local.len() >= MAX_CLIENT_MAPPINGS {
                            tracing::warn!(
                                "UDP client map full ({} entries), dropping packet from {}",
                                MAX_CLIENT_MAPPINGS,
                                client_addr
                            );
                            counter!("synvoid.tunnel.quic.server.udp_tunnels.client_map_full")
                                .increment(1);
                            continue;
                        }

                        client_map_for_local.insert(sequence_counter, client_addr);
                        timestamps_for_local.insert(client_addr, std::time::Instant::now());

                        if len >= 2 && dns_id_map_for_local.len() < MAX_DNS_IDS {
                            let dns_id = u16::from_be_bytes([data[0], data[1]]);
                            dns_id_map_for_local.insert(dns_id, client_addr);
                            counter!("synvoid.tunnel.quic.server.udp_tunnels.dns_tracked")
                                .increment(1);
                        }

                        let msg = DatagramMessage::new(
                            identifier_for_local.clone(),
                            sequence_counter,
                            data.to_vec(),
                            port,
                            client_addr.to_string(),
                        );

                        sequence_counter = sequence_counter.wrapping_add(1);

                        let permit = match semaphore_for_local.try_acquire() {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!(
                                    "UDP backpressure: too many pending datagrams, dropping packet"
                                );
                                counter!("synvoid.tunnel.quic.server.udp_tunnels.backpressure")
                                    .increment(1);
                                continue;
                            }
                        };

                        if let Ok(encoded) = msg.encode() {
                            if encoded.len() <= max_size {
                                match connection_for_quic_send.send_datagram(encoded.into()) {
                                    Err(e) => {
                                        tracing::debug!(
                                            "Failed to send UDP datagram to QUIC: {}",
                                            e
                                        );
                                    }
                                    _ => {
                                        counter!(
                                            "synvoid.tunnel.quic.server.udp_tunnels.forwarded"
                                        )
                                        .increment(1);
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    "UDP packet too large for datagram ({} > {}), dropping",
                                    encoded.len(),
                                    max_size
                                );
                                counter!("synvoid.tunnel.quic.server.udp_tunnels.oversized")
                                    .increment(1);
                            }
                        }
                        drop(permit);
                    }
                    Err(e) => {
                        tracing::debug!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        let recv_from_quic = async move {
            loop {
                match connection_for_quic_recv.read_datagram().await {
                    Ok(data) => {
                        if let Some(msg) = DatagramMessage::decode(&data) {
                            if msg.identifier != identifier_for_quic_recv {
                                continue;
                            }

                            let target_client = if msg.source_addr.is_empty() {
                                if msg.data.len() >= 2 {
                                    let dns_id = u16::from_be_bytes([msg.data[0], msg.data[1]]);
                                    dns_id_map_for_quic.get(&dns_id).map(|e| *e.value())
                                } else {
                                    client_map_for_quic.get(&msg.sequence).map(|e| *e.value())
                                }
                            } else if let Ok(client_addr) = msg.source_addr.parse::<SocketAddr>() {
                                let known_client = client_map_for_quic
                                    .iter()
                                    .any(|entry| *entry.value() == client_addr);
                                let known_dns = dns_id_map_for_quic
                                    .iter()
                                    .any(|entry| *entry.value() == client_addr);

                                if known_client || known_dns {
                                    Some(client_addr)
                                } else {
                                    tracing::warn!(
                                        "UDP packet from unknown source address {}, rejecting",
                                        client_addr
                                    );
                                    None
                                }
                            } else if msg.data.len() >= 2 {
                                let dns_id = u16::from_be_bytes([msg.data[0], msg.data[1]]);
                                dns_id_map_for_quic.get(&dns_id).map(|e| *e.value())
                            } else {
                                client_map_for_quic.get(&msg.sequence).map(|e| *e.value())
                            };

                            if let Some(client_addr) = target_client {
                                if let Err(e) =
                                    udp_for_send_to_client.send_to(&msg.data, client_addr).await
                                {
                                    tracing::debug!(
                                        "Failed to send UDP to client {}: {}",
                                        client_addr,
                                        e
                                    );
                                } else {
                                    counter!("synvoid.tunnel.quic.server.udp_tunnels.forwarded")
                                        .increment(1);
                                }
                            } else {
                                tracing::trace!(
                                    "No client mapping found for sequence {}",
                                    msg.sequence
                                );
                            }
                        } else if let Some(msg) = TunnelMessage::decode(&data) {
                            match msg {
                                TunnelMessage::UdpData {
                                    identifier: msg_id,
                                    data,
                                } => {
                                    if msg_id != identifier_for_quic_recv {
                                        continue;
                                    }

                                    if let Some(client_addr) =
                                        client_map_for_quic.iter().next().map(|e| *e.value())
                                    {
                                        if let Err(e) =
                                            udp_for_send_to_client.send_to(&data, client_addr).await
                                        {
                                            tracing::debug!(
                                                "Failed to send UDP to client {}: {}",
                                                client_addr,
                                                e
                                            );
                                        } else {
                                            counter!(
                                                "synvoid.tunnel.quic.server.udp_tunnels.forwarded"
                                            )
                                            .increment(1);
                                        }
                                    }
                                }
                                TunnelMessage::UdpClose { .. } => {
                                    tracing::debug!("UDP tunnel close requested");
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::trace!("Datagram read error: {}", e);
                        break;
                    }
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        let cleanup_expired_clients = async {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let timestamps = client_timestamps.clone();
            let client_map = client_map.clone();
            let dns_id_map = dns_id_map.clone();

            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                let ttl = std::time::Duration::from_secs(CLIENT_TTL_SECS);

                let expired: Vec<SocketAddr> = timestamps
                    .iter()
                    .filter(|e| now.duration_since(*e.value()) > ttl)
                    .map(|e| *e.key())
                    .collect();

                let expired_count = expired.len();

                for addr in expired {
                    timestamps.remove(&addr);
                }

                client_map.retain(|_, v| timestamps.contains_key(v));
                dns_id_map.retain(|_, v| timestamps.contains_key(v));

                let remaining = timestamps.len();
                if remaining > 0 || expired_count > 0 {
                    tracing::trace!(
                        "UDP tunnel {} cleanup: {} clients expired, {} remaining",
                        identifier_for_cleanup,
                        expired_count,
                        remaining
                    );
                }
            }
        };

        tokio::select! {
            result = recv_from_local_client => {
                if let Err(e) = result {
                    tracing::debug!("UDP local recv error: {}", e);
                }
            }
            result = recv_from_quic => {
                if let Err(e) = result {
                    tracing::debug!("UDP QUIC recv error: {}", e);
                }
            }
            _ = cleanup_expired_clients => {}
            _ = connection_for_closed.closed() => {
                tracing::debug!("UDP tunnel connection closed");
            }
        }

        tracing::debug!("UDP tunnel {} closed", identifier);
        counter!("synvoid.tunnel.quic.server.udp_tunnels.closed").increment(1);

        Ok(())
    }

    async fn proxy_bidirectional(
        mut send_stream: SendStream,
        mut recv_stream: RecvStream,
        upstream_tcp: TcpStream,
        identifier: String,
        max_message_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut tcp_read, mut tcp_write) = upstream_tcp.into_split();

        let identifier_clone = identifier.clone();
        let max_msg_size = max_message_size;
        let quic_to_tcp = async {
            let mut len_buf = [0u8; 4];
            let mut data_pooled = BufferPool::acquire_medium();
            loop {
                match recv_stream.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(quinn::ReadExactError::FinishedEarly(_)) => break Ok(()),
                    Err(e) => break Err(e.into()),
                }

                let len = u32::from_be_bytes(len_buf) as usize;
                if len > max_msg_size {
                    tracing::warn!(
                        "Message size {} exceeds max {} for {}",
                        len,
                        max_msg_size,
                        identifier_clone
                    );
                    break Err(format!("Message too large: {} > {}", len, max_msg_size).into());
                }
                if len > data_pooled.capacity() {
                    data_pooled = BufferPool::acquire(len);
                } else {
                    data_pooled.resize(len);
                }
                recv_stream.read_exact(data_pooled.as_mut_slice()).await?;

                if let Some((_, _, data, fin)) =
                    TunnelMessage::decode_data_chunk_zero_copy(data_pooled.as_slice())
                {
                    if !data.is_empty() {
                        if let Err(e) = tcp_write.write_all(data).await {
                            tracing::debug!("TCP write error for {}: {}", identifier_clone, e);
                            break Err(e.into());
                        }
                    }
                    if fin {
                        tracing::debug!("QUIC stream fin received for {}", identifier_clone);
                        break Ok(());
                    }
                } else if let Some(msg) = TunnelMessage::decode(data_pooled.as_slice()) {
                    match msg {
                        TunnelMessage::DataChunk { data, fin, .. } => {
                            if !data.is_empty() {
                                if let Err(e) = tcp_write.write_all(&data).await {
                                    tracing::debug!(
                                        "TCP write error for {}: {}",
                                        identifier_clone,
                                        e
                                    );
                                    break Err(e.into());
                                }
                            }
                            if fin {
                                tracing::debug!(
                                    "QUIC stream fin received for {}",
                                    identifier_clone
                                );
                                break Ok(());
                            }
                        }
                        TunnelMessage::StreamClose { .. } => {
                            tracing::debug!("StreamClose received for {}", identifier_clone);
                            break Ok(());
                        }
                        _ => {}
                    }
                }
            }
        };

        let identifier_clone = identifier.clone();
        let tcp_to_quic = async {
            let mut pooled = BufferPool::acquire(64 * 1024);
            let mut sequence: u64 = 0;
            loop {
                match tcp_read.read(pooled.as_mut_slice()).await {
                    Ok(0) => {
                        tracing::debug!("TCP connection closed for {}", identifier_clone);
                        TunnelMessage::write_data_chunk_zero_copy(
                            &mut send_stream,
                            &identifier_clone,
                            sequence,
                            &[],
                            true,
                        )
                        .await
                        .map_err(|e| format!("Zero-copy write error: {}", e))?;
                        break Ok(());
                    }
                    Ok(n) => {
                        TunnelMessage::write_data_chunk_zero_copy(
                            &mut send_stream,
                            &identifier_clone,
                            sequence,
                            &pooled.as_slice()[..n],
                            false,
                        )
                        .await
                        .map_err(|e| format!("Zero-copy write error: {}", e))?;
                        sequence += 1;
                    }
                    Err(e) => {
                        tracing::debug!("TCP read error for {}: {}", identifier_clone, e);
                        break Err(e.into());
                    }
                }
            }
        };

        counter!("synvoid.tunnel.quic.server.streams.proxied").increment(1);

        let result = tokio::try_join!(quic_to_tcp, tcp_to_quic);

        counter!("synvoid.tunnel.quic.server.streams.closed").increment(1);

        let _ = send_stream.finish();

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn authenticate_client(
        client_id: &str,
        auth_token: &str,
        config: &TunnelQuicConfig,
    ) -> Option<AuthResult> {
        if let Some(client_config) = config.server.clients.get(client_id) {
            if client_config.enabled
                && !client_config.auth_token.is_empty()
                && auth_token
                    .as_bytes()
                    .ct_eq(client_config.auth_token.as_bytes())
                    .into()
            {
                return Some(AuthResult {
                    access_level: client_config.access_level,
                    allowed_ports_tcp: config.server.vpn_access.general_allowed_ports.clone(),
                    allowed_ports_udp: config.server.vpn_access.general_allowed_ports_udp.clone(),
                });
            }
        }

        if !config.server.auth_token.is_empty()
            && auth_token
                .as_bytes()
                .ct_eq(config.server.auth_token.as_bytes())
                .into()
        {
            return Some(AuthResult {
                access_level: VpnAccessLevel::Admin,
                allowed_ports_tcp: vec![],
                allowed_ports_udp: vec![],
            });
        }

        let whitelisted = config
            .whitelist
            .iter()
            .any(|w| w.as_bytes().ct_eq(client_id.as_bytes()).into());
        if whitelisted {
            return Some(AuthResult {
                access_level: VpnAccessLevel::General,
                allowed_ports_tcp: config.server.vpn_access.general_allowed_ports.clone(),
                allowed_ports_udp: config.server.vpn_access.general_allowed_ports_udp.clone(),
            });
        }

        if config.server.is_allow_unauthenticated_confirmed() {
            tracing::warn!(
                "SECURITY WARNING: allow_unauthenticated is enabled with confirmation. \
                VPN tunnel will accept connections without authentication. \
                This should ONLY be used in trusted private networks."
            );
            return Some(AuthResult {
                access_level: VpnAccessLevel::General,
                allowed_ports_tcp: config.server.vpn_access.general_allowed_ports.clone(),
                allowed_ports_udp: config.server.vpn_access.general_allowed_ports_udp.clone(),
            });
        }

        if config.server.allow_unauthenticated {
            counter!("synvoid.tunnel.quic.server.allow_unauthenticated_misconfigured").increment(1);
            tracing::error!(
                "SECURITY REJECTION: allow_unauthenticated=true but missing confirmation. \
                To enable unauthenticated access, you must set \
                allow_unauthenticated_confirmation = \"I_UNDERSTAND_THIS_IS_INSECURE_FOR_PRODUCTION\" \
                in your config. This is intentional friction to prevent accidental misconfiguration."
            );
        }

        None
    }

    fn authenticate_peer(
        peer_id: &str,
        auth_token: &str,
        config: &TunnelQuicConfig,
    ) -> Option<TunnelQuicPeerConfig> {
        if let Some(peer_config) = config.client.peers.get(peer_id) {
            if peer_config.enabled
                && auth_token
                    .as_bytes()
                    .ct_eq(peer_config.auth_token.as_bytes())
                    .into()
            {
                return Some(peer_config.clone());
            }
        }
        None
    }

    fn convert_mappings(
        mappings: &HashMap<String, PortMapping>,
    ) -> HashMap<String, PortMappingConfig> {
        mappings
            .iter()
            .map(|(name, mapping)| {
                (
                    name.clone(),
                    PortMappingConfig {
                        port: mapping.port,
                        protocol: mapping.protocol.clone(),
                        upstream_host: mapping.upstream_host.clone(),
                        upstream_port: mapping.upstream_port,
                    },
                )
            })
            .collect()
    }

    pub fn get_session(&self, id: &str) -> Option<QuicTunnelSession> {
        self.sessions.get(id).map(|s| s.clone())
    }

    pub fn list_sessions(&self) -> Vec<QuicTunnelSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub async fn close_session(&self, session_id: &str) {
        if let Some(session) = self.sessions.get(session_id) {
            session
                .connection
                .close(0u32.into(), b"Session closed by server");
        }
        self.sessions.remove(session_id);
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

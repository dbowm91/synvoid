use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use metrics::{counter, gauge};
use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt};
use tokio::sync::{broadcast, mpsc, Mutex};

use super::health::{HealthCheckConfig, QuicHealthMonitor};
use super::messages::{DatagramCapabilities, DatagramMessage};
use super::registry::{TunnelSessionInfo, QUIC_TUNNEL_REGISTRY};
use super::tls::QuicTlsConfig;
use super::validation::{validate_max_message_size, DEFAULT_MESSAGE_SIZE};
use super::ConnectionQuality;
use synvoid_config::TunnelQuicConfig;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10000;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5000;
const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;

#[derive(Clone)]
pub struct QuicRuntime {
    config: TunnelQuicConfig,
    tls_config: QuicTlsConfig,
    shutdown_tx: broadcast::Sender<()>,
    max_idle_timeout: Duration,
    keepalive_interval: Duration,
    max_concurrent_streams: u64,
    max_stream_buffer_size: usize,
    max_message_size: usize,
    max_datagram_size: usize,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    sessions: Arc<DashMap<String, QuicConnection>>,
    endpoint: Arc<Mutex<Option<Endpoint>>>,
    connections: Arc<DashMap<String, Connection>>,
    health_monitor: Option<Arc<QuicHealthMonitor>>,
    datagram_enabled: bool,
}

#[derive(Clone)]
pub struct QuicConnection {
    pub remote_addr: SocketAddr,
    pub peer_id: Option<String>,
    pub session_id: String,
    pub client_id: String,
    pub mappings: HashMap<String, u16>,
    pub connection: Option<Connection>,
    pub datagram_capabilities: DatagramCapabilities,
}

pub struct IncomingConnection {
    pub remote_addr: SocketAddr,
    pub connection: Connection,
}

impl QuicRuntime {
    pub fn new(config: TunnelQuicConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let mut tls_config = QuicTlsConfig::from_config(&config);

        tls_config.ensure_certs()?;

        let max_message_size =
            validate_max_message_size(config.max_message_size).unwrap_or(DEFAULT_MESSAGE_SIZE);
        let datagram_enabled = true;

        tracing::info!(
            "QUIC tunnel runtime initialized: server={}, client={}, datagrams={}, max_msg_size={}KB",
            config.server.enabled,
            config.client.enabled,
            datagram_enabled,
            max_message_size / 1024
        );

        Ok(Self {
            config,
            tls_config,
            shutdown_tx,
            max_idle_timeout: Duration::from_secs(300),
            keepalive_interval: Duration::from_secs(25),
            max_concurrent_streams: 100,
            max_stream_buffer_size: 1024 * 1024,
            max_message_size,
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            sessions: Arc::new(DashMap::new()),
            endpoint: Arc::new(Mutex::new(None)),
            connections: Arc::new(DashMap::new()),
            health_monitor: None,
            datagram_enabled,
        })
    }

    pub fn with_timeouts(mut self, max_idle_secs: u64, keepalive_secs: u64) -> Self {
        self.max_idle_timeout = Duration::from_secs(max_idle_secs);
        self.keepalive_interval = Duration::from_secs(keepalive_secs);
        self
    }

    pub fn with_connect_timeout(mut self, timeout_ms: u64) -> Self {
        self.connect_timeout = Duration::from_millis(timeout_ms);
        self
    }

    pub fn with_handshake_timeout(mut self, timeout_ms: u64) -> Self {
        self.handshake_timeout = Duration::from_millis(timeout_ms);
        self
    }

    pub fn with_stream_limits(mut self, max_streams: u64, buffer_size: usize) -> Self {
        self.max_concurrent_streams = max_streams;
        self.max_stream_buffer_size = buffer_size;
        self
    }

    pub fn with_datagram_size(mut self, max_size: usize) -> Self {
        self.max_datagram_size = max_size.min(65535);
        self
    }

    pub fn with_health_monitor(mut self, config: HealthCheckConfig) -> Self {
        let (monitor, _rx) = QuicHealthMonitor::new(config);
        self.health_monitor = Some(Arc::new(monitor));
        self
    }

    fn build_transport_config(&self) -> Arc<TransportConfig> {
        let mut transport = TransportConfig::default();

        let max_streams =
            VarInt::try_from(self.config.max_concurrent_streams).unwrap_or(VarInt::from(100u32));

        if self.config.high_throughput_mode {
            transport
                .max_concurrent_bidi_streams(max_streams)
                .max_concurrent_uni_streams(max_streams);

            let stream_window =
                VarInt::try_from(self.config.stream_receive_window).unwrap_or(VarInt::MAX);
            let conn_window =
                VarInt::try_from(self.config.connection_receive_window).unwrap_or(VarInt::MAX);

            transport
                .stream_receive_window(stream_window)
                .datagram_receive_buffer_size(Some(self.config.udp_max_datagram_size * 1024))
                .receive_window(conn_window);

            // NOTE: congestion_control and initial_congestion_window cannot be configured via
            // Quinn's public API (as of quinn 0.11). Quinn defaults to BBR which is suitable
            // for high-throughput scenarios. Tracking: https://github.com/quinn-rs/quinn/issues

            tracing::info!(
                "QUIC high-throughput mode enabled: streams={}, stream_window={}MB, conn_window={}MB, cc={}",
                self.config.max_concurrent_streams,
                self.config.stream_receive_window / (1024 * 1024),
                self.config.connection_receive_window / (1024 * 1024),
                self.config.congestion_control
            );
        } else {
            transport.max_concurrent_bidi_streams(max_streams);
        }

        let idle_timeout_varint = VarInt::try_from(self.max_idle_timeout.as_millis() as u64)
            .unwrap_or_else(|_| VarInt::from(300_000u32));
        let idle_timeout = IdleTimeout::from(idle_timeout_varint);
        transport.max_idle_timeout(Some(idle_timeout));

        Arc::new(transport)
    }

    pub async fn start_server(
        &self,
    ) -> Result<mpsc::Receiver<IncomingConnection>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = mpsc::channel(32);

        if !self.config.server.enabled {
            tracing::info!("QUIC tunnel server disabled");
            return Ok(rx);
        }

        let bind_addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .map_err(|e| format!("Invalid bind address: {}", e))?;

        let mut server_config = self
            .tls_config
            .build_server_config()
            .map_err(|e| format!("Failed to build server config: {}", e))?;

        let transport_config = self.build_transport_config();
        server_config.transport = transport_config;

        let endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| format!("Failed to create QUIC endpoint: {}", e))?;

        tracing::info!("QUIC tunnel server listening on {}", bind_addr);
        gauge!("synvoid.tunnel.quic.server.enabled").set(1.0);
        counter!("synvoid.tunnel.quic.server.started").increment(1);

        {
            let mut endpoint_guard = self.endpoint.lock().await;
            *endpoint_guard = Some(endpoint.clone());
        }

        let sessions = self.sessions.clone();
        let connections = self.connections.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        let max_message_size = self.max_message_size;
        let health_monitor = self.health_monitor.clone();

        let peer_config = if self.config.client.enabled {
            Some(Arc::new(std::sync::RwLock::new(
                self.config.client.peers.clone(),
            )))
        } else {
            None
        };

        tokio::spawn(async move {
            Self::accept_loop(
                endpoint,
                tx,
                sessions,
                connections,
                shutdown_rx,
                max_message_size,
                peer_config,
                health_monitor,
            )
            .await;
        });

        Ok(rx)
    }

    async fn accept_loop(
        endpoint: Endpoint,
        tx: mpsc::Sender<IncomingConnection>,
        _sessions: Arc<DashMap<String, QuicConnection>>,
        _connections: Arc<DashMap<String, Connection>>,
        mut shutdown_rx: broadcast::Receiver<()>,
        _max_message_size: usize,
        _peer_config: Option<
            Arc<std::sync::RwLock<HashMap<String, synvoid_config::TunnelQuicPeerConfig>>>,
        >,
        health_monitor: Option<Arc<QuicHealthMonitor>>,
    ) {
        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(incoming_conn) => {
                            let remote_addr = incoming_conn.remote_address();

                            match incoming_conn.await {
                                Ok(connection) => {
                                    let incoming = IncomingConnection {
                                        remote_addr,
                                        connection: connection.clone(),
                                    };

                                    if tx.send(incoming).await.is_err() {
                                        tracing::debug!("QUIC connection receiver dropped");
                                        break;
                                    }

                                    if let Some(ref monitor) = health_monitor {
                                        let conn_id = connection.stable_id().to_string();
                                        monitor.register_connection(conn_id.clone(), None);

                                        let monitor_clone = monitor.clone();
                                        tokio::spawn(async move {
                                            let _stats = connection.stats();
                                            monitor_clone.record_packet_stats(
                                                &conn_id,
                                                0,
                                                0,
                                            );
                                        });
                                    }

                                    counter!("synvoid.tunnel.quic.server.connections").increment(1);
                                }
                                Err(e) => {
                                    tracing::warn!("QUIC connection failed from {}: {}", remote_addr, e);
                                    counter!("synvoid.tunnel.quic.server.connection_errors").increment(1);
                                }
                            }
                        }
                        None => {
                            tracing::info!("QUIC endpoint closed");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("QUIC accept loop shutting down");
                    break;
                }
            }
        }
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicConnection, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = {
            let mut endpoint_guard = self.endpoint.lock().await;
            if let Some(ep) = endpoint_guard.as_ref() {
                ep.clone()
            } else {
                let transport_config = self.build_transport_config();
                let client_config = self
                    .tls_config
                    .build_client_config_with_transport(Some(server_name), Some(transport_config))
                    .map_err(|e| format!("Failed to build client config: {}", e))?;

                let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
                let mut ep = Endpoint::client(bind_addr)
                    .map_err(|e| format!("Failed to create client endpoint: {}", e))?;

                ep.set_default_client_config(client_config);

                let _ = endpoint_guard.insert(ep.clone());
                ep
            }
        };

        let connect_timeout = self.connect_timeout;

        let connecting = endpoint
            .connect(addr, server_name)
            .map_err(|e| format!("Failed to initiate connection: {}", e))?;

        let connection = tokio::time::timeout(connect_timeout, connecting)
            .await
            .map_err(|_| format!("Connection timed out after {:?}", connect_timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        let conn_id = connection.stable_id().to_string();
        let session_id = uuid::Uuid::new_v4().to_string();

        self.connections.insert(conn_id.clone(), connection.clone());

        let datagram_caps = self.detect_datagram_capabilities(&connection);

        let quic_conn = QuicConnection {
            remote_addr: addr,
            peer_id: None,
            session_id: session_id.clone(),
            client_id: String::new(),
            mappings: HashMap::new(),
            connection: Some(connection),
            datagram_capabilities: datagram_caps,
        };

        self.add_session(quic_conn.clone()).await;

        if let Some(ref monitor) = self.health_monitor {
            monitor.register_connection(session_id.clone(), None);
            monitor.set_datagram_capabilities(&session_id, datagram_caps);
        }

        counter!("synvoid.tunnel.quic.client.connections").increment(1);
        tracing::info!(
            "QUIC client connected to {} (session: {}, datagrams: {})",
            addr,
            session_id,
            datagram_caps.supported
        );

        Ok(quic_conn)
    }

    fn detect_datagram_capabilities(&self, connection: &Connection) -> DatagramCapabilities {
        let max_size = connection.max_datagram_size().unwrap_or(0);
        DatagramCapabilities::new(max_size > 0, max_size)
    }

    pub async fn connect_to_peer(
        &self,
        peer_addr: &str,
        server_name: &str,
    ) -> Result<QuicConnection, Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = peer_addr
            .parse()
            .map_err(|e| format!("Invalid peer address: {}", e))?;

        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            match self.connect(addr, server_name).await {
                Ok(conn) => {
                    if let Some(ref monitor) = self.health_monitor {
                        monitor.record_health_check_success(
                            &conn.session_id,
                            Duration::from_millis(0),
                        );
                    }
                    return Ok(conn);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < MAX_RETRIES - 1 {
                        tracing::warn!(
                            "QUIC connection attempt {} failed, retrying...",
                            attempt + 1
                        );
                        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "Connection failed after retries".into()))
    }

    pub fn bind_address(&self) -> SocketAddr {
        format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .unwrap_or_else(|_| {
                "0.0.0.0:51821"
                    .parse()
                    .expect("valid socket address literal")
            })
    }

    pub async fn local_addr(&self) -> Option<SocketAddr> {
        let endpoint_guard = self.endpoint.lock().await;
        if let Some(ref endpoint) = *endpoint_guard {
            endpoint.local_addr().ok()
        } else {
            None
        }
    }

    pub fn local_port(&self) -> Option<u16> {
        if self.config.port == 0 {
            None
        } else {
            Some(self.config.port)
        }
    }

    pub fn max_idle_timeout(&self) -> Duration {
        self.max_idle_timeout
    }

    pub fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn is_datagram_enabled(&self) -> bool {
        self.datagram_enabled
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn is_server_enabled(&self) -> bool {
        self.config.server.enabled
    }

    pub fn is_client_enabled(&self) -> bool {
        self.config.client.enabled
    }

    pub fn tls_config(&self) -> &QuicTlsConfig {
        &self.tls_config
    }

    pub fn health_monitor(&self) -> Option<&Arc<QuicHealthMonitor>> {
        self.health_monitor.as_ref()
    }

    pub async fn add_session(&self, connection: QuicConnection) {
        let session_id = connection.session_id.clone();
        self.sessions.insert(session_id.clone(), connection.clone());

        QUIC_TUNNEL_REGISTRY
            .register(TunnelSessionInfo {
                session_id: connection.session_id.clone(),
                client_id: connection.client_id.clone(),
                peer_id: connection.peer_id.clone(),
                remote_addr: connection.remote_addr.to_string(),
                mappings: connection.mappings.clone(),
            })
            .await;

        gauge!("synvoid.tunnel.quic.sessions").set(self.sessions.len() as f64);
        tracing::debug!(
            "QUIC session added: {} (total: {})",
            session_id,
            self.sessions.len()
        );
    }

    pub async fn remove_session(&self, session_id: &str) {
        self.sessions.remove(session_id);

        QUIC_TUNNEL_REGISTRY.unregister(session_id).await;

        if let Some(ref monitor) = self.health_monitor {
            monitor.unregister_connection(session_id);
        }

        gauge!("synvoid.tunnel.quic.sessions").set(self.sessions.len() as f64);
        tracing::debug!(
            "QUIC session removed: {} (remaining: {})",
            session_id,
            self.sessions.len()
        );
    }

    pub fn get_session(&self, session_id: &str) -> Option<QuicConnection> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    pub fn get_session_by_client_id(&self, client_id: &str) -> Option<QuicConnection> {
        self.sessions
            .iter()
            .find(|s| s.client_id == client_id)
            .map(|s| s.clone())
    }

    pub fn get_session_by_peer(&self, peer_id: &str) -> Option<QuicConnection> {
        self.sessions
            .iter()
            .find(|s| s.peer_id.as_deref() == Some(peer_id))
            .map(|s| s.clone())
    }

    pub fn list_sessions(&self) -> Vec<QuicConnection> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn update_session_mappings(&self, session_id: &str, mappings: HashMap<String, u16>) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.mappings = mappings;
        }
    }

    pub fn config(&self) -> &TunnelQuicConfig {
        &self.config
    }

    pub fn is_ip_whitelisted(&self, ip: &SocketAddr) -> bool {
        let ip_str = ip.ip().to_string();

        if self.config.whitelist.is_empty() {
            return true;
        }

        for allowed in &self.config.whitelist {
            if allowed == &ip_str || allowed == "*" {
                return true;
            }
        }

        false
    }

    pub async fn open_tunnel_stream(
        &self,
        session_id: &str,
        _identifier: &str,
    ) -> Result<(SendStream, RecvStream), Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("Session not found: {}", session_id))?;

        let connection = session
            .connection
            .as_ref()
            .ok_or_else(|| "No active connection for session".to_string())?;

        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open bidirectional stream: {}", e))?;

        counter!("synvoid.tunnel.quic.streams.opened").increment(1);
        Ok((send, recv))
    }

    pub async fn open_tunnel_stream_to_peer(
        &self,
        peer_id: &str,
        identifier: &str,
    ) -> Result<(SendStream, RecvStream), Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .get_session_by_peer(peer_id)
            .ok_or_else(|| format!("No session found for peer: {}", peer_id))?;

        self.open_tunnel_stream(&session.session_id, identifier)
            .await
    }

    pub fn get_connection(&self, session_id: &str) -> Option<Connection> {
        self.sessions
            .get(session_id)
            .and_then(|s| s.connection.clone())
    }

    pub async fn close_session(&self, session_id: &str) {
        if let Some(session) = self.get_session(session_id) {
            if let Some(conn) = &session.connection {
                conn.close(0u32.into(), b"Session closed");
            }
        }
        self.remove_session(session_id).await;
    }

    pub fn send_datagram(
        &self,
        session_id: &str,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("Session not found: {}", session_id))?;

        let connection = session
            .connection
            .as_ref()
            .ok_or_else(|| "No active connection for session".to_string())?;

        if !session.datagram_capabilities.supported {
            return Err("Datagrams not supported for this connection".into());
        }

        if data.len() > session.datagram_capabilities.max_size {
            return Err(format!(
                "Datagram too large: {} > {}",
                data.len(),
                session.datagram_capabilities.max_size
            )
            .into());
        }

        connection
            .send_datagram(data.clone().into())
            .map_err(|e| format!("Failed to send datagram: {}", e))?;

        counter!("synvoid.tunnel.quic.datagrams.sent").increment(1);

        if let Some(ref monitor) = self.health_monitor {
            monitor.record_packet_stats(session_id, 1, 0);
        }

        Ok(())
    }

    pub async fn recv_datagram(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("Session not found: {}", session_id))?;

        let connection = session
            .connection
            .as_ref()
            .ok_or_else(|| "No active connection for session".to_string())?;

        if !session.datagram_capabilities.supported {
            return Err("Datagrams not supported for this connection".into());
        }

        let result = tokio::time::timeout(timeout, async {
            loop {
                match connection.read_datagram().await {
                    Ok(data) => return Ok(data.to_vec()),
                    Err(e) => {
                        tracing::trace!("Datagram read error: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await;

        match result {
            Ok(data) => {
                counter!("synvoid.tunnel.quic.datagrams.received").increment(1);
                data
            }
            Err(_) => Err("Datagram receive timeout".into()),
        }
    }

    pub async fn send_datagram_message(
        &self,
        session_id: &str,
        msg: DatagramMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let encoded = msg
            .encode()
            .map_err(|e| format!("Failed to encode datagram message: {}", e))?;
        self.send_datagram(session_id, encoded)
    }

    pub fn get_connection_quality(&self, session_id: &str) -> Option<ConnectionQuality> {
        self.health_monitor
            .as_ref()?
            .get_connection_quality(session_id)
    }

    pub fn get_connection_health(
        &self,
        session_id: &str,
    ) -> Option<super::health::ConnectionHealth> {
        self.health_monitor
            .as_ref()?
            .get_connection_health(session_id)
    }
}

impl QuicConnection {
    pub fn connection(&self) -> Option<&Connection> {
        self.connection.as_ref()
    }

    pub async fn open_stream(
        &self,
    ) -> Result<(SendStream, RecvStream), Box<dyn std::error::Error + Send + Sync>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| "No active connection".to_string())?;

        conn.open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e).into())
    }

    pub fn supports_datagrams(&self) -> bool {
        self.datagram_capabilities.supported
    }

    pub fn max_datagram_size(&self) -> usize {
        self.datagram_capabilities.max_size
    }

    pub fn send_datagram(
        &self,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = self
            .connection
            .as_ref()
            .ok_or_else(|| "No active connection".to_string())?;

        if !self.datagram_capabilities.supported {
            return Err("Datagrams not supported for this connection".into());
        }

        if data.len() > self.datagram_capabilities.max_size {
            return Err(format!(
                "Datagram too large: {} > {}",
                data.len(),
                self.datagram_capabilities.max_size
            )
            .into());
        }

        conn.send_datagram(data.into())
            .map_err(|e| format!("Failed to send datagram: {}", e))?;

        counter!("synvoid.tunnel.quic.datagrams.sent").increment(1);
        Ok(())
    }
}

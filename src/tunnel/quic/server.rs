use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, Semaphore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use metrics::{gauge, counter, histogram};
use quinn::{Connection, SendStream, RecvStream};
use subtle::ConstantTimeEq;

use crate::config::main::{TunnelQuicConfig, PortMappingConfig};
use crate::tunnel::quic::runtime::{QuicRuntime, QuicConnection, IncomingConnection};
use crate::tunnel::quic::tls::QuicTlsConfig;
use crate::tunnel::quic::messages::{TunnelMessage, PortMapping, DatagramCapabilities};
use crate::tunnel::quic::health::{QuicHealthMonitor, ConnectionQuality};

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
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.server.enabled {
            tracing::info!("QUIC tunnel server disabled");
            return Ok(());
        }

        tracing::info!("Starting QUIC tunnel server on {}", self.runtime.bind_address());
        
        let connection_rx = self.runtime.start_server().await?;
        self.connection_rx = Some(connection_rx);
        
        gauge!("rustwaf.tunnel.quic.server.enabled").set(1.0);
        
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

        tokio::spawn(async move {
            Self::connection_loop(connection_rx, sessions, config, shutdown_rx, connection_limit).await;
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
    ) {
        loop {
            tokio::select! {
                incoming = connection_rx.recv() => {
                    match incoming {
                        Some(incoming) => {
                            let permit = match connection_limit.clone().acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!("Connection limit semaphore closed, rejecting new connection");
                                    counter!("rustwaf.tunnel.quic.server.rejected").increment(1);
                                    continue;
                                }
                            };
                            
                            let sessions = sessions.clone();
                            let config = config.clone();
                            let remote_addr = incoming.remote_addr.to_string();
                            tokio::spawn(async move {
                                let result = Self::handle_connection(incoming, sessions, config).await;
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
            }
        }
    }

    async fn handle_connection(
        incoming: IncomingConnection,
        sessions: Arc<DashMap<String, QuicTunnelSession>>,
        config: TunnelQuicConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let remote_addr = incoming.remote_addr;
        let connection = incoming.connection;
        let max_message_size = config.max_message_size;
        let datagram_enabled = true;
        let max_datagram_size = connection.max_datagram_size().unwrap_or(1200);

        tracing::info!("New QUIC connection from {}", remote_addr);

        let (mut send_stream, mut recv_stream) = connection.accept_bi().await
            .map_err(|e| format!("Failed to accept stream: {}", e))?;

        let msg = Self::read_message(&mut recv_stream, max_message_size).await?;

        match msg {
            TunnelMessage::Hello { client_id, auth_token, mappings, .. } => {
                let authenticated = Self::authenticate_client(&client_id, &auth_token, &config);
                
                if !authenticated {
                    let error = TunnelMessage::AuthFailure {
                        reason: "Invalid credentials".to_string(),
                    };
                    Self::write_message(&mut send_stream, &error).await?;
                    counter!("rustwaf.tunnel.quic.server.auth_failures").increment(1);
                    return Ok(());
                }

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
                    datagram_capabilities: datagram_caps.clone(),
                };

                sessions.insert(session_id.clone(), session.clone());

                let ack = TunnelMessage::HelloAck {
                    server_session_id: session_id.clone(),
                    server_mappings: HashMap::new(),
                    supports_datagrams: datagram_enabled,
                    max_datagram_size,
                };
                Self::write_message(&mut send_stream, &ack).await?;

                counter!("rustwaf.tunnel.quic.server.sessions").increment(1);
                gauge!("rustwaf.tunnel.quic.server.active_sessions").increment(1.0);
                
                tracing::info!("QUIC session established: {} for client {} (datagrams: {})", 
                    session_id, client_id, datagram_caps.supported);

                Self::session_loop(connection, session, sessions, max_message_size).await?;
            }
            TunnelMessage::PeerHello { peer_id, auth_token, .. } => {
                let authenticated = Self::authenticate_peer(&peer_id, &auth_token, &config);
                
                if !authenticated {
                    let error = TunnelMessage::AuthFailure {
                        reason: "Invalid peer credentials".to_string(),
                    };
                    Self::write_message(&mut send_stream, &error).await?;
                    counter!("rustwaf.tunnel.quic.server.peer_auth_failures").increment(1);
                    return Ok(());
                }

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
                    datagram_capabilities: datagram_caps.clone(),
                };

                sessions.insert(session_id.clone(), session.clone());

                let ack = TunnelMessage::PeerHelloAck {
                    session_id: session_id.clone(),
                    supports_datagrams: datagram_enabled,
                    max_datagram_size,
                };
                Self::write_message(&mut send_stream, &ack).await?;

                counter!("rustwaf.tunnel.quic.server.peer_sessions").increment(1);
                
                tracing::info!("QUIC peer session established: {} for peer {} (datagrams: {})", 
                    session_id, peer_id, datagram_caps.supported);

                Self::peer_session_loop(connection, session, sessions, max_message_size).await?;
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
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_id = session.id.clone();
        
        let result = Self::session_loop_inner(connection, session.clone(), sessions.clone(), max_message_size).await;
        
        sessions.remove(&session_id);
        
        gauge!("rustwaf.tunnel.quic.server.active_sessions").decrement(1.0);
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
                                histogram!("rustwaf.tunnel.quic.server.stream_duration").record(start.elapsed());
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

    async fn peer_session_loop(
        connection: Connection,
        session: QuicTunnelSession,
        sessions: Arc<DashMap<String, QuicTunnelSession>>,
        max_message_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Self::session_loop(connection, session, sessions, max_message_size).await
    }

    async fn handle_stream(
        send_stream: SendStream,
        recv_stream: RecvStream,
        session: QuicTunnelSession,
        max_message_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut send_stream = send_stream;
        let mut recv_stream = recv_stream;

        let msg = Self::read_message(&mut recv_stream, max_message_size).await?;

        match msg {
            TunnelMessage::KeepAlive => {
                Self::write_message(&mut send_stream, &TunnelMessage::KeepAliveAck).await?;
                send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::StreamOpen { identifier, port, protocol } => {
                tracing::debug!("Stream open request for {} ({}:{}) in session {}", identifier, protocol, port, session.id);
                
                let upstream_host = session.mappings.get(&identifier)
                    .and_then(|m| m.upstream_host.clone())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let upstream_port = session.mappings.get(&identifier)
                    .and_then(|m| m.upstream_port)
                    .unwrap_or(port);

                let upstream_addr = format!("{}:{}", upstream_host, upstream_port);
                
                let tcp_result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    TcpStream::connect(&upstream_addr)
                ).await;

                match tcp_result {
                    Ok(Ok(upstream_tcp)) => {
                        counter!("rustwaf.tunnel.quic.server.streams.opened").increment(1);
                        
                        let ack = TunnelMessage::StreamOpenAck {
                            identifier: identifier.clone(),
                            success: true,
                            message: None,
                        };
                        Self::write_message(&mut send_stream, &ack).await?;
                        
                        Self::proxy_bidirectional(send_stream, recv_stream, upstream_tcp, identifier, max_message_size).await?;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Failed to connect to upstream {} for {}: {}", upstream_addr, identifier, e);
                        counter!("rustwaf.tunnel.quic.server.streams.upstream_failed").increment(1);
                        
                        let ack = TunnelMessage::StreamOpenAck {
                            identifier: identifier.clone(),
                            success: false,
                            message: Some(format!("Upstream connection failed: {}", e)),
                        };
                        Self::write_message(&mut send_stream, &ack).await?;
                        send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
                    }
                    Err(_) => {
                        tracing::warn!("Timeout connecting to upstream {} for {}", upstream_addr, identifier);
                        counter!("rustwaf.tunnel.quic.server.streams.upstream_timeout").increment(1);
                        
                        let ack = TunnelMessage::StreamOpenAck {
                            identifier: identifier.clone(),
                            success: false,
                            message: Some("Upstream connection timeout".to_string()),
                        };
                        Self::write_message(&mut send_stream, &ack).await?;
                        send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
                    }
                }
            }
            TunnelMessage::UdpTunnelOpen { identifier, port } => {
                tracing::debug!("UDP tunnel open request for {}:{} in session {}", identifier, port, session.id);
                
                if !session.datagram_capabilities.supported {
                    let ack = TunnelMessage::UdpTunnelOpenAck {
                        identifier: identifier.clone(),
                        success: false,
                        message: Some("Datagrams not supported".to_string()),
                    };
                    Self::write_message(&mut send_stream, &ack).await?;
                    send_stream.finish()?;
                    return Ok(());
                }

                counter!("rustwaf.tunnel.quic.server.udp_tunnels.opened").increment(1);
                
                let ack = TunnelMessage::UdpTunnelOpenAck {
                    identifier: identifier.clone(),
                    success: true,
                    message: Some(format!("UDP tunnel opened for port {}", port)),
                };
                Self::write_message(&mut send_stream, &ack).await?;
                
                let connection = session.connection.clone();
                Self::handle_udp_tunnel(connection, session, identifier, port, max_message_size).await?;
            }
            TunnelMessage::PortOpen { identifier, port, protocol } => {
                tracing::debug!("Port open request for {} ({}:{}) in session {}", identifier, protocol, port, session.id);
                let ack = TunnelMessage::PortOpen { 
                    identifier: identifier.clone(),
                    port,
                    protocol,
                };
                Self::write_message(&mut send_stream, &ack).await?;
                send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::StreamClose { identifier } => {
                tracing::debug!("Stream close request for {} in session {}", identifier, session.id);
                send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::PortClose { identifier } => {
                tracing::debug!("Port close request for {} in session {}", identifier, session.id);
                send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            TunnelMessage::PortData { identifier } => {
                tracing::trace!("Port data for {} in session {}", identifier, session.id);
                send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
            }
            _ => {
                tracing::debug!("Unexpected stream message in session {}", session.id);
                send_stream.finish().map_err(|e| format!("Failed to finish stream: {}", e))?;
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
        let bind_addr = format!("0.0.0.0:0");
        let udp_socket = tokio::net::UdpSocket::bind(&bind_addr).await?;
        
        let upstream_host = session.mappings.get(&identifier)
            .and_then(|m| m.upstream_host.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let upstream_port = session.mappings.get(&identifier)
            .and_then(|m| m.upstream_port)
            .unwrap_or(port);
        
        let upstream_addr = format!("{}:{}", upstream_host, upstream_port);
        
        tracing::info!("UDP tunnel {} bound to {}, forwarding to {}", identifier, udp_socket.local_addr()?, upstream_addr);

        let max_size = session.datagram_capabilities.max_size;
        
        loop {
            let mut buf = vec![0u8; max_size];
            
            tokio::select! {
                result = udp_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, client_addr)) => {
                            let data = buf[..len].to_vec();
                            
                            if let Err(e) = connection.send_datagram(data.clone().into()) {
                                tracing::debug!("Failed to send UDP datagram to QUIC: {}", e);
                            } else {
                                counter!("rustwaf.tunnel.quic.server.udp_tunnels.forwarded").increment(1);
                            }
                        }
                        Err(e) => {
                            tracing::debug!("UDP recv error: {}", e);
                            break;
                        }
                    }
                }
                result = async {
                    loop {
                        match connection.read_datagram().await {
                            Ok(data) => {
                                let data_vec = data.to_vec();
                                if let Err(e) = udp_socket.send_to(&data_vec, &upstream_addr).await {
                                    tracing::debug!("Failed to forward UDP to {}: {}", upstream_addr, e);
                                } else {
                                    counter!("rustwaf.tunnel.quic.server.udp_tunnels.forwarded").increment(1);
                                }
                            }
                            Err(e) => {
                                tracing::trace!("Datagram read: {}", e);
                                break;
                            }
                        }
                    }
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                } => {
                    if let Err(e) = result {
                        tracing::debug!("UDP tunnel error: {}", e);
                    }
                }
            }
        }

        tracing::debug!("UDP tunnel {} closed", identifier);
        counter!("rustwaf.tunnel.quic.server.udp_tunnels.closed").increment(1);
        
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
        let quic_to_tcp = async {
            let mut sequence: u64 = 0;
            loop {
                let msg = match Self::read_message(&mut recv_stream, max_message_size).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::trace!("QUIC recv ended for {}: {}", identifier_clone, e);
                        break Err(e);
                    }
                };

                match msg {
                    TunnelMessage::DataChunk { data, fin, .. } => {
                        if !data.is_empty() {
                            if let Err(e) = tcp_write.write_all(&data).await {
                                tracing::debug!("TCP write error for {}: {}", identifier_clone, e);
                                break Err(e.into());
                            }
                        }
                        if fin {
                            tracing::debug!("QUIC stream fin received for {}", identifier_clone);
                            break Ok(());
                        }
                    }
                    TunnelMessage::StreamClose { .. } => {
                        tracing::debug!("StreamClose received for {}", identifier_clone);
                        break Ok(());
                    }
                    _ => {}
                }
                sequence += 1;
            }
        };

        let identifier_clone = identifier.clone();
        let tcp_to_quic = async {
            let mut buf = vec![0u8; 64 * 1024];
            let mut sequence: u64 = 0;
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        tracing::debug!("TCP connection closed for {}", identifier_clone);
                        let fin_msg = TunnelMessage::DataChunk {
                            identifier: identifier_clone.clone(),
                            sequence,
                            data: Vec::new(),
                            fin: true,
                        };
                        let mut data = fin_msg.encode().map_err(|e| format!("Encode error: {}", e))?;
                        let len = (data.len() as u32).to_be_bytes();
                        send_stream.write_all(&len).await?;
                        send_stream.write_all(&data).await?;
                        break Ok(());
                    }
                    Ok(n) => {
                        let data_msg = TunnelMessage::DataChunk {
                            identifier: identifier_clone.clone(),
                            sequence,
                            data: buf[..n].to_vec(),
                            fin: false,
                        };
                        let data = data_msg.encode().map_err(|e| format!("Encode error: {}", e))?;
                        let len = (data.len() as u32).to_be_bytes();
                        if let Err(e) = send_stream.write_all(&len).await {
                            tracing::debug!("QUIC write error for {}: {}", identifier_clone, e);
                            break Err(e.into());
                        }
                        if let Err(e) = send_stream.write_all(&data).await {
                            tracing::debug!("QUIC write error for {}: {}", identifier_clone, e);
                            break Err(e.into());
                        }
                        sequence += 1;
                    }
                    Err(e) => {
                        tracing::debug!("TCP read error for {}: {}", identifier_clone, e);
                        break Err(e.into());
                    }
                }
            }
        };

        counter!("rustwaf.tunnel.quic.server.streams.proxied").increment(1);
        
        let result = tokio::try_join!(quic_to_tcp, tcp_to_quic);
        
        counter!("rustwaf.tunnel.quic.server.streams.closed").increment(1);
        
        let _ = send_stream.finish();
        
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn authenticate_client(client_id: &str, auth_token: &str, config: &TunnelQuicConfig) -> bool {
        if !config.server.auth_token.is_empty() && auth_token.as_bytes().ct_eq(config.server.auth_token.as_bytes()).into() {
            return true;
        }
        
        let whitelisted = config.whitelist.iter().any(|w| w.as_bytes().ct_eq(client_id.as_bytes()).into());
        if whitelisted {
            return true;
        }

        config.server.allow_unauthenticated
    }

    fn authenticate_peer(peer_id: &str, auth_token: &str, config: &TunnelQuicConfig) -> bool {
        if let Some(peer_config) = config.client.peers.get(peer_id) {
            if peer_config.enabled && auth_token.as_bytes().ct_eq(peer_config.auth_token.as_bytes()).into() {
                return true;
            }
        }
        false
    }

    fn convert_mappings(mappings: &HashMap<String, PortMapping>) -> HashMap<String, PortMappingConfig> {
        mappings.iter().map(|(name, mapping)| {
            (name.clone(), PortMappingConfig {
                port: mapping.port,
                protocol: mapping.protocol.clone(),
                upstream_host: mapping.upstream_host.clone(),
                upstream_port: mapping.upstream_port,
            })
        }).collect()
    }

    async fn read_message(
        recv_stream: &mut RecvStream,
        max_message_size: usize,
    ) -> Result<TunnelMessage, Box<dyn std::error::Error + Send + Sync>> {
        let mut len_buf = [0u8; 4];
        recv_stream.read_exact(&mut len_buf).await
            .map_err(|e| format!("Failed to read message length: {}", e))?;
        
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > max_message_size {
            return Err("Message too large".into());
        }

        let mut data = vec![0u8; len];
        recv_stream.read_exact(&mut data).await
            .map_err(|e| format!("Failed to read message: {}", e))?;

        TunnelMessage::decode(&data)
            .ok_or_else(|| "Failed to decode message".into())
    }

    async fn write_message(
        send_stream: &mut SendStream,
        msg: &TunnelMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data = msg.encode()
            .map_err(|e| format!("Failed to encode message: {}", e))?;
        let len = (data.len() as u32).to_be_bytes();
        send_stream.write_all(&len).await
            .map_err(|e| format!("Failed to write message length: {}", e))?;
        send_stream.write_all(&data).await
            .map_err(|e| format!("Failed to write message: {}", e))?;
        Ok(())
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
            session.connection.close(0u32.into(), b"Session closed by server");
        }
        self.sessions.remove(session_id);
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

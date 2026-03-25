use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::broadcast;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use metrics::{gauge, counter, histogram};
use quinn::{Connection, SendStream, RecvStream};

use crate::config::{TunnelQuicConfig, TunnelQuicPeerConfig, PortMappingConfig};
use crate::tunnel::quic::runtime::{QuicRuntime, QuicConnection};
use crate::tunnel::quic::tls::QuicTlsConfig;
use crate::tunnel::quic::messages::{PortMapping, DatagramMessage, DatagramCapabilities, TunnelMessage};
use crate::tunnel::quic::ConnectionQuality;
use crate::tunnel::quic::health::QuicHealthMonitor;
use crate::tunnel::quic::framing::{write_message, read_message_default};
use crate::tunnel::quic::validation::JitteredBackoff;
use crate::buffer::BufferPool;

#[allow(dead_code)]
pub struct QuicTunnelClient {
    config: TunnelQuicConfig,
    tls_config: QuicTlsConfig,
    runtime: Arc<QuicRuntime>,
    sessions: Arc<DashMap<String, QuicClientSession>>,
    shutdown_tx: broadcast::Sender<()>,
    peer_connections: Arc<DashMap<String, QuicConnection>>,
    connections: Arc<DashMap<String, Connection>>,
    health_monitor: Option<Arc<QuicHealthMonitor>>,
}

#[derive(Clone)]
pub struct QuicClientSession {
    pub id: String,
    pub peer_id: String,
    pub remote_addr: String,
    pub connected_at: std::time::Instant,
    pub mappings: HashMap<String, PortMappingConfig>,
    pub connection: Option<Connection>,
    pub datagram_capabilities: DatagramCapabilities,
}

impl QuicTunnelClient {
    pub fn new(
        config: TunnelQuicConfig,
        runtime: Arc<QuicRuntime>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let tls_config = QuicTlsConfig::from_config(&config);
        let health_monitor = runtime.health_monitor().cloned();
        
        Self {
            config,
            tls_config,
            runtime,
            sessions: Arc::new(DashMap::new()),
            shutdown_tx,
            peer_connections: Arc::new(DashMap::new()),
            connections: Arc::new(DashMap::new()),
            health_monitor,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.client.enabled {
            tracing::info!("QUIC tunnel client disabled");
            return Ok(());
        }

        tracing::info!("QUIC tunnel client starting");
        
        for (peer_name, peer_config) in &self.config.client.peers {
            if peer_config.enabled {
                let sessions = self.sessions.clone();
                let connections = self.connections.clone();
                let peer_name = peer_name.clone();
                let peer_config = peer_config.clone();
                let runtime = self.runtime.clone();
                let shutdown_rx = self.shutdown_tx.subscribe();
                let health_monitor = self.health_monitor.clone();

                tokio::spawn(async move {
                    Self::manage_peer_connection(
                        peer_name,
                        peer_config,
                        sessions,
                        connections,
                        runtime,
                        shutdown_rx,
                        health_monitor,
                    ).await;
                });
            }
        }
        
        gauge!("maluwaf.tunnel.quic.client.enabled").set(1.0);
        
        Ok(())
    }

    async fn manage_peer_connection(
        peer_name: String,
        peer_config: TunnelQuicPeerConfig,
        sessions: Arc<DashMap<String, QuicClientSession>>,
        connections: Arc<DashMap<String, Connection>>,
        runtime: Arc<QuicRuntime>,
        mut shutdown_rx: broadcast::Receiver<()>,
        health_monitor: Option<Arc<QuicHealthMonitor>>,
    ) {
        let max_retries = 10u32;
        let mut backoff = JitteredBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            2.0,
        );
        let _connection_quality = ConnectionQuality::Good;

        loop {
            match Self::connect_to_peer(&peer_name, &peer_config, runtime.clone()).await {
                Ok((session, connection)) => {
                    backoff.reset();
                    
                    sessions.insert(peer_name.clone(), session.clone());
                    connections.insert(session.id.clone(), connection.clone());

                    if let Some(ref monitor) = health_monitor {
                        monitor.register_connection(session.id.clone(), Some(peer_name.clone()));
                        monitor.set_datagram_capabilities(&session.id, session.datagram_capabilities);
                    }

                    counter!("maluwaf.tunnel.quic.client.connected").increment(1);
                    gauge!("maluwaf.tunnel.quic.client.peers").increment(1.0);
                    tracing::info!("Connected to QUIC peer: {} at {} (datagrams: {})", 
                        peer_name, peer_config.address, session.datagram_capabilities.supported);

                    tokio::select! {
                        _ = connection.closed() => {
                            tracing::info!("Connection to peer {} closed", peer_name);
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::debug!("Shutting down connection to peer {}", peer_name);
                            connection.close(0u32.into(), b"Client shutdown");
                            break;
                        }
                    }

                    sessions.remove(&peer_name);
                    connections.remove(&session.id);
                    
                    if let Some(ref monitor) = health_monitor {
                        monitor.unregister_connection(&session.id);
                    }
                    
                    gauge!("maluwaf.tunnel.quic.client.peers").decrement(1.0);
                }
                Err(e) => {
                    if let Some(ref monitor) = health_monitor {
                        monitor.record_health_check_failure(&peer_name, &e.to_string());
                    }
                    
                    if backoff.attempt() >= max_retries {
                        tracing::error!(
                            "Max retry attempts ({}) reached for peer {}. Giving up.",
                            max_retries, peer_name
                        );
                        counter!("maluwaf.tunnel.quic.client.max_retries_exceeded").increment(1);
                        break;
                    }
                    
                    let delay = backoff.next_delay();
                    
                    tracing::warn!(
                        "Failed to connect to peer {} (attempt {}/{}): {}. Retrying in {:?}",
                        peer_name, backoff.attempt(), max_retries, e, delay
                    );
                    
                    counter!("maluwaf.tunnel.quic.client.connection_errors").increment(1);

                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = shutdown_rx.recv() => {
                            tracing::info!("Stopping reconnection attempts for peer {}", peer_name);
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn connect_to_peer(
        peer_name: &str,
        peer_config: &TunnelQuicPeerConfig,
        runtime: Arc<QuicRuntime>,
    ) -> Result<(QuicClientSession, Connection), Box<dyn std::error::Error + Send + Sync>> {
        let server_name = peer_config.server_name.as_deref()
            .unwrap_or(peer_name);

        let quic_conn = runtime.connect_to_peer(&peer_config.address, server_name).await?;
        
        let connection = quic_conn.connection.clone()
            .ok_or_else(|| "No connection in QuicConnection".to_string())?;

        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let hello = TunnelMessage::PeerHello {
            peer_id: peer_name.to_string(),
            auth_token: peer_config.auth_token.clone(),
            supports_datagrams: runtime.is_datagram_enabled(),
        };
        write_message(&mut send_stream, &hello).await?;

        let response = read_message_default(&mut recv_stream).await?;

        match response {
            TunnelMessage::PeerHelloAck { session_id, supports_datagrams, max_datagram_size } => {
                let datagram_caps = DatagramCapabilities::new(supports_datagrams, max_datagram_size);
                
                let session = QuicClientSession {
                    id: session_id,
                    peer_id: peer_name.to_string(),
                    remote_addr: peer_config.address.clone(),
                    connected_at: std::time::Instant::now(),
                    mappings: HashMap::new(),
                    connection: Some(connection.clone()),
                    datagram_capabilities: datagram_caps,
                };

                Ok((session, connection))
            }
            TunnelMessage::AuthFailure { reason } => {
                Err(format!("Authentication failed: {}", reason).into())
            }
            _ => Err("Unexpected response from peer".into()),
        }
    }

    pub async fn connect_as_client(
        &self,
        client_id: &str,
        auth_token: &str,
        server_addr: &str,
        mappings: HashMap<String, u16>,
    ) -> Result<QuicClientSession, Box<dyn std::error::Error + Send + Sync>> {
        let quic_conn = self.runtime.connect_to_peer(server_addr, client_id).await?;
        
        let connection = quic_conn.connection.clone()
            .ok_or_else(|| "No connection in QuicConnection".to_string())?;

        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let port_mappings: HashMap<String, PortMapping> = mappings.iter()
            .map(|(k, &port)| (k.clone(), PortMapping::new(port, "tcp")))
            .collect();

        let hello = TunnelMessage::Hello {
            client_id: client_id.to_string(),
            auth_token: auth_token.to_string(),
            mappings: port_mappings,
            supports_datagrams: self.runtime.is_datagram_enabled(),
        };
        write_message(&mut send_stream, &hello).await?;

        let response = read_message_default(&mut recv_stream).await?;

        match response {
            TunnelMessage::HelloAck { server_session_id, server_mappings, supports_datagrams, max_datagram_size, access_level } => {
                let datagram_caps = DatagramCapabilities::new(supports_datagrams, max_datagram_size);
                
                tracing::info!("QUIC session established with server, access level: {:?}", access_level);
                
                let session = QuicClientSession {
                    id: server_session_id.clone(),
                    peer_id: client_id.to_string(),
                    remote_addr: server_addr.to_string(),
                    connected_at: std::time::Instant::now(),
                    mappings: Self::convert_mappings(&server_mappings),
                    connection: Some(connection.clone()),
                    datagram_capabilities: datagram_caps,
                };

                self.sessions.insert(client_id.to_string(), session.clone());
                self.connections.insert(session.id.clone(), connection);

                if let Some(ref monitor) = self.health_monitor {
                    monitor.register_connection(session.id.clone(), Some(client_id.to_string()));
                    monitor.set_datagram_capabilities(&session.id, datagram_caps);
                }

                counter!("maluwaf.tunnel.quic.client.sessions").increment(1);
                Ok(session)
            }
            TunnelMessage::AuthFailure { reason } => {
                Err(format!("Authentication failed: {}", reason).into())
            }
            _ => Err("Unexpected response from server".into()),
        }
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

    pub fn get_session(&self, id: &str) -> Option<QuicClientSession> {
        self.sessions.get(id).map(|s| s.clone())
    }

    pub async fn resolve_upstream(&self, identifier: &str) -> Option<(String, u16)> {
        for entry in self.sessions.iter() {
            if let Some(mapping) = entry.mappings.get(identifier) {
                let host = mapping.upstream_host.as_deref().unwrap_or("127.0.0.1");
                let port = mapping.upstream_port.unwrap_or(mapping.port);
                return Some((host.to_string(), port));
            }
        }
        
        None
    }

    pub fn get_connection_for_peer(&self, peer_id: &str) -> Option<QuicConnection> {
        self.sessions.get(peer_id).and_then(|session| {
            session.connection.as_ref().map(|conn| {
                QuicConnection {
                    remote_addr: session.remote_addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid socket address literal")),
                    peer_id: Some(peer_id.to_string()),
                    session_id: session.id.clone(),
                    client_id: peer_id.to_string(),
                    mappings: session.mappings.iter().map(|(k, v)| (k.clone(), v.port)).collect(),
                    connection: Some(conn.clone()),
                    datagram_capabilities: session.datagram_capabilities,
                }
            })
        })
    }

    pub fn list_connected_peers(&self) -> Vec<String> {
        self.sessions.iter().map(|e| e.key().clone()).collect()
    }

    pub async fn open_stream_to_peer(
        &self,
        peer_id: &str,
    ) -> Result<(SendStream, RecvStream), Box<dyn std::error::Error + Send + Sync>> {
        let session = self.sessions.get(peer_id)
            .ok_or_else(|| format!("No session for peer: {}", peer_id))?;
        
        let connection = session.connection.as_ref()
            .ok_or_else(|| format!("No connection for peer: {}", peer_id))?;

        connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e).into())
    }

    pub async fn send_keepalive(&self, peer_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = self.sessions.get(peer_id)
            .ok_or_else(|| format!("No session for peer: {}", peer_id))?;
        
        let connection = session.connection.as_ref()
            .ok_or_else(|| format!("No connection for peer: {}", peer_id))?;

        let start = std::time::Instant::now();
        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        write_message(&mut send_stream, &TunnelMessage::KeepAlive).await?;
        let response = read_message_default(&mut recv_stream).await?;

        let rtt = start.elapsed();
        if let Some(ref monitor) = self.health_monitor {
            monitor.record_health_check_success(&session.id, rtt);
        }

        match response {
            TunnelMessage::KeepAliveAck => Ok(()),
            _ => Err("Unexpected keepalive response".into()),
        }
    }

    pub async fn send_datagram_to_peer(
        &self,
        peer_id: &str,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = self.sessions.get(peer_id)
            .ok_or_else(|| format!("No session for peer: {}", peer_id))?;

        if !session.datagram_capabilities.supported {
            return Err("Datagrams not supported by this peer".into());
        }

        if data.len() > session.datagram_capabilities.max_size {
            return Err(format!(
                "Datagram too large: {} > {}",
                data.len(),
                session.datagram_capabilities.max_size
            ).into());
        }

        let connection = session.connection.as_ref()
            .ok_or_else(|| format!("No connection for peer: {}", peer_id))?;

        connection.send_datagram(data.into())
            .map_err(|e| format!("Failed to send datagram: {}", e))?;

        counter!("maluwaf.tunnel.quic.client.datagrams.sent").increment(1);
        
        if let Some(ref monitor) = self.health_monitor {
            monitor.record_packet_stats(&session.id, 1, 0);
        }

        Ok(())
    }

    pub async fn open_udp_tunnel(
        &self,
        peer_id: &str,
        port: u16,
    ) -> Result<UdpTunnel, Box<dyn std::error::Error + Send + Sync>> {
        let session = self.sessions.get(peer_id)
            .ok_or_else(|| format!("No session for peer: {}", peer_id))?;

        if !session.datagram_capabilities.supported {
            return Err("Datagrams not supported - UDP tunnel unavailable".into());
        }

        let identifier = format!("udp-port-{}", port);
        
        let (mut send_stream, mut recv_stream) = self.open_stream_to_peer(peer_id).await?;
        
        let open_msg = TunnelMessage::UdpTunnelOpen {
            identifier: identifier.clone(),
            port,
        };
        write_message(&mut send_stream, &open_msg).await?;

        let response = read_message_default(&mut recv_stream).await?;
        
        let connection = session.connection.clone()
            .ok_or_else(|| "No connection available".to_string())?;
        
        match response {
            TunnelMessage::UdpTunnelOpenAck { identifier: _, success, message } => {
                if success {
                    counter!("maluwaf.tunnel.quic.client.udp_tunnels.opened").increment(1);
                    Ok(UdpTunnel {
                        identifier,
                        peer_id: peer_id.to_string(),
                        session_id: session.id.clone(),
                        port,
                        max_datagram_size: session.datagram_capabilities.max_size,
                        connection,
                    })
                } else {
                    Err(format!("UDP tunnel open failed: {}", message.unwrap_or_default()).into())
                }
            }
            _ => Err("Unexpected response to UdpTunnelOpen".into()),
        }
    }

    pub async fn close_session(&self, peer_id: &str) {
        if let Some(session) = self.sessions.get(peer_id) {
            if let Some(conn) = &session.connection {
                conn.close(0u32.into(), b"Client closed session");
            }
        }
        self.sessions.remove(peer_id);
    }

    pub async fn open_proxied_stream(
        &self,
        peer_id: &str,
        identifier: &str,
        port: u16,
        protocol: &str,
        tls_passthrough: bool,
    ) -> Result<(SendStream, RecvStream), Box<dyn std::error::Error + Send + Sync>> {
        let session = self.sessions.get(peer_id)
            .ok_or_else(|| format!("No session for peer: {}", peer_id))?;
        
        let connection = session.connection.as_ref()
            .ok_or_else(|| format!("No connection for peer: {}", peer_id))?;

        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let stream_open = TunnelMessage::StreamOpen {
            identifier: identifier.to_string(),
            port,
            protocol: protocol.to_string(),
            tls_passthrough,
        };
        write_message(&mut send_stream, &stream_open).await?;

        let response = read_message_default(&mut recv_stream).await?;

        match response {
            TunnelMessage::StreamOpenAck { success, message, .. } => {
                if success {
                    counter!("maluwaf.tunnel.quic.client.streams.opened").increment(1);
                    Ok((send_stream, recv_stream))
                } else {
                    let msg = message.unwrap_or_else(|| "Unknown error".to_string());
                    Err(format!("Stream open failed: {}", msg).into())
                }
            }
            _ => Err("Unexpected response to StreamOpen".into()),
        }
    }

    pub async fn proxy_tcp_through_peer(
        &self,
        peer_id: &str,
        port: u16,
        tcp_stream: TcpStream,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.proxy_tcp_through_peer_with_tls(peer_id, port, tcp_stream, false).await
    }

    pub async fn proxy_tcp_through_peer_with_tls(
        &self,
        peer_id: &str,
        port: u16,
        mut tcp_stream: TcpStream,
        tls_passthrough: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let identifier = format!("tcp-port-{}", port);
        
        let (mut send_stream, mut recv_stream) = self.open_proxied_stream(peer_id, &identifier, port, "tcp", tls_passthrough).await?;

        let (mut tcp_read, mut tcp_write) = tcp_stream.split();

        let identifier_clone = identifier.clone();
        let tcp_to_quic = async {
            let mut pooled = BufferPool::acquire(64 * 1024);
            let mut sequence: u64 = 0;
            loop {
                match tcp_read.read(pooled.as_mut_slice()).await {
                    Ok(0) => {
                        let fin_msg = TunnelMessage::DataChunk {
                            identifier: identifier_clone.clone(),
                            sequence,
                            data: Vec::new(),
                            fin: true,
                        };
                        let data = fin_msg.encode()
                            .map_err(|e| format!("Encode error: {}", e))?;
                        let len = (data.len() as u32).to_be_bytes();
                        send_stream.write_all(&len).await?;
                        send_stream.write_all(&data).await?;
                        break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                    }
                    Ok(n) => {
                        let data_msg = TunnelMessage::DataChunk {
                            identifier: identifier_clone.clone(),
                            sequence,
                            data: pooled.as_slice()[..n].to_vec(),
                            fin: false,
                        };
                        let data = data_msg.encode()
                            .map_err(|e| format!("Encode error: {}", e))?;
                        let len = (data.len() as u32).to_be_bytes();
                        send_stream.write_all(&len).await?;
                        send_stream.write_all(&data).await?;
                        sequence += 1;
                    }
                    Err(e) => {
                        tracing::debug!("TCP read error for {}: {}", identifier_clone, e);
                        break Err(e.into());
                    }
                }
            }
        };

        let identifier_clone = identifier.clone();
        let max_msg_size = 64 * 1024;
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
                    tracing::warn!("Message size {} exceeds max {} for {}", len, max_msg_size, identifier_clone);
                    break Err(format!("Message too large: {} > {}", len, max_msg_size).into());
                }
                if len > data_pooled.capacity() {
                    data_pooled = BufferPool::acquire(len);
                } else {
                    data_pooled.resize(len);
                }
                recv_stream.read_exact(data_pooled.as_mut_slice()).await?;
                
                let msg = TunnelMessage::decode(data_pooled.as_slice())
                    .ok_or_else(|| "Failed to decode message".to_string())?;
                
                match msg {
                    TunnelMessage::DataChunk { data, fin, .. } => {
                        if !data.is_empty() {
                            tcp_write.write_all(&data).await?;
                        }
                        if fin {
                            break Ok(());
                        }
                    }
                    TunnelMessage::StreamClose { .. } => break Ok(()),
                    _ => {}
                }
            }
        };

        counter!("maluwaf.tunnel.quic.client.streams.proxied").increment(1);
        let start = std::time::Instant::now();
        
        let result = tokio::try_join!(tcp_to_quic, quic_to_tcp);
        
        histogram!("maluwaf.tunnel.quic.client.stream_duration").record(start.elapsed());
        counter!("maluwaf.tunnel.quic.client.streams.closed").increment(1);
        
        let _ = send_stream.finish();
        
        result.map(|_| ())
    }

    pub fn get_connection_quality(&self, peer_id: &str) -> Option<ConnectionQuality> {
        let session = self.sessions.get(peer_id)?;
        self.health_monitor.as_ref()?.get_connection_quality(&session.id)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

pub struct UdpTunnel {
    pub identifier: String,
    pub peer_id: String,
    pub session_id: String,
    pub port: u16,
    pub max_datagram_size: usize,
    connection: Connection,
}

impl UdpTunnel {
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn send_datagram(
        &self,
        data: &[u8],
        source_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = DatagramMessage::new(
            self.identifier.clone(),
            0,
            data.to_vec(),
            self.port,
            source_addr.to_string(),
        );
        
        let encoded = msg.encode()
            .map_err(|e| format!("Failed to encode datagram: {}", e))?;
        
        if encoded.len() > self.max_datagram_size {
            return Err(format!(
                "Datagram too large: {} > {}",
                encoded.len(),
                self.max_datagram_size
            ).into());
        }
        
        self.connection.send_datagram(encoded.into())
            .map_err(|e| format!("Failed to send datagram: {}", e))?;
        
        counter!("maluwaf.tunnel.quic.client.udp_datagrams.sent").increment(1);
        
        Ok(())
    }
}

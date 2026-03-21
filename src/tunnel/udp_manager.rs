use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use metrics::{counter, gauge, histogram};
use quinn::{Connection, RecvStream};
use tokio::sync::{broadcast, mpsc};

use super::quic::messages::{DatagramMessage, TunnelMessage};
use super::quic::registry::QUIC_TUNNEL_REGISTRY;
use super::quic::framing::{read_message, write_message};

const DEFAULT_UDP_TUNNEL_TIMEOUT_SECS: u64 = 60;
const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;
const HEADER_OVERHEAD: usize = 128;

pub struct UdpTunnelManager {
    tunnels: Arc<DashMap<String, ActiveUdpTunnel>>,
    tunnel_timeout: Duration,
    max_datagram_size: usize,
    shutdown_tx: broadcast::Sender<()>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct ActiveUdpTunnel {
    pub identifier: String,
    pub peer_id: String,
    pub port: u16,
    pub max_datagram_size: usize,
    pub connection: Connection,
    pub created_at: Instant,
    pub last_activity: Arc<std::sync::RwLock<Instant>>,
    pending_requests: Arc<DashMap<u64, PendingRequest>>,
    sequence: Arc<AtomicU64>,
    response_tx: mpsc::Sender<UdpResponse>,
}

#[derive(Clone)]
pub struct PendingRequest {
    pub client_addr: SocketAddr,
    pub timestamp: Instant,
    pub dns_transaction_id: Option<u16>,
}

pub struct UdpResponse {
    pub client_addr: SocketAddr,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct UdpTunnelConfig {
    pub tunnel_timeout_secs: u64,
    pub max_datagram_size: usize,
}

impl Default for UdpTunnelConfig {
    fn default() -> Self {
        Self {
            tunnel_timeout_secs: DEFAULT_UDP_TUNNEL_TIMEOUT_SECS,
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
        }
    }
}

impl UdpTunnelManager {
    pub fn new(config: UdpTunnelConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        Self {
            tunnels: Arc::new(DashMap::new()),
            tunnel_timeout: Duration::from_secs(config.tunnel_timeout_secs),
            max_datagram_size: config.max_datagram_size,
            shutdown_tx,
        }
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.tunnel_timeout = Duration::from_secs(timeout_secs);
        self
    }

    pub async fn get_or_open_tunnel(
        &self,
        peer_id: &str,
        port: u16,
    ) -> Result<Arc<ActiveUdpTunnel>, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("{}:{}", peer_id, port);
        
        if let Some(tunnel) = self.tunnels.get(&key) {
            *tunnel.last_activity.write().unwrap() = Instant::now();
            return Ok(Arc::new(tunnel.clone()));
        }
        
        let runtime = QUIC_TUNNEL_REGISTRY.get_runtime().await
            .ok_or_else(|| "QUIC tunnel runtime not available".to_string())?;
        
        let session = runtime.get_session_by_peer(peer_id)
            .ok_or_else(|| format!("No session found for peer: {}", peer_id))?;
        
        let connection = session.connection.clone()
            .ok_or_else(|| "No active connection for session".to_string())?;
        
        let identifier = format!("udp-port-{}", port);
        
        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| format!("Failed to open bidirectional stream: {}", e))?;
        
        let open_msg = TunnelMessage::UdpTunnelOpen {
            identifier: identifier.clone(),
            port,
        };
        write_message(&mut send_stream, &open_msg).await
            .map_err(|e| format!("Failed to send UdpTunnelOpen: {}", e))?;
        
        let response = read_message(&mut recv_stream, 65536).await
            .map_err(|e| format!("Failed to read UdpTunnelOpenAck: {}", e))?;
        
        match response {
            TunnelMessage::UdpTunnelOpenAck { success, message, .. } => {
                if !success {
                    return Err(format!("UDP tunnel open failed: {}", message.unwrap_or_default()).into());
                }
            }
            _ => return Err("Unexpected response to UdpTunnelOpen".into()),
        }
        
        counter!("maluwaf.tunnel.udp.tunnels.opened").increment(1);
        
        let (response_tx, response_rx) = mpsc::channel::<UdpResponse>(256);
        
        let tunnel = ActiveUdpTunnel {
            identifier: identifier.clone(),
            peer_id: peer_id.to_string(),
            port,
            max_datagram_size: session.datagram_capabilities.max_size.min(self.max_datagram_size),
            connection,
            created_at: Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
            pending_requests: Arc::new(DashMap::new()),
            sequence: Arc::new(AtomicU64::new(0)),
            response_tx,
        };
        
        self.tunnels.insert(key.clone(), tunnel.clone());
        gauge!("maluwaf.tunnel.udp.tunnels.active").set(self.tunnels.len() as f64);
        
        self.spawn_response_handler(tunnel.clone(), recv_stream, response_rx);
        
        Ok(Arc::new(tunnel))
    }

    fn spawn_response_handler(
        &self,
        tunnel: ActiveUdpTunnel,
        _recv_stream: RecvStream,
        _response_rx: mpsc::Receiver<UdpResponse>,
    ) {
        let connection = tunnel.connection.clone();
        let pending_requests = tunnel.pending_requests.clone();
        let identifier = tunnel.identifier.clone();
        let tunnel_key = format!("{}:{}", tunnel.peer_id, tunnel.port);
        let tunnels = self.tunnels.clone();
        
        tokio::spawn(async move {
            loop {
                match connection.read_datagram().await {
                    Ok(data) => {
                        if let Some(msg) = DatagramMessage::decode(&data) {
                            if msg.identifier != identifier {
                                continue;
                            }
                            
                            if let Some((_, pending)) = pending_requests.remove(&msg.sequence) {
                                counter!("maluwaf.tunnel.udp.responses.routed").increment(1);
                                histogram!("maluwaf.tunnel.udp.response_latency")
                                    .record(pending.timestamp.elapsed().as_millis() as f64);
                                
                                // Route response back to client
                                // This will be handled by the UDP listener
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Datagram read error for {}: {}", identifier, e);
                        tunnels.remove(&tunnel_key);
                        break;
                    }
                }
            }
        });
    }

    pub async fn send(
        &self,
        peer_id: &str,
        port: u16,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tunnel = self.get_or_open_tunnel(peer_id, port).await?;
        tunnel.send(data, client_addr).await
    }

    pub async fn send_with_dns_tracking(
        &self,
        peer_id: &str,
        port: u16,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tunnel = self.get_or_open_tunnel(peer_id, port).await?;
        
        let dns_transaction_id = if data.len() >= 2 {
            Some(u16::from_be_bytes([data[0], data[1]]))
        } else {
            None
        };
        
        tunnel.send_with_tracking(data, client_addr, dns_transaction_id).await
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }

    pub fn cleanup_idle_tunnels(&self) {
        let now = Instant::now();
        let keys_to_remove: Vec<String> = self.tunnels.iter()
            .filter_map(|entry| {
                let last_activity = *entry.last_activity.read().unwrap();
                if now.duration_since(last_activity) > self.tunnel_timeout {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        
        let removed = keys_to_remove.len();
        for key in keys_to_remove {
            self.tunnels.remove(&key);
        }
        
        if removed > 0 {
            counter!("maluwaf.tunnel.udp.tunnels.cleaned").increment(removed as u64);
            gauge!("maluwaf.tunnel.udp.tunnels.active").set(self.tunnels.len() as f64);
            tracing::debug!("Cleaned up {} idle UDP tunnels", removed);
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

impl ActiveUdpTunnel {
    pub async fn send(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        
        let effective_max = self.max_datagram_size.saturating_sub(HEADER_OVERHEAD);
        
        if data.len() <= effective_max {
            self.send_datagram(data, client_addr, sequence).await
        } else {
            self.send_stream(data, client_addr, sequence).await
        }
    }

    pub async fn send_with_tracking(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        dns_transaction_id: Option<u16>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        
        self.pending_requests.insert(sequence, PendingRequest {
            client_addr,
            timestamp: Instant::now(),
            dns_transaction_id,
        });
        
        counter!("maluwaf.tunnel.udp.requests.tracked").increment(1);
        
        self.send(data, client_addr).await
    }

    async fn send_datagram(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        sequence: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = DatagramMessage::new(
            self.identifier.clone(),
            sequence,
            data.to_vec(),
            self.port,
            client_addr.to_string(),
        );
        
        let encoded = msg.encode()
            .map_err(|e| format!("Failed to encode datagram: {}", e))?;
        
        if encoded.len() > self.max_datagram_size {
            return self.send_stream(data, client_addr, sequence).await;
        }
        
        self.connection.send_datagram(encoded.into())
            .map_err(|e| format!("Failed to send datagram: {}", e))?;
        
        counter!("maluwaf.tunnel.udp.datagrams.sent").increment(1);
        histogram!("maluwaf.tunnel.udp.packet_size").record(data.len() as f64);
        
        Ok(())
    }

    async fn send_stream(
        &self,
        data: &[u8],
        _client_addr: SocketAddr,
        sequence: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        counter!("maluwaf.tunnel.udp.stream_fallback").increment(1);
        
        let (mut send_stream, _) = self.connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;
        
        let msg = TunnelMessage::DataChunk {
            identifier: self.identifier.clone(),
            sequence,
            data: data.to_vec(),
            fin: true,
        };
        
        write_message(&mut send_stream, &msg).await
            .map_err(|e| format!("Failed to write data chunk: {}", e))?;
        
        send_stream.finish()
            .map_err(|e| format!("Failed to finish stream: {}", e))?;
        
        counter!("maluwaf.tunnel.udp.streams.sent").increment(1);
        histogram!("maluwaf.tunnel.udp.large_packet_size").record(data.len() as f64);
        
        Ok(())
    }

    pub fn get_pending_request(&self, sequence: u64) -> Option<PendingRequest> {
        self.pending_requests.get(&sequence).map(|r| r.clone())
    }

    pub fn find_pending_by_dns_id(&self, dns_id: u16) -> Option<(u64, PendingRequest)> {
        for entry in self.pending_requests.iter() {
            if entry.dns_transaction_id == Some(dns_id) {
                return Some((*entry.key(), entry.clone()));
            }
        }
        None
    }

    pub fn remove_pending(&self, sequence: u64) -> Option<PendingRequest> {
        self.pending_requests.remove(&sequence).map(|(_, v)| v)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        let last_activity = *self.last_activity.read().unwrap();
        last_activity.elapsed() > timeout
    }
}

pub fn extract_dns_transaction_id(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_be_bytes([data[0], data[1]]))
    } else {
        None
    }
}

pub fn extract_dns_response_id(data: &[u8]) -> Option<u16> {
    extract_dns_transaction_id(data)
}

pub struct UdpTunnelStats {
    pub active_tunnels: usize,
    pub total_pending_requests: usize,
}

impl UdpTunnelManager {
    pub fn stats(&self) -> UdpTunnelStats {
        let mut total_pending = 0;
        for tunnel in self.tunnels.iter() {
            total_pending += tunnel.pending_count();
        }
        
        UdpTunnelStats {
            active_tunnels: self.tunnels.len(),
            total_pending_requests: total_pending,
        }
    }
}

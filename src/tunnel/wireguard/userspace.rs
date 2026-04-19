#![allow(unused_variables, dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use metrics::{counter, gauge};
use tokio::sync::{broadcast, mpsc};

use super::config::{WireGuardConfig, WireGuardPeerConfig};
use super::session::{WgConnectionStats, WgPeerSession, WgSessionManager};
use crate::tunnel::tun::{is_tun_available, TunInterface};
#[cfg(feature = "tun-rs")]
use crate::tunnel::tun::{TunReader, TunWriter};
use crate::tunnel::{PeerInfo, TunnelStats, TunnelTransport, TunnelType};

const MAX_PACKET_SIZE: usize = 65535;
const QUEUE_SIZE: usize = 1024;

pub struct UserspaceWireGuard {
    config: WireGuardConfig,
    sessions: Arc<WgSessionManager>,
    stats: Arc<DashMap<String, WgConnectionStats>>,
    tun: Option<Arc<TunInterface>>,
    shutdown_tx: broadcast::Sender<()>,
    running: bool,
    interface_name: String,
    tx_queue: mpsc::Sender<Vec<u8>>,
    tx_queue_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

pub struct BoringtunPeer {
    public_key: [u8; 32],
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<ipnetwork::IpNetwork>,
    persistent_keepalive: Option<Duration>,
    last_handshake: Option<Instant>,
    tx_bytes: u64,
    rx_bytes: u64,
}

pub struct BoringtunState {
    peers: DashMap<[u8; 32], BoringtunPeer>,
    private_key: [u8; 32],
    started: bool,
}

impl BoringtunState {
    pub fn new(private_key: [u8; 32]) -> Self {
        Self {
            peers: DashMap::new(),
            private_key,
            started: false,
        }
    }

    pub fn add_peer(&self, peer: BoringtunPeer) {
        self.peers.insert(peer.public_key, peer);
    }

    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        self.peers.remove(public_key);
    }

    pub fn get_peer(&self, public_key: &[u8; 32]) -> Option<BoringtunPeer> {
        self.peers.get(public_key).map(|p| p.clone())
    }

    pub fn list_peers(&self) -> Vec<BoringtunPeer> {
        self.peers.iter().map(|p| p.clone()).collect()
    }
}

impl Clone for BoringtunPeer {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key,
            endpoint: self.endpoint,
            allowed_ips: self.allowed_ips.clone(),
            persistent_keepalive: self.persistent_keepalive,
            last_handshake: self.last_handshake,
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
        }
    }
}

impl UserspaceWireGuard {
    pub fn new(config: WireGuardConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let sessions = Arc::new(WgSessionManager::new());
        let stats = Arc::new(DashMap::new());
        let (tx_queue, tx_queue_rx) = mpsc::channel(QUEUE_SIZE);

        let interface_name = config.interface_name.clone();

        tracing::info!(
            "Userspace WireGuard initialized: interface={}, port={}",
            interface_name,
            config.listen_port
        );

        Ok(Self {
            config,
            sessions,
            stats,
            tun: None,
            shutdown_tx,
            running: false,
            interface_name,
            tx_queue,
            tx_queue_rx: Some(tx_queue_rx),
        })
    }

    fn decode_private_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let decoded = STANDARD
            .decode(&self.config.private_key)
            .map_err(|e| format!("Failed to decode private key: {}", e))?;

        if decoded.len() != 32 {
            return Err(format!("Invalid private key length: {}", decoded.len()).into());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    #[cfg(feature = "wireguard")]
    async fn start_boringtun(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use defguard_boringtun::noise::{Tunn, TunnResult};
        use defguard_boringtun::x25519::StaticSecret;

        tracing::info!("Starting boringtun userspace WireGuard");

        let private_key = self.decode_private_key()?;
        let secret = StaticSecret::from(private_key);

        let tun_config = TunConfig::new(
            &self.interface_name,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
        )
        .with_mtu(self.config.mtu);

        let (tun, async_device) = TunInterface::create(tun_config)?;
        let tun = Arc::new(tun);
        let async_device = Arc::new(async_device);
        self.tun = Some(tun);

        for peer_config in &self.config.peers {
            let peer_public_key = super::config::base64_decode_key(&peer_config.public_key)
                .ok_or_else(|| format!("Invalid peer public key: {}", peer_config.public_key))?;

            let endpoint: Option<SocketAddr> =
                peer_config.endpoint.as_ref().and_then(|s| s.parse().ok());

            let allowed_ips: Vec<ipnetwork::IpNetwork> = peer_config
                .allowed_ips
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            let peer_session = WgPeerSession::new(
                peer_config.public_key.clone(),
                peer_config.allowed_ips.clone(),
            )
            .with_endpoint(peer_config.endpoint.clone().unwrap_or_default());

            self.sessions.add_session(peer_session);
            counter!("maluwaf.tunnel.wireguard.peers.added").increment(1);
        }

        self.running = true;
        gauge!("maluwaf.tunnel.wireguard.running").set(1.0);

        tracing::info!(
            "boringtun WireGuard started with {} peers",
            self.config.peers.len()
        );

        Ok(())
    }

    #[cfg(not(feature = "wireguard"))]
    async fn start_boringtun(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::warn!("WireGuard userspace support not compiled in (enable 'wireguard' feature)");

        for peer_config in &self.config.peers {
            let peer_session = WgPeerSession::new(
                peer_config.public_key.clone(),
                peer_config.allowed_ips.clone(),
            )
            .with_endpoint(peer_config.endpoint.clone().unwrap_or_default());

            self.sessions.add_session(peer_session);
        }

        self.running = true;
        gauge!("maluwaf.tunnel.wireguard.running").set(1.0);

        tracing::info!("WireGuard userspace peer session started (no tunnel - wireguard feature not compiled in)");
        Ok(())
    }

    pub fn add_peer(
        &self,
        peer_config: WireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let peer_session = WgPeerSession::new(
            peer_config.public_key.clone(),
            peer_config.allowed_ips.clone(),
        )
        .with_endpoint(peer_config.endpoint.clone().unwrap_or_default());

        self.sessions.add_session(peer_session);

        tracing::info!("Added WireGuard peer: {}", peer_config.public_key);
        Ok(())
    }

    pub fn remove_peer(
        &self,
        public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(session) = self.sessions.get_session_by_public_key(public_key) {
            self.sessions.remove_session(&session.id);
            tracing::info!("Removed WireGuard peer: {}", public_key);
        }
        Ok(())
    }

    pub async fn send_datagram(
        &self,
        peer_public_key: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session = self
            .sessions
            .get_session_by_public_key(peer_public_key)
            .ok_or_else(|| format!("Peer not found: {}", peer_public_key))?;

        if !session.is_established() {
            return Err("Session not established".into());
        }

        self.tx_queue
            .send(data.to_vec())
            .await
            .map_err(|e| format!("Failed to queue packet: {}", e))?;

        self.sessions.update_session(&session.id, |s| {
            s.add_tx_bytes(data.len() as u64);
        });

        counter!("maluwaf.tunnel.wireguard.packets.sent").increment(1);

        Ok(())
    }

    pub fn session_manager(&self) -> &WgSessionManager {
        &self.sessions
    }

    #[cfg(feature = "tun-rs")]
    fn spawn_packet_handler(&mut self, device: Arc<crate::tunnel::tun::AsyncTunDevice>) {
        let shutdown_rx = self.shutdown_tx.subscribe();
        let sessions = self.sessions.clone();
        let tx_queue_rx = self.tx_queue_rx.take();

        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let mut rx_buf = vec![0u8; MAX_PACKET_SIZE];

            if let Some(mut tx_queue) = tx_queue_rx {
                loop {
                    tokio::select! {
                        result = device.read_packet(&mut rx_buf) => {
                            match result {
                                Ok(n) if n > 0 => {
                                    let packet = TunPacket::new(rx_buf[..n].to_vec());

                                    if let Some(src) = packet.src_addr() {
                                        tracing::trace!("Received packet from TUN: {} bytes, src={}", n, src);
                                    }

                                    counter!("maluwaf.tunnel.wireguard.packets.received").increment(1);
                                    counter!("maluwaf.tunnel.wireguard.bytes.received").increment(n as u64);
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::trace!("TUN read error: {}", e);
                                }
                            }
                        }
                        Some(data) = tx_queue.recv() => {
                            let packet = TunPacket::new(data);
                            match device.write_packet(packet.data()).await {
                                Ok(_n) => {
                                    counter!("maluwaf.tunnel.wireguard.packets.sent").increment(1);
                                }
                                Err(e) => {
                                    tracing::trace!("TUN write error: {}", e);
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            tracing::debug!("Packet handler shutting down");
                            break;
                        }
                    }
                }
            }
        });
    }
}

#[async_trait]
impl TunnelTransport for UserspaceWireGuard {
    fn tunnel_type(&self) -> TunnelType {
        TunnelType::WireGuard
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.start_boringtun().await
    }

    async fn stop(&mut self) {
        self.running = false;
        gauge!("maluwaf.tunnel.wireguard.running").set(0.0);

        for session in self.sessions.list_sessions() {
            self.sessions.remove_session(&session.id);
        }

        self.tun = None;

        tracing::info!("WireGuard stopped");
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn stats(&self) -> TunnelStats {
        let mut total_tx = 0u64;
        let mut total_rx = 0u64;

        for session in self.sessions.list_sessions() {
            total_tx += session.tx_bytes;
            total_rx += session.rx_bytes;
        }

        TunnelStats {
            bytes_sent: total_tx,
            bytes_received: total_rx,
            packets_sent: 0,
            packets_received: 0,
            latency_ms: None,
            connected_at: None,
        }
    }

    fn local_address(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            self.config.listen_port,
        ))
    }

    fn peer_count(&self) -> usize {
        self.sessions.session_count()
    }

    fn peers(&self) -> Vec<PeerInfo> {
        self.sessions
            .list_sessions()
            .into_iter()
            .map(|s| PeerInfo {
                id: s.public_key,
                endpoint: s.endpoint,
                allowed_ips: s.allowed_ips,
                last_handshake: s.last_handshake,
                bytes_sent: s.tx_bytes,
                bytes_received: s.rx_bytes,
            })
            .collect()
    }

    fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

pub async fn is_userspace_available() -> bool {
    cfg!(feature = "wireguard") && is_tun_available()
}

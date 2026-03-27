pub mod quic;
pub mod router;
pub mod tun;
pub mod udp_manager;
pub mod upstream;
pub mod wireguard;

pub use quic::{
    QuicConnection, QuicRuntime, QuicTunnelRegistry, TunnelSessionInfo, QUIC_TUNNEL_REGISTRY,
};
pub use router::{TunnelBackend, TunnelMapping, TunnelRouteSession, TunnelRouter};
pub use tun::{
    is_tun_available, AsyncTunDevice, TunConfig, TunInterface, TunPacket, TunProtocol, TunReader,
    TunWriter,
};
pub use udp_manager::{
    ActiveUdpTunnel, PendingRequest, UdpResponse, UdpTunnelConfig, UdpTunnelManager,
};
pub use upstream::TunnelUpstreamResolver;
pub use wireguard::{
    detect_available_implementation, generate_keypair, is_wireguard_available, WgImplementation,
    WgSessionInfo, WireGuardClient, WireGuardClientConfig, WireGuardConfig, WireGuardPeerConfig,
    WireGuardRuntime, WireGuardServer, WireGuardServerConfig, WireGuardServerWrapper,
    WG_TUNNEL_REGISTRY,
};

use std::collections::HashMap;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::config::TunnelConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelType {
    Quic,
    WireGuard,
}

#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub latency_ms: Option<u64>,
    pub connected_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_handshake: Option<std::time::Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[async_trait]
pub trait TunnelTransport: Send + Sync {
    fn tunnel_type(&self) -> TunnelType;

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    async fn stop(&mut self);

    fn is_running(&self) -> bool;

    fn stats(&self) -> TunnelStats;

    fn local_address(&self) -> Option<std::net::SocketAddr>;

    fn peer_count(&self) -> usize;

    fn peers(&self) -> Vec<PeerInfo>;

    fn shutdown(&self);
}

#[derive(Debug, Clone)]
pub struct TunnelPortForward {
    pub session_id: String,
    pub identifier: String,
    pub target_port: u16,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TunnelManager {
    config: TunnelConfig,
    sessions: Arc<RwLock<HashMap<String, TunnelSession>>>,
    shutdown_tx: broadcast::Sender<()>,
}

#[derive(Debug, Clone)]
pub struct TunnelSession {
    pub id: String,
    pub remote_addr: String,
    pub connected_at: std::time::Instant,
    pub mappings: HashMap<String, u16>,
}

impl TunnelManager {
    pub fn new(config: TunnelConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
        }
    }

    pub async fn add_session(&self, session: TunnelSession) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), session);
        tracing::info!("Tunnel session added: {}", sessions.len());
    }

    pub async fn remove_session(&self, id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(id);
        tracing::info!("Tunnel session removed: {} remaining", sessions.len());
    }

    pub async fn get_session(&self, id: &str) -> Option<TunnelSession> {
        let sessions = self.sessions.read().await;
        sessions.get(id).cloned()
    }

    pub async fn resolve_tunnel_endpoint(&self, tunnel_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        sessions
            .get(tunnel_id)
            .map(|s| format!("tunnel://{}", s.id))
    }

    pub async fn list_sessions(&self) -> Vec<TunnelSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

impl TunnelSession {
    pub fn new(id: String, remote_addr: String, mappings: HashMap<String, u16>) -> Self {
        Self {
            id,
            remote_addr,
            connected_at: std::time::Instant::now(),
            mappings,
        }
    }

    pub fn get_local_port(&self, tunnel_identifier: &str) -> Option<u16> {
        self.mappings.get(tunnel_identifier).copied()
    }
}

use std::net::SocketAddr;

pub struct TunnelConnection {
    pub session_id: String,
    pub remote_addr: SocketAddr,
    pub tunnel_identifier: String,
    pub local_port: u16,
}

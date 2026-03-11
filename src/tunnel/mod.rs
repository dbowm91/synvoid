pub mod quic;
pub mod upstream;
pub mod wireguard;
pub mod waf_peers;
pub mod router;

pub use quic::{TunnelMessage, QuicRuntime, QuicConnection, QUIC_TUNNEL_REGISTRY, QuicTunnelRegistry, TunnelSessionInfo};
pub use upstream::TunnelUpstreamResolver;
pub use wireguard::WireGuardServer;
pub use waf_peers::{WafPeerServer, PeerConnection, PeerMessage};
pub use router::{TunnelRouter, TunnelBackend, TunnelRouteSession, TunnelMapping};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::broadcast;

use crate::config::main::{TunnelConfig, TunnelWafPeersConfig};

#[derive(Debug, Clone)]
pub struct TunnelPortForward {
    pub session_id: String,
    pub identifier: String,
    pub target_port: u16,
}

#[derive(Debug, Clone)]
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

    pub fn peer_config(&self) -> Option<&TunnelWafPeersConfig> {
        if self.config.waf_peers.enabled {
            Some(&self.config.waf_peers)
        } else {
            None
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
        sessions.get(tunnel_id).map(|s| format!("tunnel://{}", s.id))
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

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use quinn::{SendStream, RecvStream};

use super::runtime::QuicRuntime;

#[derive(Clone)]
pub struct QuicTunnelRegistry {
    sessions: Arc<RwLock<HashMap<String, TunnelSessionInfo>>>,
    runtime: Arc<RwLock<Option<Arc<QuicRuntime>>>>,
}

#[derive(Clone)]
pub struct TunnelSessionInfo {
    pub session_id: String,
    pub client_id: String,
    pub peer_id: Option<String>,
    pub remote_addr: String,
    pub mappings: HashMap<String, u16>,
}

impl QuicTunnelRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            runtime: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_runtime(&self, runtime: Arc<QuicRuntime>) {
        let mut r = self.runtime.write().await;
        *r = Some(runtime);
    }

    pub async fn get_runtime(&self) -> Option<Arc<QuicRuntime>> {
        let r = self.runtime.read().await;
        r.clone()
    }

    pub async fn register(&self, info: TunnelSessionInfo) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(info.session_id.clone(), info);
        tracing::debug!("Tunnel session registered: {}", sessions.len());
    }

    pub async fn unregister(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
        tracing::debug!("Tunnel session unregistered: {}", sessions.len());
    }

    pub async fn get(&self, session_id: &str) -> Option<TunnelSessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn get_by_client_id(&self, client_id: &str) -> Option<TunnelSessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.values().find(|s| s.client_id == client_id).cloned()
    }

    pub async fn get_by_peer_id(&self, peer_id: &str) -> Option<TunnelSessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.values().find(|s| s.peer_id.as_deref() == Some(peer_id)).cloned()
    }

    pub async fn list(&self) -> Vec<TunnelSessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    pub async fn find_by_port(&self, port: u16) -> Option<TunnelSessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.values()
            .find(|s| s.mappings.values().any(|&p| p == port))
            .cloned()
    }
}

impl Default for QuicTunnelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    pub static ref QUIC_TUNNEL_REGISTRY: QuicTunnelRegistry = QuicTunnelRegistry::new();
}

pub struct QuicTunnelProxy {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl QuicTunnelProxy {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

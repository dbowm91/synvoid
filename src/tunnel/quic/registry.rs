use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;
use quinn::{SendStream, RecvStream};
use once_cell::sync::Lazy;

use super::runtime::QuicRuntime;

#[derive(Clone)]
pub struct QuicTunnelRegistry {
    sessions: DashMap<String, TunnelSessionInfo>,
    sessions_by_client: DashMap<String, String>,
    sessions_by_peer: DashMap<String, String>,
    runtime: Arc<std::sync::RwLock<Option<Arc<QuicRuntime>>>>,
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
            sessions: DashMap::new(),
            sessions_by_client: DashMap::new(),
            sessions_by_peer: DashMap::new(),
            runtime: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    pub async fn set_runtime(&self, runtime: Arc<QuicRuntime>) {
        let mut r = self.runtime.write().unwrap();
        *r = Some(runtime);
    }

    pub async fn get_runtime(&self) -> Option<Arc<QuicRuntime>> {
        let r = self.runtime.read().unwrap();
        r.clone()
    }

    pub async fn register(&self, info: TunnelSessionInfo) {
        let session_id = info.session_id.clone();
        let client_id = info.client_id.clone();
        
        if let Some(ref peer_id) = info.peer_id {
            self.sessions_by_peer.insert(peer_id.clone(), session_id.clone());
        }
        
        self.sessions_by_client.insert(client_id, session_id.clone());
        self.sessions.insert(session_id, info);
        
        tracing::trace!("Tunnel session registered: {}", self.sessions.len());
    }

    pub async fn unregister(&self, session_id: &str) {
        if let Some((_, info)) = self.sessions.remove(session_id) {
            self.sessions_by_client.remove(&info.client_id);
            if let Some(peer_id) = info.peer_id {
                self.sessions_by_peer.remove(&peer_id);
            }
        }
        tracing::trace!("Tunnel session unregistered: {}", self.sessions.len());
    }

    pub async fn get(&self, session_id: &str) -> Option<TunnelSessionInfo> {
        self.sessions.get(session_id).map(|r| r.clone())
    }

    pub async fn get_by_client_id(&self, client_id: &str) -> Option<TunnelSessionInfo> {
        let session_id = self.sessions_by_client.get(client_id)?;
        self.sessions.get(session_id.value()).map(|r| r.clone())
    }

    pub async fn get_by_peer_id(&self, peer_id: &str) -> Option<TunnelSessionInfo> {
        let session_id = self.sessions_by_peer.get(peer_id)?;
        self.sessions.get(session_id.value()).map(|r| r.clone())
    }

    pub async fn list(&self) -> Vec<TunnelSessionInfo> {
        self.sessions.iter().map(|r| r.clone()).collect()
    }

    pub async fn find_by_port(&self, port: u16) -> Option<TunnelSessionInfo> {
        for entry in self.sessions.iter() {
            if entry.mappings.values().any(|&p| p == port) {
                return Some(entry.clone());
            }
        }
        None
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for QuicTunnelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub static QUIC_TUNNEL_REGISTRY: Lazy<QuicTunnelRegistry> = Lazy::new(QuicTunnelRegistry::new);

pub struct QuicTunnelProxy {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl QuicTunnelProxy {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

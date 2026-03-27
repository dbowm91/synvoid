use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use metrics::{counter, gauge};
use std::sync::LazyLock;
use tokio::sync::broadcast;

pub static WG_TUNNEL_REGISTRY: LazyLock<WgTunnelRegistry> = LazyLock::new(WgTunnelRegistry::new);

#[derive(Debug, Clone)]
pub struct WgSessionInfo {
    pub session_id: String,
    pub peer_public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub connected_at: Instant,
    pub last_handshake: Option<Instant>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

pub struct WgTunnelRegistry {
    sessions: DashMap<String, WgSessionInfo>,
}

impl WgTunnelRegistry {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn register(&self, session: WgSessionInfo) {
        let session_id = session.session_id.clone();
        self.sessions.insert(session_id.clone(), session);

        counter!("maluwaf.tunnel.wireguard.sessions.created").increment(1);
        gauge!("maluwaf.tunnel.wireguard.sessions.active").set(self.sessions.len() as f64);

        tracing::debug!(
            "WireGuard session registered: {} (total: {})",
            session_id,
            self.sessions.len()
        );
    }

    pub fn unregister(&self, session_id: &str) {
        if self.sessions.remove(session_id).is_some() {
            counter!("maluwaf.tunnel.wireguard.sessions.closed").increment(1);
            gauge!("maluwaf.tunnel.wireguard.sessions.active").set(self.sessions.len() as f64);

            tracing::debug!(
                "WireGuard session unregistered: {} (remaining: {})",
                session_id,
                self.sessions.len()
            );
        }
    }

    pub fn get(&self, session_id: &str) -> Option<WgSessionInfo> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    pub fn get_by_public_key(&self, public_key: &str) -> Option<WgSessionInfo> {
        self.sessions
            .iter()
            .find(|s| s.peer_public_key == public_key)
            .map(|s| s.clone())
    }

    pub fn list(&self) -> Vec<WgSessionInfo> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn update_stats(&self, session_id: &str, tx_bytes: u64, rx_bytes: u64) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.tx_bytes = tx_bytes;
            session.rx_bytes = rx_bytes;
        }
    }

    pub fn update_handshake(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.last_handshake = Some(Instant::now());
        }
    }
}

impl Default for WgTunnelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct WgSessionManager {
    sessions: Arc<DashMap<String, WgPeerSession>>,
    shutdown_tx: broadcast::Sender<()>,
}

#[derive(Debug, Clone)]
pub struct WgPeerSession {
    pub id: String,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub created_at: Instant,
    pub last_handshake: Option<Instant>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub state: WgSessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgSessionState {
    Initializing,
    Handshaking,
    Established,
    Rekeying,
    Disconnected,
    Error,
}

impl WgPeerSession {
    pub fn new(public_key: String, allowed_ips: Vec<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            public_key,
            endpoint: None,
            allowed_ips,
            created_at: Instant::now(),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            state: WgSessionState::Initializing,
        }
    }

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn update_handshake(&mut self) {
        self.last_handshake = Some(Instant::now());
        self.state = WgSessionState::Established;
    }

    pub fn add_tx_bytes(&mut self, bytes: u64) {
        self.tx_bytes = self.tx_bytes.saturating_add(bytes);
    }

    pub fn add_rx_bytes(&mut self, bytes: u64) {
        self.rx_bytes = self.rx_bytes.saturating_add(bytes);
    }

    pub fn is_established(&self) -> bool {
        matches!(self.state, WgSessionState::Established)
    }

    pub fn seconds_since_handshake(&self) -> Option<u64> {
        self.last_handshake.map(|t| t.elapsed().as_secs())
    }

    pub fn needs_rekey(&self, rekey_interval_secs: u64) -> bool {
        match self.last_handshake {
            Some(t) => t.elapsed().as_secs() > rekey_interval_secs,
            None => true,
        }
    }

    pub fn to_info(&self) -> WgSessionInfo {
        WgSessionInfo {
            session_id: self.id.clone(),
            peer_public_key: self.public_key.clone(),
            endpoint: self.endpoint.clone(),
            allowed_ips: self.allowed_ips.clone(),
            connected_at: self.created_at,
            last_handshake: self.last_handshake,
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
        }
    }
}

impl WgSessionManager {
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            sessions: Arc::new(DashMap::new()),
            shutdown_tx,
        }
    }

    pub fn add_session(&self, session: WgPeerSession) {
        let id = session.id.clone();
        WG_TUNNEL_REGISTRY.register(session.to_info());
        self.sessions.insert(id.clone(), session);

        tracing::info!("WireGuard peer session added: {}", id);
    }

    pub fn remove_session(&self, id: &str) {
        self.sessions.remove(id);
        WG_TUNNEL_REGISTRY.unregister(id);

        tracing::info!("WireGuard peer session removed: {}", id);
    }

    pub fn get_session(&self, id: &str) -> Option<WgPeerSession> {
        self.sessions.get(id).map(|s| s.clone())
    }

    pub fn get_session_by_public_key(&self, public_key: &str) -> Option<WgPeerSession> {
        self.sessions
            .iter()
            .find(|s| s.public_key == public_key)
            .map(|s| s.clone())
    }

    pub fn update_session<F>(&self, id: &str, f: F)
    where
        F: FnOnce(&mut WgPeerSession),
    {
        if let Some(mut session) = self.sessions.get_mut(id) {
            f(&mut session);
        }
    }

    pub fn list_sessions(&self) -> Vec<WgPeerSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

impl Default for WgSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WgConnectionStats {
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub total_packets_tx: u64,
    pub total_packets_rx: u64,
    pub handshakes: u64,
    pub rekey_count: u64,
    pub errors: u64,
}

impl WgConnectionStats {
    pub fn add_tx(&mut self, bytes: u64, packets: u64) {
        self.total_tx_bytes = self.total_tx_bytes.saturating_add(bytes);
        self.total_packets_tx = self.total_packets_tx.saturating_add(packets);
    }

    pub fn add_rx(&mut self, bytes: u64, packets: u64) {
        self.total_rx_bytes = self.total_rx_bytes.saturating_add(bytes);
        self.total_packets_rx = self.total_packets_rx.saturating_add(packets);
    }

    pub fn record_handshake(&mut self) {
        self.handshakes = self.handshakes.saturating_add(1);
    }

    pub fn record_rekey(&mut self) {
        self.rekey_count = self.rekey_count.saturating_add(1);
    }

    pub fn record_error(&mut self) {
        self.errors = self.errors.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_peer_session_new() {
        let session = WgPeerSession::new("abc123".to_string(), vec!["10.0.0.0/24".to_string()]);

        assert!(!session.id.is_empty());
        assert_eq!(session.public_key, "abc123");
        assert_eq!(session.allowed_ips.len(), 1);
        assert_eq!(session.state, WgSessionState::Initializing);
        assert!(session.last_handshake.is_none());
    }

    #[test]
    fn test_wg_peer_session_with_endpoint() {
        let session = WgPeerSession::new("abc123".to_string(), vec!["0.0.0.0/0".to_string()])
            .with_endpoint("192.168.1.1:51820".to_string());

        assert_eq!(session.endpoint, Some("192.168.1.1:51820".to_string()));
    }

    #[test]
    fn test_wg_peer_session_update_handshake() {
        let mut session = WgPeerSession::new("abc123".to_string(), vec!["0.0.0.0/0".to_string()]);

        assert!(!session.is_established());

        session.update_handshake();

        assert!(session.last_handshake.is_some());
        assert!(session.is_established());
        assert_eq!(session.state, WgSessionState::Established);
    }

    #[test]
    fn test_wg_peer_session_add_bytes() {
        let mut session = WgPeerSession::new("abc123".to_string(), vec!["0.0.0.0/0".to_string()]);

        session.add_tx_bytes(100);
        session.add_tx_bytes(50);
        session.add_rx_bytes(200);

        assert_eq!(session.tx_bytes, 150);
        assert_eq!(session.rx_bytes, 200);
    }

    #[test]
    fn test_wg_peer_session_needs_rekey() {
        let mut session = WgPeerSession::new("abc123".to_string(), vec!["0.0.0.0/0".to_string()]);

        assert!(session.needs_rekey(120));

        session.update_handshake();

        assert!(!session.needs_rekey(120));
    }

    #[test]
    fn test_wg_peer_session_to_info() {
        let session = WgPeerSession::new("abc123".to_string(), vec!["10.0.0.0/24".to_string()])
            .with_endpoint("1.2.3.4:51820".to_string());

        let info = session.to_info();

        assert_eq!(info.peer_public_key, "abc123");
        assert_eq!(info.endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(info.allowed_ips.len(), 1);
    }

    #[test]
    fn test_wg_session_manager() {
        let manager = WgSessionManager::new();

        let session = WgPeerSession::new("pubkey1".to_string(), vec!["0.0.0.0/0".to_string()]);

        let session_id = session.id.clone();
        manager.add_session(session);

        assert_eq!(manager.session_count(), 1);
        assert!(manager.get_session(&session_id).is_some());
        assert!(manager.get_session_by_public_key("pubkey1").is_some());

        manager.remove_session(&session_id);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_wg_session_manager_update() {
        let manager = WgSessionManager::new();

        let session = WgPeerSession::new("pubkey1".to_string(), vec!["0.0.0.0/0".to_string()]);

        let session_id = session.id.clone();
        manager.add_session(session);

        manager.update_session(&session_id, |s| {
            s.add_tx_bytes(1000);
        });

        let updated = manager.get_session(&session_id).unwrap();
        assert_eq!(updated.tx_bytes, 1000);
    }

    #[test]
    fn test_wg_session_manager_list() {
        let manager = WgSessionManager::new();

        manager.add_session(WgPeerSession::new("pk1".to_string(), vec![]));
        manager.add_session(WgPeerSession::new("pk2".to_string(), vec![]));
        manager.add_session(WgPeerSession::new("pk3".to_string(), vec![]));

        let list = manager.list_sessions();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_wg_connection_stats() {
        let mut stats = WgConnectionStats::default();

        stats.add_tx(1000, 10);
        stats.add_rx(2000, 20);
        stats.record_handshake();
        stats.record_rekey();
        stats.record_error();

        assert_eq!(stats.total_tx_bytes, 1000);
        assert_eq!(stats.total_rx_bytes, 2000);
        assert_eq!(stats.total_packets_tx, 10);
        assert_eq!(stats.total_packets_rx, 20);
        assert_eq!(stats.handshakes, 1);
        assert_eq!(stats.rekey_count, 1);
        assert_eq!(stats.errors, 1);
    }

    #[test]
    fn test_wg_connection_stats_saturating() {
        let mut stats = WgConnectionStats::default();

        stats.add_tx(u64::MAX, 0);
        stats.add_tx(1, 0);

        assert_eq!(stats.total_tx_bytes, u64::MAX);
    }

    #[test]
    fn test_wg_tunnel_registry() {
        let registry = &WG_TUNNEL_REGISTRY;

        let info = WgSessionInfo {
            session_id: "session-registry-test-unique-id".to_string(),
            peer_public_key: "pk-registry-test-unique".to_string(),
            endpoint: Some("1.2.3.4:51820".to_string()),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            connected_at: Instant::now(),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        };

        registry.register(info);

        assert!(registry.get("session-registry-test-unique-id").is_some());
        assert!(registry
            .get_by_public_key("pk-registry-test-unique")
            .is_some());

        registry.unregister("session-registry-test-unique-id");
        assert!(registry.get("session-registry-test-unique-id").is_none());
        assert!(registry
            .get_by_public_key("pk-registry-test-unique")
            .is_none());
    }

    #[test]
    fn test_wg_tunnel_registry_update() {
        let registry = &WG_TUNNEL_REGISTRY;

        let info = WgSessionInfo {
            session_id: "session-456".to_string(),
            peer_public_key: "pk-456".to_string(),
            endpoint: None,
            allowed_ips: vec![],
            connected_at: Instant::now(),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        };

        registry.register(info);
        registry.update_stats("session-456", 1000, 500);

        let updated = registry.get("session-456").unwrap();
        assert_eq!(updated.tx_bytes, 1000);
        assert_eq!(updated.rx_bytes, 500);

        registry.unregister("session-456");
    }

    #[test]
    fn test_wg_tunnel_registry_update_handshake() {
        let registry = &WG_TUNNEL_REGISTRY;

        let info = WgSessionInfo {
            session_id: "session-789".to_string(),
            peer_public_key: "pk-789".to_string(),
            endpoint: None,
            allowed_ips: vec![],
            connected_at: Instant::now(),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
        };

        registry.register(info);
        assert!(registry
            .get("session-789")
            .unwrap()
            .last_handshake
            .is_none());

        registry.update_handshake("session-789");
        assert!(registry
            .get("session-789")
            .unwrap()
            .last_handshake
            .is_some());

        registry.unregister("session-789");
    }
}

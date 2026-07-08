#![allow(unused_variables, dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;

use dashmap::DashMap;
use metrics::{counter, gauge};
use tokio::sync::broadcast;

use super::config::{WireGuardConfig, WireGuardPeerConfig};
use super::session::{WgConnectionStats, WgPeerSession, WgSessionManager};
use super::stats::WgStatsCollector;
use crate::{PeerInfo, TunnelStats, TunnelTransport, TunnelType};

pub struct KernelWireGuard {
    config: WireGuardConfig,
    sessions: Arc<WgSessionManager>,
    stats: Arc<DashMap<String, WgConnectionStats>>,
    stats_collector: Arc<tokio::sync::RwLock<Option<WgStatsCollector>>>,
    shutdown_tx: broadcast::Sender<()>,
    running: bool,
    interface_name: String,
}

impl KernelWireGuard {
    pub fn new(config: WireGuardConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let sessions = Arc::new(WgSessionManager::new());
        let stats = Arc::new(DashMap::new());
        let stats_collector = Arc::new(tokio::sync::RwLock::new(None));
        let interface_name = config.interface_name.clone();

        tracing::info!(
            "Kernel WireGuard initialized: interface={}, port={}",
            interface_name,
            config.listen_port
        );

        Ok(Self {
            config,
            sessions,
            stats,
            stats_collector,
            shutdown_tx,
            running: false,
            interface_name,
        })
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
        Ok(())
    }

    pub fn remove_peer(
        &self,
        public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(session) = self.sessions.get_session_by_public_key(public_key) {
            self.sessions.remove_session(&session.id);
        }
        Ok(())
    }
}

#[async_trait]
impl TunnelTransport for KernelWireGuard {
    fn tunnel_type(&self) -> TunnelType {
        TunnelType::WireGuard
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::warn!(
            "Kernel WireGuard backend not yet available — \
             interface {} will not be configured",
            self.interface_name
        );

        for peer_config in &self.config.peers {
            let peer_session = WgPeerSession::new(
                peer_config.public_key.clone(),
                peer_config.allowed_ips.clone(),
            )
            .with_endpoint(peer_config.endpoint.clone().unwrap_or_default());

            self.sessions.add_session(peer_session);
            counter!("synvoid.tunnel.wireguard.peers.added").increment(1);
        }

        self.running = true;
        gauge!("synvoid.tunnel.wireguard.running").set(1.0);

        counter!("synvoid.tunnel.wireguard.started").increment(1);
        tracing::info!(
            "Kernel WireGuard started (stub) with {} peers",
            self.config.peers.len()
        );
        Ok(())
    }

    async fn stop(&mut self) {
        self.running = false;
        gauge!("synvoid.tunnel.wireguard.running").set(0.0);

        for session in self.sessions.list_sessions() {
            self.sessions.remove_session(&session.id);
        }

        tracing::info!("Kernel WireGuard stopped");
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

pub async fn is_kernel_wireguard_available() -> bool {
    false
}

pub async fn get_wireguard_stats(
    _interface: &str,
) -> Result<super::stats::WgInterfaceStats, String> {
    Err("Kernel WireGuard stats not available".to_string())
}

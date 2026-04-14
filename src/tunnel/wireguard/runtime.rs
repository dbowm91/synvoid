use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use metrics::{counter, gauge};
use tokio::sync::broadcast;

use super::config::{WgImplementation, WireGuardConfig, WireGuardPeerConfig};
use super::kernel::KernelWireGuard;
use super::session::{WgConnectionStats, WgSessionManager};
use super::userspace::UserspaceWireGuard;
use crate::tunnel::{PeerInfo, TunnelStats, TunnelTransport, TunnelType};

pub enum WireGuardBackend {
    Kernel(KernelWireGuard),
    Userspace(UserspaceWireGuard),
}

pub struct WireGuardRuntime {
    config: WireGuardConfig,
    backend: Option<WireGuardBackend>,
    sessions: Arc<WgSessionManager>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    stats: Arc<DashMap<String, WgConnectionStats>>,
    shutdown_tx: broadcast::Sender<()>,
    running: bool,
    implementation: WgImplementation,
}

impl WireGuardRuntime {
    pub fn new(config: WireGuardConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let sessions = Arc::new(WgSessionManager::new());
        let stats = Arc::new(DashMap::new());
        let implementation = config.implementation;

        tracing::info!(
            "WireGuard runtime created: implementation={:?}, interface={}",
            implementation,
            config.interface_name
        );

        Ok(Self {
            config,
            backend: None,
            sessions,
            stats,
            shutdown_tx,
            running: false,
            implementation,
        })
    }

    pub fn builder(config: WireGuardConfig) -> WireGuardRuntimeBuilder {
        WireGuardRuntimeBuilder::new(config)
    }

    async fn select_backend(
        &self,
    ) -> Result<WireGuardBackend, Box<dyn std::error::Error + Send + Sync>> {
        match self.implementation {
            WgImplementation::Kernel => {
                if super::kernel::is_kernel_wireguard_available().await {
                    tracing::info!("Using kernel WireGuard implementation");
                    return KernelWireGuard::new(self.config.clone()).map(WireGuardBackend::Kernel);
                }
                Err("Kernel WireGuard requested but not available".into())
            }
            WgImplementation::Userspace => {
                if super::userspace::is_userspace_available().await {
                    tracing::info!("Using userspace WireGuard implementation");
                    return UserspaceWireGuard::new(self.config.clone())
                        .map(WireGuardBackend::Userspace);
                }
                Err("Userspace WireGuard requested but not compiled in (enable 'wireguard' feature)".into())
            }
            WgImplementation::Auto => {
                if super::kernel::is_kernel_wireguard_available().await {
                    tracing::info!("Auto-selected kernel WireGuard implementation");
                    return KernelWireGuard::new(self.config.clone()).map(WireGuardBackend::Kernel);
                }

                if super::userspace::is_userspace_available().await {
                    tracing::info!("Auto-selected userspace WireGuard implementation");
                    return UserspaceWireGuard::new(self.config.clone())
                        .map(WireGuardBackend::Userspace);
                }

                Err("No WireGuard implementation available".into())
            }
        }
    }

    pub fn add_peer(
        &self,
        peer_config: WireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &self.backend {
            Some(WireGuardBackend::Kernel(k)) => k.add_peer(peer_config),
            Some(WireGuardBackend::Userspace(u)) => u.add_peer(peer_config),
            None => {
                let peer_session = super::session::WgPeerSession::new(
                    peer_config.public_key.clone(),
                    peer_config.allowed_ips.clone(),
                )
                .with_endpoint(peer_config.endpoint.clone().unwrap_or_default());

                self.sessions.add_session(peer_session);
                Ok(())
            }
        }
    }

    pub fn remove_peer(
        &self,
        public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &self.backend {
            Some(WireGuardBackend::Kernel(k)) => k.remove_peer(public_key),
            Some(WireGuardBackend::Userspace(u)) => u.remove_peer(public_key),
            None => {
                if let Some(session) = self.sessions.get_session_by_public_key(public_key) {
                    self.sessions.remove_session(&session.id);
                }
                Ok(())
            }
        }
    }

    pub fn session_manager(&self) -> &WgSessionManager {
        &self.sessions
    }

    pub fn implementation(&self) -> WgImplementation {
        self.implementation
    }

    pub async fn send_datagram(
        &self,
        peer_public_key: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &self.backend {
            Some(WireGuardBackend::Userspace(u)) => u.send_datagram(peer_public_key, data).await,
            Some(WireGuardBackend::Kernel(_)) => {
                Err("Kernel WireGuard handles packet routing automatically".into())
            }
            None => Err("WireGuard not started".into()),
        }
    }
}

#[async_trait]
impl TunnelTransport for WireGuardRuntime {
    fn tunnel_type(&self) -> TunnelType {
        TunnelType::WireGuard
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut backend = self.select_backend().await?;

        match &mut backend {
            WireGuardBackend::Kernel(k) => k.start().await?,
            WireGuardBackend::Userspace(u) => u.start().await?,
        }

        self.backend = Some(backend);
        self.running = true;

        gauge!("maluwaf.tunnel.wireguard.running").set(1.0);
        counter!("maluwaf.tunnel.wireguard.started").increment(1);

        tracing::info!("WireGuard runtime started");
        Ok(())
    }

    async fn stop(&mut self) {
        if let Some(mut backend) = self.backend.take() {
            match &mut backend {
                WireGuardBackend::Kernel(k) => k.stop().await,
                WireGuardBackend::Userspace(u) => u.stop().await,
            }
        }

        self.running = false;
        gauge!("maluwaf.tunnel.wireguard.running").set(0.0);

        tracing::info!("WireGuard runtime stopped");
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn stats(&self) -> TunnelStats {
        match &self.backend {
            Some(WireGuardBackend::Kernel(k)) => k.stats(),
            Some(WireGuardBackend::Userspace(u)) => u.stats(),
            None => TunnelStats::default(),
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

pub struct WireGuardRuntimeBuilder {
    config: WireGuardConfig,
    implementation: WgImplementation,
}

impl WireGuardRuntimeBuilder {
    pub fn new(config: WireGuardConfig) -> Self {
        let implementation = config.implementation;
        Self {
            config,
            implementation,
        }
    }

    pub fn with_implementation(mut self, impl_type: WgImplementation) -> Self {
        self.implementation = impl_type;
        self.config.implementation = impl_type;
        self
    }

    pub fn build(self) -> Result<WireGuardRuntime, Box<dyn std::error::Error + Send + Sync>> {
        WireGuardRuntime::new(self.config)
    }
}

pub async fn create_wireguard_runtime(
    config: WireGuardConfig,
) -> Result<WireGuardRuntime, Box<dyn std::error::Error + Send + Sync>> {
    WireGuardRuntime::new(config)
}

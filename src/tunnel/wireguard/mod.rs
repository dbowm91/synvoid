mod client;
mod config;
mod kernel;
mod runtime;
mod server;
mod session;
mod stats;
mod tun;
mod userspace;

pub use client::{WireGuardClient, WireGuardClientBuilder};
pub use config::{
    base64_decode_key, base64_encode_key, generate_keypair, x25519_public_from_private,
    WgImplementation, WireGuardClientConfig, WireGuardConfig, WireGuardConfigError,
    WireGuardInterface, WireGuardPeer, WireGuardPeerConfig, WireGuardServerConfig,
};
pub use kernel::{get_wireguard_stats, KernelWireGuard};
pub use runtime::{
    create_wireguard_runtime, WireGuardBackend, WireGuardRuntime, WireGuardRuntimeBuilder,
};
pub use server::{GeneratedPeerConfig, WireGuardServer, WireGuardServerBuilder};
pub use session::{
    WgConnectionStats, WgPeerSession, WgSessionInfo, WgSessionManager, WgSessionState,
    WgTunnelRegistry, WG_TUNNEL_REGISTRY,
};
pub use stats::{WgInterfaceStats, WgPeerStats, WgStatsCollector, WgStatsError};
pub use tun::{is_tun_available, TunConfig, TunInterface, TunPacket, TunProtocol};
pub use userspace::UserspaceWireGuard;

use metrics::{counter, gauge};
use tokio::sync::broadcast;

use crate::config::{TunnelVpnConfig, WireGuardPeerConfig as ConfigWireGuardPeerConfig};

#[allow(dead_code)]
pub struct WireGuardServerWrapper {
    config: TunnelVpnConfig,
    inner: Option<WireGuardServer>,
    shutdown_tx: broadcast::Sender<()>,
}

impl WireGuardServerWrapper {
    pub fn new(config: TunnelVpnConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            inner: None,
            shutdown_tx,
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            "WireGuard server configured on {}:{} interface {}",
            self.config.bind_address,
            self.config.port,
            self.config.interface
        );

        let private_key = self.config.private_key.clone().unwrap_or_default();

        let wg_config = WireGuardConfig::new(&private_key)
            .with_listen_port(self.config.port)
            .with_interface_name(&self.config.interface);

        let server_config = WireGuardServerConfig {
            base: wg_config,
            address_pool: None,
            max_peers: 100,
        };

        let mut server = WireGuardServer::new(server_config)?;
        server.start().await?;

        self.inner = Some(server);

        counter!("maluwaf.tunnel.wireguard.server.started").increment(1);
        gauge!("maluwaf.tunnel.wireguard.server.enabled").set(1.0);

        Ok(())
    }

    pub fn stop(&self) {
        tracing::info!("WireGuard server stopping");
    }

    pub fn add_peer(
        &self,
        peer: ConfigWireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Adding WireGuard peer: {}", peer.public_key);

        if let Some(ref server) = self.inner {
            let wg_peer = WireGuardPeerConfig::new(
                &peer.public_key,
                peer.allowed_ips.iter().map(|s| s.as_str()).collect(),
            )
            .with_endpoint(peer.endpoint.as_deref().unwrap_or(""));

            server.add_peer(wg_peer)?;
        }

        Ok(())
    }

    pub fn remove_peer(
        &self,
        public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Removing WireGuard peer: {}", public_key);

        if let Some(ref server) = self.inner {
            server.remove_peer(public_key)?;
        }

        Ok(())
    }
}

impl From<ConfigWireGuardPeerConfig> for WireGuardPeerConfig {
    fn from(config: ConfigWireGuardPeerConfig) -> Self {
        Self::new(
            &config.public_key,
            config.allowed_ips.iter().map(|s| s.as_str()).collect(),
        )
        .with_endpoint(config.endpoint.as_deref().unwrap_or(""))
        .with_persistent_keepalive(config.persistent_keepalive)
    }
}

pub async fn is_wireguard_available() -> bool {
    #[cfg(feature = "wireguard")]
    {
        true
    }
    #[cfg(not(feature = "wireguard"))]
    {
        false
    }
}

pub async fn detect_available_implementation() -> Option<WgImplementation> {
    if kernel::is_kernel_wireguard_available().await {
        return Some(WgImplementation::Kernel);
    }

    if userspace::is_userspace_available().await {
        return Some(WgImplementation::Userspace);
    }

    None
}

#[cfg(test)]
mod tests;

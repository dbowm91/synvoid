use std::sync::Arc;

use crate::config::main::{TunnelVpnConfig, WireGuardPeerConfig};

pub struct WireGuardServer {
    config: TunnelVpnConfig,
    #[cfg(feature = "wireguard")]
    device: Option<Arc<boringtun::device::Device>>,
}

impl WireGuardServer {
    pub fn new(config: TunnelVpnConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "wireguard")]
            device: None,
        }
    }

    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            "WireGuard server configured on {}:{} interface {}",
            self.config.bind_address,
            self.config.port,
            self.config.interface
        );

        #[cfg(feature = "wireguard")]
        {
            self.start_boringtun()?;
        }

        #[cfg(not(feature = "wireguard"))]
        {
            tracing::warn!("WireGuard support not enabled (enable 'wireguard' feature in build)");
        }

        Ok(())
    }

    #[cfg(feature = "wireguard")]
    fn start_boringtun(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Starting boringtun WireGuard server");

        let private_key = self
            .config
            .private_key
            .as_ref()
            .and_then(|k| base64_decode(k))
            .map(|k| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&k[..32.min(k.len())]);
                boringtun::crypto::X25519KeyPair::from_secret(&key)
            })
            .transpose()?;

        tracing::info!(
            "WireGuard configuration loaded for interface {}",
            self.config.interface
        );

        Ok(())
    }

    pub fn stop(&self) {
        tracing::info!("WireGuard server stopping");
    }

    pub fn add_peer(
        &self,
        peer: WireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Adding WireGuard peer: {}", peer.public_key);

        #[cfg(feature = "wireguard")]
        {
            self.add_peer_impl(peer)?;
        }

        Ok(())
    }

    #[cfg(feature = "wireguard")]
    fn add_peer_impl(
        &self,
        peer: WireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn remove_peer(
        &self,
        public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Removing WireGuard peer: {}", public_key);
        Ok(())
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(input).ok()
}

pub struct WireGuardPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: u16,
}

impl From<WireGuardPeerConfig> for WireGuardPeer {
    fn from(config: WireGuardPeerConfig) -> Self {
        Self {
            public_key: config.public_key,
            preshared_key: config.preshared_key,
            allowed_ips: config.allowed_ips,
            endpoint: config.endpoint,
            persistent_keepalive: config.persistent_keepalive,
        }
    }
}

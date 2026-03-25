use metrics::{counter, gauge};
use std::time::Duration;
use tokio::sync::broadcast;

use super::config::{WireGuardConfig, WireGuardPeerConfig, WireGuardClientConfig, generate_keypair};
use super::runtime::WireGuardRuntime;
use crate::tunnel::{TunnelTransport, TunnelStats, PeerInfo};

pub struct WireGuardClient {
    config: WireGuardClientConfig,
    runtime: Option<WireGuardRuntime>,
    shutdown_tx: broadcast::Sender<()>,
    local_addresses: Vec<String>,
}

impl WireGuardClient {
    pub fn new(config: WireGuardClientConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let local_addresses = config.local_addresses.clone();
        
        tracing::info!(
            "WireGuard client initialized for endpoint: {:?}",
            config.base.peers.first().and_then(|p| p.endpoint.as_ref())
        );

        Ok(Self {
            config,
            runtime: None,
            shutdown_tx,
            local_addresses,
        })
    }

    pub fn builder() -> WireGuardClientBuilder {
        WireGuardClientBuilder::new()
    }

    pub fn from_endpoint(endpoint: &str, peer_public_key: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (private_key, _public_key) = generate_keypair();
        
        let peer = WireGuardPeerConfig::new(peer_public_key, vec!["0.0.0.0/0"])
            .with_endpoint(endpoint);
        
        let config = WireGuardClientConfig::new(&private_key, peer);
        
        Self::new(config)
    }

    pub fn public_key(&self) -> Option<String> {
        let private_key = super::config::base64_decode_key(&self.config.base.private_key)?;
        let public_key = super::config::x25519_public_from_private(&private_key);
        Some(super::config::base64_encode_key(&public_key))
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.runtime.is_some() {
            return Err("Already connected".into());
        }
        
        let mut runtime = WireGuardRuntime::new(self.config.base.clone())?;
        runtime.start().await?;
        
        self.runtime = Some(runtime);
        
        counter!("maluwaf.tunnel.wireguard.client.connected").increment(1);
        gauge!("maluwaf.tunnel.wireguard.client.status").set(1.0);
        
        tracing::info!("WireGuard client connected");
        Ok(())
    }

    pub async fn disconnect(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            runtime.stop().await;
        }
        
        counter!("maluwaf.tunnel.wireguard.client.disconnected").increment(1);
        gauge!("maluwaf.tunnel.wireguard.client.status").set(0.0);
        
        tracing::info!("WireGuard client disconnected");
    }

    pub fn is_connected(&self) -> bool {
        self.runtime.as_ref().is_some_and(|r| r.is_running())
    }

    pub fn stats(&self) -> TunnelStats {
        self.runtime.as_ref().map_or(TunnelStats::default(), |r| r.stats())
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        self.runtime.as_ref().map_or(Vec::new(), |r| r.peers())
    }

    pub fn local_addresses(&self) -> &[String] {
        &self.local_addresses
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub async fn run_with_auto_reconnect(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.base.auto_reconnect {
            self.connect().await?;
            return Ok(());
        }

        let reconnect_interval = Duration::from_secs(self.config.base.reconnect_interval_secs);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            match self.connect().await {
                Ok(_) => {
                    tracing::info!("WireGuard client connected");
                    
                    if let Some(ref _runtime) = self.runtime {
                        let mut shutdown_inner = self.shutdown_tx.subscribe();
                        
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                                tracing::trace!("WireGuard connection check");
                            }
                            _ = shutdown_inner.recv() => {
                                tracing::info!("Shutdown requested");
                                self.disconnect().await;
                                return Ok(());
                            }
                        }
                    }
                    
                    self.disconnect().await;
                    tracing::info!("Connection lost, attempting reconnect...");
                }
                Err(e) => {
                    tracing::warn!("Connection failed: {}. Retrying in {:?}", e, reconnect_interval);
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(reconnect_interval) => {}
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutdown requested during reconnect");
                    return Ok(());
                }
            }
        }
    }
}

pub struct WireGuardClientBuilder {
    private_key: Option<String>,
    peer_endpoint: Option<String>,
    peer_public_key: Option<String>,
    allowed_ips: Vec<String>,
    local_addresses: Vec<String>,
    implementation: super::config::WgImplementation,
    route_all_traffic: bool,
}

impl WireGuardClientBuilder {
    pub fn new() -> Self {
        Self {
            private_key: None,
            peer_endpoint: None,
            peer_public_key: None,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            local_addresses: Vec::new(),
            implementation: super::config::WgImplementation::Auto,
            route_all_traffic: false,
        }
    }

    pub fn with_private_key(mut self, key: &str) -> Self {
        self.private_key = Some(key.to_string());
        self
    }

    pub fn with_server(mut self, endpoint: &str, public_key: &str) -> Self {
        self.peer_endpoint = Some(endpoint.to_string());
        self.peer_public_key = Some(public_key.to_string());
        self
    }

    pub fn with_allowed_ips(mut self, ips: Vec<&str>) -> Self {
        self.allowed_ips = ips.into_iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_local_address(mut self, addr: &str) -> Self {
        self.local_addresses.push(addr.to_string());
        self
    }

    pub fn with_implementation(mut self, impl_type: super::config::WgImplementation) -> Self {
        self.implementation = impl_type;
        self
    }

    pub fn route_all_traffic(mut self, route: bool) -> Self {
        self.route_all_traffic = route;
        self
    }

    pub fn build(self) -> Result<WireGuardClient, Box<dyn std::error::Error + Send + Sync>> {
        let private_key = self.private_key.unwrap_or_else(|| {
            let (priv_key, _) = generate_keypair();
            priv_key
        });

        let peer_public_key = self.peer_public_key
            .ok_or("Peer public key is required")?;
        let peer_endpoint = self.peer_endpoint
            .ok_or("Peer endpoint is required")?;

        let peer = WireGuardPeerConfig::new(&peer_public_key, self.allowed_ips.iter().map(|s| s.as_str()).collect())
            .with_endpoint(&peer_endpoint);

        let base_config = WireGuardConfig::new(&private_key)
            .with_peer(peer)
            .with_implementation(self.implementation);

        let config = WireGuardClientConfig {
            base: base_config,
            local_addresses: self.local_addresses,
            route_all_traffic: self.route_all_traffic,
            allowed_ips_for_routing: Vec::new(),
        };

        WireGuardClient::new(config)
    }
}

impl Default for WireGuardClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

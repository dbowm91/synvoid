use dashmap::DashMap;
use ipnetwork::IpNetwork;
use metrics::{counter, gauge};
use tokio::sync::broadcast;

use super::config::{WireGuardConfig, WireGuardPeerConfig, WireGuardServerConfig, generate_keypair, WgImplementation};
use super::runtime::WireGuardRuntime;
use crate::tunnel::{TunnelTransport, TunnelStats, PeerInfo};

pub struct WireGuardServer {
    config: WireGuardServerConfig,
    runtime: Option<WireGuardRuntime>,
    peers: DashMap<String, WireGuardPeerConfig>,
    shutdown_tx: broadcast::Sender<()>,
    address_pool: Option<AddressPool>,
}

impl WireGuardServer {
    pub fn new(config: WireGuardServerConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let peers = DashMap::new();
        
        let address_pool = config.address_pool.as_ref().map(|pool| {
            AddressPool::new(pool).unwrap_or_else(|_| AddressPool::default_pool())
        });

        for peer in &config.base.peers {
            peers.insert(peer.public_key.clone(), peer.clone());
        }

        tracing::info!(
            "WireGuard server initialized: port={}, peers={}",
            config.base.listen_port,
            peers.len()
        );

        Ok(Self {
            config,
            runtime: None,
            peers,
            shutdown_tx,
            address_pool,
        })
    }

    pub fn builder() -> WireGuardServerBuilder {
        WireGuardServerBuilder::new()
    }

    pub fn public_key(&self) -> Option<String> {
        let private_key = super::config::base64_decode_key(&self.config.base.private_key)?;
        let public_key = super::config::x25519_public_from_private(&private_key);
        Some(super::config::base64_encode_key(&public_key))
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.runtime.is_some() {
            return Err("Server already running".into());
        }

        let mut runtime = WireGuardRuntime::new(self.config.base.clone())?;
        runtime.start().await?;
        
        self.runtime = Some(runtime);

        counter!("maluwaf.tunnel.wireguard.server.started").increment(1);
        gauge!("maluwaf.tunnel.wireguard.server.running").set(1.0);

        tracing::info!("WireGuard server started on port {}", self.config.base.listen_port);
        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            runtime.stop().await;
        }

        counter!("maluwaf.tunnel.wireguard.server.stopped").increment(1);
        gauge!("maluwaf.tunnel.wireguard.server.running").set(0.0);

        tracing::info!("WireGuard server stopped");
    }

    pub fn is_running(&self) -> bool {
        self.runtime.as_ref().is_some_and(|r| r.is_running())
    }

    pub fn add_peer(&self, peer: WireGuardPeerConfig) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if self.peers.len() >= self.config.max_peers {
            return Err("Maximum number of peers reached".into());
        }

        let public_key = peer.public_key.clone();
        self.peers.insert(public_key.clone(), peer.clone());

        if let Some(ref runtime) = self.runtime {
            runtime.add_peer(peer)?;
        }

        counter!("maluwaf.tunnel.wireguard.server.peers.added").increment(1);
        gauge!("maluwaf.tunnel.wireguard.server.peers.count").set(self.peers.len() as f64);

        tracing::info!("Added WireGuard peer: {}", public_key);
        Ok(public_key)
    }

    pub fn remove_peer(&self, public_key: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.peers.remove(public_key).is_some() {
            if let Some(ref runtime) = self.runtime {
                runtime.remove_peer(public_key)?;
            }

            counter!("maluwaf.tunnel.wireguard.server.peers.removed").increment(1);
            gauge!("maluwaf.tunnel.wireguard.server.peers.count").set(self.peers.len() as f64);

            tracing::info!("Removed WireGuard peer: {}", public_key);
        }
        Ok(())
    }

    pub fn get_peer(&self, public_key: &str) -> Option<WireGuardPeerConfig> {
        self.peers.get(public_key).map(|p| p.clone())
    }

    pub fn list_peers(&self) -> Vec<WireGuardPeerConfig> {
        self.peers.iter().map(|p| p.clone()).collect()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn stats(&self) -> TunnelStats {
        self.runtime.as_ref().map_or(TunnelStats::default(), |r| r.stats())
    }

    pub fn peers_info(&self) -> Vec<PeerInfo> {
        self.runtime.as_ref().map_or(Vec::new(), |r| r.peers())
    }

    pub fn allocate_address(&self) -> Option<String> {
        self.address_pool.as_ref().and_then(|p| p.allocate())
    }

    pub fn release_address(&self, addr: &str) {
        if let Some(ref pool) = self.address_pool {
            pool.release(addr);
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn generate_peer_config(&self, name: &str) -> Result<GeneratedPeerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let (private_key, public_key) = generate_keypair();
        
        let server_public_key = self.public_key()
            .ok_or("Failed to get server public key")?;
        
        let address = self.allocate_address()
            .ok_or("No addresses available in pool")?;
        
        let allowed_ips = vec!["0.0.0.0/0"];
        
        let peer_config = WireGuardPeerConfig::new(&public_key, allowed_ips.clone());
        self.add_peer(peer_config)?;

        Ok(GeneratedPeerConfig {
            name: name.to_string(),
            private_key,
            public_key,
            address,
            dns: self.config.base.dns.clone(),
            server_endpoint: format!("{}:{}", 
                "YOUR_SERVER_IP",
                self.config.base.listen_port
            ),
            server_public_key,
            allowed_ips: allowed_ips.into_iter().map(|s| s.to_string()).collect(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GeneratedPeerConfig {
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    pub dns: Vec<String>,
    pub server_endpoint: String,
    pub server_public_key: String,
    pub allowed_ips: Vec<String>,
}

impl GeneratedPeerConfig {
    pub fn to_wgquick_config(&self) -> String {
        format!(
            r#"[Interface]
PrivateKey = {}
Address = {}/32
DNS = {}

[Peer]
PublicKey = {}
Endpoint = {}
AllowedIPs = {}
"#,
            self.private_key,
            self.address,
            self.dns.join(","),
            self.server_public_key,
            self.server_endpoint,
            self.allowed_ips.join(",")
        )
    }
}

pub struct WireGuardServerBuilder {
    private_key: Option<String>,
    listen_port: u16,
    interface_name: String,
    peers: Vec<WireGuardPeerConfig>,
    address_pool: Option<String>,
    max_peers: usize,
    implementation: WgImplementation,
}

impl WireGuardServerBuilder {
    pub fn new() -> Self {
        Self {
            private_key: None,
            listen_port: 51820,
            interface_name: "wg0".to_string(),
            peers: Vec::new(),
            address_pool: None,
            max_peers: 100,
            implementation: WgImplementation::Auto,
        }
    }

    pub fn with_private_key(mut self, key: &str) -> Self {
        self.private_key = Some(key.to_string());
        self
    }

    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    pub fn with_interface_name(mut self, name: &str) -> Self {
        self.interface_name = name.to_string();
        self
    }

    pub fn with_peer(mut self, peer: WireGuardPeerConfig) -> Self {
        self.peers.push(peer);
        self
    }

    pub fn with_address_pool(mut self, pool: &str) -> Self {
        self.address_pool = Some(pool.to_string());
        self
    }

    pub fn with_max_peers(mut self, max: usize) -> Self {
        self.max_peers = max;
        self
    }

    pub fn with_implementation(mut self, impl_type: WgImplementation) -> Self {
        self.implementation = impl_type;
        self
    }

    pub fn build(self) -> Result<WireGuardServer, Box<dyn std::error::Error + Send + Sync>> {
        let private_key = self.private_key.unwrap_or_else(|| {
            let (priv_key, _) = generate_keypair();
            priv_key
        });

        let base_config = WireGuardConfig::new(&private_key)
            .with_listen_port(self.listen_port)
            .with_interface_name(&self.interface_name)
            .with_implementation(self.implementation);

        let config = WireGuardServerConfig {
            base: base_config,
            address_pool: self.address_pool,
            max_peers: self.max_peers,
        };

        WireGuardServer::new(config)
    }
}

impl Default for WireGuardServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

struct AddressPool {
    network: IpNetwork,
    allocated: DashMap<String, ()>,
    next_index: std::sync::atomic::AtomicU64,
}

impl AddressPool {
    fn new(cidr: &str) -> Result<Self, String> {
        let network: IpNetwork = cidr.parse()
            .map_err(|e| format!("Invalid CIDR: {}", e))?;
        
        Ok(Self {
            network,
            allocated: DashMap::new(),
            next_index: std::sync::atomic::AtomicU64::new(2),
        })
    }

    fn default_pool() -> Self {
        Self::new("10.0.0.0/24").expect("hardcoded CIDR should always be valid")
    }

    fn allocate(&self) -> Option<String> {
        use std::sync::atomic::Ordering;
        use std::net::IpAddr;

        let max_attempts = 100;
        let mut attempts = 0;

        while attempts < max_attempts {
            let index = self.next_index.fetch_add(1, Ordering::Relaxed);
            
            let addr = match self.network {
                IpNetwork::V4(n) => {
                    let mut octets = n.network().octets();
                    let host = index as u32;
                    octets[2] = ((host >> 8) & 0xFF) as u8;
                    octets[3] = (host & 0xFF) as u8;
                    IpAddr::from(octets)
                }
                IpNetwork::V6(_) => return None,
            };

            let addr_str = addr.to_string();
            
            if !self.allocated.contains_key(&addr_str) {
                self.allocated.insert(addr_str.clone(), ());
                return Some(addr_str);
            }

            attempts += 1;
        }

        None
    }

    fn release(&self, addr: &str) {
        self.allocated.remove(addr);
    }
}

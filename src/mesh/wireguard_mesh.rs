#![allow(unused_variables, unused_mut)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::time::interval;

use crate::mesh::config::MeshWireGuardConfig;
use crate::tunnel::wireguard::{
    WgImplementation, WireGuardConfig, WireGuardPeerConfig, WireGuardRuntime,
};

#[derive(Debug, Clone)]
pub struct WireGuardMeshPeer {
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
    pub connected: bool,
    pub last_handshake: Option<std::time::Instant>,
}

pub struct WireGuardMeshRuntime {
    config: Arc<MeshWireGuardConfig>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    runtime: WireGuardRuntime,
    peers: Arc<DashMap<String, WireGuardMeshPeer>>,
    running: Arc<RwLock<bool>>,
    shutdown_tx: Arc<RwLock<Option<broadcast::Sender<()>>>>,
    local_addresses: Arc<RwLock<Vec<String>>>,
    interface_name: String,
}

impl WireGuardMeshRuntime {
    pub async fn new(
        config: MeshWireGuardConfig,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let interface_name = config.interface.clone();

        let wg_config = Self::convert_config(&config)?;

        let runtime = WireGuardRuntime::new(wg_config)?;

        let runtime_arc = Arc::new(Self {
            config: Arc::new(config),
            runtime,
            peers: Arc::new(DashMap::new()),
            running: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            local_addresses: Arc::new(RwLock::new(Vec::new())),
            interface_name,
        });

        Ok(runtime_arc)
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut running = self.running.write();
            if *running {
                return Ok(());
            }
            *running = true;
        }

        let (shutdown_tx, _) = broadcast::channel(1);
        {
            let mut tx = self.shutdown_tx.write();
            *tx = Some(shutdown_tx.clone());
        }

        self.initialize_wireguard().await?;

        let config = self.config.clone();
        let peers = self.peers.clone();
        let shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            Self::peer_maintenance_loop(config, peers, shutdown_rx).await;
        });

        tracing::info!(
            "WireGuard mesh runtime started on interface {}",
            self.interface_name
        );
        Ok(())
    }

    fn convert_config(
        config: &MeshWireGuardConfig,
    ) -> Result<WireGuardConfig, Box<dyn std::error::Error + Send + Sync>> {
        let private_key = config
            .private_key
            .clone()
            .ok_or("WireGuard private key is required for mesh")?;

        let mut wg_config = WireGuardConfig {
            enabled: true,
            interface_name: config.interface.clone(),
            private_key,
            listen_port: config.listen_port,
            mtu: config.mtu,
            dns: config.dns.clone(),
            auto_reconnect: true,
            reconnect_interval_secs: 5,
            implementation: WgImplementation::Auto,
            ..Default::default()
        };

        for peer_config in &config.peers {
            let endpoint = peer_config.endpoint.clone().ok_or_else(|| {
                format!(
                    "WireGuard peer {} requires endpoint",
                    peer_config.public_key
                )
            })?;

            let allowed_ips: Vec<&str> = if peer_config.allowed_ips.is_empty() {
                vec!["0.0.0.0/0"]
            } else {
                peer_config.allowed_ips.iter().map(|s| s.as_str()).collect()
            };

            let mut peer = WireGuardPeerConfig::new(&peer_config.public_key, allowed_ips);
            peer.endpoint = Some(endpoint);
            peer.persistent_keepalive = peer_config.persistent_keepalive.unwrap_or(25);

            wg_config.peers.push(peer);
        }

        Ok(wg_config)
    }

    async fn initialize_wireguard(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for peer_config in &self.config.peers {
            if let Some(endpoint_str) = &peer_config.endpoint {
                let endpoint: SocketAddr = endpoint_str.parse().map_err(|e| {
                    format!("Invalid WireGuard peer endpoint {}: {}", endpoint_str, e)
                })?;

                let allowed_ips = if peer_config.allowed_ips.is_empty() {
                    vec!["0.0.0.0/0".to_string()]
                } else {
                    peer_config.allowed_ips.clone()
                };

                let peer = WireGuardMeshPeer {
                    public_key: peer_config.public_key.clone(),
                    endpoint,
                    allowed_ips,
                    persistent_keepalive: peer_config.persistent_keepalive.unwrap_or(25),
                    connected: false,
                    last_handshake: None,
                };

                self.peers.insert(peer.public_key.clone(), peer);
            }
        }

        {
            let mut addrs = self.local_addresses.write();
            *addrs = self.config.addresses.clone();
        }

        tracing::info!(
            "WireGuard mesh interface {} initialized with {} peers",
            self.config.interface,
            self.config.peers.len()
        );

        Ok(())
    }

    async fn peer_maintenance_loop(
        config: Arc<MeshWireGuardConfig>,
        peers: Arc<DashMap<String, WireGuardMeshPeer>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let mut check_interval = interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    for entry in peers.iter() {
                        let peer = entry.value();
                        tracing::trace!("WireGuard peer {} status: connected={}",
                            peer.public_key, peer.connected);
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("WireGuard mesh maintenance loop stopped");
                    break;
                }
            }
        }
    }

    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    pub fn listen_port(&self) -> u16 {
        self.config.listen_port
    }

    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub fn local_addresses(&self) -> Vec<String> {
        self.local_addresses.read().clone()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn peers(&self) -> Vec<WireGuardMeshPeer> {
        self.peers.iter().map(|e| e.value().clone()).collect()
    }

    pub fn is_peer_connected(&self, public_key: &str) -> bool {
        self.peers
            .get(public_key)
            .map(|p| p.connected)
            .unwrap_or(false)
    }

    pub fn get_peer_endpoint(&self, public_key: &str) -> Option<SocketAddr> {
        self.peers.get(public_key).map(|p| p.endpoint)
    }

    pub fn update_peer_status(&self, public_key: &str, connected: bool) {
        if let Some(mut peer) = self.peers.get_mut(public_key) {
            peer.connected = connected;
            if connected {
                peer.last_handshake = Some(std::time::Instant::now());
            }
        }
    }
}

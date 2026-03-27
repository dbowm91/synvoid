#![allow(unused_variables, dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;

use dashmap::DashMap;
use metrics::{counter, gauge};
use tokio::process::Command;
use tokio::sync::{broadcast, RwLock};

#[cfg(target_os = "linux")]
use wireguard_control::{AllowedIp, Backend, DeviceUpdate, InterfaceName, PeerConfigBuilder};

use super::config::{WireGuardConfig, WireGuardPeerConfig};
use super::session::{WgConnectionStats, WgPeerSession, WgSessionManager};
use super::stats::{WgInterfaceStats, WgStatsCollector};
use super::tun::{is_tun_available, TunInterface};
#[cfg(target_os = "linux")]
use super::tun::{TunReader, TunWriter};
use crate::tunnel::{PeerInfo, TunnelStats, TunnelTransport, TunnelType};

pub struct KernelWireGuard {
    config: WireGuardConfig,
    sessions: Arc<WgSessionManager>,
    stats: Arc<DashMap<String, WgConnectionStats>>,
    stats_collector: Arc<RwLock<Option<WgStatsCollector>>>,
    tun: Option<Arc<TunInterface>>,
    shutdown_tx: broadcast::Sender<()>,
    running: bool,
    interface_name: String,
    interface_created: bool,
}

impl KernelWireGuard {
    pub fn new(config: WireGuardConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let sessions = Arc::new(WgSessionManager::new());
        let stats = Arc::new(DashMap::new());
        let stats_collector = Arc::new(RwLock::new(None));
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
            tun: None,
            shutdown_tx,
            running: false,
            interface_name,
            interface_created: false,
        })
    }

    #[cfg(target_os = "linux")]
    async fn setup_interface(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let iface = InterfaceName::from(&self.interface_name);

        let private_key = base64::engine::general_purpose::STANDARD
            .decode(&self.config.private_key)
            .map_err(|e| format!("Failed to decode private key: {}", e))?;

        let key_array: [u8; 32] = private_key
            .try_into()
            .map_err(|_| "Invalid private key length")?;

        let mut update = DeviceUpdate::new(iface);
        update.set_private_key(key_array.into());
        update.set_listen_port(self.config.listen_port);

        if let Some(fwmark) = self.config.fwmark {
            update.set_fwmark(Some(fwmark));
        }

        match update.apply(&Backend::Kernel) {
            Ok(_) => {
                tracing::debug!(
                    "Created/configured WireGuard interface: {}",
                    self.interface_name
                );
                self.interface_created = true;
            }
            Err(WgError::InterfaceExists) => {
                tracing::info!("WireGuard interface {} already exists", self.interface_name);
                self.interface_created = false;
            }
            Err(e) => {
                return Err(format!("Failed to configure WireGuard interface: {}", e).into());
            }
        }

        let output = Command::new("ip")
            .args(&[
                "link",
                "set",
                "dev",
                &self.interface_name,
                "mtu",
                &self.config.mtu.to_string(),
            ])
            .output()
            .await
            .map_err(|e| format!("Failed to set MTU: {}", e))?;

        tracing::info!("WireGuard interface {} configured", self.interface_name);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn setup_interface(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Kernel WireGuard is only available on Linux".into())
    }

    async fn configure_interface_address(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let iface = &self.interface_name;

        let address = if !self.config.peers.is_empty() {
            let peer = &self.config.peers[0];
            if let Some(endpoint) = &peer.endpoint {
                let _endpoint_port = endpoint
                    .parse::<SocketAddr>()
                    .map(|a| a.port())
                    .unwrap_or(51820);
                "10.0.0.2/24".to_string()
            } else {
                "10.0.0.1/24".to_string()
            }
        } else {
            "10.0.0.1/24".to_string()
        };

        let result = Command::new("ip")
            .args(["addr", "add", &address, "dev", iface])
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                tracing::debug!("Assigned address {} to {}", address, iface);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("already exists") {
                    tracing::debug!("Address {} already assigned to {}", address, iface);
                } else {
                    tracing::warn!("Failed to assign address (non-fatal): {}", stderr);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to assign address (non-fatal): {}", e);
            }
        }

        Ok(())
    }

    async fn bring_interface_up(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let iface = &self.interface_name;

        Command::new("ip")
            .args(["link", "set", "dev", iface, "up"])
            .output()
            .await
            .map_err(|e| format!("Failed to bring interface up: {}", e))?;

        tracing::info!("Interface {} is up", iface);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn add_peer_kernel(
        &self,
        peer: &WireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&peer.public_key)
            .map_err(|e| format!("Failed to decode peer public key: {}", e))?;

        let public_key_array: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "Invalid peer public key length")?;

        let mut peer_config = PeerConfigBuilder::new(public_key_array.into());

        if let Some(endpoint) = &peer.endpoint {
            let addr: SocketAddr = endpoint
                .parse()
                .map_err(|e| format!("Invalid endpoint: {}", e))?;
            peer_config.set_endpoint(addr);
        }

        if !peer.allowed_ips.is_empty() {
            let allowed_ips: Result<Vec<AllowedIp>, _> = peer
                .allowed_ips
                .iter()
                .map(|ip_str| {
                    let (ip, prefix) = ip_str.split_once('/').ok_or("Invalid allowed IP format")?;
                    let ip: IpAddr = ip.parse().map_err(|_| "Invalid IP address")?;
                    let prefix: u8 = prefix.parse().map_err(|_| "Invalid prefix length")?;
                    Ok(AllowedIp::new(ip, prefix))
                })
                .collect();
            peer_config.set_allowed_ips(allowed_ips?);
        }

        if peer.persistent_keepalive > 0 {
            peer_config.set_persistent_keepalive(peer.persistent_keepalive);
        }

        let iface = InterfaceName::from(&self.interface_name);
        let mut update = DeviceUpdate::new(iface);
        update.add_peer(peer_config.build());

        update
            .apply(&Backend::Kernel)
            .map_err(|e| format!("Failed to add peer: {}", e))?;

        tracing::debug!("Added peer {} via netlink", peer.public_key);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn add_peer_kernel(
        &self,
        peer: &WireGuardPeerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Kernel WireGuard peer addition is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    async fn remove_peer_kernel(
        &self,
        public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(public_key)
            .map_err(|e| format!("Failed to decode peer public key: {}", e))?;

        let public_key_array: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "Invalid peer public key length")?;

        let iface = InterfaceName::from(&self.interface_name);
        let mut update = DeviceUpdate::new(iface);
        update.add_peer(
            PeerConfigBuilder::new(public_key_array.into())
                .remove()
                .build(),
        );

        update
            .apply(&Backend::Kernel)
            .map_err(|e| format!("Failed to remove peer: {}", e))?;

        tracing::debug!("Removed peer via netlink");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn remove_peer_kernel(
        &self,
        _public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("Kernel WireGuard peer removal is only available on Linux".into())
    }

    async fn teardown_interface(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.interface_created {
            #[cfg(target_os = "linux")]
            {
                use wireguard_control::Error as WgError;
                let iface = InterfaceName::from(&self.interface_name);
                match wireguard_control::delete_interface(iface, &Backend::Kernel) {
                    Ok(_) => {
                        tracing::info!("WireGuard interface {} removed", self.interface_name);
                    }
                    Err(WgError::InterfaceNotFound) => {
                        tracing::debug!(
                            "WireGuard interface {} already removed",
                            self.interface_name
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Failed to remove interface: {}", e);
                    }
                }
            }
            self.interface_created = false;
        }
        Ok(())
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

    #[cfg(target_os = "linux")]
    async fn start_stats_collector(&self) {
        let collector = self.stats_collector.clone();
        let interface = self.interface_name.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            let mut shutdown_rx = shutdown_rx;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut guard = collector.write().await;
                        if let Some(ref mut c) = *guard {
                            match c.refresh().await {
                                Ok(stats) => {
                                    for peer in &stats.peers {
                                        if let Some(handshake) = peer.latest_handshake {
                                            gauge!("maluwaf.tunnel.wireguard.peer.handshake")
                                                .set(handshake as f64);
                                        }
                                        counter!("maluwaf.tunnel.wireguard.peer.rx")
                                            .absolute(peer.transfer_rx as f64);
                                        counter!("maluwaf.tunnel.wireguard.peer.tx")
                                            .absolute(peer.transfer_tx as f64);
                                    }
                                }
                                Err(e) => {
                                    tracing::trace!("Stats collection error: {}", e);
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Stats collector shutting down");
                        break;
                    }
                }
            }
        });
    }
}

#[async_trait]
impl TunnelTransport for KernelWireGuard {
    fn tunnel_type(&self) -> TunnelType {
        TunnelType::WireGuard
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.setup_interface().await?;

        for peer_config in &self.config.peers {
            match self.add_peer_kernel(peer_config).await {
                Ok(_) => {
                    let peer_session = WgPeerSession::new(
                        peer_config.public_key.clone(),
                        peer_config.allowed_ips.clone(),
                    )
                    .with_endpoint(peer_config.endpoint.clone().unwrap_or_default());

                    self.sessions.add_session(peer_session);
                    counter!("maluwaf.tunnel.wireguard.peers.added").increment(1);
                }
                Err(e) => {
                    tracing::error!("Failed to add peer {}: {}", peer_config.public_key, e);
                }
            }
        }

        self.configure_interface_address().await?;
        self.bring_interface_up().await?;

        #[cfg(target_os = "linux")]
        {
            let mut guard = self.stats_collector.write().await;
            *guard = Some(WgStatsCollector::new(&self.interface_name));
        }

        #[cfg(target_os = "linux")]
        self.start_stats_collector().await;

        self.running = true;
        gauge!("maluwaf.tunnel.wireguard.running").set(1.0);

        counter!("maluwaf.tunnel.wireguard.started").increment(1);
        tracing::info!(
            "Kernel WireGuard started with {} peers",
            self.config.peers.len()
        );
        Ok(())
    }

    async fn stop(&mut self) {
        let _ = self.teardown_interface().await;

        self.running = false;
        gauge!("maluwaf.tunnel.wireguard.running").set(0.0);

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
    if !is_tun_available() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        match wireguard_control::get_interfaces() {
            Ok(interfaces) => !interfaces.is_empty() || true,
            Err(_) => true,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub async fn get_wireguard_stats(interface: &str) -> Result<WgInterfaceStats, String> {
    #[cfg(target_os = "linux")]
    {
        super::stats::get_interface_stats(interface)
            .await
            .map_err(|e| e.to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        Err("WireGuard stats only available on Linux".to_string())
    }
}

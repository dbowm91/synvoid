#![allow(unused_mut)]

pub mod config;
mod local_listener;
mod events;
mod stats;

pub use config::{VpnClientConfig, ClientPortMapping, ReconnectConfig, TransportType, WireGuardClientTransportConfig};
pub use local_listener::{LocalListener, LocalPortMapping, Protocol};
pub use events::{VpnEvent, VpnEventCallback};
pub use stats::{VpnStats, VpnStatsTracker};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{broadcast, Mutex};
use metrics::{gauge, counter};
use quinn::Connection;

use crate::platform::{self, Platform};
use crate::tunnel::quic::QuicRuntime;
use crate::tunnel::quic::messages::{TunnelMessage, PortMapping, DatagramCapabilities};
use crate::tunnel::quic::framing::{read_message_default, write_message};
use crate::tunnel::quic::validation::JitteredBackoff;
use crate::tunnel::wireguard::WireGuardRuntime;
use crate::tunnel::TunnelTransport;

#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub platform: Platform,
    pub tun_available: bool,
    pub wireguard_supported: bool,
}

pub enum VpnConnection {
    Quic {
        session: VpnSession,
    },
    WireGuard,
}

pub struct VpnClient {
    config: VpnClientConfig,
    quic_runtime: Option<Arc<QuicRuntime>>,
    wg_runtime: Option<Arc<Mutex<WireGuardRuntime>>>,
    connection: Option<VpnConnection>,
    local_listeners: Arc<DashMap<String, LocalListener>>,
    shutdown_tx: broadcast::Sender<()>,
    event_callback: Option<VpnEventCallback>,
    stats: Arc<VpnStatsTracker>,
}

#[derive(Clone)]
pub struct VpnSession {
    pub id: String,
    pub client_id: String,
    pub remote_addr: String,
    pub connected_at: std::time::Instant,
    pub connection: Connection,
    pub datagram_capabilities: DatagramCapabilities,
    pub access_level: String,
}

pub struct VpnClientBuilder {
    config: VpnClientConfig,
}

impl VpnClientBuilder {
    pub fn new(config: VpnClientConfig) -> Self {
        Self { config }
    }

    pub fn build(self) -> Result<VpnClient, Box<dyn std::error::Error + Send + Sync>> {
        VpnClient::new(self.config)
    }
}

impl VpnClient {
    pub fn new(config: VpnClientConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        if config.transport == TransportType::WireGuard && !platform::is_wireguard_userspace_supported() {
            return Err(format!(
                "WireGuard is not supported on this platform ({}). Use QUIC transport instead.",
                platform::platform().libc_name()
            ).into());
        }
        
        if config.transport == TransportType::WireGuard && !platform::is_tun_supported() {
            tracing::warn!(
                "TUN support not detected on this platform. WireGuard may not work properly. \
                Consider using QUIC transport instead."
            );
        }
        
        if config.transport == TransportType::WireGuard && platform::is_admin_required_for_tun() {
            tracing::info!(
                "WireGuard requires administrator/root privileges on this platform"
            );
        }
        
        let quic_runtime = if config.transport == TransportType::Quic {
            let quic_config = config.to_quic_config();
            let runtime = QuicRuntime::new(quic_config)?
                .with_timeouts(300, 25)
                .with_connect_timeout(config.connect_timeout_ms);
            Some(Arc::new(runtime))
        } else {
            None
        };
        
        let wg_runtime = if config.transport == TransportType::WireGuard {
            if let Some(ref wg_config) = config.wireguard {
                let runtime = WireGuardRuntime::new(wg_config.to_wireguard_config())?;
                Some(Arc::new(Mutex::new(runtime)))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            quic_runtime,
            wg_runtime,
            connection: None,
            local_listeners: Arc::new(DashMap::new()),
            shutdown_tx,
            event_callback: None,
            stats: Arc::new(VpnStatsTracker::new()),
        })
    }

    pub fn with_event_callback(mut self, callback: VpnEventCallback) -> Self {
        self.event_callback = Some(callback);
        self
    }

    fn emit_event(&self, event: VpnEvent) {
        if let Some(ref cb) = self.event_callback {
            cb(event);
        }
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stats.reset();
        match self.config.transport {
            TransportType::Quic => self.connect_quic().await,
            TransportType::WireGuard => self.connect_wireguard().await,
        }
    }

    async fn connect_quic(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let runtime = self.quic_runtime.as_ref()
            .ok_or_else(|| "QUIC runtime not initialized".to_string())?;
        
        let server_addr = format!("{}:{}", self.config.server_host, self.config.server_port);
        let server_name = self.config.server_name.as_deref().unwrap_or(&self.config.server_host);
        
        tracing::info!("Connecting to VPN server at {}", server_addr);
        
        let quic_conn = runtime.connect_to_peer(&server_addr, server_name).await?;
        let connection = quic_conn.connection.clone()
            .ok_or_else(|| "No connection in QuicConnection".to_string())?;

        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let port_mappings: HashMap<String, PortMapping> = self.config.port_mappings.iter()
            .map(|m| {
                let protocol_str = m.protocol.to_string();
                (m.identifier(), PortMapping::new(m.remote_port, &protocol_str)
                    .with_upstream(m.upstream_host.as_deref().unwrap_or("127.0.0.1"), m.remote_port))
            })
            .collect();

        let hello = TunnelMessage::Hello {
            client_id: self.config.client_id.clone(),
            auth_token: self.config.auth_token.clone(),
            mappings: port_mappings,
            supports_datagrams: runtime.is_datagram_enabled(),
        };
        write_message(&mut send_stream, &hello).await?;

        let response = read_message_default(&mut recv_stream).await?;

        match response {
            TunnelMessage::HelloAck { server_session_id, supports_datagrams, max_datagram_size, access_level, .. } => {
                let datagram_caps = DatagramCapabilities::new(supports_datagrams, max_datagram_size);
                
                let access_level_str = access_level.clone().unwrap_or_else(|| "general".to_string());
                
                let session = VpnSession {
                    id: server_session_id.clone(),
                    client_id: self.config.client_id.clone(),
                    remote_addr: server_addr,
                    connected_at: std::time::Instant::now(),
                    connection,
                    datagram_capabilities: datagram_caps,
                    access_level: access_level_str.clone(),
                };

                self.connection = Some(VpnConnection::Quic { session });
                
                counter!("maluwaf.vpn.client.connected").increment(1);
                gauge!("maluwaf.vpn.client.sessions").set(1.0);
                self.stats.connected();
                
                tracing::info!("VPN session established");
                
                self.emit_event(VpnEvent::Connected { 
                    session_id: server_session_id, 
                    access_level: access_level_str 
                });
                
                Ok(())
            }
            TunnelMessage::AuthFailure { reason } => {
                Err(format!("Authentication failed: {}", reason).into())
            }
            _ => Err("Unexpected response from server".into()),
        }
    }

    async fn connect_wireguard(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let runtime = self.wg_runtime.as_ref()
            .ok_or_else(|| "WireGuard runtime not initialized".to_string())?;
        
        tracing::info!("Starting WireGuard VPN connection");
        
        let mut rt = runtime.lock().await;
        rt.start().await?;
        
        self.connection = Some(VpnConnection::WireGuard);
        
        counter!("maluwaf.vpn.client.wireguard.connected").increment(1);
        gauge!("maluwaf.vpn.client.wireguard.status").set(1.0);
        
        tracing::info!("WireGuard VPN connection established");
        
        Ok(())
    }

    pub async fn disconnect(&mut self) {
        let session_id = self.connection.as_ref().map(|c| match c {
            VpnConnection::Quic { session } => session.id.clone(),
            VpnConnection::WireGuard => "wireguard".to_string(),
        });
        
        match self.connection.take() {
            Some(VpnConnection::Quic { session }) => {
                session.connection.close(0u32.into(), b"Client disconnect");
                counter!("maluwaf.vpn.client.disconnected").increment(1);
                gauge!("maluwaf.vpn.client.sessions").set(0.0);
            }
            Some(VpnConnection::WireGuard) => {
                if let Some(runtime) = &self.wg_runtime {
                    let mut rt = runtime.lock().await;
                    rt.stop().await;
                }
                counter!("maluwaf.vpn.client.wireguard.disconnected").increment(1);
                gauge!("maluwaf.vpn.client.wireguard.status").set(0.0);
            }
            None => {}
        }
        
        if let Some(_id) = session_id {
            self.emit_event(VpnEvent::Disconnected { reason: "client_disconnect".to_string() });
        }
        
        self.stats.disconnected();
        self.stop_all_listeners();
    }

    fn stop_all_listeners(&self) {
        for entry in self.local_listeners.iter() {
            entry.stop();
        }
        self.local_listeners.clear();
    }

    async fn setup_port_mappings(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &self.connection {
            Some(VpnConnection::Quic { session }) => {
                for mapping in &self.config.port_mappings {
                    let local_mapping = LocalPortMapping {
                        local_addr: format!("{}:{}", self.config.local_bind_host, mapping.local_port)
                            .parse()
                            .map_err(|e| format!("Invalid local address: {}", e))?,
                        remote_port: mapping.remote_port,
                        protocol: match mapping.protocol {
                            config::Protocol::Tcp => Protocol::Tcp,
                            config::Protocol::Udp => Protocol::Udp,
                        },
                        upstream_host: mapping.upstream_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
                        identifier: mapping.identifier(),
                    };

                    let listener = LocalListener::new(
                        local_mapping,
                        session.connection.clone(),
                        session.datagram_capabilities,
                    );

                    let identifier = listener.identifier().to_string();
                    listener.start().await?;
                    
                    self.local_listeners.insert(identifier.clone(), listener);
                    counter!("maluwaf.vpn.client.port_mappings").increment(1);
                    
                    tracing::info!("Port mapping established: {}", identifier);
                }
            }
            Some(VpnConnection::WireGuard) => {
                tracing::info!("WireGuard mode: port mappings handled via IP routing");
            }
            None => {}
        }

        Ok(())
    }

    pub async fn add_port_mapping(&self, mapping: ClientPortMapping) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &self.connection {
            Some(VpnConnection::Quic { session }) => {
                let local_mapping = LocalPortMapping {
                    local_addr: format!("{}:{}", self.config.local_bind_host, mapping.local_port)
                        .parse()
                        .map_err(|e| format!("Invalid local address: {}", e))?,
                    remote_port: mapping.remote_port,
                    protocol: match mapping.protocol {
                        config::Protocol::Tcp => Protocol::Tcp,
                        config::Protocol::Udp => Protocol::Udp,
                    },
                    upstream_host: mapping.upstream_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
                    identifier: mapping.identifier(),
                };

                let listener = LocalListener::new(
                    local_mapping,
                    session.connection.clone(),
                    session.datagram_capabilities,
                );

                let identifier = listener.identifier().to_string();
                listener.start().await?;
                
                self.local_listeners.insert(identifier.clone(), listener);
                counter!("maluwaf.vpn.client.port_mappings").increment(1);
                
                tracing::info!("Added port mapping: {}", identifier);
            }
            Some(VpnConnection::WireGuard) => {
                tracing::warn!("Port mappings not supported in WireGuard mode");
            }
            None => {}
        }
        
        Ok(())
    }

    pub async fn remove_port_mapping(&self, local_port: u16, protocol: Protocol) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let identifier = format!("local-{}-{}", local_port, protocol);
        
        if let Some((_, listener)) = self.local_listeners.remove(&identifier) {
            listener.stop();
            tracing::info!("Removed port mapping: {}", identifier);
        }
        
        Ok(())
    }

    pub fn session(&self) -> Option<&VpnSession> {
        match &self.connection {
            Some(VpnConnection::Quic { session }) => Some(session),
            _ => None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    pub fn transport_type(&self) -> TransportType {
        self.config.transport
    }

    pub fn is_tun_available() -> bool {
        crate::tunnel::tun::is_tun_available()
    }

    pub fn supports_wireguard() -> bool {
        platform::is_wireguard_userspace_supported()
    }

    pub fn platform_info() -> PlatformInfo {
        PlatformInfo {
            platform: platform::platform(),
            tun_available: Self::is_tun_available(),
            wireguard_supported: Self::supports_wireguard(),
        }
    }

    pub fn list_port_mappings(&self) -> Vec<String> {
        self.local_listeners.iter().map(|l| l.key().clone()).collect()
    }

    pub fn get_stats(&self) -> VpnStats {
        self.stats.get_stats()
    }

    pub fn get_config(&self) -> VpnClientConfig {
        self.config.clone()
    }

    pub fn set_config(&mut self, config: VpnClientConfig) {
        self.config = config;
    }

    pub fn stats(&self) -> Arc<VpnStatsTracker> {
        self.stats.clone()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub async fn run_with_auto_reconnect(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.reconnect.enabled {
            self.connect().await?;
            self.setup_port_mappings().await?;
            return Ok(());
        }

        let max_attempts = self.config.reconnect.max_attempts;
        let mut backoff = JitteredBackoff::new(
            Duration::from_millis(self.config.reconnect.initial_delay_ms),
            Duration::from_millis(self.config.reconnect.max_delay_ms),
            self.config.reconnect.backoff_multiplier as f64,
        );
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            match self.connect().await {
                Ok(_) => {
                    backoff.reset();
                    tracing::info!("VPN connected successfully");
                    
                    if let Err(e) = self.setup_port_mappings().await {
                        tracing::error!("Failed to setup port mappings: {}", e);
                    }
                    
                    match &self.connection {
                        Some(VpnConnection::Quic { session }) => {
                            let connection = session.connection.clone();
                            let mut shutdown_rx_inner = self.shutdown_tx.subscribe();
                            
                            tokio::select! {
                                _ = connection.closed() => {
                                    tracing::info!("VPN connection lost");
                                }
                                _ = shutdown_rx_inner.recv() => {
                                    tracing::info!("Shutdown requested");
                                    self.stop_all_listeners();
                                    return Ok(());
                                }
                            }
                        }
                        Some(VpnConnection::WireGuard) => {
                            let mut shutdown_rx_inner = self.shutdown_tx.subscribe();
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                                    tracing::trace!("WireGuard connection check");
                                }
                                _ = shutdown_rx_inner.recv() => {
                                    tracing::info!("Shutdown requested");
                                    self.stop_all_listeners();
                                    return Ok(());
                                }
                            }
                        }
                        None => {}
                    }
                    
                    self.stop_all_listeners();
                    tracing::info!("Attempting reconnect...");
                }
                Err(e) => {
                    if max_attempts > 0 && backoff.attempt() >= max_attempts {
                        tracing::error!("Max reconnect attempts ({}) reached", max_attempts);
                        return Err(e);
                    }
                    
                    let delay = backoff.next_delay();
                    
                    tracing::warn!(
                        "Connection failed (attempt {}): {}. Retrying in {:?}",
                        backoff.attempt(), e, delay
                    );
                    
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = shutdown_rx.recv() => {
                            tracing::info!("Shutdown requested during reconnect");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

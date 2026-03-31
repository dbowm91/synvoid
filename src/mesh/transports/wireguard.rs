#![allow(unused_variables)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock as ParkingRwLock;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};

use crate::mesh::config::{MeshConfig, MeshNodeRole, MeshWireGuardConfig, MeshWireGuardPeer};
use crate::mesh::protocol::{MeshMessage, MESH_MESSAGE_VERSION};
use crate::mesh::topology::{MeshTopology, PeerStatus};
use crate::mesh::transports::{MeshTransportError, MeshTransportTrait, MeshTransportType};
use crate::mesh::wireguard_mesh::WireGuardMeshRuntime;

const MESH_HEADER_SIZE: usize = 4;

pub struct WireGuardMeshTransport {
    config: Arc<MeshConfig>,
    wireguard_config: Arc<MeshWireGuardConfig>,
    topology: Arc<MeshTopology>,
    #[allow(dead_code)]
    runtime: Option<Arc<WireGuardMeshRuntime>>,
    running: Arc<ParkingRwLock<bool>>,
    shutdown_tx: Arc<ParkingRwLock<Option<broadcast::Sender<()>>>>,
    peer_states: Arc<DashMap<String, WireGuardPeerState>>,
    local_addresses: Arc<ParkingRwLock<Vec<String>>>,
    socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
}

struct WireGuardPeerState {
    pub address: String,
    pub wireguard_ip: String,
    pub last_seen: Instant,
}

impl WireGuardMeshTransport {
    pub fn new(
        config: Arc<MeshConfig>,
        wireguard_config: MeshWireGuardConfig,
        topology: Arc<MeshTopology>,
    ) -> Self {
        Self {
            config: config.clone(),
            wireguard_config: Arc::new(wireguard_config),
            topology,
            runtime: None,
            running: Arc::new(ParkingRwLock::new(false)),
            shutdown_tx: Arc::new(ParkingRwLock::new(None)),
            peer_states: Arc::new(DashMap::new()),
            local_addresses: Arc::new(ParkingRwLock::new(Vec::new())),
            socket: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.wireguard_config.enabled {
            tracing::info!("WireGuard mesh transport disabled in config");
            return Ok(());
        }

        let private_key = self
            .wireguard_config
            .private_key
            .clone()
            .ok_or("WireGuard private key is required for mesh transport")?;

        tracing::info!(
            "Initializing WireGuard mesh transport: interface={}, port={}",
            self.wireguard_config.interface,
            self.wireguard_config.listen_port
        );

        {
            let mut addrs = self.local_addresses.write();
            *addrs = self.wireguard_config.addresses.clone();
        }

        let bind_addr = format!(
            "{}:{}",
            self.wireguard_config
                .addresses
                .first()
                .unwrap_or(&"0.0.0.0".to_string()),
            self.wireguard_config.listen_port
        );

        let perf_config = self.wireguard_config.effective_perf_config();

        let socket = if perf_config.rx_buffer_size > 0 || perf_config.tx_buffer_size > 0 {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;

            if perf_config.rx_buffer_size > 0 {
                socket.set_recv_buffer_size(perf_config.rx_buffer_size)?;
            }
            if perf_config.tx_buffer_size > 0 {
                socket.set_send_buffer_size(perf_config.tx_buffer_size)?;
            }

            socket.bind(&bind_addr.parse::<SocketAddr>()?.into())?;
            let std_socket: std::net::UdpSocket = socket.into();
            tokio::net::UdpSocket::from_std(std_socket)?
        } else {
            tokio::net::UdpSocket::bind(&bind_addr).await?
        };

        {
            let mut s = self.socket.write().await;
            *s = Some(Arc::new(socket));
        }

        tracing::info!(
            "WireGuard mesh transport initialized: listen={}, mtu={}, perf={:?}, rx_buf={}, tx_buf={}",
            bind_addr,
            self.wireguard_config.effective_mtu(),
            self.wireguard_config.performance_profile,
            perf_config.rx_buffer_size,
            perf_config.tx_buffer_size
        );

        Ok(())
    }

    pub async fn start(&self) -> Result<(), MeshTransportError> {
        if !self.wireguard_config.enabled {
            return Ok(());
        }

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

        let topology = self.topology.clone();
        let peer_states = self.peer_states.clone();
        let config = self.config.clone();
        let socket = self.socket.clone();
        let shutdown_tx_clone = shutdown_tx.clone();

        tokio::spawn(async move {
            let shutdown_rx = shutdown_tx_clone.subscribe();
            Self::receive_loop(config, topology, peer_states, socket, shutdown_rx).await;
        });

        tracing::info!("WireGuard mesh transport started");
        Ok(())
    }

    async fn receive_loop(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        peer_states: Arc<DashMap<String, WireGuardPeerState>>,
        socket: Arc<RwLock<Option<Arc<UdpSocket>>>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let mut buf = [0u8; 65535];

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("WireGuard receive loop stopped");
                    break;
                }
                result = async {
                    let sock = {
                        let guard = socket.read().await;
                        guard.as_ref().map(|s| s.clone())
                    };
                    match sock {
                        Some(s) => s.recv_from(&mut buf).await.ok(),
                        None => None,
                    }
                } => {
                    if let Some((len, addr)) = result {
                        let data = Bytes::copy_from_slice(&buf[..len]);
                        if let Err(e) = Self::handle_received_packet(&config, &topology, &peer_states, &socket, addr, data).await {
                            tracing::warn!("Failed to handle packet from {}: {}", addr, e);
                        }
                    }
                }
            }
        }
    }

    async fn handle_received_packet(
        config: &Arc<MeshConfig>,
        topology: &Arc<MeshTopology>,
        peer_states: &Arc<DashMap<String, WireGuardPeerState>>,
        socket: &Arc<RwLock<Option<Arc<UdpSocket>>>>,
        addr: SocketAddr,
        data: Bytes,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = match MeshMessage::decode(&data) {
            Some(m) => m,
            None => return Err("Failed to decode message".to_string().into()),
        };

        tracing::debug!("Received mesh message from {}: {:?}", addr, msg);

        match msg {
            MeshMessage::Hello {
                version,
                node_id,
                role,
                capabilities,
                upstreams,
                auth_token: _,
                network_id: _,
                global_node_key: _,
                timestamp: _,
                nonce: _,
                is_trusted: _,
                quic_port,
                wireguard_port,
                public_key: _,
                pow_nonce: _,
                pow_public_key: _,
            } => {
                tracing::info!(
                    "Received Hello from {} at {} (quic_port: {:?}, wg_port: {:?}",
                    node_id,
                    addr,
                    quic_port,
                    wireguard_port
                );

                let wireguard_ip = format!("10.100.0.{}", peer_states.len() + 2);

                let state = WireGuardPeerState {
                    address: addr.to_string(),
                    wireguard_ip: wireguard_ip.clone(),
                    last_seen: Instant::now(),
                };

                peer_states.insert(node_id.to_string(), state);

                topology
                    .add_peer(
                        crate::mesh::protocol::MeshPeerInfo {
                            node_id: node_id.to_string(),
                            address: wireguard_ip,
                            role,
                            capabilities,
                            is_global: role.is_global(),
                            latency_ms: None,
                            upstreams: upstreams.keys().cloned().collect(),
                            is_trusted: role.is_global(),
                            quic_port,
                            wireguard_port,
                            advertised_port: quic_port.or(wireguard_port),
                            dns_serving_healthy: false,
                        },
                        PeerStatus::Healthy,
                    )
                    .await;

                let response = MeshMessage::HelloAck {
                    version: MESH_MESSAGE_VERSION,
                    node_id: config.node_id().into(),
                    role: config.role,
                    session_id: format!("{}-{}", config.node_id(), uuid::Uuid::new_v4()).into(),
                    upstreams: Default::default(),
                    auth_token: None,
                    network_id: config.network_id.clone().map(|s| s.into()),
                    global_node_key: config.global_node_key.clone().map(|s| s.into()),
                    timestamp: Some(MeshMessage::generate_timestamp()),
                    nonce: Some(MeshMessage::generate_nonce()),
                    is_trusted: config.is_trusted_node(),
                    quic_port: Some(config.get_quic_port() as u32),
                    wireguard_port: config.get_advertised_wireguard_port().map(|p| p as u32),
                    public_key: config.signing_public_key().map(|s| s.into()),
                };

                let encoded = response.encode()?;
                if let Some(socket) = &*socket.read().await {
                    socket.send_to(&encoded, addr).await?;
                }
            }
            MeshMessage::RouteQuery {
                query_id,
                upstream_id,
                max_hops,
                initiator,
                sequence: _,
                timestamp: _,
                nonce: _,
            } => {
                Self::handle_route_query(
                    topology,
                    peer_states,
                    addr,
                    query_id.to_string(),
                    upstream_id.to_string(),
                    max_hops,
                    initiator.to_string(),
                )
                .await;
            }
            MeshMessage::KeepAlive => {
                let addr_str = addr.to_string();
                if let Some(peer) = peer_states.iter().find(|p| p.value().address == addr_str) {
                    let key = peer.key().clone();
                    if let Some(mut p) = peer_states.get_mut(&key) {
                        p.last_seen = Instant::now();
                    }
                }
            }
            MeshMessage::KeyForward { .. } => {
                tracing::trace!("Unhandled KeyForward message from {}", addr);
            }
            MeshMessage::KeySigned { .. } => {
                tracing::trace!("Unhandled KeySigned message from {}", addr);
            }
            _ => {
                tracing::trace!("Unhandled message type from {}: {:?}", addr, msg);
            }
        }

        Ok(())
    }

    async fn handle_route_query(
        topology: &Arc<MeshTopology>,
        peer_states: &Arc<DashMap<String, WireGuardPeerState>>,
        _addr: SocketAddr,
        query_id: String,
        upstream_id: String,
        _max_hops: u8,
        initiator: String,
    ) {
        let provider = topology.get_cached_route(&upstream_id).await;
        let mesh_name = topology.config().mesh_name().map(|s| s.into());

        let response = if let Some((provider_node_id, hops)) = provider {
            let local = topology.get_upstream_info(&upstream_id).await;
            MeshMessage::RouteResponse {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
                provider_node_id: provider_node_id.into(),
                hops,
                ttl_secs: 300,
                signature: Vec::new(),
                sequence: 0,
                timestamp: MeshMessage::generate_timestamp(),
                nonce: MeshMessage::generate_nonce(),
                upstream_url: local.as_ref().map(|l| l.upstream_url.clone().into()),
                waf_policy: local.as_ref().and_then(|l| l.waf_policy.clone()),
                priority_tier: local.map(|l| l.priority_tier).unwrap_or(0),
                tier_claim: None,
                org_id: None,
                mesh_name,
            }
        } else {
            MeshMessage::RouteNotFound {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
            }
        };

        if let Some(peer) = peer_states.iter().find(|p| p.key() == &initiator) {
            tracing::debug!("Sending route response to {}", peer.value().address);
        }
    }

    pub async fn connect_peer(
        &self,
        peer_config: &MeshWireGuardPeer,
    ) -> Result<(), MeshTransportError> {
        let peer_id = peer_config.public_key.clone();
        let endpoint = peer_config
            .endpoint
            .clone()
            .ok_or_else(|| MeshTransportError::ConnectionFailed("No endpoint".to_string()))?;

        let wireguard_ip = peer_config
            .allowed_ips
            .first()
            .map(|ip| ip.trim_end_matches("/24").to_string())
            .unwrap_or_else(|| "10.100.0.2".to_string());

        let state = WireGuardPeerState {
            address: endpoint.clone(),
            wireguard_ip: wireguard_ip.clone(),
            last_seen: Instant::now(),
        };

        self.peer_states.insert(peer_id.clone(), state);

        self.topology
            .add_peer(
                crate::mesh::protocol::MeshPeerInfo {
                    node_id: peer_id.clone(),
                    address: wireguard_ip,
                    role: MeshNodeRole::Edge,
                    capabilities: crate::mesh::protocol::MeshCapabilities {
                        can_route: true,
                        can_proxy: true,
                        max_hops: self.config.routing.max_hops,
                        supported_services: Vec::new(),
                        preferred_transport: Some(
                            crate::mesh::transports::MeshTransportType::WireGuard,
                        ),
                    },
                    is_global: false,
                    latency_ms: None,
                    upstreams: Vec::new(),
                    is_trusted: false,
                    quic_port: None,
                    wireguard_port: None,
                    advertised_port: None,
                    dns_serving_healthy: false,
                },
                PeerStatus::Healthy,
            )
            .await;

        tracing::info!(
            "Connected to WireGuard mesh peer: {} at {}",
            peer_id,
            endpoint
        );

        Ok(())
    }

    async fn send_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<(), MeshTransportError> {
        let peer = self
            .peer_states
            .get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotConnected(peer_id.to_string()))?;

        let addr: SocketAddr = peer
            .address
            .parse()
            .map_err(|e| MeshTransportError::SendFailed(format!("Invalid peer address: {}", e)))?;

        let socket_guard = self.socket.read().await;
        let socket = socket_guard
            .as_ref()
            .ok_or(MeshTransportError::NotAvailable)?;

        socket
            .send_to(data, addr)
            .await
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;

        Ok(())
    }
}

impl MeshTransportTrait for WireGuardMeshTransport {
    fn transport_type(&self) -> MeshTransportType {
        MeshTransportType::WireGuard
    }

    fn is_connected(&self, peer_id: &str) -> bool {
        self.peer_states.contains_key(peer_id)
    }

    fn get_peer_address(&self, peer_id: &str) -> Option<String> {
        self.peer_states
            .get(peer_id)
            .map(|p| p.wireguard_ip.clone())
    }

    async fn send_stream(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let encoded = message
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;

        let mut packet = Vec::with_capacity(MESH_HEADER_SIZE + encoded.len());
        let len = (encoded.len() as u32).to_be_bytes();
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encoded);

        self.send_to_peer(peer_id, &packet).await
    }

    async fn send_datagram(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let encoded = message
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;

        self.send_to_peer(peer_id, &encoded).await
    }

    async fn broadcast_datagram(&self, message: &MeshMessage) -> Result<(), MeshTransportError> {
        let encoded = message
            .encode()
            .map_err(|e| MeshTransportError::SendFailed(e.to_string()))?;

        for entry in self.peer_states.iter() {
            let peer_id = entry.key();
            if let Err(e) = self.send_to_peer(peer_id, &encoded).await {
                tracing::warn!("Failed to send broadcast to {}: {}", peer_id, e);
            }
        }

        Ok(())
    }

    fn get_connected_peers(&self) -> Vec<String> {
        self.peer_states.iter().map(|e| e.key().clone()).collect()
    }

    fn local_addresses(&self) -> Vec<String> {
        self.local_addresses.read().clone()
    }

    fn is_available(&self) -> bool {
        self.wireguard_config.enabled && *self.running.read()
    }
}

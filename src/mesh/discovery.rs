use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::mesh::cert::MeshCertManager;
use crate::mesh::config::{MeshConfig, MeshSeedNode};
use crate::mesh::protocol::{MeshCapabilities, MeshMessage, MESH_MESSAGE_VERSION};
use crate::mesh::topology::{MeshTopology, PeerStatus};

pub struct MeshDiscovery {
    config: Arc<MeshConfig>,
    topology: Arc<MeshTopology>,
    cert_manager: Arc<RwLock<MeshCertManager>>,
    running: Arc<RwLock<bool>>,
    shutdown_tx: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
}

impl MeshDiscovery {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        cert_manager: Arc<RwLock<MeshCertManager>>,
        record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
    ) -> Self {
        Self {
            config,
            topology,
            cert_manager,
            running: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            record_store,
        }
    }

    pub async fn start(&self) -> Result<(), MeshDiscoveryError> {
        {
            let mut running = self.running.write();
            if *running {
                return Ok(());
            }
            *running = true;
        }

        let (tx, mut rx) = mpsc::channel::<()>(1);
        {
            let mut shutdown = self.shutdown_tx.write();
            *shutdown = Some(tx);
        }

        let config = self.config.clone();
        let topology = self.topology.clone();
        let cert_manager = self.cert_manager.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::maintain_connections(&config, &topology, &cert_manager).await {
                            tracing::warn!("Mesh maintenance error: {}", e);
                        }
                    }
                    _ = rx.recv() => {
                        tracing::info!("Mesh discovery shutting down");
                        break;
                    }
                }
            }

            let mut is_running = self.running.write();
            *is_running = false;
        });

        if !self.config.seeds.is_empty() {
            self.bootstrap_from_seeds().await?;
        }

        Ok(())
    }

    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.write().take() {
            let _ = tx.send(()).await;
        }
    }

    async fn bootstrap_from_seeds(&self) -> Result<(), MeshDiscoveryError> {
        for seed in &self.config.seeds {
            match self.connect_to_seed(seed).await {
                Ok(_) => {
                    tracing::info!("Connected to seed node: {}", seed.address);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to seed {}: {}", seed.address, e);
                }
            }
        }

        tracing::warn!("All seeds failed, trying peer-to-peer bootstrap from cached peers");
        self.bootstrap_from_cached_peers().await?;

        Err(MeshDiscoveryError::NoSeedsAvailable)
    }

    async fn bootstrap_from_cached_peers(&self) -> Result<(), MeshDiscoveryError> {
        let peer_cache_path = self.config.persistence.peer_cache_path.as_ref();

        let Some(path) = peer_cache_path else {
            tracing::debug!("No peer cache path configured");
            return Ok(());
        };

        if let Err(e) = self.topology.load_peers_from_file(path).await {
            tracing::warn!("Failed to load peers from cache: {}", e);
            return Ok(());
        };

        let peers = self.topology.get_all_peers().await;

        if peers.is_empty() {
            tracing::debug!("No cached peers to bootstrap from");
            return Ok(());
        }

        tracing::info!("Trying to bootstrap from {} cached peers", peers.len());

        let mut connected = false;
        for peer in peers {
            if peer.is_global {
                continue;
            }

            tracing::debug!("Attempting to connect to cached peer: {}", peer.address);

            match self.try_connect_peer(&peer.address).await {
                Ok(_) => {
                    tracing::info!("Connected to cached peer: {}", peer.address);
                    connected = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to cached peer {}: {}", peer.address, e);
                }
            }
        }

        if connected {
            return Ok(());
        }

        tracing::warn!("Failed to bootstrap from any cached peer");
        Ok(())
    }

    async fn try_connect_peer(&self, address: &str) -> Result<(), MeshDiscoveryError> {
        self.topology.add_peer(
            crate::mesh::protocol::MeshPeerInfo {
                node_id: address.to_string(),
                address: address.to_string(),
                role: crate::mesh::config::MeshNodeRole::EDGE,
                capabilities: MeshCapabilities {
                    can_route: true,
                    can_proxy: true,
                    max_hops: self.config.routing.max_hops,
                    supported_services: vec![],
                    preferred_transport: Some(crate::mesh::transports::MeshTransportType::Quic),
                },
                is_global: false,
                latency_ms: None,
                upstreams: vec![],
                is_trusted: false,
                quic_port: None,
                wireguard_port: None,
                advertised_port: None,
                dns_serving_healthy: false,
            },
            PeerStatus::Connecting,
        ).await;

        Ok(())
    }

    async fn connect_to_seed(&self, seed: &MeshSeedNode) -> Result<(), MeshDiscoveryError> {
        let cert_manager = self.cert_manager.read();
        cert_manager.add_seed_public_key(&seed.address, seed.public_key.clone());

        if let Some(ref pinned_fp) = seed.pinned_cert_fingerprint {
            let fingerprints = cert_manager.get_pinned_fingerprints();
            if !fingerprints.contains_key(&seed.address) {
                drop(cert_manager);
                let cert_manager = self.cert_manager.read();
                cert_manager.pin_seed_fingerprint(&seed.address, pinned_fp);
                tracing::info!("TOFU: Loaded pre-configured fingerprint for seed {}", seed.address);
            }
        }
        drop(cert_manager);

        tracing::debug!("Connecting to seed: {}", seed.address);

        self.topology.add_peer(
            crate::mesh::protocol::MeshPeerInfo {
                node_id: seed.address.clone(),
                address: seed.address.clone(),
                role: crate::mesh::config::MeshNodeRole::GLOBAL,
                capabilities: MeshCapabilities {
                    can_route: true,
                    can_proxy: true,
                    max_hops: self.config.routing.max_hops,
                    supported_services: vec![],
                    preferred_transport: Some(crate::mesh::transports::MeshTransportType::Quic),
                },
                is_global: true,
                latency_ms: None,
                upstreams: vec![],
                is_trusted: true,
                quic_port: None,
                wireguard_port: None,
                advertised_port: None,
                dns_serving_healthy: false,
            },
            PeerStatus::Connecting,
        ).await;

        Ok(())
    }

    async fn maintain_connections(
        config: &Arc<MeshConfig>,
        topology: &Arc<MeshTopology>,
        cert_manager: &Arc<RwLock<MeshCertManager>>,
    ) -> Result<(), MeshDiscoveryError> {
        let peers = topology.get_all_peers().await;

        for peer in peers {
            if !peer.is_healthy() {
                if let Some(updated) = topology.get_peer(&peer.node_id).await {
                    tracing::debug!("Peer {} status: {:?}", peer.node_id, updated.status);
                }
            }
        }

        if !topology.is_global() {
            if let Some(global_id) = topology.get_closest_global_node().await {
                topology.set_degraded(false);
                Self::sync_with_global(topology, &global_id).await?;
            } else {
                if !config.seeds.is_empty() {
                    tracing::warn!("No global nodes available, attempting seed reconnection");
                }
                topology.set_degraded(true);
            }
        }

        topology.cleanup_expired_queries(Duration::from_secs(10)).await;
        topology.cleanup_expired_cache().await;

        Ok(())
    }

    async fn sync_with_global(
        topology: &Arc<MeshTopology>,
        global_node_id: &str,
    ) -> Result<(), MeshDiscoveryError> {
        tracing::debug!("Syncing topology with global node: {}", global_node_id);

        let request = MeshMessage::SeedListRequest {
            node_id: topology.node_id().to_string(),
            request_full_mesh: true,
        };

        tracing::trace!("Would send SeedListRequest to {}", global_node_id);

        Ok(())
    }

    pub async fn handle_seed_list_response(
        &self,
        global_nodes: Vec<crate::mesh::protocol::MeshPeerInfo>,
        edge_nodes: Vec<crate::mesh::protocol::MeshPeerInfo>,
        version: u64,
    ) {
        tracing::info!("Received seed list from global: {} global, {} edge nodes (v{})",
            global_nodes.len(), edge_nodes.len(), version);

        self.topology.add_seeded_nodes(global_nodes.clone()).await;
        
        for node in edge_nodes {
            if !self.topology.get_peer(&node.node_id).await.is_some() {
                self.topology.add_peer(
                    node,
                    crate::mesh::topology::PeerStatus::Connecting,
                ).await;
            }
        }

        tracing::info!("Seeded topology updated with {} known nodes", global_nodes.len() + edge_nodes.len());
    }

    pub async fn build_seed_list_response(&self, request_full_mesh: bool) -> MeshMessage {
        let global_nodes = if request_full_mesh {
            self.topology.get_seeded_global_nodes().await
        } else {
            Vec::new()
        };

        let edge_nodes = if request_full_mesh {
            self.topology.get_seeded_edge_nodes().await
        } else {
            Vec::new()
        };

        MeshMessage::SeedListResponse {
            global_nodes,
            edge_nodes,
            version: 1,
        }
    }

    pub async fn connect_to_peer(&self, address: &str) -> Result<String, MeshDiscoveryError> {
        tracing::info!("Connecting to mesh peer: {}", address);

        let cert_manager = self.cert_manager.read();
        let node_id = cert_manager.node_id().to_string();
        let role = self.config.role;
        let capabilities = MeshCapabilities {
            can_route: true,
            can_proxy: true,
            max_hops: self.config.routing.max_hops,
            supported_services: self
                .config
                .local_upstreams
                .keys()
                .cloned()
                .collect(),
            preferred_transport: Some(crate::mesh::transports::MeshTransportType::Quic),
        };
        drop(cert_manager);

        let local_upstreams: HashMap<String, crate::mesh::protocol::UpstreamInfo> = self
            .topology
            .get_local_upstreams()
            .into_iter()
            .map(|u| (u.upstream_id.clone(), u))
            .collect();

        let hello = MeshMessage::Hello {
            version: MESH_MESSAGE_VERSION,
            node_id: node_id.clone(),
            role,
            capabilities,
            upstreams: local_upstreams,
        };

        tracing::debug!("Would send Hello to peer: {}", address);

        Ok(address.to_string())
    }

    pub fn handle_hello(&self, msg: MeshMessage) -> Result<MeshMessage, MeshDiscoveryError> {
        match msg {
            MeshMessage::Hello {
                version,
                node_id,
                role,
                capabilities,
                upstreams,
                quic_port,
                wireguard_port,
                public_key,
                pow_nonce,
                pow_public_key,
                global_node_key,
                ..
            } => {
                if version != MESH_MESSAGE_VERSION {
                    return Err(MeshDiscoveryError::VersionMismatch {
                        expected: MESH_MESSAGE_VERSION,
                        got: version,
                    });
                }

                if let Some(ref pk) = public_key {
                    use base64::Engine;
                    if let Ok(pk_bytes) = base64::engine::general_purpose::STANDARD.decode(pk.as_str()) {
                        let expected_node_id = crate::mesh::dht::routing::node_id::NodeId::from_public_key(&pk_bytes);
                        let claimed_node_id = crate::mesh::dht::routing::node_id::NodeId::from_node_id_string(node_id.as_str());
                        if expected_node_id != claimed_node_id {
                            tracing::warn!("Node ID mismatch from incoming connection: peer claimed {} but their public key derives {}",
                                node_id, expected_node_id);
                            return Err(MeshDiscoveryError::AuthFailed("Node ID does not match public key".to_string()));
                        }
                    }
                } else {
                    tracing::warn!("Incoming connection from {} did not provide public key", node_id);
                    return Err(MeshDiscoveryError::AuthFailed("Public key required for authentication".to_string()));
                }

                let is_edge = role.is_edge();
                if is_edge {
                    use base64::Engine;
                    if let (Some(nonce), Some(ref pk_str)) = (pow_nonce, pow_public_key) {
                        if let Ok(pk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_str.as_str()) {
                            let claimed_node_id = crate::mesh::dht::routing::node_id::NodeId::from_node_id_string(node_id.as_str());
                            if !claimed_node_id.verify_pow(&pk_bytes, nonce) {
                                tracing::warn!("PoW verification failed for edge node {}", node_id);
                                return Err(MeshDiscoveryError::AuthFailed("PoW verification failed".to_string()));
                            }
                            tracing::debug!("PoW verified for edge node {}", node_id);
                        } else {
                            return Err(MeshDiscoveryError::AuthFailed("Invalid PoW public key format".to_string()));
                        }
                    } else {
                        return Err(MeshDiscoveryError::AuthFailed("Edge node must provide PoW".to_string()));
                    }
                }

                // Ed25519 challenge-response authentication for global nodes
                if let Err(e) = crate::mesh::peer_auth::validate_peer_role(
                    &role,
                    &self.get_authorized_global_pubkeys(),
                    &node_id,
                    public_key.as_ref().map(|pk| pk.as_str()),
                    global_node_key.as_ref().map(|sk| sk.as_str()),
                    timestamp.unwrap_or(0),
                    300,
                ) {
                    tracing::warn!("{}", e);
                    return Err(MeshDiscoveryError::AuthFailed(e));
                }

                let peer_info = crate::mesh::protocol::MeshPeerInfo {
                    node_id: node_id.clone(),
                    address: String::new(),
                    role,
                    capabilities: capabilities.clone(),
                    is_global: role.is_global(),
                    latency_ms: None,
                    upstreams: upstreams.keys().cloned().collect(),
                    is_trusted: role.is_global(),
                    quic_port,
                    wireguard_port,
                    advertised_port: quic_port.or(wireguard_port),
                    dns_serving_healthy: false,
                };

                self.topology.add_peer(peer_info, PeerStatus::Handshake);

                if let Some(upstreams) = self.build_hello_upstreams() {
                    let global_node_auth_sig = self.generate_global_node_auth_sig();
                    return Ok(MeshMessage::HelloAck {
                        version: MESH_MESSAGE_VERSION,
                        node_id: self.topology.node_id().to_string(),
                        role: self.config.role,
                        session_id: format!("{}-{}", self.topology.node_id(), node_id),
                        capabilities: crate::mesh::protocol::MeshCapabilities::from_config(&self.config, self.config.role),
                        upstreams,
                        auth_token: None,
                        network_id: self.config.network_id.clone().map(|s| s.into()),
                        global_node_key: global_node_auth_sig.map(|s| s.into()),
                        timestamp: Some(MeshMessage::generate_timestamp()),
                        nonce: Some(MeshMessage::generate_nonce()),
                        is_trusted: self.config.is_trusted_node(),
                        quic_port: Some(self.config.get_quic_port()),
                        wireguard_port: self.config.get_advertised_wireguard_port(),
                        public_key: self.config.signing_public_key().map(|s| s.into()),
                    });
                }

                let global_node_auth_sig = self.generate_global_node_auth_sig();
                Ok(MeshMessage::HelloAck {
                    version: MESH_MESSAGE_VERSION,
                    node_id: self.topology.node_id().to_string(),
                    role: self.config.role,
                    session_id: format!("{}-{}", self.topology.node_id(), node_id),
                    capabilities: crate::mesh::protocol::MeshCapabilities::from_config(&self.config, self.config.role),
                    upstreams: HashMap::new(),
                    auth_token: None,
                    network_id: self.config.network_id.clone().map(|s| s.into()),
                    global_node_key: global_node_auth_sig.map(|s| s.into()),
                    timestamp: Some(MeshMessage::generate_timestamp()),
                    nonce: Some(MeshMessage::generate_nonce()),
                    is_trusted: self.config.is_trusted_node(),
                    quic_port: Some(self.config.get_quic_port()),
                    wireguard_port: self.config.get_advertised_wireguard_port(),
                    public_key: self.config.signing_public_key().map(|s| s.into()),
                })
            }
            _ => Err(MeshDiscoveryError::UnexpectedMessage),
        }
    }

    fn build_hello_upstreams(&self) -> Option<HashMap<String, crate::mesh::protocol::UpstreamInfo>> {
        if self.topology.is_global() {
            let peers = self.topology.get_all_peers().await;
            let mut upstreams: HashMap<String, crate::mesh::protocol::UpstreamInfo> = HashMap::new();

            for peer in peers {
                for upstream_id in peer.upstreams {
                    upstreams.insert(
                        upstream_id.clone(),
                        crate::mesh::protocol::UpstreamInfo {
                            upstream_id,
                            upstream_url: None,
                            geo: None,
                            is_local: false,
                            owner_node_id: String::new(),
                            peered_wafs: vec![],
                            url_hash: String::new(),
                        },
                    );
                }
            }

            Some(upstreams)
        } else {
            None
        }
    }

    pub async fn send_route_query(&self, upstream_id: &str) -> Result<String, MeshDiscoveryError> {
        if let Some((provider, _)) = self.topology.get_cached_route(upstream_id).await {
            tracing::debug!("Using cached route for upstream {}: {}", upstream_id, provider);
            return Ok(provider);
        }

        if self.topology.can_forward_service(upstream_id) {
            let peer_query_count = self.config.routing.peer_query_count.min(3);

            let known_peers = self.topology.get_best_peers_for_query(upstream_id, peer_query_count).await;

            if !known_peers.is_empty() {
                tracing::debug!(\n                    "Querying {} peers for upstream {}: {:?}",\n                    known_peers.len(),\n                    upstream_id,\n                    known_peers\n                );
            }

            if let Some(global_id) = self.topology.get_closest_global_node().await {
                tracing::debug!("Querying global node {} for upstream {}", global_id, upstream_id);
                return Ok(global_id);
            }
        }

        if let Some(local) = self.topology.get_upstream_info(upstream_id).await {
            if local.is_local {
                return Ok(self.topology.node_id().to_string());
            }
        }

        Err(MeshDiscoveryError::NoRouteToUpstream(upstream_id.to_string()))
    }

    pub async fn handle_route_response(&self, msg: MeshMessage) {
        if let MeshMessage::RouteResponse {
            query_id,
            upstream_id,
            provider_node_id,
            hops,
            ttl_secs,
            upstream_url,
            waf_policy,
            priority_tier,
            ..
        } = msg
        {
            self.topology.cache_route(
                &upstream_id,
                provider_node_id.clone(),
                hops,
                Duration::from_secs(ttl_secs as u64),
            ).await;

            tracing::debug!(
                "Cached route: upstream {} -> node {} ({} hops, {}s TTL)",
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs
            );
        }
    }

    /// Collects authorized global node public keys from seed node configuration.
    fn get_authorized_global_pubkeys(&self) -> Vec<String> {
        self.config.seeds.iter()
            .filter_map(|seed| seed.public_key.clone())
            .collect()
    }

    /// Generates an Ed25519 signature for global node authentication in HelloAck responses.
    fn generate_global_node_auth_sig(&self) -> Option<String> {
        if !self.config.role.is_global() {
            return None;
        }
        if let Some(sk) = self.config.signing_key() {
            if sk.len() == 32 {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(sk);
                match crate::mesh::peer_auth::generate_global_node_auth(&self.topology.node_id(), &key_bytes) {
                    Ok((sig, _ts)) => Some(sig),
                    Err(e) => {
                        tracing::warn!("Failed to generate global node auth signature: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshDiscoveryError {
    #[error("No seed nodes available")]
    NoSeedsAvailable,
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },
    #[error("Unexpected message type")]
    UnexpectedMessage,
    #[error("No route to upstream: {0}")]
    NoRouteToUpstream(String),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Timeout")]
    Timeout,
}

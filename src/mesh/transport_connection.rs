#![allow(dead_code)] // Reserved for future mesh connection handling

use crate::mesh::transport::{
    MeshPeerConnection, MeshTransport, MeshTransportError, MAX_MESSAGE_SIZE,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::mesh::config::{MeshConfig, MeshPeerConfig};
use crate::mesh::protocol::MeshMessage;
use crate::mesh::topology::{MeshTopology, PeerStatus};

impl MeshTransport {
    pub(crate) fn clone_for_maintenance(&self) -> MeshTransport {
        MeshTransport {
            config: self.config.clone(),
            topology: self.topology.clone(),
            cert_manager: self.cert_manager.clone(),
            runtime: self.runtime.clone(),
            running: self.running.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            peer_connections: self.peer_connections.clone(),
            auth_keys: self.auth_keys.clone(),
            connection_times: self.connection_times.clone(),
            query_dedup: self.query_dedup.clone(),
            pending_queries: self.pending_queries.clone(),
            pending_dht_queries: self.pending_dht_queries.clone(),
            auth_failures: self.auth_failures.clone(),
            peer_message_times: self.peer_message_times.clone(),
            global_rate_limiter: self.global_rate_limiter.clone(),
            org_manager: self.org_manager.clone(),
            tier_key_store: self.tier_key_store.clone(),
            tier_key_encryption: self.tier_key_encryption.clone(),
            origin_ed25519_signer: self.origin_ed25519_signer.clone(),
            mesh_signer: self.mesh_signer.clone(),
            record_store: self.record_store.clone(),
            routing_manager: self.routing_manager.clone(),
            threat_intel: self.threat_intel.clone(),
            yara_rules: self.yara_rules.clone(),
            seen_messages: Arc::new(RwLock::new(
                lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                    Duration::from_secs(300),
                    10000,
                ),
            )),
            stake_manager: self.stake_manager.clone(),
            mlkem_session_manager: self.mlkem_session_manager.clone(),
            dns_resolver: self.dns_resolver.clone(),
            #[cfg(feature = "dns")]
            dns_registry: self.dns_registry.clone(),
            #[cfg(feature = "dns")]
            dns_zones: self.dns_zones.clone(),
            site_config_sync_tx: self.site_config_sync_tx.clone(),
            verification_manager: self.verification_manager.clone(),
            revocation_list: self.revocation_list.clone(),
        }
    }

    pub(crate) async fn datagram_listener_loop(
        peer_connections: Arc<DashMap<String, MeshPeerConnection>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Datagram listener stopped");
                    break;
                }
                _ = async {
                    for entry in peer_connections.iter() {
                        let connection = &entry.value().connection;
                        if let Ok(data) = connection.read_datagram().await {
                            let peer_id = entry.key().clone();
                            tracing::debug!("Received datagram from {}: {} bytes", peer_id, data.len());
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } => {}
            }
        }
    }

    pub(crate) async fn mesh_maintenance_loop(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        peer_connections: Arc<DashMap<String, MeshPeerConnection>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let announce_interval_secs = config.connection.announce_interval_secs;
        let keepalive_interval_secs = config.connection.keepalive_interval_secs;

        let mut announce_interval =
            tokio::time::interval(Duration::from_secs(announce_interval_secs));
        let mut keepalive_interval =
            tokio::time::interval(Duration::from_secs(keepalive_interval_secs));
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Mesh maintenance loop shutting down");
                    break;
                }
                _ = announce_interval.tick() => {
                    Self::handle_announcements(&topology, &peer_connections).await;
                }
                _ = keepalive_interval.tick() => {
                    Self::send_keepalives(&peer_connections).await;
                }
                _ = cleanup_interval.tick() => {
                    Self::cleanup_stale_connections(&peer_connections, &topology).await;
                    Self::cleanup_blocked_upstreams(&topology).await;
                    if let Some(partition) = topology.check_network_partition().await {
                        match partition {
                            crate::mesh::topology::NetworkPartitionState::Isolated { .. } => {
                                tracing::warn!("Network partition detected: isolated from all peers");
                            }
                            crate::mesh::topology::NetworkPartitionState::DisconnectedFromGlobal { .. } => {
                                tracing::warn!("Network partition detected: disconnected from global nodes");
                            }
                            crate::mesh::topology::NetworkPartitionState::Degraded { .. } => {
                                tracing::warn!("Network partition detected: degraded peer connectivity");
                            }
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn cleanup_blocked_upstreams(topology: &Arc<MeshTopology>) {
        topology.cleanup_expired_blocks().await;
    }

    pub(crate) async fn dht_bootstrap_from_seeds(
        &self,
        routing_manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>,
    ) -> Result<(), MeshTransportError> {
        let seeds = routing_manager.get_seeds_from_config();

        if seeds.is_empty() {
            tracing::debug!("No seed nodes configured for DHT bootstrap");
            return Ok(());
        }

        tracing::info!("Starting DHT bootstrap from {} seed nodes", seeds.len());

        for seed in &seeds {
            let is_connected = self.peer_connections.contains_key(&seed.node_id);

            if is_connected {
                routing_manager
                    .add_peer(
                        seed.node_id.clone(),
                        seed.address.clone(),
                        seed.port,
                        crate::mesh::config::MeshNodeRole::GLOBAL,
                        None,
                        true,
                        seed.geo.clone(),
                        None,
                        None,
                    )
                    .await;

                let local_id = *routing_manager.local_node_id_hash();
                let request_id = format!("dht-bootstrap-{}", uuid::Uuid::new_v4());

                let find_node = MeshMessage::FindNode {
                    request_id: request_id.into(),
                    target_node_id: local_id.as_bytes().to_vec(),
                    requester_node_id: routing_manager.local_node_id().into(),
                    timestamp: crate::utils::safe_unix_timestamp(),
                };

                if let Err(e) = self.send_datagram_to_peer(&seed.node_id, &find_node).await {
                    tracing::warn!(
                        "Failed to send FindNode to DHT seed {}: {}",
                        seed.node_id,
                        e
                    );
                } else {
                    tracing::debug!("Sent DHT FindNode to seed {}", seed.node_id);
                }
            } else {
                tracing::debug!(
                    "Seed {} not connected yet, will bootstrap when connected",
                    seed.node_id
                );
            }
        }

        let peer_count = routing_manager.total_peers().await;
        tracing::info!(
            "DHT bootstrap complete: {} peers in routing table",
            peer_count
        );

        Ok(())
    }

    pub(crate) async fn dht_on_peer_connected(
        &self,
        peer_node_id: &str,
        peer_address: &str,
        peer_role: crate::mesh::config::MeshNodeRole,
    ) {
        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                rm.add_peer(
                    peer_node_id.to_string(),
                    peer_address.to_string(),
                    443,
                    peer_role,
                    None,
                    false,
                    None,
                    None,
                    None,
                )
                .await;

                let _local_id = *rm.local_node_id_hash();
                let request_id = format!("dht-ping-{}", uuid::Uuid::new_v4());

                let ping = MeshMessage::Ping {
                    request_id: request_id.into(),
                    node_id: rm.local_node_id().into(),
                    timestamp: crate::utils::safe_unix_timestamp(),
                };

                if let Err(e) = self.send_datagram_to_peer(peer_node_id, &ping).await {
                    tracing::debug!("Failed to send DHT Ping to {}: {}", peer_node_id, e);
                }
            }
        }
    }

    pub(crate) async fn request_seed_list(
        &self,
        global_node_id: &str,
    ) -> Result<(), MeshTransportError> {
        let request = MeshMessage::SeedListRequest {
            node_id: self.config.node_id().into(),
            request_full_mesh: true,
        };

        self.send_message_to_peer(global_node_id, &request).await?;
        tracing::debug!("Requested seed list from global node: {}", global_node_id);
        Ok(())
    }

    pub(crate) async fn handle_seed_list_response(
        &self,
        global_nodes: Vec<crate::mesh::protocol::MeshPeerInfo>,
        edge_nodes: Vec<crate::mesh::protocol::MeshPeerInfo>,
        genesis_org_id: Option<crate::mesh::protocol::ArcStr>,
    ) {
        tracing::info!(
            "Received seed list: {} global, {} edge nodes",
            global_nodes.len(),
            edge_nodes.len()
        );

        if let Some(ref org_id) = genesis_org_id {
            tracing::info!("Received genesis_org_id from seed: {}", org_id);
            let mut org_mgr = self.org_manager.write();
            org_mgr.set_genesis_org_id(org_id.to_string());
            tracing::info!("Set genesis_org_id to: {}", org_id);
        }

        self.topology.add_seeded_nodes(global_nodes.clone()).await;

        let edge_count = edge_nodes.len();
        for node in edge_nodes {
            if self.topology.get_peer(&node.node_id).await.is_none() {
                self.topology.add_peer(node, PeerStatus::Connecting).await;
            }
        }

        let global_count = global_nodes.len();
        tracing::info!(
            "Seeded topology with {} global nodes and {} edge nodes",
            global_count,
            edge_count
        );

        if let Some(ref record_store) = self.record_store {
            if !self.topology.is_global()
                && self
                    .config
                    .dht
                    .as_ref()
                    .map(|d| d.warm_up_on_connect)
                    .unwrap_or(true)
            {
                if let Some(request) = record_store.create_snapshot_request() {
                    if let Some(first_global) = global_nodes.first() {
                        tracing::info!(
                            "Requesting DHT cache warm-up from global node: {}",
                            first_global.node_id
                        );
                        if let Err(e) = self
                            .send_datagram_to_peer(&first_global.node_id, &request)
                            .await
                        {
                            tracing::warn!(
                                "Failed to request DHT snapshot from {}: {}",
                                first_global.node_id,
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn connect_to_peers(&self) -> Result<(), MeshTransportError> {
        for peer_config in &self.config.peers {
            match self.connect_to_peer(peer_config).await {
                Ok(_) => {
                    tracing::info!("Connected to peer: {}", peer_config.address);
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to peer {}: {}", peer_config.address, e);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn handle_announcements(
        topology: &MeshTopology,
        peer_connections: &DashMap<String, MeshPeerConnection>,
    ) {
        let _owners = topology.get_upstream_owners().await;

        for entry in peer_connections.iter() {
            let peer = entry.value();
            if !peer.role.is_global() {
                tracing::trace!("Would announce upstreams to peer {}", peer.node_id);
            }
        }
    }

    pub(crate) async fn send_keepalives(peer_connections: &DashMap<String, MeshPeerConnection>) {
        for entry in peer_connections.iter() {
            let peer = entry.value();
            let result = async {
                let (mut send_stream, mut recv_stream) = peer.connection.open_bi().await?;

                let msg = MeshMessage::KeepAlive;
                let encoded = msg.encode()?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await?;
                send_stream.write_all(&encoded).await?;

                let mut len_buf = [0u8; 4];
                recv_stream.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_MESSAGE_SIZE {
                    return Err(MeshTransportError::ReceiveFailed(format!(
                        "Keepalive response too large: {} bytes (max {})",
                        len, MAX_MESSAGE_SIZE
                    )));
                }
                let mut response_buf = vec![0u8; len];
                recv_stream.read_exact(&mut response_buf).await?;

                Ok::<_, MeshTransportError>(())
            }
            .await;

            match result {
                Ok(_) => {
                    tracing::trace!("Keepalive OK from {}", peer.node_id);
                }
                Err(e) => {
                    tracing::warn!("Keepalive failed to {}: {}", peer.node_id, e);
                }
            }
        }
    }

    pub(crate) async fn cleanup_stale_connections(
        peer_connections: &DashMap<String, MeshPeerConnection>,
        topology: &MeshTopology,
    ) {
        let stale_threshold = Duration::from_secs(120);
        let now = Instant::now();

        let stale: Vec<String> = peer_connections
            .iter()
            .filter(|e| now.duration_since(e.value().last_seen) > stale_threshold)
            .map(|e| e.key().clone())
            .collect();

        for session_id in stale {
            if let Some(peer) = peer_connections.get(&session_id) {
                tracing::warn!("Removing stale peer connection: {}", peer.node_id);
                topology.record_connection_failure(&peer.node_id).await;
                topology
                    .update_peer_status(&peer.node_id, PeerStatus::Disconnected)
                    .await;
            }
            peer_connections.remove(&session_id);
        }

        topology
            .cleanup_expired_queries(Duration::from_secs(10))
            .await;
        topology.cleanup_expired_cache().await;
    }

    pub(crate) async fn maintain_connections(&self) {
        if let Some(ref stake_mgr) = self.stake_manager {
            if stake_mgr.get_config().strict_mode {
                if let Some(ref threat_intel) = self.threat_intel {
                    let rep_mgr = threat_intel.get_reputation_manager();
                    stake_mgr.sync_from_reputation(&rep_mgr);
                }
            }
        }

        let min_connections = self.config.connection.min_peer_connections;
        let max_connections = self.config.connection.max_peer_connections;

        let current_count = self.peer_connections.len();

        if current_count >= min_connections {
            tracing::debug!(
                "Connection pool sufficient: {}/{}",
                current_count,
                min_connections
            );
            return;
        }

        let targets = self.topology.get_prioritized_connection_targets().await;

        for (node_id, priority) in targets {
            if self.peer_connections.len() >= max_connections {
                break;
            }

            if self.is_connected_to(&node_id) {
                continue;
            }

            tracing::info!(
                "Attempting to connect to prioritized peer: {} ( {:?})",
                node_id,
                priority
            );

            let address = self
                .topology
                .get_peer(&node_id)
                .await
                .map(|p| p.address.clone())
                .unwrap_or_else(|| node_id.clone());

            let peer_config = MeshPeerConfig {
                address,
                auth_token: None,
            };

            match self.connect_to_peer(&peer_config).await {
                Ok(_) => {
                    tracing::info!("Connected to prioritized peer: {}", node_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to {}: {}", node_id, e);
                }
            }
        }
    }

    pub(crate) async fn perform_auto_slash(&self) {
        let Some(ref stake_mgr) = self.stake_manager else {
            return;
        };

        if !stake_mgr.get_config().slashing_enabled {
            return;
        }

        let connected_peers: std::collections::HashSet<_> = self
            .peer_connections
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        let auth_failures: Vec<String> = {
            let failures = self.auth_failures.read();
            let now = Instant::now();
            let threshold = Duration::from_secs(3600);

            failures
                .iter()
                .filter(|(node_id, times)| {
                    connected_peers.contains(*node_id) && {
                        let recent: Vec<_> = times
                            .iter()
                            .filter(|t| now.duration_since(**t) < threshold)
                            .collect();
                        recent.len() >= 5
                    }
                })
                .map(|(id, _)| id.clone())
                .collect()
        };

        for node_id in auth_failures {
            tracing::warn!(
                "Auto-slasher: Node {} detected with repeated auth failures",
                node_id
            );
            stake_mgr.slash_node(
                &node_id,
                crate::mesh::dht::stake::SlashReason::RepeatedMisbehavior,
                "auto-slash",
            );
        }

        if let Some(ref threat_intel) = self.threat_intel {
            let rep_mgr = threat_intel.get_reputation_manager();
            let peer_ids = rep_mgr.get_all_peer_ids();

            for node_id in peer_ids {
                if !connected_peers.contains(&node_id) {
                    continue;
                }
                if let Some(rep) = rep_mgr.get_peer_reputation(&node_id) {
                    if rep.false_positive_reports > 10 {
                        tracing::warn!(
                            "Auto-slasher: Node {} has {} false positive reports",
                            node_id,
                            rep.false_positive_reports
                        );
                        stake_mgr.slash_node(
                            &node_id,
                            crate::mesh::dht::stake::SlashReason::RepeatedMisbehavior,
                            "auto-slash",
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn is_connected_to(&self, node_id: &str) -> bool {
        self.peer_connections
            .iter()
            .any(|e| e.value().node_id == node_id)
    }
}

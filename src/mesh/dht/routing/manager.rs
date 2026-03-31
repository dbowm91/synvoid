use std::sync::Arc;
use std::time::Instant;

use lru_time_cache::LruCache;
use tokio::sync::RwLock;

use crate::mesh::config::{MeshConfig, MeshNodeRole};
use crate::mesh::dht::routing::contact::{GeoInfo, PeerContact};
use crate::mesh::dht::routing::geo_distance::{GeoDistance, GeoRoutingConfig};
use crate::mesh::dht::routing::node_id::NodeId;
use crate::mesh::dht::routing::query::LookupQuery;
use crate::mesh::dht::routing::regional_hubs::{RegionalHub, RegionalHubConfig};
use crate::mesh::dht::routing::table::PersistedRoutingTable;
use crate::mesh::dht::routing::table::RoutingTable;
use crate::mesh::dht::routing::table::REPLICATION_K;
use crate::mesh::protocol::MeshMessage;

pub struct DhtRoutingManager {
    routing_table: Arc<RwLock<Option<RoutingTable>>>,
    node_id: String,
    node_id_hash: NodeId,
    config: Arc<MeshConfig>,
    routing_enabled: bool,
    full_network_view: bool,
    edge_can_respond_privileged: bool,
    is_global: bool,
    geo_config: GeoRoutingConfig,
    hub_config: RegionalHubConfig,
}

impl Clone for DhtRoutingManager {
    fn clone(&self) -> Self {
        Self {
            routing_table: self.routing_table.clone(),
            node_id: self.node_id.clone(),
            node_id_hash: self.node_id_hash,
            config: self.config.clone(),
            routing_enabled: self.routing_enabled,
            full_network_view: self.full_network_view,
            edge_can_respond_privileged: self.edge_can_respond_privileged,
            is_global: self.is_global,
            geo_config: self.geo_config.clone(),
            hub_config: self.hub_config.clone(),
        }
    }
}

impl DhtRoutingManager {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        let node_id = config.node_id();
        let node_id_hash = NodeId::from_node_id_string(&node_id);

        let dht_config = config.dht.as_ref();
        let routing_enabled = dht_config.map(|d| d.routing_enabled).unwrap_or(true);
        let full_network_view = dht_config.map(|d| d.full_network_view).unwrap_or(false);
        let edge_can_respond_privileged = dht_config
            .map(|d| d.edge_can_respond_privileged)
            .unwrap_or(false);
        let is_global = config.role.is_global();

        let geo_config = dht_config
            .and_then(|d| d.geo_routing.clone())
            .unwrap_or_default();

        let hub_config = dht_config
            .and_then(|d| d.regional_hubs.clone())
            .unwrap_or_default();

        Self {
            routing_table: Arc::new(RwLock::new(None)),
            node_id,
            node_id_hash,
            config,
            routing_enabled,
            full_network_view,
            edge_can_respond_privileged,
            is_global,
            geo_config,
            hub_config,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.routing_enabled
    }

    pub fn wants_full_network_view(&self) -> bool {
        self.full_network_view
    }

    pub fn is_global(&self) -> bool {
        self.is_global
    }

    pub fn can_respond_to_privileged(&self) -> bool {
        self.is_global || self.edge_can_respond_privileged
    }

    pub fn can_respond_to_key(&self, key: &str) -> bool {
        use crate::mesh::dht::keys::DhtKey;
        let dht_key = DhtKey::from_str(key);

        if dht_key.is_privileged() {
            self.can_respond_to_privileged()
        } else {
            true
        }
    }

    pub async fn init(&self) {
        if !self.routing_enabled {
            tracing::info!("DHT Routing disabled");
            return;
        }

        let geo_distance = Arc::new(GeoDistance::new(self.geo_config.clone()));

        let hub = if self.hub_config.enabled {
            Some(Arc::new(RegionalHub::new(
                self.hub_config.clone(),
                self.geo_config.clone(),
            )))
        } else {
            None
        };

        let mut table = RoutingTable::new(self.node_id_hash, self.node_id.clone());

        table.set_geo_distance(geo_distance);

        if let Some(hub) = &hub {
            table.set_regional_hub(hub.clone());
        }

        let mut rt = self.routing_table.write().await;
        *rt = Some(table);

        tracing::info!(
            "DHT Routing initialized with geo-routing: {}, regional hubs: {}",
            self.geo_config.enabled,
            self.hub_config.enabled
        );
    }

    pub fn start_background_tasks(&self) {
        if !self.routing_enabled {
            return;
        }

        let self_arc = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;

                let peer_count = self_arc.total_peers().await;
                tracing::debug!("DHT routing table: {} peers", peer_count);

                let stats = self_arc.bucket_stats().await;
                if !stats.is_empty() {
                    let non_empty: usize = stats.iter().filter(|(_, c)| *c > 0).count();
                    tracing::debug!("DHT bucket stats: {} non-empty buckets", non_empty);
                }

                // Refresh regional hubs periodically
                if self_arc.hub_config.enabled {
                    self_arc.sync_regional_hub().await;
                    let hubs = self_arc.get_regional_hubs().await;
                    tracing::debug!("Regional hubs refreshed: {} total hubs", hubs.len());
                }
            }
        });

        tracing::info!("DHT routing background tasks started");
    }

    pub async fn init_with_persistence(&self, persisted: PersistedRoutingTable) {
        if !self.routing_enabled {
            return;
        }

        let table = RoutingTable::from_persisted(persisted, self.node_id_hash);

        let mut rt = self.routing_table.write().await;
        *rt = Some(table);
    }

    pub fn get_seeds_from_config(&self) -> Vec<SeedNode> {
        self.config
            .seeds
            .iter()
            .map(|seed| {
                let port = seed.quic_port.unwrap_or(443);
                SeedNode {
                    node_id: seed.node_id.clone().unwrap_or_else(|| seed.address.clone()),
                    address: seed.address.clone(),
                    port,
                    geo: None,
                }
            })
            .collect()
    }

    pub fn get_bootstrap_nodes_from_config(&self) -> Vec<SeedNode> {
        self.config
            .dht
            .as_ref()
            .map(|dht| {
                dht.bootstrap_nodes
                    .iter()
                    .map(|addr| SeedNode {
                        node_id: addr.clone(),
                        address: addr.clone(),
                        port: 443,
                        geo: None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn add_peer(
        &self,
        peer_node_id: String,
        address: String,
        port: u16,
        role: MeshNodeRole,
        latency_ms: Option<u32>,
        is_trusted: bool,
        geo: Option<crate::mesh::dht::routing::GeoInfo>,
        pow_nonce: Option<u64>,
        public_key: Option<Vec<u8>>,
    ) {
        let mut rt = self.routing_table.write().await;
        let table = match rt.as_mut() {
            Some(t) => t,
            None => return,
        };

        let node_id = NodeId::from_node_id_string(&peer_node_id);

        let mut contact = PeerContact::new(node_id, peer_node_id, address, port);

        if let Some(g) = geo {
            contact.geo = Some(g);
        }

        if let Some(latency) = latency_ms {
            contact.latency_ms = Some(latency);
        }

        contact.is_global = role.is_global();
        contact.is_trusted = is_trusted;
        contact.pow_nonce = pow_nonce;
        contact.public_key = public_key;

        table.try_insert(contact);
    }

    pub async fn remove_peer(&self, peer_node_id: &str) {
        let mut rt = self.routing_table.write().await;
        let table = match rt.as_mut() {
            Some(t) => t,
            None => return,
        };

        let node_id = NodeId::from_node_id_string(peer_node_id);
        table.remove(&node_id);
    }

    pub async fn update_peer_latency(&self, peer_node_id: &str, latency_ms: u32) {
        let mut rt = self.routing_table.write().await;
        let table = match rt.as_mut() {
            Some(t) => t,
            None => return,
        };

        let node_id = NodeId::from_node_id_string(peer_node_id);

        if let Some(contact) = table.get_contact(&node_id) {
            let mut contact = contact;
            contact.latency_ms = Some(latency_ms);
            table.try_insert(contact);
        }
    }

    pub async fn find_closest_peers(&self, target_key: &str, k: usize) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        let target_node_id = NodeId::from_node_id_string(target_key);
        table.find_closest(&target_node_id, k)
    }

    pub async fn find_closest_peers_hybrid(
        &self,
        target_key: &str,
        target_geo: Option<&GeoInfo>,
        k: usize,
    ) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        let target_node_id = NodeId::from_node_id_string(target_key);
        table.find_closest_hybrid(&target_node_id, target_geo, k)
    }

    pub async fn find_closest_for_key(&self, key: &str, k: usize) -> Vec<PeerContact> {
        use crate::mesh::dht::keys::DhtKey;

        let dht_key = DhtKey::from_str(key);

        if dht_key.is_privileged() {
            self.find_closest_global(k).await
        } else {
            self.find_closest_peers(key, k).await
        }
    }

    pub async fn sync_regional_hub(&self) {
        let rt = self.routing_table.read().await;
        if let Some(table) = rt.as_ref() {
            table.sync_to_regional_hub();
        }
    }

    pub async fn get_regional_hubs(&self) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        match rt.as_ref() {
            Some(t) => t.get_regional_hubs(),
            None => Vec::new(),
        }
    }

    pub async fn find_closest_global(&self, k: usize) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        let all_peers = table.get_all_contacts();
        let mut global_peers: Vec<_> = all_peers.into_iter().filter(|p| p.is_global).collect();

        let target_id = self.node_id_hash;
        global_peers.sort_by(|a, b| {
            let dist_a = target_id.xor_distance(&a.node_id);
            let dist_b = target_id.xor_distance(&b.node_id);
            dist_a.cmp(&dist_b)
        });

        global_peers.into_iter().take(k).collect()
    }

    pub async fn get_all_contacts(&self) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        table.get_all_contacts()
    }

    pub async fn find_closest_to_node_id(
        &self,
        target_node_id: &NodeId,
        k: usize,
    ) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        table.find_closest(target_node_id, k)
    }

    pub async fn get_persisted(&self) -> Option<PersistedRoutingTable> {
        let rt = self.routing_table.read().await;
        rt.as_ref().map(|t| t.to_persisted())
    }

    pub async fn get_persisted_bytes(&self) -> Option<Vec<u8>> {
        let rt = self.routing_table.read().await;
        rt.as_ref().and_then(|t| t.to_persisted_bytes().ok())
    }

    pub async fn init_with_persisted_bytes(&self, data: Vec<u8>) -> bool {
        match RoutingTable::from_persisted_bytes(data, self.node_id_hash) {
            Ok(table) => {
                let mut rt = self.routing_table.write().await;
                *rt = Some(table);
                true
            }
            Err(e) => {
                tracing::warn!("Failed to deserialize routing table: {}", e);
                false
            }
        }
    }

    pub fn local_node_id(&self) -> &str {
        &self.node_id
    }

    pub fn local_node_id_hash(&self) -> &NodeId {
        &self.node_id_hash
    }

    pub async fn total_peers(&self) -> usize {
        let rt = self.routing_table.read().await;
        rt.as_ref().map(|t| t.total_peers()).unwrap_or(0)
    }

    pub async fn bucket_stats(&self) -> Vec<(usize, usize)> {
        let rt = self.routing_table.read().await;
        rt.as_ref().map(|t| t.bucket_stats()).unwrap_or_default()
    }
}

pub struct DhtBootstrapper {
    routing_manager: Arc<DhtRoutingManager>,
    bootstrap_requests: parking_lot::RwLock<LruCache<String, Instant>>,
}

impl DhtBootstrapper {
    pub fn new(routing_manager: Arc<DhtRoutingManager>) -> Self {
        Self {
            routing_manager,
            bootstrap_requests: parking_lot::RwLock::new(
                LruCache::with_expiry_duration_and_capacity(
                    std::time::Duration::from_secs(300),
                    100,
                ),
            ),
        }
    }

    fn is_duplicate_request(&self, target: &str) -> bool {
        let mut cache = self.bootstrap_requests.write();
        if cache.contains_key(target) {
            return true;
        }
        cache.insert(target.to_string(), Instant::now());
        false
    }

    pub async fn bootstrap_from_seeds(
        &self,
        seed_nodes: &[SeedNode],
        transport: &impl SeedBootstrapTransport,
    ) -> Result<(), String> {
        if seed_nodes.is_empty() {
            return Err("No seed nodes provided".to_string());
        }

        for seed in seed_nodes {
            self.routing_manager
                .add_peer(
                    seed.node_id.clone(),
                    seed.address.clone(),
                    seed.port,
                    MeshNodeRole::Global,
                    None,
                    true,
                    seed.geo.clone(),
                    None,
                    None,
                )
                .await;
        }

        let local_id = *self.routing_manager.local_node_id_hash();

        for seed in seed_nodes {
            if self.is_duplicate_request(&seed.node_id) {
                tracing::debug!("Skipping duplicate bootstrap FindNode to {}", seed.node_id);
                continue;
            }

            let request_id = format!("bootstrap-{}", uuid::Uuid::new_v4());

            let find_node = MeshMessage::FindNode {
                request_id: request_id.into(),
                target_node_id: local_id.as_bytes().to_vec(),
                requester_node_id: self.routing_manager.local_node_id().into(),
                timestamp: crate::mesh::safe_unix_timestamp(),
            };

            if let Err(e) = transport.send_to_peer(&seed.node_id, find_node).await {
                tracing::warn!("Failed to send FindNode to seed {}: {}", seed.node_id, e);
            }
        }

        Ok(())
    }

    pub async fn process_find_node_response(
        &self,
        _peer_node_id: &str,
        responders: Vec<PeerContact>,
    ) {
        for contact in responders {
            if contact.node_id_string != self.routing_manager.local_node_id() {
                self.routing_manager
                    .add_peer(
                        contact.node_id_string.clone(),
                        contact.address,
                        contact.port,
                        if contact.is_global {
                            MeshNodeRole::Global
                        } else {
                            MeshNodeRole::Edge
                        },
                        contact.latency_ms,
                        contact.is_trusted,
                        contact.geo,
                        contact.pow_nonce,
                        contact.public_key,
                    )
                    .await;
            }
        }
    }
}

pub trait SeedBootstrapTransport: Send + Sync {
    fn send_to_peer(
        &self,
        node_id: &str,
        message: MeshMessage,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

#[derive(Clone)]
pub struct SeedNode {
    pub node_id: String,
    pub address: String,
    pub port: u16,
    pub geo: Option<GeoInfo>,
}

impl SeedNode {
    pub fn new(node_id: String, address: String, port: u16) -> Self {
        Self {
            node_id,
            address,
            port,
            geo: None,
        }
    }

    pub fn with_geo(mut self, geo: GeoInfo) -> Self {
        self.geo = Some(geo);
        self
    }
}

pub struct DhtQueryExecutor {
    routing_manager: Arc<DhtRoutingManager>,
}

impl DhtQueryExecutor {
    pub fn new(routing_manager: Arc<DhtRoutingManager>) -> Self {
        Self { routing_manager }
    }

    pub async fn iterative_find_node(
        &self,
        target_key: &str,
        transport: &impl DhtQueryTransport,
    ) -> Vec<PeerContact> {
        use crate::mesh::dht::routing::query::ALPHA;

        let target_node_id = NodeId::from_node_id_string(target_key);

        let initial_peers = self
            .routing_manager
            .find_closest_peers(target_key, REPLICATION_K)
            .await;

        if initial_peers.is_empty() {
            return Vec::new();
        }

        let mut query = LookupQuery::new(target_node_id);
        query.init(initial_peers);

        let local_id = self.routing_manager.local_node_id().to_string();

        loop {
            let is_complete = query.is_complete();
            if is_complete {
                break;
            }

            let limited_peers: Vec<PeerContact> = {
                let peers_to_query = query.next_peers_to_query();
                if peers_to_query.is_empty() {
                    break;
                }
                peers_to_query
                    .iter()
                    .take(ALPHA)
                    .map(|p| (*p).clone())
                    .collect()
            };

            if limited_peers.is_empty() {
                break;
            }

            let query_futures: Vec<_> = limited_peers
                .iter()
                .map(|peer| {
                    let local_id = local_id.clone();
                    let target_key = target_key.to_string();

                    async move {
                        let request_id = format!("find-{}-{}", target_key, uuid::Uuid::new_v4());

                        let find_node = MeshMessage::FindNode {
                            request_id: request_id.into(),
                            target_node_id: target_node_id.as_bytes().to_vec(),
                            requester_node_id: local_id.into(),
                            timestamp: crate::mesh::safe_unix_timestamp(),
                        };

                        let result = transport
                            .send_and_wait(peer.node_id_string.as_str(), find_node)
                            .await;
                        match result {
                            Ok(response) => {
                                if let MeshMessage::FindNodeResponse { peers, .. } = response {
                                    Some((peer.clone(), peers))
                                } else {
                                    Some((peer.clone(), Vec::new()))
                                }
                            }
                            Err(_) => None,
                        }
                    }
                })
                .collect();

            let results = futures::future::join_all(query_futures).await;

            for result in results {
                match result {
                    Some((peer, peers)) if !peers.is_empty() => {
                        query.process_response(&peer, peers)
                    }
                    Some((peer, _)) => query.mark_queried(&peer),
                    None => {}
                }
            }
        }

        query.get_result()
    }
}

pub trait DhtQueryTransport: Send + Sync {
    fn send_and_wait(
        &self,
        node_id: &str,
        message: MeshMessage,
    ) -> impl std::future::Future<Output = Result<MeshMessage, String>> + Send;
}

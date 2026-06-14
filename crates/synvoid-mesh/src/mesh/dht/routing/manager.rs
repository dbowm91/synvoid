use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use lru_time_cache::LruCache;
use tokio::sync::{watch, RwLock};

use crate::config::{MeshConfig, MeshNodeRole};
use crate::dht::routing::contact::{GeoInfo, PeerContact};
use crate::dht::routing::geo_distance::{GeoDistance, GeoRoutingConfig};
use crate::dht::routing::node_id::NodeId;
use crate::dht::routing::query::LookupQuery;
use crate::dht::routing::regional_hubs::{RegionalHub, RegionalHubConfig};
use crate::dht::routing::table::PersistedRoutingTable;
use crate::dht::routing::table::RoutingTable;
use crate::dht::routing::table::{BUCKET_COUNT, BUCKET_REFRESH_INTERVAL, REPLICATION_K};
use crate::lifecycle::DhtPeerSnapshot;
use crate::protocol::MeshMessage;

pub trait FindNodeTransport: Send + Sync {
    fn send_find_node(&self, target: NodeId, request_id: String);
}

pub trait PingTransport: Send + Sync {
    fn send_ping(&self, node_id: &str, request_id: String, local_node_id: String);
}

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
    find_node_transport: Arc<parking_lot::RwLock<Option<Arc<dyn FindNodeTransport>>>>,
    ping_transport: Arc<parking_lot::RwLock<Option<Arc<dyn PingTransport>>>>,
    pending_pings: Arc<parking_lot::RwLock<HashMap<String, Instant>>>,
    join_handles: Arc<parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    shutdown_tx: Arc<watch::Sender<()>>,
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
            find_node_transport: self.find_node_transport.clone(),
            ping_transport: self.ping_transport.clone(),
            pending_pings: self.pending_pings.clone(),
            join_handles: self.join_handles.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
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
            find_node_transport: Arc::new(parking_lot::RwLock::new(None)),
            ping_transport: Arc::new(parking_lot::RwLock::new(None)),
            pending_pings: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            join_handles: Arc::new(parking_lot::Mutex::new(Vec::new())),
            shutdown_tx: Arc::new(watch::channel::<()>(()).0),
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
        if self.edge_can_respond_privileged && !self.is_global {
            tracing::warn!(
                "Node is configured with edge_can_respond_privileged=true but is not a global node. \
                This allows edge node to respond to privileged DHT queries, effectively making it global for read operations."
            );
        }
        self.is_global || self.edge_can_respond_privileged
    }

    pub fn can_respond_to_key(&self, key: &str) -> bool {
        use crate::dht::keys::DhtKey;
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

    #[allow(unused_must_use)]
    pub fn start_background_tasks(&self) {
        if !self.routing_enabled {
            return;
        }

        let self_arc = Arc::new(self.clone());
        let shutdown_rx = self.shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            let mut shutdown = shutdown_rx;
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        tracing::debug!("Bucket stats loop shutdown");
                        break;
                    }
                    _ = interval.tick() => {
                        let peer_count = self_arc.total_peers().await;
                        tracing::debug!("DHT routing table: {} peers", peer_count);

                        let stats = self_arc.bucket_stats().await;
                        if !stats.is_empty() {
                            let non_empty: usize = stats.iter().filter(|(_, c)| *c > 0).count();
                            tracing::debug!("DHT bucket stats: {} non-empty buckets", non_empty);

                            for (bucket_idx, count) in &stats {
                                crate::stubs::metrics::record_dht_bucket_peers(*bucket_idx, *count as u64);
                            }
                        }

                        if self_arc.hub_config.enabled {
                            self_arc.sync_regional_hub().await;
                            let hubs = self_arc.get_regional_hubs().await;
                            tracing::debug!("Regional hubs refreshed: {} total hubs", hubs.len());
                        }
                    }
                }
            }
        });
        self.join_handles.lock().push(handle);

        let self_refresh = Arc::new(self.clone());
        let shutdown_rx = self.shutdown_tx.subscribe();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(BUCKET_REFRESH_INTERVAL);
            let mut shutdown = shutdown_rx;
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        tracing::debug!("Bucket refresh loop shutdown");
                        break;
                    }
                    _ = interval.tick() => {
                        self_refresh.refresh_sparse_buckets().await;
                    }
                }
            }
        });
        self.join_handles.lock().push(handle);

        let self_ping = Arc::new(self.clone());
        let shutdown_rx = self.shutdown_tx.subscribe();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut shutdown = shutdown_rx;
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        tracing::debug!("Ping loop shutdown");
                        break;
                    }
                    _ = interval.tick() => {
                        self_ping.ping_peers().await;
                    }
                }
            }
        });
        self.join_handles.lock().push(handle);

        tracing::info!("DHT routing background tasks started");
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        let handles: Vec<_> = self.join_handles.lock().drain(..).collect();
        for handle in handles {
            let _ = handle.await;
        }
        tracing::info!("DHT routing background tasks shut down");
    }

    pub fn set_find_node_transport(&self, transport: Arc<dyn FindNodeTransport>) {
        let mut t = self.find_node_transport.write();
        *t = Some(transport);
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
        geo: Option<crate::dht::routing::GeoInfo>,
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
        crate::stubs::metrics::record_dht_peer_discovered();
    }

    pub async fn remove_peer(&self, peer_node_id: &str) {
        let mut rt = self.routing_table.write().await;
        let table = match rt.as_mut() {
            Some(t) => t,
            None => return,
        };

        let node_id = NodeId::from_node_id_string(peer_node_id);
        if table.remove(&node_id).is_some() {
            crate::stubs::metrics::record_dht_peer_removed();
        }
    }

    /// Snapshot the current DHT routing state for a peer before mutation.
    ///
    /// Returns `None` if the peer has no routing entry. The snapshot captures
    /// the minimal state needed to restore the entry on rollback (Iteration 73, Phase 4).
    pub async fn snapshot_peer(&self, peer_node_id: &str) -> Option<DhtPeerSnapshot> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return None,
        };

        let node_id = NodeId::from_node_id_string(peer_node_id);
        let contact = table.get_contact(&node_id)?;

        Some(DhtPeerSnapshot {
            node_id: contact.node_id_string.clone(),
            address: contact.address.clone(),
            port: contact.port,
            role: if contact.is_global {
                MeshNodeRole::GLOBAL
            } else {
                MeshNodeRole::EDGE
            },
        })
    }

    /// Restore a peer's DHT routing state from a snapshot taken before mutation.
    ///
    /// Re-inserts the contact with the same address, port, and role. The
    /// `last_seen` timestamp is refreshed to `Instant::now()` since the peer
    /// was recently connected (Iteration 73, Phase 5).
    pub async fn restore_peer(&self, snapshot: &DhtPeerSnapshot) {
        let mut rt = self.routing_table.write().await;
        let table = match rt.as_mut() {
            Some(t) => t,
            None => return,
        };

        let node_id = NodeId::from_node_id_string(&snapshot.node_id);
        let contact = PeerContact::new(
            node_id,
            snapshot.node_id.clone(),
            snapshot.address.clone(),
            snapshot.port,
        );
        let mut contact = contact;
        contact.is_global = snapshot.role.is_global();
        table.try_insert(contact);
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
        use crate::dht::keys::DhtKey;

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

    pub async fn refresh_sparse_buckets(&self) {
        let transport = {
            let t = self.find_node_transport.read();
            t.clone()
        };

        let transport = match transport {
            Some(t) => t,
            None => return,
        };

        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return,
        };

        let sparse_buckets = table.get_sparse_bucket_indices(REPLICATION_K);
        if sparse_buckets.is_empty() {
            return;
        }

        tracing::debug!(
            "DHT bucket refresh: {} sparse buckets need repopulation",
            sparse_buckets.len()
        );

        for bucket_idx in sparse_buckets {
            let target = NodeId::generate_random_in_bucket(bucket_idx, &self.node_id_hash);
            let request_id = format!("bucket-refresh-{}-{}", bucket_idx, uuid::Uuid::new_v4());
            tracing::debug!(
                "DHT bucket refresh: triggering FindNode for bucket {} (target {})",
                bucket_idx,
                target
            );
            transport.send_find_node(target, request_id);
        }
    }

    pub fn set_ping_transport(&self, transport: Arc<dyn PingTransport>) {
        let mut t = self.ping_transport.write();
        *t = Some(transport);
    }

    pub async fn get_peers_to_ping(&self) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        let mut all_peers_to_ping = Vec::new();
        for bucket_idx in 0..BUCKET_COUNT {
            let peers = table.get_peers_to_ping(bucket_idx);
            all_peers_to_ping.extend(peers);
        }
        all_peers_to_ping
    }

    pub async fn get_stale_peers(&self) -> Vec<PeerContact> {
        let rt = self.routing_table.read().await;
        let table = match rt.as_ref() {
            Some(t) => t,
            None => return Vec::new(),
        };

        let stale_ids = table.get_stale_peers();
        stale_ids
            .iter()
            .filter_map(|id| table.get_contact(id))
            .collect()
    }

    pub async fn start_ping_loop(&self) {
        if !self.routing_enabled {
            return;
        }

        let self_arc = Arc::new(self.clone());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                self_arc.ping_peers().await;
            }
        });

        tracing::info!("DHT ping loop started");
    }

    pub async fn ping_peers(&self) {
        let transport = {
            let t = self.ping_transport.read();
            t.clone()
        };

        let transport = match transport {
            Some(t) => t,
            None => {
                tracing::debug!("DHT ping transport not set, skipping ping");
                return;
            }
        };

        let peers_to_ping = self.get_peers_to_ping().await;
        if peers_to_ping.is_empty() {
            return;
        }

        tracing::debug!("DHT pinging {} stale peers", peers_to_ping.len());

        for peer in peers_to_ping {
            let request_id = format!("dht-ping-{}", uuid::Uuid::new_v4());
            {
                let mut pending = self.pending_pings.write();
                pending.insert(peer.node_id_string.clone(), Instant::now());
            }
            transport.send_ping(&peer.node_id_string, request_id, self.node_id.clone());
        }
    }

    pub async fn mark_peer_responded(&self, node_id: &str) {
        {
            let mut pending = self.pending_pings.write();
            pending.remove(node_id);
        }
        self.update_peer_latency(node_id, 0).await;
    }

    pub fn get_pending_ping_count(&self) -> usize {
        self.pending_pings.read().len()
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

        if seed_nodes.len() < 3 {
            return Err(format!(
                "DHT bootstrap requires at least 3 independent seed nodes for security (only {} provided). \
                This prevents eclipse attacks and ensures network resilience.",
                seed_nodes.len()
            ));
        }

        for seed in seed_nodes {
            self.routing_manager
                .add_peer(
                    seed.node_id.clone(),
                    seed.address.clone(),
                    seed.port,
                    MeshNodeRole::GLOBAL,
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
                timestamp: synvoid_utils::safe_unix_timestamp(),
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
                            MeshNodeRole::GLOBAL
                        } else {
                            MeshNodeRole::EDGE
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
        use crate::dht::routing::query::ALPHA;

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
                            timestamp: synvoid_utils::safe_unix_timestamp(),
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

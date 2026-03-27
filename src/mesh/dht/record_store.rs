#![allow(unused_variables)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use linked_hash_map::LinkedHashMap;
use metrics::counter;
use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::mesh::config::MeshNodeRole;
use crate::mesh::dht::keys::DhtKey;
use crate::mesh::dht::merkle::MerkleTree;
use crate::mesh::dht::{validate_message_timestamp, DhtAccessControl};
use crate::mesh::protocol::{DhtRecord, MeshMessage};

const DEFAULT_SYNC_INTERVAL_SECS: u64 = 300;
const DEFAULT_REPLICATION_FACTOR: usize = 20;
const DEFAULT_WRITE_QUORUM: u32 = 11;
const DEFAULT_READ_QUORUM: u32 = 11;
const DEFAULT_RECORD_TTL: u64 = 3600;
const DEFAULT_EDGE_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_EDGE_CACHE_MAX_ENTRIES: usize = 1000;
const DEFAULT_CONVERGENCE_THRESHOLD: usize = 3;

#[derive(Debug, Clone)]
pub struct RecordStoreConfig {
    pub enabled: bool,
    pub sync_interval_secs: u64,
    pub replication_factor: usize,
    pub write_quorum: u32,
    pub read_quorum: u32,
    pub record_ttl: Duration,
    pub edge_cache_enabled: bool,
    pub edge_cache_max_entries: usize,
    pub edge_cache_ttl_secs: u64,
    pub edge_write_enabled: bool,
    pub health_ttl_secs: u64,
    pub load_ttl_secs: u64,
    pub initial_sync_interval_secs: u64,
    pub max_sync_interval_secs: u64,
    pub fanout_factor: f64,
    pub convergence_threshold: usize,
}

impl Default for RecordStoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval_secs: DEFAULT_SYNC_INTERVAL_SECS,
            replication_factor: DEFAULT_REPLICATION_FACTOR,
            write_quorum: DEFAULT_WRITE_QUORUM,
            read_quorum: DEFAULT_READ_QUORUM,
            record_ttl: Duration::from_secs(DEFAULT_RECORD_TTL),
            edge_cache_enabled: true,
            edge_cache_max_entries: DEFAULT_EDGE_CACHE_MAX_ENTRIES,
            edge_cache_ttl_secs: DEFAULT_EDGE_CACHE_TTL_SECS,
            edge_write_enabled: false,
            health_ttl_secs: 60,
            load_ttl_secs: 60,
            initial_sync_interval_secs: 30,
            max_sync_interval_secs: 3600,
            fanout_factor: 0.5,
            convergence_threshold: DEFAULT_CONVERGENCE_THRESHOLD,
        }
    }
}

pub struct RecordStoreManager {
    config: Arc<RecordStoreConfig>,
    node_id: String,
    node_role: MeshNodeRole,
    mesh_signer: RwLock<Option<crate::mesh::protocol::MeshMessageSigner>>,
    record_signer: RwLock<Option<crate::mesh::dht::RecordSigner>>,
    access_control: Arc<DhtAccessControl>,
    local_version: RwLock<u64>,
    records: RwLock<LinkedHashMap<String, DhtRecordEntry>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    transport: Arc<RwLock<Option<Arc<crate::mesh::transport::MeshTransport>>>>,
    routing_manager: RwLock<Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>>,
    stake_manager: RwLock<Option<Arc<crate::mesh::dht::StakeManager>>>,
    topology: RwLock<Option<Arc<crate::mesh::topology::MeshTopology>>>,
    last_sync: RwLock<Instant>,
    pending_announces: RwLock<Vec<DhtRecord>>,
    cache_hits: RwLock<u64>,
    cache_misses: RwLock<u64>,
    last_snapshot_version: RwLock<u64>,
    initial_sync_completed: RwLock<bool>,
    current_sync_interval: RwLock<u64>,
    recent_changes: RwLock<Vec<Instant>>,
    merkle_tree: RwLock<Option<MerkleTree>>,
    propagation_states: RwLock<HashMap<String, PropagationState>>,
    convergence_threshold: usize,
    rate_limiter: RwLock<Option<crate::mesh::dht::DhtRateLimiter>>,
    network_policy: RwLock<Option<crate::mesh::dht::NetworkPolicy>>,
    blocklist: RwLock<Option<crate::mesh::dht::GlobalNodeBlocklist>>,
}

#[derive(Debug, Clone)]
pub struct PropagationState {
    pub key: String,
    pub ack_count: usize,
    pub attempted_peers: Vec<String>,
    pub completed: bool,
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct DhtRecordEntry {
    pub record: DhtRecord,
    pub local_origin: bool,
    pub version: u64,
}

impl RecordStoreManager {
    pub fn new(
        config: RecordStoreConfig,
        node_id: String,
        node_role: MeshNodeRole,
        mesh_signer: Option<crate::mesh::protocol::MeshMessageSigner>,
        access_control: DhtAccessControl,
    ) -> Self {
        let initial_interval = config.initial_sync_interval_secs;
        let convergence_threshold = config.convergence_threshold;
        let fanout_factor = config.fanout_factor;
        let replication_factor = config.replication_factor;
        Self {
            config: Arc::new(config),
            node_id,
            node_role,
            mesh_signer: RwLock::new(mesh_signer),
            record_signer: RwLock::new(None),
            access_control: Arc::new(access_control),
            local_version: RwLock::new(1),
            records: RwLock::new(LinkedHashMap::new()),
            mesh_sender: Arc::new(RwLock::new(None)),
            transport: Arc::new(RwLock::new(None)),
            routing_manager: RwLock::new(None),
            stake_manager: RwLock::new(None),
            topology: RwLock::new(None),
            last_sync: RwLock::new(Instant::now()),
            pending_announces: RwLock::new(Vec::new()),
            cache_hits: RwLock::new(0),
            cache_misses: RwLock::new(0),
            last_snapshot_version: RwLock::new(0),
            initial_sync_completed: RwLock::new(false),
            current_sync_interval: RwLock::new(initial_interval),
            recent_changes: RwLock::new(Vec::new()),
            merkle_tree: RwLock::new(None),
            propagation_states: RwLock::new(HashMap::new()),
            convergence_threshold,
            rate_limiter: RwLock::new(None),
            network_policy: RwLock::new(None),
            blocklist: RwLock::new(None),
        }
    }

    pub fn set_record_signer(&self, signing_key: Option<[u8; 32]>) {
        let mut signer = self.record_signer.write();
        *signer = Some(crate::mesh::dht::RecordSigner::new(signing_key));
    }

    pub fn enable_rate_limiting(&self, max_requests: u32, window_secs: u64) {
        let mut limiter = self.rate_limiter.write();
        *limiter = Some(crate::mesh::dht::DhtRateLimiter::new(
            max_requests,
            window_secs,
        ));
    }

    pub fn is_rate_limited(&self, peer_id: &str) -> bool {
        let limiter = self.rate_limiter.read();
        match limiter.as_ref() {
            Some(l) => !l.is_allowed(peer_id),
            None => false,
        }
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        let mut sender_guard = self.mesh_sender.write();
        *sender_guard = Some(sender);
    }

    pub fn set_transport(&self, transport: Arc<crate::mesh::transport::MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    pub fn set_routing_manager(&self, manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>) {
        let mut rm = self.routing_manager.write();
        *rm = Some(manager);
    }

    pub fn set_stake_manager(&self, manager: Arc<crate::mesh::dht::StakeManager>) {
        let mut sm = self.stake_manager.write();
        *sm = Some(manager);
    }

    pub fn set_topology(&self, topology: Arc<crate::mesh::topology::MeshTopology>) {
        let mut t = self.topology.write();
        *t = Some(topology);
    }

    pub fn is_routing_enabled(&self) -> bool {
        let rm = self.routing_manager.read();
        rm.as_ref().map(|m| m.is_enabled()).unwrap_or(false)
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn is_global_node(&self) -> bool {
        self.node_role == MeshNodeRole::Global
    }

    pub fn get_network_policy(&self) -> Option<crate::mesh::dht::NetworkPolicy> {
        self.network_policy.read().clone()
    }

    pub fn set_network_policy(&self, policy: crate::mesh::dht::NetworkPolicy) {
        *self.network_policy.write() = Some(policy);
    }

    pub fn get_blocklist(&self) -> Option<crate::mesh::dht::GlobalNodeBlocklist> {
        self.blocklist.read().clone()
    }

    pub fn set_blocklist(&self, blocklist: crate::mesh::dht::GlobalNodeBlocklist) {
        *self.blocklist.write() = Some(blocklist);
    }

    pub fn is_node_blocked(&self, node_id: &str, ip: Option<&str>) -> bool {
        let blocklist = self.blocklist.read();
        if let Some(ref bl) = *blocklist {
            bl.is_blocked(node_id, ip)
        } else {
            false
        }
    }
}

impl Clone for RecordStoreManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            mesh_signer: RwLock::new(self.mesh_signer.read().clone()),
            record_signer: RwLock::new(self.record_signer.read().clone()),
            access_control: self.access_control.clone(),
            local_version: RwLock::new(*self.local_version.read()),
            records: RwLock::new(self.records.read().clone()),
            mesh_sender: self.mesh_sender.clone(),
            transport: self.transport.clone(),
            routing_manager: RwLock::new(self.routing_manager.read().clone()),
            stake_manager: RwLock::new(self.stake_manager.read().clone()),
            topology: RwLock::new(self.topology.read().clone()),
            last_sync: RwLock::new(*self.last_sync.read()),
            pending_announces: RwLock::new(self.pending_announces.read().clone()),
            cache_hits: RwLock::new(*self.cache_hits.read()),
            cache_misses: RwLock::new(*self.cache_misses.read()),
            last_snapshot_version: RwLock::new(*self.last_snapshot_version.read()),
            initial_sync_completed: RwLock::new(*self.initial_sync_completed.read()),
            current_sync_interval: RwLock::new(*self.current_sync_interval.read()),
            recent_changes: RwLock::new(self.recent_changes.read().clone()),
            merkle_tree: RwLock::new(self.merkle_tree.read().clone()),
            propagation_states: RwLock::new(self.propagation_states.read().clone()),
            convergence_threshold: self.convergence_threshold,
            rate_limiter: RwLock::new(self.rate_limiter.read().clone()),
            network_policy: RwLock::new(self.network_policy.read().clone()),
            blocklist: RwLock::new(self.blocklist.read().clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordStoreStats {
    pub node_id: String,
    pub node_role: MeshNodeRole,
    pub version: u64,
    pub record_count: usize,
    pub pending_announce_count: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub is_global: bool,
    pub last_snapshot_version: u64,
}

impl RecordStoreManager {
    pub fn get_stats(&self) -> RecordStoreStats {
        RecordStoreStats {
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            version: *self.local_version.read(),
            record_count: self.records.read().len(),
            pending_announce_count: self.pending_announces.read().len(),
            cache_hits: *self.cache_hits.read(),
            cache_misses: *self.cache_misses.read(),
            is_global: self.is_global_node(),
            last_snapshot_version: *self.last_snapshot_version.read(),
        }
    }
}

#[path = "record_store_crud.rs"]
mod record_store_crud;
#[path = "record_store_dns.rs"]
mod record_store_dns;
#[path = "record_store_message.rs"]
mod record_store_message;
#[path = "record_store_sync.rs"]
mod record_store_sync;

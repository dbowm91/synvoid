#![allow(unused_variables)]

use std::collections::{HashMap, VecDeque};
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
pub const MAX_PENDING_ANNOUNCES: usize = 10000;
const NUM_RECORD_SHARDS: usize = 64;

#[inline]
fn record_shard_index(key: &str) -> usize {
    let mut hash: u64 = 5381;
    for byte in key.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    (hash as usize) % NUM_RECORD_SHARDS
}

pub struct ShardedRecordStore {
    shards: Vec<RwLock<LinkedHashMap<String, DhtRecordEntry>>>,
}

impl ShardedRecordStore {
    pub fn new() -> Self {
        Self {
            shards: (0..NUM_RECORD_SHARDS)
                .map(|_| RwLock::new(LinkedHashMap::new()))
                .collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<DhtRecordEntry> {
        let shard = &self.shards[record_shard_index(key)];
        shard.read().get(key).cloned()
    }

    pub fn insert(&self, key: String, value: DhtRecordEntry) -> Option<DhtRecordEntry> {
        let shard = &self.shards[record_shard_index(&key)];
        shard.write().insert(key, value)
    }

    pub fn remove(&self, key: &str) -> Option<DhtRecordEntry> {
        let shard = &self.shards[record_shard_index(key)];
        shard.write().remove(key)
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.read().is_empty())
    }

    pub fn front(&self) -> Option<(String, DhtRecordEntry)> {
        for shard in &self.shards {
            if let Some((k, v)) = shard.read().front() {
                return Some((k.clone(), v.clone()));
            }
        }
        None
    }

    pub fn values(&self) -> Vec<DhtRecordEntry> {
        let mut result = Vec::new();
        for shard in &self.shards {
            let guard = shard.read();
            for v in guard.values() {
                result.push(v.clone());
            }
        }
        result
    }

    pub fn iter(&self) -> Vec<(String, DhtRecordEntry)> {
        let mut result = Vec::new();
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in guard.iter() {
                result.push((k.clone(), v.clone()));
            }
        }
        result
    }

    pub fn get_by_prefix(&self, prefix: &str) -> Vec<(String, DhtRecordEntry)> {
        let mut result = Vec::new();
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in guard.iter() {
                if k.starts_with(prefix) {
                    result.push((k.clone(), v.clone()));
                }
            }
        }
        result
    }
}

impl Default for ShardedRecordStore {
    fn default() -> Self {
        Self::new()
    }
}

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
    pub manual_quorum_override: usize,
    pub enable_degraded_quorum: bool,
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
            manual_quorum_override: 0,
            enable_degraded_quorum: true,
        }
    }
}

impl RecordStoreConfig {
    pub fn calculate_write_quorum(&self, node_count: usize) -> u32 {
        if node_count == 0 {
            return 1;
        }
        let auto_quorum = std::cmp::max(3, (node_count / 2) + 1) as u32;
        std::cmp::min(auto_quorum, node_count as u32)
    }

    pub fn calculate_read_quorum(&self, node_count: usize) -> u32 {
        self.calculate_write_quorum(node_count)
    }

    pub fn effective_write_quorum(&self, node_count: usize) -> u32 {
        if self.manual_quorum_override > 0 {
            return self.manual_quorum_override as u32;
        }
        if self.enable_degraded_quorum && node_count < 5 {
            return std::cmp::max(1, (node_count / 2) as u32);
        }
        self.calculate_write_quorum(node_count)
    }

    pub fn effective_read_quorum(&self, node_count: usize) -> u32 {
        if self.manual_quorum_override > 0 {
            return self.manual_quorum_override as u32;
        }
        if self.enable_degraded_quorum && node_count < 5 {
            return std::cmp::max(1, (node_count / 2) as u32);
        }
        self.calculate_read_quorum(node_count)
    }

    pub fn calculate_adaptive_quorum(&self, live_global_count: usize) -> u32 {
        let min_quorum = 3;
        let target = (live_global_count * 2) / 3;
        std::cmp::max(
            min_quorum,
            std::cmp::min(target, self.write_quorum as usize),
        ) as u32
    }
}

pub struct RecordStoreState {
    pub mesh_signer: Option<crate::mesh::protocol::MeshMessageSigner>,
    pub record_signer: Option<crate::mesh::dht::RecordSigner>,
    pub local_version: u64,
    pub records: ShardedRecordStore,
    pub pending_announces: VecDeque<DhtRecord>,
    pub last_snapshot_version: u64,
    pub merkle_tree: Option<MerkleTree>,
    pub propagation_states: HashMap<String, PropagationState>,
}

pub struct RoutingState {
    pub mesh_sender: Option<mpsc::Sender<MeshMessage>>,
    pub transport: Option<Arc<crate::mesh::transport::MeshTransport>>,
    pub routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
    pub stake_manager: Option<Arc<crate::mesh::dht::StakeManager>>,
    pub topology: Option<Arc<crate::mesh::topology::MeshTopology>>,
    pub rate_limiter: Option<crate::mesh::dht::DhtRateLimiter>,
    pub network_policy: Option<crate::mesh::dht::NetworkPolicy>,
    pub blocklist: Option<crate::mesh::dht::GlobalNodeBlocklist>,
}

pub struct MetricsState {
    pub last_sync: Instant,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub initial_sync_completed: bool,
    pub current_sync_interval: u64,
    pub recent_changes: Vec<Instant>,
}

pub struct RecordStoreManager {
    config: Arc<RecordStoreConfig>,
    node_id: String,
    node_role: MeshNodeRole,
    access_control: Arc<DhtAccessControl>,
    convergence_threshold: usize,
    pub record_state: RwLock<RecordStoreState>,
    pub routing_state: RwLock<RoutingState>,
    pub metrics_state: RwLock<MetricsState>,
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
            access_control: Arc::new(access_control),
            convergence_threshold,
            record_state: RwLock::new(RecordStoreState {
                mesh_signer,
                record_signer: None,
                local_version: 1,
                records: ShardedRecordStore::new(),
                pending_announces: VecDeque::new(),
                last_snapshot_version: 0,
                merkle_tree: None,
                propagation_states: HashMap::new(),
            }),
            routing_state: RwLock::new(RoutingState {
                mesh_sender: None,
                transport: None,
                routing_manager: None,
                stake_manager: None,
                topology: None,
                rate_limiter: None,
                network_policy: None,
                blocklist: None,
            }),
            metrics_state: RwLock::new(MetricsState {
                last_sync: Instant::now(),
                cache_hits: 0,
                cache_misses: 0,
                initial_sync_completed: false,
                current_sync_interval: initial_interval,
                recent_changes: Vec::new(),
            }),
        }
    }

    pub fn set_record_signer(&self, signing_key: Option<[u8; 32]>) {
        let mut state = self.record_state.write();
        state.record_signer = Some(crate::mesh::dht::RecordSigner::new(signing_key));
    }

    pub fn get_record_verifier(&self) -> Option<crate::mesh::dht::RecordSigner> {
        let state = self.record_state.read();
        state.record_signer.clone()
    }

    pub fn enable_rate_limiting(&self, max_requests: u32, window_secs: u64) {
        let mut routing = self.routing_state.write();
        routing.rate_limiter = Some(crate::mesh::dht::DhtRateLimiter::new(
            max_requests,
            window_secs,
        ));
    }

    pub fn is_rate_limited(&self, peer_id: &str) -> bool {
        let routing = self.routing_state.read();
        match routing.rate_limiter.as_ref() {
            Some(l) => !l.is_allowed(peer_id),
            None => false,
        }
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        self.routing_state.write().mesh_sender = Some(sender);
    }

    pub fn set_transport(&self, transport: Arc<crate::mesh::transport::MeshTransport>) {
        self.routing_state.write().transport = Some(transport);
    }

    pub fn set_routing_manager(&self, manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>) {
        self.routing_state.write().routing_manager = Some(manager);
    }

    pub fn set_stake_manager(&self, manager: Arc<crate::mesh::dht::StakeManager>) {
        self.routing_state.write().stake_manager = Some(manager);
    }

    pub fn set_topology(&self, topology: Arc<crate::mesh::topology::MeshTopology>) {
        self.routing_state.write().topology = Some(topology);
    }

    pub fn is_routing_enabled(&self) -> bool {
        self.routing_state
            .read()
            .routing_manager
            .as_ref()
            .map(|m| m.is_enabled())
            .unwrap_or(false)
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn is_global_node(&self) -> bool {
        self.node_role.is_global()
    }

    pub fn get_network_policy(&self) -> Option<crate::mesh::dht::NetworkPolicy> {
        self.routing_state.read().network_policy.clone()
    }

    pub fn set_network_policy(&self, policy: crate::mesh::dht::NetworkPolicy) {
        self.routing_state.write().network_policy = Some(policy);
    }

    pub fn get_blocklist(&self) -> Option<crate::mesh::dht::GlobalNodeBlocklist> {
        self.routing_state.read().blocklist.clone()
    }

    pub fn set_blocklist(&self, blocklist: crate::mesh::dht::GlobalNodeBlocklist) {
        self.routing_state.write().blocklist = Some(blocklist);
    }

    pub fn is_node_blocked(&self, node_id: &str, ip: Option<&str>) -> bool {
        let routing = self.routing_state.read();
        if let Some(ref bl) = routing.blocklist {
            bl.is_blocked(node_id, ip)
        } else {
            false
        }
    }
}

impl Clone for RecordStoreManager {
    fn clone(&self) -> Self {
        let rs = self.record_state.read();
        let record_state = RecordStoreState {
            mesh_signer: rs.mesh_signer.clone(),
            record_signer: rs.record_signer.clone(),
            local_version: rs.local_version,
            records: ShardedRecordStore::new(),
            pending_announces: rs.pending_announces.clone(),
            last_snapshot_version: rs.last_snapshot_version,
            merkle_tree: rs.merkle_tree.clone(),
            propagation_states: rs.propagation_states.clone(),
        };
        drop(rs);

        let routing = self.routing_state.read();
        let routing_state = RoutingState {
            mesh_sender: None,
            transport: None,
            routing_manager: routing.routing_manager.clone(),
            stake_manager: routing.stake_manager.clone(),
            topology: routing.topology.clone(),
            rate_limiter: routing.rate_limiter.clone(),
            network_policy: routing.network_policy.clone(),
            blocklist: routing.blocklist.clone(),
        };
        drop(routing);

        let ms = self.metrics_state.read();
        let metrics_state = MetricsState {
            last_sync: ms.last_sync,
            cache_hits: ms.cache_hits,
            cache_misses: ms.cache_misses,
            initial_sync_completed: ms.initial_sync_completed,
            current_sync_interval: ms.current_sync_interval,
            recent_changes: ms.recent_changes.clone(),
        };
        drop(ms);

        Self {
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            access_control: self.access_control.clone(),
            convergence_threshold: self.convergence_threshold,
            record_state: RwLock::new(record_state),
            routing_state: RwLock::new(routing_state),
            metrics_state: RwLock::new(metrics_state),
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
        let rs = self.record_state.read();
        let ms = self.metrics_state.read();
        RecordStoreStats {
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            version: rs.local_version,
            record_count: rs.records.len(),
            pending_announce_count: rs.pending_announces.len(),
            cache_hits: ms.cache_hits,
            cache_misses: ms.cache_misses,
            is_global: self.is_global_node(),
            last_snapshot_version: rs.last_snapshot_version,
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

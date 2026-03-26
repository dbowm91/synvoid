pub mod keys;
pub mod signed;
pub mod record_store;
pub mod store;
pub mod merkle;
pub mod routing;
pub mod network_policy;
pub mod stake;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

pub use keys::*;
pub use store::*;
pub use signed::{SignedDhtRecord, SignedRecordType, RecordSigner, TtlManager, validate_message_timestamp, DHT_MESSAGE_TIMESTAMP_WINDOW_SECS};
pub use record_store::{RecordStoreManager, RecordStoreConfig, RecordStoreStats, DhtRecordEntry};
pub use merkle::{MerkleTree, MerkleProof, MerkleNode, MerkleProofNode, ProofPosition};
pub use network_policy::{NetworkPolicy, BlockedNode, GlobalNodeBlocklist, MAX_REPUTATION_THRESHOLD, MIN_REPUTATION_THRESHOLD};
pub use stake::{StakeConfig, StakeManager, NodeStake, StakeLevel, SlashReason, SlashEvent};

pub use routing::{
    NodeId, PeerContact, GeoInfo, RoutingTable,
    KBucket, K_SIZE, LookupQuery, DhtQuery, QueryResponse, ALPHA,
    PersistedRoutingTable, PersistedBucket, PersistedContact,
    REPLICATION_K, BUCKET_REFRESH_INTERVAL, PING_TIMEOUT,
};

pub const DEFAULT_RATE_LIMIT_MAX_REQUESTS: u32 = 100;
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;

#[derive(Clone)]
pub struct DhtRateLimiter {
    max_requests: u32,
    window_secs: u64,
    peer_requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
}

impl DhtRateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_secs,
            peer_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn is_allowed(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        let mut peer_requests = self.peer_requests.write();
        
        let requests = peer_requests.entry(peer_id.to_string()).or_default();
        
        requests.retain(|t| now.duration_since(*t).as_secs() < self.window_secs);
        
        if requests.len() >= self.max_requests as usize {
            return false;
        }
        
        requests.push(now);
        true
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut peer_requests = self.peer_requests.write();
        
        for requests in peer_requests.values_mut() {
            requests.retain(|t| now.duration_since(*t).as_secs() < self.window_secs);
        }
        
        peer_requests.retain(|_, v| !v.is_empty());
    }
}

impl Default for DhtRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE_LIMIT_MAX_REQUESTS, DEFAULT_RATE_LIMIT_WINDOW_SECS)
    }
}

#[derive(Error, Debug, Clone)]
pub enum DhtError {
    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Store error: {0}")]
    StoreError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Bootstrap failed: {0}")]
    BootstrapFailed(String),

    #[error("Timeout waiting for operation")]
    Timeout,

    #[error("Not a global node - DHT requires global node role")]
    NotGlobalNode,

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
#[derive(Default)]
pub enum DhtConsistencyLevel {
    Low,
    #[default]
    Medium,
    High,
}


// Note: DhtConfig has complex dependencies - add rkyv derives to individual fields as needed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtConfig {
    pub enabled: bool,
    pub listen_port: u16,
    pub bootstrap_nodes: Vec<String>,
    pub write_quorum: usize,
    pub read_quorum: usize,
    pub replication_factor: usize,
    pub query_timeout: Duration,
    pub bootstrap_timeout: Duration,
    pub ping_interval: Duration,
    pub record_ttl: Option<Duration>,
    pub consistency_level: DhtConsistencyLevel,
    pub disk_path: Option<String>,
    pub edge_cache_enabled: bool,
    pub edge_cache_max_entries: usize,
    pub edge_cache_ttl_secs: u64,
    pub warm_up_on_connect: bool,
    pub edge_write_enabled: bool,
    pub min_reputation_for_dht_write: i64,
    pub health_ttl_secs: u64,
    pub load_ttl_secs: u64,
    pub illegal_upstream_terms: Vec<String>,
    pub initial_sync_interval_secs: u64,
    pub max_sync_interval_secs: u64,
    pub fanout_factor: f64,
    pub convergence_threshold: usize,
    pub geo_routing: Option<crate::mesh::dht::routing::GeoRoutingConfig>,
    pub regional_hubs: Option<crate::mesh::dht::routing::RegionalHubConfig>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 0,
            bootstrap_nodes: Vec::new(),
            write_quorum: 11,
            read_quorum: 11,
            replication_factor: 20,
            query_timeout: Duration::from_secs(10),
            bootstrap_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(30),
            record_ttl: Some(Duration::from_secs(3600)),
            consistency_level: DhtConsistencyLevel::Medium,
            disk_path: None,
            edge_cache_enabled: true,
            edge_cache_max_entries: 1000,
            edge_cache_ttl_secs: 300,
            warm_up_on_connect: true,
            edge_write_enabled: false,
            min_reputation_for_dht_write: 30,
            health_ttl_secs: 60,
            load_ttl_secs: 60,
            illegal_upstream_terms: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "0.0.0.0".to_string(),
                "::1".to_string(),
            ],
            initial_sync_interval_secs: 30,
            max_sync_interval_secs: 3600,
            fanout_factor: 0.5,
            convergence_threshold: 3,
            geo_routing: Some(crate::mesh::dht::routing::GeoRoutingConfig::default()),
            regional_hubs: Some(crate::mesh::dht::routing::RegionalHubConfig::default()),
        }
    }
}

impl DhtConfig {
    pub fn from_mesh_config(
        enabled: bool,
        bootstrap_nodes: Vec<String>,
        consistency_level: DhtConsistencyLevel,
    ) -> Self {
        Self {
            enabled,
            listen_port: 0,
            bootstrap_nodes,
            write_quorum: 11,
            read_quorum: 11,
            replication_factor: 20,
            query_timeout: Duration::from_secs(10),
            bootstrap_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(30),
            record_ttl: Some(Duration::from_secs(3600)),
            consistency_level,
            disk_path: None,
            edge_cache_enabled: true,
            edge_cache_max_entries: 1000,
            edge_cache_ttl_secs: 300,
            warm_up_on_connect: true,
            edge_write_enabled: false,
            min_reputation_for_dht_write: 30,
            health_ttl_secs: 60,
            load_ttl_secs: 60,
            illegal_upstream_terms: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "0.0.0.0".to_string(),
                "::1".to_string(),
            ],
            initial_sync_interval_secs: 30,
            max_sync_interval_secs: 3600,
            fanout_factor: 0.5,
            convergence_threshold: 3,
            geo_routing: Some(crate::mesh::dht::routing::GeoRoutingConfig::default()),
            regional_hubs: Some(crate::mesh::dht::routing::RegionalHubConfig::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub address: String,
    pub port: u16,
    pub role: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub global: bool,
}

impl NodeInfo {
    pub fn new(node_id: String, address: String, port: u16, role: String, global: bool) -> Self {
        Self {
            node_id,
            address,
            port,
            role,
            version: "1.0.0".to_string(),
            capabilities: vec![],
            global,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub node_id: String,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub request_rate: u64,
    pub error_rate: f32,
    pub timestamp: u64,
}

impl NodeHealth {
    pub fn new(
        node_id: String,
        cpu_usage: f32,
        memory_usage: f32,
        request_rate: u64,
        error_rate: f32,
    ) -> Self {
        Self {
            node_id,
            cpu_usage,
            memory_usage,
            request_rate,
            error_rate,
            timestamp: crate::mesh::safe_unix_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLoad {
    pub node_id: String,
    pub active_connections: u64,
    pub queue_depth: u64,
    pub upstream_capacity: u64,
    pub timestamp: u64,
}

impl NodeLoad {
    pub fn new(
        node_id: String,
        active_connections: u64,
        queue_depth: u64,
        upstream_capacity: u64,
    ) -> Self {
        Self {
            node_id,
            active_connections,
            queue_depth,
            upstream_capacity,
            timestamp: crate::mesh::safe_unix_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalNodeEntry {
    pub node_id: String,
    pub address: String,
    pub port: u16,
    pub public_key: String,
    pub timestamp: u64,
}

impl GlobalNodeEntry {
    pub fn new(node_id: String, address: String, port: u16, public_key: String) -> Self {
        Self {
            node_id,
            address,
            port,
            public_key,
            timestamp: crate::mesh::safe_unix_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedUpstream {
    pub upstream_id: String,
    pub upstream_url: String,
    pub org_id: Option<String>,
    pub global_node_id: String,
    pub global_node_signature: Vec<u8>,
    pub registered_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub enum DhtEvent {
    PeerDiscovered(String),
    PeerLost(String),
    RecordStored(String),
    RecordFound(String),
    BootstrapComplete,
    QueryProgressed {
        query_id: String,
        result_type: String,
        closest_peers: Vec<String>,
    },
    ModeChanged(String),
    Error(DhtError),
}

// DHT functionality is now provided by RecordStoreManager in record_store.rs
// This provides a gossip-based distributed record store using the mesh transport

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerInfo {
    pub peer_id: String,
    pub addresses: Vec<String>,
    pub last_seen: u64,
    pub global: bool,
}

#[derive(Debug, Clone)]
pub struct DhtAccessControl {
    require_global_for_privileged: bool,
    allowed_keys_for_edge: Vec<String>,
    global_signature_required_keys: Vec<String>,
    self_only_keys: Vec<String>,
    min_reputation_for_write: i64,
}

impl DhtAccessControl {
    pub fn new(mesh_config: &crate::mesh::config::MeshConfig) -> Self {
        let mut allowed_keys_for_edge = vec![
            "upstream:".to_string(),
            "node_info:".to_string(),
            "global_node_pubkey:".to_string(),
            "node_health:".to_string(),
            "node_load:".to_string(),
            "verified_upstream:".to_string(),
        ];

        if let Some(ref allowed) = mesh_config.dht_access_for_edge {
            allowed_keys_for_edge = allowed.clone();
        }

        let global_signature_required_keys = vec![
            "verified_upstream:".to_string(),
            "tier_claim:".to_string(),
        ];

        let self_only_keys = vec![
            "node_health:".to_string(),
            "node_load:".to_string(),
        ];

        Self {
            require_global_for_privileged: true,
            allowed_keys_for_edge,
            global_signature_required_keys,
            self_only_keys,
            min_reputation_for_write: mesh_config
                .dht
                .as_ref()
                .map(|c| c.min_reputation_for_dht_write)
                .unwrap_or(30),
        }
    }

    pub fn require_global_node(&self) -> Result<(), DhtError> {
        if self.require_global_for_privileged {
            Err(DhtError::NotGlobalNode)
        } else {
            Ok(())
        }
    }

    pub fn can_access(&self, key: &str, is_global_node: bool) -> bool {
        if is_global_node {
            return true;
        }

        for prefix in &self.allowed_keys_for_edge {
            if key.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    pub fn can_store(
        &self,
        key: &str,
        is_global_node: bool,
        is_self_record: bool,
        reputation: i64,
    ) -> bool {
        if is_global_node {
            return true;
        }

        for prefix in &self.global_signature_required_keys {
            if key.starts_with(prefix) {
                tracing::debug!(
                    "Key {} requires global node signature, edge node cannot store",
                    key
                );
                return false;
            }
        }

        for prefix in &self.self_only_keys {
            if key.starts_with(prefix) && !is_self_record {
                tracing::debug!("Key {} can only be stored by the owning node", key);
                return false;
            }
        }

        if reputation < self.min_reputation_for_write {
            tracing::debug!(
                "Node reputation {} below threshold {} for storing key {}",
                reputation,
                self.min_reputation_for_write,
                key
            );
            return false;
        }

        self.can_access(key, is_global_node)
    }

    pub fn requires_global_signature(&self, key: &str) -> bool {
        for prefix in &self.global_signature_required_keys {
            if key.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    pub fn is_self_only(&self, key: &str) -> bool {
        for prefix in &self.self_only_keys {
            if key.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    pub fn min_reputation_for_write(&self) -> i64 {
        self.min_reputation_for_write
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierKeyStoreEntry {
    pub key_id: String,
    pub tier: u32,
    pub key: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_by: String,
    pub bound_to: Option<String>,
    pub is_unspent: bool,
    pub created_at: u64,
}

pub struct TierKeyStore {
    keys: HashMap<String, TierKeyStoreEntry>,
}

impl Default for TierKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TierKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn store_key(&mut self, entry: TierKeyStoreEntry) {
        self.keys.insert(entry.key_id.clone(), entry);
    }

    pub fn get_key(&self, key_id: &str) -> Option<TierKeyStoreEntry> {
        self.keys.get(key_id).cloned()
    }

    pub fn get_all_keys(&self) -> Vec<&TierKeyStoreEntry> {
        self.keys.values().collect()
    }

    pub fn get_unspent_keys(&self) -> Vec<&TierKeyStoreEntry> {
        self.keys
            .values()
            .filter(|k| k.is_unspent && k.valid_from <= now() && k.valid_until >= now())
            .collect()
    }

    pub fn mark_bound(&mut self, key_id: &str, bound_to: &str) -> bool {
        if let Some(entry) = self.keys.get_mut(key_id) {
            entry.bound_to = Some(bound_to.to_string());
            entry.is_unspent = false;
            return true;
        }
        false
    }

    pub fn mark_unspent(&mut self, key_id: &str) -> bool {
        if let Some(entry) = self.keys.get_mut(key_id) {
            entry.bound_to = None;
            entry.is_unspent = true;
            return true;
        }
        false
    }

    pub fn remove(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
    }
}

fn now() -> u64 {
    crate::mesh::safe_unix_timestamp()
}

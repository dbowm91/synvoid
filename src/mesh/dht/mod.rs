pub mod capability_access;
pub mod capability_attestation;
pub mod keys;
pub mod merkle;
pub mod network_policy;
pub mod quorum;
pub mod record_store;
pub mod routing;
pub mod signed;
pub mod stake;
pub mod store;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use capability_attestation::CapabilityAttestation;
pub use keys::*;
pub use merkle::{MerkleNode, MerkleProof, MerkleProofNode, MerkleTree, ProofPosition};
pub use network_policy::{
    AiBotEntry, BlockedNode, BotAction, GlobalAiBotList, GlobalNodeBlocklist, NetworkPolicy,
    MAX_REPUTATION_THRESHOLD, MIN_REPUTATION_THRESHOLD,
};
pub use record_store::{
    DhtRecordEntry, RecordStoreConfig, RecordStoreManager, RecordStoreStats,
    DEFAULT_GET_BY_PREFIX_LIMIT,
};
pub use signed::{
    validate_message_timestamp, RecordSigner, SignedDhtRecord, SignedRecordType, TtlManager,
    DHT_MESSAGE_TIMESTAMP_WINDOW_SECS,
};
pub use stake::{NodeStake, SlashEvent, SlashReason, StakeConfig, StakeLevel, StakeManager};
pub use store::*;

pub use routing::{
    DhtQuery, GeoInfo, KBucket, LookupQuery, NodeId, PeerContact, PersistedBucket,
    PersistedContact, PersistedRoutingTable, QueryResponse, RoutingTable, ALPHA,
    BUCKET_REFRESH_INTERVAL, K_SIZE, PING_TIMEOUT, REPLICATION_K,
};

pub const DEFAULT_RATE_LIMIT_MAX_REQUESTS: u32 = 100;
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;

#[derive(Clone)]
pub struct DhtRateLimiter {
    max_requests: u32,
    window_secs: u64,
    peer_requests: Arc<DashMap<String, Vec<Instant>>>,
}

impl DhtRateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_secs,
            peer_requests: Arc::new(DashMap::new()),
        }
    }

    pub fn is_allowed(&self, peer_id: &str) -> bool {
        let now = Instant::now();

        let mut entry = self.peer_requests.entry(peer_id.to_string()).or_default();
        let requests = &mut entry.value_mut();

        requests.retain(|t| now.duration_since(*t).as_secs() < self.window_secs);

        if requests.len() >= self.max_requests as usize {
            return false;
        }

        requests.push(now);
        true
    }

    pub fn cleanup(&self) {
        let now = Instant::now();

        for mut entry in self.peer_requests.iter_mut() {
            entry
                .value_mut()
                .retain(|t| now.duration_since(*t).as_secs() < self.window_secs);
        }

        self.peer_requests.retain(|_, v| !v.is_empty());
    }
}

impl Default for DhtRateLimiter {
    fn default() -> Self {
        Self::new(
            DEFAULT_RATE_LIMIT_MAX_REQUESTS,
            DEFAULT_RATE_LIMIT_WINDOW_SECS,
        )
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

    #[error("Signature required for DHT record")]
    SignatureRequired,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Default,
    JsonSchema,
)]
pub enum DhtConsistencyLevel {
    Low,
    #[default]
    Medium,
    High,
}

// Note: DhtConfig has complex dependencies - add rkyv derives to individual fields as needed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtConfig {
    /// Enables the DHT subsystem. When disabled, the node participates in mesh routing
    /// but does not perform DHT operations like storing or retrieving records.
    pub enabled: bool,
    /// UDP port for DHT network communication. When set to 0, the operating system
    /// assigns an available port. This port should be accessible from the internet
    /// for full DHT participation (ensure firewall allows inbound UDP).
    pub listen_port: u16,
    /// List of bootstrap node addresses in `host:port` format. These nodes are used
    /// initially to discover the DHT network. Format: `["1.2.3.4:4000", "[2001:db8::1]:4000"]`.
    /// At least one bootstrap node is required for initial network discovery.
    pub bootstrap_nodes: Vec<String>,
    /// Minimum number of nodes that must acknowledge a write operation before it is
    /// considered successful. Higher values increase consistency at the cost of latency.
    /// Must be less than or equal to the number of active peers. Default: 11.
    pub write_quorum: usize,
    /// Minimum number of nodes that must respond to a read operation before it is
    /// considered successful. Higher values improve data consistency. Default: 11.
    pub read_quorum: usize,
    /// Target number of replicas to maintain for each DHT record. Records are
    /// distributed across this many nodes to provide redundancy and availability.
    /// Default: 20.
    pub replication_factor: usize,
    /// Maximum time to wait for a DHT query to complete before considering it failed.
    /// Queries that timeout are retried according to the replication factor. Default: 10s.
    pub query_timeout: Duration,
    /// Maximum time to wait for bootstrap node responses during initial network join.
    /// If bootstrap fails, the node operates in isolated mode. Default: 30s.
    pub bootstrap_timeout: Duration,
    /// Interval between outgoing ping messages to peer nodes for liveness checking.
    /// Nodes that fail to respond are marked as unhealthy and removed from routing. Default: 30s.
    pub ping_interval: Duration,
    /// Time-to-live for DHT records. When None, records never expire. When Some,
    /// records are automatically removed after the specified duration. Default: 3600s (1 hour).
    pub record_ttl: Option<Duration>,
    /// Consistency level for DHT operations, affecting how quorum is calculated.
    /// See [`DhtConsistencyLevel`] for available options. Default: Medium.
    pub consistency_level: DhtConsistencyLevel,
    /// Optional directory path for persistent DHT storage. When None, DHT data is
    /// stored only in memory and lost on restart. When set, records are persisted
    /// to disk for durability across restarts.
    pub disk_path: Option<String>,
    /// Enables edge node caching of DHT records. Edge nodes cache frequently accessed
    /// records locally to reduce latency and offload origin nodes. Default: true.
    pub edge_cache_enabled: bool,
    /// Maximum number of DHT records to cache on edge nodes. When exceeded, the
    /// least recently used entries are evicted. Default: 1000.
    pub edge_cache_max_entries: usize,
    /// Time-to-live for cached DHT records on edge nodes. Cached entries older than
    /// this are considered stale and refreshed on next access. Default: 300s.
    pub edge_cache_ttl_secs: u64,
    /// When true, edge nodes perform an immediate DHT sync to warm up their cache
    /// upon connecting to the network. When false, cache is populated lazily on
    /// demand. Default: true.
    pub warm_up_on_connect: bool,
    /// When true, edge nodes are allowed to write records to the DHT. When false,
    /// edge nodes can only read records. Write operations require sufficient reputation.
    /// Default: false.
    pub edge_write_enabled: bool,
    /// Minimum reputation score required for a node to write records to the DHT.
    /// Reputation is earned through successful interactions and node uptime.
    /// Nodes below this threshold are restricted to read-only DHT operations. Default: 30.
    pub min_reputation_for_dht_write: i64,
    /// Time-to-live for node health status records in the DHT. Health records
    /// track CPU, memory, and request rate for load balancing purposes. Default: 60s.
    pub health_ttl_secs: u64,
    /// Time-to-live for node load statistics records in the DHT. Load records
    /// contain request rate metrics used for weighted routing decisions. Default: 60s.
    pub load_ttl_secs: u64,
    /// Blocklist of upstream domain/IP terms that are never allowed in DHT storage.
    /// Used to prevent storing illegal or malicious upstream definitions. Defaults block
    /// localhost and similar loopback addresses to prevent SSRF attacks.
    pub illegal_upstream_terms: Vec<String>,
    /// Initial interval between DHT sync attempts when starting up or reconnecting.
    /// On each failed attempt, the interval increases up to max_sync_interval_secs.
    /// Shorter intervals mean faster sync at the cost of more network traffic. Default: 30s.
    pub initial_sync_interval_secs: u64,
    /// Maximum interval between DHT sync retry attempts. Controls how aggressively
    /// the node attempts to sync after initial failures. Default: 3600s (1 hour).
    pub max_sync_interval_secs: u64,
    /// Fraction of peers to contact in parallel during DHT operations. A value of 0.5
    /// means contact 50% of known peers simultaneously. Higher values increase
    /// bandwidth usage but reduce latency. Range: 0.0 to 1.0. Default: 0.5.
    pub fanout_factor: f64,
    /// Minimum number of successful responses required before considering a DHT
    /// operation converged. Higher values increase confidence but require more
    /// nodes to respond. Default: 3.
    pub convergence_threshold: usize,
    /// Optional geo-based routing configuration for latency-optimized routing.
    /// When Some, nodes select peers based on geographic proximity and latency.
    /// When None, geographic routing is disabled. Default: Some(GeoRoutingConfig).
    pub geo_routing: Option<crate::mesh::dht::routing::GeoRoutingConfig>,
    /// Optional regional hub configuration for hierarchical routing.
    /// When Some, nodes organize into regional hub hierarchies for efficient routing.
    /// When None, flat DHT routing is used. Default: Some(RegionalHubConfig).
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

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalNodeHeartbeat {
    pub node_id: String,
    pub timestamp: u64,
    pub version: String,
}

impl GlobalNodeHeartbeat {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            timestamp: crate::mesh::safe_unix_timestamp(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
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
    pub origin_node_id: String,
    pub upstream_url: String,
    pub org_id: Option<String>,
    pub global_node_id: String,
    pub global_node_signature: Vec<u8>,
    pub origin_signature: Vec<u8>,
    #[serde(default)]
    pub origin_pubkey: Option<String>,
    pub registered_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OwnershipChallengeType {
    Http01 {
        token: String,
        key_authorization: String,
    },
    Dns01 {
        domain: String,
        txt_record_name: String,
        txt_record_value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamOwnershipChallenge {
    pub upstream_id: String,
    pub origin_node_id: String,
    pub upstream_url: String,
    pub org_id: Option<String>,
    pub challenge_type: OwnershipChallengeType,
    pub challenge_token: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ReachabilityStatus {
    #[default]
    Good,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginReachability {
    pub upstream_id: String,
    pub provider_node_id: String,
    pub status: ReachabilityStatus,
    pub latency_ms: u32,
    pub error_rate: f32,
    pub consecutive_failures: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTask {
    pub upstream_id: String,
    pub provider_node_id: String,
    pub status: VerificationStatus,
    pub reporting_node_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub verification_node_ids: Vec<String>,
    pub verification_results: Vec<VerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub node_id: String,
    pub verified: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VerificationStatus {
    #[default]
    Pending,
    InProgress,
    Completed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsDomainRegistration {
    pub domain: String,
    pub origin_node_id: String,
    pub ip_addresses: Vec<String>,
    pub registered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct AnycastNode {
    pub node_id: String,
    pub anycast_ips: Vec<String>,
    pub geo: Option<String>,
    pub capacity: u32,
    pub healthy: bool,
    pub dns_zones: Vec<String>,
    pub registered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct OriginPenalty {
    pub upstream_id: String,
    pub provider_node_id: String,
    pub penalty_score: i32,
    pub created_at: u64,
    pub last_updated: u64,
    pub expires_at: u64,
    pub applied_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct YaraRulesManifest {
    pub version: String,
    pub content_hash: String,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub is_chunked: bool,
    pub chunk_count: usize,
    pub uncompressed_size: usize,
    pub compressed_size: usize,
    pub chunk_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct YaraRuleChunkRecord {
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub content_hash: String,
    pub node_id: String,
    pub timestamp: u64,
    pub compressed_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct YaraRuleContentRecord {
    pub version: String,
    pub rules: String,
    pub content_hash: String,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub is_chunked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalNodeKeyRecord {
    pub public_key: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct QuorumSignableContent {
    pub key: String,
    pub value: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct PeerPersistenceData {
    pub version: u32,
    pub peers: Vec<crate::mesh::topology::PeerState>,
    pub peer_scores: HashMap<String, crate::mesh::topology::PeerScore>,
    pub saved_at: u64,
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

        let global_signature_required_keys =
            vec!["verified_upstream:".to_string(), "tier_claim:".to_string()];

        let self_only_keys = vec![
            "node_health:".to_string(),
            "node_load:".to_string(),
            "capability_attestation:".to_string(),
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

    pub fn requires_quorum(&self, key: &str) -> bool {
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

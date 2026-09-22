pub mod advisory_source;
pub mod capability_access;
pub mod capability_attestation;
pub mod edge_attestation;
pub mod ingress_policy;
pub mod key_policy;
pub mod keys;
pub mod merkle;
pub mod network_policy;
pub mod quorum;
pub mod record_store;
pub mod record_store_disk;
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

pub use advisory_source::{
    AdvisoryFreshness, AdvisoryRecord, AdvisoryRecordLookup, AdvisoryRecordSource,
    AdvisoryRecordStatus, RecordStoreAdvisorySource, StaticAdvisoryRecordSource,
};
pub use capability_attestation::CapabilityAttestation;
pub use edge_attestation::EdgeAttestation;
pub use keys::*;
pub use merkle::{MerkleNode, MerkleProof, MerkleProofNode, MerkleTree, ProofPosition};
pub use network_policy::{
    AiBotEntry, AuditReceipt, BlockedNode, BotAction, GlobalAiBotList, GlobalNodeBlocklist,
    NetworkPolicy, MAX_REPUTATION_THRESHOLD, MIN_REPUTATION_THRESHOLD,
};
pub use record_store::{
    DhtRecordEntry, RecordStoreConfig, RecordStoreManager, RecordStoreStats,
    DEFAULT_GET_BY_PREFIX_LIMIT,
};
pub use record_store_disk::DiskRecordStore;
pub use signed::{
    validate_message_timestamp, RecordSigner, SignedDhtRecord, SignedRecordType, TtlManager,
    DHT_MESSAGE_TIMESTAMP_WINDOW_SECS,
};
pub use stake::{NodeStake, SlashEvent, SlashReason, StakeConfig, StakeLevel, StakeManager};
pub use store::*;

pub use ingress_policy::{
    check_dht_ingress_authority, DhtIngressGateOutcome, DhtIngressPolicyContext,
};

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
    pub geo_routing: Option<crate::dht::routing::GeoRoutingConfig>,
    /// Optional regional hub configuration for hierarchical routing.
    /// When Some, nodes organize into regional hub hierarchies for efficient routing.
    /// When None, flat DHT routing is used. Default: Some(RegionalHubConfig).
    pub regional_hubs: Option<crate::dht::routing::RegionalHubConfig>,
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
            geo_routing: Some(crate::dht::routing::GeoRoutingConfig::default()),
            regional_hubs: Some(crate::dht::routing::RegionalHubConfig::default()),
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
            geo_routing: Some(crate::dht::routing::GeoRoutingConfig::default()),
            regional_hubs: Some(crate::dht::routing::RegionalHubConfig::default()),
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
            timestamp: synvoid_utils::safe_unix_timestamp(),
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
            timestamp: synvoid_utils::safe_unix_timestamp(),
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
            timestamp: synvoid_utils::safe_unix_timestamp(),
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
    pub trust_level: u8,
    pub attestation_report: Option<String>,
}

impl GlobalNodeEntry {
    pub fn new(node_id: String, address: String, port: u16, public_key: String) -> Self {
        Self {
            node_id,
            address,
            port,
            public_key,
            timestamp: synvoid_utils::safe_unix_timestamp(),
            trust_level: 1,
            attestation_report: None,
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
pub struct YaraRuleSignature {
    pub signer_id: String,
    pub public_key: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct YaraRulesManifest {
    pub version: String,
    pub content_hash: String,
    pub compiled_hash: Option<String>,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub is_chunked: bool,
    pub chunk_count: usize,
    pub uncompressed_size: usize,
    pub compressed_size: usize,
    pub chunk_hashes: Vec<String>,
    pub compiled_chunk_hashes: Option<Vec<String>>,
    pub multi_signatures: Option<Vec<YaraRuleSignature>>,
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
pub struct YaraCompiledRuleContentRecord {
    pub version: String,
    pub compiled_rules: Vec<u8>,
    pub compiled_hash: String,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub is_chunked: bool,
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
    /// `announced_at` is the legacy wire name written by
    /// `transport_global` (`{node_id, public_key, announced_at, ...}`) while
    /// `record_store_crud::publish_global_node_public_key` writes `timestamp`.
    /// Accept both; missing timestamps decode as 0 so callers treat the
    /// record as stale (matches the old `Value::as_u64().unwrap_or(0)` path).
    #[serde(default, alias = "announced_at")]
    pub timestamp: u64,
}

/// DHT `key_exchange_endpoint:<node_id>` payload written by
/// `transports::manager::update_key_exchange_endpoint` as
/// `{node_id, public_key, endpoint, timestamp}`.
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct KeyExchangeEndpointRecord {
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default, alias = "announced_at")]
    pub timestamp: u64,
}

/// DHT `edge_key:<edge_id>` payload. Two writers exist:
/// `transports::manager::announce_edge_key` writes `{edge_id, public_key,
/// timestamp: u64}` while `transport::announce_edge_key` writes
/// `{edge_id, public_key, announced_at: i64 (chrono)}`. Both are accepted;
/// see [`EdgeKeyRecord::effective_timestamp`].
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct EdgeKeyRecord {
    #[serde(default)]
    pub edge_id: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub announced_at: Option<i64>,
}

impl EdgeKeyRecord {
    pub fn effective_timestamp(&self) -> u64 {
        if let Some(ts) = self.timestamp {
            return ts;
        }
        if let Some(announced) = self.announced_at {
            return announced.max(0) as u64;
        }
        0
    }
}

/// Tolerant bootstrap record for `global_node:*` DHT payloads read by
/// `discovery::bootstrap_from_dht`. The only field used on that path is
/// `address`; everything else is optional so minimal `{address}` payloads and
/// full [`GlobalNodeEntry`] payloads both decode.
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalNodeBootstrapRecord {
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default, alias = "announced_at")]
    pub timestamp: u64,
}

/// Decode a DHT record payload postcard-first; serde_json is a documented
/// compat fallback for records written before the postcard migration.
/// The postcard attempt requires full input consumption so long legacy JSON
/// payloads cannot misdecode as postcard garbage (a JSON `{` byte looks like
/// a 123-length string prefix to postcard).
pub fn decode_dht_record<T>(bytes: &[u8]) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    if let Ok((value, rest)) = postcard::take_from_bytes::<T>(bytes) {
        if rest.is_empty() {
            return Some(value);
        }
    }
    serde_json::from_slice::<T>(bytes).ok()
}

/// Lenient `u64` deserializer for legacy JSON DHT payloads that encoded
/// timestamps as strings (`"1700000000"`) instead of numbers. Only the
/// `*LegacyRecord` structs below use it; postcard always carries integers.
fn de_flex_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    struct FlexU64;
    impl Visitor<'_> for FlexU64 {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64 or a string holding a u64")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom("negative timestamp"))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            v.parse().map_err(|_| E::custom("invalid timestamp string"))
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<u64, E> {
            self.visit_str(&v)
        }
    }
    // `deserialize_any` is unsupported by postcard, so legacy structs using
    // this helper always fall through to the JSON path of
    // `decode_dht_record`; genuine postcard payloads are handled by the
    // primary typed decode that runs first at each call site.
    deserializer.deserialize_any(FlexU64)
}

/// Default `chunk_count` for legacy manifests that omit the field (matches
/// the old `Value::as_u64().unwrap_or(1)` fallback).
fn default_legacy_chunk_count() -> usize {
    1
}

/// Lenient `usize` counterpart of [`de_flex_u64`] for legacy `chunk_count`
/// fields (number or numeric string).
fn de_flex_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    de_flex_u64(deserializer).map(|v| v as usize)
}

/// Mutable view of `global_node_key:<id>` payloads for the
/// `UpdateKeyExchange` read-modify-write path in `transport_global`.
/// Tolerates every known publisher shape (`timestamp` or legacy
/// `announced_at`, with or without `key_exchange_endpoint`/`announced_by`)
/// so the endpoint can be updated without dropping the public key.
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct GlobalNodeKeyEndpointRecord {
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub key_exchange_endpoint: Option<String>,
    #[serde(default)]
    pub announced_by: Option<String>,
    #[serde(default, alias = "announced_at")]
    pub timestamp: u64,
}

/// Tolerant `serverless_function:<name>` payload. Two JSON publishers exist
/// (`transport::announce_serverless` omits `checksum`, the peer announce
/// handler omits `node_id`); every field defaults so both shapes decode.
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct ServerlessFunctionDhtRecord {
    #[serde(default)]
    pub function_name: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub checksum: String,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub memory_mb: Option<usize>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub priority: i32,
}

/// Legacy JSON shape of `yara_rule_content:<hash>` payloads (timestamp as
/// number-or-string). New publishers emit postcard [`YaraRuleContentRecord`];
/// this struct only serves the compat fallback. `version`/`rules` stay
/// optional so payloads missing them are rejected exactly like the old
/// `Value`-based fallback did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleContentLegacyRecord {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub rules: Option<String>,
    #[serde(default, deserialize_with = "de_flex_u64")]
    pub timestamp: u64,
}

/// Legacy JSON shape of `yara_chunk:<hash>:<i>` payloads (base64
/// `compressed_data`, string metadata). New publishers emit postcard
/// [`YaraRuleChunkRecord`]; this struct only serves the compat fallback.
/// `compressed_data`/`version` stay optional so incomplete chunks are
/// rejected exactly like the old `Value`-based fallback did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraChunkLegacyRecord {
    #[serde(default)]
    pub compressed_data: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, deserialize_with = "de_flex_u64")]
    pub timestamp: u64,
    #[serde(default)]
    pub signature: String,
}

/// Legacy JSON shape of `yara_rules_manifest:<node>` payloads (string
/// timestamps). New publishers emit postcard [`YaraRulesManifest`]; this
/// struct only serves the compat fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraManifestLegacyRecord {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub content_hash: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, deserialize_with = "de_flex_u64")]
    pub timestamp: u64,
    #[serde(default)]
    pub is_chunked: bool,
    #[serde(
        default = "default_legacy_chunk_count",
        deserialize_with = "de_flex_usize"
    )]
    pub chunk_count: usize,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub signer_public_key: String,
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
    pub peers: Vec<crate::topology::PeerState>,
    pub peer_scores: HashMap<String, crate::topology::PeerScore>,
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
    self_only_keys: Vec<String>,
    authorized_genesis_keys: Vec<String>,
    min_reputation_for_write: i64,
}

impl DhtAccessControl {
    pub fn new(mesh_config: &crate::config::MeshConfig) -> Self {
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

        let self_only_keys = vec![
            "node_health:".to_string(),
            "node_load:".to_string(),
            "capability_attestation:".to_string(),
        ];

        let authorized_genesis_keys = mesh_config
            .genesis_key
            .as_ref()
            .map(|g| g.authorized_genesis_keys.clone())
            .unwrap_or_default();

        if authorized_genesis_keys.is_empty() {
            tracing::warn!(
                "No authorized genesis keys configured - DHT immutability checks will deny all remote immutable records"
            );
        }

        Self {
            require_global_for_privileged: true,
            allowed_keys_for_edge,
            self_only_keys,
            authorized_genesis_keys,
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

        if DhtKey::from_str(key).is_raft_global() {
            tracing::debug!(
                "Key {} is Raft-owned global state, edge node cannot store directly",
                key
            );
            return false;
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
        let dht_key = DhtKey::from_str(key);
        dht_key.is_raft_global()
    }

    pub fn requires_quorum(&self, key: &str) -> bool {
        let dht_key = DhtKey::from_str(key);
        dht_key.is_raft_global()
    }

    pub fn requires_quorum_proof(&self, key: &str) -> bool {
        self.requires_quorum(key)
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

    pub fn requires_immutability_trust_anchor(&self, key: &str) -> bool {
        let dht_key = DhtKey::from_str(key);
        dht_key.is_raft_global()
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
    synvoid_utils::safe_unix_timestamp()
}

#[cfg(test)]
mod typed_record_decoding_tests {
    use super::*;

    #[test]
    fn key_exchange_endpoint_json_and_postcard_roundtrip() {
        let record = KeyExchangeEndpointRecord {
            node_id: Some("node-1".to_string()),
            public_key: Some("pk".to_string()),
            endpoint: Some("https://10.0.0.1:443".to_string()),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_vec(&record).unwrap();
        let decoded: Option<KeyExchangeEndpointRecord> = decode_dht_record(&json);
        assert_eq!(
            decoded.unwrap().endpoint.as_deref(),
            Some("https://10.0.0.1:443")
        );

        let bytes = postcard::to_allocvec(&record).unwrap();
        let decoded: Option<KeyExchangeEndpointRecord> = decode_dht_record(&bytes);
        assert_eq!(decoded.unwrap().timestamp, 1_700_000_000);
    }

    #[test]
    fn key_exchange_endpoint_malformed_is_none() {
        assert!(decode_dht_record::<KeyExchangeEndpointRecord>(b"not json\xff").is_none());
        // Valid JSON shape but no endpoint: decodes, caller falls through to fallback.
        let decoded: Option<KeyExchangeEndpointRecord> =
            decode_dht_record(br#"{"node_id":"n","timestamp":42}"#);
        assert!(decoded.unwrap().endpoint.is_none());
    }

    #[test]
    fn edge_key_accepts_timestamp_and_announced_at() {
        let via_timestamp: Option<EdgeKeyRecord> =
            decode_dht_record(br#"{"edge_id":"e","public_key":"pk","timestamp":100}"#);
        let via_timestamp = via_timestamp.unwrap();
        assert_eq!(via_timestamp.public_key.as_deref(), Some("pk"));
        assert_eq!(via_timestamp.effective_timestamp(), 100);

        // Legacy `transport::announce_edge_key` writes chrono i64 `announced_at`.
        let via_announced: Option<EdgeKeyRecord> =
            decode_dht_record(br#"{"edge_id":"e","public_key":"pk","announced_at":200}"#);
        assert_eq!(via_announced.unwrap().effective_timestamp(), 200);
    }

    #[test]
    fn edge_key_malformed_is_none() {
        assert!(decode_dht_record::<EdgeKeyRecord>(b"\x00\x01\x02").is_none());
        let missing_key: Option<EdgeKeyRecord> = decode_dht_record(br#"{"timestamp":1}"#);
        let missing_key = missing_key.unwrap();
        assert!(missing_key.public_key.is_none());
        assert_eq!(missing_key.effective_timestamp(), 1);
    }

    #[test]
    fn global_node_key_accepts_timestamp_and_announced_at() {
        let via_timestamp: Option<GlobalNodeKeyRecord> =
            decode_dht_record(br#"{"public_key":"pk","timestamp":7}"#);
        assert_eq!(via_timestamp.unwrap().timestamp, 7);

        // `transport_global` writes `announced_at` with extra unknown fields.
        let via_announced: Option<GlobalNodeKeyRecord> = decode_dht_record(
            br#"{"node_id":"n","public_key":"pk","announced_at":9,"announced_by":"x"}"#,
        );
        let decoded = via_announced.unwrap();
        assert_eq!(decoded.public_key, "pk");
        assert_eq!(decoded.timestamp, 9);
    }

    #[test]
    fn global_node_key_malformed_is_none() {
        assert!(decode_dht_record::<GlobalNodeKeyRecord>(b"garbage").is_none());
        // Missing required public_key must not decode.
        assert!(decode_dht_record::<GlobalNodeKeyRecord>(br#"{"timestamp":1}"#).is_none());
    }

    #[test]
    fn bootstrap_record_minimal_and_full() {
        let minimal: Option<GlobalNodeBootstrapRecord> =
            decode_dht_record(br#"{"address":"10.0.0.2:8080"}"#);
        assert_eq!(minimal.unwrap().address.as_deref(), Some("10.0.0.2:8080"));

        let full: Option<GlobalNodeBootstrapRecord> = decode_dht_record(
            br#"{"node_id":"n","address":"10.0.0.3:8080","port":8080,"public_key":"pk","timestamp":5}"#,
        );
        assert_eq!(full.unwrap().port, Some(8080));
    }

    #[test]
    fn bootstrap_record_malformed_is_none() {
        assert!(decode_dht_record::<GlobalNodeBootstrapRecord>(b"\xff\xfe").is_none());
    }

    #[test]
    fn site_config_payloads_decode_typed() {
        let image_protection: Option<crate::config::MeshImageProtectionConfig> =
            decode_dht_record(br#"{"enabled":true,"min_size_bytes":1024}"#);
        let image_protection = image_protection.unwrap();
        assert_eq!(image_protection.enabled, Some(true));
        assert_eq!(image_protection.min_size_bytes, Some(1024));

        let compression: Option<crate::config::MeshCompressionConfig> =
            decode_dht_record(br#"{"enabled":true,"gzip_level":6}"#);
        assert_eq!(compression.unwrap().gzip_level, Some(6));

        let minification: Option<crate::config::MeshMinificationConfig> =
            decode_dht_record(br#"{"enabled":true,"enable_html":true}"#);
        assert_eq!(minification.unwrap().enable_html, Some(true));

        // Partial proxy-cache payloads must fill defaults (old Value path used unwrap_or).
        let prefs: Option<crate::protocol::ProxyCachePreferences> =
            decode_dht_record(br#"{"enable":true}"#);
        let prefs = prefs.unwrap();
        assert!(prefs.enable);
        assert!(prefs.methods.is_empty());

        assert!(decode_dht_record::<crate::protocol::ProxyCachePreferences>(b"nope").is_none());
        assert!(decode_dht_record::<crate::config::MeshImageProtectionConfig>(b"nope").is_none());
    }

    #[test]
    fn long_json_never_decodes_as_postcard_garbage() {
        // Regression: a JSON payload longer than 123 bytes must not be
        // misread as postcard (a `{` byte looks like a 123-length string
        // prefix). The decoder must fall through to JSON and return exact
        // field values.
        let long_key = "k".repeat(64);
        let json = format!(
            r#"{{"node_id":"node-abc","public_key":"{long_key}","key_exchange_endpoint":"https://10.0.0.9:443","announced_at":1700000000,"announced_by":"node-abc"}}"#,
        );
        assert!(json.len() > 123);
        let decoded: Option<GlobalNodeKeyRecord> = decode_dht_record(json.as_bytes());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.public_key, long_key);
        assert_eq!(decoded.timestamp, 1_700_000_000);
    }

    #[test]
    fn endpoint_record_roundtrip_and_malformed() {
        let record = GlobalNodeKeyEndpointRecord {
            node_id: Some("n".to_string()),
            public_key: Some("pk".to_string()),
            key_exchange_endpoint: Some("https://10.0.0.1:443".to_string()),
            announced_by: Some("peer".to_string()),
            timestamp: 42,
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let decoded: Option<GlobalNodeKeyEndpointRecord> = decode_dht_record(&bytes);
        let decoded = decoded.unwrap();
        assert_eq!(decoded.public_key.as_deref(), Some("pk"));
        assert_eq!(
            decoded.key_exchange_endpoint.as_deref(),
            Some("https://10.0.0.1:443")
        );

        // Legacy JSON with `announced_at` and no endpoint.
        let legacy: Option<GlobalNodeKeyEndpointRecord> =
            decode_dht_record(br#"{"node_id":"n","public_key":"pk","announced_at":7}"#);
        let legacy = legacy.unwrap();
        assert_eq!(legacy.timestamp, 7);
        assert!(legacy.key_exchange_endpoint.is_none());

        assert!(decode_dht_record::<GlobalNodeKeyEndpointRecord>(b"\xff\xfe\xfd").is_none());
    }

    #[test]
    fn serverless_record_tolerates_both_publishers_and_malformed() {
        // `transport::announce_serverless` omits `checksum`.
        let without_checksum: Option<ServerlessFunctionDhtRecord> = decode_dht_record(
            br#"{"function_name":"f","version":1,"node_id":"n","routes":[],"allowed_methods":[],"priority":100}"#,
        );
        let decoded = without_checksum.unwrap();
        assert_eq!(decoded.function_name, "f");
        assert!(decoded.checksum.is_empty());

        // Peer announce handler omits `node_id` but carries `checksum`.
        let without_node: Option<ServerlessFunctionDhtRecord> = decode_dht_record(
            br#"{"function_name":"g","version":2,"checksum":"abc","routes":["/x"],"allowed_methods":["GET"]}"#,
        );
        let decoded = without_node.unwrap();
        assert!(decoded.node_id.is_none());
        assert_eq!(decoded.checksum, "abc");
        assert_eq!(decoded.routes, vec!["/x".to_string()]);

        // Postcard roundtrip.
        let record = ServerlessFunctionDhtRecord {
            function_name: "h".to_string(),
            node_id: Some("n".to_string()),
            version: 3,
            checksum: "chk".to_string(),
            routes: vec![],
            allowed_methods: vec![],
            memory_mb: Some(128),
            timeout_seconds: Some(30),
            priority: 100,
        };
        let bytes = postcard::to_allocvec(&record).unwrap();
        let decoded: Option<ServerlessFunctionDhtRecord> = decode_dht_record(&bytes);
        assert_eq!(decoded.unwrap().memory_mb, Some(128));

        assert!(decode_dht_record::<ServerlessFunctionDhtRecord>(b"not-a-record").is_none());
    }

    #[test]
    fn yara_legacy_records_decode_string_timestamps_and_malformed() {
        // Rule content with numeric and string timestamps.
        let numeric: Option<YaraRuleContentLegacyRecord> =
            decode_dht_record(br#"{"version":"v1","rules":"rule x {}","timestamp":99}"#);
        let numeric = numeric.unwrap();
        assert_eq!(numeric.version.as_deref(), Some("v1"));
        assert_eq!(numeric.timestamp, 99);
        let textual: Option<YaraRuleContentLegacyRecord> =
            decode_dht_record(br#"{"version":"v1","rules":"rule x {}","timestamp":"100"}"#);
        assert_eq!(textual.unwrap().timestamp, 100);
        // Missing rules/version must be rejected like the old fallback.
        let incomplete: Option<YaraRuleContentLegacyRecord> =
            decode_dht_record(br#"{"timestamp":1}"#);
        let incomplete = incomplete.unwrap();
        assert!(incomplete.version.is_none());
        assert!(incomplete.rules.is_none());

        // Chunk with base64 payload and string timestamp.
        let chunk: Option<YaraChunkLegacyRecord> = decode_dht_record(
            br#"{"compressed_data":"aGVsbG8=","version":"v1","timestamp":"7","signature":"c2ln"}"#,
        );
        let chunk = chunk.unwrap();
        assert_eq!(chunk.compressed_data.as_deref(), Some("aGVsbG8="));
        assert_eq!(chunk.timestamp, 7);

        // Manifest with string timestamp and defaulted chunk_count.
        let manifest: Option<YaraManifestLegacyRecord> = decode_dht_record(
            br#"{"node_id":"n","content_hash":"h","version":"v2","timestamp":"55","is_chunked":true,"chunk_count":"3"}"#,
        );
        let manifest = manifest.unwrap();
        assert_eq!(manifest.timestamp, 55);
        assert_eq!(manifest.chunk_count, 3);

        assert!(decode_dht_record::<YaraRuleContentLegacyRecord>(b"\x00\x01").is_none());
        assert!(decode_dht_record::<YaraChunkLegacyRecord>(b"\x00\x01").is_none());
        assert!(decode_dht_record::<YaraManifestLegacyRecord>(b"\x00\x01").is_none());
    }

    #[test]
    fn heartbeat_and_verified_upstream_decode_and_malformed() {
        let heartbeat = GlobalNodeHeartbeat::new("node-1".to_string());
        let bytes = postcard::to_allocvec(&heartbeat).unwrap();
        let decoded: Option<GlobalNodeHeartbeat> = decode_dht_record(&bytes);
        assert_eq!(decoded.unwrap().node_id, "node-1");
        // JSON compat.
        let via_json: Option<GlobalNodeHeartbeat> =
            decode_dht_record(br#"{"node_id":"node-2","timestamp":5,"version":"0.1.0"}"#);
        assert_eq!(via_json.unwrap().node_id, "node-2");
        assert!(decode_dht_record::<GlobalNodeHeartbeat>(b"nope").is_none());

        let verified_json = br#"{"upstream_id":"site","origin_node_id":"o","upstream_url":"https://o","global_node_id":"g","global_node_signature":[],"origin_signature":[],"registered_at":1,"expires_at":2}"#;
        let verified: Option<VerifiedUpstream> = decode_dht_record(verified_json);
        assert_eq!(verified.unwrap().upstream_id, "site");
        assert!(decode_dht_record::<VerifiedUpstream>(b"nope").is_none());
    }
}

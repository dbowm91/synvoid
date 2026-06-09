use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use synvoid_config::site::ProxyUpstreamConfig;

pub use synvoid_config::mesh::MeshNodeRole;

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::organization::ADMIN_ORG_ID;
pub use crate::reputation::ReputationConfig;
pub use crate::threat_intel::ThreatIntelligenceConfig;

/// Configuration for stale authority artifact handling.
///
/// Defines fail-open/fail-closed behavior when Raft-derived authority
/// artifacts (org keys, threat intel, revocations, global node auth)
/// become stale relative to expected freshness windows.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityFreshnessConfig {
    /// Grace period for normal global policy updates before fail-closed.
    /// Default: 3600 (1 hour)
    #[serde(default = "default_global_policy_grace_secs")]
    pub global_policy_grace_secs: u64,
    /// Hard limit for revocation freshness. Revocations exceeding this
    /// are fail-closed for global nodes. Default: 300 (5 minutes)
    #[serde(default = "default_revocation_hard_limit_secs")]
    pub revocation_hard_limit_secs: u64,
    /// Hard limit for CA/trust-root epoch staleness. Default: 86400 (24 hours)
    #[serde(default = "default_ca_epoch_hard_limit_secs")]
    pub ca_epoch_hard_limit_secs: u64,
    /// When true, stale threat intel falls back to local rules.
    /// Default: true (fail open local)
    #[serde(default = "default_threat_intel_stale_local")]
    pub threat_intel_stale_local: bool,
    /// When true, peer discovery uses cached peers/bootstrap seeds
    /// when authoritative source is stale. Default: true
    #[serde(default = "default_peer_discovery_degraded")]
    pub peer_discovery_degraded: bool,
    /// TTL for DHT soft-state entries. Expired entries are removed
    /// from routing decisions naturally. Default: 300 (5 minutes)
    #[serde(default = "default_dht_soft_state_ttl_secs")]
    pub dht_soft_state_ttl_secs: u64,
}

fn default_global_policy_grace_secs() -> u64 {
    3600
}
fn default_revocation_hard_limit_secs() -> u64 {
    300
}
fn default_ca_epoch_hard_limit_secs() -> u64 {
    86400
}
fn default_threat_intel_stale_local() -> bool {
    true
}
fn default_peer_discovery_degraded() -> bool {
    true
}
fn default_dht_soft_state_ttl_secs() -> u64 {
    300
}

impl Default for AuthorityFreshnessConfig {
    fn default() -> Self {
        Self {
            global_policy_grace_secs: 3600,
            revocation_hard_limit_secs: 300,
            ca_epoch_hard_limit_secs: 86400,
            threat_intel_stale_local: true,
            peer_discovery_degraded: true,
            dht_soft_state_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct YaraRulesMeshConfig {
    #[serde(default = "default_yara_mesh_enabled")]
    pub enabled: bool,
    #[serde(default = "default_yara_mesh_sync_interval")]
    pub sync_interval_secs: u64,
    #[serde(default = "default_re_announce_interval")]
    pub re_announce_interval_secs: u64,
    #[serde(default = "default_allow_edge_submissions")]
    pub allow_edge_submissions: bool,
    #[serde(default)]
    pub require_global_approval: bool,
    #[serde(default = "default_require_signature")]
    pub require_signature: bool,
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default = "default_yara_mesh_max_rules_size")]
    pub max_rules_size_kb: u32,
    #[serde(default)]
    pub hub_only_mode: bool,
}

fn default_allow_edge_submissions() -> bool {
    false
}

fn default_require_signature() -> bool {
    true
}

fn default_yara_mesh_enabled() -> bool {
    true
}

fn default_yara_mesh_sync_interval() -> u64 {
    3600
}

fn default_re_announce_interval() -> u64 {
    300
}

fn default_yara_mesh_max_rules_size() -> u32 {
    1024
}

impl Default for YaraRulesMeshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval_secs: 3600,
            re_announce_interval_secs: 300,
            allow_edge_submissions: false,
            require_global_approval: true,
            require_signature: true,
            trusted_signers: Vec::new(),
            max_rules_size_kb: 1024,
            hub_only_mode: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SequenceCounter {
    counter: Arc<AtomicU32>,
}

impl SequenceCounter {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicU32::new(0)),
        }
    }

    // SAFETY: Relaxed ordering is correct here because each SequenceCounter
    // is used independently — there is no accompanying data that needs to be
    // synchronized via the counter's ordering. The only guarantee needed is
    // that successive calls to `next()` return monotonically increasing values,
    // which `fetch_add(Relaxed)` provides on a single atomic.
    pub fn next(&self) -> u32 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for SequenceCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct MeshSeedNode {
    pub address: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub global_node_key: Option<String>,
    #[serde(default)]
    pub quic_port: Option<u16>,
    #[serde(default)]
    pub pinned_cert_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct SeedTofuConfig {
    #[serde(default = "default_tofu_enabled")]
    pub enabled: bool,
    #[serde(default = "default_require_explicit_fingerprint")]
    pub require_explicit_fingerprint: bool,
    #[serde(default)]
    pub pinned_fingerprints: HashMap<String, String>,
}

fn default_tofu_enabled() -> bool {
    true
}

fn default_require_explicit_fingerprint() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshPeerConfig {
    pub address: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshUpstreamPeer {
    pub node_id: String,
    #[serde(default)]
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct MeshLocalUpstream {
    pub upstream_url: String,
    #[serde(default)]
    pub geo: Option<String>,
    #[serde(default)]
    pub waf_policy: Option<crate::protocol::WafPolicy>,
    #[serde(default)]
    pub protocol: crate::protocol::UpstreamProtocol,
    #[serde(default)]
    pub priority_tier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct MeshServicePolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl MeshServicePolicy {
    pub fn can_forward(&self, service_id: &str) -> bool {
        if self.deny.contains(&service_id.to_string()) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.contains(&service_id.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshRoutingConfig {
    #[serde(default = "default_routing_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_hops")]
    pub max_hops: u8,
    #[serde(default = "default_query_timeout_ms")]
    pub query_timeout_ms: u64,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u8,
    #[serde(default = "default_peer_query_count")]
    pub peer_query_count: usize,
    #[serde(default = "default_allow_all_services")]
    pub allow_all_services: bool,
    #[serde(default)]
    pub allowed_services: Vec<String>,
    #[serde(default = "default_route_query_limit")]
    pub route_queries_per_minute: usize,
    #[serde(default = "default_mesh_messages_per_sec")]
    pub mesh_messages_per_sec: usize,
    #[serde(skip)]
    pub query_sequence: SequenceCounter,
}

impl Default for MeshRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_hops: 3,
            query_timeout_ms: 5000,
            retry_attempts: 2,
            peer_query_count: 3,
            allow_all_services: true,
            allowed_services: Vec::new(),
            route_queries_per_minute: 6000,
            mesh_messages_per_sec: 10000,
            query_sequence: SequenceCounter::new(),
        }
    }
}

fn default_routing_enabled() -> bool {
    true
}

fn default_max_hops() -> u8 {
    3
}

fn default_query_timeout_ms() -> u64 {
    5000
}

fn default_retry_attempts() -> u8 {
    2
}

fn default_peer_query_count() -> usize {
    3
}

fn default_allow_all_services() -> bool {
    true
}

fn default_route_query_limit() -> usize {
    6000
}

fn default_mesh_messages_per_sec() -> usize {
    10000
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshConnectionConfig {
    #[serde(default = "default_min_peers")]
    pub min_peer_connections: usize,
    #[serde(default = "default_max_peers")]
    pub max_peer_connections: usize,
    #[serde(default)]
    pub connection_score_weights: ConnectionScoreWeights,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_secs: u64,
    #[serde(default)]
    pub reconnection_priority: ReconnectionPriority,
    #[serde(default = "default_announce_interval")]
    pub announce_interval_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,
    #[serde(default = "default_max_auth_failures")]
    pub max_auth_failures: usize,
    #[serde(default = "default_auth_failure_window_secs")]
    pub auth_failure_window_secs: u64,
    #[serde(default = "default_max_pending_connections")]
    pub max_pending_connections: usize,
    #[serde(default = "default_circuit_open_threshold")]
    pub circuit_open_threshold: u32,
    #[serde(default = "default_circuit_open_timeout_secs")]
    pub circuit_open_timeout_secs: u64,
    #[serde(default = "default_half_open_max_requests")]
    pub half_open_max_requests: u32,
    #[serde(default = "default_circuit_close_threshold")]
    pub circuit_close_threshold: u32,
}

fn default_min_peers() -> usize {
    3
}

fn default_max_peers() -> usize {
    20
}

fn default_health_check_interval() -> u64 {
    30
}

fn default_announce_interval() -> u64 {
    30
}

fn default_keepalive_interval() -> u64 {
    10
}

fn default_max_auth_failures() -> usize {
    5
}

fn default_auth_failure_window_secs() -> u64 {
    300
}

fn default_max_pending_connections() -> usize {
    100
}

fn default_circuit_open_threshold() -> u32 {
    5
}

fn default_circuit_open_timeout_secs() -> u64 {
    30
}

fn default_half_open_max_requests() -> u32 {
    3
}

fn default_circuit_close_threshold() -> u32 {
    3
}

impl Default for MeshConnectionConfig {
    fn default() -> Self {
        Self {
            min_peer_connections: 3,
            max_peer_connections: 20,
            connection_score_weights: ConnectionScoreWeights::default(),
            health_check_interval_secs: 30,
            reconnection_priority: ReconnectionPriority::default(),
            announce_interval_secs: 30,
            keepalive_interval_secs: 10,
            max_auth_failures: 5,
            auth_failure_window_secs: 300,
            max_pending_connections: 100,
            circuit_open_threshold: 5,
            circuit_open_timeout_secs: 30,
            half_open_max_requests: 3,
            circuit_close_threshold: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionScoreWeights {
    #[serde(default = "default_latency_weight")]
    pub latency: f64,
    #[serde(default = "default_stability_weight")]
    pub stability: f64,
    #[serde(default = "default_load_weight")]
    pub load: f64,
    #[serde(default = "default_traffic_weight")]
    pub traffic: f64,
    #[serde(default = "default_upstream_weight")]
    pub upstream: f64,
}

fn default_latency_weight() -> f64 {
    0.3
}
fn default_stability_weight() -> f64 {
    0.25
}
fn default_load_weight() -> f64 {
    0.2
}
fn default_traffic_weight() -> f64 {
    0.15
}
fn default_upstream_weight() -> f64 {
    0.1
}

impl Default for ConnectionScoreWeights {
    fn default() -> Self {
        Self {
            latency: 0.3,
            stability: 0.25,
            load: 0.2,
            traffic: 0.15,
            upstream: 0.1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReconnectionPriority {
    #[serde(default = "default_priority_global")]
    pub global_nodes: usize,
    #[serde(default = "default_priority_upstream")]
    pub upstream_providers: usize,
    #[serde(default = "default_priority_frequent")]
    pub frequent_routes: usize,
}

fn default_priority_global() -> usize {
    3
}
fn default_priority_upstream() -> usize {
    5
}
fn default_priority_frequent() -> usize {
    3
}

impl Default for ReconnectionPriority {
    fn default() -> Self {
        Self {
            global_nodes: 3,
            upstream_providers: 5,
            frequent_routes: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshUpstreamConfig {
    pub upstream_url: String,
    #[serde(default)]
    pub supported_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub geo: Option<String>,
    #[serde(default)]
    pub peered_wafs: Vec<MeshUpstreamPeer>,
    #[serde(default)]
    pub waf_policy: Option<crate::protocol::WafPolicy>,
    #[serde(default)]
    pub protocol: crate::protocol::UpstreamProtocol,
    #[serde(default)]
    pub priority_tier: u32,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
    #[serde(default)]
    pub image_protection: Option<MeshImageProtectionConfig>,
    #[serde(default)]
    pub compression: Option<MeshCompressionConfig>,
    #[serde(default)]
    pub minification: Option<MeshMinificationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct MeshImageProtectionConfig {
    pub enabled: Option<bool>,
    pub min_size_bytes: Option<usize>,
    pub whitelist_patterns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct MeshCompressionConfig {
    pub enabled: Option<bool>,
    pub gzip_on_the_fly: Option<bool>,
    pub gzip_level: Option<u32>,
    pub gzip_min_size: Option<usize>,
    pub gzip_types: Option<Vec<String>>,
    pub enable_brotli: Option<bool>,
    pub brotli_level: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct MeshMinificationConfig {
    pub enabled: Option<bool>,
    pub enable_html: Option<bool>,
    pub enable_css: Option<bool>,
    pub enable_js: Option<bool>,
}

impl MeshUpstreamConfig {
    pub fn can_be_routed_by(&self, node_id: &str) -> bool {
        if self.peered_wafs.is_empty() {
            return true;
        }
        self.peered_wafs
            .iter()
            .any(|p| p.node_id == node_id && p.allowed)
    }

    pub fn to_proxy_upstream_config(&self) -> ProxyUpstreamConfig {
        ProxyUpstreamConfig {
            allowed_protocols: if self.allowed_protocols.is_empty() {
                None
            } else {
                Some(self.allowed_protocols.clone())
            },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MeshTransportPreference {
    #[default]
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub role: MeshNodeRole,
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub mesh_name: Option<String>,
    #[serde(default)]
    pub global_node_key: Option<String>,
    #[serde(default)]
    pub bind_address: Option<String>,
    #[serde(default = "config_defaults::default_mesh_port")]
    pub port: u16,
    #[serde(default)]
    pub quic_port: Option<u16>,
    #[serde(default)]
    pub auto_port: bool,
    #[serde(default)]
    pub seeds: Vec<MeshSeedNode>,
    #[serde(default)]
    pub peers: Vec<MeshPeerConfig>,
    #[serde(default)]
    pub local_upstreams: HashMap<String, MeshUpstreamConfig>,
    #[serde(default)]
    pub service_policy: MeshServicePolicy,
    #[serde(default)]
    pub routing: MeshRoutingConfig,
    #[serde(default)]
    pub tls: MeshTlsConfig,
    #[serde(default)]
    pub transport_preference: MeshTransportPreference,
    #[serde(default)]
    pub connection: MeshConnectionConfig,
    #[serde(default)]
    pub persistence: MeshPersistenceConfig,
    #[serde(default)]
    pub proxy_cache: Option<synvoid_config::site::ProxyCacheConfig>,
    #[serde(default)]
    pub upstream_resolution: Option<UpstreamResolutionConfig>,
    #[serde(default)]
    pub threat_intel: ThreatIntelligenceConfig,
    #[serde(default)]
    pub yara_rules: YaraRulesMeshConfig,
    #[serde(default)]
    pub node_identity: NodeIdentityConfig,
    #[serde(default)]
    pub tier_config: TierConfig,
    #[serde(default = "config_defaults::default_bandwidth_report_interval")]
    pub bandwidth_report_interval_secs: u64,
    #[serde(default = "config_defaults::default_stale_cache_ttl_secs")]
    pub stale_cache_ttl_secs: u64,
    #[serde(default = "config_defaults::default_ratelimit_block_advertisement")]
    pub ratelimit_block_advertisement: bool,
    #[serde(default)]
    pub origin_signing_key: Option<OriginSigningKeyConfig>,
    #[serde(default)]
    pub global_node: GlobalNodeConfig,
    #[serde(default)]
    pub genesis_key: Option<GenesisKeyConfig>,
    #[serde(default)]
    pub dht: Option<MeshDhtConfig>,
    #[serde(default)]
    pub dht_access_for_edge: Option<Vec<String>>,
    #[serde(default)]
    pub org_config: Option<OrgConfig>,
    #[serde(default)]
    pub can_serve_origin_direct: bool,
    #[serde(default)]
    pub disable_direct_origin: bool,
    #[serde(default)]
    pub capabilities_enabled: bool,
    #[serde(default)]
    pub require_tier_claim: bool,
    #[serde(default = "config_defaults::default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default)]
    pub stake: Option<crate::dht::stake::StakeConfig>,
    #[serde(default)]
    pub mlkem: Option<MeshMlKemConfig>,
    #[serde(default)]
    pub seed_tofu: Option<SeedTofuConfig>,
    #[serde(default)]
    pub authority_freshness: AuthorityFreshnessConfig,
    #[serde(skip)]
    cached_pow: Arc<RwLock<Option<(u64, std::time::Instant)>>>,
}

pub(crate) const POW_CACHE_TTL_SECS: u64 = 3600; // 1 hour

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OriginSigningKeyConfig {
    pub mesh_id: String,
    #[serde(default)]
    pub private_key_base64: Option<String>,
    #[serde(skip)]
    pub private_key: Option<[u8; 32]>,
    #[serde(skip)]
    pub public_key_base64: Option<String>,
}

impl OriginSigningKeyConfig {
    pub fn load_key(&mut self) -> Result<(), String> {
        if let Some(ref b64) = self.private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("Key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.private_key = Some(key);

            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&key);
            self.public_key_base64 =
                Some(URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
/// Configuration for global node identity and key exchange.
/// Supports post-quantum cryptography when `post-quantum` feature is enabled:
/// - ML-KEM-768 for hybrid key encapsulation (X25519 + ML-KEM)
/// - ML-DSA-44 for post-quantum message signatures
pub struct GlobalNodeConfig {
    #[serde(default)]
    pub known_origin_keys: HashMap<String, String>,
    #[serde(default)]
    pub known_edge_keys: HashMap<String, String>,
    #[serde(default = "default_key_exchange_enabled")]
    pub key_exchange_enabled: bool,
    #[serde(default = "default_key_exchange_port")]
    pub key_exchange_port: u16,
    #[serde(default = "default_true")]
    pub key_exchange_require_edge_auth: bool,
    #[serde(default)]
    pub cors_allow_origin: Option<String>,
    #[serde(default)]
    pub cors_allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub cors_allow_headers: Option<Vec<String>>,
    #[serde(default)]
    pub x25519_private_key_base64: Option<String>,
    #[serde(skip)]
    pub x25519_private_key: Option<[u8; 32]>,
    #[serde(skip)]
    pub x25519_public_key_base64: Option<String>,
    #[serde(default)]
    pub ed25519_private_key_base64: Option<String>,
    #[serde(skip)]
    pub ed25519_private_key: Option<[u8; 32]>,
    #[serde(skip)]
    pub ed25519_public_key_base64: Option<String>,
    #[serde(default)]
    pub ml_kem_private_key_base64: Option<String>,
    #[serde(skip)]
    pub ml_kem_public_key_base64: Option<String>,
    #[serde(default)]
    pub ml_dsa_private_key_base64: Option<String>,
    #[serde(skip)]
    pub ml_dsa_public_key_base64: Option<String>,
    #[serde(default)]
    pub invite_tokens: Vec<String>,
}

fn default_key_exchange_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_key_exchange_port() -> u16 {
    50052
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct GenesisKeyConfig {
    #[serde(default)]
    pub private_key_base64: Option<String>,
    #[serde(skip)]
    pub private_key: Option<[u8; 32]>,
    #[serde(skip)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub is_first_node: bool,
    #[serde(default)]
    pub previous_genesis_key_base64: Option<String>,
    #[serde(default)]
    pub rotation_sequence: u32,
    #[serde(default)]
    pub authorized_genesis_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TrustedNodeConfig {
    pub node_id: String,
    pub trusted_at: u64,
    pub granted_by_global_node: Option<String>,
    pub is_genesis: bool,
}

impl TrustedNodeConfig {
    pub fn new(node_id: String, granted_by: Option<String>, is_genesis: bool) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();
        Self {
            node_id,
            trusted_at: now,
            granted_by_global_node: granted_by,
            is_genesis,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshDhtConfig {
    #[serde(default = "default_dht_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dht_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,
    #[serde(default = "default_write_quorum")]
    pub write_quorum: usize,
    #[serde(default = "default_read_quorum")]
    pub read_quorum: usize,
    #[serde(default = "default_query_timeout_secs")]
    pub query_timeout_secs: u64,
    #[serde(default = "default_bootstrap_timeout_secs")]
    pub bootstrap_timeout_secs: u64,
    #[serde(default)]
    pub consistency_level: crate::dht::DhtConsistencyLevel,
    #[serde(default = "default_edge_cache_enabled")]
    pub edge_cache_enabled: bool,
    #[serde(default = "default_edge_cache_max_entries")]
    pub edge_cache_max_entries: usize,
    #[serde(default = "default_edge_cache_ttl_secs")]
    pub edge_cache_ttl_secs: u64,
    #[serde(default = "default_warm_up_enabled")]
    pub warm_up_on_connect: bool,
    #[serde(default = "default_edge_write_enabled")]
    pub edge_write_enabled: bool,
    #[serde(default = "default_min_reputation_for_dht_write")]
    pub min_reputation_for_dht_write: i64,
    #[serde(default = "default_min_reputation_for_dht_read")]
    pub min_reputation_for_dht_read: i64,
    #[serde(default = "default_health_ttl_secs")]
    pub health_ttl_secs: u64,
    #[serde(default = "default_load_ttl_secs")]
    pub load_ttl_secs: u64,
    #[serde(default)]
    pub illegal_upstream_terms: Vec<String>,
    #[serde(default = "default_initial_sync_interval_secs")]
    pub initial_sync_interval_secs: u64,
    #[serde(default = "default_max_sync_interval_secs")]
    pub max_sync_interval_secs: u64,
    #[serde(default = "default_fanout_factor")]
    pub fanout_factor: f64,
    #[serde(default = "default_convergence_threshold")]
    pub convergence_threshold: usize,
    #[serde(default = "default_routing_enabled")]
    pub routing_enabled: bool,
    #[serde(default = "default_routing_full_network_view")]
    pub full_network_view: bool,
    #[serde(default = "default_edge_can_respond_privileged")]
    pub edge_can_respond_privileged: bool,
    #[serde(default = "default_dynamic_policy_enabled")]
    pub dynamic_policy_enabled: bool,
    #[serde(default = "default_grace_period_secs")]
    pub new_node_grace_period_secs: u64,
    #[serde(default = "default_max_away_secs")]
    pub max_away_before_reset_secs: u64,
    #[serde(default = "default_policy_proposal_delay_secs")]
    pub policy_proposal_delay_secs: u64,
    #[serde(default = "default_max_reputation_threshold")]
    pub max_reputation_threshold: i64,
    #[serde(default = "default_manual_threshold_override")]
    pub manual_threshold_override: Option<i64>,
    #[serde(default)]
    pub geo_routing: Option<crate::dht::routing::GeoRoutingConfig>,
    #[serde(default)]
    pub regional_hubs: Option<crate::dht::routing::RegionalHubConfig>,
    #[serde(default = "default_dns_server_enabled")]
    pub dns_server_enabled: bool,
    #[serde(default = "default_dns_mesh_mode_only")]
    pub dns_mesh_mode_only: bool,
    #[serde(default = "default_dht_write_enabled")]
    pub dht_write_enabled: bool,
    #[serde(default = "default_proxy_to_origins")]
    pub proxy_to_origins: bool,
    #[serde(default = "default_can_host_origins")]
    pub can_host_origins: bool,
    #[serde(default = "default_announce_rate_limit_max_requests")]
    pub announce_rate_limit_max_requests: u32,
    #[serde(default = "default_announce_rate_limit_window_secs")]
    pub announce_rate_limit_window_secs: u64,
    #[serde(default = "default_require_signed_sync_requests")]
    pub require_signed_sync_requests: bool,
    /// Optional migration deadline for legacy unsigned DHT sync requests.
    /// When set, unsigned sync requests are rejected after this Unix timestamp
    /// even if `require_signed_sync_requests` is false.
    #[serde(default)]
    pub unsigned_sync_compat_until_unix: Option<u64>,
    /// When true, DHT anti-entropy requests must include a valid envelope
    /// signature (otherwise the request is rejected). Default: true.
    #[serde(default = "default_require_signed_anti_entropy_requests")]
    pub require_signed_anti_entropy_requests: bool,
    /// Optional migration deadline for legacy unsigned anti-entropy requests.
    /// When set, unsigned anti-entropy requests are rejected after this Unix
    /// timestamp even if `require_signed_anti_entropy_requests` is false.
    #[serde(default)]
    pub unsigned_anti_entropy_compat_until_unix: Option<u64>,
    /// When true, DHT record pushes must include a valid envelope signature
    /// covering the record set digest (otherwise the push is rejected).
    /// Default: true.
    #[serde(default = "default_require_signed_record_push")]
    pub require_signed_record_push: bool,
    /// Optional migration deadline for legacy unsigned DHT record pushes.
    /// When set, unsigned record pushes are rejected after this Unix timestamp
    /// even if `require_signed_record_push` is false.
    #[serde(default)]
    pub unsigned_record_push_compat_until_unix: Option<u64>,
}

fn default_announce_rate_limit_max_requests() -> u32 {
    100
}

fn default_announce_rate_limit_window_secs() -> u64 {
    60
}

fn default_require_signed_sync_requests() -> bool {
    true
}

fn default_require_signed_anti_entropy_requests() -> bool {
    true
}

fn default_require_signed_record_push() -> bool {
    true
}

fn default_convergence_threshold() -> usize {
    3
}

fn default_fanout_factor() -> f64 {
    0.5
}

fn default_dht_enabled() -> bool {
    true
}

fn default_dht_port() -> u16 {
    0
}

fn default_write_quorum() -> usize {
    11
}

fn default_read_quorum() -> usize {
    11
}

fn default_query_timeout_secs() -> u64 {
    10
}

fn default_bootstrap_timeout_secs() -> u64 {
    30
}

fn default_edge_cache_enabled() -> bool {
    true
}

fn default_edge_cache_max_entries() -> usize {
    1000
}

fn default_edge_cache_ttl_secs() -> u64 {
    300
}

fn default_warm_up_enabled() -> bool {
    true
}

fn default_initial_sync_interval_secs() -> u64 {
    30
}

fn default_max_sync_interval_secs() -> u64 {
    3600
}

fn default_edge_write_enabled() -> bool {
    false
}

fn default_min_reputation_for_dht_write() -> i64 {
    30
}

fn default_min_reputation_for_dht_read() -> i64 {
    10
}

fn default_health_ttl_secs() -> u64 {
    60
}

fn default_load_ttl_secs() -> u64 {
    60
}

fn default_routing_full_network_view() -> bool {
    false
}

fn default_edge_can_respond_privileged() -> bool {
    false
}

fn default_dynamic_policy_enabled() -> bool {
    false
}

fn default_grace_period_secs() -> u64 {
    300
}

fn default_max_away_secs() -> u64 {
    3600
}

fn default_policy_proposal_delay_secs() -> u64 {
    30
}

fn default_max_reputation_threshold() -> i64 {
    80
}

fn default_manual_threshold_override() -> Option<i64> {
    None
}

fn default_dns_server_enabled() -> bool {
    true
}

fn default_dns_mesh_mode_only() -> bool {
    true
}

fn default_dht_write_enabled() -> bool {
    true
}

fn default_proxy_to_origins() -> bool {
    true
}

fn default_can_host_origins() -> bool {
    false
}

impl Default for MeshDhtConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 0,
            bootstrap_nodes: Vec::new(),
            write_quorum: 11,
            read_quorum: 11,
            query_timeout_secs: 10,
            bootstrap_timeout_secs: 30,
            consistency_level: crate::dht::DhtConsistencyLevel::Medium,
            edge_cache_enabled: true,
            edge_cache_max_entries: 1000,
            edge_cache_ttl_secs: 300,
            warm_up_on_connect: true,
            edge_write_enabled: false,
            min_reputation_for_dht_write: 30,
            min_reputation_for_dht_read: 10,
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
            routing_enabled: true,
            full_network_view: false,
            edge_can_respond_privileged: false,
            dynamic_policy_enabled: false,
            new_node_grace_period_secs: 300,
            max_away_before_reset_secs: 3600,
            policy_proposal_delay_secs: 30,
            max_reputation_threshold: 80,
            manual_threshold_override: None,
            geo_routing: Some(crate::dht::routing::GeoRoutingConfig::default()),
            regional_hubs: Some(crate::dht::routing::RegionalHubConfig::default()),
            dns_server_enabled: true,
            dns_mesh_mode_only: true,
            dht_write_enabled: true,
            proxy_to_origins: true,
            can_host_origins: false,
            announce_rate_limit_max_requests: 100,
            announce_rate_limit_window_secs: 60,
            require_signed_sync_requests: true,
            unsigned_sync_compat_until_unix: None,
            require_signed_anti_entropy_requests: true,
            unsigned_anti_entropy_compat_until_unix: None,
            require_signed_record_push: true,
            unsigned_record_push_compat_until_unix: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum MlKemVariant {
    #[serde(rename = "ml-kem-768")]
    #[default]
    MlKem768,
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
/// Post-quantum key exchange configuration for mesh TLS.
/// Enable via `post-quantum` feature flag to use ML-KEM-768 or ML-KEM-1024
/// hybrid key exchange instead of classical X25519.
pub struct MeshMlKemConfig {
    #[serde(default = "default_mlkem_enabled")]
    pub enabled: bool,
    #[serde(default = "default_mlkem_variant")]
    pub variant: MlKemVariant,
    #[serde(default = "default_mlkem_rotation_interval")]
    pub rotation_interval_secs: u64,
    #[serde(default = "default_mlkem_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_mlkem_max_sessions")]
    pub max_sessions: usize,
}

fn default_mlkem_enabled() -> bool {
    true
}

fn default_mlkem_variant() -> MlKemVariant {
    MlKemVariant::MlKem768
}

fn default_mlkem_rotation_interval() -> u64 {
    2700 // 45 minutes
}

fn default_mlkem_session_ttl() -> u64 {
    3600 // 1 hour
}

fn default_mlkem_max_sessions() -> usize {
    10000
}

impl Default for MeshMlKemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            variant: MlKemVariant::default(),
            rotation_interval_secs: 2700,
            session_ttl_secs: 3600,
            max_sessions: 10000,
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, JsonSchema, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct GenesisMintingProof {
    pub node_id: String,
    pub node_public_key: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl GenesisMintingProof {
    pub fn verify(&self, genesis_public_key: &[u8]) -> bool {
        let signable = format!(
            "{}:{}:{}",
            self.node_id,
            hex::encode(&self.node_public_key),
            self.timestamp
        );
        crate::cert::verify_ed25519(&signable, &self.signature, genesis_public_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct NodeIdentityConfig {
    #[serde(default)]
    pub private_key_path: Option<String>,
    #[serde(skip)]
    pub private_key: Option<Vec<u8>>,
    #[serde(skip)]
    pub public_key: Option<Vec<u8>>,
    #[serde(skip)]
    pub node_id: Option<String>,
    #[serde(skip)]
    pub router_id: Option<String>,
    #[serde(default)]
    pub encryption_passphrase_path: Option<String>,
    #[serde(default)]
    pub is_trusted: bool,
    #[serde(default)]
    pub genesis_org_id: Option<String>,
    #[serde(default)]
    pub genesis_key_base64: Option<String>,
    #[serde(default)]
    pub minting_proof: Option<GenesisMintingProof>,
}

fn derive_node_id_hash(private_key: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"public-key-from:");
    hasher.update(private_key);
    hasher.finalize().to_vec()
}

fn derive_node_id(private_key: &[u8]) -> String {
    let node_hash = derive_node_id_hash(private_key);
    format!("node-{}", &hex::encode(&node_hash[..8]))
}

pub fn derive_router_id(private_key: &[u8]) -> String {
    let node_hash = derive_node_id_hash(private_key);
    let mut hasher = Sha256::new();
    hasher.update(&node_hash);
    let hash = hasher.finalize();
    base32::encode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        &hash[..10],
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TierConfig {
    #[serde(default = "default_tier_names")]
    pub names: HashMap<u32, String>,
    #[serde(default)]
    pub min_tier_threshold: u32,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            names: default_tier_names(),
            min_tier_threshold: 0,
        }
    }
}

fn default_tier_names() -> HashMap<u32, String> {
    let mut m = HashMap::new();
    m.insert(0, "free".to_string());
    m.insert(1, "paid".to_string());
    m.insert(2, "premium".to_string());
    m.insert(3, "enterprise".to_string());
    m
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OrgConfig {
    #[serde(default = "default_true")]
    pub auto_approve: bool,
    #[serde(default)]
    pub bad_names: Vec<String>,
    #[serde(default)]
    pub default_tier_on_approve: u32,
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self {
            auto_approve: true,
            bad_names: Vec::new(),
            default_tier_on_approve: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpstreamResolutionConfig {
    #[serde(default)]
    pub use_first_segment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshPersistenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub peer_cache_path: Option<String>,
    #[serde(default = "default_persist_interval_secs")]
    pub persist_interval_secs: u64,
    #[serde(default = "default_policy_cache_size")]
    pub policy_cache_size: usize,
    #[serde(default)]
    pub neighborhood_persistence_enabled: bool,
    #[serde(default = "default_neighborhood_cache_size")]
    pub neighborhood_cache_size: usize,
    #[serde(default = "default_persist_max_age_secs")]
    pub persist_max_age_secs: u64,
}

fn default_policy_cache_size() -> usize {
    100000
}

fn default_persist_interval_secs() -> u64 {
    300
}

fn default_neighborhood_cache_size() -> usize {
    1000
}

fn default_persist_max_age_secs() -> u64 {
    604800
}

impl Default for MeshPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peer_cache_path: None,
            persist_interval_secs: 300,
            policy_cache_size: 100000,
            neighborhood_persistence_enabled: false,
            neighborhood_cache_size: 1000,
            persist_max_age_secs: 604800,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MeshTlsConfig {
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default = "default_auto_generate")]
    pub auto_generate_certs: bool,
    #[serde(default)]
    pub ca_mode: bool,
    #[serde(default)]
    pub cert_rotation_interval_secs: Option<u64>,
    #[serde(default = "default_auto_monitor_expiration")]
    pub auto_monitor_expiration: bool,
    #[serde(default)]
    pub crl_path: Option<String>,
    #[serde(default = "default_enforce_mutual_tls")]
    pub enforce_mutual_tls: bool,
    #[serde(default = "default_min_tls_version")]
    pub min_tls_version: String,
    #[serde(default)]
    pub certificate_pin_public_keys: Vec<String>,
    #[serde(default = "default_quic_enable_0rtt")]
    pub quic_enable_0rtt: bool,
    #[serde(default)]
    pub mode: Option<MeshTlsMode>,
    #[serde(default = "default_strict_certificate_validation")]
    pub strict_certificate_validation: bool,
    /// Require PKI binding for global node DHT messages (BindP fix).
    /// When true, DHT handlers verify source_node_id against cert chain.
    /// Default: false (backward compatible)
    #[serde(default)]
    pub require_pki_binding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeshTlsMode {
    #[default]
    Strict,
    Tofu,
    Permissive,
}

impl MeshTlsConfig {
    pub fn effective_mode(&self) -> MeshTlsMode {
        if let Some(mode) = self.mode {
            mode
        } else if self.strict_certificate_validation {
            MeshTlsMode::Strict
        } else {
            // Legacy fallback: strict=false historically allowed permissive mesh peers.
            MeshTlsMode::Permissive
        }
    }
}

fn default_auto_generate() -> bool {
    false
}

fn default_enforce_mutual_tls() -> bool {
    true
}

fn default_auto_monitor_expiration() -> bool {
    true
}

fn default_min_tls_version() -> String {
    "1.3".to_string()
}

fn default_quic_enable_0rtt() -> bool {
    // Disable 0-RTT by default due to replay attack concerns in RFC 9000.
    // 0-RTT data can be replayed by an attacker, so it should only be enabled
    // when the security implications are understood and the network path is trusted.
    false
}

fn default_strict_certificate_validation() -> bool {
    true
}

impl Default for MeshTlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            ca_path: None,
            auto_generate_certs: default_auto_generate(),
            ca_mode: false,
            cert_rotation_interval_secs: None,
            auto_monitor_expiration: default_auto_monitor_expiration(),
            crl_path: None,
            enforce_mutual_tls: default_enforce_mutual_tls(),
            min_tls_version: default_min_tls_version(),
            certificate_pin_public_keys: Vec::new(),
            quic_enable_0rtt: default_quic_enable_0rtt(),
            mode: None,
            strict_certificate_validation: default_strict_certificate_validation(),
            require_pki_binding: false,
        }
    }
}

#[path = "config_conversion.rs"]
mod config_conversion;
#[path = "config_defaults.rs"]
mod config_defaults;
#[path = "config_identity.rs"]
mod config_identity;
#[path = "config_mesh.rs"]
mod config_mesh;

pub use config_defaults::default_global_seeds;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derivation_is_deterministic() {
        let passphrase = "test_password_123";
        let salt = b"test_salt_value";
        let key1 = NodeIdentityConfig::derive_encryption_key(passphrase, salt);
        let key2 = NodeIdentityConfig::derive_encryption_key(passphrase, salt);
        assert_eq!(key1, key2, "Same passphrase should produce same key");
    }

    #[test]
    fn test_pbkdf2_different_passphrases_different_keys() {
        let salt = b"test_salt_value";
        let key1 = NodeIdentityConfig::derive_encryption_key("password1", salt);
        let key2 = NodeIdentityConfig::derive_encryption_key("password2", salt);
        assert_ne!(
            key1, key2,
            "Different passphrases should produce different keys"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = NodeIdentityConfig::default();
        let plaintext = b"this is a 32-byte secret key!!!!";
        let passphrase = "test_passphrase";

        let encrypted = config.encrypt_key(plaintext, Some(passphrase)).unwrap();
        assert_ne!(
            encrypted.as_slice(),
            plaintext,
            "Encrypted should differ from plaintext"
        );

        let decrypted = config.decrypt_key(&encrypted, Some(passphrase)).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            plaintext,
            "Decrypted should match original"
        );
    }

    #[test]
    fn test_encryption_produces_nonce() {
        let config = NodeIdentityConfig::default();
        let plaintext = b"test data for nonce check";
        let passphrase = "my_secure_pass";

        let encrypted1 = config.encrypt_key(plaintext, Some(passphrase)).unwrap();
        let encrypted2 = config.encrypt_key(plaintext, Some(passphrase)).unwrap();

        assert_ne!(encrypted1, encrypted2, "Same plaintext with same passphrase should produce different ciphertext due to random nonce");

        let nonce1 = &encrypted1[..12];
        let nonce2 = &encrypted2[..12];
        assert_ne!(nonce1, nonce2, "Nonces should be different");
    }

    #[test]
    fn test_mesh_tls_effective_mode_defaults_to_strict() {
        let tls = MeshTlsConfig::default();
        assert_eq!(tls.effective_mode(), MeshTlsMode::Strict);
    }

    #[test]
    fn test_mesh_tls_effective_mode_legacy_strict_false_maps_to_permissive() {
        let tls = MeshTlsConfig {
            mode: None,
            strict_certificate_validation: false,
            ..MeshTlsConfig::default()
        };
        assert_eq!(tls.effective_mode(), MeshTlsMode::Permissive);
    }

    #[test]
    fn test_mesh_tls_effective_mode_explicit_mode_overrides_legacy_flag() {
        let tls = MeshTlsConfig {
            mode: Some(MeshTlsMode::Tofu),
            strict_certificate_validation: true,
            ..MeshTlsConfig::default()
        };
        assert_eq!(tls.effective_mode(), MeshTlsMode::Tofu);
    }

    #[test]
    fn test_dht_sync_signing_defaults_to_required_with_no_compat_window() {
        let dht = MeshDhtConfig::default();
        assert!(dht.require_signed_sync_requests);
        assert!(dht.unsigned_sync_compat_until_unix.is_none());
        assert!(dht.require_signed_anti_entropy_requests);
        assert!(dht.unsigned_anti_entropy_compat_until_unix.is_none());
        assert!(dht.require_signed_record_push);
        assert!(dht.unsigned_record_push_compat_until_unix.is_none());
    }

    #[test]
    fn test_mesh_validate_rejects_unbounded_unsigned_sync_compat() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_sync_requests = false;
        dht.unsigned_sync_compat_until_unix = None;
        cfg.dht = Some(dht);

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("requires a bounded migration window"));
    }

    #[test]
    fn test_mesh_validate_rejects_expired_unsigned_sync_compat_window() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_sync_requests = false;
        dht.unsigned_sync_compat_until_unix =
            Some(synvoid_utils::safe_unix_timestamp().saturating_sub(1));
        cfg.dht = Some(dht);

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("compatibility window expired"));
    }

    #[test]
    fn test_mesh_validate_allows_future_bounded_unsigned_sync_compat_window() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_sync_requests = false;
        dht.unsigned_sync_compat_until_unix =
            Some(synvoid_utils::safe_unix_timestamp().saturating_add(3600));
        cfg.dht = Some(dht);

        cfg.validate().expect("validation should pass");
    }

    #[test]
    fn test_mesh_validate_rejects_unbounded_unsigned_anti_entropy_compat() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_anti_entropy_requests = false;
        dht.unsigned_anti_entropy_compat_until_unix = None;
        cfg.dht = Some(dht);

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("require_signed_anti_entropy_requests=false"));
    }

    #[test]
    fn test_mesh_validate_rejects_expired_unsigned_anti_entropy_compat_window() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_anti_entropy_requests = false;
        dht.unsigned_anti_entropy_compat_until_unix =
            Some(synvoid_utils::safe_unix_timestamp().saturating_sub(1));
        cfg.dht = Some(dht);

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("compatibility window expired"));
    }

    #[test]
    fn test_mesh_validate_allows_future_bounded_unsigned_anti_entropy_compat_window() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_anti_entropy_requests = false;
        dht.unsigned_anti_entropy_compat_until_unix =
            Some(synvoid_utils::safe_unix_timestamp().saturating_add(3600));
        cfg.dht = Some(dht);

        cfg.validate().expect("validation should pass");
    }

    #[test]
    fn test_mesh_validate_rejects_unbounded_unsigned_record_push_compat() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_record_push = false;
        dht.unsigned_record_push_compat_until_unix = None;
        cfg.dht = Some(dht);

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("require_signed_record_push=false"));
    }

    #[test]
    fn test_mesh_validate_rejects_expired_unsigned_record_push_compat_window() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_record_push = false;
        dht.unsigned_record_push_compat_until_unix =
            Some(synvoid_utils::safe_unix_timestamp().saturating_sub(1));
        cfg.dht = Some(dht);

        let err = cfg.validate().expect_err("validation should fail");
        assert!(err.contains("compatibility window expired"));
    }

    #[test]
    fn test_mesh_validate_allows_future_bounded_unsigned_record_push_compat_window() {
        let mut cfg = MeshConfig::default();
        let mut dht = MeshDhtConfig::default();
        dht.require_signed_record_push = false;
        dht.unsigned_record_push_compat_until_unix =
            Some(synvoid_utils::safe_unix_timestamp().saturating_add(3600));
        cfg.dht = Some(dht);

        cfg.validate().expect("validation should pass");
    }

    #[test]
    fn test_decrypt_with_wrong_passphrase_fails() {
        let config = NodeIdentityConfig::default();
        let plaintext = b"secret data";
        let passphrase = "correct_pass";

        let encrypted = config.encrypt_key(plaintext, Some(passphrase)).unwrap();
        let result = config.decrypt_key(&encrypted, Some("wrong_pass"));
        assert!(
            result.is_err(),
            "Decryption with wrong passphrase should fail"
        );
    }

    #[test]
    fn test_plaintext_no_encryption() {
        let config = NodeIdentityConfig::default();
        let plaintext = b"unencrypted_key_data";

        let encrypted = config.encrypt_key(plaintext, None).unwrap();
        assert_eq!(
            encrypted, plaintext,
            "No passphrase should mean no encryption"
        );

        let decrypted = config.decrypt_key(&encrypted, None).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "Decrypting unencrypted data should work"
        );
    }

    #[test]
    fn test_encrypted_key_format() {
        let config = NodeIdentityConfig::default();
        let plaintext = b"12345678901234567890123456789012"; // 32 bytes
        let passphrase = "test";

        let encrypted = config.encrypt_key(plaintext, Some(passphrase)).unwrap();

        // Should be: 12 byte nonce + 16 byte salt + 48 byte ciphertext (32 + 16 tag)
        assert_eq!(
            encrypted.len(),
            12 + 16 + 48,
            "Encrypted format should be nonce + salt + ciphertext + tag"
        );
    }

    #[test]
    fn test_short_ciphertext_fails() {
        let config = NodeIdentityConfig::default();
        let short_ciphertext = b"short";
        let result = config.decrypt_key(short_ciphertext, Some("pass"));
        assert!(result.is_err(), "Short ciphertext should fail decryption");
    }
}

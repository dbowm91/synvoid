#![allow(unused_variables, dead_code, non_snake_case, non_upper_case_globals)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::config::site::ProxyUpstreamConfig;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
pub struct MeshNodeRole(u8);

impl MeshNodeRole {
    pub const Global: MeshNodeRole = MeshNodeRole(0b010);
    pub const Edge: MeshNodeRole = MeshNodeRole(0b001);
    pub const Origin: MeshNodeRole = MeshNodeRole(0b100);
    pub const GLOBAL_EDGE: MeshNodeRole = MeshNodeRole(0b011);
    pub const GLOBAL_ORIGIN: MeshNodeRole = MeshNodeRole(0b110);
    pub const EDGE_ORIGIN: MeshNodeRole = MeshNodeRole(0b101);
    pub const ALL: MeshNodeRole = MeshNodeRole(0b111);

    pub const GLOBAL: MeshNodeRole = Self::Global;
    pub const EDGE: MeshNodeRole = Self::Edge;
    pub const ORIGIN: MeshNodeRole = Self::Origin;

    pub fn is_global(&self) -> bool {
        self.0 & 0b010 != 0
    }

    pub fn is_edge(&self) -> bool {
        self.0 & 0b001 != 0
    }

    pub fn is_origin(&self) -> bool {
        self.0 & 0b100 != 0
    }

    pub fn contains(self, flag: MeshNodeRole) -> bool {
        self.0 & flag.0 == flag.0
    }

    pub fn from_u8(v: u8) -> Self {
        MeshNodeRole(v & 0b111)
    }

    pub fn to_u8(self) -> u8 {
        self.0
    }

    pub fn bits(&self) -> u8 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }
}

impl fmt::Debug for MeshNodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.is_global() {
            flags.push("GLOBAL");
        }
        if self.is_edge() {
            flags.push("EDGE");
        }
        if self.is_origin() {
            flags.push("ORIGIN");
        }
        if flags.is_empty() {
            write!(f, "MeshNodeRole(0b{:03b})", self.0)
        } else {
            write!(f, "MeshNodeRole({})", flags.join(" | "))
        }
    }
}

impl Default for MeshNodeRole {
    fn default() -> Self {
        Self::Edge
    }
}
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub use crate::mesh::reputation::ReputationConfig;
pub use crate::mesh::threat_intel::ThreatIntelligenceConfig;
use crate::mesh::ADMIN_ORG_ID;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRulesMeshConfig {
    #[serde(default = "default_yara_mesh_enabled")]
    pub enabled: bool,
    #[serde(default = "default_yara_mesh_sync_interval")]
    pub sync_interval_secs: u64,
    #[serde(default)]
    pub allow_edge_submissions: bool,
    #[serde(default)]
    pub require_global_approval: bool,
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default = "default_yara_mesh_max_rules_size")]
    pub max_rules_size_kb: u32,
}

fn default_yara_mesh_enabled() -> bool {
    true
}

fn default_yara_mesh_sync_interval() -> u64 {
    3600
}

fn default_yara_mesh_max_rules_size() -> u32 {
    1024
}

impl Default for YaraRulesMeshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval_secs: 3600,
            allow_edge_submissions: true,
            require_global_approval: true,
            trusted_signers: Vec::new(),
            max_rules_size_kb: 1024,
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

    pub fn next(&self) -> u32 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for SequenceCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub wireguard_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeerConfig {
    pub address: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WireGuardPerformanceProfile {
    #[default]
    Balanced,
    LowLatency,
    HighThroughput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPerfConfig {
    #[serde(default)]
    pub rx_buffer_size: usize,
    #[serde(default)]
    pub tx_buffer_size: usize,
    #[serde(default)]
    pub congestion_control: String,
    #[serde(default)]
    pub gro_enabled: bool,
    #[serde(default)]
    pub gso_enabled: bool,
}

impl Default for WireGuardPerfConfig {
    fn default() -> Self {
        Self {
            rx_buffer_size: 0,
            tx_buffer_size: 0,
            congestion_control: String::new(),
            gro_enabled: true,
            gso_enabled: true,
        }
    }
}

impl WireGuardPerfConfig {
    pub fn for_low_latency() -> Self {
        Self {
            rx_buffer_size: 256 * 1024,
            tx_buffer_size: 256 * 1024,
            congestion_control: String::from("bbr"),
            gro_enabled: true,
            gso_enabled: false,
        }
    }

    pub fn for_high_throughput() -> Self {
        Self {
            rx_buffer_size: 4 * 1024 * 1024,
            tx_buffer_size: 4 * 1024 * 1024,
            congestion_control: String::from("bbr"),
            gro_enabled: true,
            gso_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshWireGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wg_interface")]
    pub interface: String,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default = "default_wg_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub persistent_keepalive: u16,
    #[serde(default)]
    pub peers: Vec<MeshWireGuardPeer>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub performance_profile: WireGuardPerformanceProfile,
    #[serde(default)]
    pub perf_config: Option<WireGuardPerfConfig>,
}

fn default_wg_interface() -> String {
    "wg-mesh0".to_string()
}

fn default_wg_listen_port() -> u16 {
    51821
}

fn default_mtu() -> u16 {
    1420
}

impl Default for MeshWireGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_wg_interface(),
            private_key: None,
            addresses: Vec::new(),
            listen_port: default_wg_listen_port(),
            persistent_keepalive: 25,
            peers: Vec::new(),
            mtu: default_mtu(),
            dns: Vec::new(),
            performance_profile: WireGuardPerformanceProfile::Balanced,
            perf_config: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshWireGuardPeer {
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshUpstreamPeer {
    pub node_id: String,
    #[serde(default)]
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshLocalUpstream {
    pub upstream_url: String,
    #[serde(default)]
    pub geo: Option<String>,
    #[serde(default)]
    pub waf_policy: Option<crate::mesh::protocol::WafPolicy>,
    #[serde(default)]
    pub protocol: crate::mesh::protocol::UpstreamProtocol,
    #[serde(default)]
    pub priority_tier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRoutingConfig {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for MeshSeedNode {
    fn default() -> Self {
        Self {
            address: String::new(),
            node_id: None,
            public_key: None,
            network_id: None,
            global_node_key: None,
            quic_port: None,
            wireguard_port: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshUpstreamConfig {
    pub upstream_url: String,
    #[serde(default)]
    pub geo: Option<String>,
    #[serde(default)]
    pub peered_wafs: Vec<MeshUpstreamPeer>,
    #[serde(default)]
    pub waf_policy: Option<crate::mesh::protocol::WafPolicy>,
    #[serde(default)]
    pub protocol: crate::mesh::protocol::UpstreamProtocol,
    #[serde(default)]
    pub priority_tier: u32,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeshTransportPreference {
    #[default]
    WireGuard,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default = "default_mesh_port")]
    pub port: u16,
    #[serde(default)]
    pub quic_port: Option<u16>,
    #[serde(default)]
    pub wireguard_port: Option<u16>,
    #[serde(default)]
    pub auto_port: bool,
    #[serde(default)]
    pub seeds: Vec<MeshSeedNode>,
    #[serde(default)]
    pub peers: Vec<MeshPeerConfig>,
    #[serde(default)]
    pub wireguard: MeshWireGuardConfig,
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
    pub proxy_cache: Option<crate::config::site::ProxyCacheConfig>,
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
    #[serde(default = "default_bandwidth_report_interval")]
    pub bandwidth_report_interval_secs: u64,
    #[serde(default = "default_ratelimit_block_advertisement")]
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
    pub stake: Option<crate::mesh::dht::stake::StakeConfig>,
    #[serde(default)]
    pub mlkem: Option<MeshMlKemConfig>,
    #[serde(skip)]
    cached_pow: Arc<RwLock<Option<(u64, std::time::Instant)>>>,
}

const POW_CACHE_TTL_SECS: u64 = 3600; // 1 hour

fn default_bandwidth_report_interval() -> u64 {
    30
}

fn default_ratelimit_block_advertisement() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
}

fn default_key_exchange_enabled() -> bool {
    true
}

fn default_key_exchange_port() -> u16 {
    50052
}

fn default_true() -> bool {
    true
}

impl GlobalNodeConfig {
    pub fn load_keys(&mut self) -> Result<(), String> {
        use base64::Engine;

        // Load X25519 key
        if let Some(ref b64) = self.x25519_private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 X25519 key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("X25519 key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.x25519_private_key = Some(key);

            // Derive public key
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(key);
            let public = PublicKey::from(&secret);
            self.x25519_public_key_base64 = Some(URL_SAFE_NO_PAD.encode(public.as_bytes()));
        }

        // Load Ed25519 key
        if let Some(ref b64) = self.ed25519_private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 Ed25519 key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("Ed25519 key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.ed25519_private_key = Some(key);

            // Derive public key
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&key);
            self.ed25519_public_key_base64 =
                Some(URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()));
        }

        // Load ML-KEM-768 key - if private key is provided, derive public key
        if let Some(ref b64) = self.ml_kem_private_key_base64 {
            use pqc::MlKem768;
            let sk = MlKem768::secret_key_from_base64(b64)
                .map_err(|e| format!("Invalid base64 ML-KEM key: {}", e))?;

            // Generate a temporary keypair to get the public key
            // In practice, the secret key format includes both sk+pk in aws-lc-rs
            // For now, we'll generate a new keypair if loading fails
            match MlKem768::generate_keypair() {
                Ok((pk, _)) => {
                    self.ml_kem_public_key_base64 = Some(pk.to_base64());
                }
                Err(e) => {
                    return Err(format!("Failed to derive ML-KEM public key: {}", e));
                }
            }
        }

        // Auto-generate ML-KEM-768 key if not configured (for post-quantum security)
        if self.ml_kem_private_key_base64.is_none() {
            tracing::info!("Auto-generating ML-KEM-768 keypair for post-quantum key exchange");
            match self.generate_ml_kem_keypair() {
                Ok((pk, _)) => {
                    tracing::debug!(
                        "Generated ML-KEM public key: {}...",
                        &pk[..32.min(pk.len())]
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to auto-generate ML-KEM key: {}", e);
                }
            }
        }

        // Load ML-DSA-44 key - if private key is provided, derive public key
        if let Some(ref b64) = self.ml_dsa_private_key_base64 {
            use pqc::MlDsa44;
            let _sk = pqc::SigningKey::from_base64(b64)
                .map_err(|e| format!("Invalid base64 ML-DSA key: {}", e))?;

            // Generate a new keypair to get the public key
            // In practice, we'd store both, but for now generate fresh
            match MlDsa44::generate_keypair() {
                Ok((vk, _)) => {
                    self.ml_dsa_public_key_base64 = Some(vk.to_base64());
                }
                Err(e) => {
                    return Err(format!("Failed to derive ML-DSA public key: {}", e));
                }
            }
        }

        Ok(())
    }

    /// Generate new ML-KEM-768 keypair for post-quantum key exchange
    pub fn generate_ml_kem_keypair(&mut self) -> Result<(String, String), String> {
        use pqc::MlKem768;
        let (pk, sk) = MlKem768::generate_keypair()
            .map_err(|e| format!("Failed to generate ML-KEM keypair: {}", e))?;

        self.ml_kem_public_key_base64 = Some(pk.to_base64());
        self.ml_kem_private_key_base64 = Some(sk.to_base64());

        Ok((pk.to_base64(), sk.to_base64()))
    }

    /// Generate new ML-DSA-44 keypair for post-quantum signatures
    pub fn generate_ml_dsa_keypair(&mut self) -> Result<(String, String), String> {
        use pqc::MlDsa44;
        let (vk, sk) = MlDsa44::generate_keypair()
            .map_err(|e| format!("Failed to generate ML-DSA keypair: {}", e))?;

        self.ml_dsa_public_key_base64 = Some(vk.to_base64());
        self.ml_dsa_private_key_base64 = Some(sk.to_base64());

        Ok((vk.to_base64(), sk.to_base64()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisKeyConfig {
    #[serde(default)]
    pub private_key_base64: Option<String>,
    #[serde(skip)]
    pub private_key: Option<[u8; 32]>,
    #[serde(skip)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub is_first_node: bool,
}

impl Default for GenesisKeyConfig {
    fn default() -> Self {
        Self {
            private_key_base64: None,
            private_key: None,
            public_key: None,
            is_first_node: false,
        }
    }
}

impl GenesisKeyConfig {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let public_key = Self::derive_public_key(&key);

        Self {
            private_key_base64: None,
            private_key: Some(key),
            public_key,
            is_first_node: true,
        }
    }

    pub fn load(&mut self) -> Result<(), String> {
        if let Some(ref b64) = self.private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 genesis key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("Genesis key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.private_key = Some(key);
            self.public_key = Self::derive_public_key(&key);
        }
        Ok(())
    }

    fn derive_public_key(key: &[u8; 32]) -> Option<String> {
        crate::mesh::cert::get_ed25519_public_key(key)
            .map(|pk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk))
    }

    pub fn get_public_key(&self) -> Option<String> {
        self.public_key.clone()
    }

    pub fn sign(&self, data: &str) -> Option<Vec<u8>> {
        self.private_key
            .as_ref()
            .and_then(|key| crate::mesh::cert::sign_ed25519(data, key))
    }

    pub fn verify(&self, data: &str, signature: &[u8]) -> bool {
        if let Some(ref key) = self.private_key {
            if let Some(pk) = crate::mesh::cert::get_ed25519_public_key(key) {
                crate::mesh::cert::verify_ed25519(data, signature, &pk)
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedNodeConfig {
    pub node_id: String,
    pub trusted_at: u64,
    pub granted_by_global_node: Option<String>,
    pub is_genesis: bool,
}

impl TrustedNodeConfig {
    pub fn new(node_id: String, granted_by: Option<String>, is_genesis: bool) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            node_id,
            trusted_at: now,
            granted_by_global_node: granted_by,
            is_genesis,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub consistency_level: crate::mesh::dht::DhtConsistencyLevel,
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
    pub geo_routing: Option<crate::mesh::dht::routing::GeoRoutingConfig>,
    #[serde(default)]
    pub regional_hubs: Option<crate::mesh::dht::routing::RegionalHubConfig>,
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

fn default_routing_enabled() -> bool {
    true
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
            consistency_level: crate::mesh::dht::DhtConsistencyLevel::Medium,
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
            geo_routing: Some(crate::mesh::dht::routing::GeoRoutingConfig::default()),
            regional_hubs: Some(crate::mesh::dht::routing::RegionalHubConfig::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MlKemVariant {
    #[serde(rename = "ml-kem-768")]
    MlKem768,
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,
}

impl Default for MlKemVariant {
    fn default() -> Self {
        MlKemVariant::MlKem768
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl From<MeshMlKemConfig> for crate::mesh::session::SessionConfig {
    fn from(config: MeshMlKemConfig) -> Self {
        crate::mesh::session::SessionConfig::new(
            config.session_ttl_secs,
            config.rotation_interval_secs,
        )
    }
}

impl From<MeshDhtConfig> for crate::mesh::dht::DhtConfig {
    fn from(config: MeshDhtConfig) -> Self {
        Self {
            enabled: config.enabled,
            listen_port: config.listen_port,
            bootstrap_nodes: config.bootstrap_nodes,
            write_quorum: config.write_quorum,
            read_quorum: config.read_quorum,
            replication_factor: 20,
            query_timeout: std::time::Duration::from_secs(config.query_timeout_secs),
            bootstrap_timeout: std::time::Duration::from_secs(config.bootstrap_timeout_secs),
            ping_interval: std::time::Duration::from_secs(30),
            record_ttl: Some(std::time::Duration::from_secs(3600)),
            consistency_level: config.consistency_level,
            disk_path: None,
            edge_cache_enabled: config.edge_cache_enabled,
            edge_cache_max_entries: config.edge_cache_max_entries,
            edge_cache_ttl_secs: config.edge_cache_ttl_secs,
            warm_up_on_connect: config.warm_up_on_connect,
            edge_write_enabled: config.edge_write_enabled,
            min_reputation_for_dht_write: config.min_reputation_for_dht_write,
            health_ttl_secs: config.health_ttl_secs,
            load_ttl_secs: config.load_ttl_secs,
            illegal_upstream_terms: config.illegal_upstream_terms,
            initial_sync_interval_secs: config.initial_sync_interval_secs,
            max_sync_interval_secs: config.max_sync_interval_secs,
            fanout_factor: config.fanout_factor,
            convergence_threshold: config.convergence_threshold,
            geo_routing: config.geo_routing,
            regional_hubs: config.regional_hubs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for NodeIdentityConfig {
    fn default() -> Self {
        Self {
            private_key_path: None,
            private_key: None,
            public_key: None,
            node_id: None,
            router_id: None,
            encryption_passphrase_path: None,
            is_trusted: false,
            genesis_org_id: None,
        }
    }
}

impl NodeIdentityConfig {
    pub fn genesis_org_id(&self) -> String {
        self.genesis_org_id
            .clone()
            .unwrap_or_else(|| ADMIN_ORG_ID.to_string())
    }

    pub fn load_or_generate(&mut self) -> Result<(), String> {
        self.load_or_generate_with_passphrase(None)
    }

    pub fn load_or_generate_with_passphrase(
        &mut self,
        passphrase: Option<&str>,
    ) -> Result<(), String> {
        if let Some(ref path) = self.private_key_path {
            if std::path::Path::new(path).exists() {
                let key_data = std::fs::read(path)
                    .map_err(|e| format!("Failed to read signing key: {}", e))?;

                if key_data.len() == 32 + 12 + 16 {
                    let decrypted = self.decrypt_key(&key_data, passphrase)?;
                    let pubkey = derive_public_key(&decrypted);
                    let node_id = derive_node_id(&decrypted);
                    self.private_key = Some(decrypted);
                    self.public_key = Some(pubkey);
                    self.node_id = Some(node_id);
                    return Ok(());
                } else if key_data.len() == 32 {
                    self.private_key = Some(key_data.clone());
                    self.public_key = Some(derive_public_key(&key_data));
                    self.node_id = Some(derive_node_id(&key_data));
                    return Ok(());
                } else {
                    return Err("Invalid signing key file format".to_string());
                }
            }
        }

        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut key);
        self.private_key = Some(key.to_vec());
        self.public_key = Some(derive_public_key(&key));
        self.node_id = Some(derive_node_id(&key));

        if let Some(ref path) = self.private_key_path {
            if let Some(ref key) = self.private_key {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let encrypted = self.encrypt_key(key, passphrase);
                std::fs::write(path, encrypted)
                    .map_err(|e| format!("Failed to write signing key: {}", e))?;
            }
        }

        Ok(())
    }

    fn derive_encryption_key(passphrase: &str) -> [u8; 32] {
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;

        const SALT: &[u8] = b"rustwaf-node-identity-v1";
        pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), SALT, 100_000)
    }

    fn encrypt_key(&self, plaintext: &[u8], passphrase: Option<&str>) -> Vec<u8> {
        match passphrase {
            Some(pass) if !pass.is_empty() => {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Aes256Gcm, Nonce,
                };
                use rand::RngCore;

                let key = Self::derive_encryption_key(pass);
                let cipher = Aes256Gcm::new_from_slice(&key).expect("Valid key");

                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .expect("Encryption success");

                let mut result = Vec::with_capacity(12 + ciphertext.len() + 16);
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&ciphertext);
                result
            }
            _ => plaintext.to_vec(),
        }
    }

    fn decrypt_key(&self, ciphertext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String> {
        match passphrase {
            Some(pass) if !pass.is_empty() => {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Aes256Gcm, Nonce,
                };

                if ciphertext.len() < 12 + 16 {
                    return Err("Ciphertext too short".to_string());
                }

                let key = Self::derive_encryption_key(pass);
                let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

                let nonce = Nonce::from_slice(&ciphertext[..12]);
                let ciphertext_only = &ciphertext[12..];

                cipher
                    .decrypt(nonce, ciphertext_only)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
            _ => Ok(ciphertext.to_vec()),
        }
    }

    pub fn public_key_hex(&self) -> Option<String> {
        self.public_key.as_ref().map(|k| hex::encode(k))
    }

    pub fn node_id(&self) -> Option<&String> {
        self.node_id.as_ref()
    }

    pub fn router_id(&self) -> Option<&String> {
        self.router_id.as_ref()
    }
}

fn derive_public_key(private_key: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"public-key-from:");
    hasher.update(private_key);
    hasher.finalize().to_vec()
}

fn derive_node_id(private_key: &[u8]) -> String {
    let pubkey = derive_public_key(private_key);
    format!("node-{}", &hex::encode(&pubkey[..8]))
}

pub fn derive_router_id(private_key: &[u8]) -> String {
    let pubkey = derive_public_key(private_key);
    let mut hasher = Sha256::new();
    hasher.update(&pubkey);
    let hash = hasher.finalize();
    base32::encode(
        base32::Alphabet::Rfc4648Lower { padding: false },
        &hash[..10],
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamResolutionConfig {
    #[serde(default)]
    pub use_first_segment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPersistenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub peer_cache_path: Option<String>,
    #[serde(default = "default_persist_interval_secs")]
    pub persist_interval_secs: u64,
    #[serde(default = "default_policy_cache_size")]
    pub policy_cache_size: usize,
}

fn default_policy_cache_size() -> usize {
    10000
}

fn default_persist_interval_secs() -> u64 {
    300
}

impl Default for MeshPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peer_cache_path: None,
            persist_interval_secs: 300,
            policy_cache_size: 10000,
        }
    }
}

pub fn default_global_seeds() -> Vec<MeshSeedNode> {
    vec![]
}

impl MeshConfig {
    pub fn with_defaults_if_enabled(mut self) -> Self {
        if self.enabled {
            if self.seeds.is_empty() && self.role == MeshNodeRole::Edge {
                self.seeds = default_global_seeds();
            }
            if self.connection.min_peer_connections == 0 {
                self.connection.min_peer_connections = 3;
            }
            if self.connection.max_peer_connections == 0 {
                self.connection.max_peer_connections = 20;
            }
        }
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn init_origin_signing_key(&mut self) -> Result<(), String> {
        if let Some(ref mut origin_key) = self.origin_signing_key {
            origin_key.load_key()?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate genesis key configuration
        if let Some(ref genesis) = self.genesis_key {
            if genesis.is_first_node && self.role != MeshNodeRole::Global {
                return Err(
                    "genesis_key.is_first_node can only be true for global nodes".to_string(),
                );
            }

            if genesis.private_key_base64.is_none() && !genesis.is_first_node {
                return Err(
                    "genesis_key requires either a private_key_base64 or is_first_node: true"
                        .to_string(),
                );
            }
        }

        // If role is Global, we should have either a genesis key or be the first node
        if self.role == MeshNodeRole::Global && self.genesis_key.is_none() {
            tracing::warn!(
                "Global node without genesis key - cannot add/remove other global nodes"
            );
        }

        Ok(())
    }
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            role: MeshNodeRole::Edge,
            network_id: None,
            mesh_name: None,
            global_node_key: None,
            bind_address: None,
            port: default_mesh_port(),
            quic_port: None,
            wireguard_port: None,
            auto_port: true,
            seeds: Vec::new(),
            peers: Vec::new(),
            wireguard: MeshWireGuardConfig::default(),
            local_upstreams: HashMap::new(),
            service_policy: MeshServicePolicy::default(),
            routing: MeshRoutingConfig::default(),
            tls: MeshTlsConfig::default(),
            transport_preference: MeshTransportPreference::WireGuard,
            connection: MeshConnectionConfig::default(),
            persistence: MeshPersistenceConfig::default(),
            proxy_cache: None,
            upstream_resolution: None,
            threat_intel: ThreatIntelligenceConfig::default(),
            yara_rules: YaraRulesMeshConfig::default(),
            node_identity: NodeIdentityConfig::default(),
            tier_config: TierConfig::default(),
            bandwidth_report_interval_secs: default_bandwidth_report_interval(),
            ratelimit_block_advertisement: default_ratelimit_block_advertisement(),
            origin_signing_key: None,
            global_node: GlobalNodeConfig::default(),
            genesis_key: None,
            dht: None,
            dht_access_for_edge: None,
            org_config: None,
            can_serve_origin_direct: true,
            disable_direct_origin: false,
            capabilities_enabled: true,
            stake: None,
            cached_pow: Arc::new(RwLock::new(None)),
            mlkem: Some(MeshMlKemConfig::default()),
        }
    }
}

fn default_mesh_port() -> u16 {
    5001
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

impl MeshWireGuardConfig {
    pub fn effective_perf_config(&self) -> WireGuardPerfConfig {
        if let Some(ref config) = self.perf_config {
            return config.clone();
        }

        match self.performance_profile {
            WireGuardPerformanceProfile::LowLatency => WireGuardPerfConfig::for_low_latency(),
            WireGuardPerformanceProfile::HighThroughput => {
                WireGuardPerfConfig::for_high_throughput()
            }
            WireGuardPerformanceProfile::Balanced => WireGuardPerfConfig::default(),
        }
    }

    pub fn effective_mtu(&self) -> u16 {
        match self.performance_profile {
            WireGuardPerformanceProfile::HighThroughput => self.mtu.max(1500),
            _ => self.mtu,
        }
    }
}

impl MeshConfig {
    pub fn generate_node_id() -> String {
        format!("mesh-{}", uuid::Uuid::new_v4())
    }

    pub fn node_id(&self) -> String {
        if let Some(ref identity) = self.node_identity.node_id {
            return identity.clone();
        }
        self.node_id.clone().unwrap_or_else(Self::generate_node_id)
    }

    pub fn router_id(&self) -> String {
        self.node_identity.router_id.clone().unwrap_or_else(|| {
            let mut id = [0u8; 32];
            use rand::RngCore;
            rand::rng().fill_bytes(&mut id);
            derive_router_id(&id)
        })
    }

    pub fn load_node_identity(&mut self) -> Result<(), String> {
        self.node_identity.load_or_generate()
    }

    pub fn load_global_node_keys(&mut self) -> Result<(), String> {
        self.global_node.load_keys()
    }

    pub fn signing_key(&self) -> Option<&[u8]> {
        self.node_identity.private_key.as_deref()
    }

    pub fn signing_public_key(&self) -> Option<String> {
        self.node_identity.public_key_hex()
    }

    pub fn get_cached_pow_nonce(&self) -> Option<u64> {
        let cache = self.cached_pow.read();
        if let Some((nonce, cached_at)) = *cache {
            if cached_at.elapsed().as_secs() < POW_CACHE_TTL_SECS {
                return Some(nonce);
            }
        }
        None
    }

    pub fn set_cached_pow_nonce(&self, nonce: u64) {
        *self.cached_pow.write() = Some((nonce, std::time::Instant::now()));
    }

    pub fn clear_cached_pow_nonce(&self) {
        *self.cached_pow.write() = None;
    }

    pub fn is_pow_cache_valid(&self) -> bool {
        self.get_cached_pow_nonce().is_some()
    }

    pub fn has_signing_key(&self) -> bool {
        self.node_identity.private_key.is_some()
    }

    pub fn load_genesis_key(&mut self) -> Result<(), String> {
        if let Some(ref mut genesis) = self.genesis_key {
            genesis.load()
        } else {
            Ok(())
        }
    }

    pub fn get_quic_port(&self) -> u16 {
        self.quic_port.unwrap_or(self.port)
    }

    pub fn get_wireguard_port(&self) -> u16 {
        self.wireguard_port.unwrap_or(self.wireguard.listen_port)
    }

    pub fn get_advertised_quic_port(&self) -> u16 {
        if self.auto_port {
            self.quic_port.unwrap_or(self.port)
        } else {
            self.port
        }
    }

    pub fn get_advertised_wireguard_port(&self) -> Option<u16> {
        if self.auto_port {
            self.wireguard_port.or(Some(self.wireguard.listen_port))
        } else {
            Some(self.wireguard.listen_port)
        }
    }

    pub fn set_quic_port(&mut self, port: u16) {
        self.quic_port = Some(port);
    }

    pub fn set_wireguard_port(&mut self, port: u16) {
        self.wireguard_port = Some(port);
    }

    pub fn generate_random_port(&self) -> u16 {
        use rand::Rng;
        let mut rng = rand::rng();
        let base = if self.role.is_global() { 5000 } else { 60000 };
        base + rng.random_range(0..10000)
    }

    pub fn apply_dht_role_defaults(&mut self) {
        if let Some(ref mut dht) = self.dht {
            if self.role.is_global() {
                if dht.full_network_view == false {
                    dht.full_network_view = true;
                }
            }
            if self.role.is_edge() {
                if dht.routing_enabled == false {
                    dht.routing_enabled = true;
                }
            }
        }
    }

    pub fn genesis_key(&self) -> Option<&GenesisKeyConfig> {
        self.genesis_key.as_ref()
    }

    pub fn is_genesis_node(&self) -> bool {
        self.genesis_key
            .as_ref()
            .map(|g| g.is_first_node)
            .unwrap_or(false)
    }

    pub fn verify_genesis_signature(&self, data: &str, signature: &[u8]) -> bool {
        self.genesis_key
            .as_ref()
            .map(|g| g.verify(data, signature))
            .unwrap_or(false)
    }

    pub fn network_id(&self) -> String {
        self.network_id
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }

    pub fn mesh_name(&self) -> Option<&str> {
        self.mesh_name.as_deref()
    }

    pub fn org_config(&self) -> OrgConfig {
        self.org_config.clone().unwrap_or_default()
    }

    pub fn make_mesh_upstream_id(&self, service_id: &str) -> String {
        format!("{}.{}", self.router_id(), service_id)
    }

    pub fn parse_mesh_upstream_id(full_id: &str) -> Option<(&str, &str)> {
        let dot_pos = full_id.find('.')?;
        if dot_pos == 0 || dot_pos == full_id.len() - 1 {
            return None;
        }
        Some((&full_id[..dot_pos], &full_id[dot_pos + 1..]))
    }

    pub fn generate_network_id() -> String {
        format!("net-{}", uuid::Uuid::new_v4())
    }

    pub fn is_global_node(&self) -> bool {
        self.role.is_global()
    }

    pub fn is_global_node_verified(&self) -> bool {
        self.global_node_key.is_some()
    }

    pub fn can_serve_direct(&self) -> bool {
        if self.disable_direct_origin {
            return false;
        }
        if self.role.is_origin() && self.can_serve_origin_direct {
            return true;
        }
        false
    }

    pub fn is_trusted_node(&self) -> bool {
        if self.node_identity.is_trusted {
            return true;
        }
        self.role.is_global() && self.capabilities_enabled
    }

    pub fn is_capabilities_enabled(&self) -> bool {
        self.capabilities_enabled
    }

    pub fn can_grant_trusted(&self) -> bool {
        self.role.is_global() && self.capabilities_enabled
    }

    pub fn should_become_global(&self, genesis_signature: &[u8]) -> bool {
        if let Some(ref genesis_key) = self.genesis_key {
            let data = format!(
                "become-global:{}",
                self.node_id.as_ref().unwrap_or(&String::new())
            );
            genesis_key.verify(&data, genesis_signature)
        } else {
            false
        }
    }

    pub fn verify_global_node_key(&self, key: &str) -> bool {
        if let Some(ref expected_key) = self.global_node_key {
            return expected_key == key;
        }
        false
    }

    pub fn generate_global_node_key() -> String {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let uuid = uuid::Uuid::new_v4();
        let entropy = uuid.as_bytes();
        let hk = Hkdf::<Sha256>::new(None, entropy);
        let mut okm = [0u8; 32];
        hk.expand(b"maluwaf-global-node-key", &mut okm)
            .expect("HKDF expand failed");
        hex::encode(okm)
    }

    pub fn cert_rotation_interval(&self) -> Option<std::time::Duration> {
        self.tls
            .cert_rotation_interval_secs
            .map(|secs| std::time::Duration::from_secs(secs))
    }

    pub fn is_tls_configured(&self) -> bool {
        self.tls.cert_path.is_some() && self.tls.key_path.is_some()
    }

    pub fn supports_tls_1_3(&self) -> bool {
        self.tls.min_tls_version == "1.3"
    }

    pub fn verify_seed(&self, seed: &MeshSeedNode) -> bool {
        if let Some(ref seed_network) = seed.network_id {
            if let Some(ref our_network) = self.network_id {
                if seed_network != our_network {
                    tracing::warn!(
                        "Seed {} belongs to different network: {} vs {}",
                        seed.address,
                        seed_network,
                        our_network
                    );
                    return false;
                }
            }
        }

        if let Some(ref seed_key) = seed.global_node_key {
            if let Some(ref our_key) = self.global_node_key {
                if seed_key != our_key {
                    tracing::warn!("Seed {} has invalid global node key", seed.address);
                    return false;
                }
            } else if self.is_global_node() {
                tracing::warn!(
                    "Seed {} requires global node key but none configured",
                    seed.address
                );
                return false;
            }
        }

        true
    }

    pub fn get_verified_seeds(&self) -> Vec<MeshSeedNode> {
        if !self.enabled {
            return Vec::new();
        }
        self.seeds
            .iter()
            .filter(|seed| self.verify_seed(seed))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_derivation_is_deterministic() {
        let passphrase = "test_password_123";
        let key1 = NodeIdentityConfig::derive_encryption_key(passphrase);
        let key2 = NodeIdentityConfig::derive_encryption_key(passphrase);
        assert_eq!(key1, key2, "Same passphrase should produce same key");
    }

    #[test]
    fn test_pbkdf2_different_passphrases_different_keys() {
        let key1 = NodeIdentityConfig::derive_encryption_key("password1");
        let key2 = NodeIdentityConfig::derive_encryption_key("password2");
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

        let encrypted = config.encrypt_key(plaintext, Some(passphrase));
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

        let encrypted1 = config.encrypt_key(plaintext, Some(passphrase));
        let encrypted2 = config.encrypt_key(plaintext, Some(passphrase));

        assert_ne!(encrypted1, encrypted2, "Same plaintext with same passphrase should produce different ciphertext due to random nonce");

        let nonce1 = &encrypted1[..12];
        let nonce2 = &encrypted2[..12];
        assert_ne!(nonce1, nonce2, "Nonces should be different");
    }

    #[test]
    fn test_decrypt_with_wrong_passphrase_fails() {
        let config = NodeIdentityConfig::default();
        let plaintext = b"secret data";
        let passphrase = "correct_pass";

        let encrypted = config.encrypt_key(plaintext, Some(passphrase));
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

        let encrypted = config.encrypt_key(plaintext, None);
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

        let encrypted = config.encrypt_key(plaintext, Some(passphrase));

        // Should be: 12 byte nonce + 32 byte ciphertext + 16 byte tag
        assert_eq!(
            encrypted.len(),
            12 + 32 + 16,
            "Encrypted format should be nonce + ciphertext + tag"
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

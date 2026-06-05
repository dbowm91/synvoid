use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use utoipa::ToSchema;

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
}

impl NodeIdentityConfig {
    pub fn public_key_hex(&self) -> Option<String> {
        self.public_key.as_ref().map(hex::encode)
    }

    pub fn load_or_generate(&mut self) -> Result<(), String> {
        // Placeholder implementation
        if self.private_key.is_none() {
            let mut key = [0u8; 32];
            use rand::RngCore;
            rand::rng().fill_bytes(&mut key);
            self.private_key = Some(key.to_vec());
            self.public_key = Some(derive_node_id_hash(&key));
            self.node_id = Some(derive_node_id(&key));
            self.router_id = Some(derive_router_id(&key));
        }
        Ok(())
    }

    pub fn derive_signing_key_from_genesis(
        &mut self,
        genesis_key: &[u8; 32],
        public_key: &[u8],
    ) -> Result<(), String> {
        use hkdf::Hkdf;

        const INFO: &[u8] = b"synvoid-global-node-signing-key";

        let hk = Hkdf::<Sha256>::new(Some(genesis_key), INFO);
        let mut okm = [0u8; 32];

        hk.expand(public_key, &mut okm)
            .map_err(|e| format!("HKDF expand failed: {}", e))?;

        self.private_key = Some(okm.to_vec());
        self.public_key = Some(derive_node_id_hash(&okm));
        self.node_id = Some(derive_node_id(&okm));
        self.router_id = Some(derive_router_id(&okm));

        Ok(())
    }
}

fn derive_node_id_hash(private_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct GlobalNodeConfig {
    #[serde(default)]
    pub known_origin_keys: HashMap<String, String>,
    #[serde(default)]
    pub known_edge_keys: HashMap<String, String>,
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
    pub invite_tokens: Vec<String>,
    #[serde(default)]
    pub key_exchange_enabled: bool,
    #[serde(default)]
    pub key_exchange_require_edge_auth: bool,
}

impl GlobalNodeConfig {
    pub fn is_invite_token_valid(&self, token: &str) -> bool {
        self.invite_tokens.iter().any(|t| t == token)
    }

    pub fn load_keys(&mut self) -> Result<(), String> {
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
        #[cfg(feature = "mesh")]
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
            #[cfg(feature = "mesh")]
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&key);
            self.ed25519_public_key_base64 =
                Some(URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()));
        }

        Ok(())
    }
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
    pub authorized_genesis_keys: Vec<String>,
}

impl GenesisKeyConfig {
    pub fn is_genesis_key_authorized(&self, genesis_public_key: &str) -> bool {
        if self.authorized_genesis_keys.is_empty() {
            return false;
        }
        self.authorized_genesis_keys
            .iter()
            .any(|k| k == genesis_public_key)
    }

    pub fn get_public_key(&self) -> Option<String> {
        self.public_key.clone()
    }
}

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
    JsonSchema,
    ToSchema,
)]
pub struct MeshNodeRole(u8);

impl MeshNodeRole {
    pub const GLOBAL: MeshNodeRole = MeshNodeRole(0b010);
    pub const EDGE: MeshNodeRole = MeshNodeRole(0b001);
    pub const ORIGIN: MeshNodeRole = MeshNodeRole(0b100);
    pub const GLOBAL_EDGE: MeshNodeRole = MeshNodeRole(0b011);
    pub const GLOBAL_ORIGIN: MeshNodeRole = MeshNodeRole(0b110);
    pub const EDGE_ORIGIN: MeshNodeRole = MeshNodeRole(0b101);
    pub const ALL: MeshNodeRole = MeshNodeRole(0b111);
    pub const SERVERLESS_ORIGIN: MeshNodeRole = MeshNodeRole(0b1000);

    pub fn is_global(&self) -> bool {
        self.0 & 0b010 != 0
    }

    pub fn is_edge(&self) -> bool {
        self.0 & 0b001 != 0
    }

    pub fn is_origin(&self) -> bool {
        self.0 & 0b100 != 0
    }

    pub fn is_serverless_origin(&self) -> bool {
        self.0 & 0b1000 != 0
    }

    pub fn contains(self, flag: MeshNodeRole) -> bool {
        self.0 & flag.0 == flag.0
    }

    pub fn from_u8(v: u8) -> Self {
        MeshNodeRole(v & 0b1111)
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

impl std::ops::BitOr for MeshNodeRole {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        MeshNodeRole(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for MeshNodeRole {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Default for MeshNodeRole {
    fn default() -> Self {
        Self::EDGE
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
        if self.is_serverless_origin() {
            flags.push("SERVERLESS_ORIGIN");
        }
        if flags.is_empty() {
            write!(f, "MeshNodeRole(0b{:04b})", self.0)
        } else {
            write!(f, "MeshNodeRole({})", flags.join(" | "))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshPeerConfig {
    pub address: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshUpstreamPeer {
    pub node_id: String,
    #[serde(default)]
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshLocalUpstream {
    pub upstream_url: String,
    #[serde(default)]
    pub geo: Option<String>,
    #[serde(default)]
    pub priority_tier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
pub struct MeshServicePolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshRoutingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_hops")]
    pub max_hops: u8,
    #[serde(default = "default_query_timeout_ms")]
    pub query_timeout_ms: u64,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u8,
    #[serde(default = "default_peer_query_count")]
    pub peer_query_count: usize,
    #[serde(default = "default_true")]
    pub allow_all_services: bool,
    #[serde(default)]
    pub allowed_services: Vec<String>,
    #[serde(default = "default_route_query_limit")]
    pub route_queries_per_minute: usize,
    #[serde(default = "default_mesh_messages_per_sec")]
    pub mesh_messages_per_sec: usize,
}

fn default_true() -> bool {
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
fn default_route_query_limit() -> usize {
    6000
}
fn default_mesh_messages_per_sec() -> usize {
    10000
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshTlsConfig {
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default)]
    pub auto_generate_certs: bool,
    #[serde(default)]
    pub ca_mode: bool,
    #[serde(default)]
    pub cert_rotation_interval_secs: Option<u64>,
    #[serde(default = "default_true")]
    pub auto_monitor_expiration: bool,
    #[serde(default)]
    pub crl_path: Option<String>,
    #[serde(default = "default_true")]
    pub enforce_mutual_tls: bool,
    #[serde(default = "default_tls_version")]
    pub min_tls_version: String,
    #[serde(default)]
    pub certificate_pin_public_keys: Vec<String>,
    #[serde(default)]
    pub quic_enable_0rtt: bool,
    #[serde(default = "default_true")]
    pub strict_certificate_validation: bool,
}

fn default_tls_version() -> String {
    "1.3".to_string()
}

impl Default for MeshTlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            ca_path: None,
            auto_generate_certs: false,
            ca_mode: false,
            cert_rotation_interval_secs: None,
            auto_monitor_expiration: true,
            crl_path: None,
            enforce_mutual_tls: true,
            min_tls_version: "1.3".to_string(),
            certificate_pin_public_keys: Vec::new(),
            quic_enable_0rtt: false,
            strict_certificate_validation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshUpstreamConfig {
    pub upstream_url: String,
    #[serde(default)]
    pub supported_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub geo: Option<String>,
    #[serde(default)]
    pub peered_wafs: Vec<MeshUpstreamPeer>,
    #[serde(default)]
    pub priority_tier: u32,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct MeshConnectionConfig {
    #[serde(default = "default_min_peers")]
    pub min_peer_connections: usize,
    #[serde(default = "default_max_peers")]
    pub max_peer_connections: usize,
    #[serde(default)]
    pub health_check_interval_secs: u64,
    #[serde(default = "default_announce_interval")]
    pub announce_interval_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,
}

fn default_min_peers() -> usize {
    3
}
fn default_max_peers() -> usize {
    20
}
fn default_announce_interval() -> u64 {
    30
}
fn default_keepalive_interval() -> u64 {
    10
}

impl Default for MeshConnectionConfig {
    fn default() -> Self {
        Self {
            min_peer_connections: 3,
            max_peer_connections: 20,
            health_check_interval_secs: 30,
            announce_interval_secs: 30,
            keepalive_interval_secs: 10,
        }
    }
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
    #[serde(default = "default_mesh_port")]
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
    pub connection: MeshConnectionConfig,
    #[serde(default = "default_bandwidth_report_interval")]
    pub bandwidth_report_interval_secs: u64,
    #[serde(default)]
    pub node_identity: NodeIdentityConfig,
    #[serde(default)]
    pub global_node: GlobalNodeConfig,
    #[serde(default)]
    pub genesis_key: Option<GenesisKeyConfig>,
    #[serde(default)]
    pub threat_intel: super::protection::ThreatIntelligenceConfig,
    #[serde(default)]
    pub yara_rules: super::protection::YaraRulesMeshConfig,
    #[serde(default)]
    pub origin_signing_key: Option<String>,
    #[serde(skip)]
    pub cached_pow: Arc<RwLock<Option<(u64, std::time::Instant)>>>,
}

fn default_mesh_port() -> u16 {
    50051
}
fn default_bandwidth_report_interval() -> u64 {
    60
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: None,
            role: MeshNodeRole::default(),
            network_id: None,
            mesh_name: None,
            global_node_key: None,
            bind_address: None,
            port: 50051,
            quic_port: None,
            auto_port: false,
            seeds: Vec::new(),
            peers: Vec::new(),
            local_upstreams: HashMap::new(),
            service_policy: MeshServicePolicy::default(),
            routing: MeshRoutingConfig::default(),
            tls: MeshTlsConfig::default(),
            connection: MeshConnectionConfig::default(),
            bandwidth_report_interval_secs: 60,
            node_identity: NodeIdentityConfig::default(),
            global_node: GlobalNodeConfig::default(),
            genesis_key: None,
            threat_intel: super::protection::ThreatIntelligenceConfig::default(),
            yara_rules: super::protection::YaraRulesMeshConfig::default(),
            origin_signing_key: None,
            cached_pow: Arc::new(RwLock::new(None)),
        }
    }
}

impl MeshConfig {
    pub fn node_id(&self) -> String {
        self.node_id
            .clone()
            .or_else(|| self.node_identity.node_id.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn router_id(&self) -> String {
        self.node_identity
            .router_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn signing_key(&self) -> Option<&[u8]> {
        self.node_identity.private_key.as_deref()
    }

    pub fn has_signing_key(&self) -> bool {
        self.node_identity.private_key.is_some()
    }

    pub fn signing_public_key(&self) -> Option<Vec<u8>> {
        self.node_identity.public_key.clone()
    }

    #[cfg(feature = "mesh")]
    pub fn load_node_identity(&mut self) -> Result<(), String> {
        if let Some(ref genesis_b64) = self.node_identity.genesis_key_base64 {
            tracing::warn!(
                "DEPRECATION: Using genesis_key_base64 for identity derivation is deprecated and will be removed in a future version. \
                 Please migrate to Decentralized Admission (JoinRequest)."
            );
            let genesis_bytes = URL_SAFE_NO_PAD
                .decode(genesis_b64)
                .map_err(|e| format!("Invalid genesis key base64: {}", e))?;

            if genesis_bytes.len() != 32 {
                return Err("Genesis key must be 32 bytes".to_string());
            }

            let mut genesis_key = [0u8; 32];
            genesis_key.copy_from_slice(&genesis_bytes);

            // In the real implementation, we derive the public key from the private key.
            // Since we don't have the full crypto logic here, we'll use a placeholder
            // or use ed25519-dalek to get the public key.
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&genesis_key);
            let public_key = signing_key.verifying_key().to_bytes();

            let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key);

            if let Some(genesis_config) = &self.genesis_key {
                if !genesis_config.is_genesis_key_authorized(&public_key_b64) {
                    return Err("Genesis key is not in the authorized list".to_string());
                }
            }

            self.node_identity
                .derive_signing_key_from_genesis(&genesis_key, &public_key)
        } else {
            self.node_identity.load_or_generate()
        }
    }

    pub fn load_global_node_keys(&mut self) -> Result<(), String> {
        self.global_node.load_keys()
    }
}

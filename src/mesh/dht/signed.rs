use std::time::Duration;

use base64::Engine;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::integrity::protocol::{Ed25519Signer, Ed25519Verifier};
use crate::mesh::protocol::MeshMessageSigner;

#[derive(Clone, Debug, Serialize)]
pub struct DhtRecordSignable<'a> {
    pub key: &'a str,
    pub value_hash: &'a [u8],
    pub source_node_id: &'a str,
    pub timestamp: u64,
    pub ttl_seconds: u64,
    pub sequence_number: u64,
    pub record_type: &'a str,
}

pub const DHT_MESSAGE_TIMESTAMP_WINDOW_SECS: i64 = 300;

pub const DHT_RECORD_TIMESTAMP_WINDOW_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSnapshotResponseSignable<'a> {
    pub request_id: &'a str,
    pub responder_node_id: &'a str,
    pub version: u64,
    pub record_count: usize,
    pub timestamp: u64,
    pub record_set_digest: &'a [u8],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSyncResponseSignable<'a> {
    pub request_id: &'a str,
    pub from_peer: &'a str,
    pub responder_node_id: &'a str,
    pub version: u64,
    pub record_count: usize,
    pub timestamp: u64,
    pub record_set_digest: &'a [u8],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtAntiEntropyRequestSignable<'a> {
    pub request_id: &'a str,
    pub node_id: &'a str,
    pub local_root_hash: &'a [u8],
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtAntiEntropyResponseSignable<'a> {
    pub request_id: &'a str,
    pub responder_node_id: &'a str,
    pub root_hash: &'a [u8],
    pub record_count: usize,
    pub timestamp: u64,
    pub record_set_digest: &'a [u8],
}

pub fn compute_record_set_digest(records: &[crate::mesh::protocol::DhtRecord]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for record in records {
        let signed = dht_record_to_signed_record(record);
        let signable_content = signed.get_signable_content();
        hasher.update(&signable_content);
    }
    hasher.finalize().to_vec()
}

pub fn get_snapshot_signable_content(
    request_id: &str,
    responder_node_id: &str,
    version: u64,
    record_count: usize,
    timestamp: u64,
    record_set_digest: &[u8],
) -> Vec<u8> {
    crate::serialization::serialize(&DhtSnapshotResponseSignable {
        request_id,
        responder_node_id,
        version,
        record_count,
        timestamp,
        record_set_digest,
    })
    .unwrap_or_default()
}

pub fn get_sync_signable_content(
    request_id: &str,
    from_peer: &str,
    responder_node_id: &str,
    version: u64,
    record_count: usize,
    timestamp: u64,
    record_set_digest: &[u8],
) -> Vec<u8> {
    crate::serialization::serialize(&DhtSyncResponseSignable {
        request_id,
        from_peer,
        responder_node_id,
        version,
        record_count,
        timestamp,
        record_set_digest,
    })
    .unwrap_or_default()
}

pub fn get_anti_entropy_request_signable_content(
    request_id: &str,
    node_id: &str,
    local_root_hash: &[u8],
    timestamp: u64,
) -> Vec<u8> {
    crate::serialization::serialize(&DhtAntiEntropyRequestSignable {
        request_id,
        node_id,
        local_root_hash,
        timestamp,
    })
    .unwrap_or_default()
}

pub fn get_anti_entropy_response_signable_content(
    request_id: &str,
    responder_node_id: &str,
    root_hash: &[u8],
    record_count: usize,
    timestamp: u64,
    record_set_digest: &[u8],
) -> Vec<u8> {
    crate::serialization::serialize(&DhtAntiEntropyResponseSignable {
        request_id,
        responder_node_id,
        root_hash,
        record_count,
        timestamp,
        record_set_digest,
    })
    .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SignedDhtRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub publisher_id: String,
    pub signature: Vec<u8>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub record_type: SignedRecordType,
    pub sequence_number: u64,
    pub source_node_id: String,
    pub ttl_seconds: u64,
    pub signer_public_key: Option<String>,
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
)]
pub enum SignedRecordType {
    Organization,
    OrgPublicKey,
    TierKey,
    MemberCertificate,
    Upstream,
    NodeInfo,
    GlobalNodeList,
    TierClaim,
    GlobalNodePublicKey,
    NodeHealth,
    NodeLoad,
    GlobalNodeHeartbeat,
    VerifiedUpstream,
    OrgNameReservation,
    DnsZone,
    DnsRecord,
    DnsDomainRegistration,
    GlobalAiBotList,
    AnycastNode,
    ThreatIndicator,
    UpstreamImageProtection,
    UpstreamMinification,
    UpstreamCompression,
    UpstreamProxyCachePreferences,
    SiteImagePoisonConfig,
    YaraRuleContent,
    YaraRulesManifest,
    GenesisKeyTransition,
    RevokedGlobalNode,
}

impl SignedRecordType {
    pub fn requires_global_node(&self) -> bool {
        matches!(
            self,
            SignedRecordType::Organization
                | SignedRecordType::OrgPublicKey
                | SignedRecordType::TierKey
                | SignedRecordType::MemberCertificate
                | SignedRecordType::GlobalNodeList
                | SignedRecordType::OrgNameReservation
                | SignedRecordType::DnsZone
                | SignedRecordType::DnsDomainRegistration
                | SignedRecordType::AnycastNode
        )
    }

    pub fn is_public(&self) -> bool {
        matches!(
            self,
            SignedRecordType::Upstream
                | SignedRecordType::NodeInfo
                | SignedRecordType::TierClaim
                | SignedRecordType::GlobalNodePublicKey
                | SignedRecordType::NodeHealth
                | SignedRecordType::NodeLoad
                | SignedRecordType::VerifiedUpstream
                | SignedRecordType::DnsZone
                | SignedRecordType::DnsRecord
                | SignedRecordType::GlobalAiBotList
                | SignedRecordType::AnycastNode
                | SignedRecordType::ThreatIndicator
                | SignedRecordType::UpstreamImageProtection
                | SignedRecordType::UpstreamMinification
                | SignedRecordType::UpstreamCompression
                | SignedRecordType::UpstreamProxyCachePreferences
                | SignedRecordType::SiteImagePoisonConfig
                | SignedRecordType::OrgPublicKey
        )
    }

    pub fn requires_confirmation(&self) -> bool {
        matches!(
            self,
            SignedRecordType::TierKey
                | SignedRecordType::Organization
                | SignedRecordType::OrgPublicKey
                | SignedRecordType::Upstream
                | SignedRecordType::OrgNameReservation
        )
    }

    pub fn default_ttl(&self) -> Option<Duration> {
        match self {
            SignedRecordType::Organization => Some(Duration::from_secs(86400 * 7)),
            SignedRecordType::OrgPublicKey => Some(Duration::from_secs(86400 * 30)),
            SignedRecordType::TierKey => Some(Duration::from_secs(86400 * 30)),
            SignedRecordType::MemberCertificate => Some(Duration::from_secs(86400 * 365)),
            SignedRecordType::Upstream => Some(Duration::from_secs(300)),
            SignedRecordType::NodeInfo => Some(Duration::from_secs(3600)),
            SignedRecordType::GlobalNodeList => Some(Duration::from_secs(3600)),
            SignedRecordType::TierClaim => Some(Duration::from_secs(86400)),
            SignedRecordType::GlobalNodePublicKey => Some(Duration::from_secs(86400)),
            SignedRecordType::NodeHealth => Some(Duration::from_secs(60)),
            SignedRecordType::NodeLoad => Some(Duration::from_secs(60)),
            SignedRecordType::GlobalNodeHeartbeat => Some(Duration::from_secs(90)),
            SignedRecordType::VerifiedUpstream => Some(Duration::from_secs(300)),
            SignedRecordType::OrgNameReservation => Some(Duration::from_secs(86400 * 7)),
            SignedRecordType::DnsZone => Some(Duration::from_secs(3600)),
            SignedRecordType::DnsRecord => Some(Duration::from_secs(300)),
            SignedRecordType::DnsDomainRegistration => Some(Duration::from_secs(600)),
            SignedRecordType::GlobalAiBotList => Some(Duration::from_secs(86400)),
            SignedRecordType::AnycastNode => Some(Duration::from_secs(600)),
            SignedRecordType::ThreatIndicator => Some(Duration::from_secs(3600)),
            SignedRecordType::UpstreamImageProtection => Some(Duration::from_secs(3600)),
            SignedRecordType::UpstreamMinification => Some(Duration::from_secs(3600)),
            SignedRecordType::UpstreamCompression => Some(Duration::from_secs(3600)),
            SignedRecordType::UpstreamProxyCachePreferences => Some(Duration::from_secs(3600)),
            SignedRecordType::SiteImagePoisonConfig => Some(Duration::from_secs(3600)),
            SignedRecordType::YaraRuleContent => Some(Duration::from_secs(3600)),
            SignedRecordType::YaraRulesManifest => Some(Duration::from_secs(3600)),
            SignedRecordType::GenesisKeyTransition => Some(Duration::from_secs(86400)),
            SignedRecordType::RevokedGlobalNode => Some(Duration::from_secs(86400 * 7)),
        }
    }

    pub fn requires_announce_refresh(&self) -> bool {
        matches!(
            self,
            SignedRecordType::Upstream | SignedRecordType::YaraRuleContent
        )
    }

    /// Returns true if this record type requires an origin node to announce it.
    /// Origin-node specific records are those that relate to site-specific configuration
    /// and should only be announced by nodes serving as origins for particular sites.
    pub fn requires_origin_node(&self) -> bool {
        matches!(
            self,
            SignedRecordType::Upstream
                | SignedRecordType::DnsZone
                | SignedRecordType::DnsRecord
                | SignedRecordType::VerifiedUpstream
        )
    }

    pub fn is_immutable(&self) -> bool {
        matches!(
            self,
            SignedRecordType::GenesisKeyTransition
                | SignedRecordType::RevokedGlobalNode
                | SignedRecordType::YaraRulesManifest
                | SignedRecordType::YaraRuleContent
        )
    }

    pub fn allows_older_version_replacement(&self) -> bool {
        matches!(
            self,
            SignedRecordType::NodeInfo
                | SignedRecordType::NodeHealth
                | SignedRecordType::NodeLoad
                | SignedRecordType::GlobalNodeHeartbeat
                | SignedRecordType::Upstream
                | SignedRecordType::ThreatIndicator
        )
    }
}

impl SignedDhtRecord {
    pub fn new(
        key: String,
        value: Vec<u8>,
        publisher_id: String,
        record_type: SignedRecordType,
    ) -> Self {
        let now = crate::mesh::safe_unix_timestamp();

        let default_ttl = record_type.default_ttl();
        let ttl_seconds = default_ttl.map(|ttl| ttl.as_secs()).unwrap_or(3600);
        let expires_at = default_ttl.map(|ttl| now + ttl.as_secs());
        let source_node_id = publisher_id.clone();

        Self {
            key,
            value,
            publisher_id,
            signature: Vec::new(),
            created_at: now,
            expires_at,
            record_type,
            sequence_number: 1,
            source_node_id,
            ttl_seconds,
            signer_public_key: None,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        let now = crate::mesh::safe_unix_timestamp();
        self.ttl_seconds = ttl.as_secs();
        self.expires_at = Some(now + ttl.as_secs());
        self
    }

    pub fn with_source_node_id(mut self, node_id: String) -> Self {
        self.source_node_id = node_id;
        self
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    pub fn with_signer_public_key(mut self, public_key: String) -> Self {
        self.signer_public_key = Some(public_key);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = crate::mesh::safe_unix_timestamp();
            now > expires_at
        } else {
            false
        }
    }

    pub fn time_until_expiry(&self) -> Option<Duration> {
        if let Some(expires_at) = self.expires_at {
            let now = crate::mesh::safe_unix_timestamp();
            if expires_at > now {
                Some(Duration::from_secs(expires_at - now))
            } else {
                Some(Duration::ZERO)
            }
        } else {
            None
        }
    }

    pub fn needs_refresh(&self) -> bool {
        if let Some(ttl) = self.record_type.default_ttl() {
            if let Some(remaining) = self.time_until_expiry() {
                return remaining < ttl / 2;
            }
        }
        true
    }

    pub fn requires_global_node(&self) -> bool {
        self.record_type.requires_global_node()
    }

    pub fn requires_signature(&self) -> bool {
        self.record_type.requires_global_node()
            || self.record_type.is_public()
            || self.record_type.requires_confirmation()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self).map(|b| b.into_vec())
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(data)
    }

    pub fn serialize_value<T: Serialize>(value: &T) -> Vec<u8> {
        crate::serialization::serialize(value).unwrap_or_default()
    }

    pub fn serialize_postcard(&self) -> Vec<u8> {
        crate::serialization::serialize(self).unwrap_or_default()
    }

    pub fn deserialize_postcard(data: &[u8]) -> Option<Self> {
        crate::serialization::deserialize(data).ok()
    }

    pub fn get_signable_content(&self) -> Vec<u8> {
        let value_hash = Sha256::digest(&self.value);

        let record_type_str = match &self.record_type {
            SignedRecordType::Organization => "Organization",
            SignedRecordType::OrgPublicKey => "OrgPublicKey",
            SignedRecordType::TierKey => "TierKey",
            SignedRecordType::MemberCertificate => "MemberCertificate",
            SignedRecordType::Upstream => "Upstream",
            SignedRecordType::NodeInfo => "NodeInfo",
            SignedRecordType::GlobalNodeList => "GlobalNodeList",
            SignedRecordType::TierClaim => "TierClaim",
            SignedRecordType::GlobalNodePublicKey => "GlobalNodePublicKey",
            SignedRecordType::NodeHealth => "NodeHealth",
            SignedRecordType::NodeLoad => "NodeLoad",
            SignedRecordType::GlobalNodeHeartbeat => "GlobalNodeHeartbeat",
            SignedRecordType::VerifiedUpstream => "VerifiedUpstream",
            SignedRecordType::OrgNameReservation => "OrgNameReservation",
            SignedRecordType::DnsZone => "DnsZone",
            SignedRecordType::DnsRecord => "DnsRecord",
            SignedRecordType::DnsDomainRegistration => "DnsDomainRegistration",
            SignedRecordType::GlobalAiBotList => "GlobalAiBotList",
            SignedRecordType::AnycastNode => "AnycastNode",
            SignedRecordType::ThreatIndicator => "ThreatIndicator",
            SignedRecordType::UpstreamImageProtection => "UpstreamImageProtection",
            SignedRecordType::UpstreamMinification => "UpstreamMinification",
            SignedRecordType::UpstreamCompression => "UpstreamCompression",
            SignedRecordType::UpstreamProxyCachePreferences => "UpstreamProxyCachePreferences",
            SignedRecordType::SiteImagePoisonConfig => "SiteImagePoisonConfig",
            SignedRecordType::YaraRuleContent => "YaraRuleContent",
            SignedRecordType::YaraRulesManifest => "YaraRulesManifest",
            SignedRecordType::GenesisKeyTransition => "GenesisKeyTransition",
            SignedRecordType::RevokedGlobalNode => "RevokedGlobalNode",
        };

        let content = DhtRecordSignable {
            key: &self.key,
            value_hash: &value_hash,
            source_node_id: &self.source_node_id,
            timestamp: self.created_at,
            ttl_seconds: self.ttl_seconds,
            sequence_number: self.sequence_number,
            record_type: record_type_str,
        };

        crate::serialization::serialize(&content).unwrap_or_default()
    }
}

pub fn dht_record_to_signed_record(record: &crate::mesh::protocol::DhtRecord) -> SignedDhtRecord {
    let dht_key = crate::mesh::dht::keys::DhtKey::from_str(&record.key);
    let record_type = dht_key
        .to_signed_record_type()
        .unwrap_or(SignedRecordType::NodeInfo);

    let expires_at = record.timestamp.saturating_add(record.ttl_seconds);

    SignedDhtRecord {
        key: record.key.clone(),
        value: record.value.clone(),
        publisher_id: record.source_node_id.clone(),
        signature: record.signature.clone(),
        created_at: record.timestamp,
        expires_at: Some(expires_at),
        record_type,
        sequence_number: record.sequence_number,
        source_node_id: record.source_node_id.clone(),
        ttl_seconds: record.ttl_seconds,
        signer_public_key: record.signer_public_key.clone(),
    }
}

pub fn verify_dht_record_signature(record: &crate::mesh::protocol::DhtRecord) -> bool {
    if record.signature.is_empty() {
        tracing::warn!("Empty signature on record {}", record.key);
        return false;
    }

    let signer_public_key = match &record.signer_public_key {
        Some(pk) if !pk.is_empty() => pk.clone(),
        _ => {
            tracing::warn!(
                "No signer public key on record {} - cannot verify",
                record.key
            );
            return false;
        }
    };

    let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signer_public_key) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let signed_record = dht_record_to_signed_record(record);
    let content = signed_record.get_signable_content();

    // Hybrid auto-detection
    let default_signer = MeshMessageSigner::new([0u8; 32]);
    default_signer.verify_auto(&content, &record.signature, &pk_bytes)
}

pub fn verify_dht_record_signature_for_key(
    record: &crate::mesh::protocol::DhtRecord,
    expected_record_type: SignedRecordType,
) -> bool {
    if record.signature.is_empty() {
        tracing::warn!("Empty signature on record {}", record.key);
        return false;
    }

    let signer_public_key = match &record.signer_public_key {
        Some(pk) if !pk.is_empty() => pk.clone(),
        _ => {
            tracing::warn!(
                "No signer public key on record {} - cannot verify",
                record.key
            );
            return false;
        }
    };

    let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signer_public_key) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let expires_at = record.timestamp.saturating_add(record.ttl_seconds);

    let signed_record = SignedDhtRecord {
        key: record.key.clone(),
        value: record.value.clone(),
        publisher_id: record.source_node_id.clone(),
        signature: record.signature.clone(),
        created_at: record.timestamp,
        expires_at: Some(expires_at),
        record_type: expected_record_type,
        sequence_number: record.sequence_number,
        source_node_id: record.source_node_id.clone(),
        ttl_seconds: record.ttl_seconds,
        signer_public_key: record.signer_public_key.clone(),
    };

    let content = signed_record.get_signable_content();
    let default_signer = MeshMessageSigner::new([0u8; 32]);
    default_signer.verify_auto(&content, &record.signature, &pk_bytes)
}

#[derive(Clone)]
pub struct RecordSigner {
    mesh_signer: Option<MeshMessageSigner>,
}

impl RecordSigner {
    pub fn new(mesh_signer: Option<MeshMessageSigner>) -> Self {
        Self { mesh_signer }
    }

    pub fn sign(&self, record: &SignedDhtRecord) -> Option<Vec<u8>> {
        let signer = self.mesh_signer.as_ref()?;
        let content = record.get_signable_content();

        if signer.has_ml_dsa() {
            Some(signer.sign_hybrid(&content).to_bytes())
        } else {
            Some(signer.sign(&content))
        }
    }

    pub fn verify(&self, record: &SignedDhtRecord) -> bool {
        if record.signature.is_empty() {
            tracing::warn!("Empty signature on record {}", record.key);
            return false;
        }

        let Some(ref public_key_b64) = record.signer_public_key else {
            tracing::warn!("No public key on record {} - cannot verify", record.key);
            return false;
        };

        let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(public_key_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let content = record.get_signable_content();

        if let Some(ref signer) = self.mesh_signer {
            signer.verify_auto(&content, &record.signature, &pk_bytes)
        } else {
            let default_signer = MeshMessageSigner::new([0u8; 32]);
            default_signer.verify_auto(&content, &record.signature, &pk_bytes)
        }
    }

    pub fn get_verifying_key(&self) -> Option<String> {
        self.mesh_signer.as_ref().map(|s| s.get_public_key())
    }
}

pub fn validate_message_timestamp(timestamp: u64) -> bool {
    let now = crate::mesh::safe_unix_timestamp() as i64;

    let msg_time = timestamp as i64;
    let diff = (now - msg_time).abs();

    diff <= DHT_MESSAGE_TIMESTAMP_WINDOW_SECS
}

pub fn validate_record_timestamp(timestamp: u64) -> bool {
    let now = crate::mesh::safe_unix_timestamp() as i64;

    let msg_time = timestamp as i64;
    let diff = (now - msg_time).abs();

    diff <= DHT_RECORD_TIMESTAMP_WINDOW_SECS
}

pub struct TtlManager {
    org_ttl: Duration,
    tier_key_ttl: Duration,
    member_cert_ttl: Duration,
    upstream_ttl: Duration,
    node_info_ttl: Duration,
    global_node_list_ttl: Duration,
    tier_claim_ttl: Duration,
    global_node_public_key_ttl: Duration,
    node_health_ttl: Duration,
    node_load_ttl: Duration,
    global_node_heartbeat_ttl: Duration,
    verified_upstream_ttl: Duration,
    org_name_reservation_ttl: Duration,
    upstream_image_protection_ttl: Duration,
    upstream_minification_ttl: Duration,
    upstream_compression_ttl: Duration,
    upstream_proxy_cache_preferences_ttl: Duration,
    site_image_poison_config_ttl: Duration,
    yara_rule_content_ttl: Duration,
    yara_rules_manifest_ttl: Duration,
    genesis_key_transition_ttl: Duration,
    revoked_global_node_ttl: Duration,
}

impl Default for TtlManager {
    fn default() -> Self {
        Self {
            org_ttl: Duration::from_secs(86400 * 7),
            tier_key_ttl: Duration::from_secs(86400 * 30),
            member_cert_ttl: Duration::from_secs(86400 * 365),
            upstream_ttl: Duration::from_secs(300),
            node_info_ttl: Duration::from_secs(3600),
            global_node_list_ttl: Duration::from_secs(3600),
            tier_claim_ttl: Duration::from_secs(86400),
            global_node_public_key_ttl: Duration::from_secs(86400),
            node_health_ttl: Duration::from_secs(60),
            node_load_ttl: Duration::from_secs(60),
            global_node_heartbeat_ttl: Duration::from_secs(90),
            verified_upstream_ttl: Duration::from_secs(300),
            org_name_reservation_ttl: Duration::from_secs(86400 * 7),
            upstream_image_protection_ttl: Duration::from_secs(3600),
            upstream_minification_ttl: Duration::from_secs(3600),
            upstream_compression_ttl: Duration::from_secs(3600),
            upstream_proxy_cache_preferences_ttl: Duration::from_secs(3600),
            site_image_poison_config_ttl: Duration::from_secs(3600),
            yara_rule_content_ttl: Duration::from_secs(3600),
            yara_rules_manifest_ttl: Duration::from_secs(3600),
            genesis_key_transition_ttl: Duration::from_secs(86400),
            revoked_global_node_ttl: Duration::from_secs(86400 * 7),
        }
    }
}

impl TtlManager {
    pub fn with_org_ttl(mut self, ttl: Duration) -> Self {
        self.org_ttl = ttl;
        self
    }

    pub fn with_tier_key_ttl(mut self, ttl: Duration) -> Self {
        self.tier_key_ttl = ttl;
        self
    }

    pub fn with_upstream_ttl(mut self, ttl: Duration) -> Self {
        self.upstream_ttl = ttl;
        self
    }

    pub fn ttl_for(&self, record_type: SignedRecordType) -> Duration {
        match record_type {
            SignedRecordType::Organization => self.org_ttl,
            SignedRecordType::OrgPublicKey => self.org_ttl,
            SignedRecordType::TierKey => self.tier_key_ttl,
            SignedRecordType::MemberCertificate => self.member_cert_ttl,
            SignedRecordType::Upstream => self.upstream_ttl,
            SignedRecordType::NodeInfo => self.node_info_ttl,
            SignedRecordType::GlobalNodeList => self.global_node_list_ttl,
            SignedRecordType::TierClaim => self.tier_claim_ttl,
            SignedRecordType::GlobalNodePublicKey => self.global_node_public_key_ttl,
            SignedRecordType::NodeHealth => self.node_health_ttl,
            SignedRecordType::NodeLoad => self.node_load_ttl,
            SignedRecordType::GlobalNodeHeartbeat => self.global_node_heartbeat_ttl,
            SignedRecordType::VerifiedUpstream => self.verified_upstream_ttl,
            SignedRecordType::OrgNameReservation => self.org_name_reservation_ttl,
            SignedRecordType::DnsZone => self.node_info_ttl,
            SignedRecordType::DnsRecord => self.upstream_ttl,
            SignedRecordType::DnsDomainRegistration => Duration::from_secs(600),
            SignedRecordType::GlobalAiBotList => Duration::from_secs(86400),
            SignedRecordType::AnycastNode => self.node_info_ttl,
            SignedRecordType::ThreatIndicator => self.node_info_ttl,
            SignedRecordType::UpstreamImageProtection => self.upstream_image_protection_ttl,
            SignedRecordType::UpstreamMinification => self.upstream_minification_ttl,
            SignedRecordType::UpstreamCompression => self.upstream_compression_ttl,
            SignedRecordType::UpstreamProxyCachePreferences => {
                self.upstream_proxy_cache_preferences_ttl
            }
            SignedRecordType::SiteImagePoisonConfig => self.site_image_poison_config_ttl,
            SignedRecordType::YaraRuleContent => self.yara_rule_content_ttl,
            SignedRecordType::YaraRulesManifest => self.yara_rules_manifest_ttl,
            SignedRecordType::GenesisKeyTransition => self.genesis_key_transition_ttl,
            SignedRecordType::RevokedGlobalNode => self.revoked_global_node_ttl,
        }
    }

    pub fn expires_at_for(&self, record_type: SignedRecordType) -> u64 {
        let now = crate::mesh::safe_unix_timestamp();
        now + self.ttl_for(record_type).as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_record_creation() {
        let record = SignedDhtRecord::new(
            "org:test".to_string(),
            b"test_value".to_vec(),
            "publisher_1".to_string(),
            SignedRecordType::Organization,
        );

        assert!(record.signature.is_empty());
        assert!(!record.is_expired());
    }

    #[test]
    fn test_upstream_needs_refresh() {
        let mut record = SignedDhtRecord::new(
            "upstream:test".to_string(),
            b"test_value".to_vec(),
            "publisher_1".to_string(),
            SignedRecordType::Upstream,
        );

        assert!(!record.needs_refresh());

        record.created_at = crate::mesh::safe_unix_timestamp() - 100;

        assert!(!record.needs_refresh());
    }

    #[test]
    fn test_privileged_record_types() {
        assert!(SignedRecordType::Organization.requires_global_node());
        assert!(SignedRecordType::TierKey.requires_global_node());
        assert!(!SignedRecordType::Upstream.requires_global_node());
    }

    #[test]
    fn test_canonical_signature_rejects_tampered_value() {
        let secret = [
            0x9c, 0xef, 0x61, 0x2a, 0xf2, 0x74, 0x23, 0x32, 0x1e, 0x3e, 0x8e, 0x1a, 0x7a, 0x06,
            0x51, 0x4f, 0x4c, 0x3a, 0x38, 0xc4, 0x8c, 0x4f, 0x8c, 0x18, 0x7a, 0x16, 0x32, 0x7d,
            0x5e, 0x41, 0x6e, 0x67,
        ];
        let signer = MeshMessageSigner::new(secret);
        let verifying_key_b64 = signer.get_public_key();

        let mut record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"original_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(verifying_key_b64.clone()),
            content_hash: Vec::new(),
        };

        let signed = dht_record_to_signed_record(&record);
        let record_signer = RecordSigner::new(Some(signer));
        let sig = record_signer.sign(&signed).unwrap();
        record.signature = sig;

        let verified = verify_dht_record_signature(&record);
        assert!(verified, "Original record should verify");

        record.value = b"tampered_value".to_vec();
        let verified_after_tamper = verify_dht_record_signature(&record);
        assert!(
            !verified_after_tamper,
            "Tampered value should fail verification"
        );
    }

    #[test]
    fn test_canonical_signature_rejects_tampered_ttl() {
        let secret = [
            0x9c, 0xef, 0x61, 0x2a, 0xf2, 0x74, 0x23, 0x32, 0x1e, 0x3e, 0x8e, 0x1a, 0x7a, 0x06,
            0x51, 0x4f, 0x4c, 0x3a, 0x38, 0xc4, 0x8c, 0x4f, 0x8c, 0x18, 0x7a, 0x16, 0x32, 0x7d,
            0x5e, 0x41, 0x6e, 0x67,
        ];
        let signer = MeshMessageSigner::new(secret);
        let verifying_key_b64 = signer.get_public_key();

        let mut record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(verifying_key_b64.clone()),
            content_hash: Vec::new(),
        };

        let signed = dht_record_to_signed_record(&record);
        let record_signer = RecordSigner::new(Some(signer));
        let sig = record_signer.sign(&signed).unwrap();
        record.signature = sig;

        let verified = verify_dht_record_signature(&record);
        assert!(verified, "Original record should verify");

        record.ttl_seconds = 600;
        let verified_after_tamper = verify_dht_record_signature(&record);
        assert!(
            !verified_after_tamper,
            "Tampered TTL should fail verification"
        );
    }

    #[test]
    fn test_canonical_signature_rejects_tampered_sequence() {
        let secret = [
            0x9c, 0xef, 0x61, 0x2a, 0xf2, 0x74, 0x23, 0x32, 0x1e, 0x3e, 0x8e, 0x1a, 0x7a, 0x06,
            0x51, 0x4f, 0x4c, 0x3a, 0x38, 0xc4, 0x8c, 0x4f, 0x8c, 0x18, 0x7a, 0x16, 0x32, 0x7d,
            0x5e, 0x41, 0x6e, 0x67,
        ];
        let signer = MeshMessageSigner::new(secret);
        let verifying_key_b64 = signer.get_public_key();

        let mut record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(verifying_key_b64.clone()),
            content_hash: Vec::new(),
        };

        let signed = dht_record_to_signed_record(&record);
        let record_signer = RecordSigner::new(Some(signer));
        let sig = record_signer.sign(&signed).unwrap();
        record.signature = sig;

        let verified = verify_dht_record_signature(&record);
        assert!(verified, "Original record should verify");

        record.sequence_number = 999;
        let verified_after_tamper = verify_dht_record_signature(&record);
        assert!(
            !verified_after_tamper,
            "Tampered sequence should fail verification"
        );
    }

    #[test]
    fn test_canonical_signature_rejects_tampered_source_node() {
        let secret = [
            0x9c, 0xef, 0x61, 0x2a, 0xf2, 0x74, 0x23, 0x32, 0x1e, 0x3e, 0x8e, 0x1a, 0x7a, 0x06,
            0x51, 0x4f, 0x4c, 0x3a, 0x38, 0xc4, 0x8c, 0x4f, 0x8c, 0x18, 0x7a, 0x16, 0x32, 0x7d,
            0x5e, 0x41, 0x6e, 0x67,
        ];
        let signer = MeshMessageSigner::new(secret);
        let verifying_key_b64 = signer.get_public_key();

        let mut record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(verifying_key_b64.clone()),
            content_hash: Vec::new(),
        };

        let signed = dht_record_to_signed_record(&record);
        let record_signer = RecordSigner::new(Some(signer));
        let sig = record_signer.sign(&signed).unwrap();
        record.signature = sig;

        let verified = verify_dht_record_signature(&record);
        assert!(verified, "Original record should verify");

        record.source_node_id = "attacker_node".to_string();
        let verified_after_tamper = verify_dht_record_signature(&record);
        assert!(
            !verified_after_tamper,
            "Tampered source_node_id should fail verification"
        );
    }

    #[test]
    fn test_canonical_signature_rejects_tampered_record_type() {
        let secret = [
            0x9c, 0xef, 0x61, 0x2a, 0xf2, 0x74, 0x23, 0x32, 0x1e, 0x3e, 0x8e, 0x1a, 0x7a, 0x06,
            0x51, 0x4f, 0x4c, 0x3a, 0x38, 0xc4, 0x8c, 0x4f, 0x8c, 0x18, 0x7a, 0x16, 0x32, 0x7d,
            0x5e, 0x41, 0x6e, 0x67,
        ];
        let signer = MeshMessageSigner::new(secret);
        let verifying_key_b64 = signer.get_public_key();

        let mut record = crate::mesh::protocol::DhtRecord {
            key: "upstream:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(verifying_key_b64.clone()),
            content_hash: Vec::new(),
        };

        let signed = dht_record_to_signed_record(&record);
        let record_signer = RecordSigner::new(Some(signer));
        let sig = record_signer.sign(&signed).unwrap();
        record.signature = sig;

        let verified = verify_dht_record_signature(&record);
        assert!(verified, "Original record should verify");

        record.key = "org:test".to_string();
        let verified_after_tamper = verify_dht_record_signature(&record);
        assert!(
            !verified_after_tamper,
            "Tampered key (implies different record type) should fail verification"
        );
    }

    #[test]
    fn test_verify_dht_record_signature_empty_signature() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
        };

        let verified = verify_dht_record_signature(&record);
        assert!(!verified, "Empty signature should fail verification");
    }

    #[test]
    fn test_verify_dht_record_signature_no_public_key() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: vec![1; 64],
            signer_public_key: None,
            content_hash: Vec::new(),
        };

        let verified = verify_dht_record_signature(&record);
        assert!(!verified, "Missing public key should fail verification");
    }
}

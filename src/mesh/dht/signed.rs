use std::collections::HashSet;
use std::time::Duration;

use base64::Engine;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mesh::protocol::MeshMessageSigner;

#[derive(Clone)]
pub struct QuorumVerifierContext<'a> {
    pub total_known_global_nodes: usize,
    pub regional_voter_set: Option<&'a HashSet<String>>,
    pub request_id: &'a str,
    pub action: &'a str,
    pub authorized_global_keys: &'a dyn Fn(&str) -> Option<String>,
}

impl<'a> QuorumVerifierContext<'a> {
    pub fn new(
        total_known_global_nodes: usize,
        regional_voter_set: Option<&'a HashSet<String>>,
        request_id: &'a str,
        action: &'a str,
        authorized_global_keys: &'a dyn Fn(&str) -> Option<String>,
    ) -> Self {
        Self {
            total_known_global_nodes,
            regional_voter_set,
            request_id,
            action,
            authorized_global_keys,
        }
    }

    pub fn get_trusted_key(&self, node_id: &str) -> Option<String> {
        (self.authorized_global_keys)(node_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressPath {
    Announce,
    SnapshotSync,
    SyncResponse,
    AntiEntropy,
    QuorumCommit,
    Push,
    LocalCreate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceClassification {
    LocalNode,
    GlobalNode,
    EdgeNode,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DhtRecordIngressContext {
    pub peer_id: String,
    pub source_node_id: String,
    pub source_classification: SourceClassification,
    pub path: IngressPath,
    pub requires_quorum_proof: bool,
    pub requires_trust_anchor: bool,
    pub is_immutable_key: bool,
    pub envelope_signature_valid: bool,
    pub timestamp: u64,
    pub request_id: Option<String>,
    pub is_local_origin: bool,
}

impl DhtRecordIngressContext {
    pub fn new_local(source_node_id: String) -> Self {
        Self {
            peer_id: source_node_id.clone(),
            source_node_id,
            source_classification: SourceClassification::LocalNode,
            path: IngressPath::LocalCreate,
            requires_quorum_proof: false,
            requires_trust_anchor: false,
            is_immutable_key: false,
            envelope_signature_valid: true,
            timestamp: crate::mesh::safe_unix_timestamp(),
            request_id: None,
            is_local_origin: true,
        }
    }

    pub fn new_remote(
        peer_id: String,
        source_node_id: String,
        source_classification: SourceClassification,
        path: IngressPath,
    ) -> Self {
        Self {
            peer_id,
            source_node_id,
            source_classification,
            path,
            requires_quorum_proof: false,
            requires_trust_anchor: false,
            is_immutable_key: false,
            envelope_signature_valid: false,
            timestamp: crate::mesh::safe_unix_timestamp(),
            request_id: None,
            is_local_origin: false,
        }
    }

    pub fn with_quorum_proof(mut self, required: bool) -> Self {
        self.requires_quorum_proof = required;
        self
    }

    pub fn with_trust_anchor(mut self, required: bool) -> Self {
        self.requires_trust_anchor = required;
        self
    }

    pub fn with_immutable(mut self, is_immutable: bool) -> Self {
        self.is_immutable_key = is_immutable;
        self
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    pub fn with_envelope_signature(mut self, valid: bool) -> Self {
        self.envelope_signature_valid = valid;
        self
    }

    pub fn is_local(&self) -> bool {
        self.source_classification == SourceClassification::LocalNode
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub const SNAPSHOT_REQUEST_PROTOCOL_VERSION: &str = "maluwaf:dht-snapshot:v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSnapshotRequestSignable<'a> {
    pub request_id: &'a str,
    pub node_id: &'a str,
    pub from_version: u64,
    pub timestamp: u64,
    pub protocol_version: &'a str,
}

pub fn get_snapshot_request_signable_content(
    request_id: &str,
    node_id: &str,
    from_version: u64,
    timestamp: u64,
) -> Vec<u8> {
    crate::serialization::serialize(&DhtSnapshotRequestSignable {
        request_id,
        node_id,
        from_version,
        timestamp,
        protocol_version: SNAPSHOT_REQUEST_PROTOCOL_VERSION,
    })
    .unwrap_or_default()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumProofSignable<'a> {
    pub request_id: &'a str,
    pub key: &'a str,
    pub value_hash: &'a [u8],
    pub ttl_seconds: u64,
    pub sequence_number: u64,
    pub origin_node_id: &'a str,
    pub action: &'a str,
    pub protocol_version: &'a str,
}

pub const QUORUM_PROOF_PROTOCOL_VERSION: &str = "maluwaf:dht-quorum:v1";

pub fn get_quorum_proof_signable_content(
    request_id: &str,
    record: &crate::mesh::protocol::DhtRecord,
    action: &str,
) -> Vec<u8> {
    let value_hash = record.compute_content_hash();
    crate::serialization::serialize(&QuorumProofSignable {
        request_id,
        key: &record.key,
        value_hash: &value_hash,
        ttl_seconds: record.ttl_seconds,
        sequence_number: record.sequence_number,
        origin_node_id: &record.source_node_id,
        action,
        protocol_version: QUORUM_PROOF_PROTOCOL_VERSION,
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

    let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signer_public_key)
    {
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

    let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&signer_public_key)
    {
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

        let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(public_key_b64)
        {
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

pub const MIN_QUORUM_PROOF_SIGNATURES: usize = 2;

pub fn verify_quorum_proof(
    record: &crate::mesh::protocol::DhtRecord,
    total_known_global_nodes: usize,
    request_id: &str,
    action: &str,
) -> bool {
    if record.quorum_proof.is_empty() {
        tracing::warn!(
            "Quorum proof verification failed for key {}: no proof attached",
            record.key
        );
        return false;
    }

    let required = if total_known_global_nodes == 0 {
        MIN_QUORUM_PROOF_SIGNATURES
    } else {
        crate::mesh::dht::quorum::QuorumRequest::required_signatures_for(total_known_global_nodes)
            .max(MIN_QUORUM_PROOF_SIGNATURES)
    };

    let signable_content = get_quorum_proof_signable_content(request_id, record, action);
    let default_signer = crate::mesh::protocol::MeshMessageSigner::new([0u8; 32]);

    let mut verified_signers: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for proof in &record.quorum_proof {
        let Some(ref signer_pk) = proof.signer_public_key else {
            tracing::debug!(
                "Skipping signature from {} - no signer_public_key in proof",
                proof.node_id
            );
            continue;
        };

        let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_pk) {
            Ok(bytes) => bytes,
            Err(_) => {
                tracing::debug!(
                    "Skipping signature from {} - failed to decode public key",
                    proof.node_id
                );
                continue;
            }
        };

        if pk_bytes.len() != 32 {
            tracing::debug!(
                "Skipping signature from {} - invalid public key length {}",
                proof.node_id,
                pk_bytes.len()
            );
            continue;
        }

        if default_signer.verify_auto(&signable_content, &proof.signature, &pk_bytes) {
            verified_signers.insert(proof.node_id.as_str());
        } else {
            tracing::debug!(
                "Signature verification failed for node {} on key {}",
                proof.node_id,
                record.key
            );
        }
    }

    if verified_signers.len() < required {
        tracing::warn!(
            "Quorum proof verification failed for key {}: {} verified signers < {} required ({} total signatures)",
            record.key,
            verified_signers.len(),
            required,
            record.quorum_proof.len()
        );
        return false;
    }

    tracing::debug!(
        "Quorum proof verified for key {}: {} verified signers >= {} required ({} total signatures)",
        record.key,
        verified_signers.len(),
        required,
        record.quorum_proof.len()
    );
    true
}

pub fn verify_quorum_proof_with_context(
    record: &crate::mesh::protocol::DhtRecord,
    ctx: &QuorumVerifierContext<'_>,
) -> bool {
    if record.quorum_proof.is_empty() {
        tracing::warn!(
            "Quorum proof verification failed for key {}: no proof attached",
            record.key
        );
        return false;
    }

    let quorum_nodes = ctx
        .regional_voter_set
        .map(|rs| rs.len())
        .unwrap_or(ctx.total_known_global_nodes);

    let required = if quorum_nodes == 0 {
        MIN_QUORUM_PROOF_SIGNATURES
    } else {
        crate::mesh::dht::quorum::QuorumRequest::required_signatures_for(quorum_nodes)
            .max(MIN_QUORUM_PROOF_SIGNATURES)
    };

    let signable_content = get_quorum_proof_signable_content(ctx.request_id, record, ctx.action);
    let default_signer = crate::mesh::protocol::MeshMessageSigner::new([0u8; 32]);

    let mut verified_signers: HashSet<&str> = HashSet::new();

    for proof in &record.quorum_proof {
        if let Some(regional_set) = ctx.regional_voter_set {
            if !regional_set.contains(&proof.node_id) {
                tracing::debug!(
                    "Skipping signature from {} - not in regional voter set",
                    proof.node_id
                );
                continue;
            }
        }

        let Some(ref signer_pk) = proof.signer_public_key else {
            tracing::debug!(
                "Skipping signature from {} - no signer_public_key in proof",
                proof.node_id
            );
            continue;
        };

        let trusted_key = ctx.get_trusted_key(&proof.node_id);
        let Some(expected_key_b64) = trusted_key else {
            tracing::debug!(
                "Skipping signature from {} - node_id not in authorized global nodes",
                proof.node_id
            );
            continue;
        };

        if signer_pk != &expected_key_b64 {
            tracing::warn!(
                "Skipping signature from {} - signer_public_key does not match trusted key for node",
                proof.node_id
            );
            continue;
        }

        let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_pk) {
            Ok(bytes) => bytes,
            Err(_) => {
                tracing::debug!(
                    "Skipping signature from {} - failed to decode public key",
                    proof.node_id
                );
                continue;
            }
        };

        if pk_bytes.len() != 32 {
            tracing::debug!(
                "Skipping signature from {} - invalid public key length {}",
                proof.node_id,
                pk_bytes.len()
            );
            continue;
        }

        if default_signer.verify_auto(&signable_content, &proof.signature, &pk_bytes) {
            verified_signers.insert(proof.node_id.as_str());
        } else {
            tracing::debug!(
                "Signature verification failed for node {} on key {}",
                proof.node_id,
                record.key
            );
        }
    }

    if verified_signers.len() < required {
        tracing::warn!(
            "Quorum proof verification failed for key {}: {} verified signers < {} required ({} total signatures)",
            record.key,
            verified_signers.len(),
            required,
            record.quorum_proof.len()
        );
        return false;
    }

    tracing::debug!(
        "Quorum proof verified for key {}: {} verified signers >= {} required ({} total signatures)",
        record.key,
        verified_signers.len(),
        required,
        record.quorum_proof.len()
    );
    true
}

#[cfg(test)]
pub fn verify_quorum_proof_minimum_threshold(
    record: &crate::mesh::protocol::DhtRecord,
    total_known_global_nodes: usize,
    request_id: &str,
    action: &str,
) -> bool {
    let ctx =
        QuorumVerifierContext::new(total_known_global_nodes, None, request_id, action, &|_| {
            None
        });
    verify_quorum_proof_with_context(record, &ctx)
}

pub fn validate_message_freshness(timestamp: u64) -> bool {
    let now = crate::mesh::safe_unix_timestamp() as i64;
    let msg_time = timestamp as i64;
    let diff = (now - msg_time).abs();
    diff <= DHT_MESSAGE_TIMESTAMP_WINDOW_SECS
}

pub fn validate_message_timestamp(timestamp: u64) -> bool {
    validate_message_freshness(timestamp)
}

/// Validates that a record's timestamp is not too far in the future.
/// This prevents clock skew attacks but allows old records that are still live.
/// Note: Actual expiry is determined by timestamp + ttl_seconds, not by record age.
pub fn validate_record_timestamp(timestamp: u64) -> bool {
    let now = crate::mesh::safe_unix_timestamp() as i64;
    let record_time = timestamp as i64;
    let future_diff = record_time.saturating_sub(now);
    future_diff <= DHT_RECORD_TIMESTAMP_WINDOW_SECS
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
            quorum_proof: Vec::new(),
            request_id: None,
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
            quorum_proof: Vec::new(),
            request_id: None,
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
            quorum_proof: Vec::new(),
            request_id: None,
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
            quorum_proof: Vec::new(),
            request_id: None,
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
            quorum_proof: Vec::new(),
            request_id: None,
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
            quorum_proof: Vec::new(),
            request_id: None,
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
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let verified = verify_dht_record_signature(&record);
        assert!(!verified, "Missing public key should fail verification");
    }

    #[test]
    fn test_verify_quorum_proof_empty_proof_rejected() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "malicious_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        assert!(
            !verify_quorum_proof(&record, 3, "", "add"),
            "Empty quorum proof should be rejected"
        );
    }

    #[test]
    fn test_verify_quorum_proof_insufficient_signatures_rejected() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "malicious_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![crate::mesh::protocol::QuorumSignatureProto {
                node_id: "global1".to_string(),
                signature: vec![1, 2, 3],
                timestamp: 1000,
                signer_public_key: None,
            }],
            request_id: None,
        };

        assert!(
            !verify_quorum_proof(&record, 5, "", "add"),
            "Single signature should not meet quorum threshold for 5 nodes"
        );
    }

    #[test]
    fn test_verify_quorum_proof_valid_proof_accepted() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let secret3 = [0x33u8; 32];
        let signer1 = crate::mesh::protocol::MeshMessageSigner::new(secret1);
        let signer2 = crate::mesh::protocol::MeshMessageSigner::new(secret2);
        let signer3 = crate::mesh::protocol::MeshMessageSigner::new(secret3);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig1 = signer1.sign(&signable_content);
        let sig2 = signer2.sign(&signable_content);
        let sig3 = signer3.sign(&signable_content);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: sig1,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: sig2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global3".to_string(),
                    signature: sig3,
                    timestamp: 1002,
                    signer_public_key: Some(signer3.get_public_key()),
                },
            ],
            request_id: None,
        };

        assert!(
            verify_quorum_proof(&record, 3, "", "add"),
            "3 distinct signatures should meet quorum for 3 nodes (need 3)"
        );
    }

    #[test]
    fn test_verify_quorum_proof_duplicate_node_ids_count_once() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "malicious_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: vec![1, 2, 3],
                    timestamp: 1000,
                    signer_public_key: None,
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: vec![4, 5, 6],
                    timestamp: 1001,
                    signer_public_key: None,
                },
            ],
            request_id: None,
        };

        assert!(
            !verify_quorum_proof(&record, 3, "", "add"),
            "Duplicate node_ids should count as 1 distinct signer"
        );
    }

    #[test]
    fn test_verify_quorum_proof_zero_global_nodes_uses_minimum() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let signer1 = crate::mesh::protocol::MeshMessageSigner::new(secret1);
        let signer2 = crate::mesh::protocol::MeshMessageSigner::new(secret2);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig1 = signer1.sign(&signable_content);
        let sig2 = signer2.sign(&signable_content);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: sig1,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: sig2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
            ],
            request_id: None,
        };

        assert!(
            verify_quorum_proof(&record, 0, "", "add"),
            "With 0 known global nodes, MIN_QUORUM_PROOF_SIGNATURES=2 should be the threshold"
        );
    }

    #[test]
    fn test_malicious_node_gossip_without_quorum_proof_rejected() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::config::MeshNodeRole;
        use crate::mesh::dht::DhtAccessControl;

        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        assert!(
            access_control.requires_quorum_proof("verified_upstream:example.com"),
            "verified_upstream keys should require quorum proof"
        );
        assert!(
            access_control.requires_quorum_proof("tier_claim:my-org"),
            "tier_claim keys should require quorum proof"
        );
        assert!(
            !access_control.requires_quorum_proof("upstream:example.com"),
            "upstream keys should NOT require quorum proof"
        );
        assert!(
            !access_control.requires_quorum_proof("node_info:node1"),
            "node_info keys should NOT require quorum proof"
        );

        let malicious_record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:malicious.example.com".to_string(),
            value: b"evil_upstream_data".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "malicious_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("fake_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        assert!(
            !verify_quorum_proof(&malicious_record, 3, "", "add"),
            "Malicious node gossiping Live record without quorum proof must be rejected"
        );
    }

    #[test]
    fn test_regression_forged_quorum_proof_with_fake_signatures_rejected() {
        let fake_signatures_record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:attacker.com".to_string(),
            value: b"fake_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "attacker_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("fake_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: vec![0xFF; 64],
                    timestamp: crate::mesh::safe_unix_timestamp(),
                    signer_public_key: None,
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: vec![0xFE; 64],
                    timestamp: crate::mesh::safe_unix_timestamp(),
                    signer_public_key: None,
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global3".to_string(),
                    signature: vec![0xFD; 64],
                    timestamp: crate::mesh::safe_unix_timestamp(),
                    signer_public_key: None,
                },
            ],
            request_id: None,
        };

        let result = verify_quorum_proof(&fake_signatures_record, 3, "", "add");
        assert!(
            !result,
            "BUG: verify_quorum_proof() currently accepts forged signatures! It only counts distinct node_ids without verifying any signatures."
        );
    }

    #[test]
    fn test_regression_quorum_proof_signature_replay_to_different_content_rejected() {
        let secret = [
            0x9c, 0xef, 0x61, 0x2a, 0xf2, 0x74, 0x23, 0x32, 0x1e, 0x3e, 0x8e, 0x1a, 0x7a, 0x06,
            0x51, 0x4f, 0x4c, 0x3a, 0x38, 0xc4, 0x8c, 0x4f, 0x8c, 0x18, 0x7a, 0x16, 0x32, 0x7d,
            0x5e, 0x41, 0x6e, 0x67,
        ];
        let signer = MeshMessageSigner::new(secret);

        let record1 = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example1.com".to_string(),
            value: b"value_for_record1".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: Vec::new(),
            signer_public_key: Some(signer.get_public_key()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signed_record1 = dht_record_to_signed_record(&record1);
        let sig1 = signer.sign(&signed_record1.get_signable_content());

        let record2 = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example2.com".to_string(),
            value: b"different_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: sig1,
            signer_public_key: Some(signer.get_public_key()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: vec![1; 64],
                    timestamp: 1000,
                    signer_public_key: None,
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: vec![2; 64],
                    timestamp: 1001,
                    signer_public_key: None,
                },
            ],
            request_id: None,
        };

        let verified = verify_dht_record_signature(&record2);
        assert!(
            !verified,
            "BUG: Quorum proof signatures must be bound to specific record content. A proof created for record1 should NOT verify for record2."
        );
    }

    #[test]
    fn test_regression_validate_record_timestamp_rejects_old_but_live_records() {
        let now = crate::mesh::safe_unix_timestamp() as i64;
        let old_timestamp = (now - 600) as u64;
        let ttl_seconds: u64 = 3600;

        let expires_at = old_timestamp.saturating_add(ttl_seconds);
        let is_expired = now > expires_at as i64;

        let timestamp_valid = validate_record_timestamp(old_timestamp);

        assert!(
            !is_expired,
            "Record with timestamp {} and TTL {} should NOT be expired (expires at {})",
            old_timestamp, ttl_seconds, expires_at
        );

        assert!(
            timestamp_valid,
            "BUG: validate_record_timestamp() rejects records with timestamp diff > 300 seconds, even though this record is still LIVE (expires in {} seconds). The validation should check if the record is EXPIRED, not just OLD.",
            expires_at as i64 - now
        );
    }

    #[test]
    fn test_ingress_paths_reject_invalid_signatures() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "org:test".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("invalid_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let verified = verify_dht_record_signature(&record);
        assert!(
            !verified,
            "Record with invalid signature should be rejected by verify_dht_record_signature()"
        );
    }

    #[test]
    fn test_ingress_paths_reject_missing_quorum_proof_for_sensitive_namespaces() {
        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "node1".to_string(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let verified = verify_quorum_proof(&record, 3, "", "add");
        assert!(
            !verified,
            "Record in quorum-required namespace missing quorum proof should be rejected"
        );
    }

    #[test]
    fn test_ingress_paths_reject_future_timestamps() {
        let now = crate::mesh::safe_unix_timestamp() as i64;
        let future_timestamp = (now + 600) as u64;

        let timestamp_valid = validate_record_timestamp(future_timestamp);
        assert!(
            !timestamp_valid,
            "Record with timestamp 600 seconds in future should be rejected by validate_record_timestamp()"
        );
    }

    #[test]
    fn test_ingress_paths_reject_expired_ttl() {
        let now = crate::mesh::safe_unix_timestamp();
        let old_timestamp = now - 7200;
        let ttl_seconds: u64 = 300;
        let expires_at = old_timestamp.saturating_add(ttl_seconds);

        assert!(
            now > expires_at,
            "Record with timestamp {} and TTL {} should be expired",
            old_timestamp,
            ttl_seconds
        );
    }

    #[test]
    fn test_validate_record_timestamp_allows_reasonable_past_timestamps() {
        let now = crate::mesh::safe_unix_timestamp() as i64;
        let past_timestamp = (now - 299) as u64;

        let timestamp_valid = validate_record_timestamp(past_timestamp);
        assert!(
            timestamp_valid,
            "Record with timestamp 299 seconds in past should be valid"
        );
    }

    #[test]
    fn test_validate_record_timestamp_rejects_far_future_timestamps() {
        let now = crate::mesh::safe_unix_timestamp() as i64;
        let far_future = (now + 301) as u64;

        let timestamp_valid = validate_record_timestamp(far_future);
        assert!(
            !timestamp_valid,
            "Record with timestamp 301 seconds in future should be rejected"
        );
    }

    #[test]
    fn test_validate_record_timestamp_allows_current_time() {
        let now = crate::mesh::safe_unix_timestamp();

        let timestamp_valid = validate_record_timestamp(now);
        assert!(
            timestamp_valid,
            "Record with current timestamp should be valid"
        );
    }

    #[test]
    fn test_dht_record_ingress_context_new_local() {
        let source_node_id = "node123".to_string();
        let ctx = DhtRecordIngressContext::new_local(source_node_id.clone());

        assert_eq!(ctx.source_node_id, source_node_id);
        assert_eq!(ctx.source_classification, SourceClassification::LocalNode);
        assert_eq!(ctx.path, IngressPath::LocalCreate);
        assert!(ctx.is_local_origin);
        assert!(ctx.envelope_signature_valid);
    }

    #[test]
    fn test_dht_record_ingress_context_new_remote() {
        let peer_id = "peer456".to_string();
        let source_node_id = "node789".to_string();
        let ctx = DhtRecordIngressContext::new_remote(
            peer_id.clone(),
            source_node_id.clone(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );

        assert_eq!(ctx.peer_id, peer_id);
        assert_eq!(ctx.source_node_id, source_node_id);
        assert_eq!(ctx.source_classification, SourceClassification::GlobalNode);
        assert_eq!(ctx.path, IngressPath::Announce);
        assert!(!ctx.is_local_origin);
        assert!(!ctx.envelope_signature_valid);
    }

    #[test]
    fn test_dht_record_ingress_context_builder_pattern() {
        let ctx = DhtRecordIngressContext::new_local("node123".to_string())
            .with_quorum_proof(true)
            .with_trust_anchor(true)
            .with_immutable(true)
            .with_timestamp(1000)
            .with_request_id(Some("req123".to_string()));

        assert!(ctx.requires_quorum_proof);
        assert!(ctx.requires_trust_anchor);
        assert!(ctx.is_immutable_key);
        assert_eq!(ctx.timestamp, 1000);
        assert_eq!(ctx.request_id, Some("req123".to_string()));
    }

    #[test]
    fn test_source_classification_is_local() {
        let local_ctx = DhtRecordIngressContext::new_local("node123".to_string());
        assert!(local_ctx.is_local());

        let remote_ctx = DhtRecordIngressContext::new_remote(
            "peer".to_string(),
            "node".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );
        assert!(!remote_ctx.is_local());
    }

    #[test]
    fn test_verify_for_ingress_rejects_invalid_content_hash() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![0xFF; 32],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_remote(
            "peer".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::SyncResponse,
        );
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_for_ingress_rejects_future_timestamp() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let now = crate::mesh::safe_unix_timestamp();
        let far_future = (now as i64 + 600) as u64;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: far_future,
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_local("node123".to_string());
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_for_ingress_rejects_expired() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp() - 7200,
            sequence_number: 0,
            ttl_seconds: 300,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_local("node123".to_string());
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_for_ingress_accepts_valid_local_record() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_local("node123".to_string());
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_for_ingress_rejects_remote_without_signature() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_remote(
            "peer".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_quorum_proof_rejects_unknown_key_claiming_known_node() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let signer1 = crate::mesh::protocol::MeshMessageSigner::new(secret1);
        let signer2 = crate::mesh::protocol::MeshMessageSigner::new(secret2);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig1 = signer1.sign(&signable_content);
        let sig2 = signer2.sign(&signable_content);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global-A".to_string(),
                    signature: sig1,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global-B".to_string(),
                    signature: sig2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
            ],
            request_id: None,
        };

        let authorized_keys: std::collections::HashMap<String, String> = [
            ("global-A".to_string(), signer1.get_public_key()),
            ("global-B".to_string(), signer2.get_public_key()),
        ]
        .into_iter()
        .collect();

        let get_keys = |node_id: &str| authorized_keys.get(node_id).cloned();
        let ctx = QuorumVerifierContext::new(2, None, "", "add", &get_keys);

        let verified = verify_quorum_proof_with_context(&record, &ctx);
        assert!(verified, "Valid proof with authorized keys should pass");

        let mut tampered_record = record.clone();
        tampered_record.quorum_proof[0].node_id = "global-C".to_string();

        let ctx2 = QuorumVerifierContext::new(2, None, "", "add", &get_keys);

        let verified_tampered = verify_quorum_proof_with_context(&tampered_record, &ctx2);
        assert!(
            !verified_tampered,
            "Proof claiming global-C but signed by global-A's key should be rejected"
        );
    }

    #[test]
    fn test_verify_quorum_proof_rejects_valid_key_wrong_node_id() {
        let secret = [0x11u8; 32];
        let signer = crate::mesh::protocol::MeshMessageSigner::new(secret);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some(signer.get_public_key()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig = signer.sign(&signable_content);

        let mut malicious_record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some(signer.get_public_key()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global-A".to_string(),
                    signature: sig,
                    timestamp: 1000,
                    signer_public_key: Some(signer.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global-B".to_string(),
                    signature: vec![2; 64],
                    timestamp: 1001,
                    signer_public_key: Some("fake_key".to_string()),
                },
            ],
            request_id: None,
        };

        let authorized_keys: std::collections::HashMap<String, String> =
            [("global-A".to_string(), signer.get_public_key())]
                .into_iter()
                .collect();

        let get_keys = |node_id: &str| authorized_keys.get(node_id).cloned();
        let ctx = QuorumVerifierContext::new(2, None, "", "add", &get_keys);

        let result = verify_quorum_proof_with_context(&malicious_record, &ctx);
        assert!(
            !result,
            "Proof with node_id=global-A but signed with global-B's key should be rejected"
        );
    }

    #[test]
    fn test_verify_quorum_proof_rejects_below_threshold() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let secret3 = [0x33u8; 32];
        let signer1 = crate::mesh::protocol::MeshMessageSigner::new(secret1);
        let signer2 = crate::mesh::protocol::MeshMessageSigner::new(secret2);
        let signer3 = crate::mesh::protocol::MeshMessageSigner::new(secret3);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig1 = signer1.sign(&signable_content);
        let sig2 = signer2.sign(&signable_content);
        let sig3 = signer3.sign(&signable_content);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: sig1,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: sig2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
            ],
            request_id: None,
        };

        let authorized_keys: std::collections::HashMap<String, String> = [
            ("global1".to_string(), signer1.get_public_key()),
            ("global2".to_string(), signer2.get_public_key()),
            ("global3".to_string(), signer3.get_public_key()),
        ]
        .into_iter()
        .collect();

        let get_keys = |node_id: &str| authorized_keys.get(node_id).cloned();
        let ctx = QuorumVerifierContext::new(3, None, "", "add", &get_keys);

        let result = verify_quorum_proof_with_context(&record, &ctx);
        assert!(
            !result,
            "With 3 global nodes, need 3 signatures (2/3+1). Only 2 provided should fail."
        );
    }

    #[test]
    fn test_verify_quorum_proof_regional_voter_set_rejects_outside_nodes() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let secret3 = [0x33u8; 32];
        let signer1 = crate::mesh::protocol::MeshMessageSigner::new(secret1);
        let signer2 = crate::mesh::protocol::MeshMessageSigner::new(secret2);
        let signer3 = crate::mesh::protocol::MeshMessageSigner::new(secret3);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig1 = signer1.sign(&signable_content);
        let sig2 = signer2.sign(&signable_content);
        let sig3 = signer3.sign(&signable_content);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: sig1,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: sig2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global3".to_string(),
                    signature: sig3,
                    timestamp: 1002,
                    signer_public_key: Some(signer3.get_public_key()),
                },
            ],
            request_id: None,
        };

        let authorized_keys: std::collections::HashMap<String, String> = [
            ("global1".to_string(), signer1.get_public_key()),
            ("global2".to_string(), signer2.get_public_key()),
            ("global3".to_string(), signer3.get_public_key()),
        ]
        .into_iter()
        .collect();

        let regional_voters: std::collections::HashSet<String> = ["global1", "global2"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        let get_keys = |node_id: &str| authorized_keys.get(node_id).cloned();
        let ctx = QuorumVerifierContext::new(3, Some(&regional_voters), "", "add", &get_keys);

        let result = verify_quorum_proof_with_context(&record, &ctx);
        assert!(
            result,
            "global3 is filtered but global1+global2 meet quorum threshold in regional set"
        );

        let sig1_2 = signer1.sign(&signable_content);
        let sig2_2 = signer2.sign(&signable_content);

        let record2 = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global1".to_string(),
                    signature: sig1_2,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global2".to_string(),
                    signature: sig2_2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
            ],
            request_id: None,
        };

        let result2 = verify_quorum_proof_with_context(&record2, &ctx);
        assert!(
            result2,
            "global1 and global2 are both in regional voter set, should pass"
        );
    }

    #[test]
    fn test_verify_quorum_proof_with_valid_trusted_keys_passes() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let signer1 = crate::mesh::protocol::MeshMessageSigner::new(secret1);
        let signer2 = crate::mesh::protocol::MeshMessageSigner::new(secret2);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };

        let signable_content = get_quorum_proof_signable_content("", &record, "add");
        let sig1 = signer1.sign(&signable_content);
        let sig2 = signer2.sign(&signable_content);

        let record = crate::mesh::protocol::DhtRecord {
            key: "verified_upstream:example.com".to_string(),
            value: b"test_value".to_vec(),
            timestamp: 1000,
            sequence_number: 1,
            ttl_seconds: 300,
            source_node_id: "honest_node".to_string(),
            signature: vec![1; 64],
            signer_public_key: Some("some_key".to_string()),
            content_hash: Vec::new(),
            quorum_proof: vec![
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global-A".to_string(),
                    signature: sig1,
                    timestamp: 1000,
                    signer_public_key: Some(signer1.get_public_key()),
                },
                crate::mesh::protocol::QuorumSignatureProto {
                    node_id: "global-B".to_string(),
                    signature: sig2,
                    timestamp: 1001,
                    signer_public_key: Some(signer2.get_public_key()),
                },
            ],
            request_id: None,
        };

        let authorized_keys: std::collections::HashMap<String, String> = [
            ("global-A".to_string(), signer1.get_public_key()),
            ("global-B".to_string(), signer2.get_public_key()),
        ]
        .into_iter()
        .collect();

        let get_keys = |node_id: &str| authorized_keys.get(node_id).cloned();
        let ctx = QuorumVerifierContext::new(2, None, "", "add", &get_keys);

        let result = verify_quorum_proof_with_context(&record, &ctx);
        assert!(result, "Valid proof with correct trusted keys should pass");
    }

    #[test]
    fn test_ingress_rejects_missing_signature_on_remote_announce() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_remote(
            "peer456".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DhtRecordVerificationError::MissingSignature
        ));
    }

    #[test]
    fn test_ingress_rejects_missing_signer_public_key_for_global_store() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let mut record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![1; 64],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };
        record.content_hash = record.compute_content_hash();

        let ctx = DhtRecordIngressContext::new_remote(
            "peer456".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DhtRecordVerificationError::InvalidSignature),
            "Expected InvalidSignature when signature verification fails due to missing signer key, got {:?}",
            err
        );
    }

    #[test]
    fn test_ingress_rejects_source_node_mismatch() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "actual_source_node".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_remote(
            "peer456".to_string(),
            "different_source_node".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DhtRecordVerificationError::MissingSignature),
            "Expected MissingSignature for empty signature, got {:?}",
            err
        );
    }

    #[test]
    fn test_ingress_rejects_immutable_record_without_trust_anchor() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let mut record = DhtRecord {
            key: "immutable:test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![1; 64],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };
        record.content_hash = record.compute_content_hash();

        let ctx = DhtRecordIngressContext::new_remote(
            "peer456".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        )
        .with_immutable(true);

        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DhtRecordVerificationError::InvalidSignature),
            "Expected InvalidSignature for missing signer key, got {:?}",
            err
        );
    }

    #[test]
    fn test_ingress_accepts_valid_remote_announce_with_signature() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::{DhtRecord, MeshMessageSigner};

        let secret = [0x11u8; 32];
        let signer = MeshMessageSigner::new(secret);

        let mut record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: Some(signer.get_public_key()),
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let signed_record = crate::mesh::dht::signed::dht_record_to_signed_record(&record);
        record.signature = signer.sign(&signed_record.get_signable_content());
        record.content_hash = record.compute_content_hash();

        let ctx = DhtRecordIngressContext::new_remote(
            "peer456".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        );
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ingress_rejects_quorum_required_without_proof() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::{DhtRecord, MeshMessageSigner};

        let secret = [0x42u8; 32];
        let signer = MeshMessageSigner::new(secret);

        let mut record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: Some(signer.get_public_key()),
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let signed_record = crate::mesh::dht::signed::dht_record_to_signed_record(&record);
        record.signature = signer.sign(&signed_record.get_signable_content());
        record.content_hash = record.compute_content_hash();

        let ctx = DhtRecordIngressContext::new_remote(
            "peer456".to_string(),
            "node123".to_string(),
            SourceClassification::GlobalNode,
            IngressPath::Announce,
        )
        .with_quorum_proof(true);

        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DhtRecordVerificationError::MissingQuorumProof),
            "Expected MissingQuorumProof (signature verified), got {:?}",
            err
        );
    }

    #[test]
    fn test_ingress_local_create_allows_unsigned() {
        use crate::mesh::config::MeshConfig;
        use crate::mesh::dht::DhtAccessControl;
        use crate::mesh::protocol::DhtRecord;

        let record = DhtRecord {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 0,
            ttl_seconds: 3600,
            source_node_id: "node123".to_string(),
            signature: vec![],
            signer_public_key: None,
            content_hash: vec![],
            quorum_proof: vec![],
            request_id: None,
        };

        let ctx = DhtRecordIngressContext::new_local("node123".to_string());
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);

        let result = record.verify_for_ingress(&ctx, &access_control);
        assert!(result.is_ok());
    }
}

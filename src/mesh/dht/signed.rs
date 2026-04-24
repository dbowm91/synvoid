use std::time::Duration;

use base64::Engine;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::integrity::protocol::{Ed25519Signer, Ed25519Verifier};

pub const DHT_MESSAGE_TIMESTAMP_WINDOW_SECS: i64 = 300;

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
}

impl SignedRecordType {
    pub fn requires_global_node(&self) -> bool {
        matches!(
            self,
            SignedRecordType::Organization
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
        )
    }

    pub fn requires_confirmation(&self) -> bool {
        matches!(
            self,
            SignedRecordType::TierKey
                | SignedRecordType::Organization
                | SignedRecordType::Upstream
                | SignedRecordType::OrgNameReservation
        )
    }

    pub fn default_ttl(&self) -> Option<Duration> {
        match self {
            SignedRecordType::Organization => Some(Duration::from_secs(86400 * 7)),
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
        }
    }

    pub fn requires_announce_refresh(&self) -> bool {
        matches!(self, SignedRecordType::Upstream)
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

    /// Get signable content for signature verification
    /// Uses postcard for stable binary serialization
    pub fn get_signable_content(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct SignableContent<'a> {
            key: &'a str,
            value: &'a [u8],
            publisher_id: &'a str,
            created_at: u64,
            sequence_number: u64,
            source_node_id: &'a str,
        }

        let content = SignableContent {
            key: &self.key,
            value: &self.value,
            publisher_id: &self.publisher_id,
            created_at: self.created_at,
            sequence_number: self.sequence_number,
            source_node_id: &self.source_node_id,
        };

        crate::serialization::serialize(&content).unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct RecordSigner {
    signing_key: Option<Ed25519Signer>,
    verifying_key: Option<String>,
}

impl RecordSigner {
    pub fn new(signing_key: Option<[u8; 32]>) -> Self {
        let signer = signing_key.map(Ed25519Signer::new);
        let verifying_key = signer.as_ref().map(|s| s.verifying_key());
        Self {
            signing_key: signer,
            verifying_key,
        }
    }

    pub fn sign(&self, record: &SignedDhtRecord) -> Option<Vec<u8>> {
        let signer = match self.signing_key.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("No signing key configured - record will be stored unsigned");
                return None;
            }
        };

        let content = record.get_signable_content();
        let signature = signer.sign_bytes(&content);
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&signature)
            .ok()
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

        let verifier = match Ed25519Verifier::from_base64(public_key_b64) {
            Some(v) => v,
            None => {
                tracing::warn!("Invalid public key format on record {}", record.key);
                return false;
            }
        };

        let content = record.get_signable_content();
        let signature_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&record.signature);

        verifier.verify_bytes(&content, &signature_b64)
    }

    pub fn get_verifying_key(&self) -> Option<String> {
        self.verifying_key.clone()
    }
}

pub fn validate_message_timestamp(timestamp: u64) -> bool {
    let now = crate::mesh::safe_unix_timestamp() as i64;

    let msg_time = timestamp as i64;
    let diff = (now - msg_time).abs();

    diff <= DHT_MESSAGE_TIMESTAMP_WINDOW_SECS
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
        }
    }
}

impl TtlManager {
    pub fn new() -> Self {
        Self::default()
    }

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
}

use base64::Engine;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use prost::Message;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Archive, RkyvDeserialize, RkyvSerialize)]
pub struct ArcStr(String);

impl ArcStr {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_arc(&self) -> Arc<str> {
        Arc::from(self.0.clone())
    }
}

impl std::fmt::Display for ArcStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for ArcStr {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ArcStr {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::ops::Deref for ArcStr {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl Serialize for ArcStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ArcStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s))
    }
}

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/mesh.rs"));
}

use crate::mesh::config::MeshNodeRole;
use crate::mesh::hybrid_signature::HybridSignature;
use crate::mesh::ml_dsa::MeshMlDsaSigner;
use crate::mesh::organization::TierClaim;
use crate::mesh::transports::MeshTransportType;

pub const MESH_MESSAGE_VERSION: u8 = 1;
const COMPRESSION_THRESHOLD: usize = 512;
const NONCE_SIZE: usize = 16;
const REPLAY_WINDOW_SECS: u64 = 60;
const MAX_REPLAY_CACHE_SIZE: usize = 10000;

#[derive(Clone)]
pub struct MeshMessageSigner {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key_bytes: Vec<u8>,
    ml_dsa_signer: Option<Arc<MeshMlDsaSigner>>,
}

impl MeshMessageSigner {
    pub fn new(secret_key: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_bytes: verifying_key.as_bytes().to_vec(),
            ml_dsa_signer: None,
        }
    }

    pub fn from_secret(secret_key: ed25519_dalek::SecretKey) -> Self {
        let signing_key = SigningKey::from(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_bytes: verifying_key.as_bytes().to_vec(),
            ml_dsa_signer: None,
        }
    }

    pub fn with_ml_dsa_signer(mut self, signer: Arc<MeshMlDsaSigner>) -> Self {
        self.ml_dsa_signer = Some(signer);
        self
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::fill(&mut key);
        key
    }

    pub fn sign(&self, content: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(content);
        signature.to_bytes().to_vec()
    }

    pub fn sign_hybrid(&self, content: &[u8]) -> HybridSignature {
        let ed25519_sig = self.sign(content);
        let ml_dsa_sig = self
            .ml_dsa_signer
            .as_ref()
            .and_then(|s| s.sign(content))
            .unwrap_or_default();
        HybridSignature::new(ed25519_sig, ml_dsa_sig, self.get_public_key())
    }

    pub fn verify(&self, content: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != 64 || public_key.len() != 32 {
            return false;
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature);

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(public_key);

        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
            Ok(pk) => pk
                .verify(content, &ed25519_dalek::Signature::from_bytes(&sig_array))
                .is_ok(),
            Err(_) => false,
        }
    }

    pub fn verify_hybrid(&self, content: &[u8], hybrid: &HybridSignature) -> bool {
        let pk_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&hybrid.signer_public_key)
        {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let ed25519_valid = self.verify(content, &hybrid.ed25519_signature, &pk_bytes);

        if !ed25519_valid {
            return false;
        }

        if hybrid.has_ml_dsa() {
            match &self.ml_dsa_signer {
                Some(signer) => signer.verify(content, &hybrid.ml_dsa_signature),
                None => false,
            }
        } else {
            true
        }
    }

    pub fn has_ml_dsa(&self) -> bool {
        self.ml_dsa_signer
            .as_ref()
            .map(|s| s.has_signing_key())
            .unwrap_or(false)
    }

    pub fn get_public_key(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.verifying_key_bytes)
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key_bytes.clone()
    }
}

#[derive(Clone)]
pub struct ReplayProtection {
    seen_nonces: std::collections::HashSet<String>,
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            seen_nonces: std::collections::HashSet::new(),
        }
    }

    pub fn check_and_add(&mut self, nonce: &str, timestamp: u64) -> ReplayResult {
        let now = crate::mesh::safe_unix_timestamp();

        if timestamp > now + 60 {
            return ReplayResult::FutureTimestamp;
        }

        if now.saturating_sub(timestamp) > REPLAY_WINDOW_SECS {
            return ReplayResult::ExpiredTimestamp;
        }

        let nonce_key = format!("{}:{}", timestamp, nonce);
        if self.seen_nonces.contains(&nonce_key) {
            return ReplayResult::ReplayDetected;
        }

        if self.seen_nonces.len() >= MAX_REPLAY_CACHE_SIZE {
            let old_count = self.seen_nonces.len() / 4;
            let to_remove: Vec<_> = self.seen_nonces.iter().take(old_count).cloned().collect();
            for key in to_remove {
                self.seen_nonces.remove(&key);
            }
        }

        self.seen_nonces.insert(nonce_key);
        ReplayResult::Valid
    }

    pub fn clear(&mut self) {
        self.seen_nonces.clear();
    }
}

pub use protocol_types::{AuthChallenge, PendingAuthChallenge, ReplayResult};

pub use protocol_types::{
    PRIORITY_TIER_ENTERPRISE, PRIORITY_TIER_FREE, PRIORITY_TIER_PAID, PRIORITY_TIER_PREMIUM,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MeshMessage {
    Hello {
        version: u8,
        node_id: ArcStr,
        role: MeshNodeRole,
        capabilities: MeshCapabilities,
        upstreams: HashMap<String, UpstreamInfo>,
        auth_token: Option<ArcStr>,
        network_id: Option<ArcStr>,
        global_node_key: Option<ArcStr>,
        timestamp: Option<u64>,
        nonce: Option<ArcStr>,
        is_trusted: bool,
        quic_port: Option<u32>,
        wireguard_port: Option<u32>,
        public_key: Option<ArcStr>,
        pow_nonce: Option<u64>,
        pow_public_key: Option<ArcStr>,
        member_certificate: Option<crate::mesh::organization::MemberCertificate>,
        org_public_key: Option<crate::mesh::organization::OrgPublicKey>,
    },
    HelloAck {
        version: u8,
        node_id: ArcStr,
        role: MeshNodeRole,
        session_id: ArcStr,
        capabilities: MeshCapabilities,
        upstreams: HashMap<String, UpstreamInfo>,
        auth_token: Option<ArcStr>,
        network_id: Option<ArcStr>,
        global_node_key: Option<ArcStr>,
        timestamp: Option<u64>,
        nonce: Option<ArcStr>,
        is_trusted: bool,
        quic_port: Option<u32>,
        wireguard_port: Option<u32>,
        public_key: Option<ArcStr>,
        member_certificate: Option<crate::mesh::organization::MemberCertificate>,
        org_public_key: Option<crate::mesh::organization::OrgPublicKey>,
    },
    SyncRequest {
        node_id: ArcStr,
    },
    SyncResponse {
        nodes: Vec<MeshPeerInfo>,
        upstreams: HashMap<String, UpstreamOwner>,
        timestamp: u64,
    },
    RouteQuery {
        query_id: ArcStr,
        upstream_id: ArcStr,
        max_hops: u8,
        initiator: ArcStr,
        sequence: u32,
        timestamp: u64,
        nonce: ArcStr,
    },
    RouteResponse {
        query_id: ArcStr,
        upstream_id: ArcStr,
        provider_node_id: ArcStr,
        hops: u8,
        ttl_secs: u32,
        signature: Vec<u8>,
        sequence: u32,
        timestamp: u64,
        nonce: ArcStr,
        upstream_url: Option<ArcStr>,
        waf_policy: Option<WafPolicy>,
        priority_tier: u32,
        tier_claim: Option<TierClaim>,
        org_id: Option<ArcStr>,
        mesh_name: Option<ArcStr>,
    },
    RouteResponseAck {
        query_id: ArcStr,
        upstream_id: ArcStr,
        provider_node_id: ArcStr,
    },
    RouteNotFound {
        query_id: ArcStr,
        upstream_id: ArcStr,
    },
    RouteRejected {
        query_id: ArcStr,
        upstream_id: ArcStr,
        reason: ArcStr,
        alternatives: Vec<AlternativeProvider>,
    },
    TierKeyAnnounce {
        org_id: ArcStr,
        key: crate::mesh::organization::TierKey,
        signature: Vec<u8>,
    },
    TierKeyRevoke {
        org_id: ArcStr,
        key_id: ArcStr,
        signature: Vec<u8>,
    },
    TierKeyQuery {
        request_id: ArcStr,
        org_id: ArcStr,
        requested_tier: Option<u32>,
    },
    TierKeyQueryResponse {
        request_id: ArcStr,
        keys: Vec<crate::mesh::organization::TierKey>,
        signature: Vec<u8>,
    },
    UnspentTierKeyAnnounce {
        org_id: ArcStr,
        tier_keys: Vec<crate::mesh::organization::TierKey>,
        signature: Vec<u8>,
        timestamp: u64,
    },
    OrgRegistrationRequest {
        request_id: ArcStr,
        org_name: ArcStr,
        requesting_node_id: ArcStr,
        requesting_node_pubkey: ArcStr,
        timestamp: u64,
        signature: Vec<u8>,
    },
    OrgRegistrationResponse {
        request_id: ArcStr,
        org_id: ArcStr,
        org_name: ArcStr,
        approved: bool,
        reason: ArcStr,
        initial_tier_key: Option<crate::mesh::organization::TierKey>,
        signature: Vec<u8>,
        timestamp: u64,
    },
    OrgInvitationRequest {
        request_id: ArcStr,
        org_id: ArcStr,
        inviter_node_id: ArcStr,
        invited_node_id: ArcStr,
        invited_node_pubkey: Option<ArcStr>,
        invitation_token: ArcStr,
        expires_at: u64,
        timestamp: u64,
        signature: Vec<u8>,
    },
    OrgInvitationAccept {
        request_id: ArcStr,
        org_id: ArcStr,
        invited_node_id: ArcStr,
        invitation_token: ArcStr,
        proof_of_key: ArcStr,
        timestamp: u64,
        signature: Vec<u8>,
    },
    OrgInvitationResponse {
        request_id: ArcStr,
        org_id: ArcStr,
        accepted: bool,
        org_key: Option<crate::mesh::organization::TierKey>,
        reason: ArcStr,
        signature: Vec<u8>,
        timestamp: u64,
    },
    GlobalNodeAnnounce {
        node_id: ArcStr,
        public_key: ArcStr,
        action: GlobalNodeAction,
        timestamp: u64,
        signature: Vec<u8>,
        key_exchange_endpoint: Option<ArcStr>,
    },
    OrgMemberAnnounce {
        org_id: ArcStr,
        member_node_id: ArcStr,
        announced_by: ArcStr,
        joined_at: u64,
        signature: Vec<u8>,
    },
    UpstreamUrlRequest {
        request_id: ArcStr,
        upstream_id: ArcStr,
        url_hash: ArcStr,
    },
    UpstreamUrlResponse {
        request_id: ArcStr,
        upstream_id: ArcStr,
        upstream_url: ArcStr,
        signature: Vec<u8>,
    },
    UpstreamUrlDenied {
        request_id: ArcStr,
        upstream_id: ArcStr,
    },
    UpstreamAnnounce {
        upstream_id: ArcStr,
        action: AnnounceAction,
        signature: Vec<u8>,
        origin_ed25519_pubkey: ArcStr,
        origin_signature: Vec<u8>,
    },
    UpstreamUpdate {
        upstream_id: ArcStr,
        info: UpstreamInfo,
        signature: Vec<u8>,
    },
    QuorumStoreRequest {
        request_id: ArcStr,
        key: ArcStr,
        value: Vec<u8>,
        ttl_seconds: u64,
        origin_node_id: ArcStr,
        origin_signature: Vec<u8>,
        action: AnnounceAction,
    },
    QuorumSignatureResponse {
        request_id: ArcStr,
        key: ArcStr,
        signature: Vec<u8>,
    },
    QuorumRejectionResponse {
        request_id: ArcStr,
        key: ArcStr,
        reason: ArcStr,
        evidence: Option<Vec<u8>>,
    },
    KeyForward {
        session_id: ArcStr,
        key_id: ArcStr,
        mesh_id: ArcStr,
        client_x25519_pubkey: ArcStr,
        global_node_id: ArcStr,
        nonce: ArcStr,
        timestamp: u64,
    },
    KeySigned {
        session_id: ArcStr,
        key_id: ArcStr,
        mesh_id: ArcStr,
        origin_mesh_id: ArcStr,
        origin_ed25519_pubkey: ArcStr,
        server_x25519_pubkey: ArcStr,
        origin_signature: Vec<u8>,
        nonce: ArcStr,
        timestamp: u64,
    },
    KeepAlive,
    KeepAliveAck,
    LookupRequest {
        request_id: ArcStr,
        key: ArcStr,
        lookup_type: LookupType,
    },
    LookupResponse {
        request_id: ArcStr,
        key: ArcStr,
        value: Option<Vec<u8>>,
        found: bool,
    },
    LookupBatchRequest {
        request_id: ArcStr,
        keys: Vec<ArcStr>,
    },
    LookupBatchResponse {
        request_id: ArcStr,
        results: HashMap<String, Option<Vec<u8>>>,
    },
    PeerHealthCheck {
        peer_id: ArcStr,
        timestamp: u64,
    },
    PeerHealthResponse {
        peer_id: ArcStr,
        status: HealthStatus,
        latency_ms: Option<u32>,
        timestamp: u64,
    },
    PeerAnnounce {
        node_id: ArcStr,
        address: ArcStr,
        role: MeshNodeRole,
        capabilities: MeshCapabilities,
        announced_at: u64,
    },
    PeerGone {
        node_id: ArcStr,
        reason: ArcStr,
    },
    TopologySyncRequest {
        request_id: ArcStr,
        from_version: u64,
        prefer_delta: bool,
    },
    TopologySyncResponse {
        request_id: ArcStr,
        peers: Vec<MeshPeerInfo>,
        upstreams: HashMap<String, UpstreamOwner>,
        version: u64,
        is_delta: bool,
        removed_peers: Vec<ArcStr>,
        removed_upstreams: Vec<ArcStr>,
    },
    SeedListRequest {
        node_id: ArcStr,
        request_full_mesh: bool,
    },
    SeedListResponse {
        global_nodes: Vec<MeshPeerInfo>,
        edge_nodes: Vec<MeshPeerInfo>,
        version: u64,
        genesis_org_id: Option<ArcStr>,
    },
    PeerLoadReport {
        node_id: ArcStr,
        active_connections: u32,
        cpu_load_percent: f32,
        memory_percent: f32,
        requests_per_second: f32,
    },
    PeerLoadUpdate {
        node_id: ArcStr,
        load_score: f64,
    },
    RouteUsageReport {
        upstream_id: ArcStr,
        request_count: u64,
        bytes_transferred: u64,
    },
    UpstreamBlocked {
        mesh_identifier: ArcStr,
        service_id: ArcStr,
        blocked_until: u64,
        reason: ArcStr,
        origin_node_id: ArcStr,
    },
    BandwidthReport {
        upstream_id: ArcStr,
        bytes_sent: u64,
        bytes_received: u64,
        request_count: u64,
        interval_secs: u64,
        timestamp: u64,
    },
    MeshAck {
        original_message_id: ArcStr,
        status: AckStatus,
        timestamp: u64,
    },
    AuthChallenge {
        challenge: ArcStr,
        challenge_id: ArcStr,
        expires_at: u64,
    },
    AuthResponse {
        challenge_id: ArcStr,
        response: ArcStr,
    },
    Error {
        code: u16,
        message: ArcStr,
    },
    ThreatAnnounce {
        request_id: ArcStr,
        indicators: Vec<ThreatIndicator>,
        highest_severity: ThreatSeverity,
        timestamp: u64,
        source_node_id: ArcStr,
        source_role: MeshNodeRole,
        source_reputation: u64,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    ThreatSyncRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        from_version: u64,
        prefer_delta: bool,
    },
    ThreatSyncResponse {
        request_id: ArcStr,
        indicators: Vec<ThreatIndicator>,
        version: u64,
        is_delta: bool,
        removed_indicators: Vec<ArcStr>,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    ThreatAcknowledgement {
        original_request_id: ArcStr,
        node_id: ArcStr,
        accepted: bool,
        reason: ArcStr,
        timestamp: u64,
    },
    YaraRuleAnnounce {
        request_id: ArcStr,
        version: String,
        rules: String,
        timestamp: u64,
        source_node_id: ArcStr,
        source_role: MeshNodeRole,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    YaraRuleSyncRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        version: Option<String>,
    },
    YaraRuleSyncResponse {
        request_id: ArcStr,
        version: String,
        rules: String,
        is_full: bool,
        timestamp: u64,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    YaraRuleAcknowledgement {
        original_request_id: ArcStr,
        node_id: ArcStr,
        accepted: bool,
        reason: ArcStr,
        timestamp: u64,
    },
    YaraRuleSubmission {
        request_id: ArcStr,
        submission_id: ArcStr,
        node_id: ArcStr,
        timestamp: u64,
        signature: Vec<u8>,
        rules: String,
        description: String,
        signer_public_key: String,
    },
    YaraRuleSubmissionResponse {
        original_request_id: ArcStr,
        submission_id: ArcStr,
        node_id: ArcStr,
        status: ArcStr,
        timestamp: u64,
    },
    BehavioralFingerprintAnnounce {
        request_id: ArcStr,
        fingerprints: Vec<crate::mesh::behavioral::BehavioralFingerprint>,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    BehavioralFingerprintSyncRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        from_version: u64,
        prefer_delta: bool,
    },
    BehavioralFingerprintSyncResponse {
        request_id: ArcStr,
        fingerprints: Vec<crate::mesh::behavioral::BehavioralFingerprint>,
        version: u64,
        is_delta: bool,
        removed_fingerprint_ids: Vec<ArcStr>,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    ReputationUpdate {
        node_id: ArcStr,
        reputation_score: i64,
        threats_accepted: u64,
        threats_rejected: u64,
        false_positive_reports: u64,
        timestamp: u64,
        signature: Vec<u8>,
    },
    DhtRecordAnnounce {
        request_id: ArcStr,
        records: Vec<DhtRecord>,
        write_quorum: u32,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    DhtRecordQuery {
        request_id: ArcStr,
        key: ArcStr,
        timestamp: u64,
        source_node_id: ArcStr,
    },
    DhtRecordResponse {
        request_id: ArcStr,
        key: ArcStr,
        value: Vec<u8>,
        found: bool,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    DhtSyncRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        from_version: u64,
    },
    DhtSyncResponse {
        request_id: ArcStr,
        records: Vec<DhtRecord>,
        version: u64,
        timestamp: u64,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    DhtSnapshotRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        from_version: u64,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    DhtSnapshotResponse {
        request_id: ArcStr,
        records: Vec<DhtRecord>,
        version: u64,
        timestamp: u64,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    DhtAntiEntropyRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        local_root_hash: Vec<u8>,
        interested_keys: Vec<String>,
        timestamp: u64,
        signer_public_key: String,
    },
    DhtAntiEntropyResponse {
        request_id: ArcStr,
        root_hash: Vec<u8>,
        proof_keys: Vec<String>,
        proof_hashes: Vec<Vec<u8>>,
        missing_records: Vec<DhtRecord>,
        timestamp: u64,
        signature: Vec<u8>,
        signer_public_key: String,
    },
    DhtRecordPush {
        request_id: ArcStr,
        records: Vec<DhtRecord>,
        hop_count: u32,
        seen_node_ids: Vec<String>,
        timestamp: u64,
        signer_public_key: String,
    },
    DhtRecordPushAck {
        request_id: ArcStr,
        original_request_id: ArcStr,
        node_id: ArcStr,
        accepted: bool,
        missing_keys: Vec<String>,
        timestamp: u64,
    },
    NetworkPolicyUpdate {
        policy: super::dht::NetworkPolicy,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
    },
    GlobalNodeBlocklistUpdate {
        blocklist: super::dht::GlobalNodeBlocklist,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
    },
    AiBotListUpdate {
        bot_list: super::dht::GlobalAiBotList,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
    },
    OriginKeyQuery {
        request_id: ArcStr,
        mesh_id: ArcStr,
        timestamp: u64,
    },
    OriginKeyQueryResponse {
        request_id: ArcStr,
        mesh_id: ArcStr,
        public_key: Option<ArcStr>,
        timestamp: u64,
    },
    NodeShutdown {
        node_id: ArcStr,
        role: MeshNodeRole,
        domains: Vec<ArcStr>,
        graceful: bool,
        shutdown_at: u64,
        timestamp: u64,
        signature: Vec<u8>,
    },
    SiteConfigSync {
        request_id: ArcStr,
        site_id: ArcStr,
        config_version: u64,
        config_json: ArcStr,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
        signer_public_key: Option<ArcStr>,
        proxy_cache_preferences: Option<ProxyCachePreferences>,
    },
    DnsDomainRegisterRequest {
        request_id: ArcStr,
        domain: ArcStr,
        origin_node_id: ArcStr,
        challenge_token: ArcStr,
        geo: Option<ArcStr>,
        capacity: u32,
        timestamp: u64,
        signature: Vec<u8>,
    },
    DnsDomainRegisterResponse {
        request_id: ArcStr,
        domain: ArcStr,
        origin_node_id: ArcStr,
        verified: bool,
        reason: ArcStr,
        timestamp: u64,
        signature: Vec<u8>,
    },
    DnsDomainDeregisterRequest {
        request_id: ArcStr,
        domain: ArcStr,
        origin_node_id: ArcStr,
        reason: ArcStr,
        timestamp: u64,
        signature: Vec<u8>,
    },
    DnsDomainRegistered {
        domain: ArcStr,
        origin_node_id: ArcStr,
        verified_by_global_node: ArcStr,
        geo: Option<ArcStr>,
        capacity: u32,
        registered_at: u64,
        expires_at: u64,
        signature: Vec<u8>,
    },
    DnsDomainDeregistered {
        domain: ArcStr,
        origin_node_id: ArcStr,
        deregistered_by_global_node: ArcStr,
        reason: ArcStr,
        deregistered_at: u64,
        signature: Vec<u8>,
    },
    FindNode {
        request_id: ArcStr,
        target_node_id: Vec<u8>,
        requester_node_id: ArcStr,
        timestamp: u64,
    },
    FindNodeResponse {
        request_id: ArcStr,
        peers: Vec<super::dht::routing::PeerContact>,
        responder_node_id: ArcStr,
        timestamp: u64,
    },
    Ping {
        request_id: ArcStr,
        node_id: ArcStr,
        timestamp: u64,
    },
    Pong {
        request_id: ArcStr,
        node_id: ArcStr,
        timestamp: u64,
    },
    UpstreamVerificationQuery {
        request_id: ArcStr,
        upstream_id: ArcStr,
        querying_node_id: ArcStr,
        timestamp: u64,
        provider_node_id: ArcStr,
    },
    UpstreamVerificationResponse {
        request_id: ArcStr,
        upstream_id: ArcStr,
        verified: bool,
        global_node_id: ArcStr,
        global_node_signature: Option<Vec<u8>>,
        upstream_url: ArcStr,
        org_id: Option<ArcStr>,
        timestamp: u64,
        provider_node_id: ArcStr,
    },
    UpstreamOwnershipChallenge {
        request_id: ArcStr,
        upstream_id: ArcStr,
        challenge_type: OwnershipChallengeType,
        challenge_token: String,
        global_node_id: ArcStr,
        timestamp: u64,
    },
    UpstreamChallengeProof {
        request_id: ArcStr,
        upstream_id: ArcStr,
        challenge_proof: OwnershipChallengeProof,
        origin_node_id: ArcStr,
        timestamp: u64,
    },
    #[cfg(feature = "dns")]
    DnsRegistrationRequest {
        request_id: ArcStr,
        registration: crate::dns::messages::DnsRegistrationWithVerificationRequest,
        timestamp: u64,
    },
    #[cfg(feature = "dns")]
    DnsRegistrationResponse {
        request_id: ArcStr,
        response: crate::dns::messages::DnsRegistrationWithVerificationResponse,
        timestamp: u64,
    },
    #[cfg(feature = "dns")]
    DnsVerificationUpdate {
        request_id: ArcStr,
        update: crate::dns::messages::DomainVerificationStatusUpdate,
        timestamp: u64,
    },
    AnycastNodeRegistration {
        request_id: ArcStr,
        node_id: ArcStr,
        anycast_ips: Vec<String>,
        geo: Option<ArcStr>,
        capacity: u32,
        healthy: bool,
        dns_zones: Vec<String>,
        certificate_fingerprint: Option<ArcStr>,
        timestamp: u64,
    },
    AnycastHealthUpdate {
        node_id: ArcStr,
        anycast_ips: Vec<String>,
        healthy: bool,
        latency_ms: Option<u32>,
        load_percent: Option<u8>,
        timestamp: u64,
    },
    ZoneSyncRequest {
        request_id: ArcStr,
        zone_origin: ArcStr,
        serial: u32,
        requesting_node_id: ArcStr,
        timestamp: u64,
    },
    ZoneSyncResponse {
        request_id: ArcStr,
        zone_origin: ArcStr,
        records_json: ArcStr,
        serial: u32,
        complete: bool,
        timestamp: u64,
        origin_signature: Vec<u8>,
        origin_pubkey: Option<String>,
        previous_serial: u32,
        compressed: bool,
    },
    ZoneSyncAck {
        request_id: ArcStr,
        zone_origin: ArcStr,
        serial: u64,
        timestamp: u64,
    },
    WasmModuleAnnounce {
        request_id: ArcStr,
        module_name: ArcStr,
        module_type: WasmModuleType,
        version: u64,
        size_bytes: u64,
        checksum: ArcStr,
        timestamp: u64,
        source_node_id: ArcStr,
        signature: Vec<u8>,
        signer_public_key: Option<ArcStr>,
    },
    WasmModuleSyncRequest {
        request_id: ArcStr,
        node_id: ArcStr,
        module_names: Vec<ArcStr>,
        timestamp: u64,
    },
    WasmModuleSyncResponse {
        request_id: ArcStr,
        node_id: ArcStr,
        modules: Vec<WasmModuleInfo>,
        timestamp: u64,
    },
    SessionRotate {
        session_id: ArcStr,
        peer_id: ArcStr,
        key_version: u64,
        peer_entropy: Vec<u8>,
        timestamp: u64,
    },
    SessionRotateAck {
        session_id: ArcStr,
        peer_id: ArcStr,
        key_version: u64,
        peer_entropy: Vec<u8>,
        timestamp: u64,
    },
    ServerlessFunctionAnnounce(ServerlessFunctionAnnounce),
    ServerlessInvokeRequest(ServerlessInvokeRequest),
    ServerlessInvokeResponse(ServerlessInvokeResponse),
    GenesisKeyTransition {
        sequence: u32,
        new_key_fingerprint: ArcStr,
        announced_by: ArcStr,
        timestamp: u64,
        genesis_signature: Vec<u8>,
    },
    RevokeGlobalNode {
        node_id: ArcStr,
        reason: ArcStr,
        timestamp: u64,
        genesis_signature: Vec<u8>,
    },
    SiteTlsCertSync(SiteTlsCertSync),
    SiteTlsCertRequest(SiteTlsCertRequest),
    SiteTlsCertResponse(SiteTlsCertResponse),
    OrgKeySignRequest {
        request_id: ArcStr,
        org_id: ArcStr,
        org_public_key: crate::mesh::organization::OrgPublicKey,
        timestamp: u64,
        signature: Vec<u8>,
    },
    OrgKeySignResponse {
        request_id: ArcStr,
        org_id: ArcStr,
        signature: Vec<u8>,
        signer_node_id: ArcStr,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OwnershipChallengeProof {
    Http01 { key_authorization: String },
    Dns01 { txt_record_value: String },
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },
    #[error("Message is not signable")]
    NotSignable,
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProxyCachePreferences {
    pub enable: bool,
    pub inactive: u64,
    pub valid_status: Vec<u32>,
    pub methods: Vec<String>,
    pub use_stale: Vec<String>,
    pub min_uses: u32,
    pub stale_while_revalidate: u64,
    pub stale_if_error: u64,
}

impl From<&crate::config::site::ProxyCacheConfig> for ProxyCachePreferences {
    fn from(config: &crate::config::site::ProxyCacheConfig) -> Self {
        Self {
            enable: config.enable.unwrap_or(false),
            inactive: config.inactive,
            valid_status: config.valid_status.iter().map(|&v| v as u32).collect(),
            methods: config.methods.clone(),
            use_stale: config.use_stale.clone(),
            min_uses: config.min_uses,
            stale_while_revalidate: config.stale_while_revalidate.unwrap_or(0),
            stale_if_error: config.stale_if_error.unwrap_or(0),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Default,
    serde::Serialize,
    serde::Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct MeshCapabilities {
    pub can_route: bool,
    pub can_proxy: bool,
    pub can_serve_dns: bool,
    pub is_global: bool,
    pub waf_enabled: bool,
    pub max_hops: u8,
    pub supported_services: Vec<String>,
    pub preferred_transport: Option<MeshTransportType>,
    pub supported_protocols: Vec<String>,
}

impl MeshCapabilities {
    pub fn from_config(config: &crate::mesh::config::MeshConfig, role: MeshNodeRole) -> Self {
        use crate::mesh::transports::MeshTransportType;

        let preferred = MeshTransportType::Quic;

        let dht_config = config.dht.as_ref();

        let dns_mesh_mode_only = dht_config.map(|c| c.dns_mesh_mode_only).unwrap_or(true);

        let dns_server_enabled = dht_config.map(|c| c.dns_server_enabled).unwrap_or(false);

        let proxy_to_origins = dht_config.map(|c| c.proxy_to_origins).unwrap_or(false);

        let can_host_origins = dht_config.map(|c| c.can_host_origins).unwrap_or(false);

        let mut supported_services = Vec::new();

        if role.is_global() {
            supported_services.push("global".to_string());
        }
        if role.is_edge() || role.contains(MeshNodeRole::EDGE) {
            supported_services.push("edge".to_string());
        }
        if role.contains(MeshNodeRole::ORIGIN) || can_host_origins {
            supported_services.push("origin".to_string());
        }
        if dns_server_enabled && !dns_mesh_mode_only {
            supported_services.push("dnsRecursive".to_string());
        }
        if dns_mesh_mode_only && dns_server_enabled {
            supported_services.push("dnsAuthority".to_string());
        }
        if proxy_to_origins {
            supported_services.push("proxyOrigin".to_string());
        }

        Self {
            can_route: config.routing.enabled,
            can_proxy: !config.disable_direct_origin,
            can_serve_dns: !dns_mesh_mode_only || (config.dht.is_some() && role.is_global()),
            is_global: role.is_global(),
            waf_enabled: true,
            max_hops: config.routing.max_hops,
            supported_services,
            preferred_transport: Some(preferred),
            supported_protocols: vec!["http/1.1".to_string(), "h2".to_string(), "h3".to_string()],
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpstreamInfo {
    pub upstream_id: String,
    pub upstream_url: Option<String>,
    pub geo: Option<String>,
    pub is_local: bool,
    pub owner_node_id: String,
    pub peered_wafs: Vec<String>,
    pub url_hash: String,
    pub waf_policy: Option<WafPolicy>,
    pub protocol: UpstreamProtocol,
}

impl UpstreamInfo {
    pub fn new_secure(
        upstream_id: String,
        upstream_url: String,
        geo: Option<String>,
        is_local: bool,
        owner_node_id: String,
        peered_wafs: Vec<String>,
    ) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        upstream_url.hash(&mut hasher);
        let url_hash = format!("{:016x}", hasher.finish());

        Self {
            upstream_id,
            upstream_url: None,
            geo,
            is_local,
            owner_node_id,
            peered_wafs,
            url_hash,
            waf_policy: None,
            protocol: UpstreamProtocol::default(),
        }
    }

    pub fn with_url(mut self, url: String) -> Self {
        self.upstream_url = Some(url);
        self
    }

    pub fn has_access(&self, requester_node_id: &str) -> bool {
        if self.is_local || self.peered_wafs.is_empty() {
            return true;
        }
        self.peered_wafs.contains(&requester_node_id.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpstreamOwner {
    pub owner_node_id: String,
    pub peered_wafs: Vec<String>,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Default,
    schemars::JsonSchema,
)]
pub enum UpstreamProtocol {
    #[default]
    Unknown = 0,
    Http = 1,
    Https = 2,
    Tcp = 3,
    Udp = 4,
    Grpc = 5,
    Websocket = 6,
    Websockets = 7,
    Serverless = 9,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, schemars::JsonSchema)]
pub struct WafPolicy {
    pub skip_rate_limit: bool,
    pub skip_auth_challenge: bool,
    pub skip_pow_challenge: bool,
    pub skip_honeypot: bool,
    pub enabled_rules: Vec<String>,
    pub disabled_rules: Vec<String>,
    pub threat_level: u32,
    pub enable_bot_protection: bool,
    pub enable_ip_feed: bool,
    pub enable_threat_level: bool,
    pub enable_traffic_shaping: bool,
    pub policy_mode: String,
    pub priority_tier: u32,
    pub rate_limit_override: Option<RateLimitOverride>,
    pub enable_mesh_key_exchange: bool,
    pub enable_mesh_auditing: bool,
    pub mesh_id: Option<String>,
    pub mesh_global_node_url: Option<String>,
    pub mesh_audit_urls: Vec<String>,
    pub fallback_to_regular_pow: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, schemars::JsonSchema)]
pub struct RateLimitOverride {
    pub requests_per_second: Option<u64>,
    pub requests_per_minute: Option<u64>,
    pub requests_per_hour: Option<u64>,
    pub concurrent_connections: Option<u64>,
    pub bandwidth_mbps: Option<u64>,
    pub burst_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AnnounceAction {
    Add,
    Update,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GlobalNodeAction {
    Add,
    Remove,
    UpdateKeyExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LookupType {
    KeyValue,
    Route,
    Peer,
    Certificate,
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum ThreatType {
    Unspecified,
    IpBlock,
    IpThrottle,
    RateLimitViolation,
    SuspiciousActivity,
    AsnBlock,
    DomainBlock,
    UrlBlock,
    CertBlock,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum ThreatSeverity {
    Unspecified,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct ThreatIndicator {
    pub threat_type: ThreatType,
    pub indicator_value: String,
    pub severity: ThreatSeverity,
    pub reason: String,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub timestamp: u64,
    pub site_scope: String,
    pub rate_limit_requests: Option<u64>,
    pub rate_limit_window_secs: Option<u64>,
    pub suspicious_pattern: Option<String>,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
}

#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct DhtRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub content_hash: Vec<u8>,
}

impl DhtRecord {
    pub fn compute_content_hash(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.value);
        hasher.finalize().to_vec()
    }

    pub fn verify_content_hash(&self) -> bool {
        if self.content_hash.is_empty() {
            return true;
        }
        self.compute_content_hash() == self.content_hash
    }
}

#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub node_id: String,
    pub upstream_url: String,
    pub waf_policy: Option<WafPolicy>,
    pub hops: u8,
    pub ttl: Duration,
    pub score: f64,
    pub priority_tier: u32,
    pub tier_claim: Option<TierClaim>,
    pub org_id: Option<String>,
    pub mesh_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlternativeProvider {
    pub node_id: String,
    pub priority_tier: u32,
}

#[derive(Debug, Clone)]
pub struct RouteQueryResult {
    pub query_id: String,
    pub upstream_id: String,
    pub providers: Vec<ProviderInfo>,
    pub discovered_at: Instant,
}

#[derive(Debug, Clone)]
pub struct PendingQuery {
    pub query_id: String,
    pub upstream_id: String,
    pub initiator: String,
    pub created_at: Instant,
    pub max_hops: u8,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshPeerInfo {
    pub node_id: String,
    pub address: String,
    pub role: MeshNodeRole,
    pub capabilities: MeshCapabilities,
    pub is_global: bool,
    pub latency_ms: Option<u32>,
    pub upstreams: Vec<String>,
    pub is_trusted: bool,
    pub quic_port: Option<u32>,
    pub wireguard_port: Option<u32>,
    pub advertised_port: Option<u32>,
    /// True if this global node's DNS server is healthy and serving queries.
    /// Only meaningful for global nodes which are required to serve DNS.
    pub dns_serving_healthy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AckStatus {
    Success,
    Processing,
    InvalidMessage,
    Unauthorized,
    NotFound,
    RateLimited,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WasmModuleType {
    Plugin = 0,
    Serverless = 1,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WasmModuleInfo {
    pub module_name: String,
    pub module_type: WasmModuleType,
    pub version: u64,
    pub size_bytes: u64,
    pub checksum: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerlessFunctionAnnounce {
    pub function_name: String,
    pub node_id: Option<String>,
    pub version: u64,
    pub checksum: String,
    pub routes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub priority: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerlessPermissionClaim {
    pub function_name: String,
    pub caller_node_id: String,
    pub caller_org_id: Option<String>,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

impl ServerlessPermissionClaim {
    pub fn new(
        function_name: String,
        caller_node_id: String,
        caller_org_id: Option<String>,
    ) -> Self {
        Self {
            function_name,
            caller_node_id,
            caller_org_id,
            timestamp: crate::utils::safe_unix_timestamp(),
            nonce: uuid::Uuid::new_v4().to_string(),
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, key: &[u8]) {
        let data = self.get_signable_data();
        self.signature = crate::mesh::cert::sign_ed25519(&data, key).unwrap_or_default();
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let data = self.get_signable_data();
        let Some(public_key) = crate::mesh::cert::get_ed25519_public_key(key) else {
            return false;
        };
        crate::mesh::cert::verify_ed25519(&data, &self.signature, &public_key)
    }

    fn get_signable_data(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.function_name,
            self.caller_node_id,
            self.caller_org_id.as_deref().unwrap_or("none"),
            self.timestamp,
            self.nonce
        )
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerlessInvokeRequest {
    pub function_name: String,
    pub caller_node_id: String,
    pub timestamp: u64,
    pub call_signature: Vec<u8>,
    pub permission_claim: Option<ServerlessPermissionClaim>,
}

impl ServerlessInvokeRequest {
    pub fn new(function_name: String, caller_node_id: String) -> Self {
        Self {
            function_name,
            caller_node_id,
            timestamp: crate::utils::safe_unix_timestamp(),
            call_signature: Vec::new(),
            permission_claim: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerlessInvokeResponse {
    pub function_name: String,
    pub caller_node_id: String,
    pub timestamp: u64,
    pub response_data: Vec<u8>,
    pub success: bool,
    pub error_message: String,
    pub execution_time_ms: u64,
    pub response_signature: Vec<u8>,
}

impl ServerlessInvokeResponse {
    pub fn new(function_name: String, caller_node_id: String) -> Self {
        Self {
            function_name,
            caller_node_id,
            timestamp: crate::utils::safe_unix_timestamp(),
            response_data: Vec::new(),
            success: true,
            error_message: String::new(),
            execution_time_ms: 0,
            response_signature: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteTlsCertEntry {
    pub site_id: String,
    pub cert_data: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteTlsCertSync {
    pub site_id: String,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub certs: Vec<SiteTlsCertEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteTlsCertRequest {
    pub site_id: String,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiteTlsCertResponse {
    pub site_id: String,
    pub node_id: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
    pub certs: Vec<SiteTlsCertEntry>,
}

#[path = "protocol_message.rs"]
mod protocol_message;
#[path = "protocol_proto_decode.rs"]
mod protocol_proto_decode;
#[path = "protocol_proto_encode.rs"]
mod protocol_proto_encode;
#[path = "protocol_types.rs"]
mod protocol_types;

pub use protocol_proto_decode::ProtocolError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageCategory {
    Handshake,
    Sync,
    Routing,
    Upstream,
    KeyExchange,
    Dht,
    Lookup,
    Health,
    Peer,
    Organization,
    ThreatIntel,
    Yara,
    Dns,
    Anycast,
    ZoneSync,
    Wasm,
    Config,
    System,
    Serverless,
}

impl MessageCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Handshake => "Handshake",
            Self::Sync => "Sync",
            Self::Routing => "Routing",
            Self::Upstream => "Upstream",
            Self::KeyExchange => "KeyExchange",
            Self::Dht => "DHT",
            Self::Lookup => "Lookup",
            Self::Health => "Health",
            Self::Peer => "Peer",
            Self::Organization => "Organization",
            Self::ThreatIntel => "ThreatIntel",
            Self::Yara => "YARA",
            Self::Dns => "DNS",
            Self::Anycast => "Anycast",
            Self::ZoneSync => "ZoneSync",
            Self::Wasm => "WASM",
            Self::Config => "Config",
            Self::System => "System",
            Self::Serverless => "Serverless",
        }
    }
}

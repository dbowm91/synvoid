use base64::Engine;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use prost::Message;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArcStr(Arc<str>);

impl ArcStr {
    pub fn new(s: impl Into<String>) -> Self {
        Self(Arc::from(s.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_arc(&self) -> &Arc<str> {
        &self.0
    }
}

impl std::fmt::Display for ArcStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for ArcStr {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<&str> for ArcStr {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
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
        Ok(Self(Arc::from(s)))
    }
}

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/mesh.rs"));
}

use crate::mesh::config::MeshNodeRole;
use crate::mesh::organization::TierClaim;
use crate::mesh::transports::MeshTransportType;

pub const MESH_MESSAGE_VERSION: u8 = 1;
const COMPRESSION_THRESHOLD: usize = 512;

const SIGNATURE_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const REPLAY_WINDOW_SECS: u64 = 300;
const MAX_REPLAY_CACHE_SIZE: usize = 10000;

#[derive(Clone)]
pub struct MeshMessageSigner {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key_bytes: Vec<u8>,
}

impl MeshMessageSigner {
    pub fn new(secret_key: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_bytes: verifying_key.as_bytes().to_vec(),
        }
    }

    pub fn from_secret(secret_key: ed25519_dalek::SecretKey) -> Self {
        let signing_key = SigningKey::from(&secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_bytes: verifying_key.as_bytes().to_vec(),
        }
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::fill(&mut key);
        key
    }

    pub fn sign(&self, content: &str) -> Vec<u8> {
        let signature = self.signing_key.sign(content.as_bytes());
        signature.to_bytes().to_vec()
    }

    pub fn verify(&self, content: &str, signature: &[u8], public_key: &[u8]) -> bool {
        if signature.len() != 64 || public_key.len() != 32 {
            return false;
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature);

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(public_key);

        match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
            Ok(pk) => pk
                .verify(
                    content.as_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&sig_array),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    pub fn get_public_key(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.verifying_key_bytes)
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key_bytes.clone()
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayResult {
    Valid,
    ReplayDetected,
    ExpiredTimestamp,
    FutureTimestamp,
}

pub struct AuthChallenge {
    challenge: [u8; 32],
    created_at: Instant,
}

impl AuthChallenge {
    pub fn new() -> Self {
        let mut challenge = [0u8; 32];
        rand::fill(&mut challenge);
        Self {
            challenge,
            created_at: Instant::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(60)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.challenge
    }

    pub fn as_base64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.challenge)
    }
}

pub struct PendingAuthChallenge {
    challenge: String,
    expected_signer: String,
    created_at: Instant,
}

impl PendingAuthChallenge {
    pub fn new(challenge: String, expected_signer: String) -> Self {
        Self {
            challenge,
            expected_signer,
            created_at: Instant::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(60)
    }

    pub fn verify_response(&self, response: &str, signer: &MeshMessageSigner) -> bool {
        let expected = format!("{}:{}", self.challenge, self.expected_signer);
        let pk = signer.get_public_key_bytes();
        signer.verify(&expected, response.as_bytes(), &pk)
    }
}

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
    },
    HelloAck {
        version: u8,
        node_id: ArcStr,
        role: MeshNodeRole,
        session_id: ArcStr,
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
    },
    UpstreamUpdate {
        upstream_id: ArcStr,
        info: UpstreamInfo,
        signature: Vec<u8>,
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
    UpstreamRegistrationRequest {
        request_id: ArcStr,
        upstream_id: ArcStr,
        upstream_url: ArcStr,
        org_id: Option<ArcStr>,
        requesting_node_id: ArcStr,
        timestamp: u64,
        signature: Vec<u8>,
    },
    UpstreamRegistrationResponse {
        request_id: ArcStr,
        upstream_id: ArcStr,
        approved: bool,
        rejection_reason: Option<ArcStr>,
        global_node_id: ArcStr,
        global_node_signature: Option<Vec<u8>>,
        timestamp: u64,
    },
    UpstreamVerificationQuery {
        request_id: ArcStr,
        upstream_id: ArcStr,
        querying_node_id: ArcStr,
        timestamp: u64,
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
}

impl MeshMessage {
    pub fn generate_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn generate_nonce() -> ArcStr {
        let mut bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut bytes);
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes).into()
    }

    pub fn message_id(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Self::RouteQuery { query_id, .. } => Some(query_id.as_str().into()),
            Self::RouteResponse { query_id, .. } => Some(query_id.as_str().into()),
            Self::LookupRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::LookupBatchRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::TopologySyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::SeedListRequest { node_id, .. } => Some(node_id.as_str().into()),
            Self::UpstreamUrlRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::PeerAnnounce { node_id, .. } => Some(node_id.as_str().into()),
            Self::ThreatAnnounce { request_id, .. } => Some(request_id.as_str().into()),
            Self::ThreatSyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleAnnounce { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleSyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleAcknowledgement {
                original_request_id,
                ..
            } => Some(original_request_id.as_str().into()),
            Self::YaraRuleSubmission { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleSubmissionResponse {
                original_request_id,
                ..
            } => Some(original_request_id.as_str().into()),
            Self::ThreatAcknowledgement {
                original_request_id,
                ..
            } => Some(original_request_id.as_str().into()),
            Self::DhtSnapshotRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtSnapshotResponse { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtSyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::UpstreamRegistrationRequest { request_id, .. } => {
                Some(request_id.as_str().into())
            }
            Self::UpstreamRegistrationResponse { request_id, .. } => {
                Some(request_id.as_str().into())
            }
            Self::UpstreamVerificationQuery { request_id, .. } => Some(request_id.as_str().into()),
            Self::UpstreamVerificationResponse { request_id, .. } => {
                Some(request_id.as_str().into())
            }
            #[cfg(feature = "dns")]
            Self::DnsRegistrationRequest { request_id, .. } => Some(request_id.as_str().into()),
            #[cfg(feature = "dns")]
            Self::DnsRegistrationResponse { request_id, .. } => Some(request_id.as_str().into()),
            #[cfg(feature = "dns")]
            Self::DnsVerificationUpdate { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtRecordAnnounce { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtAntiEntropyRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtAntiEntropyResponse { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtRecordPush { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtRecordPushAck { request_id, .. } => Some(request_id.as_str().into()),
            Self::NetworkPolicyUpdate { source_node_id, .. } => {
                Some(source_node_id.as_str().into())
            }
            Self::GlobalNodeBlocklistUpdate { source_node_id, .. } => {
                Some(source_node_id.as_str().into())
            }
            Self::UpstreamBlocked {
                mesh_identifier,
                service_id,
                origin_node_id,
                ..
            } => Some(std::borrow::Cow::Owned(format!(
                "block:{}:{}:{}",
                mesh_identifier, service_id, origin_node_id
            ))),
            _ => None,
        }
    }

    pub fn requires_reliable_delivery(&self) -> bool {
        matches!(
            self,
            Self::RouteQuery { .. }
                | Self::UpstreamAnnounce { .. }
                | Self::UpstreamUpdate { .. }
                | Self::LookupRequest { .. }
                | Self::LookupBatchRequest { .. }
                | Self::TopologySyncRequest { .. }
                | Self::SeedListRequest { .. }
                | Self::PeerAnnounce { .. }
                | Self::ThreatAnnounce { .. }
                | Self::ThreatSyncRequest { .. }
                | Self::ThreatAcknowledgement { .. }
                | Self::ReputationUpdate { .. }
                | Self::DhtSnapshotRequest { .. }
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, prost::EncodeError> {
        let pb: proto::MeshMessage = self.into();
        let mut buf = Vec::with_capacity(pb.encoded_len());
        pb.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let pb: proto::MeshMessage = proto::MeshMessage::decode(data).ok()?;
        pb.try_into().ok()
    }

    pub fn encode_with_length(&self) -> Vec<u8> {
        let encoded = self.encode().unwrap_or_else(|e| {
            tracing::error!("Failed to encode mesh message: {}", e);
            Vec::new()
        });
        let len = (encoded.len() as u32).to_be_bytes().to_vec();
        len.into_iter().chain(encoded.into_iter()).collect()
    }

    pub fn decode_with_length(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        let msg = Self::decode(&data[4..4 + len])?;
        Some((msg, 4 + len))
    }

    pub fn encode_compressed(&self) -> Result<Vec<u8>, std::io::Error> {
        let encoded = self
            .encode()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if encoded.len() < COMPRESSION_THRESHOLD {
            return Ok(encoded);
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&encoded)?;
        encoder.finish()
    }

    pub fn decode_compressed(data: &[u8]) -> Option<Self> {
        if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
            return Self::decode(data);
        }
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).ok()?;
        Self::decode(&decompressed)
    }

    pub fn requires_signature(&self) -> bool {
        matches!(
            self,
            Self::RouteResponse { .. }
                | Self::UpstreamAnnounce { .. }
                | Self::UpstreamUpdate { .. }
                | Self::ThreatAnnounce { .. }
                | Self::ThreatSyncResponse { .. }
                | Self::ReputationUpdate { .. }
        )
    }

    pub fn get_signable_content(&self) -> Option<String> {
        match self {
            Self::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                ..
            } => Some(format!(
                "{},{},{},{},{},{}",
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )),
            Self::UpstreamAnnounce {
                upstream_id,
                action,
                ..
            } => Some(format!("{},{:?}", upstream_id, action)),
            Self::UpstreamUpdate {
                upstream_id, info, ..
            } => Some(format!(
                "{},{},{}",
                upstream_id, info.upstream_id, info.owner_node_id
            )),
            Self::UpstreamUrlResponse {
                request_id,
                upstream_id,
                upstream_url,
                ..
            } => Some(format!("{},{},{}", request_id, upstream_id, upstream_url)),
            Self::ThreatAnnounce {
                request_id,
                source_node_id,
                highest_severity,
                ..
            } => Some(format!(
                "{},{},{:?},{}",
                request_id,
                source_node_id,
                highest_severity,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )),
            Self::ThreatSyncResponse {
                request_id,
                version,
                indicators,
                ..
            } => Some(format!("{},{},{}", request_id, version, indicators.len())),
            Self::ReputationUpdate {
                node_id,
                reputation_score,
                ..
            } => Some(format!(
                "{},{},{}",
                node_id,
                reputation_score,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )),
            _ => None,
        }
    }

    #[deprecated(
        since = "0.3.0",
        note = "HMAC verification no longer supported - use Ed25519 via MeshMessageSigner"
    )]
    pub fn verify_signature_with_signer(
        &self,
        _signer: &MeshMessageSigner,
    ) -> Result<(), SignatureError> {
        tracing::warn!(
            "Deprecated verify_signature_with_signer called - HMAC is no longer supported"
        );
        Err(SignatureError::VerificationFailed(
            "HMAC verification deprecated".to_string(),
        ))
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use MeshMessageSigner.verify() with explicit public key"
    )]
    pub fn verify_signature(&self, expected_signer: &str) -> Result<(), SignatureError> {
        tracing::warn!(
            "Deprecated verify_signature called - signature not actually verified for {}",
            expected_signer
        );
        Err(SignatureError::VerificationFailed(
            "verify_signature is deprecated - use MeshMessageSigner.verify() with explicit public key".to_string(),
        ))
    }
}

impl From<&MeshMessage> for proto::MeshMessage {
    fn from(msg: &MeshMessage) -> Self {
        match msg {
            MeshMessage::Hello {
                version,
                node_id,
                role,
                capabilities,
                upstreams,
                auth_token,
                network_id,
                global_node_key,
                timestamp,
                nonce,
                is_trusted,
                quic_port,
                wireguard_port,
                public_key,
                pow_nonce,
                pow_public_key,
            } => proto::MeshMessage {
                message_type: 1,
                payload: Some(proto::mesh_message::Payload::Hello(proto::Hello {
                    version: *version as u32,
                    node_id: node_id.to_string(),
                    roles: role.bits() as u32,
                    capabilities: Some(capabilities.into()),
                    upstreams: upstreams
                        .iter()
                        .map(|(k, v)| (k.clone(), v.into()))
                        .collect(),
                    auth_token: auth_token.as_ref().map(|s| s.to_string()),
                    network_id: network_id.as_ref().map(|s| s.to_string()),
                    global_node_key: global_node_key.as_ref().map(|s| s.to_string()),
                    timestamp: *timestamp,
                    nonce: nonce.as_ref().map(|s| s.to_string()),
                    is_trusted: Some(*is_trusted),
                    quic_port: *quic_port,
                    wireguard_port: *wireguard_port,
                    public_key: public_key.as_ref().map(|s| s.to_string()),
                    pow_nonce: *pow_nonce,
                    pow_public_key: pow_public_key.as_ref().map(|s| s.to_string()),
                })),
            },
            MeshMessage::HelloAck {
                version,
                node_id,
                role,
                session_id,
                upstreams,
                auth_token,
                network_id,
                global_node_key,
                timestamp,
                nonce,
                is_trusted,
                quic_port,
                wireguard_port,
                public_key,
            } => proto::MeshMessage {
                message_type: 2,
                payload: Some(proto::mesh_message::Payload::HelloAck(proto::HelloAck {
                    version: *version as u32,
                    node_id: node_id.to_string(),
                    roles: role.bits() as u32,
                    session_id: session_id.to_string(),
                    upstreams: upstreams
                        .iter()
                        .map(|(k, v)| (k.clone(), v.into()))
                        .collect(),
                    auth_token: auth_token.as_ref().map(|s| s.to_string()),
                    network_id: network_id.as_ref().map(|s| s.to_string()),
                    global_node_key: global_node_key.as_ref().map(|s| s.to_string()),
                    timestamp: *timestamp,
                    nonce: nonce.as_ref().map(|s| s.to_string()),
                    is_trusted: Some(*is_trusted),
                    quic_port: *quic_port,
                    wireguard_port: *wireguard_port,
                    public_key: public_key.as_ref().map(|s| s.to_string()),
                })),
            },
            MeshMessage::SyncRequest { node_id } => proto::MeshMessage {
                message_type: 3,
                payload: Some(proto::mesh_message::Payload::SyncRequest(
                    proto::SyncRequest {
                        node_id: node_id.to_string(),
                    },
                )),
            },
            MeshMessage::SyncResponse {
                nodes,
                upstreams,
                timestamp,
            } => proto::MeshMessage {
                message_type: 4,
                payload: Some(proto::mesh_message::Payload::SyncResponse(
                    proto::SyncResponse {
                        nodes: nodes.iter().map(|n| n.into()).collect(),
                        upstreams: upstreams
                            .iter()
                            .map(|(k, v)| (k.clone(), v.into()))
                            .collect(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::RouteQuery {
                query_id,
                max_hops,
                upstream_id,
                initiator,
                sequence,
                timestamp,
                nonce,
            } => proto::MeshMessage {
                message_type: 5,
                payload: Some(proto::mesh_message::Payload::RouteQuery(
                    proto::RouteQuery {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        max_hops: *max_hops as u32,
                        initiator: initiator.to_string(),
                        sequence: *sequence,
                        timestamp: *timestamp,
                        nonce: nonce.to_string(),
                    },
                )),
            },
            MeshMessage::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                signature,
                sequence,
                timestamp,
                nonce,
                upstream_url,
                waf_policy,
                priority_tier,
                tier_claim,
                org_id,
                mesh_name,
            } => proto::MeshMessage {
                message_type: 6,
                payload: Some(proto::mesh_message::Payload::RouteResponse(
                    proto::RouteResponse {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        provider_node_id: provider_node_id.to_string(),
                        hops: *hops as u32,
                        ttl_secs: *ttl_secs,
                        signature: signature.clone(),
                        sequence: *sequence,
                        timestamp: *timestamp,
                        nonce: nonce.to_string(),
                        upstream_url: upstream_url.as_ref().map(|s| s.to_string()),
                        waf_policy: waf_policy.as_ref().map(|p| p.into()),
                        priority_tier: *priority_tier,
                        tier_claim: tier_claim.as_ref().map(|tc| proto::TierClaim {
                            tier: tc.tier,
                            key_id: tc.key_id.to_string(),
                            org_id: tc.org_id.to_string(),
                            mesh_id: tc.mesh_id.to_string(),
                            timestamp: tc.timestamp,
                            nonce: tc.nonce.to_string(),
                            signature: tc.signature.clone(),
                        }),
                        org_id: org_id.as_ref().map(|s| s.to_string()),
                        mesh_name: mesh_name.as_ref().map(|s| s.to_string()),
                    },
                )),
            },
            MeshMessage::RouteResponseAck {
                query_id,
                upstream_id,
                provider_node_id,
            } => proto::MeshMessage {
                message_type: 40,
                payload: Some(proto::mesh_message::Payload::RouteResponseAck(
                    proto::RouteResponseAck {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        provider_node_id: provider_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::RouteNotFound {
                query_id,
                upstream_id,
            } => proto::MeshMessage {
                message_type: 7,
                payload: Some(proto::mesh_message::Payload::RouteNotFound(
                    proto::RouteNotFound {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                    },
                )),
            },
            MeshMessage::RouteRejected {
                query_id,
                upstream_id,
                reason,
                alternatives,
            } => proto::MeshMessage {
                message_type: 50,
                payload: Some(proto::mesh_message::Payload::RouteRejected(
                    proto::RouteRejected {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        reason: reason.to_string(),
                        alternatives: alternatives
                            .iter()
                            .map(|a| proto::AlternativeProvider {
                                node_id: a.node_id.to_string(),
                                priority_tier: a.priority_tier,
                            })
                            .collect(),
                    },
                )),
            },
            MeshMessage::TierKeyAnnounce {
                org_id,
                key,
                signature,
            } => proto::MeshMessage {
                message_type: 51,
                payload: Some(proto::mesh_message::Payload::TierKeyAnnounce(
                    proto::TierKeyAnnounce {
                        org_id: org_id.to_string(),
                        key: Some(proto::TierKey {
                            key_id: key.key_id.to_string(),
                            tier: key.tier,
                            key: key.key.clone(),
                            valid_from: key.valid_from,
                            valid_until: key.valid_until,
                            issued_by: key.issued_by.to_string(),
                            revoked: key.revoked,
                        }),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::TierKeyRevoke {
                org_id,
                key_id,
                signature,
            } => proto::MeshMessage {
                message_type: 52,
                payload: Some(proto::mesh_message::Payload::TierKeyRevoke(
                    proto::TierKeyRevoke {
                        org_id: org_id.to_string(),
                        key_id: key_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::TierKeyQuery {
                request_id,
                org_id,
                requested_tier,
            } => proto::MeshMessage {
                message_type: 53,
                payload: Some(proto::mesh_message::Payload::TierKeyQuery(
                    proto::TierKeyQuery {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        requested_tier: requested_tier.unwrap_or(0),
                    },
                )),
            },
            MeshMessage::TierKeyQueryResponse {
                request_id,
                keys,
                signature,
            } => proto::MeshMessage {
                message_type: 54,
                payload: Some(proto::mesh_message::Payload::TierKeyQueryResponse(
                    proto::TierKeyQueryResponse {
                        request_id: request_id.to_string(),
                        keys: keys
                            .iter()
                            .map(|k| proto::TierKey {
                                key_id: k.key_id.to_string(),
                                tier: k.tier,
                                key: k.key.clone(),
                                valid_from: k.valid_from,
                                valid_until: k.valid_until,
                                issued_by: k.issued_by.to_string(),
                                revoked: k.revoked,
                            })
                            .collect(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UnspentTierKeyAnnounce {
                org_id,
                tier_keys,
                signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 66,
                payload: Some(proto::mesh_message::Payload::UnspentTierKeyAnnounce(
                    proto::UnspentTierKeyAnnounce {
                        org_id: org_id.to_string(),
                        tier_keys: tier_keys
                            .iter()
                            .map(|k| proto::TierKey {
                                key_id: k.key_id.to_string(),
                                tier: k.tier,
                                key: k.key.clone(),
                                valid_from: k.valid_from,
                                valid_until: k.valid_until,
                                issued_by: k.issued_by.to_string(),
                                revoked: k.revoked,
                            })
                            .collect(),
                        signature: signature.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OrgRegistrationRequest {
                request_id,
                org_name,
                requesting_node_id,
                requesting_node_pubkey,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 60,
                payload: Some(proto::mesh_message::Payload::OrgRegistrationRequest(
                    proto::OrgRegistrationRequest {
                        request_id: request_id.to_string(),
                        org_name: org_name.to_string(),
                        requesting_node_id: requesting_node_id.to_string(),
                        requesting_node_pubkey: requesting_node_pubkey.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgRegistrationResponse {
                request_id,
                org_id,
                org_name,
                approved,
                reason,
                initial_tier_key,
                signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 61,
                payload: Some(proto::mesh_message::Payload::OrgRegistrationResponse(
                    proto::OrgRegistrationResponse {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        org_name: org_name.to_string(),
                        approved: *approved,
                        reason: reason.to_string(),
                        initial_tier_key: initial_tier_key.as_ref().map(|k| proto::TierKey {
                            key_id: k.key_id.to_string(),
                            tier: k.tier,
                            key: k.key.clone(),
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.to_string(),
                            revoked: k.revoked,
                        }),
                        signature: signature.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OrgInvitationRequest {
                request_id,
                org_id,
                inviter_node_id,
                invited_node_id,
                invited_node_pubkey,
                invitation_token,
                expires_at,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 62,
                payload: Some(proto::mesh_message::Payload::OrgInvitationRequest(
                    proto::OrgInvitationRequest {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        inviter_node_id: inviter_node_id.to_string(),
                        invited_node_id: invited_node_id.to_string(),
                        invited_node_pubkey: invited_node_pubkey
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        invitation_token: invitation_token.to_string(),
                        expires_at: *expires_at,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgInvitationAccept {
                request_id,
                org_id,
                invited_node_id,
                invitation_token,
                proof_of_key,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 63,
                payload: Some(proto::mesh_message::Payload::OrgInvitationAccept(
                    proto::OrgInvitationAccept {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        invited_node_id: invited_node_id.to_string(),
                        invitation_token: invitation_token.to_string(),
                        proof_of_key: proof_of_key.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgInvitationResponse {
                request_id,
                org_id,
                accepted,
                org_key,
                reason,
                signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 64,
                payload: Some(proto::mesh_message::Payload::OrgInvitationResponse(
                    proto::OrgInvitationResponse {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        accepted: *accepted,
                        org_key: org_key.as_ref().map(|k| proto::TierKey {
                            key_id: k.key_id.to_string(),
                            tier: k.tier,
                            key: k.key.clone(),
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.to_string(),
                            revoked: k.revoked,
                        }),
                        reason: reason.to_string(),
                        signature: signature.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::GlobalNodeAnnounce {
                node_id,
                public_key,
                action,
                timestamp,
                signature,
                key_exchange_endpoint,
            } => proto::MeshMessage {
                message_type: 66,
                payload: Some(proto::mesh_message::Payload::GlobalNodeAnnounce(
                    proto::GlobalNodeAnnounce {
                        node_id: node_id.to_string(),
                        public_key: public_key.to_string(),
                        action: *action as u32,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        key_exchange_endpoint: key_exchange_endpoint
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                    },
                )),
            },
            MeshMessage::OrgMemberAnnounce {
                org_id,
                member_node_id,
                announced_by,
                joined_at,
                signature,
            } => proto::MeshMessage {
                message_type: 65,
                payload: Some(proto::mesh_message::Payload::OrgMemberAnnounce(
                    proto::OrgMemberAnnounce {
                        org_id: org_id.to_string(),
                        member_node_id: member_node_id.to_string(),
                        announced_by: announced_by.to_string(),
                        joined_at: *joined_at,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamUrlRequest {
                request_id,
                upstream_id,
                url_hash,
            } => proto::MeshMessage {
                message_type: 8,
                payload: Some(proto::mesh_message::Payload::UpstreamUrlRequest(
                    proto::UpstreamUrlRequest {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        url_hash: url_hash.to_string(),
                    },
                )),
            },
            MeshMessage::UpstreamUrlResponse {
                request_id,
                upstream_id,
                upstream_url,
                signature,
            } => proto::MeshMessage {
                message_type: 9,
                payload: Some(proto::mesh_message::Payload::UpstreamUrlResponse(
                    proto::UpstreamUrlResponse {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        upstream_url: upstream_url.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamUrlDenied {
                request_id,
                upstream_id,
            } => proto::MeshMessage {
                message_type: 10,
                payload: Some(proto::mesh_message::Payload::UpstreamUrlDenied(
                    proto::UpstreamUrlDenied {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                    },
                )),
            },
            MeshMessage::UpstreamAnnounce {
                upstream_id,
                action,
                signature,
            } => proto::MeshMessage {
                message_type: 11,
                payload: Some(proto::mesh_message::Payload::UpstreamAnnounce(
                    proto::UpstreamAnnounce {
                        upstream_id: upstream_id.to_string(),
                        action: *action as u32,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamUpdate {
                upstream_id,
                info,
                signature,
            } => proto::MeshMessage {
                message_type: 12,
                payload: Some(proto::mesh_message::Payload::UpstreamUpdate(
                    proto::UpstreamUpdate {
                        upstream_id: upstream_id.to_string(),
                        info: Some(info.into()),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::KeepAlive => proto::MeshMessage {
                message_type: 13,
                payload: Some(proto::mesh_message::Payload::KeepAlive(proto::KeepAlive {})),
            },
            MeshMessage::KeepAliveAck => proto::MeshMessage {
                message_type: 14,
                payload: Some(proto::mesh_message::Payload::KeepAliveAck(
                    proto::KeepAliveAck {},
                )),
            },
            MeshMessage::LookupRequest {
                request_id,
                key,
                lookup_type,
            } => proto::MeshMessage {
                message_type: 25,
                payload: Some(proto::mesh_message::Payload::LookupRequest(
                    proto::LookupRequest {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        lookup_type: *lookup_type as u32,
                    },
                )),
            },
            MeshMessage::LookupResponse {
                request_id,
                key,
                value,
                found,
            } => proto::MeshMessage {
                message_type: 26,
                payload: Some(proto::mesh_message::Payload::LookupResponse(
                    proto::LookupResponse {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        value: value.clone(),
                        found: *found,
                    },
                )),
            },
            MeshMessage::LookupBatchRequest { request_id, keys } => proto::MeshMessage {
                message_type: 27,
                payload: Some(proto::mesh_message::Payload::LookupBatchRequest(
                    proto::LookupBatchRequest {
                        request_id: request_id.to_string(),
                        keys: keys.iter().map(|s| s.to_string()).collect(),
                    },
                )),
            },
            MeshMessage::LookupBatchResponse {
                request_id,
                results,
            } => proto::MeshMessage {
                message_type: 28,
                payload: Some(proto::mesh_message::Payload::LookupBatchResponse(
                    proto::LookupBatchResponse {
                        request_id: request_id.to_string(),
                        results: results
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone().unwrap_or_default()))
                            .collect(),
                    },
                )),
            },
            MeshMessage::PeerHealthCheck { peer_id, timestamp } => proto::MeshMessage {
                message_type: 29,
                payload: Some(proto::mesh_message::Payload::PeerHealthCheck(
                    proto::PeerHealthCheck {
                        peer_id: peer_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::PeerHealthResponse {
                peer_id,
                status,
                latency_ms,
                timestamp,
            } => proto::MeshMessage {
                message_type: 30,
                payload: Some(proto::mesh_message::Payload::PeerHealthResponse(
                    proto::PeerHealthResponse {
                        peer_id: peer_id.to_string(),
                        status: *status as u32,
                        latency_ms: *latency_ms,
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::PeerAnnounce {
                node_id,
                address,
                role,
                capabilities,
                announced_at,
            } => proto::MeshMessage {
                message_type: 31,
                payload: Some(proto::mesh_message::Payload::PeerAnnounce(
                    proto::PeerAnnounce {
                        node_id: node_id.to_string(),
                        address: address.to_string(),
                        role: role.bits() as u32,
                        capabilities: Some(capabilities.into()),
                        announced_at: *announced_at,
                    },
                )),
            },
            MeshMessage::PeerGone { node_id, reason } => proto::MeshMessage {
                message_type: 32,
                payload: Some(proto::mesh_message::Payload::PeerGone(proto::PeerGone {
                    node_id: node_id.to_string(),
                    reason: reason.to_string(),
                })),
            },
            MeshMessage::TopologySyncRequest {
                request_id,
                from_version,
                prefer_delta,
            } => proto::MeshMessage {
                message_type: 33,
                payload: Some(proto::mesh_message::Payload::TopologySyncRequest(
                    proto::TopologySyncRequest {
                        request_id: request_id.to_string(),
                        from_version: *from_version,
                        prefer_delta: *prefer_delta,
                    },
                )),
            },
            MeshMessage::TopologySyncResponse {
                request_id,
                peers,
                upstreams,
                version,
                is_delta,
                removed_peers,
                removed_upstreams,
            } => proto::MeshMessage {
                message_type: 34,
                payload: Some(proto::mesh_message::Payload::TopologySyncResponse(
                    proto::TopologySyncResponse {
                        request_id: request_id.to_string(),
                        peers: peers.iter().map(|p| p.into()).collect(),
                        upstreams: upstreams
                            .iter()
                            .map(|(k, v)| (k.clone(), v.into()))
                            .collect(),
                        version: *version,
                        is_delta: *is_delta,
                        removed_peers: removed_peers.iter().map(|s| s.to_string()).collect(),
                        removed_upstreams: removed_upstreams
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    },
                )),
            },
            MeshMessage::SeedListRequest {
                node_id,
                request_full_mesh,
            } => proto::MeshMessage {
                message_type: 35,
                payload: Some(proto::mesh_message::Payload::SeedListRequest(
                    proto::SeedListRequest {
                        node_id: node_id.to_string(),
                        request_full_mesh: *request_full_mesh,
                    },
                )),
            },
            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version,
                genesis_org_id,
            } => proto::MeshMessage {
                message_type: 36,
                payload: Some(proto::mesh_message::Payload::SeedListResponse(
                    proto::SeedListResponse {
                        global_nodes: global_nodes.iter().map(|p| p.into()).collect(),
                        edge_nodes: edge_nodes.iter().map(|p| p.into()).collect(),
                        version: *version,
                        genesis_org_id: genesis_org_id
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                    },
                )),
            },
            MeshMessage::PeerLoadReport {
                node_id,
                active_connections,
                cpu_load_percent,
                memory_percent,
                requests_per_second,
            } => proto::MeshMessage {
                message_type: 37,
                payload: Some(proto::mesh_message::Payload::PeerLoadReport(
                    proto::PeerLoadReport {
                        node_id: node_id.to_string(),
                        active_connections: *active_connections,
                        cpu_load_percent: *cpu_load_percent,
                        memory_percent: *memory_percent,
                        requests_per_second: *requests_per_second,
                    },
                )),
            },
            MeshMessage::PeerLoadUpdate {
                node_id,
                load_score,
            } => proto::MeshMessage {
                message_type: 38,
                payload: Some(proto::mesh_message::Payload::PeerLoadUpdate(
                    proto::PeerLoadUpdate {
                        node_id: node_id.to_string(),
                        load_score: *load_score,
                    },
                )),
            },
            MeshMessage::RouteUsageReport {
                upstream_id,
                request_count,
                bytes_transferred,
            } => proto::MeshMessage {
                message_type: 39,
                payload: Some(proto::mesh_message::Payload::RouteUsageReport(
                    proto::RouteUsageReport {
                        upstream_id: upstream_id.to_string(),
                        request_count: *request_count,
                        bytes_transferred: *bytes_transferred,
                    },
                )),
            },
            MeshMessage::UpstreamBlocked {
                mesh_identifier,
                service_id,
                blocked_until,
                reason,
                origin_node_id,
            } => proto::MeshMessage {
                message_type: 70,
                payload: Some(proto::mesh_message::Payload::UpstreamBlocked(
                    proto::UpstreamBlocked {
                        mesh_identifier: mesh_identifier.to_string(),
                        service_id: service_id.to_string(),
                        blocked_until: *blocked_until,
                        reason: reason.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::BandwidthReport {
                upstream_id,
                bytes_sent,
                bytes_received,
                request_count,
                interval_secs,
                timestamp,
            } => proto::MeshMessage {
                message_type: 71,
                payload: Some(proto::mesh_message::Payload::BandwidthReport(
                    proto::BandwidthReport {
                        upstream_id: upstream_id.to_string(),
                        bytes_sent: *bytes_sent,
                        bytes_received: *bytes_received,
                        request_count: *request_count,
                        interval_secs: *interval_secs,
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::MeshAck {
                original_message_id,
                status,
                timestamp,
            } => proto::MeshMessage {
                message_type: 41,
                payload: Some(proto::mesh_message::Payload::MeshAck(proto::MeshAck {
                    original_message_id: original_message_id.to_string(),
                    status: *status as u32,
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::AuthChallenge {
                challenge,
                challenge_id,
                expires_at,
            } => proto::MeshMessage {
                message_type: 42,
                payload: Some(proto::mesh_message::Payload::AuthChallenge(
                    proto::AuthChallenge {
                        challenge: challenge.to_string(),
                        challenge_id: challenge_id.to_string(),
                        expires_at: *expires_at,
                    },
                )),
            },
            MeshMessage::AuthResponse {
                challenge_id,
                response,
            } => proto::MeshMessage {
                message_type: 43,
                payload: Some(proto::mesh_message::Payload::AuthResponse(
                    proto::AuthResponse {
                        challenge_id: challenge_id.to_string(),
                        response: response.to_string(),
                    },
                )),
            },
            MeshMessage::Error { code, message } => proto::MeshMessage {
                message_type: 15,
                payload: Some(proto::mesh_message::Payload::Error(proto::Error {
                    code: *code as u32,
                    message: message.to_string(),
                })),
            },
            MeshMessage::ThreatAnnounce {
                request_id,
                indicators,
                highest_severity,
                timestamp,
                source_node_id,
                source_role,
                source_reputation,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 50,
                payload: Some(proto::mesh_message::Payload::ThreatAnnounce(
                    proto::ThreatAnnounce {
                        request_id: request_id.to_string(),
                        indicators: indicators.iter().map(|i| i.into()).collect(),
                        highest_severity: (*highest_severity) as i32,
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        source_role: source_role.bits() as u32,
                        source_reputation: *source_reputation as u64,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::ThreatSyncRequest {
                request_id,
                node_id,
                from_version,
                prefer_delta,
            } => proto::MeshMessage {
                message_type: 51,
                payload: Some(proto::mesh_message::Payload::ThreatSyncRequest(
                    proto::ThreatSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        from_version: *from_version,
                        prefer_delta: *prefer_delta,
                    },
                )),
            },
            MeshMessage::ThreatSyncResponse {
                request_id,
                indicators,
                version,
                is_delta,
                removed_indicators,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 52,
                payload: Some(proto::mesh_message::Payload::ThreatSyncResponse(
                    proto::ThreatSyncResponse {
                        request_id: request_id.to_string(),
                        indicators: indicators.iter().map(|i| i.into()).collect(),
                        version: *version,
                        is_delta: *is_delta,
                        removed_indicators: removed_indicators
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::ThreatAcknowledgement {
                original_request_id,
                node_id,
                accepted,
                reason,
                timestamp,
            } => proto::MeshMessage {
                message_type: 53,
                payload: Some(proto::mesh_message::Payload::ThreatAck(
                    proto::ThreatAcknowledgement {
                        original_request_id: original_request_id.to_string(),
                        node_id: node_id.to_string(),
                        accepted: *accepted,
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ReputationUpdate {
                node_id,
                reputation_score,
                threats_accepted,
                threats_rejected,
                false_positive_reports,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 54,
                payload: Some(proto::mesh_message::Payload::ReputationUpdate(
                    proto::ReputationUpdate {
                        node_id: node_id.to_string(),
                        reputation_score: *reputation_score,
                        threats_accepted: *threats_accepted,
                        threats_rejected: *threats_rejected,
                        false_positive_reports: *false_positive_reports,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleAnnounce {
                request_id,
                version,
                rules,
                timestamp,
                source_node_id,
                source_role,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 86,
                payload: Some(proto::mesh_message::Payload::YaraRuleAnnounce(
                    proto::YaraRuleAnnounce {
                        request_id: request_id.to_string(),
                        version: version.clone(),
                        rules: rules.clone(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        source_role: source_role.bits() as u32,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleSyncRequest {
                request_id,
                node_id,
                version,
            } => proto::MeshMessage {
                message_type: 87,
                payload: Some(proto::mesh_message::Payload::YaraRuleSyncRequest(
                    proto::YaraRuleSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        version: version.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleSyncResponse {
                request_id,
                version,
                rules,
                is_full,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 88,
                payload: Some(proto::mesh_message::Payload::YaraRuleSyncResponse(
                    proto::YaraRuleSyncResponse {
                        request_id: request_id.to_string(),
                        version: version.clone(),
                        rules: rules.clone(),
                        is_full: *is_full,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleAcknowledgement {
                original_request_id,
                node_id,
                accepted,
                reason,
                timestamp,
            } => proto::MeshMessage {
                message_type: 89,
                payload: Some(proto::mesh_message::Payload::YaraRuleAck(
                    proto::YaraRuleAcknowledgement {
                        original_request_id: original_request_id.to_string(),
                        node_id: node_id.to_string(),
                        accepted: *accepted,
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::YaraRuleSubmission {
                request_id,
                submission_id,
                node_id,
                timestamp,
                signature,
                rules,
                description,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 90,
                payload: Some(proto::mesh_message::Payload::YaraRuleSubmission(
                    proto::YaraRuleSubmission {
                        request_id: request_id.to_string(),
                        submission_id: submission_id.to_string(),
                        node_id: node_id.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        rules: rules.clone(),
                        description: description.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleSubmissionResponse {
                original_request_id,
                submission_id,
                node_id,
                status,
                timestamp,
            } => proto::MeshMessage {
                message_type: 91,
                payload: Some(proto::mesh_message::Payload::YaraRuleSubmissionResponse(
                    proto::YaraRuleSubmissionResponse {
                        original_request_id: original_request_id.to_string(),
                        submission_id: submission_id.to_string(),
                        node_id: node_id.to_string(),
                        status: status.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::DhtRecordAnnounce {
                request_id,
                records,
                write_quorum,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 75,
                payload: Some(proto::mesh_message::Payload::DhtRecordAnnounce(
                    proto::DhtRecordAnnounce {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        write_quorum: *write_quorum,
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtRecordQuery {
                request_id,
                key,
                timestamp,
                source_node_id,
            } => proto::MeshMessage {
                message_type: 76,
                payload: Some(proto::mesh_message::Payload::DhtRecordQuery(
                    proto::DhtRecordQuery {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::DhtRecordResponse {
                request_id,
                key,
                value,
                found,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 77,
                payload: Some(proto::mesh_message::Payload::DhtRecordResponse(
                    proto::DhtRecordResponse {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        value: value.clone(),
                        found: *found,
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id,
                from_version,
            } => proto::MeshMessage {
                message_type: 78,
                payload: Some(proto::mesh_message::Payload::DhtSyncRequest(
                    proto::DhtSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        from_version: *from_version,
                    },
                )),
            },
            MeshMessage::DhtSyncResponse {
                request_id,
                records,
                version,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 79,
                payload: Some(proto::mesh_message::Payload::DhtSyncResponse(
                    proto::DhtSyncResponse {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        version: *version,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtSnapshotRequest {
                request_id,
                node_id,
                from_version,
            } => proto::MeshMessage {
                message_type: 80,
                payload: Some(proto::mesh_message::Payload::DhtSnapshotRequest(
                    proto::DhtSnapshotRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        from_version: *from_version,
                    },
                )),
            },
            MeshMessage::DhtSnapshotResponse {
                request_id,
                records,
                version,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 81,
                payload: Some(proto::mesh_message::Payload::DhtSnapshotResponse(
                    proto::DhtSnapshotResponse {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        version: *version,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 92,
                payload: Some(proto::mesh_message::Payload::DhtAntiEntropyRequest(
                    proto::DhtAntiEntropyRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        local_root_hash: local_root_hash.clone(),
                        interested_keys: interested_keys.clone(),
                        timestamp: *timestamp,
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtAntiEntropyResponse {
                request_id,
                root_hash,
                proof_keys,
                proof_hashes,
                missing_records,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 93,
                payload: Some(proto::mesh_message::Payload::DhtAntiEntropyResponse(
                    proto::DhtAntiEntropyResponse {
                        request_id: request_id.to_string(),
                        root_hash: root_hash.clone(),
                        proof_keys: proof_keys.clone(),
                        proof_hashes: proof_hashes.clone(),
                        missing_records: missing_records.iter().map(|r| r.clone().into()).collect(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtRecordPush {
                request_id,
                records,
                hop_count,
                seen_node_ids,
                timestamp,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 94,
                payload: Some(proto::mesh_message::Payload::DhtRecordPush(
                    proto::DhtRecordPush {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        hop_count: *hop_count,
                        seen_node_ids: seen_node_ids.clone(),
                        timestamp: *timestamp,
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtRecordPushAck {
                request_id,
                original_request_id,
                node_id,
                accepted,
                missing_keys,
                timestamp,
            } => proto::MeshMessage {
                message_type: 95,
                payload: Some(proto::mesh_message::Payload::DhtRecordPushAck(
                    proto::DhtRecordPushAck {
                        request_id: request_id.to_string(),
                        original_request_id: original_request_id.to_string(),
                        node_id: node_id.to_string(),
                        accepted: *accepted,
                        missing_keys: missing_keys.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OriginKeyQuery {
                request_id,
                mesh_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 108,
                payload: Some(proto::mesh_message::Payload::OriginKeyQuery(
                    proto::OriginKeyQuery {
                        request_id: request_id.to_string(),
                        mesh_id: mesh_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OriginKeyQueryResponse {
                request_id,
                mesh_id,
                public_key,
                timestamp,
            } => proto::MeshMessage {
                message_type: 109,
                payload: Some(proto::mesh_message::Payload::OriginKeyQueryResponse(
                    proto::OriginKeyQueryResponse {
                        request_id: request_id.to_string(),
                        mesh_id: mesh_id.to_string(),
                        public_key: public_key.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::NodeShutdown {
                node_id,
                role,
                domains,
                graceful,
                shutdown_at,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 110,
                payload: Some(proto::mesh_message::Payload::NodeShutdown(
                    proto::NodeShutdown {
                        node_id: node_id.to_string(),
                        role: role.bits() as u32,
                        domains: domains.iter().map(|d| d.to_string()).collect(),
                        graceful: *graceful,
                        shutdown_at: *shutdown_at,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DnsDomainRegisterRequest {
                request_id,
                domain,
                origin_node_id,
                challenge_token,
                geo,
                capacity,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 111,
                payload: Some(proto::mesh_message::Payload::DnsDomainRegisterRequest(
                    proto::DnsDomainRegisterRequest {
                        request_id: request_id.to_string(),
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        challenge_token: challenge_token.to_string(),
                        geo: geo.as_ref().map(|s| s.to_string()),
                        capacity: *capacity,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DnsDomainRegisterResponse {
                request_id,
                domain,
                origin_node_id,
                verified,
                reason,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 112,
                payload: Some(proto::mesh_message::Payload::DnsDomainRegisterResponse(
                    proto::DnsDomainRegisterResponse {
                        request_id: request_id.to_string(),
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        verified: *verified,
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DnsDomainDeregisterRequest {
                request_id,
                domain,
                origin_node_id,
                reason,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 113,
                payload: Some(proto::mesh_message::Payload::DnsDomainDeregisterRequest(
                    proto::DnsDomainDeregisterRequest {
                        request_id: request_id.to_string(),
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DnsDomainRegistered {
                domain,
                origin_node_id,
                verified_by_global_node,
                geo,
                capacity,
                registered_at,
                expires_at,
                signature,
            } => proto::MeshMessage {
                message_type: 114,
                payload: Some(proto::mesh_message::Payload::DnsDomainRegistered(
                    proto::DnsDomainRegistered {
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        verified_by_global_node: verified_by_global_node.to_string(),
                        geo: geo.as_ref().map(|s| s.to_string()),
                        capacity: *capacity,
                        registered_at: *registered_at,
                        expires_at: *expires_at,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DnsDomainDeregistered {
                domain,
                origin_node_id,
                deregistered_by_global_node,
                reason,
                deregistered_at,
                signature,
            } => proto::MeshMessage {
                message_type: 115,
                payload: Some(proto::mesh_message::Payload::DnsDomainDeregistered(
                    proto::DnsDomainDeregistered {
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        deregistered_by_global_node: deregistered_by_global_node.to_string(),
                        reason: reason.to_string(),
                        deregistered_at: *deregistered_at,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsRegistrationRequest {
                request_id,
                registration,
                timestamp,
            } => proto::MeshMessage {
                message_type: 116,
                payload: Some(proto::mesh_message::Payload::DnsRegistrationRequest(
                    proto::DnsRegistrationRequest {
                        request_id: request_id.to_string(),
                        registration: Some(proto::DnsRegistration {
                            node_id: registration.registration.node_id.to_string(),
                            domain: registration.registration.domain.to_string(),
                            ip_addresses: registration.registration.ip_addresses.clone(),
                            geo: registration
                                .registration
                                .geo
                                .as_ref()
                                .map(|s| s.to_string()),
                            capacity: registration.registration.capacity,
                            healthy: registration.registration.healthy,
                            latency_ms: registration.registration.latency_ms,
                            certificate_fingerprint: registration
                                .registration
                                .certificate_fingerprint
                                .as_ref()
                                .map(|s| s.to_string()),
                            role: registration.registration.role as u32,
                            edge_node_id: registration
                                .registration
                                .edge_node_id
                                .as_ref()
                                .map(|s| s.to_string()),
                            edge_node_geo: registration
                                .registration
                                .edge_node_geo
                                .as_ref()
                                .map(|s| s.to_string()),
                        }),
                        verify_domain_ownership: registration.verify_domain_ownership,
                        timestamp: registration.timestamp,
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsRegistrationResponse {
                request_id,
                response,
                timestamp,
            } => proto::MeshMessage {
                message_type: 117,
                payload: Some(proto::mesh_message::Payload::DnsRegistrationResponse(
                    proto::DnsRegistrationResponse {
                        request_id: request_id.to_string(),
                        domain: response.domain.to_string(),
                        registration_accepted: response.registration_accepted,
                        verification_status: response.verification_status as u32,
                        verification_type: response.verification_type.map(|v| v as u32),
                        challenge_token: response.challenge_token.as_ref().map(|s| s.to_string()),
                        nameservers_required: response
                            .nameservers_required
                            .as_ref()
                            .unwrap_or(&vec![])
                            .clone(),
                        error_message: response.error_message.as_ref().map(|s| s.to_string()),
                        global_node_id: response.global_node_id.to_string(),
                        timestamp: response.timestamp,
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsVerificationUpdate {
                request_id,
                update,
                timestamp,
            } => proto::MeshMessage {
                message_type: 118,
                payload: Some(proto::mesh_message::Payload::DnsVerificationUpdate(
                    proto::DnsVerificationUpdate {
                        request_id: request_id.to_string(),
                        domain: update.domain.to_string(),
                        status: update.status as u32,
                        verified_at: update.verified_at,
                        error_message: update.error_message.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::FindNode {
                request_id,
                target_node_id,
                requester_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 102,
                payload: Some(proto::mesh_message::Payload::FindNode(proto::FindNode {
                    request_id: request_id.to_string(),
                    target_node_id: target_node_id.clone(),
                    requester_node_id: requester_node_id.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::FindNodeResponse {
                request_id,
                peers,
                responder_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 103,
                payload: Some(proto::mesh_message::Payload::FindNodeResponse(
                    proto::FindNodeResponse {
                        request_id: request_id.to_string(),
                        peers: peers
                            .iter()
                            .map(|p| proto::PeerContact {
                                node_id: p.node_id.as_bytes().to_vec(),
                                node_id_string: p.node_id_string.clone(),
                                address: p.address.clone(),
                                port: p.port as u32,
                                country: p
                                    .geo
                                    .as_ref()
                                    .and_then(|g| g.country.clone())
                                    .unwrap_or_default(),
                                region: p
                                    .geo
                                    .as_ref()
                                    .and_then(|g| g.region.clone())
                                    .unwrap_or_default(),
                                latitude: p.geo.as_ref().and_then(|g| g.latitude).unwrap_or(0.0),
                                longitude: p.geo.as_ref().and_then(|g| g.longitude).unwrap_or(0.0),
                                latency_ms: p.latency_ms.unwrap_or(0),
                                last_seen: p.last_seen.elapsed().as_secs(),
                                is_global: p.is_global,
                                is_trusted: p.is_trusted,
                            })
                            .collect(),
                        responder_node_id: responder_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::Ping {
                request_id,
                node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 104,
                payload: Some(proto::mesh_message::Payload::Ping(proto::Ping {
                    request_id: request_id.to_string(),
                    node_id: node_id.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::Pong {
                request_id,
                node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 105,
                payload: Some(proto::mesh_message::Payload::Pong(proto::Pong {
                    request_id: request_id.to_string(),
                    node_id: node_id.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::UpstreamRegistrationRequest {
                request_id,
                upstream_id,
                upstream_url,
                org_id,
                requesting_node_id,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 96,
                payload: Some(proto::mesh_message::Payload::UpstreamRegistrationRequest(
                    proto::UpstreamRegistrationRequest {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        upstream_url: upstream_url.to_string(),
                        org_id: org_id.as_ref().map(|s| s.to_string()),
                        requesting_node_id: requesting_node_id.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamRegistrationResponse {
                request_id,
                upstream_id,
                approved,
                rejection_reason,
                global_node_id,
                global_node_signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 97,
                payload: Some(proto::mesh_message::Payload::UpstreamRegistrationResponse(
                    proto::UpstreamRegistrationResponse {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        approved: *approved,
                        rejection_reason: rejection_reason.as_ref().map(|s| s.to_string()),
                        global_node_id: global_node_id.to_string(),
                        global_node_signature: global_node_signature.clone().unwrap_or_default(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::UpstreamVerificationQuery {
                request_id,
                upstream_id,
                querying_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 98,
                payload: Some(proto::mesh_message::Payload::UpstreamVerificationQuery(
                    proto::UpstreamVerificationQuery {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        querying_node_id: querying_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::UpstreamVerificationResponse {
                request_id,
                upstream_id,
                verified,
                global_node_id,
                global_node_signature,
                upstream_url,
                org_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 99,
                payload: Some(proto::mesh_message::Payload::UpstreamVerificationResponse(
                    proto::UpstreamVerificationResponse {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        verified: *verified,
                        global_node_id: global_node_id.to_string(),
                        global_node_signature: global_node_signature.clone().unwrap_or_default(),
                        upstream_url: upstream_url.to_string(),
                        org_id: org_id.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::KeyForward {
                session_id,
                key_id,
                mesh_id,
                client_x25519_pubkey,
                global_node_id,
                nonce,
                timestamp,
            } => proto::MeshMessage {
                message_type: 100,
                payload: Some(proto::mesh_message::Payload::KeyForward(
                    proto::KeyForward {
                        session_id: session_id.to_string(),
                        key_id: key_id.to_string(),
                        mesh_id: mesh_id.to_string(),
                        client_x25519_pubkey: client_x25519_pubkey.to_string(),
                        global_node_id: global_node_id.to_string(),
                        nonce: nonce.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::KeySigned {
                session_id,
                key_id,
                mesh_id,
                origin_mesh_id,
                origin_ed25519_pubkey,
                server_x25519_pubkey,
                origin_signature,
                nonce,
                timestamp,
            } => proto::MeshMessage {
                message_type: 101,
                payload: Some(proto::mesh_message::Payload::KeySigned(proto::KeySigned {
                    session_id: session_id.to_string(),
                    key_id: key_id.to_string(),
                    mesh_id: mesh_id.to_string(),
                    origin_mesh_id: origin_mesh_id.to_string(),
                    origin_ed25519_pubkey: origin_ed25519_pubkey.to_string(),
                    server_x25519_pubkey: server_x25519_pubkey.to_string(),
                    origin_signature: origin_signature.clone(),
                    nonce: nonce.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::NetworkPolicyUpdate {
                policy,
                timestamp,
                source_node_id,
                signature,
            } => proto::MeshMessage {
                message_type: 106,
                payload: Some(proto::mesh_message::Payload::NetworkPolicyUpdate(
                    proto::NetworkPolicyUpdate {
                        policy: Some(proto::NetworkPolicy {
                            min_reputation_for_read: policy.min_reputation_for_read,
                            min_reputation_for_write: policy.min_reputation_for_write,
                            blocked_nodes: policy
                                .blocked_nodes
                                .iter()
                                .map(|b| proto::BlockedNode {
                                    node_id: b.node_id.clone(),
                                    blocked_ip: b.blocked_ip.clone(),
                                    blocked_hash: b.blocked_hash.clone(),
                                    reason: b.reason.clone(),
                                    blocked_at: b.blocked_at,
                                    blocked_by: b.blocked_by.clone(),
                                    expires_at: b.expires_at,
                                })
                                .collect(),
                            last_updated: policy.last_updated,
                            updated_by: policy.updated_by.clone(),
                            valid_from: policy.valid_from,
                            signature: policy.signature.clone(),
                        }),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::GlobalNodeBlocklistUpdate {
                blocklist,
                timestamp,
                source_node_id,
                signature,
            } => proto::MeshMessage {
                message_type: 107,
                payload: Some(proto::mesh_message::Payload::GlobalNodeBlocklistUpdate(
                    proto::GlobalNodeBlocklistUpdate {
                        blocklist: Some(proto::GlobalNodeBlocklist {
                            blocked_nodes: blocklist
                                .blocked_nodes
                                .iter()
                                .map(|b| proto::BlockedNode {
                                    node_id: b.node_id.clone(),
                                    blocked_ip: b.blocked_ip.clone(),
                                    blocked_hash: b.blocked_hash.clone(),
                                    reason: b.reason.clone(),
                                    blocked_at: b.blocked_at,
                                    blocked_by: b.blocked_by.clone(),
                                    expires_at: b.expires_at,
                                })
                                .collect(),
                            last_updated: blocklist.last_updated,
                            updated_by: blocklist.updated_by.clone(),
                            signature: blocklist.signature.clone(),
                        }),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::AnycastNodeRegistration {
                request_id,
                node_id,
                anycast_ips,
                geo,
                capacity,
                healthy,
                dns_zones,
                certificate_fingerprint,
                timestamp,
            } => proto::MeshMessage {
                message_type: 120,
                payload: Some(proto::mesh_message::Payload::AnycastNodeRegistration(
                    proto::AnycastNodeRegistration {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        anycast_ips: anycast_ips.clone(),
                        geo: geo.as_ref().map(|s| s.to_string()),
                        capacity: *capacity,
                        healthy: *healthy,
                        dns_zones: dns_zones.clone(),
                        certificate_fingerprint: certificate_fingerprint
                            .as_ref()
                            .map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::AnycastHealthUpdate {
                node_id,
                anycast_ips,
                healthy,
                latency_ms,
                load_percent,
                timestamp,
            } => proto::MeshMessage {
                message_type: 121,
                payload: Some(proto::mesh_message::Payload::AnycastHealthUpdate(
                    proto::AnycastHealthUpdate {
                        node_id: node_id.to_string(),
                        anycast_ips: anycast_ips.clone(),
                        healthy: *healthy,
                        latency_ms: *latency_ms,
                        load_percent: load_percent.map(|v| v as u32),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ZoneSyncRequest {
                request_id,
                zone_origin,
                serial,
                requesting_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 122,
                payload: Some(proto::mesh_message::Payload::ZoneSyncRequest(
                    proto::ZoneSyncRequest {
                        request_id: request_id.to_string(),
                        zone_origin: zone_origin.to_string(),
                        serial: *serial,
                        requesting_node_id: requesting_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ZoneSyncResponse {
                request_id,
                zone_origin,
                records_json,
                serial,
                complete,
                timestamp,
                origin_signature,
                origin_pubkey,
                previous_serial,
                compressed,
            } => proto::MeshMessage {
                message_type: 123,
                payload: Some(proto::mesh_message::Payload::ZoneSyncResponse(
                    proto::ZoneSyncResponse {
                        request_id: request_id.to_string(),
                        zone_origin: zone_origin.to_string(),
                        records_json: records_json.to_string(),
                        serial: *serial,
                        complete: *complete,
                        timestamp: *timestamp,
                        origin_signature: origin_signature.clone(),
                        origin_pubkey: origin_pubkey.clone().unwrap_or_default(),
                        previous_serial: *previous_serial,
                        compressed: *compressed,
                    },
                )),
            },
            MeshMessage::ZoneSyncAck {
                request_id,
                zone_origin,
                serial,
                timestamp,
            } => proto::MeshMessage {
                message_type: 124,
                payload: Some(proto::mesh_message::Payload::ZoneSyncAck(
                    proto::ZoneSyncAck {
                        request_id: request_id.to_string(),
                        zone_origin: zone_origin.to_string(),
                        serial: *serial,
                        timestamp: *timestamp,
                    },
                )),
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Missing payload")]
    MissingPayload,
    #[error("Missing field: {0}")]
    MissingField(&'static str),
    #[error("Conversion error: {0}")]
    ConversionFailed(&'static str),
    #[error("Invalid value: {0}")]
    InvalidValue(&'static str),
}

impl TryFrom<proto::MeshMessage> for MeshMessage {
    type Error = ProtocolError;

    fn try_from(pb: proto::MeshMessage) -> Result<Self, ProtocolError> {
        let payload = pb.payload.ok_or(ProtocolError::MissingPayload)?;
        match payload {
            proto::mesh_message::Payload::Hello(h) => {
                let caps_ref = h
                    .capabilities
                    .as_ref()
                    .ok_or(ProtocolError::MissingField("capabilities"))?;
                Ok(MeshMessage::Hello {
                    version: h.version as u8,
                    node_id: h.node_id.into(),
                    role: MeshNodeRole::from_u8(h.roles as u8),
                    capabilities: caps_ref.try_into()?,
                    upstreams: h
                        .upstreams
                        .into_iter()
                        .map(|(k, v)| Ok((k, v.try_into()?)))
                        .collect::<Result<_, _>>()?,
                    auth_token: h.auth_token.map(|s| s.into()),
                    network_id: h.network_id.map(|s| s.into()),
                    global_node_key: h.global_node_key.map(|s| s.into()),
                    timestamp: h.timestamp,
                    nonce: h.nonce.map(|s| s.into()),
                    is_trusted: h.is_trusted.unwrap_or(false),
                    quic_port: h.quic_port,
                    wireguard_port: h.wireguard_port,
                    public_key: h.public_key.map(|s| s.into()),
                    pow_nonce: h.pow_nonce,
                    pow_public_key: h.pow_public_key.map(|s| s.into()),
                })
            }
            proto::mesh_message::Payload::HelloAck(h) => Ok(MeshMessage::HelloAck {
                version: h.version as u8,
                node_id: h.node_id.into(),
                role: MeshNodeRole::from_u8(h.roles as u8),
                session_id: h.session_id.into(),
                upstreams: h
                    .upstreams
                    .into_iter()
                    .map(|(k, v)| Ok((k, v.try_into()?)))
                    .collect::<Result<_, _>>()?,
                auth_token: h.auth_token.map(|s| s.into()),
                network_id: h.network_id.map(|s| s.into()),
                global_node_key: h.global_node_key.map(|s| s.into()),
                timestamp: h.timestamp,
                nonce: h.nonce.map(|s| s.into()),
                is_trusted: h.is_trusted.unwrap_or(false),
                quic_port: h.quic_port,
                wireguard_port: h.wireguard_port,
                public_key: h.public_key.map(|s| s.into()),
            }),
            proto::mesh_message::Payload::SyncRequest(s) => Ok(MeshMessage::SyncRequest {
                node_id: s.node_id.into(),
            }),
            proto::mesh_message::Payload::SyncResponse(s) => Ok(MeshMessage::SyncResponse {
                nodes: s
                    .nodes
                    .into_iter()
                    .map(|n| n.try_into())
                    .collect::<Result<_, _>>()?,
                upstreams: s
                    .upstreams
                    .into_iter()
                    .map(|(k, v)| Ok((k, v.try_into()?)))
                    .collect::<Result<_, _>>()?,
                timestamp: s.timestamp,
            }),
            proto::mesh_message::Payload::RouteQuery(r) => Ok(MeshMessage::RouteQuery {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
                max_hops: r.max_hops as u8,
                initiator: r.initiator.into(),
                sequence: r.sequence,
                timestamp: r.timestamp,
                nonce: r.nonce.into(),
            }),
            proto::mesh_message::Payload::RouteResponse(r) => Ok(MeshMessage::RouteResponse {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
                provider_node_id: r.provider_node_id.into(),
                hops: r.hops as u8,
                ttl_secs: r.ttl_secs,
                signature: r.signature,
                sequence: r.sequence,
                timestamp: r.timestamp,
                nonce: r.nonce.into(),
                upstream_url: r.upstream_url.map(|s| s.into()),
                waf_policy: r.waf_policy.clone().map(|p| p.into()),
                priority_tier: r.priority_tier,
                tier_claim: r.tier_claim.clone().map(|tc| TierClaim {
                    tier: tc.tier,
                    key_id: tc.key_id.into(),
                    org_id: tc.org_id.into(),
                    mesh_id: tc.mesh_id.into(),
                    timestamp: tc.timestamp,
                    nonce: tc.nonce.into(),
                    signature: tc.signature,
                }),
                org_id: r.org_id.map(|s| s.into()),
                mesh_name: r.mesh_name.map(|s| s.into()),
            }),
            proto::mesh_message::Payload::RouteResponseAck(r) => {
                Ok(MeshMessage::RouteResponseAck {
                    query_id: r.query_id.into(),
                    upstream_id: r.upstream_id.into(),
                    provider_node_id: r.provider_node_id.into(),
                })
            }
            proto::mesh_message::Payload::RouteNotFound(r) => Ok(MeshMessage::RouteNotFound {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
            }),
            proto::mesh_message::Payload::RouteRejected(r) => Ok(MeshMessage::RouteRejected {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
                reason: r.reason.into(),
                alternatives: r
                    .alternatives
                    .into_iter()
                    .map(|a| AlternativeProvider {
                        node_id: a.node_id.into(),
                        priority_tier: a.priority_tier,
                    })
                    .collect(),
            }),
            proto::mesh_message::Payload::TierKeyAnnounce(t) => Ok(MeshMessage::TierKeyAnnounce {
                org_id: t.org_id.into(),
                key: t
                    .key
                    .map(|k| crate::mesh::organization::TierKey {
                        key_id: k.key_id.into(),
                        tier: k.tier,
                        key: k.key,
                        valid_from: k.valid_from,
                        valid_until: k.valid_until,
                        issued_by: k.issued_by.into(),
                        revoked: k.revoked,
                        revoked_at: None,
                        bound_to: None,
                        is_unspent: true,
                    })
                    .unwrap_or_else(|| crate::mesh::organization::TierKey {
                        key_id: String::new().into(),
                        tier: 0,
                        key: Vec::new(),
                        valid_from: 0,
                        valid_until: 0,
                        issued_by: String::new().into(),
                        revoked: false,
                        revoked_at: None,
                        bound_to: None,
                        is_unspent: true,
                    }),
                signature: t.signature,
            }),
            proto::mesh_message::Payload::TierKeyRevoke(t) => Ok(MeshMessage::TierKeyRevoke {
                org_id: t.org_id.into(),
                key_id: t.key_id.into(),
                signature: t.signature,
            }),
            proto::mesh_message::Payload::TierKeyQuery(t) => Ok(MeshMessage::TierKeyQuery {
                request_id: t.request_id.into(),
                org_id: t.org_id.into(),
                requested_tier: if t.requested_tier > 0 {
                    Some(t.requested_tier)
                } else {
                    None
                },
            }),
            proto::mesh_message::Payload::TierKeyQueryResponse(t) => {
                Ok(MeshMessage::TierKeyQueryResponse {
                    request_id: t.request_id.into(),
                    keys: t
                        .keys
                        .into_iter()
                        .map(|k| crate::mesh::organization::TierKey {
                            key_id: k.key_id.into(),
                            tier: k.tier,
                            key: k.key,
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.into(),
                            revoked: k.revoked,
                            revoked_at: None,
                            bound_to: None,
                            is_unspent: true,
                        })
                        .collect(),
                    signature: t.signature,
                })
            }
            proto::mesh_message::Payload::UnspentTierKeyAnnounce(t) => {
                Ok(MeshMessage::UnspentTierKeyAnnounce {
                    org_id: t.org_id.into(),
                    tier_keys: t
                        .tier_keys
                        .into_iter()
                        .map(|k| crate::mesh::organization::TierKey {
                            key_id: k.key_id,
                            tier: k.tier,
                            key: k.key,
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.into(),
                            revoked: k.revoked,
                            revoked_at: None,
                            bound_to: None,
                            is_unspent: true,
                        })
                        .collect(),
                    signature: t.signature,
                    timestamp: t.timestamp,
                })
            }
            proto::mesh_message::Payload::OrgRegistrationRequest(r) => {
                Ok(MeshMessage::OrgRegistrationRequest {
                    request_id: r.request_id.into(),
                    org_name: r.org_name.into(),
                    requesting_node_id: r.requesting_node_id.into(),
                    requesting_node_pubkey: r.requesting_node_pubkey.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::OrgRegistrationResponse(r) => {
                Ok(MeshMessage::OrgRegistrationResponse {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    org_name: r.org_name.into(),
                    approved: r.approved,
                    reason: r.reason.into(),
                    initial_tier_key: r.initial_tier_key.map(|k| {
                        crate::mesh::organization::TierKey {
                            key_id: k.key_id.into(),
                            tier: k.tier,
                            key: k.key,
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.into(),
                            revoked: k.revoked,
                            revoked_at: None,
                            bound_to: None,
                            is_unspent: true,
                        }
                    }),
                    signature: r.signature,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::OrgInvitationRequest(r) => {
                Ok(MeshMessage::OrgInvitationRequest {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    inviter_node_id: r.inviter_node_id.into(),
                    invited_node_id: r.invited_node_id.into(),
                    invited_node_pubkey: if r.invited_node_pubkey.is_empty() {
                        None
                    } else {
                        Some(r.invited_node_pubkey.into())
                    },
                    invitation_token: r.invitation_token.into(),
                    expires_at: r.expires_at,
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::OrgInvitationAccept(r) => {
                Ok(MeshMessage::OrgInvitationAccept {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    invited_node_id: r.invited_node_id.into(),
                    invitation_token: r.invitation_token.into(),
                    proof_of_key: r.proof_of_key.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::OrgInvitationResponse(r) => {
                Ok(MeshMessage::OrgInvitationResponse {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    accepted: r.accepted,
                    org_key: r.org_key.map(|k| crate::mesh::organization::TierKey {
                        key_id: k.key_id.into(),
                        tier: k.tier,
                        key: k.key,
                        valid_from: k.valid_from,
                        valid_until: k.valid_until,
                        issued_by: k.issued_by.into(),
                        revoked: k.revoked,
                        revoked_at: None,
                        bound_to: None,
                        is_unspent: true,
                    }),
                    reason: r.reason.into(),
                    signature: r.signature,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::GlobalNodeAnnounce(r) => {
                let action = match r.action {
                    0 => crate::mesh::protocol::GlobalNodeAction::Add,
                    1 => crate::mesh::protocol::GlobalNodeAction::Remove,
                    2 => crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange,
                    _ => crate::mesh::protocol::GlobalNodeAction::Add,
                };
                let key_exchange_endpoint = if r.key_exchange_endpoint.is_empty() {
                    None
                } else {
                    Some(r.key_exchange_endpoint.into())
                };
                Ok(MeshMessage::GlobalNodeAnnounce {
                    node_id: r.node_id.into(),
                    public_key: r.public_key.into(),
                    action,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    key_exchange_endpoint,
                })
            }
            proto::mesh_message::Payload::OrgMemberAnnounce(r) => {
                Ok(MeshMessage::OrgMemberAnnounce {
                    org_id: r.org_id.into(),
                    member_node_id: r.member_node_id.into(),
                    announced_by: r.announced_by.into(),
                    joined_at: r.joined_at,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamUrlRequest(r) => {
                Ok(MeshMessage::UpstreamUrlRequest {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    url_hash: r.url_hash.into(),
                })
            }
            proto::mesh_message::Payload::UpstreamUrlResponse(r) => {
                Ok(MeshMessage::UpstreamUrlResponse {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    upstream_url: r.upstream_url.into(),
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamUrlDenied(r) => {
                Ok(MeshMessage::UpstreamUrlDenied {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                })
            }
            proto::mesh_message::Payload::UpstreamAnnounce(a) => {
                Ok(MeshMessage::UpstreamAnnounce {
                    upstream_id: a.upstream_id.into(),
                    action: AnnounceAction::from_u8(a.action as u8),
                    signature: a.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamUpdate(u) => Ok(MeshMessage::UpstreamUpdate {
                upstream_id: u.upstream_id.into(),
                info: u
                    .info
                    .ok_or(ProtocolError::MissingField("info"))?
                    .try_into()
                    .map_err(|_| ProtocolError::ConversionFailed("upstream info"))?,
                signature: u.signature,
            }),
            proto::mesh_message::Payload::KeepAlive(_) => Ok(MeshMessage::KeepAlive),
            proto::mesh_message::Payload::KeepAliveAck(_) => Ok(MeshMessage::KeepAliveAck),
            proto::mesh_message::Payload::LookupRequest(r) => Ok(MeshMessage::LookupRequest {
                request_id: r.request_id.into(),
                key: r.key.into(),
                lookup_type: match r.lookup_type {
                    0 => LookupType::KeyValue,
                    1 => LookupType::Route,
                    2 => LookupType::Peer,
                    3 => LookupType::Certificate,
                    4 => LookupType::Config,
                    _ => LookupType::KeyValue,
                },
            }),
            proto::mesh_message::Payload::LookupResponse(r) => Ok(MeshMessage::LookupResponse {
                request_id: r.request_id.into(),
                key: r.key.into(),
                value: r.value,
                found: r.found,
            }),
            proto::mesh_message::Payload::LookupBatchRequest(r) => {
                Ok(MeshMessage::LookupBatchRequest {
                    request_id: r.request_id.into(),
                    keys: r.keys.into_iter().map(|s| s.into()).collect(),
                })
            }
            proto::mesh_message::Payload::LookupBatchResponse(r) => {
                Ok(MeshMessage::LookupBatchResponse {
                    request_id: r.request_id.into(),
                    results: r.results.into_iter().map(|(k, v)| (k, Some(v))).collect(),
                })
            }
            proto::mesh_message::Payload::PeerHealthCheck(r) => Ok(MeshMessage::PeerHealthCheck {
                peer_id: r.peer_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::PeerHealthResponse(r) => {
                Ok(MeshMessage::PeerHealthResponse {
                    peer_id: r.peer_id.into(),
                    status: match r.status {
                        0 => HealthStatus::Healthy,
                        1 => HealthStatus::Degraded,
                        2 => HealthStatus::Unhealthy,
                        _ => HealthStatus::Unknown,
                    },
                    latency_ms: r.latency_ms,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::PeerAnnounce(a) => {
                let caps = a
                    .capabilities
                    .ok_or(ProtocolError::MissingField("capabilities"))?;
                Ok(MeshMessage::PeerAnnounce {
                    node_id: a.node_id.into(),
                    address: a.address.into(),
                    role: MeshNodeRole::from_u8(a.role as u8),
                    capabilities: caps.try_into()?,
                    announced_at: a.announced_at,
                })
            }
            proto::mesh_message::Payload::PeerGone(r) => Ok(MeshMessage::PeerGone {
                node_id: r.node_id.into(),
                reason: r.reason.into(),
            }),
            proto::mesh_message::Payload::TopologySyncRequest(r) => {
                Ok(MeshMessage::TopologySyncRequest {
                    request_id: r.request_id.into(),
                    from_version: r.from_version,
                    prefer_delta: r.prefer_delta,
                })
            }
            proto::mesh_message::Payload::TopologySyncResponse(r) => {
                Ok(MeshMessage::TopologySyncResponse {
                    request_id: r.request_id.into(),
                    peers: r
                        .peers
                        .into_iter()
                        .map(|p| p.try_into())
                        .collect::<Result<_, _>>()?,
                    upstreams: r
                        .upstreams
                        .into_iter()
                        .map(|(k, v)| Ok((k, v.try_into()?)))
                        .collect::<Result<_, _>>()?,
                    version: r.version,
                    is_delta: r.is_delta,
                    removed_peers: r.removed_peers.into_iter().map(|s| s.into()).collect(),
                    removed_upstreams: r.removed_upstreams.into_iter().map(|s| s.into()).collect(),
                })
            }
            proto::mesh_message::Payload::SeedListRequest(r) => Ok(MeshMessage::SeedListRequest {
                node_id: r.node_id.into(),
                request_full_mesh: r.request_full_mesh,
            }),
            proto::mesh_message::Payload::SeedListResponse(r) => {
                Ok(MeshMessage::SeedListResponse {
                    global_nodes: r
                        .global_nodes
                        .into_iter()
                        .map(|p| p.try_into())
                        .collect::<Result<_, _>>()?,
                    edge_nodes: r
                        .edge_nodes
                        .into_iter()
                        .map(|p| p.try_into())
                        .collect::<Result<_, _>>()?,
                    version: r.version,
                    genesis_org_id: if r.genesis_org_id.is_empty() {
                        None
                    } else {
                        Some(r.genesis_org_id.into())
                    },
                })
            }
            proto::mesh_message::Payload::PeerLoadReport(r) => Ok(MeshMessage::PeerLoadReport {
                node_id: r.node_id.into(),
                active_connections: r.active_connections,
                cpu_load_percent: r.cpu_load_percent,
                memory_percent: r.memory_percent,
                requests_per_second: r.requests_per_second,
            }),
            proto::mesh_message::Payload::PeerLoadUpdate(r) => Ok(MeshMessage::PeerLoadUpdate {
                node_id: r.node_id.into(),
                load_score: r.load_score,
            }),
            proto::mesh_message::Payload::RouteUsageReport(r) => {
                Ok(MeshMessage::RouteUsageReport {
                    upstream_id: r.upstream_id.into(),
                    request_count: r.request_count,
                    bytes_transferred: r.bytes_transferred,
                })
            }
            proto::mesh_message::Payload::UpstreamBlocked(r) => Ok(MeshMessage::UpstreamBlocked {
                mesh_identifier: r.mesh_identifier.into(),
                service_id: r.service_id.into(),
                blocked_until: r.blocked_until,
                reason: r.reason.into(),
                origin_node_id: r.origin_node_id.into(),
            }),
            proto::mesh_message::Payload::BandwidthReport(r) => Ok(MeshMessage::BandwidthReport {
                upstream_id: r.upstream_id.into(),
                bytes_sent: r.bytes_sent,
                bytes_received: r.bytes_received,
                request_count: r.request_count,
                interval_secs: r.interval_secs,
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::MeshAck(r) => Ok(MeshMessage::MeshAck {
                original_message_id: r.original_message_id.into(),
                status: AckStatus::from_u8(r.status as u8),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::AuthChallenge(r) => Ok(MeshMessage::AuthChallenge {
                challenge: r.challenge.into(),
                challenge_id: r.challenge_id.into(),
                expires_at: r.expires_at,
            }),
            proto::mesh_message::Payload::AuthResponse(r) => Ok(MeshMessage::AuthResponse {
                challenge_id: r.challenge_id.into(),
                response: r.response.into(),
            }),
            proto::mesh_message::Payload::Error(e) => Ok(MeshMessage::Error {
                code: e.code as u16,
                message: e.message.into(),
            }),
            proto::mesh_message::Payload::ThreatAnnounce(t) => Ok(MeshMessage::ThreatAnnounce {
                request_id: t.request_id.into(),
                indicators: t.indicators.into_iter().map(|i| i.into()).collect(),
                highest_severity: match t.highest_severity {
                    1 => ThreatSeverity::Low,
                    2 => ThreatSeverity::Medium,
                    3 => ThreatSeverity::High,
                    4 => ThreatSeverity::Critical,
                    _ => ThreatSeverity::Unspecified,
                },
                timestamp: t.timestamp,
                source_node_id: t.source_node_id.into(),
                source_role: MeshNodeRole::from_u8(t.source_role as u8),
                source_reputation: t.source_reputation,
                signature: t.signature,
                signer_public_key: t.signer_public_key,
            }),
            proto::mesh_message::Payload::ThreatSyncRequest(t) => {
                Ok(MeshMessage::ThreatSyncRequest {
                    request_id: t.request_id.into(),
                    node_id: t.node_id.into(),
                    from_version: t.from_version,
                    prefer_delta: t.prefer_delta,
                })
            }
            proto::mesh_message::Payload::ThreatSyncResponse(t) => {
                Ok(MeshMessage::ThreatSyncResponse {
                    request_id: t.request_id.into(),
                    indicators: t.indicators.into_iter().map(|i| i.into()).collect(),
                    version: t.version,
                    is_delta: t.is_delta,
                    removed_indicators: t
                        .removed_indicators
                        .into_iter()
                        .map(|s| s.into())
                        .collect(),
                    signature: t.signature,
                    signer_public_key: t.signer_public_key,
                })
            }
            proto::mesh_message::Payload::ThreatAck(t) => Ok(MeshMessage::ThreatAcknowledgement {
                original_request_id: t.original_request_id.into(),
                node_id: t.node_id.into(),
                accepted: t.accepted,
                reason: t.reason.into(),
                timestamp: t.timestamp,
            }),
            proto::mesh_message::Payload::ReputationUpdate(r) => {
                Ok(MeshMessage::ReputationUpdate {
                    node_id: r.node_id.into(),
                    reputation_score: r.reputation_score,
                    threats_accepted: r.threats_accepted,
                    threats_rejected: r.threats_rejected,
                    false_positive_reports: r.false_positive_reports,
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::YaraRuleAnnounce(r) => {
                Ok(MeshMessage::YaraRuleAnnounce {
                    request_id: r.request_id.into(),
                    version: r.version.clone(),
                    rules: r.rules.clone(),
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    source_role: MeshNodeRole::from_u8(r.source_role as u8),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::YaraRuleSyncRequest(r) => {
                Ok(MeshMessage::YaraRuleSyncRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    version: r.version,
                })
            }
            proto::mesh_message::Payload::YaraRuleSyncResponse(r) => {
                Ok(MeshMessage::YaraRuleSyncResponse {
                    request_id: r.request_id.into(),
                    version: r.version,
                    rules: r.rules,
                    is_full: r.is_full,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::YaraRuleAck(r) => {
                Ok(MeshMessage::YaraRuleAcknowledgement {
                    original_request_id: r.original_request_id.into(),
                    node_id: r.node_id.into(),
                    accepted: r.accepted,
                    reason: r.reason.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::YaraRuleSubmission(r) => {
                Ok(MeshMessage::YaraRuleSubmission {
                    request_id: r.request_id.into(),
                    submission_id: r.submission_id.into(),
                    node_id: r.node_id.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                    rules: r.rules.clone(),
                    description: r.description.clone(),
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::YaraRuleSubmissionResponse(r) => {
                Ok(MeshMessage::YaraRuleSubmissionResponse {
                    original_request_id: r.original_request_id.into(),
                    submission_id: r.submission_id.into(),
                    node_id: r.node_id.into(),
                    status: r.status.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::DhtRecordAnnounce(r) => {
                Ok(MeshMessage::DhtRecordAnnounce {
                    request_id: r.request_id.into(),
                    records: r.records.into_iter().map(|rec| rec.into()).collect(),
                    write_quorum: r.write_quorum,
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtRecordQuery(r) => Ok(MeshMessage::DhtRecordQuery {
                request_id: r.request_id.into(),
                key: r.key.into(),
                timestamp: r.timestamp,
                source_node_id: r.source_node_id.into(),
            }),
            proto::mesh_message::Payload::DhtRecordResponse(r) => {
                Ok(MeshMessage::DhtRecordResponse {
                    request_id: r.request_id.into(),
                    key: r.key.into(),
                    value: r.value,
                    found: r.found,
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtSyncRequest(r) => Ok(MeshMessage::DhtSyncRequest {
                request_id: r.request_id.into(),
                node_id: r.node_id.into(),
                from_version: r.from_version,
            }),
            proto::mesh_message::Payload::DhtSyncResponse(r) => Ok(MeshMessage::DhtSyncResponse {
                request_id: r.request_id.into(),
                records: r.records.into_iter().map(|rec| rec.into()).collect(),
                version: r.version,
                timestamp: r.timestamp,
                signature: r.signature,
                signer_public_key: r.signer_public_key,
            }),
            proto::mesh_message::Payload::DhtSnapshotRequest(r) => {
                Ok(MeshMessage::DhtSnapshotRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    from_version: r.from_version,
                })
            }
            proto::mesh_message::Payload::DhtSnapshotResponse(r) => {
                Ok(MeshMessage::DhtSnapshotResponse {
                    request_id: r.request_id.into(),
                    records: r.records.into_iter().map(|rec| rec.into()).collect(),
                    version: r.version,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtAntiEntropyRequest(r) => {
                Ok(MeshMessage::DhtAntiEntropyRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    local_root_hash: r.local_root_hash,
                    interested_keys: r.interested_keys,
                    timestamp: r.timestamp,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtAntiEntropyResponse(r) => {
                Ok(MeshMessage::DhtAntiEntropyResponse {
                    request_id: r.request_id.into(),
                    root_hash: r.root_hash,
                    proof_keys: r.proof_keys,
                    proof_hashes: r.proof_hashes,
                    missing_records: r
                        .missing_records
                        .into_iter()
                        .map(|rec| rec.into())
                        .collect(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtRecordPush(r) => Ok(MeshMessage::DhtRecordPush {
                request_id: r.request_id.into(),
                records: r.records.into_iter().map(|rec| rec.into()).collect(),
                hop_count: r.hop_count,
                seen_node_ids: r.seen_node_ids,
                timestamp: r.timestamp,
                signer_public_key: r.signer_public_key,
            }),
            proto::mesh_message::Payload::DhtRecordPushAck(r) => {
                Ok(MeshMessage::DhtRecordPushAck {
                    request_id: r.request_id.into(),
                    original_request_id: r.original_request_id.into(),
                    node_id: r.node_id.into(),
                    accepted: r.accepted,
                    missing_keys: r.missing_keys,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::OriginKeyQuery(r) => Ok(MeshMessage::OriginKeyQuery {
                request_id: r.request_id.into(),
                mesh_id: r.mesh_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::OriginKeyQueryResponse(r) => {
                Ok(MeshMessage::OriginKeyQueryResponse {
                    request_id: r.request_id.into(),
                    mesh_id: r.mesh_id.into(),
                    public_key: r.public_key.map(|s| s.into()),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::NodeShutdown(r) => Ok(MeshMessage::NodeShutdown {
                node_id: r.node_id.into(),
                role: MeshNodeRole::from_u8(r.role as u8),
                domains: r.domains.into_iter().map(|s| s.into()).collect(),
                graceful: r.graceful,
                shutdown_at: r.shutdown_at,
                timestamp: r.timestamp,
                signature: r.signature,
            }),
            proto::mesh_message::Payload::DnsDomainRegisterRequest(r) => {
                Ok(MeshMessage::DnsDomainRegisterRequest {
                    request_id: r.request_id.into(),
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    challenge_token: r.challenge_token.into(),
                    geo: r.geo.map(|s| s.into()),
                    capacity: r.capacity,
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainRegisterResponse(r) => {
                Ok(MeshMessage::DnsDomainRegisterResponse {
                    request_id: r.request_id.into(),
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    verified: r.verified,
                    reason: r.reason.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainDeregisterRequest(r) => {
                Ok(MeshMessage::DnsDomainDeregisterRequest {
                    request_id: r.request_id.into(),
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    reason: r.reason.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainRegistered(r) => {
                Ok(MeshMessage::DnsDomainRegistered {
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    verified_by_global_node: r.verified_by_global_node.into(),
                    geo: r.geo.map(|s| s.into()),
                    capacity: r.capacity,
                    registered_at: r.registered_at,
                    expires_at: r.expires_at,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainDeregistered(r) => {
                Ok(MeshMessage::DnsDomainDeregistered {
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    deregistered_by_global_node: r.deregistered_by_global_node.into(),
                    reason: r.reason.into(),
                    deregistered_at: r.deregistered_at,
                    signature: r.signature,
                })
            }
            #[cfg(not(feature = "dns"))]
            proto::mesh_message::Payload::DnsRegistrationRequest(_) => Err(
                ProtocolError::InvalidValue("DNS registration not available"),
            ),
            #[cfg(feature = "dns")]
            proto::mesh_message::Payload::DnsRegistrationRequest(r) => {
                use crate::dns::messages::{
                    DnsNodeRole, DnsRegistration, DnsRegistrationWithVerificationRequest,
                };
                let req_id = r.request_id.clone();
                Ok(MeshMessage::DnsRegistrationRequest {
                    request_id: req_id.clone().into(),
                    registration: DnsRegistrationWithVerificationRequest {
                        request_id: req_id,
                        registration: DnsRegistration {
                            node_id: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.node_id.clone())
                                .unwrap_or_default(),
                            domain: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.domain.clone())
                                .unwrap_or_default(),
                            ip_addresses: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.ip_addresses.clone())
                                .unwrap_or_default(),
                            geo: r.registration.as_ref().and_then(|reg| reg.geo.clone()),
                            capacity: r.registration.as_ref().map(|reg| reg.capacity).unwrap_or(0),
                            healthy: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.healthy)
                                .unwrap_or(false),
                            latency_ms: r.registration.as_ref().and_then(|reg| reg.latency_ms),
                            certificate_fingerprint: r
                                .registration
                                .as_ref()
                                .and_then(|reg| reg.certificate_fingerprint.clone()),
                            role: DnsNodeRole::Origin,
                            edge_node_id: r
                                .registration
                                .as_ref()
                                .and_then(|reg| reg.edge_node_id.clone()),
                            edge_node_geo: r
                                .registration
                                .as_ref()
                                .and_then(|reg| reg.edge_node_geo.clone()),
                        },
                        verify_domain_ownership: r.verify_domain_ownership,
                        timestamp: r.timestamp,
                    },
                    timestamp: r.timestamp,
                })
            }
            #[cfg(not(feature = "dns"))]
            proto::mesh_message::Payload::DnsRegistrationResponse(_) => Err(
                ProtocolError::InvalidValue("DNS registration not available"),
            ),
            #[cfg(feature = "dns")]
            proto::mesh_message::Payload::DnsRegistrationResponse(r) => {
                use crate::dns::messages::{
                    DnsRegistrationWithVerificationResponse, DomainVerificationStatus,
                    DomainVerificationType,
                };
                let req_id = r.request_id.clone();
                Ok(MeshMessage::DnsRegistrationResponse {
                    request_id: req_id.clone().into(),
                    response: DnsRegistrationWithVerificationResponse {
                        request_id: req_id,
                        domain: r.domain.clone(),
                        registration_accepted: r.registration_accepted,
                        verification_status: DomainVerificationStatus::Pending,
                        verification_type: r.verification_type.map(|v| match v {
                            1 => DomainVerificationType::NsRecord,
                            _ => DomainVerificationType::TxtChallenge,
                        }),
                        challenge_token: r.challenge_token.clone(),
                        nameservers_required: Some(r.nameservers_required),
                        error_message: r.error_message.clone(),
                        global_node_id: r.global_node_id.clone(),
                        timestamp: r.timestamp,
                    },
                    timestamp: r.timestamp,
                })
            }
            #[cfg(not(feature = "dns"))]
            proto::mesh_message::Payload::DnsVerificationUpdate(_) => Err(
                ProtocolError::InvalidValue("DNS verification not available"),
            ),
            #[cfg(feature = "dns")]
            proto::mesh_message::Payload::DnsVerificationUpdate(r) => {
                use crate::dns::messages::{
                    DomainVerificationStatus, DomainVerificationStatusUpdate,
                };
                let req_id = r.request_id.clone();
                Ok(MeshMessage::DnsVerificationUpdate {
                    request_id: req_id.clone().into(),
                    update: DomainVerificationStatusUpdate {
                        request_id: req_id,
                        domain: r.domain.clone(),
                        status: DomainVerificationStatus::Pending,
                        verified_at: r.verified_at,
                        error_message: r.error_message.clone(),
                    },
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::FindNode(r) => Ok(MeshMessage::FindNode {
                request_id: r.request_id.into(),
                target_node_id: r.target_node_id,
                requester_node_id: r.requester_node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::FindNodeResponse(r) => {
                use crate::mesh::dht::routing::{GeoInfo, NodeId, PeerContact};
                Ok(MeshMessage::FindNodeResponse {
                    request_id: r.request_id.into(),
                    peers: r
                        .peers
                        .into_iter()
                        .map(|p| {
                            let node_id =
                                NodeId::from_bytes(&p.node_id).unwrap_or_else(NodeId::random);
                            let mut contact = PeerContact::new(
                                node_id,
                                p.node_id_string,
                                p.address,
                                p.port as u16,
                            );
                            if p.latitude != 0.0 || p.longitude != 0.0 {
                                contact.geo = Some(GeoInfo {
                                    country: if p.country.is_empty() {
                                        None
                                    } else {
                                        Some(p.country)
                                    },
                                    region: if p.region.is_empty() {
                                        None
                                    } else {
                                        Some(p.region)
                                    },
                                    latitude: if p.latitude == 0.0 {
                                        None
                                    } else {
                                        Some(p.latitude)
                                    },
                                    longitude: if p.longitude == 0.0 {
                                        None
                                    } else {
                                        Some(p.longitude)
                                    },
                                });
                            }
                            if p.latency_ms > 0 {
                                contact.latency_ms = Some(p.latency_ms);
                            }
                            contact.is_global = p.is_global;
                            contact.is_trusted = p.is_trusted;
                            contact
                        })
                        .collect(),
                    responder_node_id: r.responder_node_id.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::Ping(r) => Ok(MeshMessage::Ping {
                request_id: r.request_id.into(),
                node_id: r.node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::Pong(r) => Ok(MeshMessage::Pong {
                request_id: r.request_id.into(),
                node_id: r.node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::UpstreamRegistrationRequest(r) => {
                Ok(MeshMessage::UpstreamRegistrationRequest {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    upstream_url: r.upstream_url.into(),
                    org_id: r.org_id.map(|s| s.into()),
                    requesting_node_id: r.requesting_node_id.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamRegistrationResponse(r) => {
                Ok(MeshMessage::UpstreamRegistrationResponse {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    approved: r.approved,
                    rejection_reason: r.rejection_reason.map(|s| s.into()),
                    global_node_id: r.global_node_id.into(),
                    global_node_signature: if r.global_node_signature.is_empty() {
                        None
                    } else {
                        Some(r.global_node_signature)
                    },
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::UpstreamVerificationQuery(r) => {
                Ok(MeshMessage::UpstreamVerificationQuery {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    querying_node_id: r.querying_node_id.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::UpstreamVerificationResponse(r) => {
                Ok(MeshMessage::UpstreamVerificationResponse {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    verified: r.verified,
                    global_node_id: r.global_node_id.into(),
                    global_node_signature: if r.global_node_signature.is_empty() {
                        None
                    } else {
                        Some(r.global_node_signature)
                    },
                    upstream_url: r.upstream_url.into(),
                    org_id: r.org_id.map(|s| s.into()),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::KeyForward(k) => Ok(MeshMessage::KeyForward {
                session_id: k.session_id.into(),
                key_id: k.key_id.into(),
                mesh_id: k.mesh_id.into(),
                client_x25519_pubkey: k.client_x25519_pubkey.into(),
                global_node_id: k.global_node_id.into(),
                nonce: k.nonce.into(),
                timestamp: k.timestamp,
            }),
            proto::mesh_message::Payload::KeySigned(k) => Ok(MeshMessage::KeySigned {
                session_id: k.session_id.into(),
                key_id: k.key_id.into(),
                mesh_id: k.mesh_id.into(),
                origin_mesh_id: k.origin_mesh_id.into(),
                origin_ed25519_pubkey: k.origin_ed25519_pubkey.into(),
                server_x25519_pubkey: k.server_x25519_pubkey.into(),
                origin_signature: k.origin_signature,
                nonce: k.nonce.into(),
                timestamp: k.timestamp,
            }),
            proto::mesh_message::Payload::NetworkPolicyUpdate(n) => {
                let policy = n.policy.unwrap_or_default();
                let blocked_nodes: Vec<super::dht::BlockedNode> = policy
                    .blocked_nodes
                    .into_iter()
                    .map(|b| super::dht::BlockedNode {
                        node_id: b.node_id,
                        blocked_ip: b.blocked_ip,
                        blocked_hash: b.blocked_hash,
                        reason: b.reason,
                        blocked_at: b.blocked_at,
                        blocked_by: b.blocked_by,
                        expires_at: b.expires_at,
                    })
                    .collect();
                let network_policy = super::dht::NetworkPolicy {
                    min_reputation_for_read: policy.min_reputation_for_read,
                    min_reputation_for_write: policy.min_reputation_for_write,
                    blocked_nodes,
                    last_updated: policy.last_updated,
                    updated_by: policy.updated_by,
                    valid_from: policy.valid_from,
                    signature: policy.signature,
                };
                Ok(MeshMessage::NetworkPolicyUpdate {
                    policy: network_policy,
                    timestamp: n.timestamp,
                    source_node_id: n.source_node_id.into(),
                    signature: n.signature,
                })
            }
            proto::mesh_message::Payload::GlobalNodeBlocklistUpdate(b) => {
                let blocklist = b.blocklist.unwrap_or_default();
                let blocked_nodes: Vec<super::dht::BlockedNode> = blocklist
                    .blocked_nodes
                    .into_iter()
                    .map(|b| super::dht::BlockedNode {
                        node_id: b.node_id,
                        blocked_ip: b.blocked_ip,
                        blocked_hash: b.blocked_hash,
                        reason: b.reason,
                        blocked_at: b.blocked_at,
                        blocked_by: b.blocked_by,
                        expires_at: b.expires_at,
                    })
                    .collect();
                let global_blocklist = super::dht::GlobalNodeBlocklist {
                    blocked_nodes,
                    last_updated: blocklist.last_updated,
                    updated_by: blocklist.updated_by,
                    signature: blocklist.signature,
                };
                Ok(MeshMessage::GlobalNodeBlocklistUpdate {
                    blocklist: global_blocklist,
                    timestamp: b.timestamp,
                    source_node_id: b.source_node_id.into(),
                    signature: b.signature,
                })
            }
            proto::mesh_message::Payload::AnycastNodeRegistration(r) => {
                Ok(MeshMessage::AnycastNodeRegistration {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    anycast_ips: r.anycast_ips,
                    geo: r.geo.map(|s| s.into()),
                    capacity: r.capacity,
                    healthy: r.healthy,
                    dns_zones: r.dns_zones,
                    certificate_fingerprint: r.certificate_fingerprint.map(|s| s.into()),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::AnycastHealthUpdate(r) => {
                Ok(MeshMessage::AnycastHealthUpdate {
                    node_id: r.node_id.into(),
                    anycast_ips: r.anycast_ips,
                    healthy: r.healthy,
                    latency_ms: r.latency_ms,
                    load_percent: r.load_percent.map(|v| v as u8),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::ZoneSyncRequest(r) => Ok(MeshMessage::ZoneSyncRequest {
                request_id: r.request_id.into(),
                zone_origin: r.zone_origin.into(),
                serial: r.serial,
                requesting_node_id: r.requesting_node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::ZoneSyncResponse(r) => {
                Ok(MeshMessage::ZoneSyncResponse {
                    request_id: r.request_id.into(),
                    zone_origin: r.zone_origin.into(),
                    records_json: r.records_json.into(),
                    serial: r.serial,
                    complete: r.complete,
                    timestamp: r.timestamp,
                    origin_signature: r.origin_signature,
                    origin_pubkey: if r.origin_pubkey.is_empty() {
                        None
                    } else {
                        Some(r.origin_pubkey.into())
                    },
                    previous_serial: r.previous_serial,
                    compressed: r.compressed,
                })
            }
            proto::mesh_message::Payload::ZoneSyncAck(r) => Ok(MeshMessage::ZoneSyncAck {
                request_id: r.request_id.into(),
                zone_origin: r.zone_origin.into(),
                serial: r.serial,
                timestamp: r.timestamp,
            }),
        }
    }
}

impl From<&MeshCapabilities> for proto::MeshCapabilities {
    fn from(c: &MeshCapabilities) -> Self {
        proto::MeshCapabilities {
            can_route: c.can_route,
            can_proxy: c.can_proxy,
            max_hops: c.max_hops as u32,
            supported_services: c.supported_services.clone(),
            preferred_transport: c.preferred_transport.map(|t| t as u32).unwrap_or(0),
        }
    }
}

impl TryFrom<proto::MeshCapabilities> for MeshCapabilities {
    type Error = ProtocolError;

    fn try_from(pb: proto::MeshCapabilities) -> Result<Self, Self::Error> {
        Ok(MeshCapabilities {
            can_route: pb.can_route,
            can_proxy: pb.can_proxy,
            max_hops: pb.max_hops as u8,
            supported_services: pb.supported_services,
            preferred_transport: match pb.preferred_transport {
                1 => Some(MeshTransportType::WireGuard),
                2 => Some(MeshTransportType::Quic),
                _ => None,
            },
        })
    }
}

impl TryFrom<&proto::MeshCapabilities> for MeshCapabilities {
    type Error = ProtocolError;

    fn try_from(pb: &proto::MeshCapabilities) -> Result<Self, Self::Error> {
        Ok(MeshCapabilities {
            can_route: pb.can_route,
            can_proxy: pb.can_proxy,
            max_hops: pb.max_hops as u8,
            supported_services: pb.supported_services.clone(),
            preferred_transport: match pb.preferred_transport {
                1 => Some(MeshTransportType::WireGuard),
                2 => Some(MeshTransportType::Quic),
                _ => None,
            },
        })
    }
}

impl From<&UpstreamInfo> for proto::UpstreamInfo {
    fn from(u: &UpstreamInfo) -> Self {
        proto::UpstreamInfo {
            upstream_id: u.upstream_id.clone(),
            upstream_url: u.upstream_url.clone(),
            geo: u.geo.clone(),
            is_local: u.is_local,
            owner_node_id: u.owner_node_id.clone(),
            peered_wafs: u.peered_wafs.clone(),
            url_hash: u.url_hash.clone(),
            waf_policy: u.waf_policy.as_ref().map(|p| p.into()),
            protocol: u.protocol as i32,
        }
    }
}

impl TryFrom<proto::UpstreamInfo> for UpstreamInfo {
    type Error = ProtocolError;

    fn try_from(pb: proto::UpstreamInfo) -> Result<Self, Self::Error> {
        let protocol = match pb.protocol {
            0 => UpstreamProtocol::Unknown,
            1 => UpstreamProtocol::Http,
            2 => UpstreamProtocol::Https,
            3 => UpstreamProtocol::Tcp,
            4 => UpstreamProtocol::Udp,
            5 => UpstreamProtocol::Grpc,
            6 => UpstreamProtocol::Websocket,
            7 => UpstreamProtocol::Websockets,
            _ => UpstreamProtocol::Unknown,
        };

        Ok(UpstreamInfo {
            upstream_id: pb.upstream_id,
            upstream_url: pb.upstream_url,
            geo: pb.geo,
            is_local: pb.is_local,
            owner_node_id: pb.owner_node_id,
            peered_wafs: pb.peered_wafs,
            url_hash: pb.url_hash,
            waf_policy: pb.waf_policy.map(|p| p.into()),
            protocol,
        })
    }
}

impl From<&MeshPeerInfo> for proto::MeshPeerInfo {
    fn from(p: &MeshPeerInfo) -> Self {
        proto::MeshPeerInfo {
            node_id: p.node_id.clone(),
            address: p.address.clone(),
            roles: p.role.bits() as u32,
            capabilities: Some((&p.capabilities).into()),
            is_global: p.is_global,
            latency_ms: p.latency_ms,
            upstreams: p.upstreams.clone(),
            is_trusted: p.is_trusted,
            quic_port: p.quic_port,
            wireguard_port: p.wireguard_port,
            advertised_port: p.advertised_port,
        }
    }
}

impl TryFrom<proto::MeshPeerInfo> for MeshPeerInfo {
    type Error = ProtocolError;

    fn try_from(pb: proto::MeshPeerInfo) -> Result<Self, Self::Error> {
        Ok(MeshPeerInfo {
            node_id: pb.node_id,
            address: pb.address,
            role: MeshNodeRole::from_u8(pb.roles as u8),
            capabilities: pb
                .capabilities
                .ok_or(ProtocolError::MissingField("capabilities"))?
                .try_into()
                .map_err(|_| ProtocolError::ConversionFailed("capabilities"))?,
            is_global: pb.is_global,
            latency_ms: pb.latency_ms,
            upstreams: pb.upstreams,
            is_trusted: pb.is_trusted,
            quic_port: pb.quic_port,
            wireguard_port: pb.wireguard_port,
            advertised_port: pb.advertised_port,
        })
    }
}

impl From<&UpstreamOwner> for proto::UpstreamOwner {
    fn from(u: &UpstreamOwner) -> Self {
        proto::UpstreamOwner {
            owner_node_id: u.owner_node_id.clone(),
            peered_wafs: u.peered_wafs.clone(),
        }
    }
}

impl TryFrom<proto::UpstreamOwner> for UpstreamOwner {
    type Error = ProtocolError;

    fn try_from(pb: proto::UpstreamOwner) -> Result<Self, Self::Error> {
        Ok(UpstreamOwner {
            owner_node_id: pb.owner_node_id,
            peered_wafs: pb.peered_wafs,
        })
    }
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshCapabilities {
    pub can_route: bool,
    pub can_proxy: bool,
    pub max_hops: u8,
    pub supported_services: Vec<String>,
    pub preferred_transport: Option<MeshTransportType>,
}

impl Default for MeshCapabilities {
    fn default() -> Self {
        Self {
            can_route: true,
            can_proxy: true,
            max_hops: 3,
            supported_services: Vec::new(),
            preferred_transport: Some(MeshTransportType::WireGuard),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpstreamProtocol {
    Unknown = 0,
    Http = 1,
    Https = 2,
    Tcp = 3,
    Udp = 4,
    Grpc = 5,
    Websocket = 6,
    Websockets = 7,
}

impl Default for UpstreamProtocol {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<UpstreamProtocol> for proto::UpstreamProtocol {
    fn from(p: UpstreamProtocol) -> Self {
        match p {
            UpstreamProtocol::Unknown => proto::UpstreamProtocol::Unknown,
            UpstreamProtocol::Http => proto::UpstreamProtocol::Http,
            UpstreamProtocol::Https => proto::UpstreamProtocol::Https,
            UpstreamProtocol::Tcp => proto::UpstreamProtocol::Tcp,
            UpstreamProtocol::Udp => proto::UpstreamProtocol::Udp,
            UpstreamProtocol::Grpc => proto::UpstreamProtocol::Grpc,
            UpstreamProtocol::Websocket => proto::UpstreamProtocol::Websocket,
            UpstreamProtocol::Websockets => proto::UpstreamProtocol::Websockets,
        }
    }
}

impl TryFrom<proto::UpstreamProtocol> for UpstreamProtocol {
    type Error = ProtocolError;

    fn try_from(pb: proto::UpstreamProtocol) -> Result<Self, Self::Error> {
        match pb {
            proto::UpstreamProtocol::Unknown => Ok(UpstreamProtocol::Unknown),
            proto::UpstreamProtocol::Http => Ok(UpstreamProtocol::Http),
            proto::UpstreamProtocol::Https => Ok(UpstreamProtocol::Https),
            proto::UpstreamProtocol::Tcp => Ok(UpstreamProtocol::Tcp),
            proto::UpstreamProtocol::Udp => Ok(UpstreamProtocol::Udp),
            proto::UpstreamProtocol::Grpc => Ok(UpstreamProtocol::Grpc),
            proto::UpstreamProtocol::Websocket => Ok(UpstreamProtocol::Websocket),
            proto::UpstreamProtocol::Websockets => Ok(UpstreamProtocol::Websockets),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitOverride {
    pub requests_per_second: Option<u64>,
    pub requests_per_minute: Option<u64>,
    pub requests_per_hour: Option<u64>,
    pub concurrent_connections: Option<u64>,
    pub bandwidth_mbps: Option<u64>,
    pub burst_size: Option<u64>,
}

impl Default for RateLimitOverride {
    fn default() -> Self {
        Self {
            requests_per_second: None,
            requests_per_minute: None,
            requests_per_hour: None,
            concurrent_connections: None,
            bandwidth_mbps: None,
            burst_size: None,
        }
    }
}

pub const PRIORITY_TIER_FREE: u32 = 0;
pub const PRIORITY_TIER_PAID: u32 = 1;
pub const PRIORITY_TIER_PREMIUM: u32 = 2;
pub const PRIORITY_TIER_ENTERPRISE: u32 = 3;

impl WafPolicy {
    pub fn default_for_tier(tier: u32) -> Self {
        match tier {
            PRIORITY_TIER_ENTERPRISE => WafPolicy {
                skip_rate_limit: true,
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(100000),
                    requests_per_minute: Some(5000000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            PRIORITY_TIER_PREMIUM => WafPolicy {
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(10000),
                    requests_per_minute: Some(500000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            PRIORITY_TIER_PAID => WafPolicy {
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(1000),
                    requests_per_minute: Some(50000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            PRIORITY_TIER_FREE => WafPolicy {
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(100),
                    requests_per_minute: Some(5000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            _ => WafPolicy {
                priority_tier: tier,
                ..Default::default()
            },
        }
    }
}

impl From<&WafPolicy> for proto::WafPolicy {
    fn from(p: &WafPolicy) -> Self {
        proto::WafPolicy {
            skip_rate_limit: p.skip_rate_limit,
            skip_auth_challenge: p.skip_auth_challenge,
            skip_pow_challenge: p.skip_pow_challenge,
            skip_honeypot: p.skip_honeypot,
            enabled_rules: p.enabled_rules.clone(),
            disabled_rules: p.disabled_rules.clone(),
            threat_level: p.threat_level,
            enable_bot_protection: p.enable_bot_protection,
            enable_ip_feed: p.enable_ip_feed,
            enable_threat_level: p.enable_threat_level,
            enable_traffic_shaping: p.enable_traffic_shaping,
            policy_mode: p.policy_mode.clone(),
            priority_tier: p.priority_tier,
            rate_limit_override: p
                .rate_limit_override
                .as_ref()
                .map(|r| proto::RateLimitOverride {
                    requests_per_second: r.requests_per_second,
                    requests_per_minute: r.requests_per_minute,
                    requests_per_hour: r.requests_per_hour,
                    concurrent_connections: r.concurrent_connections,
                    bandwidth_mbps: r.bandwidth_mbps,
                    burst_size: r.burst_size,
                }),
            enable_mesh_key_exchange: p.enable_mesh_key_exchange,
            enable_mesh_auditing: p.enable_mesh_auditing,
            mesh_id: p.mesh_id.clone(),
            mesh_global_node_url: p.mesh_global_node_url.clone(),
            mesh_audit_urls: p.mesh_audit_urls.clone(),
            fallback_to_regular_pow: p.fallback_to_regular_pow,
        }
    }
}

impl From<proto::WafPolicy> for WafPolicy {
    fn from(pb: proto::WafPolicy) -> Self {
        WafPolicy {
            skip_rate_limit: pb.skip_rate_limit,
            skip_auth_challenge: pb.skip_auth_challenge,
            skip_pow_challenge: pb.skip_pow_challenge,
            skip_honeypot: pb.skip_honeypot,
            enabled_rules: pb.enabled_rules,
            disabled_rules: pb.disabled_rules,
            threat_level: pb.threat_level,
            enable_bot_protection: pb.enable_bot_protection,
            enable_ip_feed: pb.enable_ip_feed,
            enable_threat_level: pb.enable_threat_level,
            enable_traffic_shaping: pb.enable_traffic_shaping,
            policy_mode: pb.policy_mode,
            priority_tier: pb.priority_tier,
            rate_limit_override: pb.rate_limit_override.map(|r| RateLimitOverride {
                requests_per_second: r.requests_per_second,
                requests_per_minute: r.requests_per_minute,
                requests_per_hour: r.requests_per_hour,
                concurrent_connections: r.concurrent_connections,
                bandwidth_mbps: r.bandwidth_mbps,
                burst_size: r.burst_size,
            }),
            enable_mesh_key_exchange: pb.enable_mesh_key_exchange,
            enable_mesh_auditing: pb.enable_mesh_auditing,
            mesh_id: pb.mesh_id,
            mesh_global_node_url: pb.mesh_global_node_url,
            mesh_audit_urls: pb.mesh_audit_urls,
            fallback_to_regular_pow: pb.fallback_to_regular_pow,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatType {
    Unspecified,
    IpBlock,
    RateLimitViolation,
    SuspiciousActivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatSeverity {
    Unspecified,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DhtRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub timestamp: u64,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
}

impl AnnounceAction {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AnnounceAction::Add,
            1 => AnnounceAction::Update,
            2 => AnnounceAction::Remove,
            _ => AnnounceAction::Add,
        }
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

impl RouteQueryResult {
    pub fn is_expired(&self) -> bool {
        self.providers
            .iter()
            .all(|p| Instant::now().duration_since(self.discovered_at) > p.ttl)
    }

    pub fn remaining_ttl(&self) -> Duration {
        self.providers
            .iter()
            .map(|p| p.ttl)
            .min()
            .unwrap_or(Duration::ZERO)
    }

    pub fn best_provider(&self) -> Option<&ProviderInfo> {
        self.providers.iter().max_by(|a, b| {
            a.priority_tier.cmp(&b.priority_tier).then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        })
    }

    pub fn providers_sorted(&self) -> Vec<&ProviderInfo> {
        let mut providers: Vec<&ProviderInfo> = self.providers.iter().collect();
        providers.sort_by(|a, b| {
            a.priority_tier
                .cmp(&b.priority_tier)
                .reverse()
                .then_with(|| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        providers
    }
}

#[derive(Debug, Clone)]
pub struct PendingQuery {
    pub query_id: String,
    pub upstream_id: String,
    pub initiator: String,
    pub created_at: Instant,
    pub max_hops: u8,
}

impl PendingQuery {
    pub fn is_expired(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.created_at) > timeout
    }
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
}

impl MeshPeerInfo {
    pub fn new(
        node_id: String,
        address: String,
        role: MeshNodeRole,
        capabilities: MeshCapabilities,
    ) -> Self {
        Self {
            node_id,
            address,
            role,
            capabilities,
            is_global: role.is_global(),
            latency_ms: None,
            upstreams: Vec::new(),
            is_trusted: role.is_global(),
            quic_port: None,
            wireguard_port: None,
            advertised_port: None,
        }
    }
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

impl AckStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AckStatus::Success,
            1 => AckStatus::Processing,
            2 => AckStatus::InvalidMessage,
            3 => AckStatus::Unauthorized,
            4 => AckStatus::NotFound,
            5 => AckStatus::RateLimited,
            6 => AckStatus::InternalError,
            _ => AckStatus::InternalError,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            AckStatus::Success => 0,
            AckStatus::Processing => 1,
            AckStatus::InvalidMessage => 2,
            AckStatus::Unauthorized => 3,
            AckStatus::NotFound => 4,
            AckStatus::RateLimited => 5,
            AckStatus::InternalError => 6,
        }
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AuthChallenge {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&ThreatIndicator> for proto::ThreatIndicator {
    fn from(i: &ThreatIndicator) -> Self {
        proto::ThreatIndicator {
            threat_type: i.threat_type as i32,
            indicator_value: i.indicator_value.clone(),
            severity: i.severity as i32,
            reason: i.reason.clone(),
            ttl_seconds: i.ttl_seconds,
            source_node_id: i.source_node_id.clone(),
            timestamp: i.timestamp,
            site_scope: i.site_scope.clone(),
            rate_limit_requests: i.rate_limit_requests,
            rate_limit_window_secs: i.rate_limit_window_secs,
            suspicious_pattern: i.suspicious_pattern.clone(),
            signature: i.signature.clone(),
            signer_public_key: i.signer_public_key.clone().unwrap_or_default(),
        }
    }
}

impl From<proto::ThreatIndicator> for ThreatIndicator {
    fn from(pb: proto::ThreatIndicator) -> Self {
        ThreatIndicator {
            threat_type: match pb.threat_type {
                1 => ThreatType::IpBlock,
                2 => ThreatType::RateLimitViolation,
                3 => ThreatType::SuspiciousActivity,
                _ => ThreatType::Unspecified,
            },
            indicator_value: pb.indicator_value,
            severity: match pb.severity {
                1 => ThreatSeverity::Low,
                2 => ThreatSeverity::Medium,
                3 => ThreatSeverity::High,
                4 => ThreatSeverity::Critical,
                _ => ThreatSeverity::Unspecified,
            },
            reason: pb.reason,
            ttl_seconds: pb.ttl_seconds,
            source_node_id: pb.source_node_id,
            timestamp: pb.timestamp,
            site_scope: pb.site_scope,
            rate_limit_requests: pb.rate_limit_requests,
            rate_limit_window_secs: pb.rate_limit_window_secs,
            suspicious_pattern: pb.suspicious_pattern,
            signature: pb.signature,
            signer_public_key: if pb.signer_public_key.is_empty() {
                None
            } else {
                Some(pb.signer_public_key)
            },
        }
    }
}

impl From<proto::DhtRecord> for DhtRecord {
    fn from(pb: proto::DhtRecord) -> Self {
        DhtRecord {
            key: pb.key,
            value: pb.value,
            timestamp: pb.timestamp,
            ttl_seconds: pb.ttl_seconds,
            source_node_id: pb.source_node_id,
            signature: pb.signature,
            signer_public_key: if pb.signer_public_key.is_empty() {
                None
            } else {
                Some(pb.signer_public_key)
            },
        }
    }
}

impl From<DhtRecord> for proto::DhtRecord {
    fn from(r: DhtRecord) -> Self {
        proto::DhtRecord {
            key: r.key,
            value: r.value,
            timestamp: r.timestamp,
            ttl_seconds: r.ttl_seconds,
            source_node_id: r.source_node_id,
            signature: r.signature,
            signer_public_key: r.signer_public_key.unwrap_or_default(),
        }
    }
}

impl From<ThreatSeverity> for i32 {
    fn from(s: ThreatSeverity) -> Self {
        match s {
            ThreatSeverity::Unspecified => 0,
            ThreatSeverity::Low => 1,
            ThreatSeverity::Medium => 2,
            ThreatSeverity::High => 3,
            ThreatSeverity::Critical => 4,
        }
    }
}

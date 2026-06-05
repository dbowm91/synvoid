use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

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
pub enum DnsNodeRole {
    Edge,
    Origin,
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
pub enum DomainVerificationType {
    NsRecord,
    TxtChallenge,
    /// Mesh-internal verification using mesh certificate and signing key
    /// instead of external DNS queries. Provides resilience when external
    /// DNS is unavailable.
    MeshCertificate,
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
pub enum DomainVerificationStatus {
    Pending,
    InProgress,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DomainVerificationRequest {
    pub request_id: String,
    pub domain: String,
    pub origin_node_id: String,
    pub verification_type: DomainVerificationType,
    pub challenge_token: Option<String>,
    pub ip_addresses: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DomainVerificationResponse {
    pub request_id: String,
    pub domain: String,
    pub status: DomainVerificationStatus,
    pub verification_type: DomainVerificationType,
    pub challenge_token: Option<String>,
    pub nameservers: Option<Vec<String>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsRegistration {
    pub node_id: String,
    pub domain: String,
    pub ip_addresses: Vec<String>,
    pub geo: Option<String>,
    pub capacity: u32,
    pub healthy: bool,
    pub latency_ms: Option<u32>,
    pub certificate_fingerprint: Option<String>,
    pub role: DnsNodeRole,
    pub edge_node_id: Option<String>,
    pub edge_node_geo: Option<String>,
    #[serde(default)]
    pub certificate_chain: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsRegistrationWithVerificationRequest {
    pub request_id: String,
    pub registration: DnsRegistration,
    pub verify_domain_ownership: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsRegistrationWithVerificationResponse {
    pub request_id: String,
    pub domain: String,
    pub registration_accepted: bool,
    pub verification_status: DomainVerificationStatus,
    pub verification_type: Option<DomainVerificationType>,
    pub challenge_token: Option<String>,
    pub nameservers_required: Option<Vec<String>>,
    pub error_message: Option<String>,
    pub global_node_id: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DomainVerificationStatusUpdate {
    pub request_id: String,
    pub domain: String,
    pub status: DomainVerificationStatus,
    pub verified_at: Option<u64>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsRegistrationRequest {
    pub node_id: String,
    pub domains: Vec<DnsRegistration>,
    pub is_global: bool,
    pub certificate_fingerprint: Option<String>,
    pub role: DnsNodeRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsHealthUpdate {
    pub node_id: String,
    pub healthy: bool,
    pub latency_ms: Option<u32>,
    pub load_percent: Option<u8>,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsZoneSync {
    pub zone: String,
    pub records: Vec<DnsRecord>,
    pub serial: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub priority: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct DnsNodeShutdown {
    pub node_id: String,
    pub role: DnsNodeRole,
    pub domains: Vec<String>,
    pub graceful: bool,
    pub shutdown_at: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEdgeHealthReport {
    pub edge_node_id: String,
    pub origin_node_id: String,
    pub domain: String,
    pub healthy: bool,
    pub latency_ms: Option<u32>,
    pub consecutive_failures: u32,
    pub last_failure_reason: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnycastHealthUpdate {
    pub node_id: String,
    pub anycast_ips: Vec<String>,
    pub healthy: bool,
    pub latency_ms: Option<u32>,
    pub load_percent: Option<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnycastNodeRegistration {
    pub node_id: String,
    pub anycast_ips: Vec<String>,
    pub geo: Option<String>,
    pub capacity: u32,
    pub healthy: bool,
    pub dns_zones: Vec<String>,
    pub certificate_fingerprint: Option<String>,
}

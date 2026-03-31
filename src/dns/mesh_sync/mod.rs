use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use hkdf::Hkdf;
use parking_lot::RwLock;
use sha2::Sha256;
use tokio::sync::mpsc;

use crate::dns::messages::{
    DnsAnycastHealthUpdate, DnsAnycastNodeRegistration, DnsEdgeHealthReport, DnsHealthUpdate,
    DnsNodeRole, DnsNodeShutdown, DnsRegistration, DnsRegistrationRequest,
    DnsRegistrationWithVerificationRequest, DnsRegistrationWithVerificationResponse,
    DomainVerificationRequest, DomainVerificationStatus, DomainVerificationType,
};
use crate::dns::resolver::DnsResolver;

mod dht;
mod health;
mod query;
mod registration;
mod registry;
mod verification;

#[derive(Clone)]
pub struct RegisteredEdgeNode {
    pub node_id: String,
    pub domains: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub geo: Option<String>,
    pub healthy: bool,
    pub latency_ms: Option<u32>,
    pub load_percent: Option<u8>,
    pub consecutive_failures: u32,
    pub last_failure_reason: Option<String>,
    pub last_update: u64,
    pub authenticated: bool,
    pub domains_origin_mapping: HashMap<String, String>,
}

#[derive(Clone)]
pub struct RegisteredOriginNode {
    pub node_id: String,
    pub domains: Vec<String>,
    pub geo: Option<String>,
    pub healthy: bool,
    pub capacity: u32,
    pub latency_ms: Option<u32>,
    pub load_percent: Option<u8>,
    pub last_update: u64,
    pub last_seen: u64,
    pub authenticated: bool,
    pub edge_node_id: Option<String>,
    pub edge_node_geo: Option<String>,
    pub certificate_chain: Vec<Vec<u8>>,
    pub cert_chain_verified: bool,
}

#[derive(Clone)]
pub struct RegisteredAnycastNode {
    pub node_id: String,
    pub anycast_ips: Vec<String>,
    pub geo: Option<String>,
    pub healthy: bool,
    pub capacity: u32,
    pub latency_ms: Option<u32>,
    pub load_percent: Option<u8>,
    pub last_update: u64,
    pub authenticated: bool,
    pub dns_zones: Vec<String>,
}

#[derive(Clone)]
pub struct MeshNodeCertificate {
    pub node_id: String,
    pub certificate_der: Vec<u8>,
    pub issuer: String,
    pub not_before: u64,
    pub not_after: u64,
    pub fingerprint_sha256: String,
}

impl MeshNodeCertificate {
    pub fn new(node_id: String, certificate_der: Vec<u8>, issuer: String) -> Self {
        let fingerprint = Self::compute_fingerprint(&certificate_der);
        Self {
            node_id,
            certificate_der,
            issuer,
            not_before: 0,
            not_after: u64::MAX,
            fingerprint_sha256: fingerprint,
        }
    }

    fn compute_fingerprint(cert_der: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(cert_der);
        hex::encode(hash)
    }

    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now >= self.not_before && now <= self.not_after
    }
}

#[derive(Clone)]
pub struct MeshDnsRegistryConfig {
    pub require_mtls: bool,
    pub trusted_ca_path: Option<String>,
    pub allowed_node_ids: Vec<String>,
    pub registration_timeout_secs: u64,
    pub failure_threshold_for_demotion: u32,
    pub failure_threshold_for_removal: u32,
    pub graceful_shutdown_lead_time_secs: u64,
    pub verification_timeout_secs: u64,
    pub verification_retry_interval_secs: u64,
    pub require_cert_chain_verification: bool,
}

impl Default for MeshDnsRegistryConfig {
    fn default() -> Self {
        Self {
            require_mtls: true,
            trusted_ca_path: None,
            allowed_node_ids: Vec::new(),
            registration_timeout_secs: 60,
            failure_threshold_for_demotion: 3,
            failure_threshold_for_removal: 10,
            graceful_shutdown_lead_time_secs: 30,
            verification_timeout_secs: 600,
            verification_retry_interval_secs: 30,
            require_cert_chain_verification: false,
        }
    }
}

#[derive(Clone)]
pub struct MeshDnsRegistry {
    edge_nodes: Arc<RwLock<HashMap<String, RegisteredEdgeNode>>>,
    origin_nodes: Arc<RwLock<HashMap<String, RegisteredOriginNode>>>,
    anycast_nodes: Arc<RwLock<HashMap<String, RegisteredAnycastNode>>>,
    domain_to_origin_mapping: Arc<RwLock<HashMap<String, Vec<String>>>>,
    domain_to_anycast_mapping: Arc<RwLock<HashMap<String, Vec<String>>>>,
    registration_tx: Option<mpsc::Sender<DnsRegistrationRequest>>,
    health_tx: Option<mpsc::Sender<DnsHealthUpdate>>,
    shutdown_tx: Option<mpsc::Sender<DnsNodeShutdown>>,
    node_id: String,
    is_global: bool,
    config: MeshDnsRegistryConfig,
    trusted_certificates: Arc<RwLock<HashMap<String, MeshNodeCertificate>>>,
    dht_record_store: Option<Arc<crate::mesh::dht::record_store::RecordStoreManager>>,
    pending_verifications: Arc<RwLock<HashMap<String, DomainVerificationRequest>>>,
    routing_manager: Option<Arc<crate::mesh::dht::routing::manager::DhtRoutingManager>>,
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    verification_tx: Option<mpsc::Sender<VerificationTask>>,
    verification_failure_tx: Option<mpsc::Sender<VerificationFailure>>,
    verification_metrics: VerificationMetrics,
}

pub struct VerificationTask {
    pub request_id: String,
    pub domain: String,
    pub origin_node_id: String,
    pub challenge_token: String,
    pub verification_type: DomainVerificationType,
}

pub struct VerificationFailure {
    pub request_id: String,
    pub domain: String,
    pub origin_node_id: String,
    pub error_message: String,
}

#[derive(Clone)]
pub struct VerificationMetrics {
    verifications_initiated: Arc<std::sync::atomic::AtomicU64>,
    verifications_succeeded: Arc<std::sync::atomic::AtomicU64>,
    verifications_failed: Arc<std::sync::atomic::AtomicU64>,
    verifications_timeout: Arc<std::sync::atomic::AtomicU64>,
    txt_verifications: Arc<std::sync::atomic::AtomicU64>,
    ns_verifications: Arc<std::sync::atomic::AtomicU64>,
}

impl VerificationMetrics {
    pub fn new() -> Self {
        Self {
            verifications_initiated: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            verifications_succeeded: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            verifications_failed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            verifications_timeout: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            txt_verifications: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ns_verifications: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn record_initiated(&self, verification_type: &DomainVerificationType) {
        self.verifications_initiated
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match verification_type {
            DomainVerificationType::TxtChallenge => {
                self.txt_verifications
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            DomainVerificationType::NsRecord => {
                self.ns_verifications
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    pub fn record_succeeded(&self) {
        self.verifications_succeeded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_failed(&self) {
        self.verifications_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.verifications_timeout
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_summary(&self) -> VerificationMetricsSummary {
        VerificationMetricsSummary {
            initiated: self
                .verifications_initiated
                .load(std::sync::atomic::Ordering::Relaxed),
            succeeded: self
                .verifications_succeeded
                .load(std::sync::atomic::Ordering::Relaxed),
            failed: self
                .verifications_failed
                .load(std::sync::atomic::Ordering::Relaxed),
            timeouts: self
                .verifications_timeout
                .load(std::sync::atomic::Ordering::Relaxed),
            txt_verifications: self
                .txt_verifications
                .load(std::sync::atomic::Ordering::Relaxed),
            ns_verifications: self
                .ns_verifications
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

impl Default for VerificationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct VerificationMetricsSummary {
    pub initiated: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub timeouts: u64,
    pub txt_verifications: u64,
    pub ns_verifications: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_metrics_init() {
        let metrics = VerificationMetrics::new();
        let summary = metrics.get_summary();

        assert_eq!(summary.initiated, 0);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.timeouts, 0);
    }

    #[test]
    fn test_verification_metrics_record_initiated() {
        let metrics = VerificationMetrics::new();

        metrics.record_initiated(&DomainVerificationType::TxtChallenge);
        let summary = metrics.get_summary();
        assert_eq!(summary.initiated, 1);
        assert_eq!(summary.txt_verifications, 1);
        assert_eq!(summary.ns_verifications, 0);
    }

    #[test]
    fn test_verification_metrics_record_succeeded() {
        let metrics = VerificationMetrics::new();

        metrics.record_succeeded();
        let summary = metrics.get_summary();
        assert_eq!(summary.succeeded, 1);
    }

    #[test]
    fn test_verification_metrics_record_failed() {
        let metrics = VerificationMetrics::new();

        metrics.record_failed();
        let summary = metrics.get_summary();
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_verification_metrics_record_timeout() {
        let metrics = VerificationMetrics::new();

        metrics.record_timeout();
        let summary = metrics.get_summary();
        assert_eq!(summary.timeouts, 1);
    }

    #[test]
    fn test_mesh_dns_registry_config_defaults() {
        let config = MeshDnsRegistryConfig::default();

        assert_eq!(config.verification_timeout_secs, 600);
        assert_eq!(config.verification_retry_interval_secs, 30);
        assert!(config.require_mtls);
    }

    #[test]
    fn test_mesh_dns_registry_config_clone() {
        let config = MeshDnsRegistryConfig::default();
        let cloned = config.clone();

        assert_eq!(
            cloned.verification_timeout_secs,
            config.verification_timeout_secs
        );
        assert_eq!(
            cloned.verification_retry_interval_secs,
            config.verification_retry_interval_secs
        );
    }
}

#[derive(Clone)]
pub struct MeshSigningKey {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub key_id: String,
    pub derived_from_mesh_id: String,
}

impl MeshSigningKey {
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig_array: [u8; 64] = match signature.try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
        self.verifying_key.verify(message, &sig).is_ok()
    }
}

const DNS_SIGNING_INFO: &[u8] = b"dns-signing-key-v1";

pub fn derive_dns_signing_key(
    session_key: &[u8; 32],
    mesh_id: &str,
) -> Option<MeshSigningKey> {
    let salt = mesh_id.as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(salt), session_key);

    let mut okm = [0u8; 32];
    hk.expand(DNS_SIGNING_INFO, &mut okm).ok()?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&okm);
    let verifying_key = signing_key.verifying_key();

    let key_id = verifying_key.as_bytes()[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Some(MeshSigningKey {
        signing_key,
        verifying_key,
        key_id,
        derived_from_mesh_id: mesh_id.to_string(),
    })
}

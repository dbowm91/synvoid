use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::dns::messages::{DnsAnycastHealthUpdate, DnsAnycastNodeRegistration, DnsEdgeHealthReport, DnsHealthUpdate, DnsNodeRole, DnsRegistration, DnsRegistrationRequest, DnsNodeShutdown, DomainVerificationRequest, DomainVerificationStatus, DomainVerificationType, DnsRegistrationWithVerificationRequest, DnsRegistrationWithVerificationResponse};
use crate::dns::resolver::DnsResolver;

mod registry;
mod registration;
mod health;
mod query;
mod dht;
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
    pub authenticated: bool,
    pub edge_node_id: Option<String>,
    pub edge_node_geo: Option<String>,
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
        self.verifications_initiated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match verification_type {
            DomainVerificationType::TxtChallenge => { self.txt_verifications.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
            DomainVerificationType::NsRecord => { self.ns_verifications.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
        }
    }

    pub fn record_succeeded(&self) {
        self.verifications_succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_failed(&self) {
        self.verifications_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.verifications_timeout.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_summary(&self) -> VerificationMetricsSummary {
        VerificationMetricsSummary {
            initiated: self.verifications_initiated.load(std::sync::atomic::Ordering::Relaxed),
            succeeded: self.verifications_succeeded.load(std::sync::atomic::Ordering::Relaxed),
            failed: self.verifications_failed.load(std::sync::atomic::Ordering::Relaxed),
            timeouts: self.verifications_timeout.load(std::sync::atomic::Ordering::Relaxed),
            txt_verifications: self.txt_verifications.load(std::sync::atomic::Ordering::Relaxed),
            ns_verifications: self.ns_verifications.load(std::sync::atomic::Ordering::Relaxed),
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

        assert_eq!(cloned.verification_timeout_secs, config.verification_timeout_secs);
        assert_eq!(cloned.verification_retry_interval_secs, config.verification_retry_interval_secs);
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use async_trait::async_trait;

use metrics::{counter, gauge};

use crate::dns::messages::{DnsAnycastHealthUpdate, DnsAnycastNodeRegistration, DnsEdgeHealthReport, DnsHealthUpdate, DnsNodeRole, DnsRegistration, DnsRegistrationRequest, DnsNodeShutdown, DomainVerificationRequest, DomainVerificationStatus, DomainVerificationType, DnsRegistrationWithVerificationRequest, DnsRegistrationWithVerificationResponse, DomainVerificationStatusUpdate};
use crate::dns::resolver::{DnsResolver, ResolverError};

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

impl MeshDnsRegistry {
    const DEFAULT_VERIFICATION_TIMEOUT_SECS: u64 = 600;
    const DEFAULT_VERIFICATION_RETRY_INTERVAL_SECS: u64 = 30;
    const MAX_REGISTRATION_RETRIES: usize = 3;
    const REGISTRATION_TIMEOUT_SECS: u64 = 10;

    pub fn new(node_id: String, is_global: bool) -> Self {
        Self::with_config(node_id, is_global, MeshDnsRegistryConfig::default())
    }

    pub fn with_config(node_id: String, is_global: bool, config: MeshDnsRegistryConfig) -> Self {
        Self {
            edge_nodes: Arc::new(RwLock::new(HashMap::new())),
            origin_nodes: Arc::new(RwLock::new(HashMap::new())),
            anycast_nodes: Arc::new(RwLock::new(HashMap::new())),
            domain_to_origin_mapping: Arc::new(RwLock::new(HashMap::new())),
            domain_to_anycast_mapping: Arc::new(RwLock::new(HashMap::new())),
            registration_tx: None,
            health_tx: None,
            shutdown_tx: None,
            node_id,
            is_global,
            config,
            trusted_certificates: Arc::new(RwLock::new(HashMap::new())),
            dht_record_store: None,
            pending_verifications: Arc::new(RwLock::new(HashMap::new())),
            routing_manager: None,
            dns_resolver: None,
            verification_tx: None,
            verification_failure_tx: None,
            verification_metrics: VerificationMetrics::new(),
        }
    }

    pub fn with_dns_resolver<R: DnsResolver + 'static>(mut self, resolver: R) -> Self {
        self.dns_resolver = Some(Arc::new(resolver));
        self
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn is_global(&self) -> bool {
        self.is_global
    }

    pub fn with_verification_channel(
        mut self,
        verification_tx: mpsc::Sender<VerificationTask>,
        verification_failure_tx: mpsc::Sender<VerificationFailure>,
    ) -> Self {
        self.verification_tx = Some(verification_tx);
        self.verification_failure_tx = Some(verification_failure_tx);
        self
    }

    pub fn with_routing_manager(mut self, rm: Arc<crate::mesh::dht::routing::manager::DhtRoutingManager>) -> Self {
        self.routing_manager = Some(rm);
        self
    }

    pub fn with_dht_record_store(mut self, store: Arc<crate::mesh::dht::record_store::RecordStoreManager>) -> Self {
        self.dht_record_store = Some(store);
        self
    }

    pub fn load_trusted_certificate(&self, cert: MeshNodeCertificate) -> Result<(), String> {
        if !cert.is_valid() {
            return Err("Certificate is expired or not yet valid".to_string());
        }
        let mut certs = self.trusted_certificates.write();
        certs.insert(cert.node_id.clone(), cert);
        tracing::info!("Loaded trusted certificate for node");
        Ok(())
    }

    pub fn remove_trusted_certificate(&self, node_id: &str) -> Result<(), String> {
        let mut certs = self.trusted_certificates.write();
        certs.remove(node_id);
        tracing::info!("Removed trusted certificate for node {}", node_id);
        Ok(())
    }

    fn verify_registration(&self, node_id: &str, certificate_fingerprint: Option<&str>) -> bool {
        if !self.config.require_mtls {
            return true;
        }

        if self.config.allowed_node_ids.is_empty() {
            return false;
        }

        if !self.config.allowed_node_ids.contains(&node_id.to_string()) {
            return false;
        }

        if let Some(fingerprint) = certificate_fingerprint {
            let certs = self.trusted_certificates.read();
            if let Some(cert) = certs.get(node_id) {
                return cert.fingerprint_sha256 == fingerprint;
            }
        }

        false
    }

    pub fn set_registration_sender(&mut self, tx: mpsc::Sender<DnsRegistrationRequest>) {
        self.registration_tx = Some(tx);
    }

    pub fn set_health_sender(&mut self, tx: mpsc::Sender<DnsHealthUpdate>) {
        self.health_tx = Some(tx);
    }

    pub fn set_shutdown_sender(&mut self, tx: mpsc::Sender<DnsNodeShutdown>) {
        self.shutdown_tx = Some(tx);
    }

    pub async fn register_origin_node(&self, registration: DnsRegistration) -> Result<(), String> {
        if !self.is_global {
            if let Some(ref tx) = self.registration_tx {
                let request = DnsRegistrationRequest {
                    node_id: self.node_id.clone(),
                    domains: vec![registration.clone()],
                    is_global: false,
                    certificate_fingerprint: registration.certificate_fingerprint.clone(),
                    role: DnsNodeRole::Origin,
                };
                tx.send(request).await.map_err(|e| format!("Failed to send registration: {}", e))?;
            }
        }

        let authenticated = self.verify_registration(&registration.node_id, registration.certificate_fingerprint.as_deref());

        if !authenticated && self.config.require_mtls {
            tracing::warn!("Unauthenticated origin registration rejected for node {}", registration.node_id);
            return Err("Registration requires mTLS authentication".to_string());
        }

        let origin = RegisteredOriginNode {
            node_id: registration.node_id.clone(),
            domains: vec![registration.domain.clone()],
            geo: registration.geo.clone(),
            healthy: registration.healthy,
            capacity: registration.capacity,
            latency_ms: registration.latency_ms,
            load_percent: None,
            last_update: chrono::Utc::now().timestamp() as u64,
            authenticated,
            edge_node_id: registration.edge_node_id.clone(),
            edge_node_geo: registration.edge_node_geo.clone(),
        };

        self.origin_nodes.write().insert(registration.node_id.clone(), origin);

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            mapping.entry(registration.domain.clone())
                .or_insert_with(Vec::new)
                .push(registration.node_id.clone());
        }

        if self.is_global {
            if let Some(ref dht_store) = self.dht_record_store {
                let ip_addresses = registration.ip_addresses.clone();
                let ttl = 600;
                let stored = dht_store.store_dns_domain_registration(
                    registration.domain.clone(),
                    registration.node_id.clone(),
                    ip_addresses,
                    ttl,
                );
                if stored {
                    tracing::info!("Propagated domain registration to DHT: {}", registration.domain);
                }
            }
        }
        
        tracing::info!("Registered origin node {} for domain {}", registration.node_id, registration.domain);
        Ok(())
    }

    pub async fn register_edge_node(&self, registration: DnsRegistration) -> Result<(), String> {
        if !self.is_global {
            if let Some(ref tx) = self.registration_tx {
                let request = DnsRegistrationRequest {
                    node_id: self.node_id.clone(),
                    domains: vec![registration.clone()],
                    is_global: false,
                    certificate_fingerprint: registration.certificate_fingerprint.clone(),
                    role: DnsNodeRole::Edge,
                };
                tx.send(request).await.map_err(|e| format!("Failed to send registration: {}", e))?;
            }
        }

        let authenticated = self.verify_registration(&registration.node_id, registration.certificate_fingerprint.as_deref());

        if !authenticated && self.config.require_mtls {
            tracing::warn!("Unauthenticated edge registration rejected for node {}", registration.node_id);
            return Err("Registration requires mTLS authentication".to_string());
        }

        let edge = RegisteredEdgeNode {
            node_id: registration.node_id.clone(),
            domains: vec![registration.domain.clone()],
            ip_addresses: registration.ip_addresses.clone(),
            geo: registration.geo.clone(),
            healthy: registration.healthy,
            latency_ms: registration.latency_ms,
            load_percent: None,
            consecutive_failures: 0,
            last_failure_reason: None,
            last_update: chrono::Utc::now().timestamp() as u64,
            authenticated,
            domains_origin_mapping: HashMap::new(),
        };

        self.edge_nodes.write().insert(registration.node_id.clone(), edge);
        
        tracing::info!("Registered edge node {} for domain {}", registration.node_id, registration.domain);
        Ok(())
    }

    pub async fn register_anycast_node(&self, registration: DnsAnycastNodeRegistration) -> Result<(), String> {
        if !self.is_global {
            tracing::debug!("Ignoring anycast registration on non-global node");
            return Ok(());
        }

        let authenticated = self.verify_registration(&registration.node_id, registration.certificate_fingerprint.as_deref());

        if !authenticated && self.config.require_mtls {
            tracing::warn!("Unauthenticated anycast registration rejected for node {}", registration.node_id);
            return Err("Registration requires mTLS authentication".to_string());
        }

        let anycast = RegisteredAnycastNode {
            node_id: registration.node_id.clone(),
            anycast_ips: registration.anycast_ips.clone(),
            geo: registration.geo.clone(),
            healthy: registration.healthy,
            capacity: registration.capacity,
            latency_ms: None,
            load_percent: None,
            last_update: chrono::Utc::now().timestamp() as u64,
            authenticated,
            dns_zones: registration.dns_zones.clone(),
        };

        self.anycast_nodes.write().insert(registration.node_id.clone(), anycast);

        for zone in &registration.dns_zones {
            let mut mapping = self.domain_to_anycast_mapping.write();
            mapping.entry(zone.clone())
                .or_insert_with(Vec::new)
                .push(registration.node_id.clone());
        }

        if let Some(ref dht_store) = self.dht_record_store {
            dht_store.store_anycast_node(
                registration.node_id.clone(),
                registration.anycast_ips.clone(),
                registration.geo.as_ref().map(|g| g.to_string()),
                registration.capacity,
                registration.healthy,
                registration.dns_zones.clone(),
            );
            tracing::debug!("Stored anycast node {} in DHT", registration.node_id);
        }

        tracing::info!("Registered anycast node {} with IPs {:?}", registration.node_id, registration.anycast_ips);
        Ok(())
    }

    pub async fn update_anycast_health(&self, update: DnsAnycastHealthUpdate) -> Result<(), String> {
        if !self.is_global {
            tracing::debug!("Ignoring anycast health update on non-global node");
            return Ok(());
        }

        let (geo, capacity, dns_zones, was_healthy) = {
            let mut anycast_nodes = self.anycast_nodes.write();
            if let Some(node) = anycast_nodes.get_mut(&update.node_id) {
                let was_healthy = node.healthy;
                node.healthy = update.healthy;
                node.latency_ms = update.latency_ms;
                node.load_percent = update.load_percent;
                node.last_update = chrono::Utc::now().timestamp() as u64;
                
                if let Some(latency) = update.latency_ms {
                    gauge!("dns_anycast_node_latency_ms").set(latency as f64);
                }
                if let Some(load) = update.load_percent {
                    gauge!("dns_anycast_node_load_percent").set(load as f64);
                }
                
                (node.geo.clone(), node.capacity, node.dns_zones.clone(), was_healthy)
            } else {
                return Ok(());
            }
        };

        if update.healthy != was_healthy {
            gauge!("dns_anycast_node_healthy").set(if update.healthy { 1.0 } else { 0.0 });
        }

        let healthy_count = {
            let nodes = self.anycast_nodes.read();
            nodes.values().filter(|n| n.healthy).count()
        };
        gauge!("dns_anycast_healthy_nodes").set(healthy_count as f64);

        if let Some(ref dht_store) = self.dht_record_store {
            dht_store.store_anycast_node(
                update.node_id.clone(),
                update.anycast_ips.clone(),
                geo.as_ref().map(|g| g.to_string()),
                capacity,
                update.healthy,
                dns_zones,
            );
            tracing::debug!("Updated anycast node {} health in DHT", update.node_id);
        }

        Ok(())
    }

    pub fn get_healthy_anycast_nodes(&self) -> Vec<RegisteredAnycastNode> {
        let nodes = self.anycast_nodes.read();
        nodes
            .values()
            .filter(|n| n.healthy)
            .cloned()
            .collect()
    }

    pub fn get_healthy_anycast_for_zone(&self, zone: &str) -> Vec<RegisteredAnycastNode> {
        let nodes = self.anycast_nodes.read();
        let mapping = self.domain_to_anycast_mapping.read();
        
        if let Some(node_ids) = mapping.get(zone) {
            node_ids
                .iter()
                .filter_map(|id| nodes.get(id).cloned())
                .filter(|n| n.healthy)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn query_anycast_from_dht(&self, zone: &str) -> Vec<RegisteredAnycastNode> {
        if !self.is_global {
            return Vec::new();
        }

        if let Some(ref dht_store) = self.dht_record_store {
            let nodes = dht_store.get_anycast_nodes_for_zone(zone);
            nodes
                .into_iter()
                .filter_map(|value| {
                    let node_id = value.get("node_id")?.as_str()?;
                    let anycast_ips: Vec<String> = value.get("anycast_ips")?
                        .as_array()?
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    let geo = value.get("geo").and_then(|v| v.as_str()).map(String::from);
                    let capacity = value.get("capacity")?.as_u64()? as u32;
                    let healthy = value.get("healthy")?.as_bool()?;
                    let dns_zones: Vec<String> = value.get("dns_zones")?
                        .as_array()?
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();

                    Some(RegisteredAnycastNode {
                        node_id: node_id.to_string(),
                        anycast_ips,
                        geo: geo.map(String::into),
                        healthy,
                        capacity,
                        latency_ms: None,
                        load_percent: None,
                        last_update: chrono::Utc::now().timestamp() as u64,
                        authenticated: false,
                        dns_zones,
                    })
                })
                .filter(|n| n.healthy)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn has_anycast_for_zone(&self, zone: &str) -> bool {
        let nodes = self.anycast_nodes.read();
        nodes
            .values()
            .any(|n| n.dns_zones.iter().any(|z| z == zone) && n.healthy)
    }

    pub async fn remove_anycast_node(&self, node_id: &str) -> Result<(), String> {
        let zones = {
            let mut nodes = self.anycast_nodes.write();
            
            if let Some(node) = nodes.remove(node_id) {
                let mut mapping = self.domain_to_anycast_mapping.write();
                for zone in &node.dns_zones {
                    if let Some(node_ids) = mapping.get_mut(zone) {
                        node_ids.retain(|id| id != node_id);
                        if node_ids.is_empty() {
                            mapping.remove(zone);
                        }
                    }
                }
                tracing::info!("Removed anycast node {}", node_id);
                node.dns_zones
            } else {
                Vec::new()
            }
        };
        
        if !zones.is_empty() {
            if let Some(ref dht_store) = self.dht_record_store {
                dht_store.remove_anycast_node(node_id);
                tracing::debug!("Removed anycast node {} from DHT", node_id);
            }
        }
        
        Ok(())
    }

    pub fn get_best_anycast_for_zone(&self, zone: &str, client_geo: Option<&str>) -> Option<RegisteredAnycastNode> {
        let all_nodes = self.get_healthy_anycast_for_zone(zone);
        
        if all_nodes.is_empty() {
            return None;
        }

        let Some(client_geo) = client_geo else {
            return all_nodes.into_iter().next();
        };

        let mut scored_nodes: Vec<(RegisteredAnycastNode, f64)> = all_nodes
            .into_iter()
            .map(|node| {
                let score = self.calculate_anycast_score(&node, Some(client_geo));
                (node, score)
            })
            .collect();

        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_nodes.into_iter().next().map(|(node, _)| node)
    }

    fn calculate_anycast_score(&self, node: &RegisteredAnycastNode, client_geo: Option<&str>) -> f64 {
        let mut score = 100.0;

        if let Some(geo) = client_geo {
            if let Some(ref node_geo) = node.geo {
                let node_geo_parts: Vec<&str> = node_geo.split(',').collect();
                let client_geo_parts: Vec<&str> = geo.split(',').collect();

                if let Some(node_country) = node_geo_parts.first() {
                    if let Some(client_country) = client_geo_parts.first() {
                        if node_country.eq_ignore_ascii_case(client_country) {
                            score += 50.0;
                        }
                    }
                }

                if node_geo_parts.len() > 1 && client_geo_parts.len() > 1 {
                    if let Some(node_region) = node_geo_parts.get(1) {
                        if let Some(client_region) = client_geo_parts.get(1) {
                            if node_region.eq_ignore_ascii_case(client_region) {
                                score += 30.0;
                            }
                        }
                    }
                }

                if node_geo.eq_ignore_ascii_case(geo) {
                    score += 20.0;
                }
            }
        }

        if let Some(latency) = node.latency_ms {
            score -= (latency as f64) * 0.1;
        }

        if let Some(load) = node.load_percent {
            score -= (load as f64) * 0.5;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if node.last_update > 0 && now > node.last_update {
            let age_secs = now - node.last_update;
            if age_secs > 300 {
                score -= ((age_secs - 300) / 60) as f64 * 1.0;
            }
        }

        score
    }

    pub async fn update_origin_health(&self, update: DnsHealthUpdate) -> Result<(), String> {
        if !self.is_global {
            if let Some(ref tx) = self.health_tx {
                tx.send(update.clone()).await.map_err(|e| format!("Failed to send health update: {}", e))?;
            }
        }

        let mut origins = self.origin_nodes.write();
        if let Some(node) = origins.get_mut(&update.node_id) {
            node.healthy = update.healthy;
            node.latency_ms = update.latency_ms;
            node.load_percent = update.load_percent;
            node.last_update = chrono::Utc::now().timestamp() as u64;
        }

        Ok(())
    }

    pub async fn update_edge_health(&self, report: DnsEdgeHealthReport) -> Result<(), String> {
        let mut edges = self.edge_nodes.write();
        
        if let Some(edge) = edges.get_mut(&report.edge_node_id) {
            edge.last_update = chrono::Utc::now().timestamp() as u64;
            
            if report.healthy {
                edge.consecutive_failures = 0;
                edge.last_failure_reason = None;
            } else {
                edge.consecutive_failures += 1;
                edge.last_failure_reason = report.last_failure_reason.clone();
            }

            if edge.consecutive_failures >= self.config.failure_threshold_for_removal {
                tracing::warn!("Edge node {} exceeded failure threshold, marking unhealthy", report.edge_node_id);
                edge.healthy = false;
            } else if edge.consecutive_failures >= self.config.failure_threshold_for_demotion {
                tracing::warn!("Edge node {} exceeded demotion threshold, reducing priority", report.edge_node_id);
            }
        }

        Ok(())
    }

    pub async fn handle_node_shutdown(&self, shutdown: DnsNodeShutdown) -> Result<(), String> {
        if !self.is_global {
            if let Some(ref tx) = self.shutdown_tx {
                tx.send(shutdown.clone()).await.map_err(|e| format!("Failed to send shutdown: {}", e))?;
            }
        }

        let now = chrono::Utc::now().timestamp() as u64;
        
        if shutdown.graceful {
            let lead_time = self.config.graceful_shutdown_lead_time_secs;
            let effective_shutdown_at = shutdown.shutdown_at.saturating_sub(lead_time);
            
            if effective_shutdown_at > now {
                tracing::info!("Node {} announcing graceful shutdown at {}, removing from DNS at {}", 
                    shutdown.node_id, shutdown.shutdown_at, effective_shutdown_at);
            }
        }

        match shutdown.role {
            DnsNodeRole::Edge => {
                let mut edges = self.edge_nodes.write();
                for domain in &shutdown.domains {
                    tracing::info!("Removing edge node {} from DNS for domain {} due to shutdown", shutdown.node_id, domain);
                }
                edges.remove(&shutdown.node_id);
            }
            DnsNodeRole::Origin => {
                let mut origins = self.origin_nodes.write();
                let mut mapping = self.domain_to_origin_mapping.write();
                
                for domain in &shutdown.domains {
                    if let Some(origin_ids) = mapping.get_mut(domain) {
                        origin_ids.retain(|id| id != &shutdown.node_id);
                    }
                    tracing::info!("Removing origin node {} from DNS for domain {} due to shutdown", shutdown.node_id, domain);
                }
                origins.remove(&shutdown.node_id);
            }
        }

        Ok(())
    }

    pub fn handle_registration_request(&self, request: DnsRegistrationRequest) -> Result<(), String> {
        if !self.is_global {
            return Ok(());
        }

        let authenticated = self.verify_registration(&request.node_id, request.certificate_fingerprint.as_deref());

        if !authenticated && self.config.require_mtls {
            tracing::warn!("Unauthenticated registration request rejected for node {}", request.node_id);
            return Err("Registration request requires mTLS authentication".to_string());
        }

        match request.role {
            DnsNodeRole::Origin => {
                let mut origins = self.origin_nodes.write();
                let mut mapping = self.domain_to_origin_mapping.write();
                
                for reg in request.domains {
                    let origin = RegisteredOriginNode {
                        node_id: reg.node_id.clone(),
                        domains: vec![reg.domain.clone()],
                        geo: reg.geo.clone(),
                        healthy: reg.healthy,
                        capacity: reg.capacity,
                        latency_ms: reg.latency_ms,
                        load_percent: None,
                        last_update: chrono::Utc::now().timestamp() as u64,
                        authenticated,
                        edge_node_id: reg.edge_node_id.clone(),
                        edge_node_geo: reg.edge_node_geo.clone(),
                    };
                    origins.insert(reg.node_id.clone(), origin);
                    
                    mapping.entry(reg.domain.clone())
                        .or_insert_with(Vec::new)
                        .push(reg.node_id.clone());
                    
                    tracing::info!("Registered origin {} for domain {} (authenticated: {})", reg.node_id, reg.domain, authenticated);
                }
            }
            DnsNodeRole::Edge => {
                let mut edges = self.edge_nodes.write();
                
                for reg in request.domains {
                    let edge = RegisteredEdgeNode {
                        node_id: reg.node_id.clone(),
                        domains: vec![reg.domain.clone()],
                        ip_addresses: reg.ip_addresses.clone(),
                        geo: reg.geo.clone(),
                        healthy: reg.healthy,
                        latency_ms: reg.latency_ms,
                        load_percent: None,
                        consecutive_failures: 0,
                        last_failure_reason: None,
                        last_update: chrono::Utc::now().timestamp() as u64,
                        authenticated,
                        domains_origin_mapping: HashMap::new(),
                    };
                    edges.insert(reg.node_id.clone(), edge);
                    
                    tracing::info!("Registered edge {} for domain {} (authenticated: {})", reg.node_id, reg.domain, authenticated);
                }
            }
        }
        
        Ok(())
    }

    pub fn get_edge_nodes_for_domain(&self, domain: &str) -> Vec<RegisteredEdgeNode> {
        let edges = self.edge_nodes.read();
        
        edges
            .values()
            .filter(|n| n.domains.iter().any(|d| d == domain))
            .filter(|n| n.healthy)
            .filter(|n| n.consecutive_failures < self.config.failure_threshold_for_removal)
            .cloned()
            .collect()
    }

    pub fn get_origin_nodes_for_domain(&self, domain: &str) -> Vec<RegisteredOriginNode> {
        let origins = self.origin_nodes.read();
        
        origins
            .values()
            .filter(|n| n.domains.iter().any(|d| d == domain))
            .filter(|n| n.healthy)
            .cloned()
            .collect()
    }

    pub fn get_edge_nodes_for_domain_geo(
        &self, 
        domain: &str, 
        client_geo: Option<&str>,
    ) -> Vec<RegisteredEdgeNode> {
        let all_nodes = self.get_edge_nodes_for_domain(domain);
        
        let Some(client_geo) = client_geo else {
            return all_nodes;
        };

        let mut scored_nodes: Vec<(RegisteredEdgeNode, f64)> = all_nodes
            .into_iter()
            .map(|node| {
                let score = self.calculate_geo_score_for_edge(&node, client_geo);
                (node, score)
            })
            .collect();

        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_nodes.into_iter().map(|(node, _)| node).collect()
    }

    pub fn get_origin_nodes_for_domain_geo(
        &self, 
        domain: &str, 
        client_geo: Option<&str>,
    ) -> Vec<RegisteredOriginNode> {
        let all_nodes = self.get_origin_nodes_for_domain(domain);
        
        let Some(client_geo) = client_geo else {
            return all_nodes;
        };

        let mut scored_nodes: Vec<(RegisteredOriginNode, f64)> = all_nodes
            .into_iter()
            .map(|node| {
                let score = self.calculate_geo_score_for_origin(&node, client_geo);
                (node, score)
            })
            .collect();

        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_nodes.into_iter().map(|(node, _)| node).collect()
    }

    pub fn get_best_edge_for_client(
        &self,
        domain: &str,
        _client_ip: Option<std::net::IpAddr>,
        client_geo: Option<&str>,
    ) -> Option<RegisteredEdgeNode> {
        let nodes = self.get_edge_nodes_for_domain_geo(domain, client_geo);
        
        if nodes.is_empty() {
            return None;
        }

        if nodes.len() == 1 {
            return Some(nodes[0].clone());
        }

        let mut best_node = None;
        let mut best_score = f64::MIN;

        for node in nodes {
            let score = self.calculate_edge_score(&node, client_geo);
            if score > best_score {
                best_score = score;
                best_node = Some(node);
            }
        }

        best_node
    }

    pub fn get_best_origin_for_edge(
        &self,
        domain: &str,
        edge_node_id: &str,
        client_geo: Option<&str>,
    ) -> Option<RegisteredOriginNode> {
        let edges = self.edge_nodes.read();
        let edge = edges.get(edge_node_id);
        
        let origins = self.get_origin_nodes_for_domain_geo(domain, client_geo);
        
        let filtered: Vec<RegisteredOriginNode> = origins
            .into_iter()
            .filter(|origin| {
                if let Some(ref edge) = edge {
                    origin.edge_node_id.as_ref() == Some(&edge.node_id) || 
                    origin.edge_node_id.is_none()
                } else {
                    true
                }
            })
            .collect();

        if filtered.is_empty() {
            return None;
        }

        let mut best_node = None;
        let mut best_score = f64::MIN;

        for node in filtered {
            let score = self.calculate_origin_score(&node, client_geo);
            if score > best_score {
                best_score = score;
                best_node = Some(node);
            }
        }

        best_node
    }

    fn calculate_geo_score_for_edge(&self, node: &RegisteredEdgeNode, client_geo: &str) -> f64 {
        let mut score = 0.0;

        if let Some(ref node_geo) = node.geo {
            let node_geo_parts: Vec<&str> = node_geo.split(',').collect();
            let client_geo_parts: Vec<&str> = client_geo.split(',').collect();

            if let Some(node_country) = node_geo_parts.first() {
                if let Some(client_country) = client_geo_parts.first() {
                    if node_country.eq_ignore_ascii_case(client_country) {
                        score += 100.0;
                    }
                }
            }

            if node_geo_parts.len() > 1 && client_geo_parts.len() > 1 {
                if let Some(node_region) = node_geo_parts.get(1) {
                    if let Some(client_region) = client_geo_parts.get(1) {
                        if node_region.eq_ignore_ascii_case(client_region) {
                            score += 50.0;
                        }
                    }
                }
            }

            if node_geo.eq_ignore_ascii_case(client_geo) {
                score += 25.0;
            }
        }

        score
    }

    fn calculate_geo_score_for_origin(&self, node: &RegisteredOriginNode, client_geo: &str) -> f64 {
        let mut score = 0.0;

        if let Some(ref node_geo) = node.geo {
            let node_geo_parts: Vec<&str> = node_geo.split(',').collect();
            let client_geo_parts: Vec<&str> = client_geo.split(',').collect();

            if let Some(node_country) = node_geo_parts.first() {
                if let Some(client_country) = client_geo_parts.first() {
                    if node_country.eq_ignore_ascii_case(client_country) {
                        score += 100.0;
                    }
                }
            }

            if node_geo_parts.len() > 1 && client_geo_parts.len() > 1 {
                if let Some(node_region) = node_geo_parts.get(1) {
                    if let Some(client_region) = client_geo_parts.get(1) {
                        if node_region.eq_ignore_ascii_case(client_region) {
                            score += 50.0;
                        }
                    }
                }
            }

            if node_geo.eq_ignore_ascii_case(client_geo) {
                score += 25.0;
            }
        }

        score
    }

    fn calculate_edge_score(&self, node: &RegisteredEdgeNode, client_geo: Option<&str>) -> f64 {
        let mut score = 100.0;

        if let Some(geo) = client_geo {
            score += self.calculate_geo_score_for_edge(node, geo);
        }

        if let Some(latency) = node.latency_ms {
            score -= (latency as f64) * 0.1;
        }

        if let Some(load) = node.load_percent {
            score -= (load as f64) * 0.5;
        }

        if node.consecutive_failures > 0 {
            score -= (node.consecutive_failures as f64) * 10.0;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if node.last_update > 0 && now > node.last_update {
            let age_secs = now - node.last_update;
            if age_secs > 300 {
                score -= ((age_secs - 300) / 60) as f64 * 1.0;
            }
        }

        if !node.authenticated {
            score -= 50.0;
        }

        score
    }

    fn calculate_origin_score(&self, node: &RegisteredOriginNode, client_geo: Option<&str>) -> f64 {
        let mut score = 100.0;

        if let Some(geo) = client_geo {
            score += self.calculate_geo_score_for_origin(node, geo);
        }

        if let Some(latency) = node.latency_ms {
            score -= (latency as f64) * 0.1;
        }

        if let Some(load) = node.load_percent {
            score -= (load as f64) * 0.5;
        }

        if node.capacity > 0 {
            score += (node.capacity as f64) * 0.01;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if node.last_update > 0 && now > node.last_update {
            let age_secs = now - node.last_update;
            if age_secs > 300 {
                score -= ((age_secs - 300) / 60) as f64 * 1.0;
            }
        }

        if !node.authenticated {
            score -= 50.0;
        }

        score
    }

    pub fn get_all_healthy_edge_nodes(&self) -> Vec<RegisteredEdgeNode> {
        let edges = self.edge_nodes.read();
        
        edges
            .values()
            .filter(|n| n.healthy)
            .filter(|n| n.consecutive_failures < self.config.failure_threshold_for_removal)
            .cloned()
            .collect()
    }

    pub fn get_all_healthy_origin_nodes(&self) -> Vec<RegisteredOriginNode> {
        let origins = self.origin_nodes.read();
        
        origins
            .values()
            .filter(|n| n.healthy)
            .cloned()
            .collect()
    }

    pub fn get_registered_edge_nodes(&self) -> HashMap<String, RegisteredEdgeNode> {
        self.edge_nodes.read().clone()
    }

    pub fn get_registered_origin_nodes(&self) -> HashMap<String, RegisteredOriginNode> {
        self.origin_nodes.read().clone()
    }

    pub fn cleanup_stale_edge_nodes(&self, max_age_secs: u64) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut edges = self.edge_nodes.write();
        
        edges.retain(|_, node| {
            now - node.last_update < max_age_secs
        });
    }

    pub fn cleanup_stale_origin_nodes(&self, max_age_secs: u64) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut origins = self.origin_nodes.write();
        
        origins.retain(|_, node| {
            now - node.last_update < max_age_secs
        });
    }

    pub fn has_origin_for_domain(&self, domain: &str) -> bool {
        let origins = self.origin_nodes.read();
        origins.values().any(|n| n.domains.iter().any(|d| d == domain) && n.healthy)
    }

    pub fn has_edge_for_domain(&self, domain: &str) -> bool {
        let edges = self.edge_nodes.read();
        edges.values().any(|n| n.domains.iter().any(|d| d == domain) && n.healthy && n.consecutive_failures < self.config.failure_threshold_for_removal)
    }

    pub fn remove_origin(&self, node_id: &str, domain: &str) -> Result<(), String> {
        let mut origins = self.origin_nodes.write();
        let mut mapping = self.domain_to_origin_mapping.write();
        
        if let Some(origin) = origins.get_mut(node_id) {
            origin.domains.retain(|d| d != domain);
            if origin.domains.is_empty() {
                origins.remove(node_id);
            }
        }
        
        if let Some(origin_ids) = mapping.get_mut(domain) {
            origin_ids.retain(|id| id != node_id);
            if origin_ids.is_empty() {
                mapping.remove(domain);
            }
        }
        
        tracing::info!("Removed origin {} for domain {} from DNS registry", node_id, domain);
        Ok(())
    }

    pub fn apply_dht_domain_registration(&self, domain: String, origin_node_id: String, ip_addresses: Vec<String>) {
        if !self.is_global {
            tracing::debug!("Ignoring DHT domain registration on non-global node");
            return;
        }

        let origin = RegisteredOriginNode {
            node_id: origin_node_id.clone(),
            domains: vec![domain.clone()],
            geo: None,
            healthy: true,
            capacity: 100,
            latency_ms: None,
            load_percent: None,
            last_update: chrono::Utc::now().timestamp() as u64,
            authenticated: true,
            edge_node_id: None,
            edge_node_geo: None,
        };

        self.origin_nodes.write().insert(origin_node_id.clone(), origin);

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            mapping.entry(domain.clone())
                .or_insert_with(Vec::new)
                .push(origin_node_id.clone());
        }

        tracing::info!("Applied domain registration from DHT: {} -> {}", domain, origin_node_id);
    }

    pub fn sync_from_dht(&self) {
        if !self.is_global {
            return;
        }

        if let Some(ref dht_store) = self.dht_record_store {
            let registrations = dht_store.get_all_dns_domain_registrations();
            for (domain, origin_id, ips) in registrations {
                let existing = {
                    let origins = self.origin_nodes.read();
                    origins.get(&origin_id).cloned()
                };

                if existing.is_none() {
                    self.apply_dht_domain_registration(domain, origin_id, ips);
                }
            }

            let anycast_nodes = dht_store.get_all_anycast_nodes();
            for node_value in anycast_nodes {
                if let (Some(node_id), Some(anycast_ips), Some(geo), Some(capacity), Some(healthy), Some(dns_zones)) = (
                    node_value.get("node_id").and_then(|v| v.as_str()),
                    node_value.get("anycast_ips").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>()),
                    node_value.get("geo").and_then(|v| v.as_str()).map(String::from),
                    node_value.get("capacity").and_then(|v| v.as_u64()).map(|v| v as u32),
                    node_value.get("healthy").and_then(|v| v.as_bool()),
                    node_value.get("dns_zones").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>()),
                ) {
                    let existing = {
                        let nodes = self.anycast_nodes.read();
                        nodes.get(node_id).cloned()
                    };

                    if existing.is_none() {
                        let anycast = RegisteredAnycastNode {
                            node_id: node_id.to_string(),
                            anycast_ips,
                            geo: Some(geo.into()),
                            healthy,
                            capacity,
                            latency_ms: None,
                            load_percent: None,
                            last_update: chrono::Utc::now().timestamp() as u64,
                            authenticated: false,
                            dns_zones: dns_zones.clone(),
                        };

                        self.anycast_nodes.write().insert(node_id.to_string(), anycast);

                        for zone in &dns_zones {
                            let mut mapping = self.domain_to_anycast_mapping.write();
                            mapping.entry(zone.clone())
                                .or_insert_with(Vec::new)
                                .push(node_id.to_string());
                        }

                        tracing::info!("Synced anycast node {} from DHT", node_id);
                    }
                }
            }
        }
    }

    pub fn initiate_domain_verification(&self, domain: String, origin_node_id: String, verify_ownership: bool, ip_addresses: Vec<String>) -> DomainVerificationRequest {
        let now = chrono::Utc::now().timestamp() as u64;
        let request_id = format!("{}-{}-{}", domain, origin_node_id, now);

        let verification_type = if verify_ownership {
            DomainVerificationType::TxtChallenge
        } else {
            DomainVerificationType::NsRecord
        };

        let challenge_token = uuid::Uuid::new_v4().to_string();
        
        let request = DomainVerificationRequest {
            request_id: request_id.clone(),
            domain: domain.clone(),
            origin_node_id: origin_node_id.clone(),
            verification_type: verification_type.clone(),
            challenge_token: Some(challenge_token),
            ip_addresses,
            created_at: now,
            expires_at: now + self.config.verification_timeout_secs,
        };

        self.pending_verifications.write().insert(request_id, request.clone());
        
        self.verification_metrics.record_initiated(&verification_type);
        tracing::info!("Initiated domain verification for {} (type: {:?})", domain, verification_type);
        
        request
    }

    pub fn get_pending_verification(&self, request_id: &str) -> Option<DomainVerificationRequest> {
        self.pending_verifications.read().get(request_id).cloned()
    }

    pub fn get_pending_verifications_for_domain(&self, domain: &str) -> Vec<DomainVerificationRequest> {
        self.pending_verifications.read()
            .values()
            .filter(|v| v.domain == domain)
            .cloned()
            .collect()
    }

    pub fn get_verification_metrics(&self) -> VerificationMetricsSummary {
        self.verification_metrics.get_summary()
    }

    pub fn update_verification_status(&self, request_id: &str, status: DomainVerificationStatus, error_message: Option<String>) -> bool {
        let mut pending = self.pending_verifications.write();
        
        if let Some(verification) = pending.get_mut(request_id) {
            match status {
                DomainVerificationStatus::Verified => {
                    tracing::info!("Domain verification completed for {}: {}", verification.domain, request_id);
                }
                DomainVerificationStatus::Failed => {
                    tracing::warn!("Domain verification failed for {}: {} - {:?}", 
                        verification.domain, request_id, error_message);
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }

    pub fn cleanup_expired_verifications(&self) -> usize {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut pending = self.pending_verifications.write();
        let initial_count = pending.len();
        
        pending.retain(|_, v| v.expires_at > now);
        
        let removed = initial_count - pending.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} expired domain verifications", removed);
        }
        
        removed
    }

    pub async fn verify_domain_ns_records(&self, domain: &str, expected_nameservers: &[String]) -> Result<bool, String> {
        let resolver = self.dns_resolver.as_ref()
            .ok_or_else(|| "DNS resolver not configured".to_string())?;

        let ns_record = resolver.lookup_ns(domain).await
            .map_err(|e| format!("NS lookup failed: {}", e))?;

        for expected in expected_nameservers {
            let expected_base = expected.trim_end_matches('.').to_lowercase();
            let found = ns_record.nameservers.iter().any(|ns| {
                let ns_base = ns.trim_end_matches('.').to_lowercase();
                ns_base == expected_base || ns_base.ends_with(&format!(".{}", expected_base))
            });
            
            if !found {
                tracing::warn!("Expected nameserver {} not found for domain {}", expected, domain);
                return Ok(false);
            }
        }

        tracing::info!("NS record verification passed for domain {}", domain);
        Ok(true)
    }

    pub async fn verify_domain_txt_challenge(&self, domain: &str, expected_token: &str) -> Result<bool, String> {
        let resolver = self.dns_resolver.as_ref()
            .ok_or_else(|| "DNS resolver not configured".to_string())?;

        let txt_record = resolver.lookup_txt(&format!("_acme-challenge.{}", domain)).await
            .map_err(|e| format!("TXT lookup failed: {}", e))?;

        for txt_value in &txt_record.values {
            if txt_value.contains(expected_token) {
                tracing::info!("TXT challenge verification passed for domain {}", domain);
                return Ok(true);
            }
        }

        tracing::warn!("TXT challenge verification failed for domain {} - token not found", domain);
        Ok(false)
    }

    pub fn complete_verification_and_register(&self, request_id: &str, registration: DnsRegistration) -> Result<(), String> {
        let pending = self.pending_verifications.read();
        
        let verification = pending.get(request_id)
            .ok_or_else(|| "Verification request not found".to_string())?;
        
        if verification.domain != registration.domain {
            return Err("Domain mismatch between registration and verification".to_string());
        }
        
        if verification.origin_node_id != registration.node_id {
            return Err("Origin node mismatch between registration and verification".to_string());
        }
        
        drop(pending);

        let now = chrono::Utc::now().timestamp() as u64;
        
        let origin = RegisteredOriginNode {
            node_id: registration.node_id.clone(),
            domains: vec![registration.domain.clone()],
            geo: registration.geo.clone(),
            healthy: registration.healthy,
            capacity: registration.capacity,
            latency_ms: registration.latency_ms,
            load_percent: None,
            last_update: now,
            authenticated: true,
            edge_node_id: registration.edge_node_id.clone(),
            edge_node_geo: registration.edge_node_geo.clone(),
        };

        self.origin_nodes.write().insert(registration.node_id.clone(), origin);

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            mapping.entry(registration.domain.clone())
                .or_insert_with(Vec::new)
                .push(registration.node_id.clone());
        }

        if self.is_global {
            if let Some(ref dht_store) = self.dht_record_store {
                let ip_addresses = registration.ip_addresses.clone();
                let ttl = 600;
                let stored = dht_store.store_dns_domain_registration(
                    registration.domain.clone(),
                    registration.node_id.clone(),
                    ip_addresses,
                    ttl,
                );
                if stored {
                    tracing::info!("Registered domain {} in DHT after verification", registration.domain);
                }
            }
        }

        self.pending_verifications.write().remove(request_id);
        
        tracing::info!("Domain {} registered after verification", registration.domain);
        
        Ok(())
    }

    pub async fn register_origin_with_verification(
        &self,
        registration: DnsRegistration,
        verify_domain_ownership: bool,
    ) -> Result<DnsRegistrationWithVerificationResponse, String> {
        if self.is_global {
            return Err("Use register_origin_node for global nodes".to_string());
        }

        let request_id = format!("{}-{}-{}", registration.domain, registration.node_id, chrono::Utc::now().timestamp());
        
        let verification_request = DnsRegistrationWithVerificationRequest {
            request_id: request_id.clone(),
            registration: registration.clone(),
            verify_domain_ownership,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let global_nodes = if let Some(ref rm) = self.routing_manager {
            rm.find_closest_global(5).await
        } else {
            Vec::new()
        };

        if !global_nodes.is_empty() && self.registration_tx.is_some() {
            let mut last_error = None;
            
            for (attempt, global_node) in global_nodes.iter().enumerate() {
                if attempt >= Self::MAX_REGISTRATION_RETRIES {
                    break;
                }

                tracing::info!("Attempting registration to global node {} (attempt {}/{})", 
                    global_node.node_id, attempt + 1, Self::MAX_REGISTRATION_RETRIES);

                if let Some(ref tx) = self.registration_tx {
                    let request = DnsRegistrationRequest {
                        node_id: self.node_id.clone(),
                        domains: vec![registration.clone()],
                        is_global: false,
                        certificate_fingerprint: registration.certificate_fingerprint.clone(),
                        role: DnsNodeRole::Origin,
                    };
                    
                    match tx.try_send(request) {
                        Ok(_) => {
                            tracing::info!("Registration request sent to global node {}", global_node.node_id);
                            
                            return Ok(DnsRegistrationWithVerificationResponse {
                                request_id,
                                domain: registration.domain.clone(),
                                registration_accepted: true,
                                verification_status: DomainVerificationStatus::Pending,
                                verification_type: if verify_domain_ownership { 
                                    Some(DomainVerificationType::TxtChallenge) 
                                } else { 
                                    Some(DomainVerificationType::NsRecord) 
                                },
                                challenge_token: Some(uuid::Uuid::new_v4().to_string()),
                                nameservers_required: None,
                                error_message: None,
                                global_node_id: global_node.node_id.to_string(),
                                timestamp: chrono::Utc::now().timestamp() as u64,
                            });
                        }
                        Err(e) => {
                            last_error = Some(e.to_string());
                            tracing::warn!("Registration attempt {} failed: {:?}", 
                                attempt + 1, last_error);
                        }
                    }
                }
            }

            if last_error.is_some() {
                tracing::warn!("Failed to send to global nodes, continuing with fallback");
            }
        }

        if let Some(ref tx) = self.registration_tx {
            let request = DnsRegistrationRequest {
                node_id: self.node_id.clone(),
                domains: vec![registration.clone()],
                is_global: false,
                certificate_fingerprint: registration.certificate_fingerprint.clone(),
                role: DnsNodeRole::Origin,
            };
            
            tx.send(request).await.map_err(|e| format!("Failed to send registration: {}", e))?;
            
            tracing::info!("Registration request sent via local channel");
            
            return Ok(DnsRegistrationWithVerificationResponse {
                request_id,
                domain: registration.domain.clone(),
                registration_accepted: true,
                verification_status: DomainVerificationStatus::Pending,
                verification_type: if verify_domain_ownership { 
                    Some(DomainVerificationType::TxtChallenge) 
                } else { 
                    Some(DomainVerificationType::NsRecord) 
                },
                challenge_token: Some(uuid::Uuid::new_v4().to_string()),
                nameservers_required: None,
                error_message: None,
                global_node_id: self.node_id.clone(),
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }

        Err("No registration channel available".to_string())
    }

    pub fn handle_registration_with_verification(
        &self,
        request: DnsRegistrationWithVerificationRequest,
    ) -> Result<DnsRegistrationWithVerificationResponse, String> {
        if !self.is_global {
            return Err("Only global nodes can handle registration requests".to_string());
        }

        let now = chrono::Utc::now().timestamp() as u64;
        let request_id = request.request_id.clone();
        let domain = request.registration.domain.clone();
        let origin_node_id = request.registration.node_id.clone();

        let authenticated = self.verify_registration(
            &request.registration.node_id, 
            request.registration.certificate_fingerprint.as_deref()
        );

        if !authenticated && self.config.require_mtls {
            return Ok(DnsRegistrationWithVerificationResponse {
                request_id: request_id.clone(),
                domain: domain.clone(),
                registration_accepted: false,
                verification_status: DomainVerificationStatus::Failed,
                verification_type: None,
                challenge_token: None,
                nameservers_required: None,
                error_message: Some("Authentication required".to_string()),
                global_node_id: self.node_id.clone(),
                timestamp: now,
            });
        }

        if request.verify_domain_ownership {
            let verification = self.initiate_domain_verification(
                domain.clone(),
                origin_node_id.clone(),
                true,
                request.registration.ip_addresses.clone(),
            );

            return Ok(DnsRegistrationWithVerificationResponse {
                request_id: request_id,
                domain: domain,
                registration_accepted: true,
                verification_status: DomainVerificationStatus::Pending,
                verification_type: Some(DomainVerificationType::TxtChallenge),
                challenge_token: verification.challenge_token,
                nameservers_required: None,
                error_message: None,
                global_node_id: self.node_id.clone(),
                timestamp: now,
            });
        }

        let verification = self.initiate_domain_verification(
            domain.clone(),
            origin_node_id.clone(),
            false,
            request.registration.ip_addresses.clone(),
        );

        Ok(DnsRegistrationWithVerificationResponse {
            request_id: request_id,
            domain: domain,
            registration_accepted: true,
            verification_status: DomainVerificationStatus::Pending,
            verification_type: Some(DomainVerificationType::NsRecord),
            challenge_token: verification.challenge_token,
            nameservers_required: None,
            error_message: None,
            global_node_id: self.node_id.clone(),
            timestamp: now,
        })
    }

    const VERIFICATION_RETRY_INTERVAL_SECS: u64 = 30;
    const VERIFICATION_MAX_RETRIES: u32 = 10;

    pub async fn start_verification_loop(&self) {
        let resolver = match &self.dns_resolver {
            Some(r) => Arc::clone(r),
            None => {
                tracing::warn!("No DNS resolver configured, verification loop not starting");
                return;
            }
        };

        let pending = Arc::clone(&self.pending_verifications);
        let origin_nodes = Arc::clone(&self.origin_nodes);
        let domain_mapping = Arc::clone(&self.domain_to_origin_mapping);
        let dht_store = self.dht_record_store.clone();
        let verification_tx = self.verification_tx.clone();
        let failure_tx = self.verification_failure_tx.clone();
        let node_id = self.node_id.clone();
        let metrics = self.verification_metrics.clone();
        
        let retry_interval = self.config.verification_retry_interval_secs;
        let timeout_message = format!("Verification timeout - DNS challenge not completed within {} seconds", self.config.verification_timeout_secs);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(retry_interval)).await;

                let now = chrono::Utc::now().timestamp() as u64;
                let mut to_retry = Vec::new();
                let mut to_remove = Vec::new();
                let mut failures_to_send: Vec<VerificationFailure> = Vec::new();

                {
                    let pending_guard = pending.read();
                    for (request_id, verification) in pending_guard.iter() {
                        if verification.expires_at <= now {
                            to_remove.push(request_id.clone());
                            
                            if failure_tx.is_some() {
                                failures_to_send.push(VerificationFailure {
                                    request_id: request_id.clone(),
                                    domain: verification.domain.clone(),
                                    origin_node_id: verification.origin_node_id.clone(),
                                    error_message: timeout_message.clone(),
                                });
                            }
                        } else {
                            to_retry.push((
                                request_id.clone(),
                                verification.domain.clone(),
                                verification.challenge_token.clone().unwrap_or_default(),
                                verification.verification_type,
                                verification.ip_addresses.clone(),
                            ));
                        }
                    }
                }

                for failure in failures_to_send {
                    if let Some(tx) = &failure_tx {
                        let _ = tx.send(failure).await;
                    }
                }

                for request_id in to_remove {
                    pending.write().remove(&request_id);
                    metrics.record_timeout();
                    tracing::warn!("Verification timed out for request {}", request_id);
                }

                for (request_id, domain, token, verification_type, ip_addresses) in to_retry {
                    let verified = match verification_type {
                        DomainVerificationType::TxtChallenge => {
                            resolver.lookup_txt(&format!("_acme-challenge.{}", domain)).await
                                .map(|txt| {
                                    txt.values.iter().any(|v| v.contains(&token))
                                })
                                .unwrap_or(false)
                        }
                        DomainVerificationType::NsRecord => {
                            let ns_result = resolver.lookup_ns(&domain).await;
                            match ns_result {
                                Ok(ns) => {
                                    if ns.nameservers.is_empty() {
                                        false
                                    } else {
                                        // Verify at least one of the expected IPs is associated with the domain
                                        // by doing A/AAAA lookups on the nameservers and checking against expected IPs
                                        let expected_ips: Vec<std::net::IpAddr> = ip_addresses.iter()
                                            .filter_map(|ip| ip.parse().ok())
                                            .collect();
                                        
                                        if expected_ips.is_empty() {
                                            // No expected IPs provided, just check NS exists
                                            tracing::warn!("NS verification: no expected IPs provided, checking NS exists only");
                                            !ns.nameservers.is_empty()
                                        } else {
                                            // Try to resolve each nameserver and check if any IP matches expected
                                            let mut verified = false;
                                            for ns_name in &ns.nameservers {
                                                if let Ok(ips) = resolver.lookup_a(ns_name).await {
                                                    for ip in &ips {
                                                        if expected_ips.contains(ip) {
                                                            verified = true;
                                                            tracing::info!("NS verification: found matching IP {} for nameserver {}", ip, ns_name);
                                                            break;
                                                        }
                                                    }
                                                }
                                                if verified {
                                                    break;
                                                }
                                            }
                                            if !verified {
                                                tracing::warn!("NS verification: no matching IPs found for nameservers {:?}", ns.nameservers);
                                            }
                                            verified
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("NS lookup failed for {}: {}", domain, e);
                                    false
                                }
                            }
                        }
                    };

                    if verified {
                        metrics.record_succeeded();
                        tracing::info!("Verification succeeded for domain {}", domain);

                        {
                            let mut origins = origin_nodes.write();
                            if !origins.contains_key(&request_id.split('-').nth(1).unwrap_or("").to_string()) {
                                let origin = RegisteredOriginNode {
                                    node_id: request_id.split('-').nth(1).unwrap_or("").to_string(),
                                    domains: vec![domain.clone()],
                                    geo: None,
                                    healthy: true,
                                    capacity: 100,
                                    latency_ms: None,
                                    load_percent: None,
                                    last_update: now,
                                    authenticated: true,
                                    edge_node_id: None,
                                    edge_node_geo: None,
                                };
                                origins.insert(request_id.clone(), origin);
                            }
                        }

                        {
                            let mut mapping = domain_mapping.write();
                            mapping.entry(domain.clone())
                                .or_insert_with(Vec::new)
                                .push(request_id.clone());
                        }

                        if let Some(ref store) = dht_store {
                            let _ = store.store_dns_domain_registration(
                                domain.clone(),
                                request_id.clone(),
                                vec![],
                                600,
                            );
                        }

                        pending.write().remove(&request_id);

                        if let Some(tx) = &verification_tx {
                            let _ = tx.send(VerificationTask {
                                request_id: request_id.clone(),
                                domain: domain.clone(),
                                origin_node_id: request_id.split('-').nth(1).unwrap_or("").to_string(),
                                challenge_token: token,
                                verification_type,
                            }).await;
                        }
                    } else {
                        metrics.record_failed();
                    }
                }
            }
        });
    }
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

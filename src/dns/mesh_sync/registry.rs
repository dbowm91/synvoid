use super::*;

impl MeshDnsRegistry {
    pub(crate) const MAX_REGISTRATION_RETRIES: usize = 3;

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
            domain_to_edge_index: Arc::new(RwLock::new(HashMap::new())),
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
            geoip: None,
        }
    }

    pub fn rebuild_edge_index(&self) {
        let mut index = self.domain_to_edge_index.write();
        index.clear();
        let edges = self.edge_nodes.read();
        for (node_id, node) in edges.iter() {
            for domain in &node.domains {
                index
                    .entry(domain.clone())
                    .or_default()
                    .push(node_id.clone());
            }
        }
    }

    pub fn get_edge_node_ids_for_domain(&self, domain: &str) -> Vec<String> {
        self.domain_to_edge_index
            .read()
            .get(domain)
            .cloned()
            .unwrap_or_default()
    }

    pub fn with_dns_resolver<R: DnsResolver + 'static>(mut self, resolver: R) -> Self {
        self.dns_resolver = Some(Arc::new(resolver));
        self
    }

    pub fn with_geoip(mut self, geoip: Arc<crate::geoip::GeoIpManager>) -> Self {
        self.geoip = Some(geoip);
        self
    }

    pub(crate) fn derive_geo_from_ips(&self, ips: &[String]) -> Option<String> {
        let Some(geoip) = self.geoip.as_ref() else {
            return Some("Unknown".to_string());
        };

        for ip_str in ips {
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                if let Some(country_info) = geoip.get_country_info(ip) {
                    return Some(country_info.code);
                }
            }
        }

        Some("Unknown".to_string())
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

    pub fn with_routing_manager(
        mut self,
        rm: Arc<crate::mesh::dht::routing::manager::DhtRoutingManager>,
    ) -> Self {
        self.routing_manager = Some(rm);
        self
    }

    pub fn with_dht_record_store(
        mut self,
        store: Arc<crate::mesh::dht::record_store::RecordStoreManager>,
    ) -> Self {
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

    pub(crate) fn verify_registration(
        &self,
        node_id: &str,
        certificate_fingerprint: Option<&str>,
    ) -> bool {
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

    pub fn start_periodic_dht_sync(self: &Arc<Self>, interval_secs: u64) {
        if !self.is_global {
            return;
        }
        let registry = Arc::clone(self);
        let interval_secs = if interval_secs == 0 {
            30
        } else {
            interval_secs
        };
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                registry.sync_from_dht();
            }
        });
        tracing::info!("Started periodic DHT sync with interval {}s", interval_secs);
    }
}

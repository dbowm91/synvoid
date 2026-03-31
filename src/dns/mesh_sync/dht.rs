use super::*;

impl MeshDnsRegistry {
    pub fn apply_dht_domain_registration(
        &self,
        domain: String,
        origin_node_id: String,
        _ip_addresses: Vec<String>,
    ) {
        if !self.is_global {
            tracing::debug!("Ignoring DHT domain registration on non-global node");
            return;
        }

        let now = chrono::Utc::now().timestamp() as u64;

        let origin = RegisteredOriginNode {
            node_id: origin_node_id.clone(),
            domains: vec![domain.clone()],
            geo: None,
            healthy: true,
            capacity: 100,
            latency_ms: None,
            load_percent: None,
            last_update: now,
            last_seen: now,
            authenticated: true,
            edge_node_id: None,
            edge_node_geo: None,
            certificate_chain: Vec::new(),
            cert_chain_verified: false,
        };

        self.origin_nodes
            .write()
            .insert(origin_node_id.clone(), origin);

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            mapping
                .entry(domain.clone())
                .or_default()
                .push(origin_node_id.clone());
        }

        tracing::info!(
            "Applied domain registration from DHT: {} -> {}",
            domain,
            origin_node_id
        );
    }

    pub fn update_origin_node(
        &self,
        node_id: &str,
        domains: Vec<String>,
        healthy: bool,
        capacity: u32,
        latency_ms: Option<u32>,
        load_percent: Option<u8>,
    ) {
        let now = chrono::Utc::now().timestamp() as u64;

        let mut origins = self.origin_nodes.write();
        if let Some(origin) = origins.get_mut(node_id) {
            origin.domains = domains;
            origin.healthy = healthy;
            origin.capacity = capacity;
            origin.latency_ms = latency_ms;
            origin.load_percent = load_percent;
            origin.last_seen = now;

            tracing::debug!("Updated origin node from DHT: {}", node_id);
        }
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
                } else {
                    self.update_origin_node(&origin_id, vec![domain], true, 100, None, None);
                }
            }

            let anycast_nodes = dht_store.get_all_anycast_nodes();
            for node_value in anycast_nodes {
                if let (
                    Some(node_id),
                    Some(anycast_ips),
                    Some(geo),
                    Some(capacity),
                    Some(healthy),
                    Some(dns_zones),
                ) = (
                    node_value.get("node_id").and_then(|v| v.as_str()),
                    node_value
                        .get("anycast_ips")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        }),
                    node_value
                        .get("geo")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    node_value
                        .get("capacity")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    node_value.get("healthy").and_then(|v| v.as_bool()),
                    node_value
                        .get("dns_zones")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        }),
                ) {
                    let existing = {
                        let nodes = self.anycast_nodes.read();
                        nodes.get(node_id).cloned()
                    };

                    if existing.is_none() {
                        let anycast = RegisteredAnycastNode {
                            node_id: node_id.to_string(),
                            anycast_ips,
                            geo: Some(geo),
                            healthy,
                            capacity,
                            latency_ms: None,
                            load_percent: None,
                            last_update: chrono::Utc::now().timestamp() as u64,
                            authenticated: false,
                            dns_zones: dns_zones.clone(),
                        };

                        self.anycast_nodes
                            .write()
                            .insert(node_id.to_string(), anycast);

                        for zone in &dns_zones {
                            let mut mapping = self.domain_to_anycast_mapping.write();
                            mapping
                                .entry(zone.clone())
                                .or_default()
                                .push(node_id.to_string());
                        }

                        tracing::info!("Synced anycast node {} from DHT", node_id);
                    }
                }
            }
        }
    }
}

use super::*;

impl RecordStoreManager {
    pub fn store_dns_domain_registration(
        &self,
        domain: String,
        origin_node_id: String,
        ip_addresses: Vec<String>,
        ttl_seconds: u64,
    ) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            tracing::warn!("DNS domain registration rejected: not a global node or DHT disabled");
            return false;
        }

        let now = crate::mesh::safe_unix_timestamp();

        let value = serde_json::json!({
            "domain": domain,
            "origin_node_id": origin_node_id,
            "ip_addresses": ip_addresses,
            "registered_at": now,
        });

        let value = match serde_json::to_vec(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize DNS domain registration: {}", e);
                return false;
            }
        };

        let dht_key = DhtKey::dns_domain_registration(&domain);
        let key = dht_key.as_str();

        let record = DhtRecord {
            key,
            value,
            timestamp: now,
            ttl_seconds,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let stored = self.store_record_global(record);
        if stored {
            tracing::info!("Stored DNS domain registration for {} in DHT", domain);
        }
        stored
    }

    pub fn get_dns_domain_registration(&self, domain: &str) -> Option<serde_json::Value> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let key = DhtKey::dns_domain_registration(domain).as_str();
        let record = self.get_record(&key)?;

        serde_json::from_slice(&record.value).ok()
    }

    pub fn get_all_dns_domain_registrations(&self) -> Vec<(String, String, Vec<String>)> {
        if !self.config.enabled || !self.is_global_node() {
            return Vec::new();
        }

        let records = self.records.read();
        let mut registrations = Vec::new();

        for (key, entry) in records.iter() {
            if key.starts_with("dns_domain_reg:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.record.value)
                {
                    let domain = value
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let origin_id = value
                        .get("origin_node_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let ips: Vec<String> = value
                        .get("ip_addresses")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    registrations.push((domain, origin_id, ips));
                }
            }
        }

        registrations
    }

    pub fn remove_dns_domain_registration(&self, domain: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = DhtKey::dns_domain_registration(domain).as_str();
        self.remove(&key)
    }

    #[cfg(feature = "dns")]
    pub fn store_anycast_node(
        &self,
        node_id: String,
        anycast_ips: Vec<String>,
        geo: Option<String>,
        capacity: u32,
        healthy: bool,
        dns_zones: Vec<String>,
    ) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            tracing::warn!("Anycast node storage rejected: not a global node or DHT disabled");
            return false;
        }

        let now = crate::mesh::safe_unix_timestamp();

        let value = serde_json::json!({
            "node_id": node_id,
            "anycast_ips": anycast_ips,
            "geo": geo,
            "capacity": capacity,
            "healthy": healthy,
            "dns_zones": dns_zones,
            "registered_at": now,
        });

        let value = match serde_json::to_vec(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize anycast node: {}", e);
                return false;
            }
        };

        let dht_key = DhtKey::anycast_node(&node_id);
        let key = dht_key.as_str();

        let record = DhtRecord {
            key,
            value,
            timestamp: now,
            ttl_seconds: 600,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let stored = self.store_record_global(record);
        if stored {
            tracing::info!("Stored anycast node {} in DHT", node_id);
        }
        stored
    }

    #[cfg(feature = "dns")]
    pub fn get_anycast_node(&self, node_id: &str) -> Option<serde_json::Value> {
        if !self.config.enabled {
            return None;
        }

        let key = DhtKey::anycast_node(node_id).as_str();
        let record = self.get_record(&key)?;

        serde_json::from_slice(&record.value).ok()
    }

    #[cfg(feature = "dns")]
    pub fn get_anycast_nodes_for_zone(&self, zone: &str) -> Vec<serde_json::Value> {
        if !self.config.enabled {
            return Vec::new();
        }

        let records = self.records.read();
        let mut nodes = Vec::new();

        for (key, entry) in records.iter() {
            if key.starts_with("anycast_node:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.record.value)
                {
                    let zones: Vec<String> = value
                        .get("dns_zones")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    if zones.contains(&zone.to_string()) {
                        nodes.push(value.clone());
                    }
                }
            }
        }

        nodes
    }

    #[cfg(feature = "dns")]
    pub fn get_all_anycast_nodes(&self) -> Vec<serde_json::Value> {
        if !self.config.enabled {
            return Vec::new();
        }

        let records = self.records.read();
        let mut nodes = Vec::new();

        for (key, entry) in records.iter() {
            if key.starts_with("anycast_node:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.record.value)
                {
                    nodes.push(value.clone());
                }
            }
        }

        nodes
    }

    #[cfg(feature = "dns")]
    pub fn remove_anycast_node(&self, node_id: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = DhtKey::anycast_node(node_id).as_str();
        self.remove(&key)
    }
}

use super::*;
use crate::dht::{AnycastNode, DnsDomainRegistration};

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

        let now = synvoid_utils::safe_unix_timestamp();

        let value_struct = DnsDomainRegistration {
            domain: domain.clone(),
            origin_node_id: origin_node_id.clone(),
            ip_addresses: ip_addresses.clone(),
            registered_at: now,
        };

        let value = match synvoid_utils::serialization::serialize(&value_struct) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize DNS domain registration: {}", e);
                return false;
            }
        };

        let dht_key = DhtKey::dns_domain_registration(&domain);
        let key = dht_key.as_str();

        let mut record = DhtRecord {
            key,
            value: value.clone(),
            timestamp: now,
            sequence_number: 0,
            ttl_seconds,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&value);
                hasher.finalize().to_vec()
            },
            quorum_proof: Vec::new(),
            request_id: None,
        };

        // Sign the DNS domain registration record with the record signer
        let rs = self.record_state.read();
        if let Some(ref signer) = rs.record_signer {
            let signed_record = crate::dht::SignedDhtRecord::new(
                record.key.clone(),
                record.value.clone(),
                record.source_node_id.clone(),
                crate::dht::SignedRecordType::DnsDomainRegistration,
            );
            if let Some(signature) = signer.sign(&signed_record) {
                record.signature = signature;
                record.signer_public_key = signer.get_verifying_key();
                tracing::debug!(
                    "Signed DNS domain registration record with Ed25519: {}",
                    domain
                );
            }
        }
        drop(rs);

        let stored = self.store_record_global(record, true);
        if stored {
            tracing::info!("Stored DNS domain registration for {} in DHT", domain);
        }
        stored
    }

    pub fn get_dns_domain_registration(&self, domain: &str) -> Option<DnsDomainRegistration> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let key = DhtKey::dns_domain_registration(domain).as_str();
        let record = self.get_record(&key)?;

        synvoid_utils::serialization::deserialize::<DnsDomainRegistration>(&record.value).ok()
    }

    pub fn get_all_dns_domain_registrations(&self) -> Vec<(String, String, Vec<String>)> {
        if !self.config.enabled || !self.is_global_node() {
            return Vec::new();
        }

        let rs = self.record_state.read();
        let mut registrations = Vec::new();

        for (key, entry) in rs.records.iter() {
            if key.starts_with("dns_domain_reg:") {
                if let Ok(value) = synvoid_utils::serialization::deserialize::<DnsDomainRegistration>(
                    &entry.record.value,
                ) {
                    registrations.push((value.domain, value.origin_node_id, value.ip_addresses));
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

        let now = synvoid_utils::safe_unix_timestamp();

        let value_struct = AnycastNode {
            node_id: node_id.clone(),
            anycast_ips,
            geo,
            capacity,
            healthy,
            dns_zones,
            registered_at: now,
        };

        let value = match synvoid_utils::serialization::serialize(&value_struct) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize anycast node: {}", e);
                return false;
            }
        };

        let dht_key = DhtKey::anycast_node(&node_id);
        let key = dht_key.as_str();

        let content_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&value);
            hasher.finalize().to_vec()
        };

        let mut record = DhtRecord {
            key,
            value: value.clone(),
            timestamp: now,
            sequence_number: 0,
            ttl_seconds: 600,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash,
            quorum_proof: Vec::new(),
            request_id: None,
        };

        // Sign the anycast record with the record signer
        let rs = self.record_state.read();
        if let Some(ref signer) = rs.record_signer {
            let signed_record = crate::dht::SignedDhtRecord::new(
                record.key.clone(),
                record.value.clone(),
                record.source_node_id.clone(),
                crate::dht::SignedRecordType::AnycastNode,
            );
            if let Some(signature) = signer.sign(&signed_record) {
                record.signature = signature;
                record.signer_public_key = signer.get_verifying_key();
                tracing::debug!("Signed anycast node record with Ed25519: {}", node_id);
            }
        }
        drop(rs);

        let stored = self.store_record_global(record, true);
        if stored {
            tracing::info!("Stored anycast node {} in DHT", node_id);
        }
        stored
    }

    #[cfg(feature = "dns")]
    pub fn get_anycast_node(&self, node_id: &str) -> Option<AnycastNode> {
        if !self.config.enabled {
            return None;
        }

        let key = DhtKey::anycast_node(node_id).as_str();
        let record = self.get_record(&key)?;

        synvoid_utils::serialization::deserialize::<AnycastNode>(&record.value).ok()
    }

    #[cfg(feature = "dns")]
    pub fn get_anycast_nodes_for_zone(&self, zone: &str) -> Vec<AnycastNode> {
        if !self.config.enabled {
            return Vec::new();
        }

        let rs = self.record_state.read();
        let mut nodes = Vec::new();

        for (key, entry) in rs.records.iter() {
            if key.starts_with("anycast_node:") {
                if let Ok(value) =
                    synvoid_utils::serialization::deserialize::<AnycastNode>(&entry.record.value)
                {
                    if value.dns_zones.contains(&zone.to_string()) {
                        nodes.push(value);
                    }
                }
            }
        }

        nodes
    }

    #[cfg(feature = "dns")]
    pub fn get_all_anycast_nodes(&self) -> Vec<AnycastNode> {
        if !self.config.enabled {
            return Vec::new();
        }

        let rs = self.record_state.read();
        let mut nodes = Vec::new();

        for (key, entry) in rs.records.iter() {
            if key.starts_with("anycast_node:") {
                if let Ok(value) =
                    synvoid_utils::serialization::deserialize::<AnycastNode>(&entry.record.value)
                {
                    nodes.push(value);
                }
            }
        }

        nodes
    }

    #[cfg(feature = "dns")]
    /// Returns anycast node records with their signatures intact for verification.
    pub fn get_all_anycast_records(&self) -> Vec<DhtRecord> {
        if !self.config.enabled {
            return Vec::new();
        }

        let rs = self.record_state.read();
        let mut records = Vec::new();

        for (key, entry) in rs.records.iter() {
            if key.starts_with("anycast_node:") {
                records.push(entry.record.clone());
            }
        }

        records
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

use super::*;
use crate::utils::current_timestamp;

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

        let now = current_timestamp();

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
        let now = current_timestamp();

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

            let anycast_records = dht_store.get_all_anycast_records();
            for record in anycast_records {
                // Verify signature if present
                let is_authenticated = if !record.signature.is_empty() {
                    if let Some(ref signer_pk) = record.signer_public_key {
                        if !signer_pk.is_empty() {
                            let signed_record = crate::mesh::dht::SignedDhtRecord {
                                key: record.key.clone(),
                                value: record.value.clone(),
                                publisher_id: record.source_node_id.clone(),
                                signature: record.signature.clone(),
                                created_at: record.timestamp,
                                expires_at: Some(record.timestamp + record.ttl_seconds),
                                record_type: crate::mesh::dht::SignedRecordType::AnycastNode,
                                sequence_number: 0,
                                source_node_id: record.source_node_id.clone(),
                                ttl_seconds: record.ttl_seconds,
                                signer_public_key: record.signer_public_key.clone(),
                            };

                            // Verify using the DHT record verifier if available
                            if let Some(ref verifier) = dht_store.get_record_verifier() {
                                verifier.verify(&signed_record)
                            } else {
                                tracing::warn!(
                                    "No record verifier available, cannot verify anycast node signature"
                                );
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                    if let (
                        Some(node_id),
                        Some(anycast_ips),
                        Some(geo),
                        Some(capacity),
                        Some(healthy),
                        Some(dns_zones),
                    ) = (
                        value.get("node_id").and_then(|v| v.as_str()),
                        value
                            .get("anycast_ips")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect::<Vec<_>>()
                            }),
                        value.get("geo").and_then(|v| v.as_str()).map(String::from),
                        value
                            .get("capacity")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u32),
                        value.get("healthy").and_then(|v| v.as_bool()),
                        value
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
                                last_update: current_timestamp(),
                                authenticated: is_authenticated,
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

                            tracing::info!(
                                "Synced anycast node {} from DHT (authenticated: {})",
                                node_id,
                                is_authenticated
                            );
                        } else if let Some(mut existing_node) = existing {
                            // Update existing node, preserving authenticated status
                            existing_node.anycast_ips = anycast_ips;
                            existing_node.geo = Some(geo);
                            existing_node.healthy = healthy;
                            existing_node.capacity = capacity;
                            existing_node.last_update = current_timestamp();
                            existing_node.authenticated = is_authenticated;
                            existing_node.dns_zones = dns_zones.clone();
                            self.anycast_nodes
                                .write()
                                .insert(node_id.to_string(), existing_node);
                        }
                    }
                }
            }
        }
    }
}

use super::*;

impl MeshDnsRegistry {
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
                tx.send(request)
                    .await
                    .map_err(|e| format!("Failed to send registration: {}", e))?;
            }
        }

        let authenticated = self.verify_registration(
            &registration.node_id,
            registration.certificate_fingerprint.as_deref(),
        );

        if !authenticated && self.config.require_mtls {
            tracing::warn!(
                "Unauthenticated origin registration rejected for node {}",
                registration.node_id
            );
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

        self.origin_nodes
            .write()
            .insert(registration.node_id.clone(), origin);

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            mapping
                .entry(registration.domain.clone())
                .or_default()
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
                    tracing::info!(
                        "Propagated domain registration to DHT: {}",
                        registration.domain
                    );
                }
            }
        }

        tracing::info!(
            "Registered origin node {} for domain {}",
            registration.node_id,
            registration.domain
        );
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
                tx.send(request)
                    .await
                    .map_err(|e| format!("Failed to send registration: {}", e))?;
            }
        }

        let authenticated = self.verify_registration(
            &registration.node_id,
            registration.certificate_fingerprint.as_deref(),
        );

        if !authenticated && self.config.require_mtls {
            tracing::warn!(
                "Unauthenticated edge registration rejected for node {}",
                registration.node_id
            );
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

        self.edge_nodes
            .write()
            .insert(registration.node_id.clone(), edge);

        tracing::info!(
            "Registered edge node {} for domain {}",
            registration.node_id,
            registration.domain
        );
        Ok(())
    }

    pub async fn register_anycast_node(
        &self,
        registration: DnsAnycastNodeRegistration,
    ) -> Result<(), String> {
        if !self.is_global {
            tracing::debug!("Ignoring anycast registration on non-global node");
            return Ok(());
        }

        let authenticated = self.verify_registration(
            &registration.node_id,
            registration.certificate_fingerprint.as_deref(),
        );

        if !authenticated && self.config.require_mtls {
            tracing::warn!(
                "Unauthenticated anycast registration rejected for node {}",
                registration.node_id
            );
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

        self.anycast_nodes
            .write()
            .insert(registration.node_id.clone(), anycast);

        for zone in &registration.dns_zones {
            let mut mapping = self.domain_to_anycast_mapping.write();
            mapping
                .entry(zone.clone())
                .or_default()
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

        tracing::info!(
            "Registered anycast node {} with IPs {:?}",
            registration.node_id,
            registration.anycast_ips
        );
        Ok(())
    }

    pub fn handle_registration_request(
        &self,
        request: DnsRegistrationRequest,
    ) -> Result<(), String> {
        if !self.is_global {
            return Ok(());
        }

        let authenticated =
            self.verify_registration(&request.node_id, request.certificate_fingerprint.as_deref());

        if !authenticated && self.config.require_mtls {
            tracing::warn!(
                "Unauthenticated registration request rejected for node {}",
                request.node_id
            );
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

                    mapping
                        .entry(reg.domain.clone())
                        .or_default()
                        .push(reg.node_id.clone());

                    tracing::info!(
                        "Registered origin {} for domain {} (authenticated: {})",
                        reg.node_id,
                        reg.domain,
                        authenticated
                    );
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

                    tracing::info!(
                        "Registered edge {} for domain {} (authenticated: {})",
                        reg.node_id,
                        reg.domain,
                        authenticated
                    );
                }
            }
        }

        Ok(())
    }
}

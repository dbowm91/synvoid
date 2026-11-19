use super::*;
use crate::time::unix_timestamp_secs;

impl MeshDnsRegistry {
    /// Insert a DHT-sourced domain registration into the served maps.
    ///
    /// `authenticated` is the provider's verdict, passed in by the caller.
    /// There is no default and no local re-derivation: a registration the
    /// capability has not vouched for is never inserted, so an unverified
    /// entry cannot reach `origin_nodes` and later answer.
    ///
    /// The caller (`sync_from_dht`) has already enforced the publisher binding
    /// and the R2 authorization check. This function is the write boundary, not
    /// the policy boundary.
    pub fn apply_dht_domain_registration(
        &self,
        domain: String,
        origin_node_id: String,
        ip_addresses: Vec<String>,
        authenticated: bool,
    ) {
        if !self.is_global {
            tracing::debug!("Ignoring DHT domain registration on non-global node");
            return;
        }

        if !authenticated {
            // Defence in depth: even a caller that skipped the capability must
            // not be able to insert an unauthenticated origin.
            metrics::counter!(
                "dns_mesh_domain_registration_rejected_total",
                "reason" => DomainRegistrationRejection::Unauthenticated.as_str()
            )
            .increment(1);
            tracing::warn!(
                domain = %domain,
                origin = %origin_node_id,
                "Refusing to apply an unauthenticated DHT domain registration"
            );
            return;
        }

        let now = unix_timestamp_secs();

        {
            let mut origins = self.origin_nodes.write();
            if let Some(origin) = origins.get_mut(&origin_node_id) {
                // A later advertisement refreshes the answer set and health,
                // and adds the domain without dropping zones the origin already
                // declared. An authorized registration never narrows another
                // authorized one.
                if !origin
                    .domains
                    .iter()
                    .any(|existing| domain_eq(existing, &domain))
                {
                    origin.domains.push(domain.clone());
                }
                origin.ip_addresses = ip_addresses;
                origin.healthy = true;
                origin.last_update = now;
                origin.last_seen = now;
            } else {
                origins.insert(
                    origin_node_id.clone(),
                    RegisteredOriginNode {
                        node_id: origin_node_id.clone(),
                        domains: vec![domain.clone()],
                        // A DHT registration is not the origin's own
                        // declaration; only the live registration path fills
                        // this, which is what keeps authorization condition
                        // (a) from authorizing itself.
                        declared_zones: Vec::new(),
                        ip_addresses: ip_addresses.clone(),
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
                    },
                );
            }
        }

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            let ids = mapping.entry(domain.clone()).or_default();
            if !ids.iter().any(|id| id == &origin_node_id) {
                ids.push(origin_node_id.clone());
            }
        }

        tracing::info!(
            "Applied authenticated domain registration from DHT: {} -> {}",
            domain,
            origin_node_id
        );
    }

    /// Retain a refused registration for telemetry and count it.
    pub(crate) fn record_untrusted_domain_registration(
        &self,
        registration: &AdvertisedDomainRegistration,
        reason: DomainRegistrationRejection,
    ) {
        metrics::counter!(
            "dns_mesh_domain_registration_rejected_total",
            "reason" => reason.as_str()
        )
        .increment(1);

        tracing::warn!(
            domain = %registration.domain,
            origin = %registration.origin_node_id,
            publisher = %registration.publisher_id,
            reason = reason.as_str(),
            "Refusing DHT domain registration"
        );

        let mut untrusted = self.untrusted_registrations.write();
        if untrusted.len() == MAX_UNTRUSTED_REGISTRATIONS {
            untrusted.remove(0);
        }
        untrusted.push(UntrustedDomainRegistration {
            domain: registration.domain.clone(),
            origin_node_id: registration.origin_node_id.clone(),
            publisher_id: registration.publisher_id.clone(),
            reason,
            observed_at: unix_timestamp_secs(),
        });
    }

    /// R2: may this registration's origin answer for this domain?
    ///
    /// Authorization is deliberately a separate question from authenticity. A
    /// valid signature proves *who advertised*; it does not prove the node may
    /// serve the name. Default deny.
    pub(crate) fn is_domain_registration_authorized(
        &self,
        registration: &AdvertisedDomainRegistration,
        store: &dyn DhtRecordStore,
    ) -> bool {
        // (a) The origin's own declared zones, from a live authenticated
        //     `DnsRegistration`. `DnsRegistration` carries one `domain` per
        //     registration; the union over that node's live registrations is
        //     its declared zone set.
        {
            let origins = self.origin_nodes.read();
            if let Some(origin) = origins.get(&registration.origin_node_id) {
                if origin
                    .declared_zones
                    .iter()
                    .any(|zone| domain_eq(zone, &registration.domain))
                {
                    return true;
                }
            }
        }

        // (b) An explicit `[dns.mesh] authorized_domains` entry.
        if self
            .config
            .authorized_domains
            .iter()
            .any(|zone| domain_eq(zone, &registration.domain))
        {
            return true;
        }

        // (c) An org-key claim carried by the mesh peer. The provider owns the
        //     claim; DNS only consumes the answer. Default false until mesh
        //     grants carry a domain claim.
        store.has_domain_authorization_claim(registration)
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
        let now = unix_timestamp_secs();

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

        let Some(dht_store) = self.dht_record_store.as_ref() else {
            return;
        };

        let registrations = dht_store.all_dns_domain_registrations();
        for registration in registrations {
            // R1: authenticity is the capability's decision. An unsigned or
            // unverifiable registration never reaches the served maps.
            if !dht_store.is_domain_registration_authentic(&registration) {
                self.record_untrusted_domain_registration(
                    &registration,
                    DomainRegistrationRejection::Unauthenticated,
                );
                continue;
            }

            // R1: a valid signature by some node is not enough; the signer must
            // be the node that claims the origin. This is the part Phase 04b
            // fixes on the mesh side; DNS refuses independently.
            if registration.publisher_id != registration.origin_node_id {
                self.record_untrusted_domain_registration(
                    &registration,
                    DomainRegistrationRejection::PublisherMismatch,
                );
                continue;
            }

            // R2: authorization is separate from authenticity. A signed
            // registration for an unlisted domain is retained for telemetry but
            // not served.
            if !self.is_domain_registration_authorized(&registration, dht_store.as_ref()) {
                self.record_untrusted_domain_registration(
                    &registration,
                    DomainRegistrationRejection::Unauthorized,
                );
                continue;
            }

            self.apply_dht_domain_registration(
                registration.domain,
                registration.origin_node_id,
                registration.ip_addresses,
                true,
            );
        }

        let anycast_records = dht_store.all_anycast_advertisements();
        for record in anycast_records {
            // Phase 139: DNS no longer constructs a mesh signed record.
            // It hands the advertised fields to the provider and asks the
            // one question it actually has — is this authentic? — so no
            // `synvoid-mesh` type appears here.
            let is_authenticated = dht_store.is_anycast_advertisement_authentic(&record);

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
                            last_update: unix_timestamp_secs(),
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
                        existing_node.last_update = unix_timestamp_secs();
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

/// Case-insensitive domain comparison with a single trailing dot ignored.
fn domain_eq(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

use super::*;

#[cfg(feature = "mesh")]
use crate::mesh_sync::MeshDnsRegistry;

impl DnsServer {
    pub fn load_zones(&self, zone_configs: Vec<DnsZoneEntry>) -> Result<(), String> {
        let zone_origins: Vec<String> = zone_configs.iter().map(|zc| zc.zone.clone()).collect();
        for zone_config in zone_configs {
            let mut zone = Zone::new(zone_config.zone.clone());
            zone.dnskey_ttl = Some(3600);

            let zone_dnssec = zone_config.dnssec.as_ref();
            let use_global = zone_dnssec.map(|z| !z.enabled).unwrap_or(true);

            if use_global {
                zone.nsec3_enabled = self.config.dnssec.nsec3_enabled;
                zone.nsec_enabled = self.config.dnssec.nsec_enabled;
                zone.nsec3param = if self.config.dnssec.nsec3_enabled {
                    Some(crate::dnssec::Nsec3Config::new(
                        self.config.dnssec.nsec3_iterations,
                        Self::generate_random_salt().map_err(|e| e.to_string())?,
                    ))
                } else {
                    None
                };
            } else if let Some(dnssec) = zone_dnssec {
                zone.nsec3_enabled = dnssec.nsec3_enabled;
                zone.nsec_enabled = dnssec.nsec_enabled;
                zone.nsec3param = if dnssec.nsec3_enabled {
                    let iterations = dnssec
                        .nsec3_iterations
                        .unwrap_or(self.config.dnssec.nsec3_iterations);
                    Some(crate::dnssec::Nsec3Config::new(
                        iterations,
                        Self::generate_random_salt().map_err(|e| e.to_string())?,
                    ))
                } else {
                    None
                };
            }

            for record_config in &zone_config.records {
                let record_type = match record_config.record_type {
                    synvoid_config::dns::DnsRecordType::A => RecordType::A,
                    synvoid_config::dns::DnsRecordType::Aaaa => RecordType::AAAA,
                    synvoid_config::dns::DnsRecordType::CName => RecordType::CNAME,
                    synvoid_config::dns::DnsRecordType::Mx => RecordType::MX,
                    synvoid_config::dns::DnsRecordType::Txt => RecordType::TXT,
                    synvoid_config::dns::DnsRecordType::Ns => RecordType::NS,
                    synvoid_config::dns::DnsRecordType::Soa => RecordType::SOA,
                    synvoid_config::dns::DnsRecordType::Srv => RecordType::SRV,
                    synvoid_config::dns::DnsRecordType::Ptr => RecordType::PTR,
                    synvoid_config::dns::DnsRecordType::Caa => RecordType::CAA,
                    synvoid_config::dns::DnsRecordType::Tlsa => RecordType::TLSA,
                    synvoid_config::dns::DnsRecordType::Svcb => RecordType::SVCB,
                    synvoid_config::dns::DnsRecordType::Https => RecordType::HTTPS,
                    synvoid_config::dns::DnsRecordType::Naptr => RecordType::NAPTR,
                    synvoid_config::dns::DnsRecordType::Sshfp => RecordType::SSHFP,
                    synvoid_config::dns::DnsRecordType::Uri => RecordType::from(256),
                    synvoid_config::dns::DnsRecordType::Rp => RecordType::from(17),
                    synvoid_config::dns::DnsRecordType::Afsdb => RecordType::from(18),
                    synvoid_config::dns::DnsRecordType::Ds => RecordType::DS,
                    synvoid_config::dns::DnsRecordType::Other => RecordType::NULL,
                };

                if record_type == RecordType::MX || record_type == RecordType::SRV {
                    if let Some(pri) = record_config.priority {
                        if pri > u16::MAX as u32 {
                            tracing::warn!(
                                zone = %zone_config.zone,
                                name = %record_config.name,
                                priority = %pri,
                                "Skipping record: priority {} exceeds u16::MAX (65535)",
                                pri
                            );
                            continue;
                        }
                    }
                }

                if record_type == RecordType::SOA {
                    let parts: Vec<&str> = record_config.value.split_whitespace().collect();
                    if parts.len() < 7 {
                        tracing::error!(
                            zone = %zone_config.zone,
                            name = %record_config.name,
                            "Rejecting zone: SOA record requires 7 fields (mname rname serial refresh retry expire minimum), got {}",
                            parts.len()
                        );
                        return Err(format!(
                            "Zone {}: SOA record requires 7 fields, got {}",
                            zone_config.zone,
                            parts.len()
                        ));
                    }
                    if parts[2].parse::<u32>().is_err() {
                        tracing::error!(
                            zone = %zone_config.zone,
                            name = %record_config.name,
                            serial = %parts[2],
                            "Rejecting zone: SOA serial is not a valid u32"
                        );
                        return Err(format!(
                            "Zone {}: SOA serial '{}' is not a valid u32",
                            zone_config.zone, parts[2]
                        ));
                    }
                    for (idx, field_name) in
                        ["refresh", "retry", "expire", "minimum"].iter().enumerate()
                    {
                        if parts[3 + idx].parse::<u32>().is_err() {
                            tracing::error!(
                                zone = %zone_config.zone,
                                name = %record_config.name,
                                field = %field_name,
                                value = %parts[3 + idx],
                                "Rejecting zone: SOA {} is not a valid u32",
                                field_name
                            );
                            return Err(format!(
                                "Zone {}: SOA {} '{}' is not a valid u32",
                                zone_config.zone,
                                field_name,
                                parts[3 + idx]
                            ));
                        }
                    }
                }

                let record = DnsZoneRecord {
                    name: record_config.name.clone(),
                    record_type,
                    value: record_config.value.clone(),
                    ttl: record_config
                        .ttl
                        .unwrap_or(self.config.settings.default_ttl),
                    priority: record_config.priority,
                };

                if record.record_type == RecordType::SOA {
                    zone.serial = Self::parse_soa_serial(&record.value);
                }

                let key = (record_config.name.clone(), record.record_type);
                zone.records.entry(key).or_default().push(record);
            }

            if zone.serial == 0 {
                zone.serial = 1;
            }

            // RFC 1035 §3.3.13: every authoritative zone MUST contain at least one SOA record.
            if zone.get_soa().is_none() {
                tracing::error!(
                    zone = %zone.origin,
                    "Rejecting zone: no SOA record found (RFC 1035 §3.3.13 requires at least one SOA per zone)"
                );
                return Err(format!("Zone {}: must contain a SOA record", zone.origin));
            }

            tracing::info!("Loaded DNS zone: {} (serial: {})", zone.origin, zone.serial);
            self.zones.insert(zone.origin.clone(), zone);
        }

        self.rebuild_zone_index();

        if let Some(ref cache) = self.cache {
            for origin in &zone_origins {
                cache.invalidate_zone(origin);
            }
        }

        Ok(())
    }

    pub fn load_zones_from_store(&self, store: &ZoneStore) -> Result<(), String> {
        let stored_zones = store.load_zones()?;
        let mut loaded_origins = Vec::new();

        for (origin, zone) in stored_zones {
            // Defense-in-depth: reject zones without SOA even from persistence.
            if zone.get_soa().is_none() {
                tracing::error!(
                    zone = %origin,
                    "Rejecting zone from store: no SOA record found"
                );
                return Err(format!(
                    "Zone {} (from store): must contain a SOA record",
                    origin
                ));
            }
            tracing::info!("Loaded DNS zone from store: {}", origin);
            self.zones.insert(origin.clone(), zone);
            loaded_origins.push(origin);
        }

        self.rebuild_zone_index();

        if let Some(ref cache) = self.cache {
            for origin in &loaded_origins {
                cache.invalidate_zone(origin);
            }
        }

        Ok(())
    }

    pub fn save_zones_to_store(&self, store: &ZoneStore) -> Result<(), String> {
        self.zones.for_each(|origin, zone| {
            let records: Vec<(String, RecordType, String, u32, Option<u32>)> = zone
                .records
                .values()
                .flat_map(|v| v.iter())
                .map(|r| {
                    (
                        r.name.clone(),
                        r.record_type,
                        r.value.clone(),
                        r.ttl,
                        r.priority,
                    )
                })
                .collect();

            let _ = store.save_zone(origin, &records);
        });

        Ok(())
    }

    pub fn add_record(&self, zone: &str, record: DnsZoneRecord) -> Result<(), String> {
        let key = (record.name.clone(), record.record_type);
        let zone_origin = zone.to_string();
        self.zones.get_or_create_and_update(zone, |zone_entry| {
            zone_entry.records.entry(key).or_default().push(record);
        });

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(&zone_origin);
        }

        Ok(())
    }

    pub fn with_zone_transfer(mut self, zone_transfer: crate::transfer::ZoneTransfer) -> Self {
        self.zone_transfer = Some(Arc::new(zone_transfer));
        self
    }

    pub fn with_zone_transfer_config(
        mut self,
        allowed_transfers: Vec<String>,
        allow_wildcard_transfer: bool,
        wildcard_transfer_requires_tsig: bool,
        ixfr_enabled: bool,
        ixfr_fallback_to_axfr: bool,
        tsig_verifier: Option<Arc<crate::tsig::TsigVerifier>>,
        require_tsig: bool,
    ) -> Self {
        let zone_transfer = crate::transfer::ZoneTransfer::with_security_config(
            self.zones.clone(),
            allowed_transfers,
            tsig_verifier,
            allow_wildcard_transfer,
            wildcard_transfer_requires_tsig,
            ixfr_enabled,
            ixfr_fallback_to_axfr,
            require_tsig,
        );
        self.zone_transfer = Some(Arc::new(zone_transfer));
        self
    }

    pub fn with_notify_handler(mut self, notify_handler: crate::notify::NotifyHandler) -> Self {
        self.notify_handler = Some(notify_handler);
        self
    }

    pub fn with_dynamic_update(
        mut self,
        enabled: bool,
        allow_any: bool,
        require_tsig: bool,
    ) -> Self {
        if enabled {
            self.update_handler = Some(
                crate::update::DynamicUpdateHandler::new(self.zones.clone()).with_config(
                    enabled,
                    allow_any,
                    require_tsig,
                ),
            );
        }
        self
    }

    pub(super) fn reverse_domain(domain: &str) -> String {
        domain
            .trim_end_matches('.')
            .to_lowercase()
            .split('.')
            .rev()
            .collect::<Vec<_>>()
            .join(".")
    }

    fn rebuild_zone_index(&self) {
        let mut index = Vec::new();
        let mut btree_index = BTreeMap::new();
        let mut trie = crate::zone_trie::ZoneTrie::new();

        self.zones.for_each(|origin, _zone| {
            let origin_lower = origin.to_lowercase();
            index.push((origin_lower.clone(), origin.clone()));

            let reversed = Self::reverse_domain(&origin_lower);
            btree_index.insert(reversed, origin.clone());

            trie.insert(&origin_lower);
        });
        index.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        *self.zone_index.write() = index;
        *self.zone_index_btree.write() = btree_index;
        *self.zone_trie.write() = trie;
        self.zone_index_dirty.store(false, Ordering::Release);

        self.zones.rebuild_index();
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_registry(mut self, registry: Arc<MeshDnsRegistry>) -> Self {
        self.mesh_registry = Some(registry);
        self
    }

    pub fn with_geoip(mut self, geoip: Arc<synvoid_geoip::GeoIpManager>) -> Self {
        self.geoip_lookup = Some(geoip);
        self
    }

    pub fn get_zones(&self) -> Arc<ShardedZoneStore> {
        self.zones.clone()
    }

    pub fn get_zone_trie(&self) -> Arc<RwLock<crate::zone_trie::ZoneTrie>> {
        self.zone_trie.clone()
    }

    pub fn get_zone_index(&self) -> Arc<RwLock<Vec<(String, String)>>> {
        self.zone_index.clone()
    }

    pub fn get_cache(&self) -> Option<Arc<DnsCache>> {
        self.cache.clone()
    }

    pub fn get_dnssec(&self) -> Option<Arc<RwLock<DnsSecKeyManager>>> {
        self.dnssec.clone()
    }

    pub fn get_signer_name(&self) -> Option<String> {
        self.signer_name.clone()
    }

    pub fn get_ecs_filter_config(&self) -> crate::edns::EcsFilterConfig {
        self.ecs_filter_config.clone()
    }

    pub fn query_context(&self) -> QueryContext<'_> {
        QueryContext {
            zones: &self.zones,
            zone_trie: &self.zone_trie,
            geoip_lookup: self.geoip_lookup.as_ref(),
            min_geo_ttl: self.config.settings.min_geo_ttl,
            negative_cache_ttl: self.config.settings.negative_cache_ttl,
            cache: self.cache.as_ref(),
            dnssec: self.dnssec.as_ref(),
            signer_name: self.signer_name.as_ref(),
            query_validator: self.query_validator.as_ref(),
            firewall: self.firewall.as_ref(),
            connection_limits: Some(&self.connection_limits),
            max_idle_time: None,
            zone_transfer: self.zone_transfer.as_ref(),
            ecs_filter_config: &self.ecs_filter_config,
            rate_limiter: self.rate_limiter.as_ref(),
            rrl_enabled: self.rrl_enabled,
            update_handler: self.update_handler.as_ref(),
            notify_handler: self.notify_handler.as_ref(),
            query_coalescer: self.query_coalescer.as_ref(),
            dns64_translator: self.dns64_translator.as_ref(),
            acme_dns_challenges: self.acme_dns_challenges.as_ref(),
            cookie_server: self.cookie_server.as_ref(),
            #[cfg(feature = "mesh")]
            mesh_registry: self.mesh_registry.as_ref(),
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(ref server) = self.recursive_server {
            server.stop();
            tracing::info!("Recursive DNS server stopped");
        }

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(watcher) = self.shutdown_watcher_tx.take() {
            let _ = watcher.send(true);
        }
        self.connection_limits.initiate_graceful_shutdown();
    }

    pub fn invalidate_cache(&self) {
        if let Some(ref cache) = self.cache {
            cache.clear();
        }
    }

    pub fn cache_stats(&self) -> Option<crate::cache::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
    }
}

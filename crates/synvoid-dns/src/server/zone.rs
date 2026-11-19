use super::*;
use crate::geo::CountryLookup;
use crate::runtime_config::ZoneSpec;

#[cfg(feature = "mesh")]
use crate::mesh_sync::MeshDnsRegistry;

impl DnsServer {
    /// Normalize a zone-record name to the **origin-relative** form the
    /// authoritative query path looks records up by.
    ///
    /// The query path (`server/query.rs`) strips the zone origin off the qname
    /// and looks the remainder up, mapping the apex to `"@"`. So a record must
    /// be stored the same way or it is unreachable — the zone would answer an
    /// authoritative NXDOMAIN for a name it contains, which is fail-wrong rather
    /// than fail-closed.
    ///
    /// The operator-facing spelling is the natural FQDN, so it is accepted and
    /// normalized here. The rule follows the zone-file convention:
    ///
    /// - `"@"` is the apex;
    /// - a name containing a `.` is an FQDN: it must be inside the zone, and is
    ///   reduced to its relative form;
    /// - a name without a `.` is already origin-relative and is kept as-is.
    ///
    /// A name that is an FQDN outside the zone is rejected rather than stored
    /// under a key nothing will ever query.
    pub(crate) fn normalize_record_name(origin: &str, name: &str) -> Result<String, String> {
        // One rule, one implementation: the writer in `server/mod.rs` applies
        // the same normalizer to every installed record map.
        Zone::normalize_record_name(origin, name)
    }

    pub fn load_zones(&self, zone_configs: Vec<ZoneSpec>) -> Result<(), String> {
        let zone_origins: Vec<String> = zone_configs.iter().map(|zc| zc.origin.clone()).collect();
        let loaded_count = self.load_zones_inner(&zone_configs, &zone_origins)?;
        for _ in 0..loaded_count {
            metrics::counter!("dns_zones_loaded_total").increment(1);
            metrics::counter!("dns_zone_reload_successes_total").increment(1);
        }
        Ok(())
    }

    fn load_zones_inner(
        &self,
        zone_configs: &[ZoneSpec],
        zone_origins: &[String],
    ) -> Result<usize, String> {
        for zone_config in zone_configs {
            let mut zone = Zone::new(zone_config.origin.clone());
            zone.dnskey_ttl = Some(3600);

            let zone_dnssec = zone_config.dnssec.as_ref();
            let use_global = zone_dnssec.map(|z| !z.enabled).unwrap_or(true);

            if use_global {
                zone.nsec3_enabled = self.dnssec_runtime.denial.nsec3_enabled;
                zone.nsec_enabled = self.dnssec_runtime.denial.nsec_enabled;
                zone.nsec3param = if self.dnssec_runtime.denial.nsec3_enabled {
                    Some(crate::dnssec::Nsec3Config::new(
                        self.dnssec_runtime.denial.nsec3_iterations,
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
                        .unwrap_or(self.dnssec_runtime.denial.nsec3_iterations);
                    Some(crate::dnssec::Nsec3Config::new(
                        iterations,
                        Self::generate_random_salt().map_err(|e| e.to_string())?,
                    ))
                } else {
                    None
                };
            }

            let mut records: RecordMap = HashMap::new();
            for record_config in &zone_config.records {
                // The application adapter already mapped the persisted
                // record-type enum to Hickory's runtime type.
                let record_type = record_config.record_type;

                if record_type == RecordType::MX || record_type == RecordType::SRV {
                    if let Some(pri) = record_config.priority {
                        if pri > u16::MAX as u32 {
                            tracing::warn!(
                                zone = %zone_config.origin,
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
                            zone = %zone_config.origin,
                            name = %record_config.name,
                            "Rejecting zone: SOA record requires 7 fields (mname rname serial refresh retry expire minimum), got {}",
                            parts.len()
                        );
                        return Err(format!(
                            "Zone {}: SOA record requires 7 fields, got {}",
                            zone_config.origin,
                            parts.len()
                        ));
                    }
                    if parts[2].parse::<u32>().is_err() {
                        tracing::error!(
                            zone = %zone_config.origin,
                            name = %record_config.name,
                            serial = %parts[2],
                            "Rejecting zone: SOA serial is not a valid u32"
                        );
                        return Err(format!(
                            "Zone {}: SOA serial '{}' is not a valid u32",
                            zone_config.origin, parts[2]
                        ));
                    }
                    for (idx, field_name) in
                        ["refresh", "retry", "expire", "minimum"].iter().enumerate()
                    {
                        if parts[3 + idx].parse::<u32>().is_err() {
                            tracing::error!(
                                zone = %zone_config.origin,
                                name = %record_config.name,
                                field = %field_name,
                                value = %parts[3 + idx],
                                "Rejecting zone: SOA {} is not a valid u32",
                                field_name
                            );
                            return Err(format!(
                                "Zone {}: SOA {} '{}' is not a valid u32",
                                zone_config.origin,
                                field_name,
                                parts[3 + idx]
                            ));
                        }
                    }
                }

                // Operator input boundary: a fully-qualified name outside the
                // zone is rejected here rather than stored under a key nothing
                // can query. The writer then canonicalizes the key again.
                let stored_name =
                    Self::normalize_record_name(&zone_config.origin, &record_config.name).map_err(
                        |reason| {
                            tracing::error!(
                                zone = %zone_config.origin,
                                name = %record_config.name,
                                "Rejecting record: {reason}"
                            );
                            format!(
                                "Zone {}: record name '{}' {reason}",
                                zone_config.origin, record_config.name
                            )
                        },
                    )?;

                let record = DnsZoneRecord {
                    name: stored_name.clone(),
                    record_type,
                    value: record_config.value.clone(),
                    ttl: record_config
                        .ttl
                        .unwrap_or(self.authoritative.ttl.default_ttl),
                    priority: record_config.priority,
                };

                records
                    .entry((stored_name, record.record_type))
                    .or_default()
                    .push(record);
            }

            // Single writer: normalize owners, deduplicate, rebuild the owner
            // index and denial chains, adopt the SOA serial.
            zone.commit_records(records, SerialPolicy::AdoptSoa)
                .map_err(|reason| {
                    tracing::error!(zone = %zone_config.origin, "Rejecting zone: {reason}");
                    metrics::counter!("dns_zone_reload_failures_total").increment(1);
                    reason
                })?;

            // RFC 1035 §3.3.13: every authoritative zone MUST contain at least one SOA record.
            if zone.get_soa().is_none() {
                tracing::error!(
                    zone = %zone.origin,
                    "Rejecting zone: no SOA record found (RFC 1035 §3.3.13 requires at least one SOA per zone)"
                );
                metrics::counter!("dns_zone_reload_failures_total").increment(1);
                return Err(format!("Zone {}: must contain a SOA record", zone.origin));
            }

            zone.validate_zone_for_activation().map_err(|e| {
                metrics::counter!("dns_zone_reload_failures_total").increment(1);
                e.to_string()
            })?;

            tracing::info!("Loaded DNS zone: {} (serial: {})", zone.origin, zone.serial);
            zone.mark_active();
            self.zones.insert(zone.origin.clone(), zone);
        }

        self.rebuild_zone_index();

        for origin in zone_origins {
            self.invalidate_zone_cache(origin, InvalidationReason::ZoneLoad);
        }

        Ok(zone_configs.len())
    }

    pub fn load_zones_from_store(&self, store: &ZoneStore) -> Result<(), String> {
        let stored_zones = store.load_zones()?;
        let mut loaded_origins = Vec::new();

        for (origin, mut zone) in stored_zones {
            // Defense-in-depth: reject zones without SOA even from persistence.
            if zone.get_soa().is_none() {
                tracing::error!(
                    zone = %origin,
                    "Rejecting zone from store: no SOA record found"
                );
                metrics::counter!("dns_zone_reload_failures_total").increment(1);
                return Err(format!(
                    "Zone {} (from store): must contain a SOA record",
                    origin
                ));
            }
            zone.validate_zone_for_activation().map_err(|e| {
                metrics::counter!("dns_zone_reload_failures_total").increment(1);
                format!("Zone {} (from store): {}", origin, e)
            })?;
            // Reload path: the persisted records are the source of truth, so
            // they are installed through the single writer (normalize,
            // deduplicate, rebuild the chain, restore the SOA serial).
            zone.commit_records(zone.records.clone(), SerialPolicy::AdoptSoa)
                .map_err(|reason| format!("Zone {} (from store): {reason}", origin))?;
            tracing::info!("Loaded DNS zone from store: {}", origin);
            zone.mark_active();
            self.zones.insert(origin.clone(), zone);
            loaded_origins.push(origin);
        }

        self.rebuild_zone_index();

        for origin in &loaded_origins {
            self.invalidate_zone_cache(origin, InvalidationReason::ZoneLoadFromStore);
        }

        Ok(())
    }

    /// Atomically replace a zone in the active store after validating the candidate.
    ///
    /// This is the production-safe reload API: it guarantees that **the previously
    /// active zone is preserved if the candidate fails validation**. Validation
    /// currently enforces:
    /// - exactly one apex SOA,
    /// - non-empty, normalized, printable origin.
    ///
    /// On success, the candidate is marked active and the cache is invalidated for
    /// that origin (`InvalidationReason::ZoneLoad`). On failure, the previous zone
    /// in the store is left untouched and the error is returned.
    ///
    /// Use the lower-level `ShardedZoneStore::insert` only for already-validated
    /// or test-only zones.
    pub fn replace_zone_with_validation(&self, mut candidate: Zone) -> Result<(), String> {
        let origin = candidate.origin.clone();
        // Single writer: normalize, deduplicate, rebuild the owner index and
        // denial chains — then validate the result. The candidate's serial is
        // preserved: this API's contract is "swap in this version", and the
        // caller owns the version number.
        candidate
            .commit_records(candidate.records.clone(), SerialPolicy::Keep)
            .map_err(|reason| format!("Zone {origin}: {reason}"))?;
        candidate
            .validate_zone_for_activation()
            .map_err(|e| e.to_string())?;
        candidate.mark_active();
        self.zones.insert(origin.clone(), candidate);
        self.zone_index_dirty.store(true, Ordering::Release);
        self.invalidate_zone_cache(&origin, InvalidationReason::ZoneLoad);
        tracing::info!(zone = %origin, "Zone replaced atomically with validation");
        Ok(())
    }

    /// Invalidate the answer cache for one origin.
    ///
    /// Paired with every server-side [`Zone::commit_records`] call. The cache
    /// handle lives on the server, not on a `Zone`, because the same writer is
    /// used by cache-less callers (IXFR, mesh apply, tests).
    pub(crate) fn invalidate_zone_cache(&self, origin: &str, reason: InvalidationReason) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(origin, reason);
        }
    }

    pub fn save_zones_to_store(&self, store: &ZoneStore) -> Result<(), String> {
        let mut failure: Option<String> = None;
        self.zones.for_each(|origin, zone| {
            if failure.is_some() {
                return;
            }
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

            if let Err(e) = store.save_zone(origin, &records) {
                failure = Some(format!("Failed to persist zone {origin}: {e}"));
            }
        });

        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn add_record(&self, zone: &str, mut record: DnsZoneRecord) -> Result<(), String> {
        let zone_origin = Zone::normalize_origin(zone);
        let mut error: Option<String> = None;

        self.zones
            .get_or_create_and_update(&zone_origin, |zone_entry| {
                let relative = match Zone::normalize_record_name(&zone_entry.origin, &record.name) {
                    Ok(relative) => relative,
                    Err(reason) => {
                        error = Some(format!(
                            "Zone {}: record name '{}' {reason}",
                            zone_entry.origin, record.name
                        ));
                        return;
                    }
                };
                record.name = relative.clone();

                // RFC 2181 §5.2: every record in an RRset shares one TTL. Adding a
                // record with a different TTL would make the served RRset
                // internally inconsistent, so it is rejected instead of silently
                // rewritten.
                if let Some(existing) = zone_entry
                    .records
                    .get(&(relative.clone(), record.record_type))
                    .and_then(|rrset| rrset.first())
                {
                    if existing.ttl != record.ttl {
                        error = Some(format!(
                        "Zone {}: record '{}' has TTL {} but the existing {:?} RRset has TTL {}",
                        zone_entry.origin, relative, record.ttl, record.record_type, existing.ttl
                    ));
                        return;
                    }
                }

                let mut records = zone_entry.records.clone();
                records
                    .entry((relative, record.record_type))
                    .or_default()
                    .push(record);
                if let Err(reason) = zone_entry.commit_records(records, SerialPolicy::Bump) {
                    error = Some(reason);
                }
            });

        if let Some(error) = error {
            return Err(error);
        }

        self.invalidate_zone_cache(&zone_origin, InvalidationReason::RecordAdd);
        Ok(())
    }

    pub fn with_zone_transfer(mut self, zone_transfer: crate::transfer::ZoneTransfer) -> Self {
        self.zone_transfer = Some(Arc::new(zone_transfer));
        self
    }

    /// Attach a transfer handler built from the persisted transfer policy.
    ///
    /// Fails when the policy asks for TSIG without a verifier: a handler that
    /// cannot authenticate must not be constructed, so composition fails
    /// startup instead of serving transfers with a presence check (R2).
    #[allow(clippy::too_many_arguments)]
    pub fn with_zone_transfer_config(
        mut self,
        acl: crate::transfer::TransferAcl,
        allow_wildcard_transfer: bool,
        wildcard_transfer_requires_tsig: bool,
        ixfr_enabled: bool,
        ixfr_fallback_to_axfr: bool,
        tsig_verifier: Option<Arc<crate::tsig::TsigVerifier>>,
        require_tsig: bool,
    ) -> Result<Self, String> {
        let zone_transfer = crate::transfer::ZoneTransfer::with_security_config(
            self.zones.clone(),
            acl,
            tsig_verifier,
            allow_wildcard_transfer,
            wildcard_transfer_requires_tsig,
            ixfr_enabled,
            ixfr_fallback_to_axfr,
            require_tsig,
            false, // axfr_enabled: disabled by default
            true,  // tcp_only: AXFR requires TCP
        )?;
        self.zone_transfer = Some(Arc::new(zone_transfer));
        Ok(self)
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
    ) -> Result<Self, String> {
        if enabled {
            let handler = crate::update::DynamicUpdateHandler::new(self.zones.clone())
                .with_config(enabled, allow_any, require_tsig)?;
            self.update_handler = Some(handler);
            self.zones.for_each_mut(|zone| {
                zone.mark_active();
            });
        }
        Ok(self)
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
        index.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        *self.zone_index.write() = index;
        *self.zone_index_btree.write() = btree_index;
        *self.zone_trie.write() = trie;
        self.zone_index_dirty.store(false, Ordering::Release);

        self.zones.for_each_mut(|zone| {
            zone.health.record_count = zone.records.len();
        });

        self.zones.rebuild_index();
    }

    /// Attach the mesh DNS registry.
    ///
    /// Prefer [`Self::set_mesh_registry`]: composition holds the server as an
    /// `Arc<DnsServer>`, and this consuming builder only rebinds the temporary
    /// clone it is called on.
    #[cfg(feature = "mesh")]
    pub fn with_mesh_registry(self, registry: Arc<MeshDnsRegistry>) -> Self {
        self.set_mesh_registry(registry);
        self
    }

    /// Bind the mesh DNS registry on the live server.
    ///
    /// The registry is created in composition after `DnsServer::new` has
    /// already run, so it can only be attached here rather than through the
    /// constructor. Returns `true` if this call performed the binding, `false`
    /// if the registry was already bound (existing binding kept).
    #[cfg(feature = "mesh")]
    pub fn set_mesh_registry(&self, registry: Arc<MeshDnsRegistry>) -> bool {
        self.mesh_registry.set(registry, "mesh DNS registry")
    }

    /// The bound mesh DNS registry, if any.
    #[cfg(feature = "mesh")]
    pub fn mesh_registry(&self) -> Option<&Arc<MeshDnsRegistry>> {
        self.mesh_registry.get()
    }

    /// Attach the DNS-owned country-lookup capability.
    pub fn with_country_lookup(mut self, lookup: Arc<dyn CountryLookup>) -> Self {
        self.geoip_lookup = Some(lookup);
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

    /// Clone the connection-limits handle so encrypted transports (DoT)
    /// can hold a connection permit for the full connection lifetime and
    /// apply the same idle/query timeouts as plain TCP (Phase 45).
    pub fn connection_limits(&self) -> Arc<crate::limits::ConnectionLimits> {
        self.connection_limits.clone()
    }

    /// Cap on concurrent accepted connections per encrypted listener.
    ///
    /// DoT, DoH, and DoQ size their accept-loop semaphore from this value.
    pub fn max_encrypted_connections(&self) -> usize {
        self.connection_limits.max_encrypted_connections()
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
            min_geo_ttl: self.authoritative.ttl.min_geo_ttl,
            negative_cache_ttl: self.authoritative.ttl.negative_cache_ttl,
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
            acme_dns_challenges: self.acme_dns_challenges.get(),
            cookie_server: self.cookie_server.as_ref(),
            #[cfg(feature = "mesh")]
            mesh_registry: self.mesh_registry.get(),
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
            cache.clear(InvalidationReason::ManualFlush);
        }
    }

    pub fn cache_stats(&self) -> Option<crate::cache::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
    }

    /// Delete a zone from the in-memory store and invalidate all cached entries for it.
    /// If a `ZoneStore` is provided, also removes from SQLite persistence.
    pub fn delete_zone(&self, origin: &str, store: Option<&ZoneStore>) -> Result<(), String> {
        let origin_lower = origin.trim_end_matches('.').to_lowercase();

        self.zones.update_zone(&origin_lower, |z| {
            let _ = z.set_state(ZoneState::Deleting);
        });

        self.zones.remove(&origin_lower);
        self.zone_index_dirty.store(true, Ordering::Release);

        self.invalidate_zone_cache(&origin_lower, InvalidationReason::ZoneDelete);

        if let Some(store) = store {
            store.delete_zone(&origin_lower)?;
        }

        tracing::info!("Deleted zone {}", origin_lower);
        Ok(())
    }
}

#[cfg(test)]
mod record_name_tests {
    use super::DnsServer;

    fn normalized(origin: &str, name: &str) -> Result<String, String> {
        DnsServer::normalize_record_name(origin, name)
    }

    #[test]
    fn fqdn_inside_the_zone_becomes_origin_relative() {
        assert_eq!(normalized("example.com", "www.example.com").unwrap(), "www");
        assert_eq!(
            normalized("example.com", "_dmarc.example.com").unwrap(),
            "_dmarc"
        );
        assert_eq!(normalized("example.com", "a.b.example.com").unwrap(), "a.b");
    }

    #[test]
    fn the_apex_is_at() {
        // Both spellings of the apex, since a config author may write either.
        assert_eq!(normalized("example.com", "@").unwrap(), "@");
        assert_eq!(normalized("example.com", "example.com").unwrap(), "@");
        assert_eq!(normalized("example.com", "example.com.").unwrap(), "@");
    }

    #[test]
    fn bare_labels_are_already_origin_relative() {
        // Every pre-existing fixture in this repo uses this form.
        assert_eq!(normalized("example.com", "www").unwrap(), "www");
        assert_eq!(normalized("example.com", "ns1").unwrap(), "ns1");
    }

    #[test]
    fn names_are_case_insensitive_and_trailing_dots_are_optional() {
        assert_eq!(
            normalized("EXAMPLE.com", "WWW.Example.COM.").unwrap(),
            "www"
        );
        assert_eq!(normalized("example.com", "WWW").unwrap(), "www");
    }

    #[test]
    fn a_sibling_zone_is_rejected_rather_than_silently_unreachable() {
        // The failure this prevents is the important one: a record stored under
        // a key nothing queries, so the zone answers authoritative NXDOMAIN.
        let err = normalized("example.com", "www.other.net").unwrap_err();
        assert!(err.contains("outside zone"), "unexpected error: {err}");

        // A suffix trap: "notexample.com" must not be treated as inside
        // "example.com".
        let err = normalized("example.com", "www.notexample.com").unwrap_err();
        assert!(err.contains("outside zone"), "unexpected error: {err}");
    }

    #[test]
    fn an_empty_name_is_rejected() {
        assert!(normalized("example.com", "  ").is_err());
        assert!(normalized("example.com", "").is_err());
    }
}

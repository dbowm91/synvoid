use super::*;

impl DnsServer {
    fn build_dnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Some(ref ksk) = zone.ksk_key {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&ksk.public_key),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }

        // Per RFC 4034 Section 2.2, only KSK should be published in DNSKEY set at zone apex.
        // ZSK is used for signing but not exposed in the DNSKEY RRset.

        records
    }

    fn build_ds_records(ksk: &super::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Ok(ds_data) = super::dnssec::create_ds_record(ksk, super::dnssec::DsDigestType::Sha256) {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: hex::encode(&ds_data),
                ttl: 3600,
                priority: None,
            });
        }

        records
    }

    fn build_cds_records(ksk: &super::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Ok(ds_data) = super::dnssec::create_ds_record(ksk, super::dnssec::DsDigestType::Sha256) {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: hex::encode(&ds_data),
                ttl: 3600,
                priority: None,
            });
        }

        if let Ok(ds_data_sha1) = super::dnssec::create_ds_record(ksk, super::dnssec::DsDigestType::Sha1) {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: hex::encode(&ds_data_sha1),
                ttl: 3600,
                priority: None,
            });
        }

        records
    }

    pub fn export_ds_records(&self, zone_name: &str) -> Result<Vec<DsRecordExport>, String> {
        let zones = self.zones.read();
        let zone = zones.get(zone_name).ok_or("Zone not found")?;

        let ksk = zone.ksk_key.as_ref().ok_or("KSK not configured")?;

        let mut exports = Vec::new();

        for digest_type in &[super::dnssec::DsDigestType::Sha256, super::dnssec::DsDigestType::Sha1] {
            if let Ok(ds_data) = super::dnssec::create_ds_record(ksk, *digest_type) {
                if ds_data.len() >= 4 {
                    let key_tag = u16::from_be_bytes([ds_data[0], ds_data[1]]);
                    let algorithm = ds_data[2];
                    let digest_type_val = ds_data[3];
                    let digest = hex::encode(&ds_data[4..]);

                    exports.push(DsRecordExport {
                        key_tag,
                        algorithm,
                        digest_type: digest_type_val,
                        digest,
                    });
                }
            }
        }

        Ok(exports)
    }

    pub fn export_ds_for_parent(&self, zone_name: &str) -> Result<String, String> {
        let exports = self.export_ds_records(zone_name)?;

        let mut output = String::new();
        for ds in &exports {
            let digest_name = match ds.digest_type {
                1 => "SHA1",
                2 => "SHA256",
                _ => "UNKNOWN",
            };
            output.push_str(&format!(
                "@ {} IN DS {} {} {} {}\n",
                3600, ds.key_tag, ds.algorithm, digest_name, ds.digest
            ));
        }

        Ok(output)
    }

    fn build_cdnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Some(ref ksk) = zone.ksk_key {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&ksk.public_key),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }

        if let Some(ref zsk) = zone.zsk_key {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&zsk.public_key),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }

        records
    }

    fn build_nsec3_records(zone: &Zone, qname: &str, _qtype: RecordType) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        let Some(ref nsec3param) = zone.nsec3param else {
            return records;
        };

        let zone_origin = zone.origin.trim_end_matches('.');

        let qname_lower = qname.to_lowercase();
        let mut current = qname_lower.as_str();

        let mut closest_encloser = String::new();
        let mut found = false;

        while let Some(dot_pos) = current.rfind('.') {
            let prefix = &current[..dot_pos];
            let check_name = if prefix.is_empty() {
                zone_origin.to_string()
            } else {
                format!("{}.{}", prefix, zone_origin)
            };

            let key_exists = zone.records.keys().any(|(name, rt)| {
                let full_name = if name == "@" || name.is_empty() {
                    zone_origin.to_string()
                } else {
                    format!("{}.{}", name, zone_origin)
                };
                full_name.to_lowercase() == check_name.to_lowercase() && rt.is_signed()
            });

            if key_exists {
                closest_encloser = check_name;
                found = true;
                break;
            }

            current = prefix;
        }

        if !found {
            closest_encloser = zone_origin.to_string();
        }

        let closest_hash = super::dnssec::hash_name_nsec3(&closest_encloser, nsec3param);
        let closest_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &closest_hash);

        let wildcard_name = format!("*.{}", closest_encloser);
        let wildcard_hash = super::dnssec::hash_name_nsec3(&wildcard_name, nsec3param);
        let wildcard_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &wildcard_hash);

        let next_closer_name = qname_lower.trim_end_matches(&closest_encloser);
        let next_closer = if next_closer_name.is_empty() || next_closer_name == "." {
            qname_lower.clone()
        } else {
            next_closer_name.trim_start_matches('.').to_string()
        };
        let _next_closer_hash = super::dnssec::hash_name_nsec3(&next_closer, nsec3param);

        let wildcard_types = vec![1, 2, 5, 6, 16, 28, 33];

        let wildcard_nsec3 = super::dnssec::create_nsec3_record(&wildcard_hash_b32, &next_closer, nsec3param, &wildcard_types);

        let closest_nsec3 = super::dnssec::create_nsec3_record(&closest_hash_b32, &wildcard_hash_b32, nsec3param, &wildcard_types);

        records.push(DnsZoneRecord {
            name: wildcard_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&wildcard_nsec3),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });

        let closest_hash_b32_for_soa = closest_hash_b32.clone();

        records.push(DnsZoneRecord {
            name: closest_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&closest_nsec3),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });

        if let Some(soa_record) = zone.records.get(&("@".to_string(), RecordType::SOA)) {
            if !soa_record.is_empty() {
                let soa_hash = super::dnssec::hash_name_nsec3(zone_origin, nsec3param);
                let soa_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &soa_hash);

                let soa_types = vec![1, 2, 5, 6, 16, 28, 33];
                let soa_nsec3 = super::dnssec::create_nsec3_record(&soa_hash_b32, &closest_hash_b32_for_soa, nsec3param, &soa_types);

                records.push(DnsZoneRecord {
                    name: soa_hash_b32,
                    record_type: RecordType::NSEC3,
                    value: hex::encode(&soa_nsec3),
                    ttl: zone.dnskey_ttl.unwrap_or(3600),
                    priority: None,
                });
            }
        }

        records
    }

    fn build_nsec_records(zone: &Zone, qname: &str, qtype: RecordType) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        let zone_origin = zone.origin.trim_end_matches('.').to_lowercase();
        let qname_lower = qname.to_lowercase().trim_end_matches('.').to_string();

        let next_name = super::dnssec::find_next_name_in_zone(zone, &qname_lower)
            .unwrap_or_else(|| zone_origin.clone());

        let types = if qname_lower == zone_origin || qname_lower.ends_with(&format!(".{}", zone_origin)) {
            vec![1, 2, 5, 6, 15, 16, 28, 33]
        } else {
            let mut types = vec![1, 2, 5, 6];
            match qtype {
                RecordType::A => types.push(28),
                RecordType::AAAA => types.push(28),
                RecordType::MX => types.push(15),
                RecordType::TXT => types.push(16),
                RecordType::SRV => types.push(33),
                RecordType::CNAME => types.push(5),
                RecordType::NS => types.push(2),
                RecordType::SOA => types.push(6),
                _ => {}
            }
            types
        };

        let nsec_rdata = super::dnssec::create_nsec_record(&qname_lower, &next_name, &types);

        let owner_name = if qname_lower == zone_origin {
            zone_origin.clone()
        } else {
            qname_lower.clone()
        };

        records.push(DnsZoneRecord {
            name: owner_name,
            record_type: RecordType::NSEC,
            value: hex::encode(&nsec_rdata),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });

        records
    }

    #[allow(dead_code)]
    fn build_nsec3_nodata(zone: &Zone, qname: &str, qtype: RecordType) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        let Some(ref nsec3param) = zone.nsec3param else {
            return records;
        };

        let zone_origin = zone.origin.trim_end_matches('.');

        let qname_hash = super::dnssec::hash_name_nsec3(qname, nsec3param);
        let qname_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &qname_hash);

        let _types_exists = zone.records.keys().any(|(name, _rt)| {
            let full_name = if name == "@" || name.is_empty() {
                zone_origin.to_string()
            } else {
                format!("{}.{}", name, zone_origin)
            };
            full_name.to_lowercase() == qname.to_lowercase()
        });

        let mut types = vec![1, 2, 5, 6];

        match qtype {
            RecordType::A => types.push(28),
            RecordType::AAAA => types.push(1),
            RecordType::MX => types.push(15),
            RecordType::TXT => types.push(16),
            RecordType::SRV => types.push(33),
            _ => {}
        }

        let next_domain = format!("*.{}", zone_origin);

        let nsec3_rdata = super::dnssec::create_nsec3_record(&qname_hash_b32, &next_domain, nsec3param, &types);

        records.push(DnsZoneRecord {
            name: qname_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&nsec3_rdata),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });

        if let Some(soa_record) = zone.records.get(&("@".to_string(), RecordType::SOA)) {
            if !soa_record.is_empty() {
                let soa_hash = super::dnssec::hash_name_nsec3(zone_origin, nsec3param);
                let soa_hash_b32 = super::dnssec::create_nsec3_owner_name(zone_origin, &soa_hash);

                let soa_types = vec![1, 2, 5, 6, 16, 28, 33];
                let soa_nsec3 = super::dnssec::create_nsec3_record(&soa_hash_b32, qname, nsec3param, &soa_types);

                records.push(DnsZoneRecord {
                    name: soa_hash_b32,
                    record_type: RecordType::NSEC3,
                    value: hex::encode(&soa_nsec3),
                    ttl: zone.dnskey_ttl.unwrap_or(3600),
                    priority: None,
                });
            }
        }

        records
    }

    #[allow(dead_code)]
    fn is_nodata(zone: &Zone, qname: &str) -> bool {
        let zone_origin = zone.origin.trim_end_matches('.');

        if qname.ends_with(zone_origin) || qname == zone_origin {
            let lookup_name = if qname == zone_origin {
                "@".to_string()
            } else {
                qname.strip_suffix(&format!(".{}", zone_origin))
                    .unwrap_or(qname)
                    .to_string()
            };

            let has_records = zone.records.keys().any(|(name, _)| {
                name == &lookup_name || name.is_empty()
            });

            return has_records;
        }

        false
    }

    fn build_nsec3param_record(zone: &Zone) -> Option<DnsZoneRecord> {
        let Some(ref nsec3param) = zone.nsec3param else {
            return None;
        };

        let nsec3param_data = super::dnssec::create_nsec3param_record(nsec3param);

        Some(DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NSEC3PARAM,
            value: hex::encode(&nsec3param_data),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        })
    }

    #[allow(dead_code)]
    fn build_dnssec_response(
        &self,
        _id: u16,
        _qname: &str,
        _qtype: u16,
        _records: &[DnsZoneRecord],
    ) -> Option<Vec<u8>> {
        // DNSSEC disabled - return None
        None
    }

    pub fn start_key_rotation_task(
        dnssec: Option<Arc<RwLock<DnsSecKeyManager>>>,
        interval_secs: u64,
    ) {
        if let Some(dnssec_manager) = dnssec {
            let rotation_interval = Duration::from_secs(interval_secs);

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(rotation_interval);

                loop {
                    interval.tick().await;

                    let mut manager = dnssec_manager.write();
                    let config = super::dnssec::KeyRotationConfig::default();

                    match manager.check_and_rotate(config) {
                        Ok(result) => {
                            if result.ksk_rotated || result.zsk_rotated {
                                tracing::info!("DNSSEC key rotation completed: {:?}", result);
                            }
                        }
                        Err(e) => {
                            tracing::error!("DNSSEC key rotation check failed: {}", e);
                        }
                    }
                }
            });

            tracing::info!("DNSSEC key rotation task started with interval {}s", interval_secs);
        }
    }

    pub fn get_dnssec_status(&self) -> Option<super::dnssec::DnsSecKeyStatus> {
        self.dnssec.as_ref().and_then(|d| {
            let manager = d.read();
            manager.get_key_status().ok()
        })
    }
}

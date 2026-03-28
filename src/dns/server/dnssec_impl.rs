use super::*;

impl DnsServer {
    pub fn initialize_dnssec(&self) -> Result<(), String> {
        let dnssec = self.dnssec.as_ref().ok_or("DNSSEC not enabled")?;
        let mut manager = dnssec.write();

        manager.initialize()?;

        if manager.key_signing_key.is_none() {
            let algorithm = self.config.dnssec.algorithm.into();
            manager.generate_key(
                algorithm,
                crate::dns::dnssec::KeyType::KSK,
                self.config.dnssec.ksk_key_size,
                365,
            )?;
        }

        if manager.zone_signing_key.is_none() {
            let algorithm = self.config.dnssec.algorithm.into();
            manager.generate_key(
                algorithm,
                crate::dns::dnssec::KeyType::ZSK,
                self.config.dnssec.rsa_key_size,
                90,
            )?;
        }

        let ksk = manager.key_signing_key.clone();
        let zsk = manager.zone_signing_key.clone();

        drop(manager);

        let mut zones = self.zones.write();
        for (_, zone) in zones.iter_mut() {
            zone.ksk_key = ksk.clone();
            zone.zsk_key = zsk.clone();
            tracing::info!("Initialized DNSSEC keys for zone: {}", zone.origin);
        }

        Ok(())
    }

    pub(super) fn build_dnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
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

    pub(super) fn build_ds_records(ksk: &crate::dns::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Ok(ds_data) =
            crate::dns::dnssec::create_ds_record(ksk, crate::dns::dnssec::DsDigestType::Sha256)
        {
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

    pub(super) fn build_cds_records(
        ksk: &crate::dns::dnssec::ZoneSigningKey,
    ) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Ok(ds_data) =
            crate::dns::dnssec::create_ds_record(ksk, crate::dns::dnssec::DsDigestType::Sha256)
        {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::CDS,
                value: hex::encode(&ds_data),
                ttl: 3600,
                priority: None,
            });
        }

        if let Ok(ds_data_sha1) =
            crate::dns::dnssec::create_ds_record(ksk, crate::dns::dnssec::DsDigestType::Sha1)
        {
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

        for digest_type in &[
            crate::dns::dnssec::DsDigestType::Sha256,
            crate::dns::dnssec::DsDigestType::Sha1,
        ] {
            if let Ok(ds_data) = crate::dns::dnssec::create_ds_record(ksk, *digest_type) {
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

    pub(super) fn build_cdnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
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

    pub(super) fn build_nsec3_records(
        zone: &Zone,
        qname: &str,
        _qtype: RecordType,
    ) -> Vec<DnsZoneRecord> {
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

        let closest_hash = crate::dns::dnssec::hash_name_nsec3(&closest_encloser, nsec3param);
        let closest_hash_b32 =
            crate::dns::dnssec::create_nsec3_owner_name(zone_origin, &closest_hash);

        let wildcard_name = format!("*.{}", closest_encloser);
        let wildcard_hash = crate::dns::dnssec::hash_name_nsec3(&wildcard_name, nsec3param);
        let wildcard_hash_b32 =
            crate::dns::dnssec::create_nsec3_owner_name(zone_origin, &wildcard_hash);

        let next_closer_name = qname_lower.trim_end_matches(&closest_encloser);
        let next_closer = if next_closer_name.is_empty() || next_closer_name == "." {
            qname_lower.clone()
        } else {
            next_closer_name.trim_start_matches('.').to_string()
        };
        let _next_closer_hash = crate::dns::dnssec::hash_name_nsec3(&next_closer, nsec3param);

        let wildcard_types = vec![1, 2, 5, 6, 16, 28, 33];

        let wildcard_nsec3 = crate::dns::dnssec::create_nsec3_record(
            &wildcard_hash_b32,
            &next_closer,
            nsec3param,
            &wildcard_types,
        );

        let closest_nsec3 = crate::dns::dnssec::create_nsec3_record(
            &closest_hash_b32,
            &wildcard_hash_b32,
            nsec3param,
            &wildcard_types,
        );

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
                let soa_hash = crate::dns::dnssec::hash_name_nsec3(zone_origin, nsec3param);
                let soa_hash_b32 =
                    crate::dns::dnssec::create_nsec3_owner_name(zone_origin, &soa_hash);

                let soa_types = vec![1, 2, 5, 6, 16, 28, 33];
                let soa_nsec3 = crate::dns::dnssec::create_nsec3_record(
                    &soa_hash_b32,
                    &closest_hash_b32_for_soa,
                    nsec3param,
                    &soa_types,
                );

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

    pub(super) fn build_nsec_records(
        zone: &Zone,
        qname: &str,
        qtype: RecordType,
    ) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        let zone_origin = zone.origin.trim_end_matches('.').to_lowercase();
        let qname_lower = qname.to_lowercase().trim_end_matches('.').to_string();

        let next_name = crate::dns::dnssec::find_next_name_in_zone(zone, &qname_lower)
            .unwrap_or_else(|| zone_origin.clone());

        let types =
            if qname_lower == zone_origin || qname_lower.ends_with(&format!(".{}", zone_origin)) {
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

        let nsec_rdata = crate::dns::dnssec::create_nsec_record(&qname_lower, &next_name, &types);

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
    pub(super) fn build_nsec3_nodata(
        zone: &Zone,
        qname: &str,
        qtype: RecordType,
    ) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        let Some(ref nsec3param) = zone.nsec3param else {
            return records;
        };

        let zone_origin = zone.origin.trim_end_matches('.');

        let qname_hash = crate::dns::dnssec::hash_name_nsec3(qname, nsec3param);
        let qname_hash_b32 = crate::dns::dnssec::create_nsec3_owner_name(zone_origin, &qname_hash);

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

        let nsec3_rdata = crate::dns::dnssec::create_nsec3_record(
            &qname_hash_b32,
            &next_domain,
            nsec3param,
            &types,
        );

        records.push(DnsZoneRecord {
            name: qname_hash_b32,
            record_type: RecordType::NSEC3,
            value: hex::encode(&nsec3_rdata),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        });

        if let Some(soa_record) = zone.records.get(&("@".to_string(), RecordType::SOA)) {
            if !soa_record.is_empty() {
                let soa_hash = crate::dns::dnssec::hash_name_nsec3(zone_origin, nsec3param);
                let soa_hash_b32 =
                    crate::dns::dnssec::create_nsec3_owner_name(zone_origin, &soa_hash);

                let soa_types = vec![1, 2, 5, 6, 16, 28, 33];
                let soa_nsec3 = crate::dns::dnssec::create_nsec3_record(
                    &soa_hash_b32,
                    qname,
                    nsec3param,
                    &soa_types,
                );

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
    pub(super) fn is_nodata(zone: &Zone, qname: &str) -> bool {
        let zone_origin = zone.origin.trim_end_matches('.');

        if qname.ends_with(zone_origin) || qname == zone_origin {
            let lookup_name = if qname == zone_origin {
                "@".to_string()
            } else {
                qname
                    .strip_suffix(&format!(".{}", zone_origin))
                    .unwrap_or(qname)
                    .to_string()
            };

            let has_records = zone
                .records
                .keys()
                .any(|(name, _)| name == &lookup_name || name.is_empty());

            return has_records;
        }

        false
    }

    pub(super) fn build_nsec3param_record(zone: &Zone) -> Option<DnsZoneRecord> {
        let Some(ref nsec3param) = zone.nsec3param else {
            return None;
        };

        let nsec3param_data = crate::dns::dnssec::create_nsec3param_record(nsec3param);

        Some(DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NSEC3PARAM,
            value: hex::encode(&nsec3param_data),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        })
    }

    pub(super) fn create_signed_rrsig(
        record: &DnsZoneRecord,
        signer_name: &str,
        key: &crate::dns::dnssec::ZoneSigningKey,
    ) -> Vec<u8> {
        let labels = crate::dns::dnssec::count_labels(&record.name);

        let canonical_rdata = crate::dns::dnssec::canonical_rdata(
            u16::from(record.record_type),
            &record.value,
            record.priority,
            None,
            None,
            record.ttl,
        );

        let mut canonical_msg = Vec::new();

        let name_lower = record.name.to_lowercase();
        let name = name_lower.trim_end_matches('.');

        if name.is_empty() {
            canonical_msg.push(0);
        } else {
            for part in name.split('.') {
                if !part.is_empty() {
                    canonical_msg.push(part.len() as u8);
                    canonical_msg.extend_from_slice(part.as_bytes());
                }
            }
            canonical_msg.push(0);
        }

        canonical_msg.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
        canonical_msg.extend_from_slice(&1u16.to_be_bytes());
        canonical_msg.extend_from_slice(&record.ttl.to_be_bytes());
        canonical_msg.extend_from_slice(&(canonical_rdata.len() as u16).to_be_bytes());
        canonical_msg.extend_from_slice(&canonical_rdata);

        let signature = match crate::dns::dnssec::sign_data(&canonical_msg, key) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::warn!("Failed to sign record: {}", e);
                return Vec::new();
            }
        };

        let now = chrono::Utc::now().timestamp() as u64;
        let sig_expire = now + (7 * 86400);
        let sig_inception = now - 86400;

        let mut rrsig = Vec::new();

        rrsig.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
        rrsig.push(key.algorithm.to_u8());
        rrsig.push(labels);
        rrsig.extend_from_slice(&record.ttl.to_be_bytes());
        rrsig.extend_from_slice(&sig_expire.to_be_bytes());
        rrsig.extend_from_slice(&sig_inception.to_be_bytes());
        rrsig.extend_from_slice(&key.key_tag.to_be_bytes());

        let signer = signer_name.trim_end_matches('.');
        for part in signer.split('.') {
            if !part.is_empty() {
                rrsig.push(part.len() as u8);
                rrsig.extend_from_slice(part.as_bytes());
            }
        }
        rrsig.push(0);

        rrsig.extend_from_slice(&signature);

        rrsig
    }

    #[allow(dead_code)]
    pub(super) fn build_dnssec_response(
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
                    let config = crate::dns::dnssec::KeyRotationConfig::default();

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

            tracing::info!(
                "DNSSEC key rotation task started with interval {}s",
                interval_secs
            );
        }
    }

    pub fn get_dnssec_status(&self) -> Option<crate::dns::dnssec::DnsSecKeyStatus> {
        self.dnssec.as_ref().and_then(|d| {
            let manager = d.read();
            manager.get_key_status().ok()
        })
    }
}

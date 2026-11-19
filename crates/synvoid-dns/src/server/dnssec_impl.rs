use super::*;
use crate::dnssec::canonical_name;
use crate::time::unix_timestamp_secs;
use crate::wire::OwnerName;

/// The key handles a signed zone signs with (RFC 4035 §2.2).
///
/// A zone is either signed with both keys or not signed at all: a KSK signs the
/// DNSKEY RRset (and CDS/CDNSKEY), a ZSK signs everything else. Making the pair
/// a value instead of two independent `Option`s means a call site cannot pick
/// the wrong handle, and a half-configured zone cannot produce a partially
/// signed response.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ZoneSigningKeys<'a> {
    ksk: &'a crate::dnssec::ZoneSigningKey,
    zsk: &'a crate::dnssec::ZoneSigningKey,
}

impl<'a> ZoneSigningKeys<'a> {
    /// Classify a zone: `Ok(None)` for an unsigned zone, `Err` for a zone that
    /// carries one key but not the other.
    pub(super) fn from_zone(zone: &'a Zone) -> Result<Option<Self>, MissingSigningKey> {
        match (&zone.ksk_key, &zone.zsk_key) {
            (None, None) => Ok(None),
            (Some(ksk), Some(zsk)) => Ok(Some(Self { ksk, zsk })),
            (Some(_), None) => Err(MissingSigningKey::Zsk),
            (None, Some(_)) => Err(MissingSigningKey::Ksk),
        }
    }

    /// True when both handles can produce a signature.
    ///
    /// Startup rejects a signed zone whose keys are public-only: it would pass
    /// the "both keys exist" check and then fail every response at signing
    /// time, which is a configuration error, not a runtime condition.
    fn can_sign(&self) -> bool {
        self.ksk.has_private() && self.zsk.has_private()
    }

    /// The key that signs an RRset of `record_type`.
    ///
    /// RFC 4035 §2.2: the DNSKEY RRset must be signed by the key the parent DS
    /// points at, i.e. the KSK. The signal for that relationship (CDS/CDNSKEY)
    /// is published alongside the DNSKEY and is signed the same way. Every
    /// other RRset — DS, NSEC, NSEC3, NSEC3PARAM, SOA and ordinary zone data —
    /// is signed by the ZSK.
    pub(super) fn signing_key_for(
        &self,
        record_type: RecordType,
    ) -> &'a crate::dnssec::ZoneSigningKey {
        match record_type {
            RecordType::DNSKEY | RecordType::CDS | RecordType::CDNSKEY => self.ksk,
            _ => self.zsk,
        }
    }
}

/// Which half of a signed zone's key pair is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingSigningKey {
    Ksk,
    Zsk,
}

impl std::fmt::Display for MissingSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ksk => write!(f, "signed zone has a ZSK but no KSK"),
            Self::Zsk => write!(f, "signed zone has a KSK but no ZSK"),
        }
    }
}

impl DnsServer {
    pub fn initialize_dnssec(&self) -> Result<(), String> {
        let dnssec = self.dnssec.as_ref().ok_or("DNSSEC not enabled")?;
        let mut manager = dnssec.write();

        manager.initialize().map_err(|e| e.to_string())?;
        manager.load_keys_from_disk().map_err(|e| e.to_string())?;

        if manager.active_ksk().is_err() {
            let algorithm = crate::dnssec::algorithm_from_runtime(self.dnssec_runtime.algorithm);
            manager
                .generate_key(
                    algorithm,
                    crate::dnssec::KeyType::KSK,
                    self.dnssec_runtime.ksk_key_size,
                    365,
                )
                .map_err(|e| e.to_string())?;
        }

        if manager.active_zsk().is_err() {
            let algorithm = crate::dnssec::algorithm_from_runtime(self.dnssec_runtime.algorithm);
            manager
                .generate_key(
                    algorithm,
                    crate::dnssec::KeyType::ZSK,
                    self.dnssec_runtime.rsa_key_size,
                    90,
                )
                .map_err(|e| e.to_string())?;
        }

        let ksk = manager.active_ksk().map_err(|e| e.to_string())?;
        let zsk = manager.active_zsk().map_err(|e| e.to_string())?;

        drop(manager);

        self.zones.for_each_mut(|zone| {
            zone.ksk_key = Some(Arc::clone(&ksk));
            zone.zsk_key = Some(Arc::clone(&zsk));
            tracing::info!("Initialized DNSSEC keys for zone: {}", zone.origin);
        });

        // Fail fast: every zone is either signed with both keys or not signed.
        // A half-configured zone would otherwise serve unsigned data in a zone
        // whose RRSIGs a validator expects (R3).
        let mut problem = None;
        self.zones
            .for_each(|origin, zone| match ZoneSigningKeys::from_zone(zone) {
                Ok(Some(keys)) if !keys.can_sign() => {
                    problem = Some(format!(
                        "Zone {origin}: a signing key handle holds no private material"
                    ));
                }
                Ok(_) => {}
                Err(reason) => problem = Some(format!("Zone {origin}: {reason}")),
            });
        if let Some(reason) = problem {
            tracing::error!("DNSSEC key configuration is unusable: {reason}");
            return Err(reason);
        }

        Ok(())
    }

    pub(super) fn build_dnskey_records(zone: &Zone) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Some(ref ksk) = zone.ksk_key {
            let dnskey_rdata = crate::dnssec::compute_dnskey(ksk);
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&dnskey_rdata),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }

        if let Some(ref zsk) = zone.zsk_key {
            let dnskey_rdata = crate::dnssec::compute_dnskey(zsk);
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: hex::encode(&dnskey_rdata),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }

        records
    }

    pub(super) fn build_ds_records(ksk: &crate::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Ok(ds_data) =
            crate::dnssec::create_ds_record(ksk, crate::dnssec::DsDigestType::Sha256)
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

    pub(super) fn build_cds_records(ksk: &crate::dnssec::ZoneSigningKey) -> Vec<DnsZoneRecord> {
        let mut records = Vec::new();

        if let Ok(ds_data) =
            crate::dnssec::create_ds_record(ksk, crate::dnssec::DsDigestType::Sha256)
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
            crate::dnssec::create_ds_record(ksk, crate::dnssec::DsDigestType::Sha1)
        {
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::CDS,
                value: hex::encode(&ds_data_sha1),
                ttl: 3600,
                priority: None,
            });
        }

        records
    }

    pub fn export_ds_records(&self, zone_name: &str) -> Result<Vec<DsRecordExport>, String> {
        let zone = self.zones.get(zone_name).ok_or("Zone not found")?;

        let ksk = zone.ksk_key.as_deref().ok_or("KSK not configured")?;

        let mut exports = Vec::new();

        for digest_type in &[
            crate::dnssec::DsDigestType::Sha256,
            crate::dnssec::DsDigestType::Sha1,
        ] {
            if let Ok(ds_data) = crate::dnssec::create_ds_record(ksk, *digest_type) {
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
            let cdnskey_rdata = crate::dnssec::compute_dnskey(ksk);
            records.push(DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::CDNSKEY,
                value: hex::encode(&cdnskey_rdata),
                ttl: zone.dnskey_ttl.unwrap_or(3600),
                priority: None,
            });
        }

        records
    }

    pub(super) fn build_nsec3param_record(zone: &Zone) -> Option<DnsZoneRecord> {
        // Publish the same parameters the hash chain was built from: a salt
        // that cannot be length-prefixed, or an iteration count above the cap,
        // must not appear in RDATA that the chain does not use.
        let nsec3param = zone.nsec3param.as_ref()?.sanitized()?;

        let nsec3param_data = crate::dnssec::create_nsec3param_record(&nsec3param);

        Some(DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NSEC3PARAM,
            value: hex::encode(&nsec3param_data),
            ttl: zone.dnskey_ttl.unwrap_or(3600),
            priority: None,
        })
    }

    /// The RRSIG for one RRset, signed over the canonical FQDN.
    ///
    /// `origin` is the zone the records belong to. The owner that is signed
    /// and the `Labels` field both come from [`OwnerName`], so a storage key
    /// (`www`, `@`) can never become the signing input; the RRSIG signer name
    /// is derived from the same origin, which is the zone apex by definition,
    /// so it cannot drift from the owner.
    ///
    /// The signature covers the **whole RRset** (RFC 4034 §3.1.2), in
    /// canonical order — not one record — because a validator hashes every
    /// record of the RRset. `rrset` must be non-empty and homogeneous (same
    /// owner and type); the caller encodes exactly these records.
    ///
    /// Errors are returned, never swallowed: the caller must answer SERVFAIL
    /// rather than emit an RRset without its signature.
    pub(super) fn create_signed_rrsig(
        rrset: &[&DnsZoneRecord],
        origin: &str,
        keys: &ZoneSigningKeys<'_>,
    ) -> Result<Vec<u8>, String> {
        let Some(first) = rrset.first() else {
            // An empty RRset has nothing to authenticate; treating it as
            // "nothing to sign" would let a caller emit unsigned data.
            return Err("cannot sign an empty RRset".to_string());
        };
        let record_type = first.record_type;

        match Self::sign_rrset(rrset, origin, keys) {
            Ok(rrsig) => Ok(rrsig),
            Err(reason) => {
                tracing::error!(
                    owner = %first.name,
                    origin = %origin,
                    record_type = ?record_type,
                    records = rrset.len(),
                    reason = %reason,
                    "DNSSEC: refusing to serve an RRset whose RRSIG could not be produced"
                );
                metrics::counter!("dns_dnssec_signing_failures_total").increment(1);
                Err(reason)
            }
        }
    }

    fn sign_rrset(
        rrset: &[&DnsZoneRecord],
        origin: &str,
        keys: &ZoneSigningKeys<'_>,
    ) -> Result<Vec<u8>, String> {
        let first = rrset
            .first()
            .copied()
            .ok_or_else(|| "cannot sign an empty RRset".to_string())?;
        let record_type = first.record_type;
        if rrset
            .iter()
            .any(|r| r.record_type != record_type || r.name != first.name)
        {
            return Err("RRset contains records with different owners or types".to_string());
        }

        let key = keys.signing_key_for(record_type);
        let owner = OwnerName::new(&first.name, origin);
        let labels = owner.labels();
        let canonical_owner = canonical_name(&owner.fqdn()).map_err(|e| {
            format!(
                "owner '{}' in zone '{}' is not encodable: {e}",
                first.name, origin
            )
        })?;

        // RFC 4034 §6.3: the RRset is signed in canonical order, i.e. sorted
        // by RDATA bytes.
        let mut rdatas = Vec::with_capacity(rrset.len());
        for record in rrset {
            rdatas.push(super::rdata_wire(record)?);
        }
        rdatas.sort();

        let mut canonical_msg = Vec::new();
        canonical_msg.extend_from_slice(&u16::from(record_type).to_be_bytes());
        canonical_msg.push(key.algorithm().to_u8());
        canonical_msg.push(labels);
        canonical_msg.extend_from_slice(&first.ttl.to_be_bytes());
        let now = unix_timestamp_secs();
        let sig_expire = now + (7 * 86400);
        let sig_inception = now - 86400;
        canonical_msg.extend_from_slice(&(sig_expire as u32).to_be_bytes());
        canonical_msg.extend_from_slice(&(sig_inception as u32).to_be_bytes());
        canonical_msg.extend_from_slice(&key.key_tag().to_be_bytes());
        // The signer name is the zone apex, in canonical (lowercase) form.
        let signer = canonical_name(&OwnerName::new("@", origin).fqdn())
            .map_err(|e| format!("zone apex '{origin}' is not encodable: {e}"))?;
        canonical_msg.extend_from_slice(&signer);

        for rdata in &rdatas {
            let rdata_len = u16::try_from(rdata.len())
                .map_err(|_| format!("RDATA of {} bytes exceeds u16::MAX", rdata.len()))?;
            canonical_msg.extend_from_slice(&canonical_owner);
            canonical_msg.extend_from_slice(&u16::from(record_type).to_be_bytes());
            canonical_msg.extend_from_slice(&1u16.to_be_bytes());
            canonical_msg.extend_from_slice(&first.ttl.to_be_bytes());
            canonical_msg.extend_from_slice(&rdata_len.to_be_bytes());
            canonical_msg.extend_from_slice(rdata);
        }

        let signature = crate::dnssec::sign_data(&canonical_msg, key)?;

        let mut rrsig = Vec::new();
        rrsig.extend_from_slice(&u16::from(record_type).to_be_bytes());
        rrsig.push(key.algorithm().to_u8());
        rrsig.push(labels);
        rrsig.extend_from_slice(&first.ttl.to_be_bytes());
        rrsig.extend_from_slice(&(sig_expire as u32).to_be_bytes());
        rrsig.extend_from_slice(&(sig_inception as u32).to_be_bytes());
        rrsig.extend_from_slice(&key.key_tag().to_be_bytes());
        rrsig.extend_from_slice(&signer);
        rrsig.extend_from_slice(&signature);

        Ok(rrsig)
    }

    /// A SERVFAIL that echoes the question and, when the client sent one, its
    /// OPT record. Count-free: signing failures are counted where they are
    /// detected, so a response can never inflate the metric twice.
    pub(super) fn servfail_packet(
        response_id: u16,
        rd: bool,
        edns_options: Option<&EdnsOptions>,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let flags = build_response_flags(true, false, rd, false, false, 2);
        let mut envelope = ResponseEnvelope::default();
        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }
        Arc::new(assemble_packet(&envelope, response_id, flags, question))
    }

    /// Fail closed for a zone that cannot be signed at all.
    ///
    /// A zone carrying one half of a key pair must not answer with a mix of
    /// signed and unsigned RRsets, so the whole response is SERVFAIL and the
    /// event is counted (R3/R6).
    pub(super) fn dnssec_servfail(
        response_id: u16,
        qname: &str,
        rd: bool,
        edns_options: Option<&EdnsOptions>,
        question: &[u8],
        reason: &str,
    ) -> Arc<Vec<u8>> {
        tracing::error!(
            qname = %qname,
            reason = %reason,
            "DNSSEC: signed zone cannot sign; returning SERVFAIL"
        );
        metrics::counter!("dns_dnssec_signing_failures_total").increment(1);
        Self::servfail_packet(response_id, rd, edns_options, question)
    }

    /// The signing keys for `zone`, or the SERVFAIL a half-signed zone must
    /// answer with.
    pub(super) fn signing_keys_for_zone<'a>(
        zone: &'a Zone,
        response_id: u16,
        qname: &str,
        rd: bool,
        edns_options: Option<&EdnsOptions>,
        question: &[u8],
    ) -> Result<Option<ZoneSigningKeys<'a>>, Arc<Vec<u8>>> {
        ZoneSigningKeys::from_zone(zone).map_err(|reason| {
            Self::dnssec_servfail(
                response_id,
                qname,
                rd,
                edns_options,
                question,
                &reason.to_string(),
            )
        })
    }

    pub fn get_dnssec_status(&self) -> Option<crate::dnssec::DnsSecKeyStatus> {
        self.dnssec.as_ref().and_then(|d| {
            let manager = d.read();
            manager.key_status().ok()
        })
    }
}

#[cfg(test)]
mod signing_key_selection_tests {
    use super::*;

    fn key(key_type: crate::dnssec::KeyType) -> Arc<crate::dnssec::ZoneSigningKey> {
        Arc::new(
            crate::dnssec::ZoneSigningKey::generate_ephemeral(
                crate::dnssec::Algorithm::Ed25519,
                key_type,
            )
            .expect("ephemeral key"),
        )
    }

    #[test]
    fn key_selection_is_ksk_for_dnskey_material_and_zsk_for_everything_else() {
        let mut zone = Zone::new("example.com".to_string());
        zone.ksk_key = Some(key(crate::dnssec::KeyType::KSK));
        zone.zsk_key = Some(key(crate::dnssec::KeyType::ZSK));

        let keys = ZoneSigningKeys::from_zone(&zone)
            .expect("a zone with both keys is signed")
            .expect("both keys yield a signing set");

        for record_type in [RecordType::DNSKEY, RecordType::CDS, RecordType::CDNSKEY] {
            assert_eq!(
                keys.signing_key_for(record_type).key_tag(),
                zone.ksk_key.as_ref().unwrap().key_tag(),
                "{record_type} must be signed by the KSK (RFC 4035 §2.2)"
            );
        }
        for record_type in [
            RecordType::DS,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::NSEC3PARAM,
            RecordType::SOA,
            RecordType::A,
            RecordType::TXT,
        ] {
            assert_eq!(
                keys.signing_key_for(record_type).key_tag(),
                zone.zsk_key.as_ref().unwrap().key_tag(),
                "{record_type} must be signed by the ZSK"
            );
        }
    }

    #[test]
    fn a_half_configured_zone_is_not_signed() {
        let mut zone = Zone::new("example.com".to_string());
        assert!(
            ZoneSigningKeys::from_zone(&zone).unwrap().is_none(),
            "a zone with no keys is simply unsigned"
        );

        zone.ksk_key = Some(key(crate::dnssec::KeyType::KSK));
        assert_eq!(
            ZoneSigningKeys::from_zone(&zone).unwrap_err(),
            MissingSigningKey::Zsk,
            "a KSK without a ZSK is a startup error, not a signed zone"
        );

        zone.ksk_key = None;
        zone.zsk_key = Some(key(crate::dnssec::KeyType::ZSK));
        assert_eq!(
            ZoneSigningKeys::from_zone(&zone).unwrap_err(),
            MissingSigningKey::Ksk,
            "a ZSK without a KSK is a startup error, not a signed zone"
        );
    }
}

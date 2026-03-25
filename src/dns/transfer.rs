use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::dns::server::{DnsZoneRecord, RecordType, RecordTypeExt, Zone};
use crate::dns::tsig::{TsigParseResult, TsigVerifier};
use crate::dns::wire;

pub const AXFR_QUERY_TYPE: u16 = 252;
pub const IXFR_QUERY_TYPE: u16 = 251;

pub struct ZoneTransfer {
    zones: Arc<RwLock<HashMap<String, Zone>>>,
    allowed_transfers: Vec<String>,
    tsig_verifier: Option<Arc<TsigVerifier>>,
    allow_wildcard_transfer: bool,
    wildcard_transfer_requires_tsig: bool,
    ixfr_enabled: bool,
    ixfr_fallback_to_axfr: bool,
}

impl ZoneTransfer {
    pub fn new(
        zones: Arc<RwLock<HashMap<String, Zone>>>,
        allowed_transfers: Vec<String>,
        tsig_verifier: Option<Arc<TsigVerifier>>,
    ) -> Self {
        Self {
            zones,
            allowed_transfers,
            tsig_verifier,
            allow_wildcard_transfer: false,
            wildcard_transfer_requires_tsig: true,
            ixfr_enabled: true,
            ixfr_fallback_to_axfr: true,
        }
    }

    pub fn with_security_config(
        zones: Arc<RwLock<HashMap<String, Zone>>>,
        allowed_transfers: Vec<String>,
        tsig_verifier: Option<Arc<TsigVerifier>>,
        allow_wildcard_transfer: bool,
        wildcard_transfer_requires_tsig: bool,
        ixfr_enabled: bool,
        ixfr_fallback_to_axfr: bool,
    ) -> Self {
        if allowed_transfers.contains(&"*".to_string()) && !allow_wildcard_transfer {
            tracing::warn!(
                "SECURITY: Zone transfer configuration contains wildcard '*' which is disabled by default. \
                 Set allow_wildcard_transfer: true in dns.settings to enable."
            );
        }

        if allowed_transfers.contains(&"*".to_string()) && wildcard_transfer_requires_tsig {
            tracing::warn!(
                "SECURITY: Zone transfer wildcard '*' requires TSIG authentication. \
                 Ensure TSIG is configured for zone transfers."
            );
        }

        Self {
            zones,
            allowed_transfers,
            tsig_verifier,
            allow_wildcard_transfer,
            wildcard_transfer_requires_tsig,
            ixfr_enabled,
            ixfr_fallback_to_axfr,
        }
    }

    fn is_wildcard_allowed(&self) -> bool {
        self.allow_wildcard_transfer
    }

    fn wildcard_requires_tsig(&self) -> bool {
        self.wildcard_transfer_requires_tsig
    }

    pub fn is_transfer_allowed(&self, client_ip: IpAddr, origin: &str) -> bool {
        if self.allowed_transfers.is_empty() {
            return false;
        }

        let mut wildcard_used = false;

        for allowed in &self.allowed_transfers {
            if allowed == "*" {
                wildcard_used = true;
                if !self.is_wildcard_allowed() {
                    tracing::warn!(
                        "Zone transfer wildcard '*' is not allowed. \
                         Set allow_wildcard_transfer: true in dns.settings to enable."
                    );
                    continue;
                }
                return true;
            }
            if let Ok(cidr) = allowed.parse::<ipnetwork::IpNetwork>() {
                if cidr.contains(client_ip) {
                    return true;
                }
            }
            if allowed == origin {
                return true;
            }
        }

        if wildcard_used && self.is_wildcard_allowed() {
            return true;
        }

        false
    }

    pub fn is_wildcard_transfer(&self, _origin: &str) -> bool {
        for allowed in &self.allowed_transfers {
            if allowed == "*" {
                return true;
            }
        }
        false
    }

    pub fn verify_tsig(&self, tsig: &TsigParseResult, message: &[u8]) -> Result<(), String> {
        let verifier = self
            .tsig_verifier
            .as_ref()
            .ok_or_else(|| "TSIG not configured".to_string())?;

        verifier
            .verify(
                &[],
                message,
                &tsig.mac,
                &tsig.key_name,
                tsig.algorithm,
                tsig.time_signed,
                tsig.fudge,
                tsig.tsig_error,
                tsig.other_len,
            )
            .map_err(|e| e.to_string())
    }

    pub fn sign_response(&self, key_name: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        let verifier = self
            .tsig_verifier
            .as_ref()
            .ok_or_else(|| "TSIG not configured".to_string())?;

        verifier
            .sign(key_name, message, 0)
            .map_err(|e| e.to_string())
    }

    fn append_tsig_to_response(
        &self,
        mut response: Vec<u8>,
        key_name: &str,
    ) -> Result<Vec<u8>, String> {
        let signed = self.sign_response(key_name, &response)?;

        if response.len() < 12 {
            return Err("Response too short for TSIG".to_string());
        }

        let arcount = u16::from_be_bytes([response[10], response[11]]);
        let new_arcount = arcount + 1;
        response[10] = (new_arcount >> 8) as u8;
        response[11] = (new_arcount & 0xff) as u8;

        response.extend_from_slice(&signed);

        Ok(response)
    }

    pub fn handle_axfr_request(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
    ) -> Result<Vec<u8>, String> {
        let messages = self.handle_axfr_request_impl(qname, client_ip, tsig)?;

        let mut combined = Vec::new();
        for resp in messages {
            combined.extend_from_slice(&resp);
        }

        Ok(combined)
    }

    pub fn handle_axfr_request_messages(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.handle_axfr_request_impl(qname, client_ip, tsig)
    }

    fn handle_axfr_request_impl(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let origin = qname.trim_end_matches('.');

        if !self.is_transfer_allowed(client_ip, origin) {
            tracing::warn!(
                "SECURITY: AXFR request DENIED for zone={} client={} reason=not_in_allowed_list",
                origin,
                client_ip
            );
            return Err("Zone transfer not allowed".to_string());
        }

        if self.is_wildcard_transfer(origin) && self.wildcard_requires_tsig()
            && tsig.is_none() {
                tracing::warn!(
                    "SECURITY: AXFR request DENIED for zone={} client={} reason=wildcard_requires_tsig",
                    origin,
                    client_ip
                );
                return Err("Zone transfer requires TSIG authentication".to_string());
            }

        let tsig_key_name = tsig.as_ref().map(|t| t.key_name.clone());
        let tsig_configured = self.tsig_verifier.is_some();

        let tsig_status = if tsig.is_some() {
            "TSIG secured"
        } else {
            "unsecured"
        };
        tracing::info!(
            "AXFR request for zone={} from {} ({})",
            origin,
            client_ip,
            tsig_status
        );

        if let Some(tsig) = tsig {
            if let Some(verifier) = &self.tsig_verifier {
                if let Err(e) = verifier.verify(
                    &[],
                    qname.as_bytes(),
                    &tsig.mac,
                    &tsig.key_name,
                    tsig.algorithm,
                    tsig.time_signed,
                    tsig.fudge,
                    tsig.tsig_error,
                    tsig.other_len,
                ) {
                    tracing::warn!(
                        "SECURITY: TSIG verification FAILED for AXFR zone={} client={} error={}",
                        origin,
                        client_ip,
                        e
                    );
                    return Err(format!("TSIG verification failed: {}", e));
                }
            }
        }

        let zones = self.zones.read();
        let zone = zones
            .get(origin)
            .ok_or_else(|| "Zone not found".to_string())?;

        let mut responses = Vec::new();

        let soa_record = self.find_soa_record(zone);
        if let Some(ref soa) = soa_record {
            responses.push(self.build_axfr_first_message(qname, &[soa.clone()]));
        }

        for ((name, record_type), records) in &zone.records {
            if *record_type != RecordType::SOA {
                let full_name = if name == "@" || name.is_empty() {
                    origin.to_string()
                } else {
                    format!("{}.{}", name, origin)
                };
                responses.push(self.build_axfr_record(&full_name, record_type, records));
            }
        }

        if let Some(ref soa) = soa_record {
            responses.push(self.build_axfr_last_message(qname, &[soa.clone()]));
        }

        tracing::info!(
            "AXFR transfer completed for {} to {} ({} messages)",
            origin,
            client_ip,
            responses.len()
        );

        if tsig_configured {
            if let Some(ref key_name) = tsig_key_name {
                let signed_responses = responses
                    .into_iter()
                    .map(|resp| self.append_tsig_to_response(resp, key_name))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(signed_responses)
            } else {
                Ok(responses)
            }
        } else {
            Ok(responses)
        }
    }

    pub fn handle_ixfr_request(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
    ) -> Result<Vec<u8>, String> {
        let messages = self.handle_ixfr_request_impl(qname, client_ip, serial, tsig)?;

        let mut combined = Vec::new();
        for resp in messages {
            combined.extend_from_slice(&resp);
        }

        Ok(combined)
    }

    pub fn handle_ixfr_request_messages(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.handle_ixfr_request_impl(qname, client_ip, serial, tsig)
    }

    fn handle_ixfr_request_impl(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
    ) -> Result<Vec<Vec<u8>>, String> {
        if !self.ixfr_enabled {
            tracing::debug!("IXFR disabled, returning error");
            return Err("IXFR not enabled".to_string());
        }

        let origin = qname.trim_end_matches('.');

        if !self.is_transfer_allowed(client_ip, origin) {
            tracing::warn!(
                "IXFR request denied for {} from {} - not in allowed list",
                origin,
                client_ip
            );
            return Err("Zone transfer not allowed".to_string());
        }

        if self.is_wildcard_transfer(origin) && self.wildcard_requires_tsig()
            && tsig.is_none() {
                tracing::warn!(
                    "IXFR request denied for {} from {} - wildcard requires TSIG",
                    origin,
                    client_ip
                );
                return Err("Zone transfer requires TSIG authentication".to_string());
            }

        let tsig_key_name = tsig.as_ref().map(|t| t.key_name.clone());
        let tsig_configured = self.tsig_verifier.is_some();

        let tsig_status = if tsig.is_some() {
            "TSIG secured"
        } else {
            "unsecured"
        };
        tracing::info!(
            "IXFR request for {} from {} (serial: {:?}) ({})",
            origin,
            client_ip,
            serial,
            tsig_status
        );

        if let Some(tsig) = tsig {
            if let Some(verifier) = &self.tsig_verifier {
                if let Err(e) = verifier.verify(
                    &[],
                    qname.as_bytes(),
                    &tsig.mac,
                    &tsig.key_name,
                    tsig.algorithm,
                    tsig.time_signed,
                    tsig.fudge,
                    tsig.tsig_error,
                    tsig.other_len,
                ) {
                    tracing::warn!("TSIG verification failed for IXFR: {}", e);
                    return Err(format!("TSIG verification failed: {}", e));
                }
            }
        }

        let zones = self.zones.read();
        let zone = zones
            .get(origin)
            .ok_or_else(|| "Zone not found".to_string())?;
        let current_serial = zone.serial;
        let client_serial = serial.unwrap_or(0);

        let responses = if client_serial == current_serial {
            vec![self.build_ixfr_current_response(qname, zone)?]
        } else if client_serial == 0 || client_serial > current_serial {
            if self.ixfr_fallback_to_axfr {
                self.build_ixfr_full_response_messages(qname, zone)?
            } else {
                return Err("IXFR cannot proceed: client has newer serial".to_string());
            }
        } else if let Some(old_version) = zone.get_previous_version(client_serial) {
            self.build_ixfr_incremental_response_messages(qname, zone, &old_version.records)?
        } else if self.ixfr_fallback_to_axfr {
            self.build_ixfr_full_response_messages(qname, zone)?
        } else {
            return Err("IXFR cannot proceed: no history available".to_string());
        };

        tracing::info!(
            "IXFR transfer completed for {} to {} ({} messages)",
            origin,
            client_ip,
            responses.len()
        );

        if tsig_configured {
            if let Some(ref key_name) = tsig_key_name {
                let signed_responses = responses
                    .into_iter()
                    .map(|resp| self.append_tsig_to_response(resp, key_name))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(signed_responses)
            } else {
                Ok(responses)
            }
        } else {
            Ok(responses)
        }
    }

    fn build_ixfr_full_response_messages(
        &self,
        qname: &str,
        zone: &Zone,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut responses = Vec::new();

        let soa_record = self.find_soa_record(zone).ok_or("Zone has no SOA record")?;
        responses.push(self.build_axfr_first_message(qname, &[soa_record.clone()]));

        for ((name, record_type), records) in &zone.records {
            if *record_type != RecordType::SOA {
                let full_name = if name == "@" || name.is_empty() {
                    zone.origin.clone()
                } else {
                    format!("{}.{}", name, zone.origin)
                };
                responses.push(self.build_axfr_record(&full_name, record_type, records));
            }
        }

        responses.push(self.build_axfr_last_message(qname, &[soa_record.clone()]));

        tracing::debug!("IXFR full response: {} messages", responses.len());
        Ok(responses)
    }

    fn build_ixfr_incremental_response_messages(
        &self,
        qname: &str,
        zone: &Zone,
        old_records: &std::collections::HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let current_soa = self
            .find_soa_record(zone)
            .ok_or("Zone has no SOA record")?
            .clone();

        let old_soa = old_records
            .get(&("@".to_string(), RecordType::SOA))
            .and_then(|v| v.first())
            .cloned();

        let mut all_keys = std::collections::HashSet::new();
        for key in old_records.keys() {
            all_keys.insert(key.clone());
        }
        for key in zone.records.keys() {
            all_keys.insert(key.clone());
        }

        let mut to_delete = Vec::new();
        let mut to_add = Vec::new();

        for key in &all_keys {
            let old_recs = old_records.get(key);
            let new_recs = zone.records.get(key);
            match (old_recs, new_recs) {
                (Some(old), None) => to_delete.push((key.clone(), old.clone())),
                (None, Some(new)) => to_add.push((key.clone(), new.clone())),
                (Some(old), Some(new)) => {
                    if old.len() != new.len()
                        || old
                            .iter()
                            .zip(new.iter())
                            .any(|(a, b)| a.value != b.value || a.ttl != b.ttl)
                    {
                        to_delete.push((key.clone(), old.clone()));
                        to_add.push((key.clone(), new.clone()));
                    }
                }
                _ => {}
            }
        }

        let mut responses = Vec::new();

        let first_ancount = (1 + to_delete.len()) as u16;
        responses.push(self.build_ixfr_message(qname, old_soa.as_ref(), &to_delete, first_ancount));

        let second_ancount = (to_add.len() + 1) as u16;
        responses.push(self.build_ixfr_message(qname, Some(&current_soa), &to_add, second_ancount));

        tracing::debug!("IXFR incremental: {} messages", responses.len());
        Ok(responses)
    }

    fn build_ixfr_message(
        &self,
        qname: &str,
        soa: Option<&DnsZoneRecord>,
        records: &[((String, RecordType), Vec<DnsZoneRecord>)],
        ancount: u16,
    ) -> Vec<u8> {
        let mut response = Vec::new();

        let id = super::crypto_rng::random_u16();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8580u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ancount.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        response.extend_from_slice(&wire::encode_name(qname));
        response.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        if let Some(soa_record) = soa {
            response.extend_from_slice(&wire::encode_name(qname));
            response.extend_from_slice(&6u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&soa_record.ttl.to_be_bytes());

            let soa_data = Self::build_soa_rdata(&soa_record.value);
            response.extend_from_slice(&(soa_data.len() as u16).to_be_bytes());
            response.extend_from_slice(&soa_data);
        }

        for ((name, _), recs) in records {
            let full_name = if name == "@" || name.is_empty() {
                qname.to_string()
            } else {
                format!("{}.{}", name, qname)
            };
            for record in recs {
                let rr = self.build_axfr_record(&full_name, &record.record_type, &[record.clone()]);
                response.extend_from_slice(&rr[12..]);
            }
        }

        response
    }

    fn build_ixfr_current_response(&self, qname: &str, zone: &Zone) -> Result<Vec<u8>, String> {
        let soa = self.find_soa_record(zone).ok_or("Zone has no SOA record")?;

        let mut response = Vec::new();
        let id = super::crypto_rng::random_u16();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8580u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        response.extend_from_slice(&wire::encode_name(qname));
        response.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        response.extend_from_slice(&wire::encode_name(qname));
        response.extend_from_slice(&6u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&soa.ttl.to_be_bytes());

        let soa_data = Self::build_soa_rdata(&soa.value);
        response.extend_from_slice(&(soa_data.len() as u16).to_be_bytes());
        response.extend_from_slice(&soa_data);

        tracing::debug!("IXFR sending current SOA for serial {}", zone.serial);

        Ok(response)
    }

    fn build_soa_rdata(soa_value: &str) -> Vec<u8> {
        let parts: Vec<&str> = soa_value.split_whitespace().collect();
        if parts.len() < 7 {
            return Vec::new();
        }

        let mut rdata = Vec::new();

        let mname = parts[0];
        for part in mname.split('.') {
            if !part.is_empty() {
                rdata.push(part.len() as u8);
                rdata.extend_from_slice(part.as_bytes());
            }
        }
        rdata.push(0);

        let rname = parts[1];
        for part in rname.split('.') {
            if !part.is_empty() {
                rdata.push(part.len() as u8);
                rdata.extend_from_slice(part.as_bytes());
            }
        }
        rdata.push(0);

        if let Ok(serial) = parts[2].parse::<u32>() {
            rdata.extend_from_slice(&serial.to_be_bytes());
        } else {
            rdata.extend_from_slice(&1u32.to_be_bytes());
        }

        if let Ok(refresh) = parts[3].parse::<u32>() {
            rdata.extend_from_slice(&refresh.to_be_bytes());
        } else {
            rdata.extend_from_slice(&3600u32.to_be_bytes());
        }

        if let Ok(retry) = parts[4].parse::<u32>() {
            rdata.extend_from_slice(&retry.to_be_bytes());
        } else {
            rdata.extend_from_slice(&600u32.to_be_bytes());
        }

        if let Ok(expire) = parts[5].parse::<u32>() {
            rdata.extend_from_slice(&expire.to_be_bytes());
        } else {
            rdata.extend_from_slice(&86400u32.to_be_bytes());
        }

        if let Ok(minimum) = parts[6].parse::<u32>() {
            rdata.extend_from_slice(&minimum.to_be_bytes());
        } else {
            rdata.extend_from_slice(&3600u32.to_be_bytes());
        }

        rdata
    }

    fn find_soa_record(&self, zone: &Zone) -> Option<DnsZoneRecord> {
        let soa_key = ("@".to_string(), RecordType::SOA);
        zone.records
            .get(&soa_key)
            .and_then(|records| records.first().cloned())
    }

    fn build_axfr_first_message(&self, qname: &str, records: &[DnsZoneRecord]) -> Vec<u8> {
        self.build_axfr_record(qname, &RecordType::SOA, records)
    }

    fn build_axfr_last_message(&self, qname: &str, records: &[DnsZoneRecord]) -> Vec<u8> {
        self.build_axfr_record(qname, &RecordType::SOA, records)
    }

    fn build_axfr_record(
        &self,
        qname: &str,
        record_type: &RecordType,
        records: &[DnsZoneRecord],
    ) -> Vec<u8> {
        let mut response = Vec::new();

        let id = super::crypto_rng::random_u16();
        response.extend_from_slice(&id.to_be_bytes());

        let flags = if record_type == &RecordType::SOA {
            0x8580u16
        } else {
            0x8180u16
        };
        response.extend_from_slice(&flags.to_be_bytes());

        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(records.len() as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        response.extend_from_slice(&wire::encode_name(qname));

        response.extend_from_slice(&record_type.to_u16().to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for record in records {
            response.extend_from_slice(&wire::encode_name(qname));

            response.extend_from_slice(&record.record_type.to_u16().to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl.to_be_bytes());

            match record.record_type {
                RecordType::A => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv4Addr>() {
                        response.extend_from_slice(&2u16.to_be_bytes());
                        response.extend_from_slice(&ip.octets());
                    }
                }
                RecordType::AAAA => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv6Addr>() {
                        response.extend_from_slice(&16u16.to_be_bytes());
                        response.extend_from_slice(&ip.octets());
                    }
                }
                RecordType::CNAME | RecordType::NS | RecordType::SOA => {
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 0;
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                RecordType::TXT => {
                    let txt_len = record.value.len() as u8;
                    response.push(txt_len);
                    response.extend_from_slice(record.value.as_bytes());
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    response.extend_from_slice(&2u16.to_be_bytes());
                    response.extend_from_slice(&priority.to_be_bytes());
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                _ => continue,
            };
        }

        response
    }
}

use std::net::IpAddr;
use std::sync::Arc;

use crate::parsed_query::build_response_flags;
use crate::server::{DnsZoneRecord, RecordType, RecordTypeExt, ShardedZoneStore, Zone};
use crate::tsig::{TsigParseResult, TsigVerifier};
use crate::wire;

pub const AXFR_QUERY_TYPE: u16 = 252;
pub const IXFR_QUERY_TYPE: u16 = 251;

pub struct ZoneTransfer {
    zones: Arc<ShardedZoneStore>,
    allowed_transfers: Vec<String>,
    tsig_verifier: Option<Arc<TsigVerifier>>,
    allow_wildcard_transfer: bool,
    wildcard_transfer_requires_tsig: bool,
    require_tsig: bool,
    ixfr_enabled: bool,
    ixfr_fallback_to_axfr: bool,
}

impl ZoneTransfer {
    pub fn new(
        zones: Arc<ShardedZoneStore>,
        allowed_transfers: Vec<String>,
        tsig_verifier: Option<Arc<TsigVerifier>>,
    ) -> Self {
        Self {
            zones,
            allowed_transfers,
            tsig_verifier,
            allow_wildcard_transfer: false,
            wildcard_transfer_requires_tsig: true,
            require_tsig: true,
            ixfr_enabled: true,
            ixfr_fallback_to_axfr: true,
        }
    }

    pub fn with_security_config(
        zones: Arc<ShardedZoneStore>,
        allowed_transfers: Vec<String>,
        tsig_verifier: Option<Arc<TsigVerifier>>,
        allow_wildcard_transfer: bool,
        wildcard_transfer_requires_tsig: bool,
        ixfr_enabled: bool,
        ixfr_fallback_to_axfr: bool,
        require_tsig: bool,
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
            require_tsig,
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
        message_id: u16,
        message: &[u8],
    ) -> Result<Vec<u8>, String> {
        let messages =
            self.handle_axfr_request_impl(qname, client_ip, tsig, message_id, message)?;

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
        message_id: u16,
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        self.handle_axfr_request_impl(qname, client_ip, tsig, message_id, message)
    }

    fn handle_axfr_request_impl(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
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

        if self.is_wildcard_transfer(origin) && self.wildcard_requires_tsig() && tsig.is_none() {
            tracing::warn!(
                "SECURITY: AXFR request DENIED for zone={} client={} reason=wildcard_requires_tsig",
                origin,
                client_ip
            );
            return Err("Zone transfer requires TSIG authentication".to_string());
        }

        if self.require_tsig && tsig.is_none() {
            tracing::warn!(
                "SECURITY: AXFR request DENIED for zone={} client={} reason=require_tsig",
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
                    message,
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

        let zone = self
            .zones
            .get(origin)
            .ok_or_else(|| "Zone not found".to_string())?;

        let mut responses = Vec::new();

        let soa_record = self.find_soa_record(&zone);
        if let Some(ref soa) = soa_record {
            responses.push(self.build_axfr_first_message(
                qname,
                std::slice::from_ref(soa),
                message_id,
            ));
        }

        for ((name, record_type), records) in &zone.records {
            if *record_type != RecordType::SOA {
                let full_name = if name == "@" || name.is_empty() {
                    origin.to_string()
                } else {
                    format!("{}.{}", name, origin)
                };
                responses.push(self.build_axfr_record(
                    &full_name,
                    record_type,
                    records,
                    message_id,
                ));
            }
        }

        if let Some(ref soa) = soa_record {
            responses.push(self.build_axfr_last_message(
                qname,
                std::slice::from_ref(soa),
                message_id,
            ));
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
        message_id: u16,
        message: &[u8],
    ) -> Result<Vec<u8>, String> {
        let messages =
            self.handle_ixfr_request_impl(qname, client_ip, serial, tsig, message_id, message)?;

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
        message_id: u16,
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        self.handle_ixfr_request_impl(qname, client_ip, serial, tsig, message_id, message)
    }

    fn handle_ixfr_request_impl(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
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

        if self.is_wildcard_transfer(origin) && self.wildcard_requires_tsig() && tsig.is_none() {
            tracing::warn!(
                "IXFR request denied for {} from {} - wildcard requires TSIG",
                origin,
                client_ip
            );
            return Err("Zone transfer requires TSIG authentication".to_string());
        }

        if self.require_tsig && tsig.is_none() {
            tracing::warn!(
                "SECURITY: IXFR request DENIED for zone={} client={} reason=require_tsig",
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
                    message,
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

        let zone = self
            .zones
            .get(origin)
            .ok_or_else(|| "Zone not found".to_string())?;
        let current_serial = zone.serial;
        let client_serial = serial.unwrap_or(0);

        let responses = if client_serial == current_serial {
            vec![self.build_ixfr_current_response(qname, &zone, message_id)?]
        } else if client_serial == 0 || client_serial > current_serial {
            if self.ixfr_fallback_to_axfr {
                self.build_ixfr_full_response_messages(qname, &zone, message_id)?
            } else {
                return Err("IXFR cannot proceed: client has newer serial".to_string());
            }
        } else if let Some(old_version) = zone.get_previous_version(client_serial) {
            self.build_ixfr_incremental_response_messages(
                qname,
                &zone,
                &old_version.records,
                message_id,
            )?
        } else if self.ixfr_fallback_to_axfr {
            self.build_ixfr_full_response_messages(qname, &zone, message_id)?
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
        message_id: u16,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut responses = Vec::new();

        let soa_record = self.find_soa_record(zone).ok_or("Zone has no SOA record")?;
        responses.push(self.build_axfr_first_message(
            qname,
            std::slice::from_ref(&soa_record),
            message_id,
        ));

        for ((name, record_type), records) in &zone.records {
            if *record_type != RecordType::SOA {
                let full_name = if name == "@" || name.is_empty() {
                    zone.origin.clone()
                } else {
                    format!("{}.{}", name, zone.origin)
                };
                responses.push(self.build_axfr_record(
                    &full_name,
                    record_type,
                    records,
                    message_id,
                ));
            }
        }

        responses.push(self.build_axfr_last_message(
            qname,
            std::slice::from_ref(&soa_record),
            message_id,
        ));

        tracing::debug!("IXFR full response: {} messages", responses.len());
        Ok(responses)
    }

    fn build_ixfr_incremental_response_messages(
        &self,
        qname: &str,
        zone: &Zone,
        old_records: &std::collections::HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
        message_id: u16,
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
        responses.push(self.build_ixfr_message(
            qname,
            old_soa.as_ref(),
            &to_delete,
            first_ancount,
            message_id,
        ));

        let second_ancount = (to_add.len() + 1) as u16;
        responses.push(self.build_ixfr_message(
            qname,
            Some(&current_soa),
            &to_add,
            second_ancount,
            message_id,
        ));

        tracing::debug!("IXFR incremental: {} messages", responses.len());
        Ok(responses)
    }

    fn build_ixfr_message(
        &self,
        qname: &str,
        soa: Option<&DnsZoneRecord>,
        records: &[((String, RecordType), Vec<DnsZoneRecord>)],
        ancount: u16,
        message_id: u16,
    ) -> Vec<u8> {
        let mut response = Vec::new();

        response.extend_from_slice(&message_id.to_be_bytes());
        response.extend_from_slice(
            &build_response_flags(true, false, true, false, false, 0).to_be_bytes(),
        );
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
                let rr = self.build_axfr_record(
                    &full_name,
                    &record.record_type,
                    std::slice::from_ref(record),
                    message_id,
                );
                response.extend_from_slice(&rr[12..]);
            }
        }

        response
    }

    fn build_ixfr_current_response(
        &self,
        qname: &str,
        zone: &Zone,
        message_id: u16,
    ) -> Result<Vec<u8>, String> {
        let soa = self.find_soa_record(zone).ok_or("Zone has no SOA record")?;

        let mut response = Vec::new();
        response.extend_from_slice(&message_id.to_be_bytes());
        response.extend_from_slice(
            &build_response_flags(true, false, true, false, false, 0).to_be_bytes(),
        );
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

    fn build_axfr_first_message(
        &self,
        qname: &str,
        records: &[DnsZoneRecord],
        message_id: u16,
    ) -> Vec<u8> {
        self.build_axfr_record(qname, &RecordType::SOA, records, message_id)
    }

    fn build_axfr_last_message(
        &self,
        qname: &str,
        records: &[DnsZoneRecord],
        message_id: u16,
    ) -> Vec<u8> {
        self.build_axfr_record(qname, &RecordType::SOA, records, message_id)
    }

    fn build_axfr_record(
        &self,
        qname: &str,
        record_type: &RecordType,
        records: &[DnsZoneRecord],
        message_id: u16,
    ) -> Vec<u8> {
        let mut response = Vec::new();

        response.extend_from_slice(&message_id.to_be_bytes());

        let flags = if record_type == &RecordType::SOA {
            build_response_flags(true, false, true, false, false, 0)
        } else {
            build_response_flags(false, false, true, false, false, 0)
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
                RecordType::SRV => {
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let priority: u16 = parts[0].parse().unwrap_or(0);
                        let weight: u16 = parts[1].parse().unwrap_or(0);
                        let port: u16 = parts[2].parse().unwrap_or(0);
                        response.extend_from_slice(&6u16.to_be_bytes());
                        response.extend_from_slice(&priority.to_be_bytes());
                        response.extend_from_slice(&weight.to_be_bytes());
                        response.extend_from_slice(&port.to_be_bytes());
                        let target = parts[3];
                        let mut target_parts: Vec<&str> =
                            target.split('.').filter(|s| !s.is_empty()).collect();
                        if target_parts.is_empty() {
                            target_parts.push("");
                        }
                        for part in &target_parts {
                            response.push((*part).len() as u8);
                            response.extend_from_slice(part.as_bytes());
                        }
                    }
                }
                RecordType::PTR => {
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
                RecordType::DNSKEY => {
                    if let Ok(key_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&key_bytes);
                    }
                }
                RecordType::RRSIG => {
                    if let Ok(rrsig_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(rrsig_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig_bytes);
                    }
                }
                RecordType::NSEC => {
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if !parts.is_empty() {
                        let next_domain = parts[0];
                        let mut target_parts: Vec<&str> =
                            next_domain.split('.').filter(|s| !s.is_empty()).collect();
                        if target_parts.is_empty() {
                            target_parts.push("");
                        }
                        let mut _total_len = 0;
                        for part in &target_parts {
                            _total_len += 1 + part.len();
                        }
                        let mut nsec_data = Vec::new();
                        for part in &target_parts {
                            nsec_data.push((*part).len() as u8);
                            nsec_data.extend_from_slice(part.as_bytes());
                        }
                        if parts.len() > 1 {
                            let mut bitmap = Vec::new();
                            let mut current_window = 0u8;
                            let mut block_bits = Vec::new();
                            for type_str in &parts[1..] {
                                let type_val: u16 = match type_str.to_uppercase().as_str() {
                                    "A" => 1,
                                    "AAAA" => 28,
                                    "CNAME" => 5,
                                    "NS" => 2,
                                    "SOA" => 6,
                                    "TXT" => 16,
                                    "MX" => 15,
                                    "SRV" => 33,
                                    "PTR" => 12,
                                    "DNSKEY" => 48,
                                    "RRSIG" => 46,
                                    "NSEC" => 47,
                                    "NSEC3" => 50,
                                    "DS" => 43,
                                    "CAA" => 257,
                                    _ => continue,
                                };
                                let window_byte = (type_val >> 8) as u8;
                                let bitmap_bit = type_val & 0xFF;
                                if window_byte != current_window {
                                    if !block_bits.is_empty() {
                                        bitmap.push(current_window);
                                        bitmap.push(block_bits.len() as u8);
                                        bitmap.extend_from_slice(&block_bits);
                                    }
                                    current_window = window_byte;
                                    block_bits = vec![0u8; (bitmap_bit / 8) as usize + 1];
                                }
                                let byte_idx = (bitmap_bit / 8) as usize;
                                let bit_idx = bitmap_bit % 8;
                                if byte_idx < block_bits.len() {
                                    block_bits[byte_idx] |= 1 << (7 - bit_idx);
                                }
                            }
                            if !block_bits.is_empty() {
                                bitmap.push(current_window);
                                bitmap.push(block_bits.len() as u8);
                                bitmap.extend_from_slice(&block_bits);
                            }
                            nsec_data.extend_from_slice(&bitmap);
                        } else {
                            nsec_data.push(0);
                        }
                        response.extend_from_slice(&(nsec_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&nsec_data);
                    }
                }
                RecordType::NSEC3 => {
                    if let Ok(nsec3_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(nsec3_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&nsec3_bytes);
                    }
                }
                RecordType::DS => {
                    if let Ok(ds_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(ds_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&ds_bytes);
                    }
                }
                RecordType::CAA => {
                    let parts: Vec<&str> = record.value.splitn(3, ' ').collect();
                    let mut data = Vec::new();
                    if parts.len() >= 3 {
                        let flags: u8 = parts[0].parse().unwrap_or(0);
                        let tag = parts[1].as_bytes();
                        let value = parts[2].trim_matches('"').as_bytes();
                        data.push(flags);
                        data.push(tag.len() as u8);
                        data.extend_from_slice(tag);
                        data.extend_from_slice(value);
                    } else {
                        data.push(0);
                        data.push(record.value.len() as u8);
                        data.extend_from_slice(record.value.as_bytes());
                    }
                    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    response.extend_from_slice(&data);
                }
                _ => continue,
            };
        }

        response
    }
}

use super::response_encoder::{
    assemble_packet, build_opt_encoded_record, build_response_flags, encode_rr, DnsSection,
    EncodeReport, ResponseEnvelope, SkippedRecord,
};
use super::*;

impl DnsServer {
    pub(super) fn build_response(
        query_id: u16,
        qname: &str,
        qtype: u16,
        records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&crate::dnssec::ZoneSigningKey>,
        signer_name: &str,
        rd: bool,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let max_size = edns_options
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(512);

        let qname_clean = if qname.is_empty() || qname == "@" {
            String::new()
        } else {
            qname.trim_end_matches('.').to_lowercase()
        };

        let question_name_offset: u16 = 12;

        let mut envelope = ResponseEnvelope::default();
        let mut report = EncodeReport {
            total_records: records.len(),
            encoded_ok: 0,
            skipped: Vec::new(),
        };

        for record in records {
            let compression = if qname_clean.is_empty() {
                None
            } else {
                Some((qname_clean.as_str(), question_name_offset))
            };
            match encode_rr(record, compression) {
                Ok(encoded) => {
                    envelope.answer_records.push(encoded);
                    report.encoded_ok += 1;
                }
                Err(reason) => {
                    tracing::warn!(
                        qname = %record.name,
                        record_type = ?record.record_type,
                        reason = %reason,
                        "DNS encode: record skipped"
                    );
                    report.skipped.push(SkippedRecord {
                        name: record.name.clone(),
                        record_type: record.record_type,
                        reason,
                    });
                }
            }
        }

        if report.all_failed() && !records.is_empty() {
            tracing::error!(
                qname = %qname,
                qtype = %qtype,
                total = %records.len(),
                "DNS encode: ALL records failed encoding for positive answer, returning SERVFAIL"
            );
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let question = super::wire::build_question(qname, qtype, 1);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(&question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        }

        let records_signed = dnssec_ok
            && !records.is_empty()
            && records[0].record_type != RecordType::DNSKEY
            && zsk.is_some();

        if records_signed {
            if let Some(key) = zsk {
                for record in records {
                    let rrsig = Self::create_signed_rrsig(record, signer_name, key);
                    if !rrsig.is_empty() {
                        let rrsig_record = DnsZoneRecord {
                            name: record.name.clone(),
                            record_type: RecordType::RRSIG,
                            value: hex::encode(&rrsig),
                            ttl: record.ttl,
                            priority: None,
                        };
                        let compression = if qname_clean.is_empty() {
                            None
                        } else {
                            Some((qname_clean.as_str(), question_name_offset))
                        };
                        match encode_rr(&rrsig_record, compression) {
                            Ok(encoded) => {
                                envelope.answer_records.push(encoded);
                            }
                            Err(reason) => {
                                tracing::warn!(
                                    qname = %record.name,
                                    record_type = "RRSIG",
                                    reason = %reason,
                                    "DNS encode: RRSIG record skipped"
                                );
                                report.skipped.push(SkippedRecord {
                                    name: record.name.clone(),
                                    record_type: RecordType::RRSIG,
                                    reason,
                                });
                            }
                        }
                    }
                }
            }
        }

        let has_opt = edns_options.is_some() || dnssec_ok;
        if has_opt {
            let udp_size = edns_options.map(|e| e.udp_payload_size).unwrap_or(4096);
            envelope
                .additional_records
                .push(build_opt_encoded_record(udp_size, dnssec_ok));
        }

        let flags = build_response_flags(true, false, rd, false, records_signed, 0);

        let response = assemble_packet(&envelope, query_id, flags, qname, qtype);

        if max_size > 0 && response.len() > max_size {
            return Self::build_truncated_tc_response(query_id, qname, qtype, rd, edns_options);
        }

        (Arc::new(response), report)
    }

    fn build_truncated_tc_response(
        query_id: u16,
        qname: &str,
        qtype: u16,
        rd: bool,
        edns_options: Option<&EdnsOptions>,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let flags = build_response_flags(true, true, rd, false, false, 0);

        let question = super::wire::build_question(qname, qtype, 1);

        let has_opt = edns_options.is_some();
        let arcount: u16 = if has_opt { 1 } else { 0 };

        let mut packet = Vec::with_capacity(12 + question.len() + 16);
        packet.extend_from_slice(&query_id.to_be_bytes());
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&arcount.to_be_bytes());
        packet.extend_from_slice(&question);

        if let Some(edns) = edns_options {
            let opt = build_opt_encoded_record(edns.udp_payload_size, false);
            packet.extend_from_slice(&opt.bytes);
        }

        (Arc::new(packet), EncodeReport::default())
    }

    pub(super) fn build_truncated_response(
        query_id: u16,
        qname: &str,
        qtype: u16,
        _records: &[DnsZoneRecord],
        _dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        _zsk: Option<&crate::dnssec::ZoneSigningKey>,
        _signer_name: &str,
        rd: bool,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        Self::build_truncated_tc_response(query_id, qname, qtype, rd, edns_options)
    }

    pub(crate) fn parse_svcb_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("SVCB value must have priority and target".to_string());
        }

        let priority: u16 = parts[0].parse().map_err(|_| "Invalid SVCB priority")?;
        let target = parts[1];

        let mut result = Vec::new();
        result.extend_from_slice(&priority.to_be_bytes());

        if target.ends_with('.') || target == "." {
            let target_parts: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else if target.is_empty() {
            result.push(0);
        } else {
            let target_parts: Vec<&str> = target.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        if parts.len() > 2 {
            let mut params: Vec<(u16, Vec<u8>)> = Vec::new();

            for param in &parts[2..] {
                if let Some((key, val)) = param.split_once('=') {
                    let svcparam_key = match key {
                        "mandatory" => 0,
                        "alpn" => 1,
                        "no-default-alpn" => 2,
                        "port" => 3,
                        "ipv4hint" => 4,
                        "ech" => 5,
                        "ipv6hint" => 6,
                        "dns" => 7,
                        "nhttp" => 8,
                        _ => continue,
                    };

                    let mut encoded = Vec::new();
                    match svcparam_key {
                        0 => {
                            for m in val.split(',') {
                                let m_trimmed = m.trim();
                                let m_key = match m_trimmed {
                                    "alpn" => 1u16,
                                    "no-default-alpn" => 2,
                                    "port" => 3,
                                    "ipv4hint" => 4,
                                    "ech" => 5,
                                    "ipv6hint" => 6,
                                    "dns" => 7,
                                    "nhttp" => 8,
                                    _ => continue,
                                };
                                encoded.extend_from_slice(&m_key.to_be_bytes());
                            }
                        }
                        1 => {
                            for alpn in val.split(',') {
                                let alpn = alpn.trim();
                                encoded.push(alpn.len() as u8);
                                encoded.extend_from_slice(alpn.as_bytes());
                            }
                        }
                        2 => {}
                        3 => {
                            if let Ok(port) = val.parse::<u16>() {
                                encoded.extend_from_slice(&port.to_be_bytes());
                            }
                        }
                        4 => {
                            for ip in val.split(',') {
                                let ip = ip.trim();
                                if let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() {
                                    encoded.extend_from_slice(&ipv4.octets());
                                }
                            }
                        }
                        5 => {
                            if let Ok(ech) = hex::decode(val) {
                                encoded.extend_from_slice(&ech);
                            }
                        }
                        6 => {
                            for ip in val.split(',') {
                                let ip = ip.trim();
                                if let Ok(ipv6) = ip.parse::<std::net::Ipv6Addr>() {
                                    encoded.extend_from_slice(&ipv6.octets());
                                }
                            }
                        }
                        7 => {
                            if let Ok(port) = val.parse::<u16>() {
                                encoded.extend_from_slice(&port.to_be_bytes());
                            }
                        }
                        8 => {
                            if let Some((ver, rest)) = val.split_once('/') {
                                encoded.extend_from_slice(ver.as_bytes());
                                if let Ok(port) = rest.parse::<u16>() {
                                    encoded.extend_from_slice(&port.to_be_bytes());
                                }
                            }
                        }
                        _ => {
                            encoded.extend_from_slice(val.as_bytes());
                        }
                    }

                    if !encoded.is_empty() {
                        params.push((svcparam_key, encoded));
                    }
                }
            }

            params.sort_by_key(|(key, _)| *key);

            for (key, encoded) in params {
                result.push((key >> 8) as u8);
                result.push((key & 0xFF) as u8);
                result.push((encoded.len() >> 8) as u8);
                result.push((encoded.len() & 0xFF) as u8);
                result.extend_from_slice(&encoded);
            }
        }

        Ok(result)
    }

    pub(super) fn parse_naptr_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 5 {
            return Err("NAPTR value must have at least 5 fields: order preference flags service replacement".to_string());
        }

        let order: u16 = parts[0].parse().map_err(|_| "Invalid NAPTR order")?;
        let preference: u16 = parts[1].parse().map_err(|_| "Invalid NAPTR preference")?;
        let flags = parts[2];
        let service = parts[3];
        let replacement = parts[4];

        let mut result = Vec::new();
        result.extend_from_slice(&order.to_be_bytes());
        result.extend_from_slice(&preference.to_be_bytes());

        result.push(flags.len() as u8);
        result.extend_from_slice(flags.as_bytes());

        result.push(service.len() as u8);
        result.extend_from_slice(service.as_bytes());

        let regex = if parts.len() > 5 { parts[5] } else { "" };
        result.push(regex.len() as u8);
        result.extend_from_slice(regex.as_bytes());

        if replacement.ends_with('.') || replacement == "." {
            let target_parts: Vec<&str> =
                replacement.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        } else if replacement.is_empty() {
            result.push(0);
        } else {
            let target_parts: Vec<&str> =
                replacement.split('.').filter(|s| !s.is_empty()).collect();
            for part in target_parts {
                result.push(part.len() as u8);
                result.extend_from_slice(part.as_bytes());
            }
            result.push(0);
        }

        Ok(result)
    }

    pub(super) fn parse_sshfp_value(value: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(
                "SSHFP value must have at least 2 fields: algorithm fingerprint".to_string(),
            );
        }

        let algorithm: u8 = parts[0].parse().map_err(|_| "Invalid SSHFP algorithm")?;
        let fingerprint_type: u8 = parts[1]
            .parse()
            .map_err(|_| "Invalid SSHFP fingerprint type")?;
        let fingerprint = parts.get(2).unwrap_or(&"");

        if algorithm > 2 {
            return Err("Invalid SSHFP algorithm (must be 0-2)".to_string());
        }
        if fingerprint_type > 2 {
            return Err("Invalid SSHFP fingerprint type (must be 0-2)".to_string());
        }

        let mut result = Vec::new();
        result.push(algorithm);
        result.push(fingerprint_type);

        let fp_bytes = hex::decode(fingerprint.replace(":", "").replace(" ", ""))
            .map_err(|_| "Invalid SSHFP fingerprint (expected hex)")?;
        result.extend_from_slice(&fp_bytes);

        Ok(result)
    }

    #[allow(dead_code)]
    pub(super) fn estimate_record_size(record: &DnsZoneRecord, name_parts: &[&str]) -> usize {
        let name_size = name_parts.iter().map(|p| 1 + p.len()).sum::<usize>() + 1;
        let rdata_size = match record.record_type {
            RecordType::A => 4,
            RecordType::AAAA => 16,
            RecordType::CNAME | RecordType::NS => {
                record
                    .value
                    .split('.')
                    .filter(|s| !s.is_empty())
                    .map(|s| 1 + s.len())
                    .sum::<usize>()
                    + 1
            }
            RecordType::TXT => {
                let len = record.value.len();
                (len / 255) + 1 + len
            }
            RecordType::MX => {
                2 + record
                    .value
                    .split('.')
                    .filter(|s| !s.is_empty())
                    .map(|s| 1 + s.len())
                    .sum::<usize>()
                    + 1
            }
            _ => record.value.len(),
        };
        name_size + 2 + 2 + 4 + 2 + rdata_size
    }

    pub(super) fn build_acme_txt_response(
        query_id: u16,
        qname: &str,
        txt_value: &str,
        edns_options: Option<&EdnsOptions>,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let max_response_size = edns_options
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(512);

        let qname_clean = if qname.is_empty() || qname == "@" {
            String::new()
        } else {
            qname.trim_end_matches('.').to_lowercase()
        };

        let question_name_offset: u16 = 12;

        let mut envelope = ResponseEnvelope::default();
        let mut report = EncodeReport {
            total_records: 1,
            encoded_ok: 0,
            skipped: Vec::new(),
        };

        let acme_record = DnsZoneRecord {
            name: qname.to_string(),
            record_type: RecordType::TXT,
            value: txt_value.to_string(),
            ttl: 300,
            priority: None,
        };
        let compression = if qname_clean.is_empty() {
            None
        } else {
            Some((qname_clean.as_str(), question_name_offset))
        };
        match encode_rr(&acme_record, compression) {
            Ok(encoded) => {
                envelope.answer_records.push(encoded);
                report.encoded_ok += 1;
            }
            Err(reason) => {
                tracing::warn!(
                    qname = %qname,
                    record_type = "TXT",
                    reason = %reason,
                    "DNS encode: ACME TXT record failed"
                );
                report.skipped.push(SkippedRecord {
                    name: qname.to_string(),
                    record_type: RecordType::TXT,
                    reason,
                });
            }
        }

        if let Some(edns) = edns_options {
            envelope
                .additional_records
                .push(build_opt_encoded_record(edns.udp_payload_size, false));
        }

        let flags = build_response_flags(true, false, false, false, false, 0);

        let response = assemble_packet(&envelope, query_id, flags, qname, 16);

        if response.len() > max_response_size && max_response_size > 0 {
            return Self::build_truncated_response(
                query_id,
                qname,
                16,
                &[crate::server::DnsZoneRecord {
                    name: qname.to_string(),
                    record_type: RecordType::TXT,
                    value: txt_value.to_string(),
                    ttl: 300,
                    priority: None,
                }],
                false,
                edns_options,
                None,
                "",
                false,
            );
        }

        (Arc::new(response), report)
    }

    pub(super) fn build_unsigned_nxdomain(
        query_id: u16,
        qname: &str,
        qtype: u16,
        soa: Option<&DnsZoneRecord>,
        edns_options: Option<&EdnsOptions>,
        _negative_cache_ttl: u32,
        rd: bool,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let mut envelope = ResponseEnvelope::default();
        let mut report = EncodeReport::default();

        let mut soa_failed = false;
        if let Some(soa_record) = soa {
            match encode_rr(soa_record, None) {
                Ok(mut rec) => {
                    rec.section = DnsSection::Authority;
                    envelope.authority_records.push(rec);
                }
                Err(reason) => {
                    tracing::error!(
                        qname = %qname,
                        reason = %reason,
                        "DNS encode: SOA record failed for NXDOMAIN response, returning SERVFAIL"
                    );
                    report.skipped.push(SkippedRecord {
                        name: soa_record.name.clone(),
                        record_type: RecordType::SOA,
                        reason,
                    });
                    soa_failed = true;
                }
            }
        }

        if soa_failed {
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let question = super::wire::build_question(qname, qtype, 1);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(&question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        }

        if let Some(edns) = edns_options {
            envelope
                .additional_records
                .push(build_opt_encoded_record(edns.udp_payload_size, false));
        }

        let flags = build_response_flags(true, false, rd, false, false, 3);

        let packet = assemble_packet(&envelope, query_id, flags, qname, qtype);
        (Arc::new(packet), report)
    }

    pub(super) fn build_unsigned_nodata(
        query_id: u16,
        qname: &str,
        qtype: u16,
        soa: Option<&DnsZoneRecord>,
        edns_options: Option<&EdnsOptions>,
        _negative_cache_ttl: u32,
        rd: bool,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let mut envelope = ResponseEnvelope::default();
        let mut report = EncodeReport::default();

        let mut soa_failed = false;
        if let Some(soa_record) = soa {
            match encode_rr(soa_record, None) {
                Ok(mut rec) => {
                    rec.section = DnsSection::Authority;
                    envelope.authority_records.push(rec);
                }
                Err(reason) => {
                    tracing::error!(
                        qname = %qname,
                        reason = %reason,
                        "DNS encode: SOA record failed for NODATA response, returning SERVFAIL"
                    );
                    report.skipped.push(SkippedRecord {
                        name: soa_record.name.clone(),
                        record_type: RecordType::SOA,
                        reason,
                    });
                    soa_failed = true;
                }
            }
        }

        if soa_failed {
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let question = super::wire::build_question(qname, qtype, 1);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(&question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        }

        if let Some(edns) = edns_options {
            envelope
                .additional_records
                .push(build_opt_encoded_record(edns.udp_payload_size, false));
        }

        let flags = build_response_flags(true, false, rd, false, false, 0);

        let packet = assemble_packet(&envelope, query_id, flags, qname, qtype);
        (Arc::new(packet), report)
    }

    pub(super) fn build_refused(
        query_id: u16,
        qname: &str,
        qtype: u16,
        edns_options: Option<&EdnsOptions>,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let mut envelope = ResponseEnvelope::default();

        let flags = build_response_flags(true, false, false, false, false, 5);

        if let Some(edns) = edns_options {
            envelope
                .additional_records
                .push(build_opt_encoded_record(edns.udp_payload_size, false));
        }

        let packet = assemble_packet(&envelope, query_id, flags, qname, qtype);
        (Arc::new(packet), EncodeReport::default())
    }
}

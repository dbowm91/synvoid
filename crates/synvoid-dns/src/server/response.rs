use super::response_encoder::{
    assemble_packet, build_opt_encoded_record, build_response_flags, encode_rr, DnsSection,
    EncodeReport, ResponseEnvelope,
};
use super::*;

impl DnsServer {
    /// Build a positive answer.
    ///
    /// `origin` is the zone origin: it is both the owner origin for the
    /// stored records and the RRSIG signer name. `signing` is `None` for an
    /// unsigned zone; `Some` for a signed one, in which case every RRset is
    /// signed with the key its type requires and **no** RRset is emitted
    /// without its RRSIG — a signing failure answers SERVFAIL instead.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_response(
        query_id: u16,
        qname: &str,
        qtype: u16,
        records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        signing: Option<&ZoneSigningKeys<'_>>,
        origin: &str,
        rd: bool,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
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

        // RFC 4035 §3.1.1: a signed response carries an RRSIG for every RRset
        // it contains, and one RRSIG covers the whole RRset (RFC 4034
        // §3.1.2) — not one signature per record. Signing is all-or-nothing:
        // a failed signature is a SERVFAIL, never an unsigned RRset beside a
        // signed one (L4). The RRSIG is emitted directly after its RRset.
        let mut handled = vec![false; records.len()];
        for i in 0..records.len() {
            if handled[i] {
                continue;
            }
            let owner = records[i].name.clone();
            let record_type = records[i].record_type;
            let members: Vec<usize> = (0..records.len())
                .filter(|&j| {
                    !handled[j] && records[j].name == owner && records[j].record_type == record_type
                })
                .collect();
            for &j in &members {
                handled[j] = true;
            }

            let mut served: Vec<&DnsZoneRecord> = Vec::with_capacity(members.len());
            for &j in &members {
                let record = &records[j];
                let compression = if qname_clean.is_empty() {
                    None
                } else {
                    Some((qname_clean.as_str(), question_name_offset))
                };
                match encode_rr(record, origin, compression) {
                    Ok(encoded) => {
                        envelope.answer_records.push(encoded);
                        report.encoded_ok += 1;
                        served.push(record);
                    }
                    Err(reason) => {
                        tracing::warn!(
                            qname = %record.name,
                            record_type = ?record.record_type,
                            reason = %reason,
                            "DNS encode: record skipped"
                        );
                        report.record_skip(record.name.clone(), record.record_type, reason);
                    }
                }
            }

            let (true, Some(keys)) = (dnssec_ok, signing) else {
                continue;
            };
            if served.is_empty() {
                continue;
            }

            let Ok(rrsig) = Self::create_signed_rrsig(&served, origin, keys) else {
                return Self::servfail_with_opt(query_id, rd, edns_options, question, &report);
            };
            let rrsig_record = DnsZoneRecord {
                name: owner,
                record_type: RecordType::RRSIG,
                value: hex::encode(&rrsig),
                ttl: served[0].ttl,
                priority: None,
            };
            let compression = if qname_clean.is_empty() {
                None
            } else {
                Some((qname_clean.as_str(), question_name_offset))
            };
            match encode_rr(&rrsig_record, origin, compression) {
                Ok(encoded) => {
                    envelope.answer_records.push(encoded);
                }
                Err(reason) => {
                    tracing::error!(
                        qname = %rrsig_record.name,
                        record_type = "RRSIG",
                        reason = %reason,
                        "DNS encode: RRSIG failed; refusing to serve the unsigned RRset"
                    );
                    return Self::servfail_with_opt(query_id, rd, edns_options, question, &report);
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
            return Self::servfail_with_opt(query_id, rd, edns_options, question, &report);
        }

        let has_opt = edns_options.is_some() || dnssec_ok;
        if has_opt {
            let udp_size = edns_options
                .map(|e| e.udp_payload_size)
                .unwrap_or(crate::edns::EDNS_MAX_UDP_PAYLOAD);
            envelope.additional_records.push(build_opt_encoded_record(
                udp_size,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        // Authoritative servers never set AD — AD is a recursive validation signal.
        let flags = build_response_flags(true, false, rd, false, false, 0);

        let response = assemble_packet(&envelope, query_id, flags, question);

        if max_size > 0 && response.len() > max_size {
            return Self::build_truncated_tc_response(
                query_id,
                qname,
                qtype,
                rd,
                edns_options,
                question,
            );
        }

        (Arc::new(response), report)
    }

    /// A SERVFAIL that echoes the question, carrying the client's OPT when it
    /// sent one. Used whenever a response cannot be completed truthfully
    /// (unencodable RRset, dropped RRSIG, missing signing key).
    fn servfail_with_opt(
        query_id: u16,
        rd: bool,
        edns_options: Option<&EdnsOptions>,
        question: &[u8],
        report: &EncodeReport,
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let flags = build_response_flags(true, false, rd, false, false, 2);
        let mut envelope = ResponseEnvelope::default();
        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }
        let packet = assemble_packet(&envelope, query_id, flags, question);
        (Arc::new(packet), report.clone())
    }

    pub(super) fn build_truncated_tc_response(
        query_id: u16,
        _qname: &str,
        _qtype: u16,
        rd: bool,
        edns_options: Option<&EdnsOptions>,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let flags = build_response_flags(true, true, rd, false, false, 0);

        // Assemble through the same envelope as every other response so
        // QDCOUNT always equals the question bytes actually written.
        let mut envelope = ResponseEnvelope::default();
        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let packet = assemble_packet(&envelope, query_id, flags, question);
        (Arc::new(packet), EncodeReport::default())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_truncated_response(
        query_id: u16,
        qname: &str,
        qtype: u16,
        _records: &[DnsZoneRecord],
        _dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        _signing: Option<&ZoneSigningKeys<'_>>,
        _origin: &str,
        rd: bool,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        Self::build_truncated_tc_response(query_id, qname, qtype, rd, edns_options, question)
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
        max_size: usize,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
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
        // The ACME owner is the absolute queried name, not a zone-relative one.
        match encode_rr(&acme_record, "", compression) {
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
                report.record_skip(qname.to_string(), RecordType::TXT, reason);
            }
        }

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let flags = build_response_flags(true, false, false, false, false, 0);

        let response = assemble_packet(&envelope, query_id, flags, question);

        if response.len() > max_size {
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
                question,
            );
        }

        (Arc::new(response), report)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_unsigned_nxdomain(
        query_id: u16,
        qname: &str,
        qtype: u16,
        soa: Option<&DnsZoneRecord>,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        _negative_cache_ttl: u32,
        rd: bool,
        origin: &str,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let mut envelope = ResponseEnvelope::default();
        let mut report = EncodeReport::default();

        // Fail-closed: missing SOA is an internal invariant violation.
        // The zone SOA check in handle_parsed_query should catch this earlier,
        // but we enforce it here as defense-in-depth.
        let Some(soa_record) = soa else {
            tracing::error!(
                qname = %qname,
                "Missing SOA record for NXDOMAIN response (internal invariant violation), returning SERVFAIL"
            );
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(
                    edns.udp_payload_size,
                    edns.dnssec_ok,
                    crate::edns::EXTENDED_RCODE_NONE,
                );
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        };

        let mut soa_failed = false;
        match encode_rr(soa_record, origin, None) {
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
                report.record_skip(soa_record.name.clone(), RecordType::SOA, reason);
                soa_failed = true;
            }
        }

        if soa_failed {
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(
                    edns.udp_payload_size,
                    edns.dnssec_ok,
                    crate::edns::EXTENDED_RCODE_NONE,
                );
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        }

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let flags = build_response_flags(true, false, rd, false, false, 3);

        let packet = assemble_packet(&envelope, query_id, flags, question);
        let packet = Self::fit_to_transport(
            query_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        );
        (packet, report)
    }

    /// Append one answer-section RRset and, for a signed zone, the RRSIG that
    /// covers it — at `signature_owner`, which is **not** always the owner of
    /// the records as served.
    ///
    /// A wildcard expansion answers at the qname while the RRSIG covers the
    /// wildcard owner (RFC 4035 §3.1.3.3); a DNAME answer signs the DNAME RRset
    /// at its own owner (RFC 6672 §5.3.1). Returns `false` when the RRset or
    /// its signature cannot be produced; the caller must then SERVFAIL.
    fn push_signed_answer_rrset(
        envelope: &mut super::response_encoder::ResponseEnvelope,
        rrset: &[&DnsZoneRecord],
        signature_owner: &str,
        origin: &str,
        signing: Option<&ZoneSigningKeys<'_>>,
    ) -> bool {
        let Some(keys) = signing else {
            return true;
        };
        let Some(first) = rrset.first() else {
            return true;
        };
        let Ok(rrsig) = Self::create_signed_rrsig(rrset, origin, keys) else {
            return false;
        };
        let rrsig_record = DnsZoneRecord {
            name: signature_owner.to_string(),
            record_type: RecordType::RRSIG,
            value: hex::encode(&rrsig),
            ttl: first.ttl,
            priority: None,
        };
        match encode_rr(&rrsig_record, origin, None) {
            Ok(mut encoded) => {
                encoded.section = DnsSection::Answer;
                envelope.answer_records.push(encoded);
                true
            }
            Err(reason) => {
                tracing::error!(
                    owner = %signature_owner,
                    reason = %reason,
                    "DNS encode: answer RRSIG failed; refusing to serve the unsigned RRset"
                );
                false
            }
        }
    }

    /// A wildcard answer: the RRset synthesized at the qname, its RRSIG at the
    /// wildcard owner, and the phase-05 next-closer proof (RFC 4035 §3.1.3.3).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_wildcard_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        wildcard: &str,
        records: &[DnsZoneRecord],
        proof: &[Arc<DnsZoneRecord>],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        signing: Option<&ZoneSigningKeys<'_>>,
        origin: &str,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let signing = if dnssec_ok { signing } else { None };
        let qname_clean = qname.trim_end_matches('.').to_lowercase();
        let compression = if qname_clean.is_empty() {
            None
        } else {
            Some((qname_clean.as_str(), 12u16))
        };

        let mut envelope = ResponseEnvelope::default();
        let mut handled = vec![false; records.len()];

        for index in 0..records.len() {
            if handled[index] {
                continue;
            }
            let owner = records[index].name.clone();
            let record_type = records[index].record_type;
            let members: Vec<usize> = (0..records.len())
                .filter(|&candidate| {
                    !handled[candidate]
                        && records[candidate].name == owner
                        && records[candidate].record_type == record_type
                })
                .collect();
            for &member in &members {
                handled[member] = true;
            }

            for &member in &members {
                match encode_rr(&records[member], origin, compression) {
                    Ok(encoded) => {
                        envelope.answer_records.push(encoded);
                    }
                    Err(reason) => {
                        tracing::error!(
                            qname = %qname,
                            reason = %reason,
                            "DNS encode: wildcard answer failed; returning SERVFAIL"
                        );
                        return Self::servfail_packet(response_id, rd, edns_options, question);
                    }
                }
            }

            // The RRSIG covers the wildcard owner, not the synthesized name.
            let wildcard_rrset: Vec<DnsZoneRecord> = members
                .iter()
                .map(|&member| {
                    let mut record = records[member].clone();
                    record.name = wildcard.to_string();
                    record
                })
                .collect();
            let signed: Vec<&DnsZoneRecord> = wildcard_rrset.iter().collect();
            if !Self::push_signed_answer_rrset(&mut envelope, &signed, wildcard, origin, signing) {
                return Self::servfail_packet(response_id, rd, edns_options, question);
            }
        }

        for proof_record in proof {
            if !Self::push_authority_rrset(&mut envelope, proof_record.as_ref(), origin, signing) {
                tracing::error!(
                    qname = %qname,
                    "DNS encode: wildcard proof or its RRSIG failed; returning SERVFAIL"
                );
                return Self::servfail_packet(response_id, rd, edns_options, question);
            }
        }

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        } else if dnssec_ok {
            envelope.additional_records.push(build_opt_encoded_record(
                crate::edns::EDNS_MAX_UDP_PAYLOAD,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let flags = build_response_flags(true, false, rd, false, false, 0);
        let packet = assemble_packet(&envelope, response_id, flags, question);
        Self::fit_to_transport(
            response_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        )
    }

    /// A DNAME answer: the DNAME RRset (signed) and the synthesized CNAME
    /// (never signed, RFC 6672 §5.3.1), in that order.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_dname_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        answer: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        signing: Option<&ZoneSigningKeys<'_>>,
        origin: &str,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let signing = if dnssec_ok { signing } else { None };
        let qname_clean = qname.trim_end_matches('.').to_lowercase();
        let compression = if qname_clean.is_empty() {
            None
        } else {
            Some((qname_clean.as_str(), 12u16))
        };

        let mut envelope = ResponseEnvelope::default();

        let dname: Vec<&DnsZoneRecord> = answer
            .iter()
            .filter(|record| record.record_type == RecordType::DNAME)
            .collect();
        for record in &dname {
            match encode_rr(record, origin, compression) {
                Ok(encoded) => envelope.answer_records.push(encoded),
                Err(reason) => {
                    tracing::error!(
                        qname = %qname,
                        reason = %reason,
                        "DNS encode: DNAME failed; returning SERVFAIL"
                    );
                    return Self::servfail_packet(response_id, rd, edns_options, question);
                }
            }
        }
        let dname_owner = dname
            .first()
            .map(|record| record.name.as_str())
            .unwrap_or(qname);
        if !Self::push_signed_answer_rrset(&mut envelope, &dname, dname_owner, origin, signing) {
            return Self::servfail_packet(response_id, rd, edns_options, question);
        }

        for cname in answer
            .iter()
            .filter(|record| record.record_type == RecordType::CNAME)
        {
            match encode_rr(cname, origin, compression) {
                Ok(encoded) => envelope.answer_records.push(encoded),
                Err(reason) => {
                    tracing::error!(
                        qname = %qname,
                        reason = %reason,
                        "DNS encode: synthesized CNAME failed; returning SERVFAIL"
                    );
                    return Self::servfail_packet(response_id, rd, edns_options, question);
                }
            }
        }

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        } else if dnssec_ok {
            envelope.additional_records.push(build_opt_encoded_record(
                crate::edns::EDNS_MAX_UDP_PAYLOAD,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let flags = build_response_flags(true, false, rd, false, false, 0);
        let packet = assemble_packet(&envelope, response_id, flags, question);
        Self::fit_to_transport(
            response_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        )
    }

    /// A referral: AA=0, the delegation NS RRset in authority, in-bailiwick
    /// glue in additional, and — for a signed zone — the DS RRset when the
    /// delegation is secure, or the phase-05 no-DS proof when it is not
    /// (RFC 4035 §3.1.4.1).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_referral_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        authority: &[DnsZoneRecord],
        additional: &[DnsZoneRecord],
        proof: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        signing: Option<&ZoneSigningKeys<'_>>,
        origin: &str,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let signing = if dnssec_ok { signing } else { None };
        let mut envelope = ResponseEnvelope::default();

        for record in authority {
            if !Self::push_authority_rrset(&mut envelope, record, origin, signing) {
                tracing::error!(
                    qname = %qname,
                    "DNS encode: referral NS or its RRSIG failed; returning SERVFAIL"
                );
                return Self::servfail_packet(response_id, rd, edns_options, question);
            }
        }
        for proof_record in proof {
            if !Self::push_authority_rrset(&mut envelope, proof_record, origin, signing) {
                tracing::error!(
                    qname = %qname,
                    "DNS encode: referral delegation proof failed; returning SERVFAIL"
                );
                return Self::servfail_packet(response_id, rd, edns_options, question);
            }
        }

        // Glue is advisory: a record that cannot be encoded is dropped, never
        // turned into a SERVFAIL for a referral that is otherwise complete.
        for record in additional {
            match encode_rr(record, origin, None) {
                Ok(mut encoded) => {
                    encoded.section = DnsSection::Additional;
                    envelope.additional_records.push(encoded);
                }
                Err(reason) => tracing::warn!(
                    owner = %record.name,
                    reason = %reason,
                    "DNS encode: referral glue skipped"
                ),
            }
        }

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        // A referral is not authoritative data: AA=0.
        let flags = build_response_flags(false, false, rd, false, false, 0);
        let packet = assemble_packet(&envelope, response_id, flags, question);
        Self::fit_to_transport(
            response_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        )
    }

    /// An empty response carrying `rcode` (used for YXDOMAIN when a DNAME
    /// substitution would overflow the legal name length, RFC 6672 §3.2).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_rcode_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        rcode: u8,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let mut envelope = ResponseEnvelope::default();
        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }
        let flags = build_response_flags(true, false, rd, false, false, rcode);
        let packet = assemble_packet(&envelope, response_id, flags, question);
        Self::fit_to_transport(
            response_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_unsigned_nodata(
        query_id: u16,
        qname: &str,
        qtype: u16,
        soa: Option<&DnsZoneRecord>,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        _negative_cache_ttl: u32,
        rd: bool,
        origin: &str,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let mut envelope = ResponseEnvelope::default();
        let mut report = EncodeReport::default();

        // Fail-closed: missing SOA is an internal invariant violation.
        // The zone SOA check in handle_parsed_query should catch this earlier,
        // but we enforce it here as defense-in-depth.
        let Some(soa_record) = soa else {
            tracing::error!(
                qname = %qname,
                "Missing SOA record for NODATA response (internal invariant violation), returning SERVFAIL"
            );
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(
                    edns.udp_payload_size,
                    edns.dnssec_ok,
                    crate::edns::EXTENDED_RCODE_NONE,
                );
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        };

        let mut soa_failed = false;
        match encode_rr(soa_record, origin, None) {
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
                report.record_skip(soa_record.name.clone(), RecordType::SOA, reason);
                soa_failed = true;
            }
        }

        if soa_failed {
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&query_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(
                    edns.udp_payload_size,
                    edns.dnssec_ok,
                    crate::edns::EXTENDED_RCODE_NONE,
                );
                packet.extend_from_slice(&opt.bytes);
            }
            return (Arc::new(packet), report);
        }

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let flags = build_response_flags(true, false, rd, false, false, 0);

        let packet = assemble_packet(&envelope, query_id, flags, question);
        let packet = Self::fit_to_transport(
            query_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        );
        (packet, report)
    }

    pub(super) fn build_refused(
        query_id: u16,
        _qname: &str,
        _qtype: u16,
        edns_options: Option<&EdnsOptions>,
        question: &[u8],
    ) -> (Arc<Vec<u8>>, EncodeReport) {
        let mut envelope = ResponseEnvelope::default();

        let flags = build_response_flags(true, false, false, false, false, 5);

        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        let packet = assemble_packet(&envelope, query_id, flags, question);
        (Arc::new(packet), EncodeReport::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The question section a client for `name`/`qtype` would have sent.
    fn question(name: &str, qtype: u16) -> Vec<u8> {
        crate::wire::build_question(name, qtype, 1)
    }

    fn make_record(name: &str, rt: RecordType, value: &str, ttl: u32) -> DnsZoneRecord {
        DnsZoneRecord {
            name: name.to_string(),
            record_type: rt,
            value: value.to_string(),
            ttl,
            priority: None,
        }
    }

    #[test]
    fn tc_oversized_no_edns_returns_tc_within_512() {
        let mut records = Vec::new();
        for i in 0..50 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(20),
                300,
            ));
        }

        let (resp, _report) = DnsServer::build_response(
            0xABCD,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 16),
        );

        assert!(
            resp.len() <= 512,
            "TC response must fit in 512, got {}",
            resp.len()
        );
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & 0x0200, 0, "TC bit must be set");
        let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        let nscount = u16::from_be_bytes([resp[8], resp[9]]);
        let arcount = u16::from_be_bytes([resp[10], resp[11]]);
        assert_eq!(qdcount, 1, "QDCOUNT must be 1");
        assert_eq!(ancount, 0, "ANCOUNT must be 0 in TC response");
        assert_eq!(nscount, 0, "NSCOUNT must be 0 in TC response");
        assert_eq!(arcount, 0, "ARCOUNT must be 0 without EDNS");
    }

    #[test]
    fn nxdomain_and_nodata_authoritative_responses_respect_udp_limit() {
        // Regression guard: the DNSSEC-bearing NXDOMAIN / NODATA builders
        // assemble their own packets and previously emitted them unbounded, so
        // an NSEC-heavy zone could send a >512-byte datagram with TC=0.
        let mut nsec: Vec<Arc<DnsZoneRecord>> = Vec::new();
        for i in 0..40 {
            // TXT encodes cleanly; NSEC rdata needs a real bitmap and is
            // silently skipped by `encode_rr`, which would make this vacuous.
            nsec.push(Arc::new(make_record(
                &format!("n{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(60),
                300,
            )));
        }
        let soa = make_record(
            "example.com",
            RecordType::SOA,
            "ns.example.com hostmaster.example.com 1 3600 600 86400 60",
            300,
        );

        for qtype in [1u16, 6, 15, 28] {
            let nx = DnsServer::build_nxdomain_response(
                0x4242,
                "absent.example.com",
                qtype,
                &nsec,
                false,
                None,
                512,
                None,
                "example.com",
                Some(&soa),
                false,
                &question("absent.example.com", qtype),
            );
            assert!(
                nx.len() <= 512,
                "NXDOMAIN must fit 512 without EDNS, got {}",
                nx.len()
            );
            assert_eq!(
                u16::from_be_bytes([nx[0], nx[1]]),
                0x4242,
                "TC fallback must echo the query id"
            );

            let nodata = DnsServer::build_nodata_response(
                0x4343,
                "nokey.example.com",
                qtype,
                &nsec,
                false,
                None,
                512,
                None,
                "example.com",
                Some(&soa),
                false,
                &question("nokey.example.com", qtype),
            );
            assert!(
                nodata.len() <= 512,
                "NODATA must fit 512 without EDNS, got {}",
                nodata.len()
            );
            assert_eq!(u16::from_be_bytes([nodata[0], nodata[1]]), 0x4343);
        }
    }

    #[test]
    fn tc_oversized_exceeding_edns_4096_returns_tc_with_opt() {
        let mut records = Vec::new();
        for i in 0..200 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(100),
                300,
            ));
        }

        let edns = EdnsOptions {
            udp_payload_size: 4096,
            dnssec_ok: false,
            ..Default::default()
        };

        let (resp, _report) = DnsServer::build_response(
            0x1234,
            "example.com",
            16,
            &records,
            false,
            Some(&edns),
            4096,
            None,
            "",
            true,
            &question("example.com", 16),
        );

        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(
            flags & 0x0200,
            0,
            "TC bit must be set when response exceeds EDNS buffer"
        );
        assert!(
            resp.len() <= 4096,
            "TC response must fit in EDNS buffer, got {}",
            resp.len()
        );
        let arcount = u16::from_be_bytes([resp[10], resp[11]]);
        assert_eq!(arcount, 1, "ARCOUNT must be 1 (OPT) with EDNS");
    }

    #[test]
    fn tc_response_preserves_query_id() {
        let mut records = Vec::new();
        for i in 0..50 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(20),
                300,
            ));
        }

        let (resp, _) = DnsServer::build_response(
            0xDEAD,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 16),
        );

        let id = u16::from_be_bytes([resp[0], resp[1]]);
        assert_eq!(id, 0xDEAD, "Query ID must be preserved in TC response");
    }

    #[test]
    fn tc_response_preserves_rd_flag() {
        let mut records = Vec::new();
        for i in 0..50 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(20),
                300,
            ));
        }

        // rd=true
        let (resp_rd, _) = DnsServer::build_response(
            0x1111,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 16),
        );
        let flags_rd = u16::from_be_bytes([resp_rd[2], resp_rd[3]]);
        assert_ne!(
            flags_rd & 0x0100,
            0,
            "RD bit must be set when query has RD=true"
        );

        // rd=false
        let (resp_nord, _) = DnsServer::build_response(
            0x2222,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            false,
            &question("example.com", 16),
        );
        let flags_nord = u16::from_be_bytes([resp_nord[2], resp_nord[3]]);
        assert_eq!(
            flags_nord & 0x0100,
            0,
            "RD bit must not be set when query has RD=false"
        );
    }

    #[test]
    fn tc_response_sets_aa_and_no_ra() {
        let mut records = Vec::new();
        for i in 0..50 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(20),
                300,
            ));
        }

        let (resp, _) = DnsServer::build_response(
            0x3333,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 16),
        );
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & 0x0400, 0, "AA bit must be set (authoritative)");
        assert_eq!(flags & 0x0080, 0, "RA bit must not be set (authoritative)");
    }

    #[test]
    fn tc_response_rcode_zero() {
        let mut records = Vec::new();
        for i in 0..50 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(20),
                300,
            ));
        }

        let (resp, _) = DnsServer::build_response(
            0x4444,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 16),
        );
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        let rcode = (flags & 0x000F) as u8;
        assert_eq!(rcode, 0, "RCODE must be 0 (NOERROR) for TC response");
    }

    // ── SOA fail-closed tests ──────────────────────────────────────────

    #[test]
    fn unsigned_nodata_no_soa_returns_servfail() {
        let (resp, _report) = DnsServer::build_unsigned_nodata(
            0x50A1,
            "www.example.com",
            15,   // MX
            None, // no SOA
            None,
            512,
            300,
            true,
            "example.com",
            &question("www.example.com", 15),
        );

        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        let rcode = (flags & 0x000F) as u8;
        assert_eq!(rcode, 2, "RCODE must be SERVFAIL (2) when SOA is None");
        assert_ne!(flags & 0x0400, 0, "AA bit must be set");
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "ANCOUNT must be 0"
        );
    }

    #[test]
    fn unsigned_nxdomain_no_soa_returns_servfail() {
        let (resp, _report) = DnsServer::build_unsigned_nxdomain(
            0x50A2,
            "nonexistent.example.com",
            1,    // A
            None, // no SOA
            None,
            512,
            300,
            true,
            "example.com",
            &question("nonexistent.example.com", 1),
        );

        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        let rcode = (flags & 0x000F) as u8;
        assert_eq!(rcode, 2, "RCODE must be SERVFAIL (2) when SOA is None");
        assert_ne!(flags & 0x0400, 0, "AA bit must be set");
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "ANCOUNT must be 0"
        );
    }

    #[test]
    fn tc_acme_txt_response_rd_echoed() {
        let mut records = Vec::new();
        for i in 0..30 {
            records.push(make_record(
                &format!("_acme-challenge.host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(30),
                300,
            ));
        }

        let (resp, _) = DnsServer::build_response(
            0x5555,
            "_acme-challenge.example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("_acme-challenge.example.com", 16),
        );

        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(
            flags & 0x0200,
            0,
            "TC bit must be set for oversized ACME response"
        );
        assert_ne!(flags & 0x0100, 0, "RD must be echoed in TC ACME response");
    }

    #[test]
    fn non_oversized_no_edns_fits_512() {
        let records = vec![make_record(
            "www.example.com",
            RecordType::A,
            "192.0.2.10",
            300,
        )];

        let (resp, report) = DnsServer::build_response(
            0x6666,
            "example.com",
            1,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 1),
        );

        assert!(
            resp.len() <= 512,
            "Small response must fit in 512, got {}",
            resp.len()
        );
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(
            flags & 0x0200,
            0,
            "TC bit must NOT be set for small response"
        );
        assert_eq!(report.encoded_ok, 1, "One record must be encoded");
    }

    #[test]
    fn non_oversized_with_edns_4096_no_truncation() {
        let mut records = Vec::new();
        for i in 0..10 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(50),
                300,
            ));
        }

        let edns = EdnsOptions {
            udp_payload_size: 4096,
            dnssec_ok: false,
            ..Default::default()
        };

        let (resp, report) = DnsServer::build_response(
            0x7777,
            "example.com",
            16,
            &records,
            false,
            Some(&edns),
            4096,
            None,
            "",
            true,
            &question("example.com", 16),
        );

        // Should be > 512 but <= 4096, with no TC
        assert!(
            resp.len() > 512,
            "Response with 10 TXT should exceed 512, got {}",
            resp.len()
        );
        assert!(
            resp.len() <= 4096,
            "Response must fit in EDNS 4096, got {}",
            resp.len()
        );
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(
            flags & 0x0200,
            0,
            "TC bit must NOT be set when response fits EDNS buffer"
        );
        assert_eq!(report.encoded_ok, 10, "All 10 records must be encoded");
    }

    #[test]
    fn tc_response_has_question_section() {
        let mut records = Vec::new();
        for i in 0..50 {
            records.push(make_record(
                &format!("host{}.example.com", i),
                RecordType::TXT,
                &"x".repeat(20),
                300,
            ));
        }

        let (resp, _) = DnsServer::build_response(
            0x8888,
            "example.com",
            16,
            &records,
            false,
            None,
            512,
            None,
            "",
            true,
            &question("example.com", 16),
        );

        // 12-byte header + question section (QNAME + QTYPE(2) + QCLASS(2))
        // Minimal question is 5 bytes (root label + qtype + qclass)
        assert!(
            resp.len() > 12 + 4,
            "Response must contain question section after header"
        );
    }
}

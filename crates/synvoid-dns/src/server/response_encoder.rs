use super::*;
use crate::parsed_query::build_response_flags as canonical_build_response_flags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsSection {
    Answer,
    #[allow(dead_code)]
    Authority,
    Additional,
}

#[derive(Debug, Clone)]
pub(super) struct EncodedRecord {
    #[allow(dead_code)]
    pub section: DnsSection,
    #[allow(dead_code)]
    pub record_type: RecordType,
    #[allow(dead_code)]
    pub ttl: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct ResponseEnvelope {
    pub answer_records: Vec<EncodedRecord>,
    pub authority_records: Vec<EncodedRecord>,
    pub additional_records: Vec<EncodedRecord>,
}

pub(super) fn build_response_flags(
    auth: bool,
    trunc: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authentic_data: bool,
    rcode: u8,
) -> u16 {
    canonical_build_response_flags(
        auth,
        trunc,
        recursion_desired,
        recursion_available,
        authentic_data,
        rcode,
    )
}

pub(super) fn encode_rr(
    record: &DnsZoneRecord,
    qname_compressed: Option<(&str, u16)>,
) -> Result<EncodedRecord, String> {
    let name_bytes = if let Some((qname, offset)) = qname_compressed {
        let record_name = if record.name == "@" || record.name.is_empty() {
            qname
        } else {
            &record.name
        };
        if !qname.is_empty() && record_name.to_lowercase() == qname.to_lowercase() {
            vec![0xC0 | (offset >> 8) as u8, (offset & 0xFF) as u8]
        } else {
            super::wire::encode_name(record_name)
        }
    } else {
        super::wire::encode_name(&record.name)
    };

    let rdata = match record.record_type {
        RecordType::A => {
            let ip: std::net::Ipv4Addr =
                record.value.parse().map_err(|_| "Invalid A record value")?;
            ip.octets().to_vec()
        }
        RecordType::AAAA => {
            let ip: std::net::Ipv6Addr = record
                .value
                .parse()
                .map_err(|_| "Invalid AAAA record value")?;
            ip.octets().to_vec()
        }
        RecordType::CNAME | RecordType::NS => {
            let mut parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                parts.push("");
            }
            let mut encoded = Vec::new();
            for part in &parts {
                encoded.push(part.len() as u8);
                encoded.extend_from_slice(part.as_bytes());
            }
            encoded.push(0);
            encoded
        }
        RecordType::TXT => {
            let mut txt_data = Vec::new();
            let txt_bytes = record.value.as_bytes();
            if txt_bytes.is_empty() {
                txt_data.push(0);
            } else {
                let mut offset = 0;
                while offset < txt_bytes.len() {
                    let remaining = txt_bytes.len() - offset;
                    let chunk_len = std::cmp::min(remaining, 255);
                    txt_data.push(chunk_len as u8);
                    txt_data.extend_from_slice(&txt_bytes[offset..offset + chunk_len]);
                    offset += chunk_len;
                }
            }
            txt_data
        }
        RecordType::MX => {
            let priority = record.priority.unwrap_or(10) as u16;
            let mut mx_data = Vec::new();
            mx_data.extend_from_slice(&priority.to_be_bytes());
            let mut parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                parts.push("");
            }
            for part in &parts {
                mx_data.push(part.len() as u8);
                mx_data.extend_from_slice(part.as_bytes());
            }
            mx_data.push(0);
            mx_data
        }
        RecordType::SOA => {
            let parts: Vec<&str> = record.value.split_whitespace().collect();
            if parts.len() < 7 {
                return Err(
                    "SOA record requires 7 fields: mname rname serial refresh retry expire minimum"
                        .to_string(),
                );
            }
            let serial: u32 = parts[2].parse().map_err(|_| "Invalid SOA serial")?;
            let refresh: u32 = parts[3].parse().map_err(|_| "Invalid SOA refresh")?;
            let retry: u32 = parts[4].parse().map_err(|_| "Invalid SOA retry")?;
            let expire: u32 = parts[5].parse().map_err(|_| "Invalid SOA expire")?;
            let minimum: u32 = parts[6].parse().map_err(|_| "Invalid SOA minimum")?;
            let mut soa_data = Vec::new();
            soa_data.extend_from_slice(&super::wire::encode_name(parts[0]));
            soa_data.extend_from_slice(&super::wire::encode_name(parts[1]));
            soa_data.extend_from_slice(&serial.to_be_bytes());
            soa_data.extend_from_slice(&refresh.to_be_bytes());
            soa_data.extend_from_slice(&retry.to_be_bytes());
            soa_data.extend_from_slice(&expire.to_be_bytes());
            soa_data.extend_from_slice(&minimum.to_be_bytes());
            soa_data
        }
        RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM => hex::decode(&record.value)
            .map_err(|_| format!("Invalid {} hex value", u16::from(record.record_type)))?,
        RecordType::DNSKEY => {
            let key_bytes = hex::decode(&record.value).map_err(|_| "Invalid DNSKEY hex value")?;
            compute_dnskey(&crate::dnssec::ZoneSigningKey {
                key_id: String::new(),
                algorithm: Algorithm::Ed25519,
                key_type: crate::dnssec::KeyType::KSK,
                created_at: 0,
                expires_at: 0,
                public_key: key_bytes,
                private_key: Vec::new(),
                key_tag: 0,
                flags: 257,
                key_size: None,
            })
        }
        RecordType::DS => hex::decode(&record.value).map_err(|_| "Invalid DS hex value")?,
        RecordType::PTR => {
            let mut parts: Vec<&str> = record.value.split('.').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                parts.push("");
            }
            let mut ptr_data = Vec::new();
            for part in &parts {
                ptr_data.push(part.len() as u8);
                ptr_data.extend_from_slice(part.as_bytes());
            }
            ptr_data.push(0);
            ptr_data
        }
        RecordType::CAA => {
            let mut data = Vec::new();
            let parts: Vec<&str> = record.value.splitn(3, ' ').collect();
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
            data
        }
        RecordType::TLSA => {
            let mut data = Vec::new();
            let parts: Vec<&str> = record.value.splitn(4, ' ').collect();
            if parts.len() >= 4 {
                let usage: u8 = parts[0].parse().unwrap_or(0);
                let selector: u8 = parts[1].parse().unwrap_or(0);
                let matching_type: u8 = parts[2].parse().unwrap_or(0);
                let cert_data =
                    hex::decode(parts[3]).unwrap_or_else(|_| parts[3].as_bytes().to_vec());
                data.push(usage);
                data.push(selector);
                data.push(matching_type);
                data.extend_from_slice(&cert_data);
            } else {
                data.extend_from_slice(record.value.as_bytes());
            }
            data
        }
        RecordType::SVCB | RecordType::HTTPS => DnsServer::parse_svcb_value(&record.value)?,
        RecordType::NAPTR => DnsServer::parse_naptr_value(&record.value)?,
        RecordType::SSHFP => DnsServer::parse_sshfp_value(&record.value)?,
        RecordType::RRSIG => hex::decode(&record.value).map_err(|_| "Invalid RRSIG hex value")?,
        _ => {
            return Err("unsupported record type".to_string());
        }
    };

    let mut bytes = Vec::with_capacity(name_bytes.len() + 10 + rdata.len());
    bytes.extend_from_slice(&name_bytes);
    bytes.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&record.ttl.to_be_bytes());
    bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&rdata);

    Ok(EncodedRecord {
        section: DnsSection::Answer,
        record_type: record.record_type,
        ttl: record.ttl,
        bytes,
    })
}

pub(super) fn assemble_packet(
    envelope: &ResponseEnvelope,
    query_id: u16,
    flags: u16,
    qname: &str,
    qtype: u16,
) -> Vec<u8> {
    let answer_size: usize = envelope.answer_records.iter().map(|r| r.bytes.len()).sum();
    let authority_size: usize = envelope
        .authority_records
        .iter()
        .map(|r| r.bytes.len())
        .sum();
    let additional_size: usize = envelope
        .additional_records
        .iter()
        .map(|r| r.bytes.len())
        .sum();

    let mut packet = Vec::with_capacity(12 + 64 + answer_size + authority_size + additional_size);

    packet.extend_from_slice(&query_id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&(envelope.answer_records.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(envelope.authority_records.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(envelope.additional_records.len() as u16).to_be_bytes());

    let question = super::wire::build_question(qname, qtype, 1);
    packet.extend_from_slice(&question);

    for record in &envelope.answer_records {
        packet.extend_from_slice(&record.bytes);
    }
    for record in &envelope.authority_records {
        packet.extend_from_slice(&record.bytes);
    }
    for record in &envelope.additional_records {
        packet.extend_from_slice(&record.bytes);
    }

    packet
}

pub(super) fn truncate_to_fit(envelope: &mut ResponseEnvelope, max_size: usize) {
    let authority_size: usize = envelope
        .authority_records
        .iter()
        .map(|r| r.bytes.len())
        .sum();
    let additional_size: usize = envelope
        .additional_records
        .iter()
        .map(|r| r.bytes.len())
        .sum();
    let base_size = 12 + 32 + authority_size + additional_size;

    let mut current_size = base_size;
    let mut keep = 0;
    for record in &envelope.answer_records {
        if current_size + record.bytes.len() > max_size {
            break;
        }
        current_size += record.bytes.len();
        keep += 1;
    }

    envelope.answer_records.truncate(keep);
}

pub(super) fn build_opt_encoded_record(udp_payload_size: u16, dnssec_ok: bool) -> EncodedRecord {
    let opt_rdata = crate::edns::EdnsOptions::build_opt_record(udp_payload_size, dnssec_ok);

    let mut bytes = Vec::with_capacity(1 + 2 + 2 + opt_rdata.len());
    bytes.push(0x00);
    bytes.extend_from_slice(&41u16.to_be_bytes());
    bytes.extend_from_slice(&(opt_rdata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&opt_rdata);

    EncodedRecord {
        section: DnsSection::Additional,
        record_type: RecordType::OPT,
        ttl: 0,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsed_query::build_response_flags as canonical_build_response_flags;

    fn make_record(name: &str, rt: RecordType, value: &str, ttl: u32) -> DnsZoneRecord {
        DnsZoneRecord {
            name: name.to_string(),
            record_type: rt,
            value: value.to_string(),
            ttl,
            priority: None,
        }
    }

    fn make_record_with_priority(
        name: &str,
        rt: RecordType,
        value: &str,
        ttl: u32,
        pri: u32,
    ) -> DnsZoneRecord {
        DnsZoneRecord {
            name: name.to_string(),
            record_type: rt,
            value: value.to_string(),
            ttl,
            priority: Some(pri),
        }
    }

    /// Parse RR bytes to find rdata_start offset and rdlength.
    /// Returns (type, class, ttl, rdlength, rdata_start).
    fn parse_rr(bytes: &[u8]) -> (u16, u16, u32, usize, usize) {
        let mut pos = 0;
        while pos < bytes.len() {
            let len = bytes[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        let rr_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let rr_class = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
        let rr_ttl = u32::from_be_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        (rr_type, rr_class, rr_ttl, rdlength, rdata_start)
    }

    #[test]
    fn test_flags_basic_response() {
        let flags = build_response_flags(true, false, true, true, false, 0);
        assert_eq!(flags & 0x8000, 0x8000, "QR bit must be set");
        assert_eq!(flags & 0x0400, 0x0400, "AA bit must be set");
        assert_eq!(flags & 0x0200, 0, "TC bit must not be set");
        assert_eq!(flags & 0x0100, 0x0100, "RD bit must be set");
        assert_eq!(flags & 0x0080, 0x0080, "RA bit must be set");
        assert_eq!(flags & 0x0020, 0, "AD bit must not be set");
        assert_eq!(flags & 0x000F, 0, "RCODE must be 0");
    }

    #[test]
    fn test_flags_truncated_response() {
        let flags = build_response_flags(true, true, true, true, false, 0);
        assert_ne!(flags & 0x0200, 0, "TC bit must be set");
    }

    #[test]
    fn test_flags_ad_bit() {
        let flags = build_response_flags(true, false, true, true, true, 0);
        assert_ne!(flags & 0x0020, 0, "AD bit must be set");
    }

    #[test]
    fn test_flags_rcode_nxdomain() {
        let flags = build_response_flags(true, false, true, true, false, 3);
        assert_eq!(flags & 0x000F, 3, "RCODE must be 3 (NXDOMAIN)");
    }

    #[test]
    fn test_flags_rcode_servfail() {
        let flags = build_response_flags(true, false, true, true, false, 2);
        assert_eq!(flags & 0x000F, 2, "RCODE must be 2 (SERVFAIL)");
    }

    #[test]
    fn test_encode_rr_a_record() {
        let record = make_record("www.example.com", RecordType::A, "93.184.216.34", 300);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::A);
        assert_eq!(encoded.ttl, 300);

        let (_, rr_class, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        assert_eq!(rr_class, 1, "Class must be IN");
        assert_eq!(rdlength, 4, "A record RDLENGTH must be 4");
        let rdata = &encoded.bytes[rdata_start..rdata_start + 4];
        assert_eq!(rdata, &[93, 184, 216, 34]);
    }

    #[test]
    fn test_encode_rr_a_record_invalid() {
        let record = make_record("www.example.com", RecordType::A, "not-an-ip", 300);
        let result = encode_rr(&record, None);
        assert!(result.is_err(), "Invalid A record must return error");
    }

    #[test]
    fn test_encode_rr_aaaa_record() {
        let record = make_record("v6.example.com", RecordType::AAAA, "2001:db8::1", 300);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::AAAA);

        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert_eq!(rdlength, 16, "AAAA record RDLENGTH must be 16");
    }

    #[test]
    fn test_encode_rr_aaaa_record_invalid() {
        let record = make_record("v6.example.com", RecordType::AAAA, "not-ipv6", 300);
        let result = encode_rr(&record, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_rr_cname_record() {
        let record = make_record(
            "alias.example.com",
            RecordType::CNAME,
            "target.example.com",
            600,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::CNAME);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0, "CNAME RDLENGTH must be > 0");
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(rdata.last(), Some(&0u8), "CNAME must end with root label");
    }

    #[test]
    fn test_encode_rr_ns_record() {
        let record = make_record("example.com", RecordType::NS, "ns1.example.com", 86400);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::NS);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(rdata.last(), Some(&0u8), "NS must end with root label");
    }

    #[test]
    fn test_encode_rr_txt_record_has_rdlength() {
        let record = make_record(
            "_dmarc.example.com",
            RecordType::TXT,
            "v=DMARC1; p=reject",
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::TXT);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0, "TXT RDLENGTH must be > 0");
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        let first_chunk_len = rdata[0] as usize;
        assert_eq!(first_chunk_len, 18, "First TXT chunk length must be 18");
        assert_eq!(&rdata[1..=first_chunk_len], b"v=DMARC1; p=reject");
    }

    #[test]
    fn test_encode_rr_txt_long_value() {
        let long_value = "a".repeat(300);
        let record = make_record("test.example.com", RecordType::TXT, &long_value, 300);
        let encoded = encode_rr(&record, None).unwrap();

        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert_eq!(
            rdlength, 302,
            "Long TXT must have 302 bytes RDLENGTH (255+1 chunk + 45+1 chunk)"
        );
    }

    #[test]
    fn test_encode_rr_mx_preference_before_exchange() {
        let record =
            make_record_with_priority("example.com", RecordType::MX, "mail.example.com", 300, 10);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::MX);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
        assert_eq!(preference, 10, "MX preference must come first");
        assert_eq!(
            rdata.last(),
            Some(&0u8),
            "MX exchange must end with root label"
        );
    }

    #[test]
    fn test_encode_rr_mx_default_priority() {
        let record = make_record("example.com", RecordType::MX, "mail.example.com", 300);
        let encoded = encode_rr(&record, None).unwrap();
        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
        assert_eq!(preference, 10, "Default MX priority must be 10");
    }

    #[test]
    fn test_encode_rr_ptr_has_root_terminator() {
        let record = make_record(
            "34.216.184.93.in-addr.arpa",
            RecordType::PTR,
            "www.example.com",
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::PTR);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(
            rdata.last(),
            Some(&0u8),
            "PTR must end with root terminator 0x00"
        );
    }

    #[test]
    fn test_encode_rr_ds_record() {
        let record = make_record("example.com", RecordType::DS, "ABCD1234", 86400);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::DS);

        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert_eq!(rdlength, 4, "DS RDLENGTH must match hex-decoded length");
    }

    #[test]
    fn test_encode_rr_caa_record() {
        let record = make_record(
            "example.com",
            RecordType::CAA,
            r#"0 issue "letsencrypt.org""#,
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::CAA);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(rdata[0], 0, "CAA flags must be 0");
        assert_eq!(rdata[1], 5, "CAA tag length must be 5 (issue)");
        assert_eq!(&rdata[2..7], b"issue");
    }

    #[test]
    fn test_encode_rr_tlsa_record() {
        let record = make_record(
            "_25._tcp.mail.example.com",
            RecordType::TLSA,
            "3 1 1 AABBCCDD",
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::TLSA);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(rdata[0], 3, "TLSA usage must be 3");
        assert_eq!(rdata[1], 1, "TLSA selector must be 1");
        assert_eq!(rdata[2], 1, "TLSA matching type must be 1");
        assert_eq!(&rdata[3..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_encode_rr_svcb_record() {
        let record = make_record("example.com", RecordType::SVCB, "1 . alpn=h2", 300);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::SVCB);
        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert!(rdlength > 4, "SVCB must have priority(2) + target + params");
    }

    #[test]
    fn test_encode_rr_naptr_record() {
        let record = make_record(
            "example.com",
            RecordType::NAPTR,
            "100 10 S SIP+D2U _sip._udp.example.com .",
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::NAPTR);
    }

    #[test]
    fn test_encode_rr_sshfp_record() {
        let record = make_record("ssh.example.com", RecordType::SSHFP, "1 1 AABBCCDD", 300);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::SSHFP);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(rdata[0], 1, "SSHFP algorithm must be 1");
        assert_eq!(rdata[1], 1, "SSHFP fingerprint type must be 1");
    }

    #[test]
    fn test_encode_rr_rrsig_from_hex() {
        let rrsig_hex = "00300e10000000005f9f0000000000000000000000";
        let record = make_record("example.com", RecordType::RRSIG, rrsig_hex, 300);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::RRSIG);
    }

    #[test]
    fn test_encode_rr_unsupported_type() {
        let record = make_record(
            "example.com",
            RecordType::SRV,
            "0 5 5060 sip.example.com",
            300,
        );
        let result = encode_rr(&record, None);
        assert!(result.is_err(), "Unsupported type must return error");
    }

    #[test]
    fn test_encode_rr_compression_pointer_used() {
        let record = make_record("@", RecordType::A, "1.2.3.4", 300);
        let encoded = encode_rr(&record, Some(("example.com", 12))).unwrap();
        let bytes = &encoded.bytes;
        assert_eq!(
            bytes[0],
            0xC0 | (12 >> 8) as u8,
            "Compression pointer high byte"
        );
        assert_eq!(bytes[1], (12 & 0xFF) as u8, "Compression pointer low byte");
    }

    #[test]
    fn test_encode_rr_compression_pointer_not_used_for_different_name() {
        let record = make_record("other.example.com", RecordType::A, "1.2.3.4", 300);
        let encoded = encode_rr(&record, Some(("example.com", 12))).unwrap();
        let bytes = &encoded.bytes;
        assert_ne!(
            bytes[0] & 0xC0,
            0xC0,
            "Different name must not use compression pointer"
        );
    }

    #[test]
    fn test_assemble_packet_header_structure() {
        let envelope = ResponseEnvelope::default();
        let packet = assemble_packet(&envelope, 0x1234, 0x8580, "example.com", 1);

        assert_eq!(&packet[0..2], &[0x12, 0x34], "Query ID");
        assert_eq!(&packet[2..4], &[0x85, 0x80], "Flags");
        assert_eq!(&packet[4..6], &[0x00, 0x01], "QDCOUNT must be 1");
        assert_eq!(&packet[6..8], &[0x00, 0x00], "ANCOUNT must be 0");
        assert_eq!(&packet[8..10], &[0x00, 0x00], "NSCOUNT must be 0");
        assert_eq!(&packet[10..12], &[0x00, 0x00], "ARCOUNT must be 0");
    }

    #[test]
    fn test_assemble_packet_with_records() {
        let mut envelope = ResponseEnvelope::default();
        let record = make_record("www.example.com", RecordType::A, "1.2.3.4", 300);
        envelope
            .answer_records
            .push(encode_rr(&record, Some(("example.com", 12))).unwrap());

        let packet = assemble_packet(&envelope, 0x5678, 0x8580, "example.com", 1);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(ancount, 1, "ANCOUNT must be 1");
    }

    #[test]
    fn test_assemble_packet_query_id_preserved() {
        let envelope = ResponseEnvelope::default();
        let packet = assemble_packet(&envelope, 0xABCD, 0x8580, "example.com", 1);
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        assert_eq!(id, 0xABCD, "Query ID must be preserved");
    }

    #[test]
    fn test_truncate_to_fit_removes_later_records() {
        let mut envelope = ResponseEnvelope::default();
        for i in 0..10 {
            let record = make_record(
                &format!("host{}.example.com", i),
                RecordType::A,
                &format!("10.0.0.{}", i),
                300,
            );
            envelope
                .answer_records
                .push(encode_rr(&record, None).unwrap());
        }

        let small_max = 12 + 32 + envelope.answer_records[0].bytes.len() + 1;
        truncate_to_fit(&mut envelope, small_max);
        assert_eq!(
            envelope.answer_records.len(),
            1,
            "Should keep only records that fit"
        );
    }

    #[test]
    fn test_truncate_to_fit_preserves_all_when_enough_space() {
        let mut envelope = ResponseEnvelope::default();
        for i in 0..3 {
            let record = make_record(
                &format!("host{}.example.com", i),
                RecordType::A,
                &format!("10.0.0.{}", i),
                300,
            );
            envelope
                .answer_records
                .push(encode_rr(&record, None).unwrap());
        }

        truncate_to_fit(&mut envelope, 4096);
        assert_eq!(envelope.answer_records.len(), 3, "All records should fit");
    }

    #[test]
    fn test_build_opt_encoded_record() {
        let opt = build_opt_encoded_record(4096, true);
        assert_eq!(opt.section, DnsSection::Additional);
        assert_eq!(opt.record_type, RecordType::OPT);
        assert_eq!(opt.bytes[0], 0x00, "OPT name must be root");
        let opt_type = u16::from_be_bytes([opt.bytes[1], opt.bytes[2]]);
        assert_eq!(opt_type, 41, "OPT type must be 41");
    }

    #[test]
    fn test_full_a_record_wire_format() {
        let record = make_record("@", RecordType::A, "192.168.1.1", 300);
        let encoded = encode_rr(&record, Some(("example.com", 12))).unwrap();

        let bytes = &encoded.bytes;
        assert_eq!(
            bytes[0], 0xC0u8,
            "Compression pointer high byte for offset 12"
        );
        assert_eq!(bytes[1], 12, "Compression pointer low byte for offset 12");

        let type_val = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(type_val, 1, "TYPE must be 1 (A)");

        let class_val = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(class_val, 1, "CLASS must be 1 (IN)");

        let ttl_val = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        assert_eq!(ttl_val, 300, "TTL must be 300");

        let rdlength = u16::from_be_bytes([bytes[10], bytes[11]]);
        assert_eq!(rdlength, 4, "RDLENGTH must be 4");

        let rdata = &bytes[12..16];
        assert_eq!(rdata, &[192, 168, 1, 1], "RDATA must be IP octets");
    }

    #[test]
    fn test_txt_rdlength_present() {
        let record = make_record("test.example.com", RecordType::TXT, "hello", 300);
        let encoded = encode_rr(&record, None).unwrap();
        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert_eq!(rdlength, 6, "TXT RDLENGTH must be present (1 + 5 = 6)");
    }

    #[test]
    fn test_mx_preference_order() {
        let record =
            make_record_with_priority("example.com", RecordType::MX, "mail.example.com", 300, 20);
        let encoded = encode_rr(&record, None).unwrap();
        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
        assert_eq!(pref, 20, "MX preference must be at rdata start");
        let exchange_start = 2;
        let label_len = rdata[exchange_start] as usize;
        assert_eq!(label_len, 4, "First label of exchange must be 'mail'");
        assert_eq!(
            &rdata[exchange_start + 1..exchange_start + 1 + label_len],
            b"mail"
        );
    }

    #[test]
    fn test_ptr_root_terminator() {
        let record = make_record("1.0.0.127.in-addr.arpa", RecordType::PTR, "localhost", 300);
        let encoded = encode_rr(&record, None).unwrap();
        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(
            rdata.last(),
            Some(&0u8),
            "PTR RDATA must end with root terminator"
        );
    }

    #[test]
    fn test_encode_rr_soa_record() {
        let record = make_record(
            "example.com",
            RecordType::SOA,
            "ns1.example.com admin.example.com 2024010101 3600 900 604800 86400",
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::SOA);
        assert_eq!(encoded.ttl, 300);

        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        // SOA RDATA: mname_name + rname_name + 5 * u32 (20 bytes)
        // "ns1.example.com": [3,ns1] + [7,example] + [3,com] + [0] = 17 bytes
        // "admin.example.com": [5,admin] + [7,example] + [3,com] + [0] = 19 bytes
        assert_eq!(
            rdlength,
            17 + 19 + 20,
            "SOA RDLENGTH must cover mname + rname + 5 u32 fields"
        );

        // Verify SERIAL at offset mname + rname
        let serial_offset = 17 + 19;
        let serial = u32::from_be_bytes([
            rdata[serial_offset],
            rdata[serial_offset + 1],
            rdata[serial_offset + 2],
            rdata[serial_offset + 3],
        ]);
        assert_eq!(serial, 2024010101, "SOA serial must match");

        let refresh = u32::from_be_bytes([
            rdata[serial_offset + 4],
            rdata[serial_offset + 5],
            rdata[serial_offset + 6],
            rdata[serial_offset + 7],
        ]);
        assert_eq!(refresh, 3600, "SOA refresh must match");

        let retry = u32::from_be_bytes([
            rdata[serial_offset + 8],
            rdata[serial_offset + 9],
            rdata[serial_offset + 10],
            rdata[serial_offset + 11],
        ]);
        assert_eq!(retry, 900, "SOA retry must match");

        let expire = u32::from_be_bytes([
            rdata[serial_offset + 12],
            rdata[serial_offset + 13],
            rdata[serial_offset + 14],
            rdata[serial_offset + 15],
        ]);
        assert_eq!(expire, 604800, "SOA expire must match");

        let minimum = u32::from_be_bytes([
            rdata[serial_offset + 16],
            rdata[serial_offset + 17],
            rdata[serial_offset + 18],
            rdata[serial_offset + 19],
        ]);
        assert_eq!(minimum, 86400, "SOA minimum must match");
    }

    #[test]
    fn test_encode_rr_soa_too_few_fields() {
        let record = make_record(
            "example.com",
            RecordType::SOA,
            "ns1.example.com admin.example.com 1",
            300,
        );
        let result = encode_rr(&record, None);
        assert!(result.is_err(), "SOA with too few fields must return error");
    }

    #[test]
    fn test_encode_rr_soa_mname_rname_end_with_root_label() {
        let record = make_record(
            "example.com",
            RecordType::SOA,
            "ns1.example.com admin.example.com 2024010101 3600 900 604800 86400",
            300,
        );
        let encoded = encode_rr(&record, None).unwrap();
        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        // mname "ns1.example.com" is 17 bytes (indices 0..17), root at index 16
        // rname "admin.example.com" is 19 bytes (indices 17..36), root at index 35
        assert_eq!(rdata[16], 0x00, "MNAME must end with root label");
        assert_eq!(rdata[35], 0x00, "RNAME must end with root label");
    }

    #[test]
    fn test_encode_rr_dnskey_from_hex() {
        let key_hex = "01010003080bed0b3b5c091c4728bfe63b25d3e7e3c26f8536b0e4df1e053e7f224c134e";
        let record = make_record("example.com", RecordType::DNSKEY, key_hex, 3600);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::DNSKEY);
        assert_eq!(encoded.ttl, 3600);

        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0, "DNSKEY RDLENGTH must be > 0");
    }

    #[test]
    fn test_encode_rr_https_record() {
        let record = make_record("example.com", RecordType::HTTPS, "1 . alpn=h2", 300);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::HTTPS);
        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert!(
            rdlength > 4,
            "HTTPS must have priority(2) + target + params"
        );
    }

    #[test]
    fn test_encode_rr_nsec_from_hex() {
        let nsec_hex = "04777777086578616d706c6503636f6d000006c0010000000000";
        let record = make_record("www.example.com", RecordType::NSEC, nsec_hex, 3600);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::NSEC);
        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0, "NSEC RDLENGTH must be > 0");
    }

    #[test]
    fn test_encode_rr_nsec3_from_hex() {
        let nsec3_hex = "0100056B52473B2E9C82B40F7C437E05B9C6E1A9";
        let record = make_record("example.com", RecordType::NSEC3, nsec3_hex, 3600);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::NSEC3);
        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0, "NSEC3 RDLENGTH must be > 0");
    }

    #[test]
    fn test_encode_rr_nsec3param_from_hex() {
        let nsec3param_hex = "0100056B52473B2E";
        let record = make_record("example.com", RecordType::NSEC3PARAM, nsec3param_hex, 3600);
        let encoded = encode_rr(&record, None).unwrap();
        assert_eq!(encoded.record_type, RecordType::NSEC3PARAM);
        let (_, _, _, rdlength, _) = parse_rr(&encoded.bytes);
        assert!(rdlength > 0, "NSEC3PARAM RDLENGTH must be > 0");
    }

    #[test]
    fn test_opt_increments_arcount() {
        let mut envelope = ResponseEnvelope::default();
        let record = make_record("www.example.com", RecordType::A, "1.2.3.4", 300);
        envelope
            .answer_records
            .push(encode_rr(&record, Some(("example.com", 12))).unwrap());
        envelope
            .additional_records
            .push(build_opt_encoded_record(4096, true));

        let packet = assemble_packet(&envelope, 0x1234, 0x8580, "example.com", 1);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);
        assert_eq!(ancount, 1, "ANCOUNT must be 1");
        assert_eq!(arcount, 1, "ARCOUNT must be 1 for OPT additional record");
    }

    #[test]
    fn test_invalid_mx_does_not_produce_partial_bytes() {
        let record = make_record("example.com", RecordType::MX, "mail.example.com", 300);
        // MX is valid, so test with empty exchange to ensure it doesn't panic
        let record_empty = make_record("example.com", RecordType::MX, "", 300);
        let result = encode_rr(&record_empty, None);
        // Empty MX should succeed but produce a record with just root label after preference
        if let Ok(encoded) = result {
            let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
            let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
            assert!(
                rdlength >= 3,
                "MX RDLENGTH must be at least 2 (preference) + 1 (root)"
            );
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            assert_eq!(pref, 10, "Default MX preference must be 10");
        }
    }

    #[test]
    fn test_empty_txt_value_produces_valid_wire_format() {
        // Empty TXT produces a single 0-length character string chunk, which is valid per RFC 1035
        let record = make_record("test.example.com", RecordType::TXT, "", 300);
        let result = encode_rr(&record, None);
        assert!(
            result.is_ok(),
            "Empty TXT value is valid wire format (0-length chunk)"
        );
        let encoded = result.unwrap();
        let (_, _, _, rdlength, rdata_start) = parse_rr(&encoded.bytes);
        let rdata = &encoded.bytes[rdata_start..rdata_start + rdlength];
        assert_eq!(
            rdlength, 1,
            "Empty TXT must have 1-byte RDLENGTH (0-length chunk)"
        );
        assert_eq!(rdata[0], 0, "Empty TXT chunk length must be 0");
    }

    #[test]
    fn test_assemble_packet_dnskey_response() {
        let mut envelope = ResponseEnvelope::default();
        let key_hex = "01010003080bed0b3b5c091c4728bfe63b25d3e7e3c26f8536b0e4df1e053e7f224c134e";
        let record = make_record("example.com", RecordType::DNSKEY, key_hex, 3600);
        envelope
            .answer_records
            .push(encode_rr(&record, None).unwrap());

        let packet = assemble_packet(&envelope, 0xABCD, 0x8580, "example.com", 48);
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(id, 0xABCD, "Query ID must be preserved for DNSKEY response");
        assert_eq!(ancount, 1, "ANCOUNT must be 1 for DNSKEY response");
    }

    #[test]
    fn test_assemble_packet_rrsig_response() {
        let mut envelope = ResponseEnvelope::default();
        let rrsig_hex = "00300e10000000005f9f0000000000000000000000";
        let record = make_record("example.com", RecordType::RRSIG, rrsig_hex, 300);
        envelope
            .answer_records
            .push(encode_rr(&record, None).unwrap());

        let packet = assemble_packet(&envelope, 0x5678, 0x8580, "example.com", 1);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(ancount, 1, "ANCOUNT must be 1 for RRSIG response");
    }

    #[test]
    fn test_assemble_packet_with_multiple_records_and_opt() {
        let mut envelope = ResponseEnvelope::default();
        let a1 = make_record("www.example.com", RecordType::A, "1.2.3.4", 300);
        let a2 = make_record("www.example.com", RecordType::A, "5.6.7.8", 300);
        envelope
            .answer_records
            .push(encode_rr(&a1, Some(("example.com", 12))).unwrap());
        envelope
            .answer_records
            .push(encode_rr(&a2, Some(("example.com", 12))).unwrap());
        envelope
            .additional_records
            .push(build_opt_encoded_record(4096, false));

        let packet = assemble_packet(&envelope, 0x9999, 0x8580, "example.com", 1);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);
        assert_eq!(ancount, 2, "ANCOUNT must be 2");
        assert_eq!(arcount, 1, "ARCOUNT must be 1 (OPT)");
    }

    #[test]
    fn test_truncated_response_preserves_id_and_sets_tc() {
        let mut envelope = ResponseEnvelope::default();
        for i in 0..20 {
            let record = make_record(
                &format!("host{}.example.com", i),
                RecordType::A,
                &format!("10.0.0.{}", i % 256),
                300,
            );
            envelope
                .answer_records
                .push(encode_rr(&record, None).unwrap());
        }
        truncate_to_fit(&mut envelope, 80);

        let flags = build_response_flags(true, true, true, true, false, 0);
        let packet = assemble_packet(&envelope, 0xBEEF, flags, "example.com", 1);
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags_val = u16::from_be_bytes([packet[2], packet[3]]);
        assert_eq!(id, 0xBEEF, "Truncated response must preserve query ID");
        assert_ne!(flags_val & 0x0200, 0, "Truncated response must set TC bit");
    }
}

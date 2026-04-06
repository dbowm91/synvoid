use super::*;

impl DnsServer {
    pub(super) fn build_response(
        query_id: u16,
        qname: &str,
        qtype: u16,
        records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&crate::dns::dnssec::ZoneSigningKey>,
        signer_name: &str,
    ) -> Arc<Vec<u8>> {
        let max_response_size = edns_options
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(512);

        let mut response = Vec::new();
        let mut compressor = DnsMessageCompressor::new();

        response.extend_from_slice(&query_id.to_be_bytes());

        let mut qr_aa = 0x8580u16;
        // AD flag: only set when records are actually DNSSEC-signed (not just when client requests it)
        let records_signed = dnssec_ok
            && !records.is_empty()
            && records[0].record_type != RecordType::DNSKEY
            && zsk.is_some();
        if records_signed {
            qr_aa |= 0x0020;
        }
        response.extend_from_slice(&qr_aa.to_be_bytes());

        response.extend_from_slice(&1u16.to_be_bytes());
        let ancount_offset = response.len();
        response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT placeholder
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        let arcount_offset = response.len();
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT placeholder

        let qname_for_compression = if qname.is_empty() || qname == "@" {
            String::new()
        } else {
            qname.trim_end_matches('.').to_lowercase()
        };

        let question_name_offset = response.len();
        if !qname_for_compression.is_empty() {
            compressor.add_label(&qname_for_compression, question_name_offset as u16);
        }

        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        for part in &name_parts {
            response.push((*part).len() as u8);
            response.extend_from_slice(part.as_bytes());
        }
        response.push(0);

        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for record in records {
            let record_name = if record.name == "@" || record.name.is_empty() {
                qname_for_compression.clone()
            } else {
                record.name.to_lowercase()
            };

            if record_name == qname_for_compression && !qname_for_compression.is_empty() {
                response.push(0xC0 | (question_name_offset >> 8) as u8);
                response.push((question_name_offset & 0xFF) as u8);
            } else {
                compressor.add_label(&record_name, response.len() as u16);
                for part in record_name.split('.') {
                    if !part.is_empty() {
                        response.push(part.len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                }
                response.push(0);
            }

            response.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl.to_be_bytes());

            match record.record_type {
                RecordType::A => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv4Addr>() {
                        let bytes: &[u8; 4] = &ip.octets();
                        let len = bytes.len() as u16;
                        response.extend_from_slice(&len.to_be_bytes());
                        response.extend_from_slice(bytes);
                    }
                }
                RecordType::AAAA => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv6Addr>() {
                        let bytes = ip.octets();
                        let len = bytes.len() as u16;
                        response.extend_from_slice(&len.to_be_bytes());
                        response.extend_from_slice(&bytes);
                    }
                }
                RecordType::CNAME | RecordType::NS => {
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 1; // trailing null byte
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                    response.push(0);
                }
                RecordType::TXT => {
                    let txt_value = record.value.as_bytes();
                    let mut offset = 0;
                    while offset < txt_value.len() {
                        let remaining = txt_value.len() - offset;
                        let chunk_len = std::cmp::min(remaining, 255);
                        response.push(chunk_len as u8);
                        response.extend_from_slice(&txt_value[offset..offset + chunk_len]);
                        offset += chunk_len;
                    }
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
                    response.push(0);
                }
                RecordType::DNSKEY => {
                    if let Ok(key_bytes) = hex::decode(&record.value) {
                        let dnskey = compute_dnskey(&crate::dns::dnssec::ZoneSigningKey {
                            key_id: String::new(),
                            algorithm: Algorithm::Ed25519,
                            key_type: crate::dns::dnssec::KeyType::KSK,
                            created_at: 0,
                            expires_at: 0,
                            public_key: key_bytes.clone(),
                            private_key: Vec::new(),
                            key_tag: 0,
                            flags: 257,
                            key_size: None,
                        });
                        response.extend_from_slice(&(dnskey.len() as u16).to_be_bytes());
                        response.extend_from_slice(&dnskey);
                    }
                }
                RecordType::DS => {
                    if let Ok(ds_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(ds_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&ds_bytes);
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
                RecordType::CAA => {
                    // Wire format: flags (1 byte) | tag length (1 byte) | tag bytes | value bytes
                    // Expected input format: "flags tag value" e.g. "0 issue \"letsencrypt.org\""
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
                        // Fallback: treat entire value as raw data with flags=0
                        data.push(0);
                        data.push(record.value.len() as u8);
                        data.extend_from_slice(record.value.as_bytes());
                    }
                    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    response.extend_from_slice(&data);
                }
                RecordType::TLSA => {
                    // Wire format: usage (1) | selector (1) | matching type (1) | cert data bytes
                    // Expected input format: "usage selector matching_type cert_data"
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
                        // Fallback: treat entire value as raw data
                        data.extend_from_slice(record.value.as_bytes());
                    }
                    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    response.extend_from_slice(&data);
                }
                RecordType::SVCB | RecordType::HTTPS => {
                    if let Ok(svcb_data) = Self::parse_svcb_value(&record.value) {
                        response.extend_from_slice(&(svcb_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&svcb_data);
                    }
                }
                RecordType::NAPTR => {
                    if let Ok(naptr_data) = Self::parse_naptr_value(&record.value) {
                        response.extend_from_slice(&(naptr_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&naptr_data);
                    }
                }
                RecordType::SSHFP => {
                    if let Ok(sshfp_data) = Self::parse_sshfp_value(&record.value) {
                        response.extend_from_slice(&(sshfp_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&sshfp_data);
                    }
                }
                _ => continue,
            };
        }

        if dnssec_ok && !records.is_empty() && records[0].record_type != RecordType::DNSKEY {
            if let Some(key) = zsk {
                for record in records {
                    let _rrname_offset = response.len();
                    if !qname_for_compression.is_empty() {
                        response.push(0xC0 | (question_name_offset >> 8) as u8);
                        response.push((question_name_offset & 0xFF) as u8);
                    } else {
                        response.push(0);
                    }

                    let rrsig = Self::create_signed_rrsig(record, signer_name, key);
                    if !rrsig.is_empty() {
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                    }
                }
            }
        }

        if let Some(edns) = edns_options {
            let opt_record =
                crate::dns::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            if !opt_record.is_empty() {
                response.extend_from_slice(&[0]);
                response.extend_from_slice(&41u16.to_be_bytes());
                response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
                response.extend_from_slice(&opt_record);
            }
        } else if dnssec_ok {
            let opt_record = crate::dns::edns::EdnsOptions::build_opt_record(4096, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        // Patch ANCOUNT: answer records + RRSIG records
        let rrsig_count = if dnssec_ok
            && !records.is_empty()
            && records[0].record_type != RecordType::DNSKEY
            && zsk.is_some()
        {
            records.len()
        } else {
            0
        };
        let ancount = (records.len() + rrsig_count) as u16;
        response[ancount_offset..ancount_offset + 2].copy_from_slice(&ancount.to_be_bytes());

        // Patch ARCOUNT: 1 for OPT record if present, 0 otherwise
        let has_opt = edns_options.is_some() || dnssec_ok;
        let arcount: u16 = if has_opt { 1 } else { 0 };
        response[arcount_offset..arcount_offset + 2].copy_from_slice(&arcount.to_be_bytes());

        if response.len() > max_response_size && max_response_size > 0 {
            return Self::build_truncated_response(
                qname,
                qtype,
                records,
                dnssec_ok,
                edns_options,
                zsk,
                signer_name,
            );
        }

        Arc::new(response)
    }

    pub(super) fn build_truncated_response(
        qname: &str,
        qtype: u16,
        records: &[DnsZoneRecord],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&crate::dns::dnssec::ZoneSigningKey>,
        signer_name: &str,
    ) -> Arc<Vec<u8>> {
        let max_size = edns_options
            .map(|e| e.udp_payload_size as usize)
            .unwrap_or(512);

        let mut response = Vec::new();

        let response_id = Self::generate_random_id();
        response.extend_from_slice(&response_id.to_be_bytes());
        response.extend_from_slice(&0x8582u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        let mut included_records = Vec::new();

        for record in records {
            let record_size = Self::estimate_record_size(record, &name_parts);

            let rrsig_size = if dnssec_ok && zsk.is_some() && record.record_type.is_signed() {
                let sig_size = zsk
                    .map(|k| match k.algorithm {
                        crate::dns::dnssec::Algorithm::Ed25519 => 64,
                        crate::dns::dnssec::Algorithm::RSA => 256, // RSA signatures are larger
                    })
                    .unwrap_or(64);

                2 + name_parts.iter().map(|p| 1 + p.len()).sum::<usize>()
                    + 1
                    + 2
                    + 2
                    + 4
                    + 8
                    + 8
                    + 2
                    + signer_name.len()
                    + 1
                    + sig_size
            } else {
                0
            };

            if response.len() + record_size + rrsig_size + 20 > max_size {
                break;
            }

            included_records.push(record.clone());
        }

        let ancount = included_records.len() as u16;
        response.extend_from_slice(&ancount.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        for part in &name_parts {
            if !part.is_empty() {
                response.push((*part).len() as u8);
                response.extend_from_slice(part.as_bytes());
            }
        }
        response.push(0);

        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for record in &included_records {
            for part in &name_parts {
                if !part.is_empty() {
                    response.push((*part).len() as u8);
                    response.extend_from_slice(part.as_bytes());
                }
            }
            response.push(0);

            response.extend_from_slice(&u16::from(record.record_type).to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl.to_be_bytes());

            match record.record_type {
                RecordType::A => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv4Addr>() {
                        let bytes: &[u8; 4] = &ip.octets();
                        response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(bytes);
                    }
                }
                RecordType::AAAA => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv6Addr>() {
                        let bytes = ip.octets();
                        response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&bytes);
                    }
                }
                RecordType::CNAME | RecordType::NS => {
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 1; // trailing null byte
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                    response.push(0);
                }
                RecordType::TXT => {
                    let txt_value = record.value.as_bytes();
                    let mut offset = 0;
                    while offset < txt_value.len() {
                        let remaining = txt_value.len() - offset;
                        let chunk_len = std::cmp::min(remaining, 255);
                        response.push(chunk_len as u8);
                        response.extend_from_slice(&txt_value[offset..offset + chunk_len]);
                        offset += chunk_len;
                    }
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
                    response.push(0);
                }
                RecordType::SVCB | RecordType::HTTPS => {
                    if let Ok(svcb_data) = Self::parse_svcb_value(&record.value) {
                        response.extend_from_slice(&(svcb_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&svcb_data);
                    }
                }
                RecordType::NAPTR => {
                    if let Ok(naptr_data) = Self::parse_naptr_value(&record.value) {
                        response.extend_from_slice(&(naptr_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&naptr_data);
                    }
                }
                _ => continue,
            };
        }

        if dnssec_ok && !included_records.is_empty() {
            if let Some(key) = zsk {
                for record in &included_records {
                    let rrsig = Self::create_signed_rrsig(record, signer_name, key);
                    if !rrsig.is_empty() && response.len() + rrsig.len() + 12 < max_size {
                        for part in &name_parts {
                            if !part.is_empty() {
                                response.push((*part).len() as u8);
                                response.extend_from_slice(part.as_bytes());
                            }
                        }
                        response.push(0);
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                    }
                }
            }
        }

        if let Some(edns) = edns_options {
            let opt_record =
                crate::dns::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        Arc::new(response)
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
}

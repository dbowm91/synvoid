// DNSSEC validation: signature verification, chain of trust, NSEC3 hashing, DS records

use sha2::{Digest, Sha256, Sha384};

use super::dnssec::{DsDigestType, ZoneSigningKey};

pub fn calculate_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.push(protocol);
    buf.push(algorithm);
    buf.extend_from_slice(public_key);

    let mut sum: u32 = 0;
    for (i, byte) in buf.iter().enumerate() {
        if i & 1 == 0 {
            sum += (*byte as u32) << 8;
        } else {
            sum += *byte as u32;
        }
    }

    (sum + (sum >> 16)) as u16
}

pub fn compute_dnskey(key: &ZoneSigningKey) -> Vec<u8> {
    let mut dnskey = Vec::new();

    dnskey.extend_from_slice(&key.flags.to_be_bytes());
    dnskey.push(0x03);
    dnskey.push(key.algorithm.to_u8());
    dnskey.extend_from_slice(&key.public_key);

    dnskey
}

pub fn get_dnskey_record(key: &ZoneSigningKey) -> Vec<u8> {
    let mut record = Vec::new();

    record.push(0x00);
    record.push(0x00);

    record.extend_from_slice(&key.flags.to_be_bytes());
    record.push(0x03);
    record.push(key.algorithm.to_u8());
    record.extend_from_slice(&key.public_key);

    record
}

pub fn canonical_rdata(
    record_type: u16,
    value: &str,
    priority: Option<u32>,
    weight: Option<u32>,
    port: Option<u32>,
    _ttl: u32,
) -> Vec<u8> {
    match record_type {
        1 => {
            if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
                return ip.octets().to_vec();
            }
            Vec::new()
        }
        28 => {
            if let Ok(ip) = value.parse::<std::net::Ipv6Addr>() {
                return ip.octets().to_vec();
            }
            Vec::new()
        }
        2 => canonical_name(value),
        5 => canonical_name(value),
        6 => canonical_soa(value),
        15 => {
            let mut rdata = Vec::new();
            let pri = priority.unwrap_or(10) as u16;
            rdata.extend_from_slice(&pri.to_be_bytes());
            rdata.extend_from_slice(&canonical_name(value));
            rdata
        }
        16 => {
            let mut rdata = Vec::new();
            let txt = value.as_bytes();

            let mut pos = 0;
            while pos < txt.len() {
                let remaining = &txt[pos..];
                if remaining.is_empty() {
                    break;
                }
                let len = remaining[0] as usize;
                if len == 0 || pos + 1 + len > txt.len() {
                    rdata.push(txt.len() as u8);
                    rdata.extend_from_slice(txt);
                    break;
                }
                rdata.push(len as u8);
                rdata.extend_from_slice(&remaining[1..1 + len]);
                pos += 1 + len;
            }

            if rdata.is_empty() {
                rdata.push(txt.len() as u8);
                rdata.extend_from_slice(txt);
            }

            rdata
        }
        33 => {
            let mut rdata = Vec::new();
            let pri = priority.unwrap_or(0);
            let w = weight.unwrap_or(0);
            let p = port.unwrap_or(0);
            rdata.extend_from_slice(&pri.to_be_bytes());
            rdata.extend_from_slice(&w.to_be_bytes());
            rdata.extend_from_slice(&p.to_be_bytes());
            rdata.extend_from_slice(&canonical_name(value));
            rdata
        }
        64 | 65 => {
            if let Ok(svcb_data) = crate::dns::server::DnsServer::parse_svcb_value(value) {
                svcb_data
            } else {
                value.as_bytes().to_vec()
            }
        }
        _ => value.as_bytes().to_vec(),
    }
}

pub fn canonical_name(name: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    let name_lower = name.to_lowercase();
    let name = name_lower.trim_end_matches('.');

    if name.is_empty() {
        rdata.push(0);
        return rdata;
    }

    for part in name.split('.') {
        if !part.is_empty() {
            rdata.push(part.len() as u8);
            rdata.extend_from_slice(part.as_bytes());
        }
    }
    rdata.push(0);
    rdata
}

fn canonical_soa(value: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    let parts: Vec<&str> = value.split_whitespace().collect();

    if parts.len() >= 7 {
        rdata.extend_from_slice(&canonical_name(parts[0]));
        rdata.extend_from_slice(&canonical_name(parts[1]));

        if let Ok(serial) = parts[2].parse::<u32>() {
            rdata.extend_from_slice(&serial.to_be_bytes());
        } else {
            rdata.extend_from_slice(&0u32.to_be_bytes());
        }

        for i in 3..7 {
            if let Ok(refresh) = parts[i].parse::<u32>() {
                rdata.extend_from_slice(&refresh.to_be_bytes());
            } else {
                rdata.extend_from_slice(&0u32.to_be_bytes());
            }
        }
    }

    rdata
}

pub fn canonical_dns_message(
    name: &str,
    record_type: u16,
    record_class: u16,
    ttl: u32,
    rdata: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();

    let name_lower = name.to_lowercase();
    let name = name_lower.trim_end_matches('.');

    if name.is_empty() {
        msg.push(0);
    } else {
        for part in name.split('.') {
            if !part.is_empty() {
                msg.push(part.len() as u8);
                msg.extend_from_slice(part.as_bytes());
            }
        }
        msg.push(0);
    }

    msg.extend_from_slice(&record_type.to_be_bytes());
    msg.extend_from_slice(&record_class.to_be_bytes());
    msg.extend_from_slice(&ttl.to_be_bytes());
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(rdata);

    msg
}

pub fn count_labels(name: &str) -> u8 {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return 1;
    }
    name.split('.').count() as u8
}

pub fn compute_dnskey_canonical(
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.push(protocol);
    buf.push(algorithm);
    buf.extend_from_slice(public_key);
    buf
}

pub fn compute_ds_digest(
    digest_type: u8,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let canonical = compute_dnskey_canonical(flags, protocol, algorithm, public_key);

    match digest_type {
        1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            hasher.update(&canonical);
            Ok(hasher.finalize().to_vec())
        }
        2 => {
            let mut hasher = Sha256::new();
            hasher.update(&canonical);
            Ok(hasher.finalize().to_vec())
        }
        4 => {
            let mut hasher = Sha384::new();
            hasher.update(&canonical);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(format!("Unsupported DS digest type: {}", digest_type)),
    }
}

pub fn verify_ds_digest(
    digest_type: u8,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
    expected_digest: &[u8],
) -> Result<bool, String> {
    let computed = compute_ds_digest(digest_type, flags, protocol, algorithm, public_key)?;
    Ok(computed == expected_digest)
}

pub fn create_ds_record(
    key: &ZoneSigningKey,
    digest_type: DsDigestType,
) -> Result<Vec<u8>, String> {
    let mut ds_data = Vec::new();

    ds_data.extend_from_slice(&key.key_tag.to_be_bytes());
    ds_data.push(key.algorithm.to_u8());
    ds_data.push(digest_type.to_u8());

    let canonical_dnskey = compute_dnskey_canonical(
        key.flags,
        3, // protocol
        key.algorithm.to_u8(),
        &key.public_key,
    );

    let digest = match digest_type {
        DsDigestType::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(&canonical_dnskey);
            hasher.finalize().to_vec()
        }
        DsDigestType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&canonical_dnskey);
            hasher.finalize().to_vec()
        }
        DsDigestType::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(&canonical_dnskey);
            hasher.finalize().to_vec()
        }
    };

    ds_data.extend_from_slice(&digest);

    Ok(ds_data)
}

pub fn get_ds_record(key: &ZoneSigningKey) -> Vec<u8> {
    let mut record = Vec::new();

    record.push(0x00);
    record.push(0x00);

    if let Ok(ds_data) = create_ds_record(key, DsDigestType::Sha256) {
        record.extend_from_slice(&ds_data);
    }

    record
}

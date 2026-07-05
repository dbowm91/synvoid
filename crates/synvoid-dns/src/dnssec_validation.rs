// DNSSEC validation: signature verification, chain of trust, NSEC3 hashing, DS records

use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

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
            if let Ok(svcb_data) = crate::server::DnsServer::parse_svcb_value(value) {
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

        for part in parts.iter().take(7).skip(3) {
            if let Ok(refresh) = part.parse::<u32>() {
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
        3 => Err("GOST R 34.11-94 (DS digest type 3) is not yet supported. This requires adding a GOST digest crate (e.g., gost94) to Cargo.toml".to_string()),
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
    Ok(bool::from(computed.ct_eq(expected_digest)))
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

/// Result of DNSSEC validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_secure: bool,
    pub trust_anchor_id: Option<String>,
    pub validation_method: ValidationMethod,
}

/// How the DNSSEC validation was performed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMethod {
    /// Validated via standard RFC 5011 trust anchors
    Rfc5011,
    /// Validated via mesh-derived Ed25519 trust anchors
    MeshEd25519,
    /// No validation performed
    None,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::{Algorithm, KeyType, ZoneSigningKey};

    fn ed25519_test_key() -> ZoneSigningKey {
        let mut private_bytes = [0u8; 32];
        getrandom::getrandom(&mut private_bytes).expect("getrandom failed");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_bytes.into());
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        let private_bytes = signing_key.to_bytes().to_vec();

        ZoneSigningKey {
            key_id: "test-key".to_string(),
            algorithm: Algorithm::Ed25519,
            key_type: KeyType::KSK,
            created_at: 0,
            expires_at: u64::MAX,
            public_key: verifying_key,
            private_key: private_bytes,
            key_tag: 12345,
            flags: 257,
            key_size: None,
        }
    }

    #[test]
    fn test_compute_dnskey_wire_format() {
        let key = ed25519_test_key();
        let dnskey = compute_dnskey(&key);
        assert_eq!(dnskey.len(), 4 + 32);
        let flags = u16::from_be_bytes([dnskey[0], dnskey[1]]);
        assert_eq!(flags, 257);
        assert_eq!(dnskey[2], 3);
        assert_eq!(dnskey[3], Algorithm::Ed25519.to_u8());
    }

    #[test]
    fn test_get_dnskey_record_includes_zero_prefix() {
        let key = ed25519_test_key();
        let record = get_dnskey_record(&key);
        assert_eq!(record[0], 0x00);
        assert_eq!(record[1], 0x00);
        assert_eq!(record.len(), 2 + 4 + 32);
    }

    #[test]
    fn test_canonical_rdata_a() {
        let rdata = canonical_rdata(1, "192.168.1.1", None, None, None, 300);
        assert_eq!(rdata.len(), 4);
        assert_eq!(rdata, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_canonical_rdata_aaaa() {
        let rdata = canonical_rdata(28, "::1", None, None, None, 300);
        assert_eq!(rdata.len(), 16);
        assert_eq!(rdata[15], 1);
    }

    #[test]
    fn test_canonical_name_empty() {
        let name = canonical_name("");
        assert_eq!(name, vec![0]);
    }

    #[test]
    fn test_canonical_name_root() {
        let name = canonical_name(".");
        assert_eq!(name, vec![0]);
    }

    #[test]
    fn test_canonical_name_labels() {
        let name = canonical_name("example.com");
        assert_eq!(name.len(), 12 + 1);
        assert_eq!(name[0], 7);
        assert_eq!(&name[1..8], b"example");
        assert_eq!(name[8], 3);
        assert_eq!(&name[9..12], b"com");
        assert_eq!(name[12], 0);
    }

    #[test]
    fn test_count_labels_root() {
        assert_eq!(count_labels("."), 1);
    }

    #[test]
    fn test_count_labels_single() {
        assert_eq!(count_labels("com"), 1);
    }

    #[test]
    fn test_count_labels_multi() {
        assert_eq!(count_labels("www.example.com"), 3);
    }

    #[test]
    fn test_calculate_key_tag_known_ksk() {
        let tag = calculate_key_tag(257, 3, 15, &[0x01; 32]);
        assert!(tag > 0);
    }

    #[test]
    fn test_calculate_key_tag_stable() {
        let tag1 = calculate_key_tag(257, 3, 15, &[0xAA; 32]);
        let tag2 = calculate_key_tag(257, 3, 15, &[0xAA; 32]);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_compute_ds_digest_sha1() {
        let mut dnskey = vec![0, 1, 0, 3, 15];
        dnskey.extend_from_slice(&[0xAA; 32]);
        let digest = compute_ds_digest(1, 15, 3, 1, &dnskey);
        assert!(digest.is_ok());
        assert_eq!(digest.unwrap().len(), 20);
    }

    #[test]
    fn test_compute_ds_digest_sha256() {
        let mut dnskey = vec![0, 1, 0, 3, 15];
        dnskey.extend_from_slice(&[0xBB; 32]);
        let digest = compute_ds_digest(2, 257, 3, 15, &dnskey);
        assert!(digest.is_ok());
        assert_eq!(digest.unwrap().len(), 32);
    }

    #[test]
    fn test_compute_ds_digest_sha384() {
        let mut dnskey = vec![0, 1, 0, 3, 15];
        dnskey.extend_from_slice(&[0xCC; 32]);
        let digest = compute_ds_digest(4, 257, 3, 15, &dnskey);
        assert!(digest.is_ok());
        assert_eq!(digest.unwrap().len(), 48);
    }

    #[test]
    fn test_compute_ds_digest_unsupported() {
        let mut dnskey = vec![0, 1, 0, 3, 15];
        dnskey.extend_from_slice(&[0xDD; 32]);
        let result = compute_ds_digest(3, 257, 3, 15, &dnskey);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ds_digest_match() {
        let mut dnskey = vec![0, 1, 0, 3, 15];
        dnskey.extend_from_slice(&[0xEE; 32]);
        let digest = compute_ds_digest(1, 257, 3, 15, &dnskey).unwrap();
        assert!(verify_ds_digest(1, 257, 3, 15, &dnskey, &digest).unwrap());
    }

    #[test]
    fn test_verify_ds_digest_mismatch() {
        let mut dnskey = vec![0, 1, 0, 3, 15];
        dnskey.extend_from_slice(&[0xEF; 32]);
        let wrong_digest = vec![0u8; 20];
        assert!(!verify_ds_digest(1, 257, 3, 15, &dnskey, &wrong_digest).unwrap());
    }

    #[test]
    fn test_create_ds_record() {
        let key = ed25519_test_key();
        let ds = create_ds_record(&key, DsDigestType::Sha256);
        assert!(ds.is_ok());
        let ds_data = ds.unwrap();
        assert!(ds_data.len() > 4);
    }

    #[test]
    fn test_get_ds_record_includes_zero_prefix() {
        let key = ed25519_test_key();
        let record = get_ds_record(&key);
        assert_eq!(record[0], 0x00);
        assert_eq!(record[1], 0x00);
    }

    #[test]
    fn test_compute_dnskey_canonical() {
        let dnskey = compute_dnskey_canonical(257, 3, 15, &[0x01; 32]);
        let flags = u16::from_be_bytes([dnskey[0], dnskey[1]]);
        assert_eq!(flags, 257);
        assert_eq!(dnskey[2], 3);
        assert_eq!(dnskey[3], 15);
    }

    #[test]
    fn test_validation_result_struct() {
        let result = ValidationResult {
            is_secure: true,
            trust_anchor_id: Some("test-id".to_string()),
            validation_method: ValidationMethod::Rfc5011,
        };
        assert!(result.is_secure);
        assert_eq!(result.validation_method, ValidationMethod::Rfc5011);
    }

    #[test]
    fn test_canonical_dns_message() {
        let msg = canonical_dns_message("example.com.", 1, 1, 300, &[0x01; 4]);
        assert!(!msg.is_empty());
    }
}

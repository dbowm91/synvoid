// DNSSEC validation: signature verification, chain of trust, NSEC3 hashing, DS records.
// Phase 30: public-only. These helpers touch algorithm/flags/public_key/key_tag
// via the sealed-handle accessors; they never access private bytes.

use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

use super::dnssec::{DsDigestType, ZoneSigningKey};
use crate::wire::NameError;

/// Key-tag calculation delegates to the custody crate so DNS and keystore
/// agree by construction (single implementation in `synvoid-dnssec-keystore`).
pub fn calculate_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    synvoid_dnssec_keystore::calculate_key_tag(flags, protocol, algorithm, public_key)
}

pub fn compute_dnskey(key: &ZoneSigningKey) -> Vec<u8> {
    key.dnskey_rdata()
}

pub fn get_dnskey_record(key: &ZoneSigningKey) -> Vec<u8> {
    let mut record = Vec::new();

    record.push(0x00);
    record.push(0x00);
    record.extend_from_slice(&key.dnskey_rdata());

    record
}

/// Canonical RDATA for one record, exactly as it is written to the wire.
///
/// This is a compatibility wrapper over
/// [`crate::server::rdata_wire`], the single encoder the response path and
/// the signer share. There is deliberately no second, presentation-string
/// based implementation: the previous TXT heuristic guessed a length prefix
/// from the first byte and signed bytes that were not served (finding L1).
///
/// `_weight`/`_port` are retained for the documented signature; SRV is not
/// encodable as RDATA today, so they carry no information.
pub fn canonical_rdata(
    record_type: u16,
    value: &str,
    priority: Option<u32>,
    _weight: Option<u32>,
    _port: Option<u32>,
    _ttl: u32,
) -> Vec<u8> {
    let record = crate::server::DnsZoneRecord {
        name: String::new(),
        record_type: crate::server::RecordType::from(record_type),
        value: value.to_string(),
        ttl: 0,
        priority,
    };
    // Malformed data has no canonical form; callers that sign use the
    // `Result` form and fail closed instead.
    crate::server::rdata_wire(&record).unwrap_or_default()
}

/// Canonical wire form of a **fully qualified** domain name (RFC 4034 §6.2).
///
/// The input must be absolute: `"example.com."`, or `"."`/`""` for the root.
/// A relative name (`"www"`) has no canonical form without its origin, so it
/// is rejected rather than silently encoded as `\x03www\x00` — that silent
/// guess is how a signature came to cover the wrong owner (finding D4).
/// Callers holding a zone-relative storage name must build
/// [`crate::wire::OwnerName`] first; this function is not a name joiner.
pub fn canonical_name(fqdn: &str) -> Result<Vec<u8>, NameError> {
    let name = fqdn.trim();

    if name.is_empty() || name == "." {
        return Ok(vec![0]);
    }

    let Some(absolute) = name.strip_suffix('.') else {
        return Err(NameError::RelativeName {
            name: name.to_string(),
        });
    };

    crate::wire::encode_name(&absolute.to_ascii_lowercase())
}

/// Assemble one record in the form RFC 4034 §3.1.2 signs:
/// `owner | type | class | ttl | rdlength | rdata`.
///
/// `name` must be a fully qualified name for the same reason
/// [`canonical_name`] requires one.
pub fn canonical_dns_message(
    name: &str,
    record_type: u16,
    record_class: u16,
    ttl: u32,
    rdata: &[u8],
) -> Result<Vec<u8>, NameError> {
    let mut msg = canonical_name(name)?;

    msg.extend_from_slice(&record_type.to_be_bytes());
    msg.extend_from_slice(&record_class.to_be_bytes());
    msg.extend_from_slice(&ttl.to_be_bytes());
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(rdata);

    Ok(msg)
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

    ds_data.extend_from_slice(&key.key_tag().to_be_bytes());
    ds_data.push(key.algorithm().to_u8());
    ds_data.push(digest_type.to_u8());

    let canonical_dnskey = compute_dnskey_canonical(
        key.flags(),
        3, // protocol
        key.algorithm().to_u8(),
        key.public_key(),
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
        // Public-only handle: validation helpers never need private bytes.
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
        let key_tag =
            crate::dnssec::calculate_key_tag(257, 3, Algorithm::Ed25519.to_u8(), &verifying_key);

        ZoneSigningKey::from_public_parts(
            "test-key".to_string(),
            Algorithm::Ed25519,
            KeyType::KSK,
            verifying_key,
            key_tag,
            257,
        )
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
        let name = canonical_name("").unwrap();
        assert_eq!(name, vec![0]);
    }

    #[test]
    fn test_canonical_name_root() {
        let name = canonical_name(".").unwrap();
        assert_eq!(name, vec![0]);
    }

    #[test]
    fn test_canonical_name_labels() {
        let name = canonical_name("example.com.").unwrap();
        assert_eq!(name.len(), 12 + 1);
        assert_eq!(name[0], 7);
        assert_eq!(&name[1..8], b"example");
        assert_eq!(name[8], 3);
        assert_eq!(&name[9..12], b"com");
        assert_eq!(name[12], 0);
    }

    #[test]
    fn test_canonical_name_rejects_a_relative_name() {
        // A relative storage key has no canonical form without the origin.
        // Encoding it as `\x03www\x00` is finding D4.
        assert_eq!(
            canonical_name("www"),
            Err(NameError::RelativeName {
                name: "www".to_string()
            })
        );
        // The same name with its origin resolves, and the labels come from
        // `OwnerName`.
        assert_eq!(
            canonical_name(&crate::wire::OwnerName::new("www", "example.com").fqdn()).unwrap(),
            vec![
                0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
                b'o', b'm', 0,
            ]
        );
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
        let msg = canonical_dns_message("example.com.", 1, 1, 300, &[0x01; 4]).unwrap();
        assert!(!msg.is_empty());
    }
}

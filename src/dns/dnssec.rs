// DNSSEC signing module
//
// NOTE: This module currently uses manual DNS wire format construction.
// For production use, consider switching to the `dns-parser` or `hickory` crate
// for proper DNS message parsing and construction. This would provide:
// - Proper handling of DNS message compression
// - Correct RDATA encoding for all record types
// - Better RFC compliance
// - Easier maintenance

use std::result::Result;

pub use rand_core_06;

pub use super::dnssec_key_mgmt::DnsSecKeyManager;
pub use super::dnssec_signing::{
    base32_encode, create_nsec3_owner_name, create_nsec3_record, create_nsec3param_record,
    create_nsec_record, create_rrsig_record, find_next_name_in_zone, get_nsec3_type_bitmap,
    get_nsec_type_bitmap, hash_name_nsec3, sign_data,
};
pub use super::dnssec_validation::{
    calculate_key_tag, canonical_dns_message, canonical_name, canonical_rdata, compute_dnskey,
    compute_dnskey_canonical, compute_ds_digest, count_labels, create_ds_record, get_dnskey_record,
    get_ds_record, verify_ds_digest,
};

/// RNG adapter that wraps getrandom to implement rand_core 0.6 traits.
/// Required because rsa 0.9 depends on rand_core 0.6 while our project uses rand 0.9.
pub(crate) struct CryptoRngAdapter;

impl rand_core_06::RngCore for CryptoRngAdapter {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        getrandom::getrandom(dest).map_err(rand_core_06::Error::new)
    }
}

impl rand_core_06::CryptoRng for CryptoRngAdapter {}

#[derive(Debug, Clone, Copy)]
pub struct KeyRotationConfig {
    pub ksk_rollover_days: u32,
    pub zsk_rollover_days: u32,
    pub grace_period_days: u32,
    pub key_expiration_days: u32,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            ksk_rollover_days: 30,
            zsk_rollover_days: 7,
            grace_period_days: 2,
            key_expiration_days: 365,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeyRotationResult {
    pub ksk_rotated: bool,
    pub zsk_rotated: bool,
    pub ksk_new_key_id: Option<String>,
    pub zsk_new_key_id: Option<String>,
    pub ksk_age_days: Option<u64>,
    pub zsk_age_days: Option<u64>,
    pub ksk_error: Option<String>,
    pub zsk_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_type: String,
    pub algorithm: String,
    pub key_tag: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub age_days: u64,
    pub days_until_expiry: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DnsSecKeyStatus {
    pub ksk: Option<KeyInfo>,
    pub zsk: Option<KeyInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct RolloverState {
    pub ksk_in_rollover: bool,
    pub zsk_in_rollover: bool,
    pub ksk_rollover_started: Option<u64>,
    pub zsk_rollover_started: Option<u64>,
    pub publish_dnssec: bool,
}

#[derive(Clone, Debug)]
pub struct ZoneSigningKey {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub key_type: KeyType,
    pub created_at: u64,
    pub expires_at: u64,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub key_tag: u16,
    pub flags: u16,
    pub key_size: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    RSA,
}

impl Algorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            Algorithm::Ed25519 => 15,
            Algorithm::RSA => 8, // RSASHA256
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            15 => Some(Algorithm::Ed25519),
            8 => Some(Algorithm::RSA),
            _ => None,
        }
    }

    pub fn dns_algorithm_name(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ED25519",
            Algorithm::RSA => "RSASHA256",
        }
    }
}

impl From<crate::config::dns::DnsSecAlgorithm> for Algorithm {
    fn from(config: crate::config::dns::DnsSecAlgorithm) -> Self {
        match config {
            crate::config::dns::DnsSecAlgorithm::Ed25519 => Algorithm::Ed25519,
            crate::config::dns::DnsSecAlgorithm::RsaSha256 => Algorithm::RSA,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    KSK,
    ZSK,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsDigestType {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 4,
}

impl DsDigestType {
    pub fn to_u8(&self) -> u8 {
        match self {
            DsDigestType::Sha1 => 1,
            DsDigestType::Sha256 => 2,
            DsDigestType::Sha384 => 4,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DsDigestType::Sha1),
            2 => Some(DsDigestType::Sha256),
            4 => Some(DsDigestType::Sha384),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Nsec3Config {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

impl Default for Nsec3Config {
    fn default() -> Self {
        Self {
            algorithm: 1, // SHA-1 is the default NSEC3 algorithm
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
        }
    }
}

impl Nsec3Config {
    pub fn new(iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            algorithm: 1,
            flags: 0,
            iterations,
            salt,
        }
    }

    pub fn new_with_algorithm(algorithm: u8, iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            algorithm,
            flags: 0,
            iterations,
            salt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_name() {
        let result = canonical_name("EXAMPLE.COM");
        assert_eq!(
            result,
            vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );

        let result2 = canonical_name("example.com.");
        assert_eq!(
            result2,
            vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );

        let result3 = canonical_name("");
        assert_eq!(result3, vec![0]);
    }

    #[test]
    fn test_canonical_a_record() {
        let result = canonical_rdata(1, "192.0.2.1", None, None, None, 3600);
        assert_eq!(result, vec![192, 0, 2, 1]);
    }

    #[test]
    fn test_canonical_aaaa_record() {
        let result = canonical_rdata(28, "2001:db8::1", None, None, None, 3600);
        assert_eq!(
            result,
            vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn test_canonical_cname_record() {
        let result = canonical_rdata(5, "example.com", None, None, None, 3600);
        assert_eq!(
            result,
            vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );
    }

    #[test]
    fn test_canonical_txt_record_single_string() {
        let result = canonical_rdata(16, "Hello World", None, None, None, 3600);
        assert_eq!(result.len(), 12);
        assert_eq!(result[0], 11);
        assert_eq!(&result[1..], b"Hello World");
    }

    #[test]
    fn test_canonical_txt_record_multiple_strings() {
        let result = canonical_rdata(16, "\x0bHello World", None, None, None, 3600);
        // TXT record: length byte + text (no trailing null in canonical form)
        assert_eq!(result.len(), 12);
        assert_eq!(result[0], 11);
        assert_eq!(&result[1..12], b"Hello World");
    }

    #[test]
    fn test_canonical_mx_record() {
        let result = canonical_rdata(15, "example.com", Some(10), None, None, 3600);
        eprintln!(
            "DEBUG: result len = {}, result = {:?}",
            result.len(),
            result
        );
        // MX RDATA: 2 bytes priority + canonical name
        // canonical name "example.com" = [7, 'example', 3, 'com', 0] = 13 bytes
        // Total: 2 + 13 = 15 bytes
        assert_eq!(result.len(), 15);
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 10);
        assert_eq!(
            &result[2..],
            &vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );
    }

    #[test]
    fn test_canonical_soa_record() {
        let soa_value = "ns.example.com. hostmaster.example.com. 2024010101 3600 600 604800 86400";
        let result = canonical_rdata(6, soa_value, None, None, None, 3600);

        assert!(result.len() > 0);

        // SOA record structure: mname (primary NS) + rname (admin) + serial + refresh + retry + expire + minimum
        // mname: ns.example.com = [2, 'ns', 7, 'example', 3, 'com', 0] = 16 bytes
        // rname: hostmaster.example.com = [10, 'hostmaster', 7, 'example', 3, 'com', 0] = 24 bytes
        // serial: 4 bytes, refresh: 4, retry: 4, expire: 4, minimum: 4 = 20 bytes
        // Total: 16 + 24 + 20 = 60 bytes
        assert_eq!(result.len(), 60);

        // Verify first label is "ns" (length 2)
        assert_eq!(result[0], 2);
        assert_eq!(result[1], b'n');
        assert_eq!(result[2], b's');
    }

    #[test]
    fn test_count_labels() {
        assert_eq!(count_labels("example.com"), 2);
        assert_eq!(count_labels("example.com."), 2);
        assert_eq!(count_labels("@"), 1);
        assert_eq!(count_labels(""), 1);
        assert_eq!(count_labels("a.b.c"), 3);
    }

    #[test]
    fn test_nsec3_hash() {
        let config = Nsec3Config::new(0, vec![0xab, 0xcd]);

        let hash1 = hash_name_nsec3("example.com", &config);
        let hash2 = hash_name_nsec3("example.com", &config);

        assert_eq!(hash1, hash2);

        let hash3 = hash_name_nsec3("test.example.com", &config);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_base32_encode() {
        // 3 bytes = 24 bits = 4 full 5-bit groups + 4 remaining bits = 5 base32 chars
        // Per RFC 4648 base32 without padding (used by NSEC3 in RFC 5155)
        let input = vec![0xfb, 0x53, 0x2c];
        let result = base32_encode(&input);
        assert_eq!(result.len(), 5, "3 bytes should produce 5 base32 chars");
    }

    #[test]
    fn test_algorithm_to_u8() {
        assert_eq!(Algorithm::Ed25519.to_u8(), 15);
    }

    #[test]
    fn test_algorithm_from_u8() {
        assert_eq!(Algorithm::from_u8(15), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_u8(5), None);
        assert_eq!(Algorithm::from_u8(99), None);
    }

    #[test]
    fn test_ds_digest_type() {
        assert_eq!(DsDigestType::Sha1.to_u8(), 1);
        assert_eq!(DsDigestType::Sha256.to_u8(), 2);
        assert_eq!(DsDigestType::from_u8(1), Some(DsDigestType::Sha1));
        assert_eq!(DsDigestType::from_u8(2), Some(DsDigestType::Sha256));
    }

    #[test]
    fn test_key_tag_calculation() {
        let public_key = vec![
            0x04, 0x9f, 0x2c, 0x8e, 0x7a, 0x2f, 0x1a, 0x5c, 0x3a, 0x7d, 0x4b, 0x9a, 0x8c, 0xde,
            0x15, 0x16, 0x2e, 0x86, 0x4a, 0x7f, 0x52, 0x91, 0x3c, 0xc1, 0x96, 0x4d, 0x89, 0x2c,
            0x7b, 0x5e, 0x9f, 0x43,
        ];
        let key_tag = calculate_key_tag(257, 3, Algorithm::Ed25519.to_u8(), &public_key);
        assert!(key_tag > 0);
    }

    #[test]
    fn test_compute_dnskey() {
        let key = ZoneSigningKey {
            key_id: "test".to_string(),
            algorithm: Algorithm::Ed25519,
            key_type: KeyType::KSK,
            created_at: 0,
            expires_at: 0,
            public_key: vec![
                0x04, 0x9f, 0x2c, 0x8e, 0x7a, 0x2f, 0x1a, 0x5c, 0x3a, 0x7d, 0x4b, 0x9a, 0x8c, 0xde,
                0x15, 0x16, 0x2e, 0x86, 0x4a, 0x7f, 0x52, 0x91, 0x3c, 0xc1, 0x96, 0x4d, 0x89, 0x2c,
                0x7b, 0x5e, 0x9f, 0x43,
            ],
            private_key: Vec::new(),
            key_tag: 12345,
            flags: 257,
            key_size: None,
        };

        let dnskey = compute_dnskey(&key);
        assert!(dnskey.len() > 0);
        // DNSKEY format: flags (2 bytes) + protocol (1 byte) + algorithm (1 byte) + public key
        assert_eq!(dnskey[0], 1); // flags high byte (257 = 0x0101)
        assert_eq!(dnskey[1], 1); // flags low byte
        assert_eq!(dnskey[2], 3); // protocol (always 3 for DNSSEC)
        assert_eq!(dnskey[3], 15); // algorithm (15 = Ed25519)
    }

    #[test]
    fn test_nsec3_config_default() {
        let config = Nsec3Config::default();
        assert_eq!(config.algorithm, 1);
        assert_eq!(config.flags, 0);
        assert_eq!(config.iterations, 0);
        assert!(config.salt.is_empty());
    }

    #[test]
    fn test_nsec3_config_new() {
        let salt = vec![0x01, 0x02, 0x03];
        let config = Nsec3Config::new(100, salt.clone());
        assert_eq!(config.algorithm, 1);
        assert_eq!(config.flags, 0);
        assert_eq!(config.iterations, 100);
        assert_eq!(config.salt, salt);
    }

    #[test]
    fn test_key_rotation_config_default() {
        let config = KeyRotationConfig::default();
        assert_eq!(config.ksk_rollover_days, 30);
        assert_eq!(config.zsk_rollover_days, 7);
        assert_eq!(config.grace_period_days, 2);
        assert_eq!(config.key_expiration_days, 365);
    }

    #[test]
    fn test_key_info_structure() {
        let key_info = KeyInfo {
            key_type: "KSK".to_string(),
            algorithm: "Ed25519".to_string(),
            key_tag: 12345,
            created_at: 1000,
            expires_at: 2000,
            age_days: 1,
            days_until_expiry: Some(30),
        };

        assert_eq!(key_info.key_type, "KSK");
        assert_eq!(key_info.key_tag, 12345);
        assert!(key_info.days_until_expiry.is_some());
    }

    #[test]
    fn test_rollover_state_default() {
        let state = RolloverState::default();
        assert!(!state.ksk_in_rollover);
        assert!(!state.zsk_in_rollover);
        assert!(state.ksk_rollover_started.is_none());
    }

    #[test]
    fn test_dnssec_key_status() {
        let key_info = KeyInfo {
            key_type: "ZSK".to_string(),
            algorithm: "Ed25519".to_string(),
            key_tag: 54321,
            created_at: 1000,
            expires_at: 2000,
            age_days: 1,
            days_until_expiry: Some(30),
        };

        let status = DnsSecKeyStatus {
            ksk: None,
            zsk: Some(key_info),
        };

        assert!(status.ksk.is_none());
        assert!(status.zsk.is_some());
    }

    #[test]
    fn test_key_rotation_result() {
        let result = KeyRotationResult {
            ksk_rotated: true,
            zsk_rotated: false,
            ksk_new_key_id: Some("new-ksk".to_string()),
            zsk_new_key_id: None,
            ksk_age_days: Some(0),
            zsk_age_days: Some(5),
            ksk_error: None,
            zsk_error: None,
        };

        assert!(result.ksk_rotated);
        assert!(!result.zsk_rotated);
        assert!(result.ksk_new_key_id.is_some());
    }
}

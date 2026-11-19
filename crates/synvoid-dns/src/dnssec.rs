//! DNSSEC module: public protocol types + key-custody facade (Phase 30).
//!
//! # Limitations
//!
//! This module uses **manual DNS wire format construction** for performance.
//!
//! # Phase 30 custody boundary
//!
//! Private-key generation, sealed storage, rotation, signing dispatch, and
//! HSM backing live in `synvoid-dnssec-keystore`. This module re-exports
//! the custody types for compatibility (`Algorithm`, `KeyType`,
//! `ZoneSigningKey` = opaque [`SealedSigningKey`], `DnsSecKeyManager`,
//! rotation/status types, `calculate_key_tag`) and retains only public
//! protocol vocabulary (`Nsec3Config`) plus re-exports of the
//! validation/proof helpers that operate without private keys.
//!
//! Query/transport code must use [`SealedSigningKey::sign`] over
//! caller-supplied canonical bytes and [`KeyMetadata`] for DNSKEY/DS
//! construction. There is no API here that returns raw private bytes.

pub use synvoid_dnssec_keystore::{
    calculate_key_tag, Algorithm, DnsSecKeyManager, DnsSecKeyStatus, DnssecKeystore, DsDigestType,
    KeyInfo, KeyMetadata, KeyRotationConfig, KeyRotationResult, KeyType, RolloverState,
    SealedSigningKey, ZoneSigningKey,
};

pub use super::dnssec_signing::{
    base32_encode, create_nsec3_owner_name, create_nsec3_record, create_nsec3param_record,
    create_nsec_record, create_rrsig_record, find_next_name_in_zone, get_nsec3_type_bitmap,
    get_nsec_type_bitmap, hash_name_nsec3, sign_data,
};
pub use super::dnssec_validation::{
    canonical_dns_message, canonical_name, canonical_rdata, compute_dnskey,
    compute_dnskey_canonical, compute_ds_digest, create_ds_record, get_dnskey_record,
    get_ds_record, verify_ds_digest,
};

/// Convert the DNS-owned runtime algorithm enum into the custody-crate
/// algorithm. A free function (not `From`) because both types are foreign to
/// this crate after the Phase 30 extraction (orphan rule).
pub fn algorithm_from_runtime(config: crate::runtime_config::DnssecAlgorithmRuntime) -> Algorithm {
    match config {
        crate::runtime_config::DnssecAlgorithmRuntime::Ed25519 => Algorithm::Ed25519,
        crate::runtime_config::DnssecAlgorithmRuntime::Rsa => Algorithm::RSA,
    }
}

#[derive(Clone, Debug)]
pub struct Nsec3Config {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

/// Largest NSEC3 salt the wire format can carry (one-octet length field,
/// RFC 5155 §3.1.4).
pub const NSEC3_MAX_SALT_LEN: usize = 255;

/// Hard cap on NSEC3 iterations.
///
/// RFC 9276 §3.2 recommends 0: extra iterations multiply the work of every
/// negative answer without adding meaningful resistance. The cap exists so an
/// operator cannot turn a hostile iteration count into a query-time DoS; the
/// RFC 5155 §B vectors use 12, which stays below it.
pub const NSEC3_MAX_ITERATIONS: u16 = 100;

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

    /// The parameters as they can actually be published.
    ///
    /// `None` when the salt cannot be encoded (more than 255 octets), because
    /// a chain built from it would have an invalid RDATA length byte.
    /// Iterations are clamped to [`NSEC3_MAX_ITERATIONS`], and the returned
    /// value is what both the hash and the RDATA use — never one of each.
    pub fn sanitized(&self) -> Option<Self> {
        if self.salt.len() > NSEC3_MAX_SALT_LEN {
            tracing::error!(
                salt_len = self.salt.len(),
                "NSEC3 salt exceeds 255 octets and cannot be encoded"
            );
            return None;
        }
        let iterations = self.iterations.min(NSEC3_MAX_ITERATIONS);
        if iterations != self.iterations {
            tracing::warn!(
                configured = self.iterations,
                used = iterations,
                "NSEC3 iterations capped (RFC 9276 recommends 0)"
            );
        }
        Some(Self {
            algorithm: self.algorithm,
            flags: self.flags,
            iterations,
            salt: self.salt.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_name() {
        // Canonicalization requires a fully qualified name: `EXAMPLE.COM` is
        // relative and must be rejected rather than guessed at (finding L3).
        assert_eq!(
            canonical_name("EXAMPLE.COM"),
            Err(crate::wire::NameError::RelativeName {
                name: "EXAMPLE.COM".to_string()
            })
        );

        let expected = vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0];
        assert_eq!(canonical_name("EXAMPLE.COM.").unwrap(), expected);
        assert_eq!(canonical_name("example.com.").unwrap(), expected);

        let result3 = canonical_name("").unwrap();
        assert_eq!(result3, vec![0]);
        assert_eq!(canonical_name(".").unwrap(), vec![0]);
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
    fn test_canonical_txt_record_does_not_guess_a_length_prefix() {
        // The value is 12 presentation bytes whose first byte happens to be
        // 0x0b. The old heuristic read that byte as a length prefix and
        // signed a different 12-byte string than the wire form (finding L1);
        // the canonical bytes are the wire encoding of the whole value.
        let value = "\x0bHello World";
        let result = canonical_rdata(16, value, None, None, None, 3600);
        assert_eq!(result.len(), 13);
        assert_eq!(result[0], 12);
        assert_eq!(&result[1..], value.as_bytes());
    }

    #[test]
    fn test_canonical_mx_record() {
        let result = canonical_rdata(15, "example.com", Some(10), None, None, 3600);
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
        assert!(!result.is_empty());
        assert_eq!(result.len(), 60);
        assert_eq!(result[0], 2);
        assert_eq!(result[1], b'n');
        assert_eq!(result[2], b's');
    }

    #[test]
    fn test_owner_labels() {
        // `count_labels` was replaced by `OwnerName::labels`, which knows the
        // origin and the wildcard rule (RFC 4034 §3.1.3).
        assert_eq!(crate::wire::OwnerName::new("@", "example.com").labels(), 2);
        assert_eq!(
            crate::wire::OwnerName::new("www", "example.com").labels(),
            3
        );
        assert_eq!(crate::wire::OwnerName::new("*", "example.com").labels(), 2);
        assert_eq!(crate::wire::OwnerName::new("@", "").labels(), 0);
        assert_eq!(
            crate::wire::OwnerName::new("a.b", "example.com").labels(),
            4
        );
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
        let input = vec![0xfb, 0x53, 0x2c];
        let result = base32_encode(&input);
        assert_eq!(result.len(), 5);
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
    fn test_compute_dnskey_public_only() {
        let key = SealedSigningKey::from_public_parts(
            "test".to_string(),
            Algorithm::Ed25519,
            KeyType::KSK,
            vec![
                0x04, 0x9f, 0x2c, 0x8e, 0x7a, 0x2f, 0x1a, 0x5c, 0x3a, 0x7d, 0x4b, 0x9a, 0x8c, 0xde,
                0x15, 0x16, 0x2e, 0x86, 0x4a, 0x7f, 0x52, 0x91, 0x3c, 0xc1, 0x96, 0x4d, 0x89, 0x2c,
                0x7b, 0x5e, 0x9f, 0x43,
            ],
            12345,
            257,
        );
        let dnskey = compute_dnskey(&key);
        assert!(!dnskey.is_empty());
        assert_eq!(dnskey[0], 1);
        assert_eq!(dnskey[1], 1);
        assert_eq!(dnskey[2], 3);
        assert_eq!(dnskey[3], 15);
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
    fn test_nsec3_config_sanitized() {
        // A salt larger than the one-octet length field can express is
        // rejected, never truncated.
        let oversized = Nsec3Config::new(0, vec![0u8; NSEC3_MAX_SALT_LEN + 1]);
        assert!(oversized.sanitized().is_none());

        // The RFC 5155 §B parameter set (12) survives untouched.
        let rfc = Nsec3Config::new(12, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(rfc.sanitized().unwrap().iterations, 12);

        // An operator cannot make every negative answer cost unbounded work.
        let hostile = Nsec3Config::new(u16::MAX, Vec::new());
        assert_eq!(
            hostile.sanitized().unwrap().iterations,
            NSEC3_MAX_ITERATIONS
        );

        let max_salt = Nsec3Config::new(0, vec![0u8; NSEC3_MAX_SALT_LEN]);
        assert!(max_salt.sanitized().is_some(), "255 octets is encodable");
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

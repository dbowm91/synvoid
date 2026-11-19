// DNSSEC signing facade: narrow signing entry + NSEC/NSEC3 proof construction.
// Phase 30: private-key signing lives in `synvoid-dnssec-keystore` behind
// `SealedSigningKey::sign` (no raw private bytes cross this module).
// NSEC/NSEC3/RRSIG wire construction stays here: it needs only public
// metadata (algorithm, key tag) plus caller-supplied signatures.

use crate::time::unix_timestamp_secs;
use sha2::{Digest, Sha256};

use super::dnssec::{Nsec3Config, ZoneSigningKey};

/// Sign caller-supplied canonical bytes with the sealed key handle.
/// Compat wrapper over [`SealedSigningKey::sign`]; the query path should
/// prefer `key.sign(canonical)` directly.
pub fn sign_data(data: &[u8], key: &ZoneSigningKey) -> Result<Vec<u8>, String> {
    key.sign(data).map_err(|e| e.to_string())
}

pub fn create_rrsig_record(
    key: &ZoneSigningKey,
    type_covered: u16,
    original_ttl: u32,
    signer_name: &str,
    signature: &[u8],
    labels_count: u8,
) -> Vec<u8> {
    let mut rrsig = Vec::new();

    rrsig.extend_from_slice(&type_covered.to_be_bytes());
    rrsig.push(key.algorithm().to_u8());
    rrsig.push(labels_count);
    rrsig.extend_from_slice(&original_ttl.to_be_bytes());

    let now = unix_timestamp_secs();
    let sig_expire = now + (7 * 86400);
    let sig_inception = now - (86400);

    rrsig.extend_from_slice(&(sig_expire as u32).to_be_bytes());
    rrsig.extend_from_slice(&(sig_inception as u32).to_be_bytes());
    rrsig.extend_from_slice(&key.key_tag().to_be_bytes());

    let signer_name_labels = signer_name.trim_end_matches('.');
    let signer_name_parts: Vec<&str> = signer_name_labels.split('.').collect();
    for part in &signer_name_parts {
        rrsig.push((*part).len() as u8);
        rrsig.extend_from_slice(part.as_bytes());
    }
    rrsig.push(0);

    rrsig.extend_from_slice(signature);

    rrsig
}

fn build_type_bitmap(type_codes: &[u16]) -> Vec<(u8, Vec<u8>)> {
    let mut window_blocks = Vec::new();
    let mut current_window: u8 = 0;
    let mut block_bits = Vec::new();

    for &rt in type_codes {
        let window = (rt / 256) as u8;
        let bit = rt % 256;

        if window != current_window && !block_bits.is_empty() {
            window_blocks.push((current_window, std::mem::take(&mut block_bits)));
            current_window = window;
        }

        let byte_index = bit / 8;
        let bit_index = bit % 8;

        while block_bits.len() <= byte_index as usize {
            block_bits.push(0);
        }
        block_bits[byte_index as usize] |= 1 << (7 - bit_index);
    }

    if !block_bits.is_empty() {
        while block_bits.last() == Some(&0) {
            block_bits.pop();
        }
        if !block_bits.is_empty() {
            window_blocks.push((current_window, block_bits));
        }
    }

    window_blocks
}

pub fn create_nsec_record(_current_name: &str, next_name: &str, type_bitmap: &[u16]) -> Vec<u8> {
    let mut nsec = Vec::new();

    let next_name_labels = next_name.trim_end_matches('.');
    let next_name_parts: Vec<&str> = next_name_labels.split('.').collect();
    for part in &next_name_parts {
        nsec.push((*part).len() as u8);
        nsec.extend_from_slice(part.as_bytes());
    }
    nsec.push(0);

    for (window, bits) in build_type_bitmap(type_bitmap) {
        nsec.push(window);
        nsec.push(bits.len() as u8);
        nsec.extend_from_slice(&bits);
    }

    nsec
}

pub fn get_nsec_type_bitmap() -> Vec<u16> {
    vec![1, 2, 5, 6, 15, 16, 28, 33, 46, 47, 50]
}

/// The canonical successor of `current_name` in `zone`.
///
/// Kept as a compatibility helper for callers that hold only a `Zone`; the
/// authoritative path selects proofs from the precomputed index instead
/// ([`ZoneDenial`](super::denial::ZoneDenial)). The ordering is RFC 4034 §6.1
/// canonical order, not `String` order (finding L5): an ancestor sorts before
/// its descendants and the last owner wraps to the apex.
///
/// A zone built by hand (not yet inserted into a store) has an empty denial
/// index, so one is built on demand for this call only.
pub fn find_next_name_in_zone(zone: &super::server::Zone, current_name: &str) -> Option<String> {
    if !zone.denial().is_empty() {
        return zone.denial().successor(current_name).map(str::to_string);
    }
    let denial = super::denial::ZoneDenial::build(
        &zone.origin,
        &zone.records,
        zone.nsec3param.as_ref(),
        zone.dnskey_ttl.unwrap_or(3600),
    );
    denial.successor(current_name).map(str::to_string)
}

/// RFC 5155 §5 hash of an owner name.
///
/// The input is the canonical wire form: fully qualified, lowercase, no
/// compression, wildcard label kept unexpanded (RFC 5155 §5, RFC 4034 §6.2).
/// Iteration zero is a hash too — `IH(salt, x, 0) = H(x || salt)` — so one
/// hash is always applied before the loop (finding D5). `iterations` is
/// clamped by [`Nsec3Config::sanitized`]-adjacent policy; an unencodable name
/// yields an empty hash that cannot match any chain member.
pub fn hash_name_nsec3(name: &str, config: &Nsec3Config) -> Vec<u8> {
    let canonical = canonical_wire_name(name);
    let Some(wire) = canonical else {
        tracing::error!(
            name = %name,
            "NSEC3: owner name is not encodable in canonical wire form"
        );
        return Vec::new();
    };

    // RFC 5155 §5: IH(salt, x, 0) = H(x || salt); the salt is raw bytes.
    let mut input = Vec::with_capacity(wire.len() + config.salt.len());
    input.extend_from_slice(&wire);
    input.extend_from_slice(&config.salt);
    let mut hash = hash_once(config.algorithm, &input);

    let iterations = config.iterations.min(crate::dnssec::NSEC3_MAX_ITERATIONS);
    for _ in 1..=iterations {
        let mut input = Vec::with_capacity(hash.len() + config.salt.len());
        input.extend_from_slice(&hash);
        input.extend_from_slice(&config.salt);
        hash = hash_once(config.algorithm, &input);
    }
    hash
}

fn hash_once(algorithm: u8, input: &[u8]) -> Vec<u8> {
    use sha1::Sha1;

    match algorithm {
        1 => {
            let mut hasher = Sha1::new();
            hasher.update(input);
            hasher.finalize().to_vec()
        }
        2 => {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hasher.finalize().to_vec()
        }
        _ => {
            tracing::warn!(
                "Unsupported NSEC3 algorithm {}, falling back to SHA-1",
                algorithm
            );
            let mut hasher = Sha1::new();
            hasher.update(input);
            hasher.finalize().to_vec()
        }
    }
}

/// Canonical wire form of an owner name for NSEC3 hashing.
///
/// Accepts either an absolute spelling (`example.com.`) or the presentation
/// spelling used throughout the zone (`example.com`); the result is always
/// absolute. Invalid labels are rejected rather than guessed at.
fn canonical_wire_name(name: &str) -> Option<Vec<u8>> {
    let mut fqdn = name.trim().to_ascii_lowercase();
    if fqdn.is_empty() || fqdn == "." {
        return Some(vec![0]);
    }
    if !fqdn.ends_with('.') {
        fqdn.push('.');
    }
    crate::dnssec::canonical_name(&fqdn).ok()
}

/// NSEC3 RDATA (RFC 5155 §3.2).
///
/// `next_hash` is the **next hashed owner name in hash order**, as raw octets
/// taken from the sorted chain — never an owner name and never re-hashed
/// (finding D38). The hash-length byte is the hash length (20 for SHA-1), not
/// the length of its base32 spelling.
pub fn create_nsec3_record(config: &Nsec3Config, next_hash: &[u8], type_bitmap: &[u16]) -> Vec<u8> {
    let mut nsec3 = Vec::new();

    nsec3.push(config.algorithm);
    nsec3.push(config.flags);
    nsec3.extend_from_slice(&config.iterations.to_be_bytes());
    nsec3.push(config.salt.len() as u8);
    nsec3.extend_from_slice(&config.salt);
    nsec3.push(next_hash.len() as u8);
    nsec3.extend_from_slice(next_hash);

    for (window, bits) in build_type_bitmap(type_bitmap) {
        nsec3.push(window);
        nsec3.push(bits.len() as u8);
        nsec3.extend_from_slice(&bits);
    }

    nsec3
}

pub fn create_nsec3param_record(config: &Nsec3Config) -> Vec<u8> {
    let mut nsec3param = Vec::new();

    nsec3param.push(config.algorithm);
    nsec3param.push(config.flags);
    nsec3param.extend_from_slice(&config.iterations.to_be_bytes());
    nsec3param.push(config.salt.len() as u8);
    nsec3param.extend_from_slice(&config.salt);

    nsec3param
}

pub fn get_nsec3_type_bitmap() -> Vec<u16> {
    vec![1, 2, 5, 6, 15, 16, 28, 33, 46, 47, 50]
}

pub fn create_nsec3_owner_name(origin: &str, hash: &[u8]) -> String {
    let hash_b32 = base32_encode(hash);
    let origin = origin.trim_end_matches('.');
    if origin.is_empty() {
        hash_b32
    } else {
        format!("{hash_b32}.{origin}")
    }
}

pub fn base32_encode(input: &[u8]) -> String {
    const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut result = String::new();

    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u64);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::Algorithm;

    fn ed25519_test_key() -> ZoneSigningKey {
        // Sealed handle via the custody boundary: generate in a temp
        // keystore, clone the handle out, and drop the dir.
        let dir = tempfile::Builder::new()
            .prefix("dnssec_signing_test_")
            .tempdir()
            .unwrap();
        let mut ks = synvoid_dnssec_keystore::DnssecKeystore::new(dir.path().to_path_buf());
        ks.initialize().unwrap();
        ks.generate_key(
            synvoid_dnssec_keystore::Algorithm::Ed25519,
            synvoid_dnssec_keystore::KeyType::ZSK,
            0,
            90,
        )
        .unwrap();
        (*ks.active_zsk().unwrap()).clone()
    }

    #[test]
    fn test_sign_data_ed25519() {
        let key = ed25519_test_key();
        let data = b"test data to sign";
        let sig = sign_data(data, &key);
        assert!(sig.is_ok());
        let sig_bytes = sig.unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_sign_data_different_messages_differ() {
        let key = ed25519_test_key();
        let sig1 = sign_data(b"message one", &key).unwrap();
        let sig2 = sign_data(b"message two", &key).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_sign_data_public_only_handle_refuses() {
        let key = ZoneSigningKey::from_public_parts(
            "test".to_string(),
            Algorithm::Ed25519,
            crate::dnssec::KeyType::ZSK,
            vec![0u8; 32],
            12345,
            256,
        );
        let result = sign_data(b"test", &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_rrsig_record() {
        let key = ed25519_test_key();
        let signature = sign_data(b"test data", &key).unwrap();
        let rrsig = create_rrsig_record(&key, 1, 3600, "example.com.", &signature, 2);

        assert!(!rrsig.is_empty());
        let type_covered = u16::from_be_bytes([rrsig[0], rrsig[1]]);
        assert_eq!(type_covered, 1);
        assert_eq!(rrsig[2], Algorithm::Ed25519.to_u8());
        assert_eq!(rrsig[3], 2);
    }

    #[test]
    fn test_create_nsec_record() {
        let nsec = create_nsec_record("a.example.com.", "b.example.com.", &[1, 2, 28]);
        assert!(!nsec.is_empty());
    }

    #[test]
    fn test_build_type_bitmap_single_window() {
        let types = vec![1, 2, 28];
        let nsec = create_nsec_record("a.example.com.", "b.example.com.", &types);
        assert!(!nsec.is_empty());
    }

    #[test]
    fn test_create_nsec3_record() {
        let config = Nsec3Config {
            algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![0xAB, 0xCD],
        };
        let next_hash = [0x11u8; 20];
        let nsec3 = create_nsec3_record(&config, &next_hash, &[1, 2, 28]);
        // algorithm, flags, iterations(2), salt length, salt, hash length.
        assert_eq!(nsec3[0], 1);
        assert_eq!(nsec3[1], 0);
        assert_eq!(u16::from_be_bytes([nsec3[2], nsec3[3]]), 0);
        assert_eq!(nsec3[4], 2, "salt length is the raw salt octets");
        assert_eq!(&nsec3[5..7], &[0xAB, 0xCD]);
        assert_eq!(
            nsec3[7], 20,
            "hash length is the hash length (20), never the base32 length"
        );
        assert_eq!(
            &nsec3[8..28],
            &next_hash,
            "the next-hash field is the next hash bytes, not a re-hash"
        );
    }

    /// RFC 5155 Appendix A, salt `aabbccdd`, 12 iterations: H(example) =
    /// `0p9mhaveqvm6t7vbl5lop2u3t2rp3tom`.
    #[test]
    fn test_hash_name_nsec3_rfc5155_vector() {
        let config = Nsec3Config {
            algorithm: 1,
            flags: 0,
            iterations: 12,
            salt: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let hash = hash_name_nsec3("example.", &config);
        assert_eq!(hash.len(), 20);
        assert_eq!(
            base32_encode(&hash),
            "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
            "the hash must be H(canonical wire name || salt), iterated 12 times"
        );
    }

    #[test]
    fn test_create_nsec3param_record() {
        let config = Nsec3Config::default();
        let param = create_nsec3param_record(&config);
        assert!(!param.is_empty());
        assert_eq!(param[0], config.algorithm);
        assert_eq!(param[1], config.flags);
    }

    #[test]
    fn test_hash_name_nsec3_deterministic() {
        let config = Nsec3Config::default();
        let hash1 = hash_name_nsec3("example.com.", &config);
        let hash2 = hash_name_nsec3("example.com.", &config);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_name_nsec3_different_names() {
        let config = Nsec3Config::default();
        let hash1 = hash_name_nsec3("example.com.", &config);
        let hash2 = hash_name_nsec3("other.com.", &config);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_name_nsec3_with_salt() {
        let config = Nsec3Config {
            algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![0xAB, 0xCD],
        };
        let hash_no_salt = hash_name_nsec3(
            "example.com.",
            &Nsec3Config {
                algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: vec![],
            },
        );
        let hash_with_salt = hash_name_nsec3("example.com.", &config);
        assert_ne!(hash_no_salt, hash_with_salt);
    }

    #[test]
    fn test_hash_name_nsec3_with_iterations() {
        let config0 = Nsec3Config {
            algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
        };
        let config1 = Nsec3Config {
            algorithm: 1,
            flags: 0,
            iterations: 1,
            salt: vec![],
        };
        let hash0 = hash_name_nsec3("example.com.", &config0);
        let hash1 = hash_name_nsec3("example.com.", &config1);
        assert_ne!(hash0, hash1);
    }

    #[test]
    fn test_create_nsec3_owner_name_format() {
        let config = Nsec3Config::default();
        let hash = hash_name_nsec3("example.com.", &config);
        let owner = create_nsec3_owner_name("example.com.", &hash);
        assert_eq!(
            owner,
            format!("{}.example.com", base32_encode(&hash)),
            "the owner is base32(hash) + '.' + origin, with no length prefix"
        );
        let first = owner.split('.').next().unwrap();
        assert_eq!(
            first.len(),
            32,
            "a 20-octet SHA-1 hash encodes to 32 base32hex characters"
        );
        assert!(
            !first.chars().all(|c| c.is_ascii_digit()),
            "the first label is the hash, not the length of its base32 spelling"
        );
    }

    #[test]
    fn test_base32_encode_empty() {
        assert_eq!(base32_encode(&[]), "");
    }

    #[test]
    fn test_base32_encode_single_byte() {
        let encoded = base32_encode(&[0xFF]);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_base32_encode_multiple_bytes() {
        let encoded = base32_encode(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert!(!encoded.is_empty());
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_create_nsec_record_type_bitmap() {
        let nsec = create_nsec_record(
            "a.example.com.",
            "b.example.com.",
            &[1, 2, 5, 6, 15, 16, 28, 33],
        );
        assert!(!nsec.is_empty());
    }
}

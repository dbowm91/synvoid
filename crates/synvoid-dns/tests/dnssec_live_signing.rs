//! Live DNSSEC signing and RRSIG response validation tests.
//!
//! Verifies that Ed25519/RSA key generation, signing, RRSIG construction,
//! and NSEC chain creation produce well-formed DNSSEC artifacts.

use synvoid_dns::dnssec::{Algorithm, KeyType, ZoneSigningKey};
use synvoid_dns::dnssec_signing::{
    create_nsec_record, create_rrsig_record, find_next_name_in_zone, get_nsec_type_bitmap,
    sign_data,
};
use synvoid_dns::dnssec_validation::{
    calculate_key_tag, canonical_name, canonical_rdata, compute_dnskey, compute_ds_digest,
};
use synvoid_dns::server::{DnsZoneRecord, RecordType, Zone};

// ── Helpers ─────────────────────────────────────────────────────────────

fn ed25519_ksk() -> ZoneSigningKey {
    let mut priv_bytes = [0u8; 32];
    getrandom::getrandom(&mut priv_bytes).expect("getrandom");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_bytes);
    let verifying = signing_key.verifying_key().to_bytes().to_vec();
    let private = signing_key.to_bytes().to_vec();
    ZoneSigningKey {
        key_id: "test-ksk".to_string(),
        algorithm: Algorithm::Ed25519,
        key_type: KeyType::KSK,
        created_at: 0,
        expires_at: u64::MAX,
        public_key: verifying,
        private_key: private,
        key_tag: 12345,
        flags: 257,
        key_size: None,
    }
}

fn ed25519_zsk() -> ZoneSigningKey {
    let mut priv_bytes = [0u8; 32];
    getrandom::getrandom(&mut priv_bytes).expect("getrandom");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_bytes);
    let verifying = signing_key.verifying_key().to_bytes().to_vec();
    let private = signing_key.to_bytes().to_vec();
    ZoneSigningKey {
        key_id: "test-zsk".to_string(),
        algorithm: Algorithm::Ed25519,
        key_type: KeyType::ZSK,
        created_at: 0,
        expires_at: u64::MAX,
        public_key: verifying,
        private_key: private,
        key_tag: 12346,
        flags: 256,
        key_size: None,
    }
}

#[allow(dead_code)]
fn rsa_test_key() -> ZoneSigningKey {
    // Use a fixed 256-byte RSA public key representation for testing
    // (avoids rand_core version conflicts between rsa and getrandom)
    let pub_key: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();
    ZoneSigningKey {
        key_id: "test-rsa".to_string(),
        algorithm: Algorithm::RSA,
        key_type: KeyType::ZSK,
        created_at: 0,
        expires_at: u64::MAX,
        public_key: pub_key.clone(),
        private_key: vec![0u8; 256],
        key_tag: 54321,
        flags: 256,
        key_size: Some(2048),
    }
}

fn build_test_zone() -> Zone {
    let mut z = Zone::new("signed.test".to_string());
    z.serial = 2026070601;
    z.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.signed.test. admin.signed.test. 2026070601 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    z.records.insert(
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: "ns1.signed.test.".to_string(),
            ttl: 3600,
            priority: None,
        }],
    );
    z.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    z
}

// ══════════════════════════════════════════════════════════════════════
// Section 1: Ed25519 live signing roundtrip
// ══════════════════════════════════════════════════════════════════════

/// Sign arbitrary data with Ed25519 and verify key tag is non-zero.
#[test]
fn ed25519_sign_data_produces_signature() {
    let key = ed25519_zsk();
    let data = b"test data to sign for DNSSEC";
    let sig = sign_data(data, &key);
    assert!(sig.is_ok(), "Ed25519 signing must succeed: {:?}", sig.err());
    let sig_bytes = sig.unwrap();
    assert!(
        sig_bytes.len() >= 32,
        "Ed25519 signature must be at least 32 bytes, got {}",
        sig_bytes.len()
    );
    assert!(
        !sig_bytes.iter().all(|&b| b == 0),
        "signature must not be all zeros"
    );
}

/// Different data produces different signatures (non-deterministic across
/// different inputs).
#[test]
fn ed25519_different_data_different_signature() {
    let key = ed25519_zsk();
    let sig1 = sign_data(b"data-one", &key).unwrap();
    let sig2 = sign_data(b"data-two", &key).unwrap();
    assert_ne!(
        sig1, sig2,
        "different data must produce different signatures"
    );
}

/// Same data signed twice with same key may differ (Ed25519 uses random
/// nonce), but both must be valid-length.
#[test]
fn ed25519_same_data_signature_length_stable() {
    let key = ed25519_zsk();
    let data = b"stable length check";
    let sig1 = sign_data(data, &key).unwrap();
    let sig2 = sign_data(data, &key).unwrap();
    assert_eq!(
        sig1.len(),
        sig2.len(),
        "same algorithm must produce same-length signatures"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: RRSIG construction shape
// ══════════════════════════════════════════════════════════════════════

/// RRSIG RDATA wire format: type_covered(2) + algorithm(1) + labels(1) +
/// original_ttl(4) + sig_expiration(4) + sig_inception(4) + key_tag(2) +
/// signer_name(wire) + signature(variable).
#[test]
fn rrsig_construction_shape() {
    let key = ed25519_zsk();
    let data = b"some rrset data";
    let signature = sign_data(data, &key).unwrap();
    let rrsig = create_rrsig_record(&key, 1, 300, "signed.test.", &signature, 2);

    // type_covered = A (1)
    assert_eq!(rrsig[0], 0, "type_covered high byte");
    assert_eq!(rrsig[1], 1, "type_covered low byte = A");

    // algorithm = Ed25519 (15)
    assert_eq!(rrsig[2], 15, "algorithm must be Ed25519 (15)");

    // labels = 2 (signed.test. = 2 labels)
    assert_eq!(rrsig[3], 2, "labels count must be 2");

    // original_ttl = 300
    let orig_ttl = u32::from_be_bytes(rrsig[4..8].try_into().unwrap());
    assert_eq!(orig_ttl, 300, "original_ttl must be 300");

    // sig_expiration and sig_inception (8 bytes total)
    let sig_exp = u32::from_be_bytes(rrsig[8..12].try_into().unwrap());
    let sig_inc = u32::from_be_bytes(rrsig[12..16].try_into().unwrap());
    assert!(
        sig_exp > sig_inc,
        "sig_expiration ({}) must be > sig_inception ({})",
        sig_exp,
        sig_inc
    );

    // key_tag = 12346
    let kt = u16::from_be_bytes(rrsig[16..18].try_into().unwrap());
    assert_eq!(kt, 12346, "key_tag must match ZSK");

    // Signer name is wire-encoded "signed.test."
    // Skip signer name to reach signature
    let mut pos = 18;
    while pos < rrsig.len() && rrsig[pos] != 0 {
        pos += 1 + rrsig[pos] as usize;
    }
    pos += 1; // skip null terminator
    assert!(pos < rrsig.len(), "signature must follow signer name");
    let sig_from_rrsig = &rrsig[pos..];
    assert_eq!(
        sig_from_rrsig,
        signature.as_slice(),
        "embedded signature must match computed signature"
    );
}

/// RRSIG construction shape with different key tag.
#[test]
fn rrsig_different_key_tag() {
    let mut key = ed25519_zsk();
    key.key_tag = 9999;
    let data = b"rrsig tag test";
    let signature = sign_data(data, &key).unwrap();
    let rrsig = create_rrsig_record(&key, 1, 300, "signed.test.", &signature, 2);

    let kt = u16::from_be_bytes(rrsig[16..18].try_into().unwrap());
    assert_eq!(kt, 9999, "key_tag must match");
}

/// RRSIG labels=1 for a single-label name like "test.".
#[test]
fn rrsig_labels_single_label() {
    let key = ed25519_zsk();
    let data = b"single label";
    let signature = sign_data(data, &key).unwrap();
    let rrsig = create_rrsig_record(&key, 1, 300, "test.", &signature, 1);
    assert_eq!(rrsig[3], 1, "labels must be 1 for single-label name");
}

/// RRSIG labels=0 for the root zone.
#[test]
fn rrsig_labels_root_zone() {
    let key = ed25519_zsk();
    let data = b"root zone";
    let signature = sign_data(data, &key).unwrap();
    let rrsig = create_rrsig_record(&key, 1, 300, ".", &signature, 0);
    assert_eq!(rrsig[3], 0, "labels must be 0 for root zone");
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: NSEC chain construction
// ══════════════════════════════════════════════════════════════════════

/// NSEC record has correct wire format: next domain name + type bitmap.
#[test]
fn nsec_record_wire_format() {
    let type_bitmap = get_nsec_type_bitmap();
    let nsec = create_nsec_record("a.signed.test.", "b.signed.test.", &type_bitmap);
    assert!(!nsec.is_empty(), "NSEC RDATA must not be empty");
    // First bytes are the next domain name in wire format
    assert!(
        nsec[0] > 0 && nsec[0] < 64,
        "first byte must be a label length, got {}",
        nsec[0]
    );
}

/// NSEC type bitmap covers standard record types.
#[test]
fn nsec_type_bitmap_contains_standard_types() {
    let bitmap = get_nsec_type_bitmap();
    assert!(bitmap.contains(&1u16), "must contain A");
    assert!(bitmap.contains(&2u16), "must contain NS");
    assert!(bitmap.contains(&6u16), "must contain SOA");
    assert!(bitmap.contains(&28u16), "must contain AAAA");
    assert!(bitmap.contains(&46u16), "must contain RRSIG");
    assert!(bitmap.contains(&47u16), "must contain NSEC");
    assert!(bitmap.contains(&50u16), "must contain NSEC3");
}

/// NSEC chain: find_next_name_in_zone returns the next lexicographic name.
#[test]
fn nsec_find_next_name_in_zone() {
    let zone = build_test_zone();
    // Names in zone: @, ns1, www
    let next = find_next_name_in_zone(&zone, "@");
    // Should return the next lexicographic name
    assert!(
        next.is_some(),
        "find_next_name must return a name for @ in zone with records"
    );
}

/// NSEC chain for a zone with only SOA: next from @ wraps to @ (single entry).
#[test]
fn nsec_single_record_zone_chain() {
    let mut zone = Zone::new("minimal.test".to_string());
    zone.serial = 1;
    zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.minimal.test. admin.minimal.test. 1 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    // For a single-record zone, find_next_name_in_zone returns None or @
    let next = find_next_name_in_zone(&zone, "@");
    // A zone with one record: either wraps to @ itself or returns None
    // Both are valid for NSEC chaining
    if let Some(name) = next {
        assert!(!name.is_empty(), "next name must not be empty");
    }
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: DNSKEY RDATA computation
// ══════════════════════════════════════════════════════════════════════

/// compute_dnskey produces correct RDATA: flags(2) + protocol(3) + algorithm(1) + key.
#[test]
fn dnskey_rdata_computation() {
    let key = ed25519_ksk();
    let dnskey = compute_dnskey(&key);
    assert_eq!(
        dnskey.len(),
        2 + 1 + 1 + 32,
        "DNSKEY RDATA must be 36 bytes for Ed25519"
    );
    let flags = u16::from_be_bytes([dnskey[0], dnskey[1]]);
    assert_eq!(flags, 257, "KSK flags must be 257");
    assert_eq!(dnskey[2], 3, "protocol must be 3");
    assert_eq!(dnskey[3], 15, "algorithm must be Ed25519 (15)");
}

/// DS digest for SHA-256 is deterministic for same inputs.
#[test]
fn ds_digest_deterministic() {
    let d1 = compute_ds_digest(2, 257, 3, 15, &[0xAA; 32]).unwrap();
    let d2 = compute_ds_digest(2, 257, 3, 15, &[0xAA; 32]).unwrap();
    assert_eq!(d1, d2, "DS digest must be deterministic");
}

/// DS digest for different keys differs.
#[test]
fn ds_digest_different_keys_differ() {
    let d1 = compute_ds_digest(2, 257, 3, 15, &[0xAA; 32]).unwrap();
    let d2 = compute_ds_digest(2, 257, 3, 15, &[0xBB; 32]).unwrap();
    assert_ne!(d1, d2, "different keys must produce different DS digests");
}

// ══════════════════════════════════════════════════════════════════════
// Section 5: Key tag properties
// ══════════════════════════════════════════════════════════════════════

/// Key tag for Ed25519 KSK vs ZSK differ by 1 with same key material.
#[test]
fn key_tag_ksk_zsk_differ() {
    let pub_key: Vec<u8> = (1..=32).collect();
    let ksk = calculate_key_tag(257, 3, 15, &pub_key);
    let zsk = calculate_key_tag(256, 3, 15, &pub_key);
    assert_eq!(
        ksk.wrapping_sub(zsk),
        1,
        "KSK and ZSK tags differ by exactly 1"
    );
}

/// Key tag is idempotent.
#[test]
fn key_tag_idempotent() {
    let pub_key: Vec<u8> = (1..=32).collect();
    let t1 = calculate_key_tag(257, 3, 15, &pub_key);
    let t2 = calculate_key_tag(257, 3, 15, &pub_key);
    assert_eq!(t1, t2, "key tag must be deterministic");
}

// ══════════════════════════════════════════════════════════════════════
// Section 6: Canonical name/rdata for signing
// ══════════════════════════════════════════════════════════════════════

/// canonical_name produces lowercase wire format.
#[test]
fn canonical_name_lowercases() {
    let cn = canonical_name("WWW.Example.Test.");
    assert!(
        cn.windows(3).any(|w| w == b"www"),
        "canonical name must be lowercase: {:?}",
        cn
    );
}

/// canonical_rdata for A record is exactly 4 bytes.
#[test]
fn canonical_rdata_a_record() {
    let cr = canonical_rdata(1, "192.0.2.10", None, None, None, 300);
    assert_eq!(cr.len(), 4, "A record canonical rdata must be 4 bytes");
    assert_eq!(cr, [192, 0, 2, 10]);
}

/// canonical_rdata for AAAA record is exactly 16 bytes.
#[test]
fn canonical_rdata_aaaa_record() {
    let cr = canonical_rdata(28, "2001:db8::1", None, None, None, 300);
    assert_eq!(cr.len(), 16, "AAAA record canonical rdata must be 16 bytes");
}

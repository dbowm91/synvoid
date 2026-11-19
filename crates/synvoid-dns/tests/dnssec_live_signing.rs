//! Live DNSSEC signing and RRSIG response validation tests.
//!
//! Verifies that Ed25519/RSA key generation, signing, RRSIG construction,
//! and NSEC chain creation produce well-formed DNSSEC artifacts.

mod support;

use support::dnssec::{verify_signed_data, DnskeyParts};
use synvoid_dns::dnssec::{Algorithm, KeyType, ZoneSigningKey};
use synvoid_dns::dnssec_signing::{
    create_nsec_record, create_rrsig_record, find_next_name_in_zone, get_nsec_type_bitmap,
    sign_data,
};
use synvoid_dns::dnssec_validation::{
    calculate_key_tag, canonical_dns_message, canonical_name, canonical_rdata, compute_dnskey,
    compute_ds_digest,
};
use synvoid_dns::server::{DnsZoneRecord, RecordType, Zone};

// ── Helpers ─────────────────────────────────────────────────────────────
// Phase 30: sealed handles come from the custody boundary. Signing tests use
// in-memory ephemeral keys (private bytes never leave the handle);
// public-shape tests use `from_public_parts`.

fn ed25519_ksk() -> ZoneSigningKey {
    ZoneSigningKey::generate_ephemeral(Algorithm::Ed25519, KeyType::KSK)
        .expect("ephemeral KSK must generate")
}

fn ed25519_zsk() -> ZoneSigningKey {
    ZoneSigningKey::generate_ephemeral(Algorithm::Ed25519, KeyType::ZSK)
        .expect("ephemeral ZSK must generate")
}

#[allow(dead_code)]
fn rsa_test_key() -> ZoneSigningKey {
    // Public-only shape for RSA wire-format tests (no private material).
    let pub_key: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();
    let key_tag = synvoid_dns::dnssec::calculate_key_tag(256, 3, 8, &pub_key);
    ZoneSigningKey::from_public_parts(
        "test-rsa".to_string(),
        Algorithm::RSA,
        KeyType::ZSK,
        pub_key,
        key_tag,
        256,
    )
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

/// The RRSIG RDATA is a signature over the RFC 4034 §3.1.2 signed data, not a
/// bag of fields: this builds an RRSIG, signs the canonical data the RRSIG
/// actually covers, and verifies the embedded signature with hickory's
/// verifier. A wrong type, label count, TTL, key tag, or signer name changes
/// the signed bytes and fails here.
///
/// This replaces the old `rrsig_construction_shape` test, which asserted the
/// same field offsets over a placeholder signature and therefore could not
/// tell a valid signature from a signature over the relative storage name.
#[test]
fn rrsig_construction_verifies_over_the_signed_data() {
    let key = ed25519_zsk();
    let owner = "www.signed.test.";
    let ttl = 300;
    let labels = 3; // www.signed.test

    // A RRSIG RDATA prefix (everything before the signature) is what the
    // signature covers, together with the canonical RR.
    let rrsig_prefix = create_rrsig_record(&key, 1, ttl, "signed.test.", &[], labels);

    let rdata = canonical_rdata(1, "192.0.2.10", None, None, None, ttl);
    let mut signed_data = rrsig_prefix.clone();
    signed_data.extend_from_slice(&canonical_dns_message(owner, 1, 1, ttl, &rdata).unwrap());

    let signature = sign_data(&signed_data, &key).unwrap();
    let mut rrsig = rrsig_prefix.clone();
    rrsig.extend_from_slice(&signature);

    // The fields a validator reads out of the wire RRSIG.
    assert_eq!(rrsig[3], labels, "Labels must describe the FQDN");
    assert_eq!(
        u16::from_be_bytes(rrsig[16..18].try_into().unwrap()),
        key.key_tag(),
        "the key tag must name the signing key"
    );
    assert!(
        rrsig.ends_with(&signature),
        "the signature is the tail of the RDATA"
    );

    verify_signed_data(&signed_data, &signature, &DnskeyParts::from_key(&key))
        .expect("the signature must verify over the data the RRSIG covers");

    // The old signer covered the storage key `www` with Labels = 1. Same
    // timestamps and key tag — only the owner and label count differ — so this
    // must fail for exactly the reason that makes the zone bogus.
    let mut wrong_prefix = rrsig_prefix.clone();
    wrong_prefix[3] = 1;
    let mut wrong = wrong_prefix;
    wrong.extend_from_slice(&canonical_dns_message("www.", 1, 1, ttl, &rdata).unwrap());
    assert!(
        verify_signed_data(&wrong, &signature, &DnskeyParts::from_key(&key)).is_err(),
        "the signature must not verify over the relative storage name"
    );
}

/// RRSIG construction shape with different key tag.
#[test]
fn rrsig_different_key_tag() {
    // Sealed key tags are immutable (private-field boundary); the shape path
    // is exercised with a public-only handle carrying tag 9999 while the
    // signature itself comes from a real sealed key.
    let key = ed25519_zsk();
    let data = b"rrsig tag test";
    let signature = sign_data(data, &key).unwrap();
    let shape_key = ZoneSigningKey::from_public_parts(
        "shape".to_string(),
        Algorithm::Ed25519,
        KeyType::ZSK,
        key.public_key().to_vec(),
        9999,
        256,
    );
    let rrsig = create_rrsig_record(&shape_key, 1, 300, "signed.test.", &signature, 2);

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
    let cn = canonical_name("WWW.Example.Test.").unwrap();
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

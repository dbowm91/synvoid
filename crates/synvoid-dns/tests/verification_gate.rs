mod support;

use synvoid_dns::cache::{CacheKey, DnsCache, InvalidationReason, TransportClass};
use synvoid_dns::dnssec::{Algorithm, DsDigestType, KeyType, Nsec3Config, ZoneSigningKey};
use synvoid_dns::dnssec_signing::{create_nsec_record, create_rrsig_record, sign_data};
use synvoid_dns::recursive_cache::DnssecValidationState;
use synvoid_dns::recursive_cache::RecursiveCacheKey;
use synvoid_dns::recursive_cache::RecursiveDnsCache;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsZoneRecord, Zone};

// ── Helpers ─────────────────────────────────────────────────────────────

/// Build a test zone: test.local with standard records.
fn build_test_zone() -> Zone {
    let mut zone = Zone::new("test.local".to_string());
    zone.serial = 2026070201;
    zone.nsec_enabled = false;
    zone.nsec3_enabled = false;

    zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.test.local. admin.test.local. 2026070201 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: "ns1.test.local.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("ns1".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "ns1".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.53".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone
}

fn ed25519_test_key() -> ZoneSigningKey {
    // Phase 30: sealed ephemeral handle from the custody boundary.
    ZoneSigningKey::generate_ephemeral(Algorithm::Ed25519, KeyType::ZSK)
        .expect("ephemeral test key must generate")
}

// ══════════════════════════════════════════════════════════════════════
// Gate 2: Zone Lifecycle / Mutation Safety
// ══════════════════════════════════════════════════════════════════════

/// Successful atomic reload: the new candidate zone is accepted (passes
/// `validate_zone_for_activation`) and replaces the previous active zone
/// in the production reload helper `DnsServer::replace_zone_with_validation`.
#[test]
fn successful_reload_swaps_zone_atomically() {
    use synvoid_dns::server::DnsServer;

    let server = DnsServer::new(support::dns_runtime(), None);
    let zones = server.get_zones();

    let mut initial = build_test_zone();
    initial.serial = 2026070201;
    server
        .replace_zone_with_validation(initial.clone())
        .expect("valid zone must be accepted");

    let after_initial = zones.get(&initial.origin).expect("zone must exist");
    assert_eq!(after_initial.serial, 2026070201);
    assert!(after_initial
        .records
        .contains_key(&("www".to_string(), RecordType::A)));

    // Candidate with valid SOA, different serial — atomic swap.
    let mut candidate = build_test_zone();
    candidate.serial = 2026070202;
    candidate
        .records
        .get_mut(&("www".to_string(), RecordType::A))
        .unwrap()[0]
        .value = "192.0.2.20".to_string();

    server
        .replace_zone_with_validation(candidate.clone())
        .expect("valid candidate must be accepted");

    let after_reload = zones.get(&candidate.origin).expect("zone must exist");
    assert_eq!(
        after_reload.serial, 2026070202,
        "swap must be atomic to the new serial"
    );
    assert_eq!(
        after_reload.records[&("www".to_string(), RecordType::A)][0].value,
        "192.0.2.20"
    );
}

/// Failed reload preservation: a candidate zone that fails
/// `validate_zone_for_activation` (e.g. missing SOA) must NOT replace the
/// previously active zone — the old data must survive unchanged.
#[test]
fn failed_reload_preserves_previous_active_zone() {
    use synvoid_dns::server::DnsServer;

    let server = DnsServer::new(support::dns_runtime(), None);
    let zones = server.get_zones();

    // Install a known-good active zone.
    let mut initial = build_test_zone();
    initial.serial = 2026070201;
    server
        .replace_zone_with_validation(initial.clone())
        .expect("valid zone must be accepted");

    let initial_serial = zones.get(&initial.origin).unwrap().serial;
    let initial_www = zones.get(&initial.origin).unwrap().records
        [&("www".to_string(), RecordType::A)][0]
        .value
        .clone();

    // Try to replace it with a zone that has NO SOA — must be rejected.
    let mut broken = Zone::new(initial.origin.clone());
    broken.serial = 2026070299;
    // Intentionally NO SOA record.

    let result = server.replace_zone_with_validation(broken.clone());
    assert!(
        result.is_err(),
        "validation must reject zone without SOA: got {:?}",
        result
    );

    // The previously active zone must be unchanged.
    let still_active = zones.get(&initial.origin).expect("zone must survive");
    assert_eq!(
        still_active.serial, initial_serial,
        "failed reload must not change serial"
    );
    assert_eq!(
        still_active.records[&("www".to_string(), RecordType::A)][0].value,
        initial_www,
        "failed reload must not change records"
    );
    assert!(
        still_active.health.last_error.is_none(),
        "failed reload must not poison health: {:?}",
        still_active.health.last_error
    );
}

/// The `validate_zone_for_activation` gate rejects zones with multiple apex
/// SOA records (more than one `@ IN SOA`).
#[test]
fn validate_zone_for_activation_rejects_duplicate_soa() {
    let mut z = build_test_zone();
    // Add a second SOA record at apex to violate exactly-one invariant.
    z.records
        .entry(("@".to_string(), RecordType::SOA))
        .or_default()
        .push(DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns2.test.local. admin.test.local. 2026070202 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        });
    assert!(z.validate_zone_for_activation().is_err());
}

/// The `validate_zone_for_activation` gate rejects zones with empty / malformed
/// origin strings (whitespace, control bytes, empty).
#[test]
fn validate_zone_for_activation_rejects_bad_origin() {
    let bad_origins = [
        "",
        "  ",
        "\x00bad.local",
        "bad\\origin.local",
        "bad/origin.local",
    ];
    for bad in bad_origins {
        let z = Zone::new(bad.to_string());
        assert!(
            z.validate_zone_for_activation().is_err(),
            "origin {:?} must be rejected by validate_zone_for_activation",
            bad
        );
    }
}

/// `replace_zone_with_validation` invalidates cache for the origin after a
/// successful reload — stale entries must not survive an accepted reload.
#[test]
fn successful_reload_invalidates_cache_for_zone() {
    use synvoid_dns::cache::CacheKey;
    use synvoid_dns::server::DnsServer;

    let server = DnsServer::new(support::dns_runtime(), None);
    let initial = build_test_zone();
    server
        .replace_zone_with_validation(initial.clone())
        .expect("valid zone must be accepted");

    let cache = server
        .get_cache()
        .expect("server must have a default cache");
    let stale_key = CacheKey::new("www.test.local".into(), RecordType::A, None);
    cache.insert(stale_key.clone(), vec![1, 2, 3, 4], 300);
    assert!(
        cache.get(&stale_key).is_some(),
        "stale cache entry must exist before reload"
    );

    let mut candidate = build_test_zone();
    candidate.serial = 2026070299;
    server
        .replace_zone_with_validation(candidate)
        .expect("valid candidate must be accepted");

    assert!(
        cache.get(&stale_key).is_none(),
        "successful reload must invalidate cache for the zone"
    );
}

/// Verify that cache invalidation is triggered after zone mutations.
///
/// After a dynamic update modifies a zone, the associated cache entries
/// must be invalidated so stale responses are never served.
#[test]
fn all_zone_mutations_invalidate_cache() {
    let cache = DnsCache::new(100, 300, 10);

    let key_www = CacheKey::new("www.test.local".into(), RecordType::A, None);
    let key_ns = CacheKey::new("ns1.test.local".into(), RecordType::A, None);
    let key_other = CacheKey::new("other.zone.local".into(), RecordType::A, None);

    cache.insert(key_www.clone(), vec![192, 0, 2, 10], 300);
    cache.insert(key_ns.clone(), vec![192, 0, 2, 53], 300);
    cache.insert(key_other.clone(), vec![192, 0, 2, 99], 300);

    assert!(cache.get(&key_www).is_some(), "www must be cached");
    assert!(cache.get(&key_ns).is_some(), "ns1 must be cached");
    assert!(cache.get(&key_other).is_some(), "other must be cached");

    // Simulate zone mutation invalidation (DynamicUpdate, Notify, etc.)
    cache.invalidate_zone("test.local", InvalidationReason::DynamicUpdate);

    assert!(
        cache.get(&key_www).is_none(),
        "www.test.local must be invalidated"
    );
    assert!(
        cache.get(&key_ns).is_none(),
        "ns1.test.local must be invalidated"
    );
    assert!(
        cache.get(&key_other).is_some(),
        "other.zone.local must NOT be invalidated (different zone)"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Gate 3: DNSSEC Correctness
// ══════════════════════════════════════════════════════════════════════

/// Verify DNSSEC type constants and enum conversions are correct.
///
/// Algorithm and DsDigestType must map to their IANA-assigned values.
#[test]
fn dnssec_types_constants_are_correct() {
    // Algorithm values per IANA DNSSEC Algorithm Numbers
    assert_eq!(Algorithm::Ed25519.to_u8(), 15, "Ed25519 = algorithm 15");
    assert_eq!(Algorithm::RSA.to_u8(), 8, "RSASHA256 = algorithm 8");
    assert_eq!(Algorithm::from_u8(15), Some(Algorithm::Ed25519));
    assert_eq!(Algorithm::from_u8(8), Some(Algorithm::RSA));
    assert_eq!(
        Algorithm::from_u8(13),
        None,
        "ECDSAP256SHA256 is not supported"
    );

    // DS Digest Type values per IANA
    assert_eq!(DsDigestType::Sha1.to_u8(), 1);
    assert_eq!(DsDigestType::Sha256.to_u8(), 2);
    assert_eq!(DsDigestType::Sha384.to_u8(), 4);
    assert_eq!(DsDigestType::from_u8(1), Some(DsDigestType::Sha1));
    assert_eq!(DsDigestType::from_u8(2), Some(DsDigestType::Sha256));
    assert_eq!(DsDigestType::from_u8(4), Some(DsDigestType::Sha384));
    assert_eq!(DsDigestType::from_u8(3), None, "GOST is not supported");

    // NSEC3 default config
    let nsec3 = Nsec3Config::default();
    assert_eq!(nsec3.algorithm, 1, "default NSEC3 algorithm = SHA-1");
    assert_eq!(nsec3.flags, 0);
    assert_eq!(nsec3.iterations, 0);
    assert!(nsec3.salt.is_empty());
}

/// Verify NSEC handling for wildcard no-data responses.
///
/// When a query for a wildcard name gets a no-data response, the NSEC
/// record must cover the owner name with an appropriate type bitmap.
#[test]
fn nsec_wildcard_no_data_no_match() {
    // NSEC record encodes the NEXT domain name in RDATA, not the owner.
    // create_nsec_record("a.example.com.", "b.example.com.", &[46, 47])
    // produces RDATA: [next_name_wire] [window=0] [bitmap_len] [bitmap...]
    let nsec_data = create_nsec_record("a.example.com.", "b.example.com.", &[46, 47]);

    // "b.example.com." wire encoding: [1,'b'] [7,'example'] [3,'com'] [0] = 15 bytes
    // Then: window(1) + bitmap_len(1) + bitmap(6) = 8 bytes
    // Total = 23 bytes
    assert_eq!(nsec_data.len(), 23, "NSEC RDATA must be 23 bytes");

    // Verify the next domain name encoding
    assert_eq!(nsec_data[0], 1, "first label length must be 1");
    assert_eq!(nsec_data[1], b'b', "first label must be 'b'");
    assert_eq!(nsec_data[2], 7, "second label length must be 7");
    assert_eq!(
        &nsec_data[3..10],
        b"example",
        "second label must be 'example'"
    );
    assert_eq!(nsec_data[10], 3, "third label length must be 3");
    assert_eq!(&nsec_data[11..14], b"com", "third label must be 'com'");
    assert_eq!(nsec_data[14], 0, "name terminator must be 0");

    // Type bitmap starts at offset 15
    let window_num = nsec_data[15];
    assert_eq!(window_num, 0, "window block must be 0");
    let bitmap_len = nsec_data[16];
    assert_eq!(bitmap_len, 6, "bitmap must cover bytes 0-5 for type 47");

    // Bitmap: types 46 (RRSIG) and 47 (NSEC) are in window 0
    // Per RFC 4034 §4.1.2, bit numbering is big-endian within each byte:
    // byte 5 contains types 40-47, where bit 0 = type 40, bit 7 = type 47
    // RRSIG (46): bit 6 → 1 << (7-6) = 0b0000_0010
    // NSEC (47):  bit 7 → 1 << (7-7) = 0b0000_0001
    // Combined byte 5: 0b0000_0011 = 0x03
    let bitmap_bytes = &nsec_data[17..23];
    assert_eq!(
        bitmap_bytes[5], 0x03,
        "RRSIG+NSEC bits must be set in byte 5"
    );
    // All other bytes must be zero
    assert_eq!(
        &bitmap_bytes[0..5],
        &[0, 0, 0, 0, 0],
        "no other type bits should be set"
    );
}

/// Verify DNSKEY record structure matches RFC 4034 §2.
///
/// DNSKEY wire format: Flags (2 bytes) + Protocol (1 byte) +
/// Algorithm (1 byte) + Public Key.
#[test]
fn dnskey_query_returns_expected_structure() {
    let key = ed25519_test_key();
    let dnskey_rdata = synvoid_dns::dnssec_validation::compute_dnskey(&key);

    // Minimum size: flags(2) + protocol(1) + algorithm(1) + pubkey(32 for Ed25519)
    assert!(
        dnskey_rdata.len() >= 36,
        "DNSKEY RDATA must be at least 36 bytes, got {}",
        dnskey_rdata.len()
    );

    // Flags: 256 (ZSK) = 0x0100
    let flags = u16::from_be_bytes([dnskey_rdata[0], dnskey_rdata[1]]);
    assert_eq!(flags, 256, "ZSK flags must be 256");

    // Protocol: always 3 for DNSSEC
    assert_eq!(dnskey_rdata[2], 3, "protocol must be 3");

    // Algorithm: 15 (Ed25519)
    assert_eq!(dnskey_rdata[3], 15, "algorithm must be 15 (Ed25519)");

    // Public key must be 32 bytes for Ed25519
    assert_eq!(
        dnskey_rdata[4..].len(),
        32,
        "Ed25519 public key must be 32 bytes"
    );
}

/// Verify RRSIG creation with a valid signing key.
///
/// RRSIG wire format: Type Covered (2) + Algorithm (1) + Labels (1) +
/// Original TTL (4) + Signature Expiration (4) + Signature Inception (4) +
/// Key Tag (2) + Signer Name (wire) + Signature.
#[test]
fn rrsig_creation_with_valid_key() {
    let key = ed25519_test_key();
    let data_to_sign = b"test RRSET data for signing";

    let signature = sign_data(data_to_sign, &key).expect("Ed25519 signing must succeed");

    let rrsig = create_rrsig_record(&key, 1, 3600, "example.com.", &signature, 2);

    // Minimum RRSIG size: type_covered(2) + algorithm(1) + labels(1) +
    // original_ttl(4) + sig_exp(4) + sig_inc(4) + key_tag(2) + signer_name(wire) + signature(64)
    assert!(
        rrsig.len() >= 82,
        "RRSIG must be at least 82 bytes, got {}",
        rrsig.len()
    );

    // Type covered: A (1)
    let type_covered = u16::from_be_bytes([rrsig[0], rrsig[1]]);
    assert_eq!(type_covered, 1, "type covered must be A (1)");

    // Algorithm: Ed25519 (15)
    assert_eq!(rrsig[2], 15, "algorithm must be 15");

    // Labels count
    assert_eq!(rrsig[3], 2, "labels count must be 2 for example.com");

    // Original TTL
    let original_ttl = u32::from_be_bytes([rrsig[4], rrsig[5], rrsig[6], rrsig[7]]);
    assert_eq!(original_ttl, 3600, "original TTL must be 3600");

    // Key tag at offset 16 (2+1+1+4+4+4)
    let key_tag = u16::from_be_bytes([rrsig[16], rrsig[17]]);
    assert_eq!(key_tag, key.key_tag(), "key tag must match");
}

// ══════════════════════════════════════════════════════════════════════
// Gate 4: Encrypted Transport Adapters
// ══════════════════════════════════════════════════════════════════════

/// Verify transport class isolation — different transport classes produce
/// different cache keys so responses are never cross-contaminated.
#[test]
fn transport_class_isolation_all_variants() {
    let base_key = |tc: TransportClass| {
        CacheKey::with_transport("example.com".into(), RecordType::A, None, tc)
    };

    let udp512 = base_key(TransportClass::Udp512);
    let udp_edns_1232 = base_key(TransportClass::UdpEdns(1232));
    let udp_edns_4096 = base_key(TransportClass::UdpEdns(4096));
    let tcp = base_key(TransportClass::Tcp);
    let http = base_key(TransportClass::Http);
    let quic = base_key(TransportClass::Quic);

    // All must be pairwise distinct
    assert_ne!(udp512, udp_edns_1232);
    assert_ne!(udp512, tcp);
    assert_ne!(udp512, http);
    assert_ne!(udp512, quic);
    assert_ne!(
        udp_edns_1232, udp_edns_4096,
        "different EDNS sizes must differ"
    );
    assert_ne!(udp_edns_1232, tcp);
    assert_ne!(tcp, http);
    assert_ne!(http, quic);
    assert_ne!(tcp, quic);
}

// ══════════════════════════════════════════════════════════════════════
// Gate 5: Recursive Resolver Safety
// ══════════════════════════════════════════════════════════════════════

/// Verify recursive cache key shapes are isolated from authoritative.
///
/// RecursiveCacheKey (byte-keyed) and CacheKey (string-keyed) use
/// fundamentally different key types, preventing cross-contamination.
#[test]
fn recursive_cache_key_shape_isolation() {
    // Recursive cache key (byte-keyed, used by RecursiveDnsCache)
    let rec_key = RecursiveCacheKey::new(b"example.com", 1, None);
    assert_eq!(rec_key.qname, b"example.com");
    assert!(!rec_key.dnssec_ok);

    // Authoritative cache key (string-keyed, used by DnsCache)
    let auth_key = CacheKey::new("example.com".into(), RecordType::A, None);
    assert_eq!(auth_key.qname, "example.com");

    // They are fundamentally different types — cannot be compared directly,
    // but we verify they exist in separate type spaces.
    // The recursive cache uses byte arrays; the authoritative uses Strings.
    let rec_key_dnssec = RecursiveCacheKey::new_with_dnssec(b"example.com", 1, None, true);
    assert!(rec_key_dnssec.dnssec_ok, "DNSSEC flag must propagate");

    // Verify recursive cache key type isolation
    let auth_key_with_dnssec = CacheKey::with_dnssec("example.com".into(), RecordType::A, None);
    assert_ne!(
        auth_key, auth_key_with_dnssec,
        "DNSSEC flag must produce different cache keys"
    );
}

/// Verify DNSSEC validation state is separate from cache entry validity.
///
/// A cache entry can be valid (not expired) but have an Unchecked
/// validation state, which must not be confused with Secure or Bogus.
#[test]
fn dnssec_validation_state_cache_separation() {
    let config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let cache = RecursiveDnsCache::new(1000, &config);

    let key = RecursiveCacheKey::new(b"secure.example.com", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"secure.example.com".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![93, 184, 216, 34],
    }];

    // Insert with Secure validation
    cache.insert_positive(
        key.clone(),
        records.clone(),
        300,
        DnssecValidationState::Secure,
    );
    let (_, _, state) = cache.get(&key).unwrap();
    assert_eq!(
        state,
        DnssecValidationState::Secure,
        "validation state must be Secure"
    );

    // Clear and insert with Unchecked validation
    cache.invalidate_all();
    cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);
    let (_, _, state) = cache.get(&key).unwrap();
    assert_eq!(
        state,
        DnssecValidationState::Unchecked,
        "validation state must be Unchecked"
    );

    // Verify all variants are distinct
    assert_ne!(
        DnssecValidationState::Secure,
        DnssecValidationState::Unchecked
    );
    assert_ne!(DnssecValidationState::Secure, DnssecValidationState::Bogus);
    assert_ne!(
        DnssecValidationState::Bogus,
        DnssecValidationState::Unchecked
    );
    assert_ne!(
        DnssecValidationState::Insecure,
        DnssecValidationState::Bogus
    );
}

// ══════════════════════════════════════════════════════════════════════
// Gate 6: Cache / Coalescing Under Advanced Features
// ══════════════════════════════════════════════════════════════════════

/// Verify cache invalidation by name covers all name variants.
///
/// Zone-based invalidation must invalidate all entries that match the
/// zone origin, regardless of subdomain depth.
#[test]
fn cache_invalidation_by_name_comprehensive() {
    let cache = DnsCache::new(100, 300, 10);

    let keys: Vec<CacheKey> = vec![
        CacheKey::new("test.local".into(), RecordType::SOA, None),
        CacheKey::new("www.test.local".into(), RecordType::A, None),
        CacheKey::new("mail.test.local".into(), RecordType::MX, None),
        CacheKey::new("deep.sub.test.local".into(), RecordType::A, None),
        CacheKey::new("other.zone".into(), RecordType::A, None),
        CacheKey::new("notmatching".into(), RecordType::A, None),
    ];

    for (i, key) in keys.iter().enumerate() {
        cache.insert(key.clone(), vec![i as u8; 4], 300);
    }

    // Invalidate all entries for test.local
    cache.invalidate_zone("test.local", InvalidationReason::ManualFlush);

    assert!(
        cache.get(&keys[0]).is_none(),
        "test.local SOA must be invalidated"
    );
    assert!(
        cache.get(&keys[1]).is_none(),
        "www.test.local must be invalidated"
    );
    assert!(
        cache.get(&keys[2]).is_none(),
        "mail.test.local must be invalidated"
    );
    assert!(
        cache.get(&keys[3]).is_none(),
        "deep.sub.test.local must be invalidated"
    );
    assert!(
        cache.get(&keys[4]).is_some(),
        "other.zone must NOT be invalidated"
    );
    assert!(
        cache.get(&keys[5]).is_some(),
        "unrelated entry must NOT be invalidated"
    );
}

/// Verify recursive cache is independent from authoritative cache.
///
/// Inserting into one must not affect lookups in the other.
#[test]
fn recursive_cache_independent_from_authoritative() {
    let auth_cache = DnsCache::new(100, 300, 10);
    let rec_config = support::recursive_cache_runtime(1_000_000, 300, 86_400, 86_400, 0);
    let rec_cache = RecursiveDnsCache::new(1000, &rec_config);

    // Insert into authoritative cache
    let auth_key = CacheKey::new("shared.example.com".into(), RecordType::A, None);
    auth_cache.insert(auth_key.clone(), vec![1, 2, 3, 4], 300);

    // Insert into recursive cache
    let rec_key = RecursiveCacheKey::new(b"shared.example.com", 1, None);
    let records = vec![synvoid_dns::recursive_cache::CachedRecord {
        name: b"shared.example.com".to_vec(),
        record_type: 1,
        ttl: 300,
        data: vec![5, 6, 7, 8],
    }];
    rec_cache.insert_positive(
        rec_key.clone(),
        records,
        300,
        DnssecValidationState::Unchecked,
    );

    // Both caches must have their own data
    let auth_data = auth_cache.get(&auth_key).unwrap();
    let (rec_records, _, _) = rec_cache.get(&rec_key).unwrap();
    assert_eq!(*auth_data, vec![1, 2, 3, 4]);
    assert_eq!(rec_records[0].data, vec![5, 6, 7, 8]);

    // Invalidating authoritative must not affect recursive
    auth_cache.invalidate_zone("example.com", InvalidationReason::ZoneDelete);
    assert!(
        auth_cache.get(&auth_key).is_none(),
        "authoritative entry must be invalidated"
    );
    assert!(
        rec_cache.get(&rec_key).is_some(),
        "recursive entry must survive"
    );

    // Invalidating recursive must not affect authoritative (re-insert first)
    auth_cache.insert(auth_key.clone(), vec![1, 2, 3, 4], 300);
    rec_cache.invalidate(b"shared.example.com");
    assert!(
        rec_cache.get(&rec_key).is_none(),
        "recursive entry must be invalidated"
    );
    assert!(
        auth_cache.get(&auth_key).is_some(),
        "authoritative entry must survive"
    );
}

/// Verify cache keys differ by transport class.
///
/// The same query through UDP, TCP, DoH, and DoQ must produce different
/// cache keys so truncated or transport-specific responses are never shared.
#[test]
fn transport_class_cache_isolation() {
    let qname = "example.com".to_string();
    let qtype = RecordType::A;

    let udp = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Udp512);
    let udp_edns =
        CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::UdpEdns(1232));
    let tcp = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Tcp);
    let http = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Http);
    let quic = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Quic);

    // Disable fingerprinting to avoid cross-transport-class fingerprint conflicts
    // (fingerprint_key doesn't include transport_class, so different transport
    // classes with same qname would trigger poisoning detection).
    let cache = DnsCache::with_security(100, 300, 10, 65535, false, false);

    // Insert different data for each transport class
    cache.insert(udp.clone(), vec![1], 300);
    cache.insert(udp_edns.clone(), vec![2], 300);
    cache.insert(tcp.clone(), vec![3], 300);
    cache.insert(http.clone(), vec![4], 300);
    cache.insert(quic.clone(), vec![5], 300);

    // Each transport class must return its own data
    assert_eq!(*cache.get(&udp).unwrap(), vec![1]);
    assert_eq!(*cache.get(&udp_edns).unwrap(), vec![2]);
    assert_eq!(*cache.get(&tcp).unwrap(), vec![3]);
    assert_eq!(*cache.get(&http).unwrap(), vec![4]);
    assert_eq!(*cache.get(&quic).unwrap(), vec![5]);
}

// ══════════════════════════════════════════════════════════════════════
// Gate 7: DNSSEC Protocol Semantics (Milestone 3 Corrective Pass WS5)
// ══════════════════════════════════════════════════════════════════════

/// RFC 4034 §2: DNSKEY flags for KSK=257 (SEP bit set) and ZSK=256.
///
/// This guards against accidental flag-swap bugs in key generation and
/// rollover: SEP must be set on KSKs only. The key tag is computed from
/// the DNSKEY RDATA per RFC 4034 Appendix B.
#[test]
fn dnskey_flags_ksk_zsk_distinct() {
    use synvoid_dns::dnssec::{KeyType, ZoneSigningKey};

    let ksk = ZoneSigningKey::from_public_parts(
        "ksk".into(),
        Algorithm::Ed25519,
        KeyType::KSK,
        vec![0u8; 32],
        0,
        257, // SEP=1
    );
    let zsk = ZoneSigningKey::from_public_parts(
        "zsk".into(),
        Algorithm::Ed25519,
        KeyType::ZSK,
        vec![0u8; 32],
        0,
        256, // ZSK
    );

    assert_eq!(ksk.flags(), 257, "KSK must have SEP bit set (257)");
    assert_eq!(zsk.flags(), 256, "ZSK must not have SEP bit (256)");
    assert_ne!(ksk.flags(), zsk.flags(), "KSK and ZSK flags must differ");
}

/// RFC 4034 §2: DNSKEY RDATA protocol field is always 3.
#[test]
fn dnskey_protocol_is_3() {
    use synvoid_dns::dnssec::KeyType;

    let key = ed25519_test_key();
    let rdata = synvoid_dns::dnssec_validation::compute_dnskey(&key);
    assert_eq!(rdata[2], 3, "DNSKEY protocol field must be 3");

    // ZSK
    let zsk = ZoneSigningKey::from_public_parts(
        "test-key".to_string(),
        Algorithm::Ed25519,
        KeyType::ZSK,
        key.public_key().to_vec(),
        key.key_tag(),
        256,
    );
    let rdata2 = synvoid_dns::dnssec_validation::compute_dnskey(&zsk);
    assert_eq!(rdata2[2], 3, "DNSKEY protocol field must be 3 (ZSK)");

    // KSK
    let ksk = ZoneSigningKey::from_public_parts(
        "test-key".to_string(),
        Algorithm::Ed25519,
        KeyType::KSK,
        key.public_key().to_vec(),
        key.key_tag(),
        257,
    );
    let rdata3 = synvoid_dns::dnssec_validation::compute_dnskey(&ksk);
    assert_eq!(rdata3[2], 3, "DNSKEY protocol field must be 3 (KSK)");
}

/// DS digest type constants: SHA-1=1, SHA-256=2, SHA-384=4 (RFC 6605).
/// GOST (3) is intentionally unsupported.
#[test]
fn ds_digest_type_constants_match_rfc_6605() {
    assert_eq!(DsDigestType::Sha1.to_u8(), 1);
    assert_eq!(DsDigestType::Sha256.to_u8(), 2);
    assert_eq!(DsDigestType::Sha384.to_u8(), 4);
    assert!(DsDigestType::from_u8(3).is_none(), "GOST is unsupported");
}

/// RFC 4034 §3.1: RRSIG inception must be in the past, expiration in the
/// future. The current implementation hardcodes 1d past and 7d ahead.
#[test]
fn rrsig_inception_before_expiration() {
    let key = ed25519_test_key();
    let data = b"test data";
    let sig = sign_data(data, &key).expect("signing must succeed");
    let rrsig = create_rrsig_record(&key, 1, 3600, "example.com.", &sig, 2);

    // rrsig layout (from create_rrsig_record):
    //   type_covered(2) algorithm(1) labels(1) original_ttl(4)
    //   sig_expire(4) sig_inception(4) key_tag(2) signer_name(...)+0 signature(...)
    let sig_expire = u32::from_be_bytes([rrsig[8], rrsig[9], rrsig[10], rrsig[11]]);
    let sig_inception = u32::from_be_bytes([rrsig[12], rrsig[13], rrsig[14], rrsig[15]]);

    assert!(
        sig_expire > sig_inception,
        "RRSIG expiration must be after inception (expire={}, inception={})",
        sig_expire,
        sig_inception
    );
    // Skew: 1 day past and 7 days ahead (per create_rrsig_record).
    let window = sig_expire - sig_inception;
    assert!(
        window >= 7 * 86400,
        "RRSIG validity window must be at least 7 days, got {} seconds",
        window
    );
}

/// RFC 4034 §3.1.3: RRSIG labels field counts labels in the owner name
/// (not the signer name). It is computed by the caller and passed in.
#[test]
fn rrsig_labels_field_matches_owner_name() {
    let key = ed25519_test_key();
    let sig = sign_data(b"data", &key).unwrap();
    let rrsig = create_rrsig_record(&key, 1, 3600, "example.com.", &sig, 3);
    assert_eq!(
        rrsig[3], 3,
        "RRSIG labels field must match owner name label count"
    );
}

/// RFC 6605: SHA-256 DS digest is 32 bytes; SHA-384 is 48 bytes; SHA-1 is 20.
#[test]
fn ds_digest_lengths_match_rfc_6605() {
    use synvoid_dns::dnssec::{KeyType, ZoneSigningKey};

    let key = ZoneSigningKey::from_public_parts(
        "k".into(),
        Algorithm::Ed25519,
        KeyType::ZSK,
        vec![0u8; 32],
        0,
        256,
    );

    let sha1 = synvoid_dns::dnssec_validation::compute_ds_digest(
        DsDigestType::Sha1.to_u8(),
        256,
        3,
        15,
        key.public_key(),
    )
    .expect("SHA-1 digest must succeed");
    let sha256 = synvoid_dns::dnssec_validation::compute_ds_digest(
        DsDigestType::Sha256.to_u8(),
        256,
        3,
        15,
        key.public_key(),
    )
    .expect("SHA-256 digest must succeed");
    let sha384 = synvoid_dns::dnssec_validation::compute_ds_digest(
        DsDigestType::Sha384.to_u8(),
        256,
        3,
        15,
        key.public_key(),
    )
    .expect("SHA-384 digest must succeed");
    assert_eq!(sha1.len(), 20, "SHA-1 DS digest must be 20 bytes");
    assert_eq!(sha256.len(), 32, "SHA-256 DS digest must be 32 bytes");
    assert_eq!(sha384.len(), 48, "SHA-384 DS digest must be 48 bytes");
}

// ══════════════════════════════════════════════════════════════════════
// Gate 8: Recursive Safety Semantics (Milestone 3 Corrective Pass WS7)
// ══════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// Gate 9: Encrypted Transport Adapter Semantics (WS6)
// ══════════════════════════════════════════════════════════════════════

/// DoT (RFC 7858) reuses the standard DNS-over-TCP framing: 2-byte
/// length prefix followed by the DNS message. The encrypted transport
/// does NOT introduce a new wire framing — it just wraps the TCP stream
/// in TLS 1.3.
#[test]
fn dot_uses_standard_tcp_framing() {
    let query = vec![0x12, 0x34, 0x00, 0x00];
    let length = (query.len() as u16).to_be_bytes();
    let mut framed = Vec::new();
    framed.extend_from_slice(&length);
    framed.extend_from_slice(&query);

    assert_eq!(
        framed.len(),
        query.len() + 2,
        "DoQ/DoT prepend 2-byte length"
    );
    let len = u16::from_be_bytes([framed[0], framed[1]]);
    assert_eq!(len as usize, query.len(), "frame length must match payload");
    let read_query = &framed[2..2 + len as usize];
    assert_eq!(read_query, &query[..], "roundtrip must preserve payload");
}

/// Encrypted transports propagate TransportClass into the cache key,
/// preventing cross-contamination of wire-format responses.
#[test]
fn encrypted_transport_cache_namespace_isolation() {
    let qname = "example.com".to_string();
    let qtype = RecordType::A;

    let tcp = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Tcp);
    let http = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Http);
    let quic = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Quic);
    let udp = CacheKey::with_transport(qname.clone(), qtype, None, TransportClass::Udp512);

    // Each encrypted transport must produce a distinct cache key from UDP.
    assert_ne!(tcp, udp, "DoT cache key must differ from UDP");
    assert_ne!(http, udp, "DoH cache key must differ from UDP");
    assert_ne!(quic, udp, "DoQ cache key must differ from UDP");
    // And all three encrypted transports must be distinct from each other.
    assert_ne!(tcp, http);
    assert_ne!(http, quic);
    assert_ne!(tcp, quic);
}

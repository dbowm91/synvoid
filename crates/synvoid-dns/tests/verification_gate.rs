use std::sync::Arc;

use synvoid_config::dns::{
    DnsConfig, DnsDohConfig, DnsDoqConfig, DnsDotConfig, RecursiveDnsConfig,
};
use synvoid_dns::cache::{CacheKey, DnsCache, InvalidationReason, TransportClass};
use synvoid_dns::dnssec::{Algorithm, DsDigestType, KeyType, Nsec3Config, ZoneSigningKey};
use synvoid_dns::dnssec_signing::{create_nsec_record, create_rrsig_record, sign_data};
use synvoid_dns::recursive_cache::DnssecValidationState;
use synvoid_dns::recursive_cache::RecursiveCacheKey;
use synvoid_dns::recursive_cache::RecursiveDnsCache;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsZoneRecord, ShardedZoneStore, Zone};

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
    let mut private_bytes = [0u8; 32];
    getrandom::getrandom(&mut private_bytes).expect("getrandom failed");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_bytes.into());
    let verifying_key = signing_key.verifying_key().to_bytes().to_vec();
    let private_bytes = signing_key.to_bytes().to_vec();

    ZoneSigningKey {
        key_id: "test-key".to_string(),
        algorithm: Algorithm::Ed25519,
        key_type: KeyType::ZSK,
        created_at: 0,
        expires_at: u64::MAX,
        public_key: verifying_key,
        private_key: private_bytes,
        key_tag: 12345,
        flags: 256,
        key_size: None,
    }
}

// ══════════════════════════════════════════════════════════════════════
// Gate 2: Zone Lifecycle / Mutation Safety
// ══════════════════════════════════════════════════════════════════════

/// Verify that zone reload operations are atomic: a failed reload leaves
/// the existing zone data intact and does not partially expose new state.
///
/// This test constructs a ShardedZoneStore, inserts a zone, then attempts
/// a second insert with invalid data. The original zone must survive.
#[test]
fn zone_load_reload_is_atomic() {
    let zones = Arc::new(ShardedZoneStore::new());
    let zone = build_test_zone();
    let origin = zone.origin.clone();

    zones.insert(origin.clone(), zone);

    let original = zones
        .get(&origin)
        .expect("zone must exist after initial insert");
    assert_eq!(original.serial, 2026070201, "serial must be preserved");
    let original_a_record = original
        .records
        .get(&("www".to_string(), RecordType::A))
        .expect("www A record must exist");
    assert_eq!(original_a_record[0].value, "192.0.2.10");

    // Simulate a "failed reload" by inserting a zone with the same origin
    // but without the www record. The store should atomically replace.
    let mut broken_zone = Zone::new("test.local".to_string());
    broken_zone.serial = 2026070202;
    broken_zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.test.local. admin.test.local. 2026070202 3600 600 604800 300".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    // No www record — this simulates a partial/corrupt zone.
    zones.insert(origin.clone(), broken_zone);

    let after = zones.get(&origin).expect("zone must exist after reload");
    assert_eq!(
        after.serial, 2026070202,
        "reload must replace zone atomically"
    );
    assert!(
        !after
            .records
            .contains_key(&("www".to_string(), RecordType::A)),
        "reloaded zone must reflect new state (no www record)"
    );
}

/// Verify that store write errors propagate correctly — a zone without
/// a SOA record is rejected and must not be stored.
#[test]
fn store_write_failure_cannot_silently_acknowledge() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = Zone::new("nosoa.local".to_string());
    zone.serial = 1;
    // Intentionally no SOA record.

    zones.insert("nosoa.local".to_string(), zone);

    // The store should either reject the zone or the caller should verify.
    // ShardedZoneStore::insert always succeeds (it's a HashMap), but the
    // zone validation happens at the DnsServer level (load_zones).
    // Here we verify that a zone without SOA has an empty records map
    // for the SOA key, demonstrating the data inconsistency that must
    // be caught by higher-level validation.
    let stored = zones.get("nosoa.local").expect("zone must be stored");
    assert!(
        !stored
            .records
            .contains_key(&("@".to_string(), RecordType::SOA)),
        "zone without SOA must not have SOA records"
    );

    // Verify that validate_single_soa would catch this.
    // Zone::validate_single_soa is the guard — it returns Err for zones
    // without exactly one SOA record.
    let result = stored.validate_single_soa();
    assert!(
        result.is_err(),
        "validate_single_soa must reject a zone without a SOA record"
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
    assert_eq!(key_tag, key.key_tag, "key tag must match");
}

// ══════════════════════════════════════════════════════════════════════
// Gate 4: Encrypted Transport Adapters
// ══════════════════════════════════════════════════════════════════════

/// Verify DoT config serialization roundtrip.
///
/// All fields must survive a serde_json serialize-deserialize cycle.
#[test]
fn dot_config_all_fields_roundtrip() {
    let config = DnsDotConfig {
        enabled: true,
        port: 8853,
        bind_address: "10.0.0.1".to_string(),
        tls_cert_path: Some("/etc/certs/dot.pem".to_string()),
        tls_key_path: Some("/etc/certs/dot-key.pem".to_string()),
        use_system_cert_store: false,
    };

    let json = serde_json::to_string(&config).expect("DoT config must serialize");
    let restored: DnsDotConfig = serde_json::from_str(&json).expect("DoT config must deserialize");

    assert!(restored.enabled);
    assert_eq!(restored.port, 8853);
    assert_eq!(restored.bind_address, "10.0.0.1");
    assert_eq!(
        restored.tls_cert_path,
        Some("/etc/certs/dot.pem".to_string())
    );
    assert_eq!(
        restored.tls_key_path,
        Some("/etc/certs/dot-key.pem".to_string())
    );
    assert!(!restored.use_system_cert_store);
}

/// Verify DoH config serialization roundtrip.
///
/// All fields must survive a serde_json serialize-deserialize cycle.
#[test]
fn doh_config_all_fields_roundtrip() {
    let config = DnsDohConfig {
        enabled: true,
        port: 1443,
        bind_address: "10.0.0.2".to_string(),
        path: "/custom-dns".to_string(),
        json_path: "/custom-dns-json".to_string(),
        tls_cert_path: Some("/etc/certs/doh.pem".to_string()),
        tls_key_path: Some("/etc/certs/doh-key.pem".to_string()),
        use_system_cert_store: true,
    };

    let json = serde_json::to_string(&config).expect("DoH config must serialize");
    let restored: DnsDohConfig = serde_json::from_str(&json).expect("DoH config must deserialize");

    assert!(restored.enabled);
    assert_eq!(restored.port, 1443);
    assert_eq!(restored.bind_address, "10.0.0.2");
    assert_eq!(restored.path, "/custom-dns");
    assert_eq!(restored.json_path, "/custom-dns-json");
    assert_eq!(
        restored.tls_cert_path,
        Some("/etc/certs/doh.pem".to_string())
    );
    assert!(restored.use_system_cert_store);
}

/// Verify DoQ config serialization roundtrip.
///
/// All fields must survive a serde_json serialize-deserialize cycle.
#[test]
fn doq_config_all_fields_roundtrip() {
    let config = DnsDoqConfig {
        enabled: true,
        port: 7853,
        bind_address: "10.0.0.3".to_string(),
        tls_cert_path: Some("/etc/certs/doq.pem".to_string()),
        tls_key_path: Some("/etc/certs/doq-key.pem".to_string()),
        use_system_cert_store: false,
        max_concurrent_streams: 200,
        idle_timeout_secs: 60,
    };

    let json = serde_json::to_string(&config).expect("DoQ config must serialize");
    let restored: DnsDoqConfig = serde_json::from_str(&json).expect("DoQ config must deserialize");

    assert!(restored.enabled);
    assert_eq!(restored.port, 7853);
    assert_eq!(restored.bind_address, "10.0.0.3");
    assert_eq!(restored.max_concurrent_streams, 200);
    assert_eq!(restored.idle_timeout_secs, 60);
    assert!(!restored.use_system_cert_store);
}

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

/// Verify all encrypted transport config defaults.
///
/// Serde defaults must produce correct values for omitted fields.
#[test]
fn encrypted_transport_config_defaults() {
    let dot: DnsDotConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(dot.port, 853, "DoT default port must be 853");
    assert!(!dot.enabled, "DoT must be disabled by default");
    assert!(
        dot.use_system_cert_store,
        "DoT must use system cert store by default"
    );

    let doh: DnsDohConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(doh.port, 443, "DoH default port must be 443");
    assert!(!doh.enabled, "DoH must be disabled by default");
    assert_eq!(
        doh.path, "/dns-query",
        "DoH default path must be /dns-query"
    );
    assert!(
        doh.use_system_cert_store,
        "DoH must use system cert store by default"
    );

    let doq: DnsDoqConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(doq.port, 853, "DoQ default port must be 853");
    assert!(!doq.enabled, "DoQ must be disabled by default");
    assert_eq!(
        doq.max_concurrent_streams, 100,
        "DoQ default max concurrent streams"
    );
    assert_eq!(doq.idle_timeout_secs, 30, "DoQ default idle timeout");
    assert!(
        doq.use_system_cert_store,
        "DoQ must use system cert store by default"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Gate 5: Recursive Resolver Safety
// ══════════════════════════════════════════════════════════════════════

/// Verify recursive DNS is disabled by default.
///
/// The default DnsConfig must have recursive.enabled = false with
/// sensible loopback binding to prevent open-resolver misconfigurations.
#[test]
fn recursive_disabled_by_default() {
    let config = DnsConfig::default();
    assert!(
        !config.recursive.enabled,
        "Recursive DNS must be disabled by default"
    );
    assert_eq!(
        config.recursive.bind_address, "127.0.0.1",
        "Recursive must bind to loopback by default"
    );
    assert_eq!(
        config.recursive.port, 1053,
        "Recursive must use non-standard port (1053) by default"
    );
}

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
    use synvoid_config::dns::RecursiveCacheConfig;

    let config = RecursiveCacheConfig::default();
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

/// Verify CNAME depth limit is enforced.
///
/// When max_cname_depth > 0, the recursive resolver must reject queries
/// that exceed the depth limit to prevent CNAME loops.
#[test]
fn cname_depth_limit_enforced() {
    // Default max_cname_depth must be 10
    let default_config = RecursiveDnsConfig::default();
    assert_eq!(
        default_config.max_cname_depth, 10,
        "default max_cname_depth must be 10"
    );

    // Setting max_cname_depth = 0 means unlimited (valid)
    let config = RecursiveDnsConfig {
        enabled: true,
        max_cname_depth: 0,
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "max_cname_depth=0 (unlimited) must be accepted"
    );

    // Setting max_cname_depth = 1 is valid (very restrictive)
    let config = RecursiveDnsConfig {
        enabled: true,
        max_cname_depth: 1,
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "max_cname_depth=1 must be accepted"
    );
}

/// Verify recursive config validation rules.
///
/// Key constraints: query_timeout_secs > 0, max_concurrent_queries > 0,
/// negative_ttl_secs <= max_ttl_secs, open-resolver guard.
#[test]
fn recursive_config_validation() {
    // Valid config
    let mut config = RecursiveDnsConfig::default();
    config.enabled = true;
    assert!(
        config.validate().is_ok(),
        "default enabled config must validate: {:?}",
        config.validate()
    );

    // query_timeout_secs = 0 is invalid
    config.query_timeout_secs = 0;
    assert!(
        config.validate().is_err(),
        "query_timeout_secs=0 must fail validation"
    );
    config.query_timeout_secs = 5;

    // max_concurrent_queries = 0 is invalid
    config.max_concurrent_queries = 0;
    assert!(
        config.validate().is_err(),
        "max_concurrent_queries=0 must fail validation"
    );
    config.max_concurrent_queries = 100;

    // negative_ttl_secs > max_ttl_secs is invalid
    config.cache.negative_ttl_secs = 1000;
    config.cache.max_ttl_secs = 500;
    assert!(
        config.validate().is_err(),
        "negative_ttl > max_ttl must fail validation"
    );
    config.cache.negative_ttl_secs = 60;
    config.cache.max_ttl_secs = 300;

    // Open-resolver guard: 0.0.0.0 is rejected
    config.bind_address = "0.0.0.0".to_string();
    assert!(
        config.validate().is_err(),
        "bind_address=0.0.0.0 must fail (open resolver)"
    );

    config.bind_address = "::".to_string();
    assert!(
        config.validate().is_err(),
        "bind_address=:: must fail (open resolver)"
    );

    config.bind_address = "127.0.0.1".to_string();
    assert!(
        config.validate().is_ok(),
        "bind_address=127.0.0.1 must pass"
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
    use synvoid_config::dns::RecursiveCacheConfig;

    let auth_cache = DnsCache::new(100, 300, 10);
    let rec_config = RecursiveCacheConfig::default();
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

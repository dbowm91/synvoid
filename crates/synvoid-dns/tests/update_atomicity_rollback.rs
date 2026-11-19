//! UPDATE mutation atomicity and rollback proof tests.
//!
//! Verifies that dynamic updates are atomic: either all mutations succeed
//! or the zone remains unchanged. Tests prerequisite failures, serial
//! preservation, and concurrent update safety.

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::cache::DnsCache;
use synvoid_dns::runtime_config::{TsigAlgorithmRuntime, TsigRuntimeKey};
use synvoid_dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::tsig::TsigVerifier;
use synvoid_dns::update::DynamicUpdateHandler;
use synvoid_dns::wire;

use support::query::{
    build_rr, build_update_add_record, build_update_header, build_zone_question, encode_qname,
};
use support::zone::zone_with_soa;

const CLASS_ANY: u16 = 255;
const CLASS_NONE: u16 = 254;

// ── Helpers ─────────────────────────────────────────────────────────────

fn zone_with_a_record(origin: &str, serial: u32, name: &str, ip: &str) -> Zone {
    let mut z = zone_with_soa(origin, serial);
    z.records.insert(
        (name.to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: name.to_string(),
            record_type: RecordType::A,
            value: ip.to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    z
}

fn test_verifier() -> Arc<TsigVerifier> {
    Arc::new(
        TsigVerifier::new(vec![TsigRuntimeKey {
            name: "update-key".to_string(),
            secret: b"update-key-secret-material-0123456789".to_vec(),
            algorithm: TsigAlgorithmRuntime::HmacSha256,
        }])
        .expect("test TSIG key"),
    )
}

fn handler(zones: Arc<ShardedZoneStore>) -> DynamicUpdateHandler {
    DynamicUpdateHandler::new(zones)
        .with_config(true, true, false)
        .expect("no TSIG required")
}

/// Delete an entire RRset: class ANY, TTL 0, empty RDATA.
fn build_rr_delete(name: &str, rtype: u16) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_ANY.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

/// Value-independent prerequisite: class ANY/NONE, TTL 0, empty RDATA.
fn build_prerequisite(name: &str, rtype: u16, class: u16) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&class.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

fn build_update_delete_record(zone: &str, name: &str, rtype: u16) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr_delete(name, rtype));
    buf
}

fn build_multi_record_update(zone: &str, records: &[(&str, u16, Vec<u8>, u32)]) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, records.len() as u16);
    buf.extend_from_slice(&build_zone_question(zone));
    for (name, rtype, rdata, ttl) in records {
        buf.extend_from_slice(&build_rr(name, *rtype, rdata, *ttl));
    }
    buf
}

// ══════════════════════════════════════════════════════════════════════
// Section 1: Atomicity — add succeeds, zone contains new record
// ══════════════════════════════════════════════════════════════════════

/// Single A record add: zone must contain the record under the relative
/// owner name the query path looks up.
#[test]
fn atomic_add_single_record() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "add must succeed: {:?}", result.err());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(rcode, wire::UPDATE_RCODE_NOERROR);

    let z = zones.get("test.local").unwrap();
    assert!(
        z.records.contains_key(&("new".to_string(), RecordType::A)),
        "zone must contain the added A record under its relative owner"
    );
}

/// Add increments serial and writes the new serial into the served SOA RDATA.
#[test]
fn atomic_add_increments_serial() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 10));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let _ = handler.handle_update(&query, client).unwrap();
    let z = zones.get("test.local").unwrap();
    assert!(
        z.serial > 10,
        "serial must increment from 10, got {}",
        z.serial
    );
    let soa = &z.records.get(&("@".to_string(), RecordType::SOA)).unwrap()[0];
    assert_eq!(
        soa.value.split_whitespace().nth(2),
        Some(z.serial.to_string().as_str()),
        "the served SOA serial must follow the zone serial"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: Atomicity — prerequisite failure leaves zone unchanged
// ══════════════════════════════════════════════════════════════════════

/// NONE + type (RRset does not exist) on an existing RRset → YXRRSET.
#[test]
fn atomic_prerequisite_nxrrset_existing_record() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "test.local".to_string(),
        zone_with_a_record("test.local", 1, "www", "10.0.0.1"),
    );
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&build_prerequisite("www", 1, CLASS_NONE));

    let result = handler.handle_update(&buf, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_YXRRSET,
        "not-exists prerequisite on an existing RRset must be YXRRSET"
    );

    let z = zones.get("test.local").unwrap();
    assert_eq!(
        z.serial, 1,
        "serial must remain 1 after prerequisite failure"
    );
    assert!(
        z.records.contains_key(&("www".to_string(), RecordType::A)),
        "www A record must still exist"
    );
}

/// ANY + type (RRset exists) on a missing RRset → NXRRSET.
#[test]
fn atomic_prerequisite_yxrrset_nonexistent() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&build_prerequisite("www", 1, CLASS_ANY));

    let result = handler.handle_update(&buf, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NXRRSET,
        "exists prerequisite on a missing RRset must be NXRRSET"
    );

    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 1, "serial must remain 1");
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: Atomicity — apex guards
// ══════════════════════════════════════════════════════════════════════

/// An apex SOA RRset delete is ignored (RFC 2136 §3.4.2.3), zone unchanged.
#[test]
fn atomic_soa_deletion_ignored() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 5));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_delete_record("test.local", "@", 6); // delete SOA RRset

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOERROR,
        "an ignored apex delete still succeeds"
    );

    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 5, "serial must remain 5 (nothing changed)");
    assert!(
        z.records.contains_key(&("@".to_string(), RecordType::SOA)),
        "SOA must still exist"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: Rollback — invalid update doesn't corrupt zone
// ══════════════════════════════════════════════════════════════════════

/// CNAME + A coexistence attempt: the CNAME add is ignored, the zone stays
/// consistent (RFC 2136 §3.4.2.2).
#[test]
fn atomic_cname_coexistence_preserves_zone() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // Add CNAME + A for same name
    let mut buf = build_update_header(1, 0, 0, 2);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&build_rr("www", 5, b"target.test.local.", 300)); // CNAME
    buf.extend_from_slice(&build_rr("www", 1, &[10, 0, 0, 1], 300)); // A

    let _result = handler.handle_update(&buf, client);
    let z = zones.get("test.local").unwrap();
    let www_cname = z.records.get(&("www".to_string(), RecordType::CNAME));
    let www_a = z.records.get(&("www".to_string(), RecordType::A));
    assert!(
        www_cname.is_none() || www_a.is_none(),
        "CNAME and A cannot coexist for same name"
    );
}

/// One out-of-zone RR in a multi-record UPDATE rejects the whole transaction
/// with NOTZONE and mutates nothing.
#[test]
fn atomic_out_of_zone_record_rejects_whole_update() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let records = vec![
        ("ok.test.local", 1u16, vec![10, 0, 0, 1], 300u32),
        ("outside.example", 1, vec![10, 0, 0, 2], 300),
    ];
    let query = build_multi_record_update("test.local", &records);

    let rcode = match handler.handle_update(&query, client) {
        Ok(response) => response[3] & 0x0F,
        Err(denied) => denied.rcode,
    };
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOTZONE,
        "an out-of-zone owner must be NOTZONE"
    );

    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 1, "the whole transaction must be rolled back");
    assert!(
        !z.records.contains_key(&("ok".to_string(), RecordType::A)),
        "no record from a rejected transaction may be committed"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 5: Cache invalidation on atomic commit
// ══════════════════════════════════════════════════════════════════════

/// Successful update invalidates zone cache.
#[test]
fn atomic_update_invalidates_zone_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = synvoid_dns::cache::CacheKey::new("test.local".to_string(), RecordType::SOA, None);
    cache.insert(key.clone(), b"stale".to_vec(), 300);
    assert!(
        cache.get(&key).is_some(),
        "cache entry must exist before update"
    );

    let handler = DynamicUpdateHandler::new(zones.clone())
        .with_config(true, true, false)
        .expect("no TSIG required")
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let _ = handler.handle_update(&query, client).unwrap();
    assert!(
        cache.get(&key).is_none(),
        "cache entry must be invalidated after successful update"
    );
}

/// Failed prerequisite does NOT invalidate cache.
#[test]
fn atomic_failed_prerequisite_preserves_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "test.local".to_string(),
        zone_with_a_record("test.local", 1, "www", "10.0.0.1"),
    );
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = synvoid_dns::cache::CacheKey::new("www.test.local".to_string(), RecordType::A, None);
    cache.insert(key.clone(), b"cached".to_vec(), 300);

    let handler = DynamicUpdateHandler::new(zones.clone())
        .with_config(true, true, false)
        .expect("no TSIG required")
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // NONE + A prerequisite for www A (exists → fails with YXRRSET)
    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&build_prerequisite("www", 1, CLASS_NONE));

    let _ = handler.handle_update(&buf, client);
    assert!(
        cache.get(&key).is_some(),
        "cache must be preserved after failed prerequisite"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 6: Serial preservation on refused updates
// ══════════════════════════════════════════════════════════════════════

/// TSIG required but absent → serial unchanged.
#[test]
fn atomic_tsig_absent_preserves_serial() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 7));
    let handler = DynamicUpdateHandler::new(zones.clone())
        .with_tsig_verifier(test_verifier())
        .with_config(true, true, true)
        .expect("require_tsig with a verifier may be constructed");
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let result = handler.handle_update(&query, client);
    assert!(result.is_err(), "require_tsig without TSIG must fail");
    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 7, "serial must remain 7");
}

/// Unknown zone → NOTAUTH, other zones untouched.
#[test]
fn atomic_unknown_zone_returns_notauth() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("known.test".to_string(), zone_with_soa("known.test", 1));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("unknown.test", "new.unknown.test", 1, &[10, 0, 0, 1], 300);

    let response = handler
        .handle_update(&query, client)
        .expect("unknown zone is answered NOTAUTH, not dropped");
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_NOTAUTH,
        "an unknown zone is not this server's authority"
    );
    let z = zones.get("known.test").unwrap();
    assert_eq!(z.serial, 1, "known zone serial must be unchanged");
}

// ══════════════════════════════════════════════════════════════════════
// Section 7: Multi-record add atomicity
// ══════════════════════════════════════════════════════════════════════

/// Adding multiple records in one UPDATE: all must appear in zone.
#[test]
fn atomic_multi_record_add() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let records = vec![
        ("a1.test.local", 1u16, vec![10, 0, 0, 1], 300u32),
        ("a2.test.local", 1, vec![10, 0, 0, 2], 300),
        ("a3.test.local", 1, vec![10, 0, 0, 3], 300),
    ];
    let query = build_multi_record_update("test.local", &records);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "multi-record add must succeed: {:?}",
        result.err()
    );

    let z = zones.get("test.local").unwrap();
    assert!(z.records.contains_key(&("a1".to_string(), RecordType::A)));
    assert!(z.records.contains_key(&("a2".to_string(), RecordType::A)));
    assert!(z.records.contains_key(&("a3".to_string(), RecordType::A)));
}

/// Delete an RRset → zone no longer contains it.
#[test]
fn atomic_delete_removes_record() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "test.local".to_string(),
        zone_with_a_record("test.local", 1, "del", "10.0.0.99"),
    );
    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_delete_record("test.local", "del", 1);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "delete must succeed: {:?}", result.err());

    let z = zones.get("test.local").unwrap();
    assert!(
        !z.records.contains_key(&("del".to_string(), RecordType::A)),
        "deleted record must not exist"
    );
}

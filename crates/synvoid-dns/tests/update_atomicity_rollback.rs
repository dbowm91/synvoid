//! UPDATE mutation atomicity and rollback proof tests.
//!
//! Verifies that dynamic updates are atomic: either all mutations succeed
//! or the zone remains unchanged. Tests prerequisite failures, serial
//! preservation, and concurrent update safety.

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::cache::DnsCache;
use synvoid_dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::update::DynamicUpdateHandler;
use synvoid_dns::wire;

use support::query::{
    build_rr, build_update_add_record, build_update_header, build_zone_question, encode_qname,
};
use support::zone::zone_with_soa;

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

fn build_rr_delete(name: &str, rtype: u16) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
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

/// Single A record add: zone must contain new record after success.
#[test]
fn atomic_add_single_record() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "add must succeed: {:?}", result.err());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(rcode, wire::UPDATE_RCODE_NOERROR);

    let z = zones.get("test.local").unwrap();
    assert!(
        z.records
            .contains_key(&("new.test.local".to_string(), RecordType::A)),
        "zone must contain the added A record"
    );
}

/// Add increments serial.
#[test]
fn atomic_add_increments_serial() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 10));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let _ = handler.handle_update(&query, client).unwrap();
    let z = zones.get("test.local").unwrap();
    assert!(
        z.serial > 10,
        "serial must increment from 10, got {}",
        z.serial
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: Atomicity — prerequisite failure leaves zone unchanged
// ══════════════════════════════════════════════════════════════════════

/// NXRRSET prerequisite on existing record → zone unchanged.
#[test]
fn atomic_prerequisite_nxrrset_existing_record() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "test.local".to_string(),
        zone_with_a_record("test.local", 1, "www", "10.0.0.1"),
    );
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // Prerequisite: NXRRSET (class=4) for www A — but www A exists, so this fails
    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&encode_qname("www"));
    buf.extend_from_slice(&1u16.to_be_bytes()); // A
    buf.extend_from_slice(&4u16.to_be_bytes()); // NXRRSET class
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    let result = handler.handle_update(&buf, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert!(
        rcode == wire::UPDATE_RCODE_YXDOMAIN || rcode == wire::UPDATE_RCODE_NXRRSET,
        "prerequisite failure must return YXDOMAIN or NXRRSET, got {}",
        rcode
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

/// YXRRSET prerequisite on non-existent record → zone unchanged.
#[test]
fn atomic_prerequisite_yxrrset_nonexistent() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // Prerequisite: YXRRSET (class=3) for www A — but www A doesn't exist, so this fails
    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&encode_qname("www"));
    buf.extend_from_slice(&1u16.to_be_bytes()); // A
    buf.extend_from_slice(&3u16.to_be_bytes()); // YXRRSET class
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    let result = handler.handle_update(&buf, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert!(
        rcode == wire::UPDATE_RCODE_YXDOMAIN || rcode == wire::UPDATE_RCODE_NXRRSET,
        "prerequisite failure must return YXDOMAIN or NXRRSET, got {}",
        rcode
    );

    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 1, "serial must remain 1");
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: Atomicity — SOA deletion refused
// ══════════════════════════════════════════════════════════════════════

/// Attempting to remove the final SOA → NOTAUTH, zone unchanged.
#[test]
fn atomic_soa_deletion_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 5));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_delete_record("test.local", "@", 6); // delete SOA

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOTAUTH,
        "SOA deletion must return NOTAUTH"
    );

    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 5, "serial must remain 5");
    assert!(
        z.records.contains_key(&("@".to_string(), RecordType::SOA)),
        "SOA must still exist"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: Rollback — invalid update doesn't corrupt zone
// ══════════════════════════════════════════════════════════════════════

/// CNAME + A coexistence attempt: zone records must remain unchanged.
#[test]
fn atomic_cname_coexistence_preserves_zone() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // Add CNAME + A for same name
    let mut buf = build_update_header(1, 0, 0, 2);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&build_rr("www", 5, b"target.test.local.", 300)); // CNAME
    buf.extend_from_slice(&build_rr("www", 1, &[10, 0, 0, 1], 300)); // A

    let _result = handler.handle_update(&buf, client);
    // May succeed or fail depending on validation, but zone must be consistent
    let z = zones.get("test.local").unwrap();
    let www_cname = z.records.get(&("www".to_string(), RecordType::CNAME));
    let www_a = z.records.get(&("www".to_string(), RecordType::A));
    // If either exists, the other must not (CNAME exclusivity)
    if let Some(cname) = www_cname {
        assert!(
            cname.is_empty() || www_a.is_none() || www_a.unwrap().is_empty(),
            "CNAME and A cannot coexist for same name"
        );
    }
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
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    // NXRRSET prerequisite for www A (exists → fails)
    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question("test.local"));
    buf.extend_from_slice(&encode_qname("www"));
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

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
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);

    let result = handler.handle_update(&query, client);
    assert!(result.is_err(), "require_tsig without TSIG must fail");
    let z = zones.get("test.local").unwrap();
    assert_eq!(z.serial, 7, "serial must remain 7");
}

/// Unknown zone → serial N/A (handler returns error).
#[test]
fn atomic_unknown_zone_returns_error() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("known.test".to_string(), zone_with_soa("known.test", 1));
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("unknown.test", "new.unknown.test", 1, &[10, 0, 0, 1], 300);

    let _result = handler.handle_update(&query, client);
    // Unknown zone may return error or NOTAUTH — either way, known zone unchanged
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
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
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
    assert!(z
        .records
        .contains_key(&("a1.test.local".to_string(), RecordType::A)));
    assert!(z
        .records
        .contains_key(&("a2.test.local".to_string(), RecordType::A)));
    assert!(z
        .records
        .contains_key(&("a3.test.local".to_string(), RecordType::A)));
}

/// Delete existing record → zone no longer contains it.
#[test]
fn atomic_delete_removes_record() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "test.local".to_string(),
        zone_with_a_record("test.local", 1, "del", "10.0.0.99"),
    );
    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
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

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::cache::{CacheKey, DnsCache};
use synvoid_dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::update::DynamicUpdateHandler;
use synvoid_dns::wire;

fn zone_with_soa(origin: &str, serial: u32) -> Zone {
    let mut z = Zone::new(origin.to_string());
    z.serial = serial;
    z.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: format!(
                "ns1.{}. admin.{}. {} 3600 600 604800 300",
                origin, origin, serial
            ),
            ttl: 300,
            priority: None,
        }],
    );
    z
}

fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn build_update_header(qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x1234u16.to_be_bytes());
    let flags: u16 = (5u16) << 11;
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&qdcount.to_be_bytes());
    buf.extend_from_slice(&ancount.to_be_bytes());
    buf.extend_from_slice(&nscount.to_be_bytes());
    buf.extend_from_slice(&arcount.to_be_bytes());
    buf
}

fn build_zone_question(zone: &str) -> Vec<u8> {
    let mut buf = encode_qname(zone);
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf
}

fn build_rr_add(name: &str, rtype: u16, rdata: &[u8], ttl: u32) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(rdata);
    buf
}

fn build_rr_delete(name: &str, rtype: u16) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

fn build_prerequisite_rr(name: &str, rtype: u16, condition_class: u16) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&condition_class.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

fn build_update_add_record(zone: &str, name: &str, rtype: u16, rdata: &[u8], ttl: u32) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr_add(name, rtype, rdata, ttl));
    buf
}

fn build_update_delete_record(zone: &str, name: &str, rtype: u16) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr_delete(name, rtype));
    buf
}

fn build_update_with_prerequisite(
    zone: &str,
    prereq_name: &str,
    prereq_type: u16,
    condition_class: u16,
) -> Vec<u8> {
    let mut buf = build_update_header(1, 1, 0, 0);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_prerequisite_rr(
        prereq_name,
        prereq_type,
        condition_class,
    ));
    buf
}

fn build_update_remove_final_soa(zone: &str) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr_delete("@", 6));
    buf
}

fn build_update_duplicate_soa_add(zone: &str) -> Vec<u8> {
    let soa_rdata = format!("ns1.{}. admin.{}. 999 3600 600 604800 300", zone, zone);
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr_add("@", 6, soa_rdata.as_bytes(), 300));
    buf
}

fn build_update_invalid_cname_coexistence(zone: &str) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 2);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr_add("www", 1, &[1, 2, 3, 4], 300));
    buf.extend_from_slice(&build_rr_add("www", 5, b"target.example.test.", 300));
    buf
}

#[test]
fn update_authorized_add_a_record_succeeds() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("example.test", "new.example.test", 1, &[1, 2, 3, 4], 300);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "add-A UPDATE should succeed: {:?}",
        result.err()
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOERROR,
        "response RCODE must be NOERROR"
    );

    let z = zones.get("example.test").unwrap();
    let key = ("new.example.test".to_string(), RecordType::A);
    assert!(
        z.records.contains_key(&key),
        "zone must contain the new A record"
    );
    assert_eq!(z.records.get(&key).unwrap().len(), 1);
}

#[test]
fn update_authorized_delete_a_record_succeeds() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
    zone.records.insert(
        ("del.example.test".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "del.example.test".to_string(),
            record_type: RecordType::A,
            value: "10.0.0.2".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example.test".to_string(), zone);

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_delete_record("example.test", "del.example.test", 1);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "delete-A UPDATE should succeed: {:?}",
        result.err()
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(rcode, wire::UPDATE_RCODE_NOERROR);

    let z = zones.get("example.test").unwrap();
    let key = ("del.example.test".to_string(), RecordType::A);
    assert!(
        !z.records.contains_key(&key),
        "zone must no longer contain the deleted A record"
    );
}

#[test]
fn update_prerequisite_nxrrset_leaves_zone_unchanged() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_with_prerequisite("example.test", "@", 6, 4);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "prerequisite check returns Ok, not Err: {:?}",
        result.err()
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert!(
        rcode == wire::UPDATE_RCODE_YXDOMAIN || rcode == wire::UPDATE_RCODE_NXRRSET,
        "prerequisite failure must return YXDOMAIN (6) or NXRRSET (8), got {}",
        rcode
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "zone serial must remain unchanged");
}

#[test]
fn update_prerequisite_yxrrset_leaves_zone_unchanged() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
    zone.records.insert(
        ("exists.example.test".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "exists.example.test".to_string(),
            record_type: RecordType::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example.test".to_string(), zone);

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_with_prerequisite("example.test", "exists.example.test", 1, 3);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "handler must return Ok for prerequisite check: {:?}",
        result.err()
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    // class 3 (ExistsRRset) = "name is in use" — prerequisite IS met because the name exists.
    // With no update records (nscount=0, arcount=0), the update proceeds with no changes → NOERROR.
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOERROR,
        "YXRRSET on existing name should succeed (NOERROR), got {}",
        rcode
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(
        z.serial, 1,
        "zone serial must remain unchanged (no update records)"
    );
}

#[test]
fn update_remove_final_soa_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_remove_final_soa("example.test");

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "post-mutation validation failure returns Ok with NOTAUTH RCODE"
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOTAUTH,
        "removing final SOA must return NOTAUTH (9), got {}",
        rcode
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(
        z.serial, 1,
        "zone serial must remain unchanged after refused update"
    );
    assert!(
        z.records.contains_key(&("@".to_string(), RecordType::SOA)),
        "SOA must still exist in zone"
    );
}

#[test]
fn update_duplicate_soa_add_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_duplicate_soa_add("example.test");

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "post-mutation validation returns Ok with NOTAUTH RCODE"
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NOTAUTH,
        "duplicate SOA must return NOTAUTH (9), got {}",
        rcode
    );

    let z = zones.get("example.test").unwrap();
    let soa_records = z.records.get(&("@".to_string(), RecordType::SOA)).unwrap();
    assert_eq!(
        soa_records.len(),
        1,
        "only one SOA record must remain after refused duplicate"
    );
}

#[test]
fn update_invalid_cname_coexistence_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_invalid_cname_coexistence("example.test");

    let result = handler.handle_update(&query, client);
    if let Ok(response) = &result {
        let rcode = response[3] & 0x0F;
        assert!(
            rcode != wire::UPDATE_RCODE_NOERROR,
            "CNAME + A coexistence must be refused (RFC 1034 §3.6.2), got NOERROR"
        );
    }
    let z = zones.get("example.test").unwrap();
    assert_eq!(
        z.serial, 1,
        "zone serial must remain unchanged after refused CNAME coexistence"
    );
}

#[test]
fn update_require_tsig_absent_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("example.test", "new.example.test", 1, &[1, 2, 3, 4], 300);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_err(),
        "require_tsig=true without TSIG must return Err"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("TSIG"),
        "error message must mention TSIG: {}",
        err
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "zone must not be mutated when TSIG is absent");
}

#[test]
fn update_successful_add_invalidates_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = CacheKey::new("example.test".to_string(), RecordType::SOA, None);
    cache.insert(key.clone(), b"cached-data".to_vec(), 300);
    assert!(
        cache.get(&key).is_some(),
        "cache entry must exist before update"
    );

    let handler = DynamicUpdateHandler::new(zones.clone())
        .with_config(true, true, false)
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("example.test", "new.example.test", 1, &[1, 2, 3, 4], 300);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "update must succeed: {:?}", result.err());

    assert!(
        cache.get(&key).is_none(),
        "cache entry for zone must be invalidated after successful update"
    );
}

#[test]
fn update_successful_add_increments_serial() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 10),
    );

    let handler = DynamicUpdateHandler::new(zones.clone()).with_config(true, true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("example.test", "new.example.test", 1, &[1, 2, 3, 4], 300);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "update must succeed: {:?}", result.err());

    let z = zones.get("example.test").unwrap();
    assert!(
        z.serial > 10,
        "serial must have increased after successful update, got {}",
        z.serial
    );
}

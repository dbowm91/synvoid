mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::cache::{CacheKey, DnsCache};
use synvoid_dns::runtime_config::{TsigAlgorithmRuntime, TsigRuntimeKey};
use synvoid_dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore};
use synvoid_dns::tsig::TsigVerifier;
use synvoid_dns::update::DynamicUpdateHandler;
use synvoid_dns::wire;

use support::query::{
    build_rr, build_update_add_record, build_update_header, build_zone_question, encode_qname,
};
use support::zone::zone_with_soa;

const CLASS_ANY: u16 = 255;
const CLASS_NONE: u16 = 254;

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

/// An RR carrying a class, TTL, and RDATA (for prerequisites and deletes).
fn build_typed_rr(name: &str, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut buf = encode_qname(name);
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&class.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(rdata);
    buf
}

/// Delete an entire RRset: class ANY, TTL 0, empty RDATA (RFC 2136 §3.4.2.3).
fn build_rr_delete(name: &str, rtype: u16) -> Vec<u8> {
    build_typed_rr(name, rtype, CLASS_ANY, 0, &[])
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
    buf.extend_from_slice(&build_typed_rr(
        prereq_name,
        prereq_type,
        condition_class,
        0,
        &[],
    ));
    buf
}

/// Wire-format SOA RDATA: two names plus the five 32-bit fields.
fn soa_rdata(zone: &str, serial: u32) -> Vec<u8> {
    let mut rdata = encode_qname(&format!("ns1.{zone}"));
    rdata.extend_from_slice(&encode_qname(&format!("admin.{zone}")));
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&600u32.to_be_bytes());
    rdata.extend_from_slice(&604800u32.to_be_bytes());
    rdata.extend_from_slice(&300u32.to_be_bytes());
    rdata
}

fn build_update_duplicate_soa_add(zone: &str, serial: u32) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 1);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr("@", 6, &soa_rdata(zone, serial), 300));
    buf
}

fn build_update_invalid_cname_coexistence(zone: &str) -> Vec<u8> {
    let mut buf = build_update_header(1, 0, 0, 2);
    buf.extend_from_slice(&build_zone_question(zone));
    buf.extend_from_slice(&build_rr("www", 1, &[1, 2, 3, 4], 300));
    buf.extend_from_slice(&build_rr(
        "www",
        5,
        &encode_qname("target.example.test"),
        300,
    ));
    buf
}

#[test]
fn update_authorized_add_a_record_succeeds() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
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
    // The store keys records by the origin-relative owner name the query
    // path looks up (D22): "new.example.test" becomes "new".
    let key = ("new".to_string(), RecordType::A);
    assert!(
        z.records.contains_key(&key),
        "zone must contain the new A record under its relative owner"
    );
    assert_eq!(z.records.get(&key).unwrap().len(), 1);
    assert_eq!(z.records.get(&key).unwrap()[0].value, "1.2.3.4");
}

#[test]
fn update_authorized_delete_a_record_succeeds() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
    zone.records.insert(
        ("del".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "del".to_string(),
            record_type: RecordType::A,
            value: "10.0.0.2".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example.test".to_string(), zone);

    let handler = handler(zones.clone());
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
    let key = ("del".to_string(), RecordType::A);
    assert!(
        !z.records.contains_key(&key),
        "zone must no longer contain the deleted A record"
    );
}

/// ANY + ANY + TTL 0 + RDLENGTH 0 on a name that does not exist is NXDOMAIN.
#[test]
fn update_prerequisite_name_not_in_use_failure_returns_nxdomain() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    // "Name is in use" for a name that is not in use.
    let query =
        build_update_with_prerequisite("example.test", "missing.example.test", 255, CLASS_ANY);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_ok(),
        "prerequisite failure is a response, not an Err"
    );
    let response = result.unwrap();
    let rcode = response[3] & 0x0F;
    assert_eq!(
        rcode,
        wire::UPDATE_RCODE_NXDOMAIN,
        "name-in-use prerequisite on a missing name must be NXDOMAIN"
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "zone serial must remain unchanged");
}

/// ANY + type + TTL 0 + RDLENGTH 0 on a missing RRset is NXRRSET.
#[test]
fn update_prerequisite_rrset_missing_returns_nxrrset() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    // "RRset exists (value independent)" for an A RRset that does not exist.
    let query = build_update_with_prerequisite("example.test", "www.example.test", 1, CLASS_ANY);

    let response = handler.handle_update(&query, client).unwrap();
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_NXRRSET,
        "missing RRset prerequisite must be NXRRSET"
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "zone serial must remain unchanged");
}

/// ANY + type + TTL 0 + RDLENGTH 0 on an existing RRset holds → NOERROR.
#[test]
fn update_prerequisite_rrset_exists_succeeds() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
    zone.records.insert(
        ("exists".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "exists".to_string(),
            record_type: RecordType::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example.test".to_string(), zone);

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_with_prerequisite("example.test", "exists.example.test", 1, CLASS_ANY);

    let response = handler.handle_update(&query, client).unwrap();
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_NOERROR,
        "existing RRset prerequisite must hold"
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(
        z.serial, 1,
        "zone serial must remain unchanged (no update records)"
    );
}

/// NONE + type + TTL 0 + RDLENGTH 0 on an existing RRset is YXRRSET.
#[test]
fn update_prerequisite_rrset_not_exists_failure_returns_yxrrset() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut zone = zone_with_soa("example.test", 1);
    zone.records.insert(
        ("exists".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "exists".to_string(),
            record_type: RecordType::A,
            value: "10.0.0.1".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zones.insert("example.test".to_string(), zone);

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query =
        build_update_with_prerequisite("example.test", "exists.example.test", 1, CLASS_NONE);

    let response = handler.handle_update(&query, client).unwrap();
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_YXRRSET,
        "not-exists prerequisite on an existing RRset must be YXRRSET"
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "zone serial must remain unchanged");
}

/// NONE + ANY + TTL 0 + RDLENGTH 0 on a name in use is YXDOMAIN.
#[test]
fn update_prerequisite_name_not_in_use_failure_returns_yxdomain() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    // "Name is not in use" for the apex, which the SOA makes exist.
    let query = build_update_with_prerequisite("example.test", "@", 255, CLASS_NONE);

    let response = handler.handle_update(&query, client).unwrap();
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_YXDOMAIN,
        "name-not-in-use prerequisite on an existing name must be YXDOMAIN"
    );

    let z = zones.get("example.test").unwrap();
    assert_eq!(z.serial, 1, "zone serial must remain unchanged");
}

/// RFC 2136 §3.4.2.3: an apex SOA RRset delete is ignored, not fatal.
#[test]
fn update_apex_soa_delete_is_ignored() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_delete_record("example.test", "@", 6);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "the update is answered, not an error");
    let response = result.unwrap();
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_NOERROR,
        "a protected apex delete is ignored and the update still succeeds"
    );

    let z = zones.get("example.test").unwrap();
    assert!(
        z.records.contains_key(&("@".to_string(), RecordType::SOA)),
        "SOA must survive an apex SOA delete"
    );
}

/// RFC 2136 §3.4.2.2: an SOA add with a newer serial replaces the SOA.
#[test]
fn update_soa_add_with_newer_serial_replaces_soa() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_duplicate_soa_add("example.test", 999);

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response[3] & 0x0F,
        wire::UPDATE_RCODE_NOERROR,
        "an add with a newer SOA serial is applied"
    );

    let z = zones.get("example.test").unwrap();
    let soa_records = z.records.get(&("@".to_string(), RecordType::SOA)).unwrap();
    assert_eq!(
        soa_records.len(),
        1,
        "only one SOA record must remain after replacement"
    );
    assert_eq!(z.serial, 999, "the zone serial follows the added SOA");
    assert!(
        soa_records[0].value.split_whitespace().nth(2) == Some("999"),
        "the served SOA RDATA carries the same serial, got '{}'",
        soa_records[0].value
    );
}

/// RFC 2136 §3.4.2.2: CNAME never coexists with other data; the conflicting
/// update RR is ignored and the rest of the transaction still applies.
#[test]
fn update_invalid_cname_coexistence_ignored() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = handler(zones.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_invalid_cname_coexistence("example.test");

    let result = handler.handle_update(&query, client);
    assert!(result.is_ok(), "the update is answered: {:?}", result.err());

    let z = zones.get("example.test").unwrap();
    let www_cname = z.records.get(&("www".to_string(), RecordType::CNAME));
    let www_a = z.records.get(&("www".to_string(), RecordType::A));
    assert!(
        www_cname.is_none() || www_a.is_none(),
        "CNAME and A must not coexist for one owner"
    );
    assert!(
        www_a.is_some(),
        "the non-conflicting A add must still apply"
    );
}

#[test]
fn update_require_tsig_absent_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));

    let handler = DynamicUpdateHandler::new(zones.clone())
        .with_tsig_verifier(test_verifier())
        .with_config(true, true, true)
        .expect("require_tsig with a verifier may be constructed");
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("example.test", "new.example.test", 1, &[1, 2, 3, 4], 300);

    let result = handler.handle_update(&query, client);
    assert!(
        result.is_err(),
        "require_tsig=true without TSIG must return Err"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("TSIG"),
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
        .expect("no TSIG required")
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

    let handler = handler(zones.clone());
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
    let soa = &z.records.get(&("@".to_string(), RecordType::SOA)).unwrap()[0];
    assert!(
        soa.value
            .split_whitespace()
            .nth(2)
            .and_then(|serial| serial.parse::<u32>().ok())
            == Some(z.serial),
        "the served SOA serial must match the zone serial"
    );
}

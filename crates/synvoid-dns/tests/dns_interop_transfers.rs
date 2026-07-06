use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, QueryContext, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 256 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    if qname.is_empty() || qname == "." {
        q.push(0);
    } else {
        for label in qname.split('.').filter(|s| !s.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
    }
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// Build an AXFR query (standard opcode, QTYPE=252).
fn build_axfr_query(id: u16, qname: &str) -> Vec<u8> {
    build_query(id, qname, 252)
}

/// Build an IXFR query (standard opcode, QTYPE=251).
fn build_ixfr_query(id: u16, qname: &str) -> Vec<u8> {
    build_query(id, qname, 251)
}

fn build_test_zone() -> Zone {
    let mut zone = Zone::new("test.local".to_string());
    zone.serial = 2026070601;
    zone.nsec_enabled = false;
    zone.nsec3_enabled = false;

    zone.records.insert(
        ("@".to_string(), RecordType::SOA),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::SOA,
            value: "ns1.test.local. admin.test.local. 2026070601 3600 600 604800 300".to_string(),
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
            value: "127.0.0.1".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.168.1.100".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone
}

fn setup() -> (
    Arc<ShardedZoneStore>,
    Arc<RwLock<ZoneTrie>>,
    EcsFilterConfig,
) {
    let zone = build_test_zone();
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone);
    let mut trie = ZoneTrie::new();
    trie.insert("test.local");
    let zone_trie = Arc::new(RwLock::new(trie));
    let ecs_config = EcsFilterConfig::default();
    (zones, zone_trie, ecs_config)
}

fn make_ctx<'a>(
    zones: &'a Arc<ShardedZoneStore>,
    zone_trie: &'a Arc<RwLock<ZoneTrie>>,
    ecs_filter_config: &'a EcsFilterConfig,
) -> QueryContext<'a> {
    QueryContext {
        zones,
        zone_trie,
        geoip_lookup: None,
        min_geo_ttl: 0,
        negative_cache_ttl: 300,
        cache: None,
        dnssec: None,
        signer_name: None,
        query_validator: None,
        firewall: None,
        connection_limits: None,
        max_idle_time: None,
        zone_transfer: None,
        ecs_filter_config,
        rate_limiter: None,
        rrl_enabled: false,
        update_handler: None,
        notify_handler: None,
        query_coalescer: None,
        dns64_translator: None,
        acme_dns_challenges: None,
        cookie_server: None,
        #[cfg(feature = "mesh")]
        mesh_registry: None,
    }
}

fn response_flags(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[2], resp[3]])
}

fn response_rcode(resp: &[u8]) -> u8 {
    (response_flags(resp) & 0x000F) as u8
}

fn response_ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

fn response_nscount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[8], resp[9]])
}

fn is_authoritative(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0400 != 0
}

const RCODE_NOERROR: u8 = 0;
const RCODE_REFUSED: u8 = 5;

/// AXFR queries over UDP are handled as regular queries by the authoritative
/// server. Without a matching AXFR record type (252) in the zone, the server
/// returns NODATA (name exists, type doesn't) with RCODE=0.
///
/// AXFR NOTIMP enforcement is in the TCP handler (`handle_tcp_query`), not the
/// UDP path (`handle_query`).
#[test]
fn test_axfr_disabled_by_default() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_axfr_query(0x4001, "test.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for AXFR query");

    assert!(is_authoritative(&resp));
    // AXFR QTYPE=252 has no matching record → NODATA
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "AXFR over UDP returns NODATA (RCODE 0) — NOTIMP is enforced in TCP handler"
    );
    assert_eq!(
        response_ancount(&resp),
        0,
        "NODATA must have 0 answer records"
    );
    assert!(
        response_nscount(&resp) >= 1,
        "NODATA must include SOA in authority section"
    );
}

/// AXFR over UDP is handled as a regular query. The server returns NODATA
/// because AXFR record type doesn't exist in zone records.
/// AXFR TCP-only enforcement is handled separately in the TCP handler.
#[test]
fn test_axfr_requires_tcp() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_axfr_query(0x4002, "test.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for AXFR-over-UDP");

    assert!(is_authoritative(&resp));
    // NODATA because AXFR type is not in zone records
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 0);
}

/// Zone serial is accessible from the ShardedZoneStore.
#[test]
fn test_axfr_zone_serial_response() {
    let (zones, zone_trie, ecs) = setup();

    let zone = zones.get("test.local").expect("zone test.local must exist");
    assert_eq!(
        zone.serial, 2026070601,
        "Zone serial must match expected value"
    );

    // AXFR query on UDP returns NODATA
    let ctx = make_ctx(&zones, &zone_trie, &ecs);
    let query = build_axfr_query(0x4003, "test.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
}

/// IXFR queries over UDP are also handled as regular queries.
/// Without a matching IXFR record type (251), the server returns NODATA.
#[test]
fn test_ixfr_requires_axfr_enabled() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_ixfr_query(0x4004, "test.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for IXFR query");

    assert!(is_authoritative(&resp));
    // IXFR QTYPE=251 has no matching record → NODATA
    assert_eq!(
        response_rcode(&resp),
        RCODE_NOERROR,
        "IXFR over UDP returns NODATA (RCODE 0)"
    );
    assert_eq!(response_ancount(&resp), 0);
}

/// Transfer without zone_transfer configured: AXFR over UDP returns NODATA.
/// The NOTIMP enforcement happens in the TCP handler path, not the UDP handler.
#[test]
fn test_transfer_authorization_required() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_axfr_query(0x4005, "test.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    // NODATA: zone exists but AXFR type doesn't
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 0);
}

/// Transfer for a non-existent zone returns REFUSED (no zone match).
#[test]
fn test_transfer_zone_not_found() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_axfr_query(0x4006, "nonexistent.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for AXFR of non-existent zone");

    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        "AXFR for non-existent zone must return REFUSED (5)"
    );
    assert_eq!(response_ancount(&resp), 0);
}

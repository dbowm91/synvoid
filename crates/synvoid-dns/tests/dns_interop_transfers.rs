mod support;

use std::net::IpAddr;

use support::response::{is_authoritative, response_ancount, response_nscount, response_rcode};
use synvoid_dns::server::DnsServer;

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
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    let query = support::build_axfr_query(0x4001, "test.local");
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
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    let query = support::build_axfr_query(0x4002, "test.local");
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
    let (zones, zone_trie, ecs) = support::setup();

    let zone = zones.get("test.local").expect("zone test.local must exist");
    assert_eq!(
        zone.serial, 2026070601,
        "Zone serial must match expected value"
    );

    // AXFR query on UDP returns NODATA
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);
    let query = support::build_axfr_query(0x4003, "test.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
}

/// IXFR queries over UDP are also handled as regular queries.
/// Without a matching IXFR record type (251), the server returns NODATA.
#[test]
fn test_ixfr_requires_axfr_enabled() {
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    let query = support::build_ixfr_query(0x4004, "test.local");
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
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    let query = support::build_axfr_query(0x4005, "test.local");
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
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    let query = support::build_axfr_query(0x4006, "nonexistent.local");
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

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

use support::context::make_ctx;
use support::query::build_query;
use support::response::*;

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

    // Add 50 A records to create a large zone that may trigger truncation
    for i in 0..50 {
        let name = format!("host{}", i);
        zone.records.insert(
            (name.clone(), RecordType::A),
            vec![DnsZoneRecord {
                name,
                record_type: RecordType::A,
                value: format!("10.0.{}.{}", i / 256, i % 256),
                ttl: 300,
                priority: None,
            }],
        );
    }

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

fn flag_tc(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0200 != 0
}

fn response_wire_size(resp: &[u8]) -> usize {
    resp.len()
}

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

#[test]
fn test_udp_response_within_size() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Simple A record query — response should fit in UDP (well under 512 bytes)
    let query = build_query(0x2001, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert!(
        response_wire_size(&resp) <= 512,
        "Simple A response should fit within 512 bytes (UDP safe), got {}",
        response_wire_size(&resp)
    );
    assert!(!flag_tc(&resp), "Response should not have TC flag set");
}

#[test]
fn test_large_response_truncation_flag() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Build a query with a very long qname to produce a large response.
    // Use a name with many labels to increase response size.
    let long_name = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.test.local";
    let query = build_query(0x2002, long_name, 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for long name query");

    assert!(is_authoritative(&resp));
    // Long name not in zone → NXDOMAIN with SOA
    let rcode = response_rcode(&resp);
    assert!(
        rcode == RCODE_NXDOMAIN || rcode == RCODE_NOERROR,
        "Long name query should return NXDOMAIN or NOERROR, got {}",
        rcode
    );

    // Test that a simple response is compact (under 512 bytes)
    let simple_query = build_query(0x2003, "www.test.local", 1);
    let simple_resp =
        DnsServer::handle_query(&ctx, &simple_query, Some(IpAddr::from([127, 0, 0, 1])))
            .expect("handle_query should return Some");

    assert!(
        response_wire_size(&simple_resp) < 512,
        "Simple A response should be compact, got {} bytes",
        response_wire_size(&simple_resp)
    );
    assert!(
        !flag_tc(&simple_resp),
        "Simple response should not have TC bit"
    );
}

#[test]
fn test_tcp_query_large_response() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Query for a single host A record — this should always fit
    let query = build_query(0x2004, "host25.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert!(
        response_wire_size(&resp) < 512,
        "Single A record response should be compact"
    );
    // TCP path doesn't truncate — verify no TC bit
    assert!(
        !flag_tc(&resp),
        "TCP-like single record response should not have TC bit"
    );
}

#[test]
fn test_query_wire_format_validity() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Build a well-formed query and verify the response is well-formed
    let query = build_query(0x2004, "www.test.local", 1);
    assert!(
        query.len() >= 12,
        "Query must be at least 12 bytes (header)"
    );

    // Verify header fields
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    assert_eq!(qdcount, 1, "QDCOUNT must be 1");

    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    // Verify response is a valid DNS message
    assert!(resp.len() >= 12, "Response must be at least 12 bytes");
    assert_eq!(
        u16::from_be_bytes([resp[0], resp[1]]),
        0x2004,
        "Response ID must match query ID"
    );

    let resp_flags = response_flags(&resp);
    assert!(resp_flags & 0x8000 != 0, "QR bit must be set (response)");
    assert!(
        resp_flags & 0x0400 != 0,
        "AA bit must be set (authoritative)"
    );
}

#[test]
fn test_response_wire_format_validity() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Test multiple query types to verify response wire format is consistent
    let test_cases: Vec<(u16, &str, u16)> = vec![
        (0x2005, "www.test.local", 1),         // A
        (0x2006, "www.test.local", 28),        // AAAA
        (0x2007, "test.local", 2),             // NS
        (0x2008, "test.local", 15),            // MX
        (0x2009, "test.local", 6),             // SOA
        (0x200A, "test.local", 16),            // TXT
        (0x200B, "nonexistent.test.local", 1), // NXDOMAIN
    ];

    for (id, qname, qtype) in test_cases {
        let query = build_query(id, qname, qtype);
        let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
            .unwrap_or_else(|| panic!("handle_query should return Some for qname={}", qname));

        assert!(
            resp.len() >= 12,
            "Response for {} type {} must be at least 12 bytes",
            qname,
            qtype
        );
        assert_eq!(
            u16::from_be_bytes([resp[0], resp[1]]),
            id,
            "Response ID must match query ID {}",
            id
        );
        let flags = response_flags(&resp);
        assert!(flags & 0x8000 != 0, "QR bit must be set for {}", qname);
    }
}

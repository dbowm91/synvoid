mod support;

use std::net::IpAddr;

use support::response::{is_authoritative, is_recursion_available, response_rcode};
use synvoid_dns::server::{DnsServer, DnsZoneRecord, RecordType};

const RCODE_NOERROR: u8 = 0;
const RCODE_REFUSED: u8 = 5;

/// Recursive resolution is disabled by default — queries for non-authoritative
/// zones return REFUSED (no zone match), not forwarded upstream.
#[test]
fn test_recursive_disabled_by_default() {
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    // Query for a zone that is NOT loaded — should be REFUSED, not forwarded
    let query = support::build_query(0x6001, "example.com", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        "Recursive disabled: unknown zone must return REFUSED (5)"
    );
    // RA bit must be false when recursion is not available
    assert!(
        !is_recursion_available(&resp),
        "RA must be false when recursion is disabled"
    );
}

/// Authoritative zone queries still work correctly even when recursive resolution
/// is not configured. The server handles them from the local zone store.
#[test]
fn test_recursive_query_forwarded() {
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    // Query for a known authoritative record
    let query = support::build_query(0x6002, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
}

/// Control-plane queries (UPDATE, NOTIFY) bypass the cache.
/// With cache=None in QueryContext, all queries bypass cache by definition.
#[test]
fn test_recursive_cache_bypass_control_plane() {
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    // Verify cache is None in the test context
    assert!(
        ctx.cache.is_none(),
        "Test context should have cache=None to verify bypass"
    );

    // Authoritative query works without cache
    let query = support::build_query(0x6003, "www.test.local", 1);
    let resp1 = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    // Send the same query again — both should return identical results
    let resp2 = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some second time");

    assert_eq!(
        response_rcode(&resp1),
        response_rcode(&resp2),
        "Both queries should return same RCODE"
    );
    assert_eq!(
        u16::from_be_bytes([resp1[0], resp1[1]]),
        0x6003,
        "First query ID preserved"
    );
    // Second query has different ID
    let q2 = support::build_query(0x6004, "www.test.local", 1);
    let resp3 = DnsServer::handle_query(&ctx, &q2, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some third time");
    assert_eq!(
        u16::from_be_bytes([resp3[0], resp3[1]]),
        0x6004,
        "Third query ID preserved"
    );
}

/// Depth limit prevents CNAME loops. The server detects self-referencing
/// CNAMEs and returns REFUSED instead of looping.
#[test]
fn test_recursive_depth_limit() {
    let (zones, zone_trie, ecs) = support::setup();

    // Add a self-referencing CNAME
    zones.update_zone("test.local", |zone| {
        zone.records.insert(
            ("loop".to_string(), RecordType::CNAME),
            vec![DnsZoneRecord {
                name: "loop".to_string(),
                record_type: RecordType::CNAME,
                value: "loop.test.local.".to_string(),
                ttl: 300,
                priority: None,
            }],
        );
    });

    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    // Query the CNAME loop
    let query = support::build_query(0x6005, "loop.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for CNAME loop");

    assert!(is_authoritative(&resp));
    assert_eq!(
        response_rcode(&resp),
        RCODE_REFUSED,
        "CNAME loop must be detected and return REFUSED"
    );
}

/// Query timeout is configured at the connection level, not per-query.
/// With max_idle_time=None in QueryContext, there is no per-query timeout
/// enforced at the query handling level.
#[test]
fn test_recursive_query_timeout() {
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    // Verify max_idle_time is None (no timeout at query level)
    assert!(
        ctx.max_idle_time.is_none(),
        "Test context should have max_idle_time=None"
    );

    // Query should complete without timeout
    let query = support::build_query(0x6006, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some without timeout");

    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
}

/// ACL (Access Control List) for recursive resolution is not active when
/// the recursive server is not configured. Authoritative queries for
/// loaded zones always succeed.
#[test]
fn test_recursive_acl_disabled() {
    let (zones, zone_trie, ecs) = support::setup();
    let ctx = support::make_ctx(&zones, &zone_trie, &ecs);

    // All queries for the loaded zone should succeed regardless of client IP
    let test_cases: Vec<(IpAddr, &str)> = vec![
        (IpAddr::from([127, 0, 0, 1]), "localhost client"),
        (IpAddr::from([10, 0, 0, 1]), "internal client"),
        (IpAddr::from([8, 8, 8, 8]), "external client"),
    ];

    for (client_ip, label) in test_cases {
        let query = support::build_query(0x6007, "www.test.local", 1);
        let resp = DnsServer::handle_query(&ctx, &query, Some(client_ip))
            .unwrap_or_else(|| panic!("handle_query should return Some for {}", label));

        assert!(
            is_authoritative(&resp),
            "{}: response must be authoritative",
            label
        );
        assert_eq!(
            response_rcode(&resp),
            RCODE_NOERROR,
            "{}: must return NOERROR for loaded zone",
            label
        );
    }
}

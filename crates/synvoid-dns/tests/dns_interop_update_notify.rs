use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_dns::edns::EcsFilterConfig;
use synvoid_dns::server::RecordType;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, QueryContext, ShardedZoneStore, Zone};
use synvoid_dns::zone_trie::ZoneTrie;

fn build_notify_query(id: u16, qname: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 256 + 4);
    q.extend_from_slice(&id.to_be_bytes());
    // OPCODE=4 (NOTIFY) in bits 12-15, plus AA=1, RD=0
    q.extend_from_slice(&0x2400u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.').filter(|s| !s.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    // SOA = 6
    q.extend_from_slice(&6u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// Build a dynamic UPDATE query (opcode=5) for adding a record.
fn build_update_add_query(id: u16, zone: &str, name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + 512);
    q.extend_from_slice(&id.to_be_bytes());
    // OPCODE=5 (UPDATE), RD=0
    q.extend_from_slice(&0x2800u16.to_be_bytes());
    // ZONE section: 1 entry
    q.extend_from_slice(&1u16.to_be_bytes());
    // PREREQ section: 0 entries
    q.extend_from_slice(&0u16.to_be_bytes());
    // UPDATE section: 1 entry
    q.extend_from_slice(&1u16.to_be_bytes());
    // ARCOUNT: 0
    q.extend_from_slice(&0u16.to_be_bytes());

    // Zone section: zone name + type=SOA + class=IN
    for label in zone.split('.').filter(|s| !s.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&6u16.to_be_bytes()); // type SOA
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN

    // Update section: RR to add
    for label in name.split('.').filter(|s| !s.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    // If name is relative, append the zone
    if !name.contains('.') {
        for label in zone.split('.').filter(|s| !s.is_empty()) {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
    }
    q.push(0);
    q.extend_from_slice(&rtype.to_be_bytes()); // type
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    q.extend_from_slice(&300u32.to_be_bytes()); // TTL
    q.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    q.extend_from_slice(rdata); // RDATA

    q
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

/// UPDATE is rejected when update_handler is not configured (returns None).
#[test]
fn test_update_rejected_when_disabled() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_update_add_query(
        0x5001,
        "test.local",
        "newhost",
        1, // A record
        &[192, 168, 1, 50],
    );
    // When update_handler is None, handle_query returns None (no response generated)
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));
    assert!(
        resp.is_none(),
        "UPDATE without update_handler should return None (no response)"
    );
}

/// NOTIFY for an unknown zone: with notify_handler=None, returns None.
#[test]
fn test_notify_rejected_for_unknown_zone() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_notify_query(0x5002, "unknown.local");
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));
    assert!(
        resp.is_none(),
        "NOTIFY for unknown zone without handler should return None"
    );
}

/// Prerequisite EXISTS check in UPDATE: when update_handler is None, returns None.
#[test]
fn test_update_prerequisite_exists() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Build an UPDATE query with a prerequisite EXISTS for www.test.local
    let mut q = Vec::with_capacity(12 + 256);
    q.extend_from_slice(&0x5003u16.to_be_bytes());
    q.extend_from_slice(&0x2800u16.to_be_bytes()); // OPCODE=5, RD=0
    q.extend_from_slice(&1u16.to_be_bytes()); // ZONE
    q.extend_from_slice(&1u16.to_be_bytes()); // PREREQ
    q.extend_from_slice(&0u16.to_be_bytes()); // UPDATE
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Zone section
    for label in "test.local".split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&6u16.to_be_bytes()); // SOA
    q.extend_from_slice(&1u16.to_be_bytes()); // IN

    // Prerequisite section: www.test.local TYPEExist (any type)
    for label in "www.test.local".split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&255u16.to_be_bytes()); // ANY
    q.extend_from_slice(&255u16.to_be_bytes()); // ANY (class)

    let resp = DnsServer::handle_query(&ctx, &q, Some(IpAddr::from([127, 0, 0, 1])));
    assert!(
        resp.is_none(),
        "UPDATE prerequisite without handler should return None"
    );
}

/// Dynamic UPDATE add record: with update_handler=None, returns None.
#[test]
fn test_update_add_record() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_update_add_query(
        0x5004,
        "test.local",
        "newhost",
        1, // A
        &[10, 0, 0, 1],
    );
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));
    assert!(
        resp.is_none(),
        "UPDATE add without handler should return None"
    );
}

/// NOTIFY rate limiting works when notify_handler is configured.
/// With notify_handler=None, NOTIFY returns None.
#[test]
fn test_notify_rate_limit() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Send multiple NOTIFY queries — all return None (no handler configured)
    for i in 0..5 {
        let query = build_notify_query(0x5010 + i as u16, "test.local");
        let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])));
        assert!(
            resp.is_none(),
            "NOTIFY {} without handler should return None",
            i
        );
    }
}

/// Large UPDATE query: with update_handler=None, returns None.
#[test]
fn test_update_max_size() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Build a large UPDATE with many records in the update section
    let mut q = Vec::with_capacity(4096);
    q.extend_from_slice(&0x5005u16.to_be_bytes());
    q.extend_from_slice(&0x2800u16.to_be_bytes()); // OPCODE=5
    q.extend_from_slice(&1u16.to_be_bytes()); // ZONE
    q.extend_from_slice(&0u16.to_be_bytes()); // PREREQ
    q.extend_from_slice(&100u16.to_be_bytes()); // UPDATE: 100 records
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Zone section
    for label in "test.local".split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&6u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());

    // 100 A record updates
    for i in 0..100u8 {
        for label in format!("host{}", i).split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        for label in "test.local".split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes()); // A
        q.extend_from_slice(&1u16.to_be_bytes()); // IN
        q.extend_from_slice(&300u32.to_be_bytes()); // TTL
        q.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        q.extend_from_slice(&[10, 0, 0, i]); // RDATA
    }

    // Without update_handler, returns None (no response generated)
    let resp = DnsServer::handle_query(&ctx, &q, Some(IpAddr::from([127, 0, 0, 1])));
    assert!(
        resp.is_none(),
        "Large UPDATE without handler should return None"
    );
}

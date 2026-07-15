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
    zone.records.insert(
        ("www".to_string(), RecordType::AAAA),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::AAAA,
            value: "fd00::100".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("mail".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "mail".to_string(),
            record_type: RecordType::A,
            value: "192.168.1.200".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("@".to_string(), RecordType::MX),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::MX,
            value: "mail".to_string(),
            ttl: 300,
            priority: Some(10),
        }],
    );
    zone.records.insert(
        ("@".to_string(), RecordType::TXT),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::TXT,
            value: "v=spf1 include:_spf.example.com ~all".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("_sip._tcp".to_string(), RecordType::SRV),
        vec![DnsZoneRecord {
            name: "_sip._tcp".to_string(),
            record_type: RecordType::SRV,
            value: "sip.example.com 5060".to_string(),
            ttl: 300,
            priority: Some(10),
        }],
    );
    zone.records.insert(
        ("cdn".to_string(), RecordType::CNAME),
        vec![DnsZoneRecord {
            name: "cdn".to_string(),
            record_type: RecordType::CNAME,
            value: "www".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("ptr".to_string(), RecordType::PTR),
        vec![DnsZoneRecord {
            name: "ptr".to_string(),
            record_type: RecordType::PTR,
            value: "www".to_string(),
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

fn skip_question_section(resp: &[u8]) -> usize {
    let mut pos = 12;
    pos = skip_wire_name(resp, pos);
    pos += 4;
    pos
}

fn first_answer_rr_type(resp: &[u8]) -> Option<u16> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    Some(u16::from_be_bytes([resp[pos], resp[pos + 1]]))
}

fn first_answer_a_rdata(resp: &[u8]) -> Option<std::net::Ipv4Addr> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    let rdata_start = pos + 10;
    if rdata_start + rdlength > resp.len() || rdlength != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        resp[rdata_start],
        resp[rdata_start + 1],
        resp[rdata_start + 2],
        resp[rdata_start + 3],
    ))
}

fn first_answer_aaaa_rdata(resp: &[u8]) -> Option<std::net::Ipv6Addr> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    let rdata_start = pos + 10;
    if rdata_start + rdlength > resp.len() || rdlength != 16 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&resp[rdata_start..rdata_start + 16]);
    Some(std::net::Ipv6Addr::from(octets))
}

fn first_answer_cname_rdata(resp: &[u8]) -> Option<String> {
    let ancount = response_ancount(resp) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = skip_question_section(resp);
    pos = skip_wire_name(resp, pos);
    if pos + 10 > resp.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
    let rdata_start = pos + 10;
    if rdata_start + rdlength > resp.len() {
        return None;
    }
    decode_wire_name(resp, rdata_start)
}

fn decode_wire_name(resp: &[u8], start: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    for _ in 0..10 {
        if pos >= resp.len() {
            return None;
        }
        let len = resp[pos] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= resp.len() {
                return None;
            }
            let offset = (len & 0x3F) << 8 | resp[pos + 1] as usize;
            if !jumped {
                jumped = true;
            }
            pos = offset;
            continue;
        }
        pos += 1;
        if pos + len > resp.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&resp[pos..pos + len]).to_string());
        pos += len;
    }
    let _ = jumped;
    Some(parts.join("."))
}

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

#[test]
fn test_authoritative_a_record_lookup() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_query(0x1001, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(1));
    assert_eq!(
        first_answer_a_rdata(&resp),
        Some(std::net::Ipv4Addr::new(192, 168, 1, 100))
    );
}

#[test]
fn test_authoritative_aaaa_record_lookup() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // AAAA = 28
    let query = build_query(0x1002, "www.test.local", 28);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(28));
    assert_eq!(
        first_answer_aaaa_rdata(&resp),
        Some("fd00::100".parse().unwrap())
    );
}

#[test]
fn test_authoritative_ns_record_lookup() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // NS = 2
    let query = build_query(0x1003, "test.local", 2);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(2));
}

#[test]
fn test_authoritative_mx_record_lookup() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // MX = 15
    let query = build_query(0x1004, "test.local", 15);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(15));

    // Verify MX RDATA: priority (10) + exchange name
    let mut pos = skip_question_section(&resp);
    pos = skip_wire_name(&resp, pos);
    if pos + 10 <= resp.len() {
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        if rdata_start + rdlen <= resp.len() && rdlen >= 2 {
            let priority = u16::from_be_bytes([resp[rdata_start], resp[rdata_start + 1]]);
            assert_eq!(priority, 10, "MX priority must be 10");
        }
    }
}

#[test]
fn test_authoritative_cname_chain() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // CNAME = 5
    let query = build_query(0x1005, "cdn.test.local", 5);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(5));

    // CNAME target is "www" (relative), which is returned as-is in wire format
    let cname = first_answer_cname_rdata(&resp).expect("CNAME RDATA must be present");
    assert_eq!(cname, "www");
}

#[test]
fn test_authoritative_txt_record_lookup() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // TXT = 16
    let query = build_query(0x1006, "test.local", 16);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(16));
}

#[test]
fn test_authoritative_soa_on_nxdomain() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    let query = build_query(0x1007, "nonexistent.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NXDOMAIN);
    assert_eq!(response_ancount(&resp), 0);
    assert!(
        response_nscount(&resp) >= 1,
        "NXDOMAIN must include SOA in authority section"
    );

    // Verify SOA is in the authority section
    let mut pos = skip_question_section(&resp);
    let nscount = response_nscount(&resp) as usize;
    let mut found_soa = false;
    for _ in 0..nscount {
        pos = skip_wire_name(&resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        if rr_type == 6 {
            found_soa = true;
        }
        pos += 10 + rdlen;
    }
    assert!(found_soa, "NXDOMAIN authority section must contain SOA");
}

#[test]
fn test_authoritative_qname_minimization() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Query for a deeply nested subdomain should parse correctly
    let query = build_query(0x1008, "a.b.c.d.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for deeply nested query");

    // Should be NXDOMAIN since a.b.c.d.test.local doesn't exist in the zone
    assert!(is_authoritative(&resp));
    let rcode = response_rcode(&resp);
    assert!(
        rcode == RCODE_NXDOMAIN || rcode == RCODE_REFUSED,
        "Non-existent subdomain should return NXDOMAIN (3) or REFUSED (5), got {}",
        rcode
    );

    // Query for ns1 (which has an A record) with a different label depth
    let query2 = build_query(0x1009, "ns1.test.local", 1);
    let resp2 = DnsServer::handle_query(&ctx, &query2, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for ns1");

    assert!(is_authoritative(&resp2));
    assert_eq!(response_rcode(&resp2), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp2), 1);
    assert_eq!(
        first_answer_a_rdata(&resp2),
        Some(std::net::Ipv4Addr::new(127, 0, 0, 1))
    );
}

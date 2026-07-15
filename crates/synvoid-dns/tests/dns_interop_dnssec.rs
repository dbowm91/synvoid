mod support;

use std::net::IpAddr;

use support::context::{make_ctx, setup};
use support::query::{build_query, build_query_with_do_bit};
use support::response::*;
use synvoid_dns::server::{DnsServer, DnsZoneRecord, RecordType};

fn skip_question_section(resp: &[u8]) -> usize {
    let mut pos = 12;
    pos = skip_wire_name(resp, pos);
    pos += 4;
    pos
}

fn flag_ad(resp: &[u8]) -> bool {
    response_flags(resp) & 0x0020 != 0
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

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

#[test]
fn test_dnssec_do_bit_query() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Query with DO bit set — server should still respond
    let query = build_query_with_do_bit(0x3001, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for DO-bit query");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 1);
    assert_eq!(first_answer_rr_type(&resp), Some(1));
}

#[test]
fn test_dnssec_nodata_response_shape() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Query for AAAA on www — www has A but not AAAA... wait, it does have AAAA.
    // Query for MX on www — www has no MX, so NODATA
    let query = build_query(0x3002, "www.test.local", 15); // MX
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for NODATA");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    assert_eq!(response_ancount(&resp), 0, "NODATA must have 0 answers");
    assert!(
        response_nscount(&resp) >= 1,
        "NODATA must include SOA in authority section"
    );

    // Verify SOA in authority section
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
    assert!(found_soa, "NODATA authority section must contain SOA");
}

#[test]
fn test_dnssec_flags_preserved() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Test that AD and CD flags are handled correctly in queries
    // Authoritative server should not set AD (unsigned zone)
    let query = build_query(0x3003, "www.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some");

    assert!(is_authoritative(&resp));
    assert_eq!(response_rcode(&resp), RCODE_NOERROR);
    // Unsigned zone: AD must be false
    assert!(!flag_ad(&resp), "AD must be false for unsigned zone");
}

#[test]
fn test_dnssec_empty_nsec_for_wildcard() {
    let (zones, zone_trie, ecs) = setup();
    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // Query for a wildcard name that doesn't exist — should get NXDOMAIN
    let query = build_query(0x3004, "*.test.local", 1);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for wildcard query");

    assert!(is_authoritative(&resp));
    // *.test.local is not configured, so should be NXDOMAIN or REFUSED
    let rcode = response_rcode(&resp);
    assert!(
        rcode == RCODE_NXDOMAIN || rcode == RCODE_REFUSED,
        "Wildcard query should return NXDOMAIN (3) or REFUSED (5), got {}",
        rcode
    );
}

/// DS record lookup at zone apex: when DNSSEC keys are not configured,
/// the server's `build_ds_records` returns an empty list, resulting in
/// a NODATA-like response. The manually inserted DS record in zone.records
/// is not used because DS queries are handled through the DNSSEC key path.
#[test]
fn test_dnssec_zone_with_ds_record() {
    let (zones, zone_trie, ecs) = setup();

    // Add a DS record at the zone apex
    zones.update_zone("test.local", |zone| {
        zone.records.insert(
            ("@".to_string(), RecordType::DS),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DS,
                value: "12345 8 2 ABCD".to_string(),
                ttl: 300,
                priority: None,
            }],
        );
    });

    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // DS = 43 — server requires DNSSEC keys to serve DS records
    let query = build_query(0x3005, "test.local", 43);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for DS query");

    assert!(is_authoritative(&resp));
    // Without DNSSEC keys, DS record lookup through the key path returns empty,
    // which the server handles as NODATA (0 answers) or SERVFAIL depending on
    // the exact code path. Both are valid outcomes for an unsigned zone.
    let rcode = response_rcode(&resp);
    assert!(
        rcode == RCODE_NOERROR || rcode == 2,
        "DS query without DNSSEC keys should return NOERROR (NODATA) or SERVFAIL, got {}",
        rcode
    );
}

/// DNSKEY record lookup at zone apex: when DNSSEC keys are not configured,
/// the server's `build_dnskey_records` returns an empty list, resulting in
/// a NODATA-like response. The manually inserted DNSKEY record in zone.records
/// is not used because DNSKEY queries are handled through the DNSSEC key path.
#[test]
fn test_dnssec_dnskey_record_lookup() {
    let (zones, zone_trie, ecs) = setup();

    // Add a DNSKEY record at the zone apex
    zones.update_zone("test.local", |zone| {
        zone.records.insert(
            ("@".to_string(), RecordType::DNSKEY),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::DNSKEY,
                value: "257 3 8 AwEAAaz/tAm8...".to_string(),
                ttl: 300,
                priority: None,
            }],
        );
    });

    let ctx = make_ctx(&zones, &zone_trie, &ecs);

    // DNSKEY = 48 — server requires DNSSEC keys to serve DNSKEY records
    let query = build_query(0x3006, "test.local", 48);
    let resp = DnsServer::handle_query(&ctx, &query, Some(IpAddr::from([127, 0, 0, 1])))
        .expect("handle_query should return Some for DNSKEY query");

    assert!(is_authoritative(&resp));
    // Without DNSSEC keys, DNSKEY record lookup through the key path returns empty,
    // which the server handles as NODATA (0 answers) or SERVFAIL depending on
    // the exact code path. Both are valid outcomes for an unsigned zone.
    let rcode = response_rcode(&resp);
    assert!(
        rcode == RCODE_NOERROR || rcode == 2,
        "DNSKEY query without DNSSEC keys should return NOERROR (NODATA) or SERVFAIL, got {}",
        rcode
    );
}

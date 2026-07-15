mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::transfer::{ZoneTransfer, IXFR_QUERY_TYPE};

use support::query::encode_qname;
use support::zone::{update_soa_value, zone_with_records, zone_with_soa};

fn build_axfr_query(zone_name: &str) -> Vec<u8> {
    support::query::build_axfr_query(0xCAFE, zone_name)
}

fn build_ixfr_query(zone_name: &str, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xCAFEu16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&synvoid_dns::transfer::IXFR_QUERY_TYPE.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    let origin_bytes = zone_name.trim_end_matches('.').as_bytes();
    buf.push(origin_bytes.len() as u8);
    buf.extend_from_slice(origin_bytes);
    buf.push(0);
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    let rdata_pos = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes());
    let rdata_start = buf.len();
    let mname = format!("ns1.{}", zone_name.trim_end_matches('.'));
    for label in mname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    let rname = format!("admin.{}", zone_name.trim_end_matches('.'));
    for label in rname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(&3600u32.to_be_bytes());
    buf.extend_from_slice(&600u32.to_be_bytes());
    buf.extend_from_slice(&604800u32.to_be_bytes());
    buf.extend_from_slice(&300u32.to_be_bytes());
    let rdata_len = buf.len() - rdata_start;
    buf[rdata_pos..rdata_pos + 2].copy_from_slice(&(rdata_len as u16).to_be_bytes());
    buf
}

struct ParsedRecord {
    record_type: u16,
    #[allow(dead_code)]
    rdata: Vec<u8>,
}

fn skip_name(buf: &[u8], pos: &mut usize) {
    while *pos < buf.len() {
        let b = buf[*pos];
        if b == 0 {
            *pos += 1;
            return;
        }
        if b & 0xC0 == 0xC0 {
            *pos += 2;
            return;
        }
        *pos += 1 + b as usize;
    }
}

#[allow(dead_code)]
fn extract_soa_serial(rdata: &[u8]) -> u32 {
    let mut pos = 0;
    skip_name(rdata, &mut pos);
    skip_name(rdata, &mut pos);
    if pos + 4 <= rdata.len() {
        u32::from_be_bytes(rdata[pos..pos + 4].try_into().unwrap())
    } else {
        0
    }
}

fn parse_axfr_messages(messages: &[Vec<u8>]) -> Vec<Vec<ParsedRecord>> {
    let mut all = Vec::new();
    for buf in messages {
        let mut records = Vec::new();
        if buf.len() < 12 {
            continue;
        }
        let qd = u16::from_be_bytes([buf[4], buf[5]]);
        let an = u16::from_be_bytes([buf[6], buf[7]]);
        let mut pos = 12;
        for _ in 0..qd {
            skip_name(buf, &mut pos);
            pos += 4;
        }
        for _ in 0..an {
            skip_name(buf, &mut pos);
            if pos + 10 > buf.len() {
                break;
            }
            let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 8;
            let rdlen = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            if pos + rdlen > buf.len() {
                break;
            }
            let rdata = buf[pos..pos + rdlen].to_vec();
            pos += rdlen;
            records.push(ParsedRecord {
                record_type: rtype,
                rdata,
            });
        }
        all.push(records);
    }
    all
}

fn make_transfer(
    zones: Arc<ShardedZoneStore>,
    allowed: Vec<String>,
    axfr_enabled: bool,
    require_tsig: bool,
    tcp_only: bool,
) -> ZoneTransfer {
    ZoneTransfer::with_security_config(
        zones,
        allowed,
        None,
        false,
        false,
        true,
        true,
        require_tsig,
        axfr_enabled,
        tcp_only,
    )
}

fn make_transfer_ixfr(
    zones: Arc<ShardedZoneStore>,
    allowed: Vec<String>,
    ixfr_enabled: bool,
    ixfr_fallback: bool,
) -> ZoneTransfer {
    ZoneTransfer::with_security_config(
        zones,
        allowed,
        None,
        false,
        false,
        ixfr_enabled,
        ixfr_fallback,
        false,
        false,
        true,
    )
}

#[test]
fn axfr_response_is_soa_bracketed() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let transfer = make_transfer(zones, vec!["10.0.0.1".to_string()], true, false, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let messages = transfer
        .handle_axfr_request_messages(
            "example.test",
            client,
            None,
            0xCAFE,
            &build_axfr_query("example.test"),
            true,
        )
        .unwrap();
    assert!(messages.len() >= 3, "need at least SOA+records+SOA");
    let first = parse_axfr_messages(&[messages[0].clone()]);
    let last = parse_axfr_messages(&[messages[messages.len() - 1].clone()]);
    assert_eq!(first[0].len(), 1);
    assert_eq!(first[0][0].record_type, 6, "first answer must be SOA");
    assert_eq!(last[0].len(), 1);
    assert_eq!(last[0][0].record_type, 6, "last answer must be SOA");
}

#[test]
fn axfr_response_includes_expected_records() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let transfer = make_transfer(zones, vec!["10.0.0.1".to_string()], true, false, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let messages = transfer
        .handle_axfr_request_messages(
            "example.test",
            client,
            None,
            0xCAFE,
            &build_axfr_query("example.test"),
            true,
        )
        .unwrap();
    let mut found_a = false;
    let mut found_ns = false;
    let mut soa_count = 0;
    for msg in &messages {
        let parsed = parse_axfr_messages(std::slice::from_ref(msg));
        for rec in &parsed[0] {
            match rec.record_type {
                1 => found_a = true,
                2 => found_ns = true,
                6 => soa_count += 1,
                _ => {}
            }
        }
    }
    assert!(found_a, "AXFR must contain A record");
    assert!(found_ns, "AXFR must contain NS record");
    assert_eq!(
        soa_count, 2,
        "AXFR must have exactly 2 SOA records (bracket)"
    );
}

#[test]
fn axfr_over_udp_refused_when_tcp_only() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let transfer = make_transfer(zones, vec!["10.0.0.1".to_string()], true, false, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let result = transfer.handle_axfr_request(
        "example.test",
        client,
        None,
        0xCAFE,
        &build_axfr_query("example.test"),
        false,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("TCP"));
}

#[test]
fn axfr_require_tsig_absent_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let transfer = make_transfer(zones, vec!["10.0.0.1".to_string()], true, true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let result = transfer.handle_axfr_request(
        "example.test",
        client,
        None,
        0xCAFE,
        &build_axfr_query("example.test"),
        true,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("TSIG"));
}

#[test]
fn axfr_unauthorized_client_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let transfer = make_transfer(zones, vec!["198.51.100.1".to_string()], true, false, true);
    let client: IpAddr = "10.0.0.99".parse().unwrap();
    let result = transfer.handle_axfr_request(
        "example.test",
        client,
        None,
        0xCAFE,
        &build_axfr_query("example.test"),
        true,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not allowed"));
}

#[test]
fn axfr_unknown_zone_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    let transfer = make_transfer(zones, vec!["10.0.0.1".to_string()], true, false, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let result = transfer.handle_axfr_request(
        "nonexistent.test",
        client,
        None,
        0xCAFE,
        &build_axfr_query("nonexistent.test"),
        true,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[test]
fn axfr_path_does_not_use_query_coalescing() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let transfer = make_transfer(zones, vec!["10.0.0.1".to_string()], true, false, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_axfr_request_messages(
            "example.test",
            client,
            None,
            0xCAFE,
            &build_axfr_query("example.test"),
            true,
        )
        .unwrap();
    assert!(!msgs.is_empty());
    let total_answers: usize = msgs
        .iter()
        .map(|m| {
            if m.len() >= 8 {
                u16::from_be_bytes([m[6], m[7]]) as usize
            } else {
                0
            }
        })
        .sum();
    assert!(
        total_answers >= 4,
        "zone with SOA+A+NS must produce >=4 answers (2 SOA + A + NS), got {}",
        total_answers
    );
}

#[test]
fn ixfr_current_serial_returns_soa_only() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 5),
    );
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_ixfr_request_messages(
            "example.test",
            client,
            Some(5),
            None,
            0xCAFE,
            &build_ixfr_query("example.test", 5),
        )
        .unwrap();
    assert_eq!(msgs.len(), 1);
    let parsed = parse_axfr_messages(&msgs);
    assert_eq!(parsed[0].len(), 1);
    assert_eq!(
        parsed[0][0].record_type, 6,
        "IXFR current serial must return SOA only"
    );
}

#[test]
fn ixfr_older_retained_serial_returns_delta() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_records("example.test", 1);
    z.increment_serial_with_limit(200);
    let new_serial = z.serial;
    update_soa_value(&mut z, "example.test", new_serial);
    z.records.insert(
        ("mail".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "mail".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.20".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    let old_serial = z.history.last().map(|h| h.serial).unwrap();
    let current_serial = z.serial;
    assert_ne!(
        old_serial, current_serial,
        "increment_serial must advance serial"
    );
    zones.insert("example.test".to_string(), z);
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_ixfr_request_messages(
            "example.test",
            client,
            Some(old_serial),
            None,
            0xCAFE,
            &build_ixfr_query("example.test", old_serial),
        )
        .unwrap();
    assert_eq!(
        msgs.len(),
        2,
        "IXFR delta must have 2 messages (delete+add)"
    );
    let parsed = parse_axfr_messages(&msgs);
    assert_eq!(
        parsed[0][0].record_type, 6,
        "first message must start with SOA"
    );
    assert_eq!(
        parsed[1][0].record_type, 6,
        "second message must start with SOA"
    );
    let first_ancount = u16::from_be_bytes([msgs[0][6], msgs[0][7]]);
    let second_ancount = u16::from_be_bytes([msgs[1][6], msgs[1][7]]);
    assert!(
        first_ancount >= 1,
        "delete section ANCOUNT must be >= 1 (SOA), got {}",
        first_ancount
    );
    assert!(
        second_ancount >= 1,
        "add section ANCOUNT must be >= 1 (SOA + mail A), got {}",
        second_ancount
    );
    assert!(
        first_ancount + second_ancount >= 3,
        "total ANCOUNT must be >= 3 (2 SOAs + mail A), got {}",
        first_ancount + second_ancount
    );
}

#[test]
fn ixfr_too_old_with_fallback_returns_full_axfr() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_records("example.test", 1);
    z.increment_serial_with_limit(200);
    zones.insert("example.test".to_string(), z);
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_ixfr_request_messages(
            "example.test",
            client,
            Some(0),
            None,
            0xCAFE,
            &build_ixfr_query("example.test", 0),
        )
        .unwrap();
    assert!(
        msgs.len() >= 3,
        "fallback to AXFR must produce SOA+records+SOA"
    );
    let first = parse_axfr_messages(&[msgs[0].clone()]);
    let last = parse_axfr_messages(&[msgs[msgs.len() - 1].clone()]);
    assert_eq!(first[0][0].record_type, 6);
    assert_eq!(last[0][0].record_type, 6);
}

#[test]
fn ixfr_too_old_without_fallback_errors() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_records("example.test", 1);
    z.increment_serial_with_limit(200);
    zones.insert("example.test".to_string(), z);
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, false);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let result = transfer.handle_ixfr_request_messages(
        "example.test",
        client,
        Some(0),
        None,
        0xCAFE,
        &build_ixfr_query("example.test", 0),
    );
    assert!(result.is_err());
}

#[test]
fn ixfr_require_tsig_absent_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let transfer = ZoneTransfer::with_security_config(
        zones,
        vec!["10.0.0.1".to_string()],
        None,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
    );
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let result = transfer.handle_ixfr_request_messages(
        "example.test",
        client,
        Some(1),
        None,
        0xCAFE,
        &build_ixfr_query("example.test", 1),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("TSIG"));
}

#[test]
fn ixfr_malformed_soa_in_additional_section_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_records("example.test", 1),
    );
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xCAFEu16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname("example.test"));
    buf.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname("example.test"));
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    let _ =
        transfer.handle_ixfr_request_messages("example.test", client, Some(1), None, 0xCAFE, &buf);
}

#[test]
fn ixfr_uses_rfc1982_serial_comparison() {
    assert!(Zone::serial_is_more_recent(1, 0xFFFFFFFF));
    assert!(!Zone::serial_is_more_recent(0xFFFFFFFF, 1));
    assert!(!Zone::serial_is_more_recent(5, 5));
    assert!(Zone::serial_is_more_recent(0x80000001, 0x7FFFFFFE));
}

#[test]
fn ixfr_serial_wraparound_fallback() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_records("example.test", 0xFFFFFFFE);
    z.increment_serial_with_limit(200);
    let current_serial = z.serial;
    zones.insert("example.test".to_string(), z);
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_ixfr_request_messages(
            "example.test",
            client,
            Some(current_serial),
            None,
            0xCAFE,
            &build_ixfr_query("example.test", current_serial),
        )
        .unwrap();
    assert_eq!(msgs.len(), 1, "same serial must return SOA-only");
    let parsed = parse_axfr_messages(&msgs);
    assert_eq!(parsed[0][0].record_type, 6);
}

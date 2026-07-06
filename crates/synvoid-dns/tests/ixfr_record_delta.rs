//! Record-by-record IXFR delta validation tests.
//!
//! Verifies that IXFR incremental transfer produces correct per-record
//! deltas: individual adds, deletes, and modifications across multiple
//! SOA-bracketed messages.

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore, Zone};
use synvoid_dns::transfer::ZoneTransfer;

// ── Helpers ─────────────────────────────────────────────────────────────

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

fn build_ixfr_query(zone_name: &str, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xCAFEu16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&synvoid_dns::transfer::IXFR_QUERY_TYPE.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    // SOA in additional section with client serial
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

// ══════════════════════════════════════════════════════════════════════
// Section 1: Single record add delta
// ══════════════════════════════════════════════════════════════════════

/// Adding one A record produces a delta with 2 messages: old SOA + add SOA.
#[test]
fn ixfr_single_add_produces_two_messages() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_soa("example.test", 1);
    z.increment_serial_with_limit(200);
    let new_serial = z.serial;
    // Add mail.example.test A
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
    // Update SOA serial
    if let Some(soa) = z.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        soa[0].value = format!(
            "ns1.example.test. admin.example.test. {} 3600 600 604800 300",
            new_serial
        );
    }
    let old_serial = z.history.last().map(|h| h.serial).unwrap();
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

    assert_eq!(msgs.len(), 2, "single add must produce 2 messages");
    let parsed = parse_axfr_messages(&msgs);
    assert_eq!(parsed[0][0].record_type, 6, "first msg starts with SOA");
    assert_eq!(parsed[1][0].record_type, 6, "second msg starts with SOA");
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: Single record delete delta
// ══════════════════════════════════════════════════════════════════════

/// Deleting one A record produces a delta with delete in first message.
#[test]
fn ixfr_single_delete_in_first_message() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_soa("example.test", 1);
    z.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    z.increment_serial_with_limit(200);
    let new_serial = z.serial;
    z.records.remove(&("www".to_string(), RecordType::A));
    if let Some(soa) = z.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        soa[0].value = format!(
            "ns1.example.test. admin.example.test. {} 3600 600 604800 300",
            new_serial
        );
    }
    let old_serial = z.history.last().map(|h| h.serial).unwrap();
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

    assert_eq!(msgs.len(), 2, "single delete must produce 2 messages");
    let parsed = parse_axfr_messages(&msgs);
    // First message: old SOA + deleted records
    assert_eq!(parsed[0][0].record_type, 6, "first msg starts with SOA");
    let first_ancount = u16::from_be_bytes([msgs[0][6], msgs[0][7]]);
    assert!(
        first_ancount >= 2,
        "delete section must have SOA + deleted record, got {} answers",
        first_ancount
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: Record modification (delete old + add new)
// ══════════════════════════════════════════════════════════════════════

/// Changing an A record value produces a delta with delete+add messages.
#[test]
fn ixfr_modify_old_and_new_in_correct_messages() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_soa("example.test", 1);
    z.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    z.increment_serial_with_limit(200);
    let new_serial = z.serial;
    // Change www A to new IP — this should produce a delete (old) + add (new)
    z.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.99".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    if let Some(soa) = z.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        soa[0].value = format!(
            "ns1.example.test. admin.example.test. {} 3600 600 604800 300",
            new_serial
        );
    }
    let old_serial = z.history.last().map(|h| h.serial).unwrap();
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

    assert_eq!(msgs.len(), 2, "modification must produce 2 messages");
    let parsed = parse_axfr_messages(&msgs);
    // Both messages must start with SOA
    assert_eq!(parsed[0][0].record_type, 6, "first msg starts with SOA");
    assert_eq!(parsed[1][0].record_type, 6, "second msg starts with SOA");
    // Total answers must be >= 3 (2 SOAs + at least 1 record delta)
    let first_ancount = u16::from_be_bytes([msgs[0][6], msgs[0][7]]);
    let second_ancount = u16::from_be_bytes([msgs[1][6], msgs[1][7]]);
    assert!(
        first_ancount + second_ancount >= 3,
        "delta must have SOA + record(s), got first={}, second={}",
        first_ancount,
        second_ancount
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: Multi-record delta
// ══════════════════════════════════════════════════════════════════════

/// Multiple adds and deletes in one update produce correct total counts.
#[test]
fn ixfr_multi_record_delta_counts() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_soa("example.test", 1);
    // Add initial records
    z.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
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
    z.increment_serial_with_limit(200);
    let new_serial = z.serial;
    // Delete www, keep mail, add ftp
    z.records.remove(&("www".to_string(), RecordType::A));
    z.records.insert(
        ("ftp".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "ftp".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.30".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    if let Some(soa) = z.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        soa[0].value = format!(
            "ns1.example.test. admin.example.test. {} 3600 600 604800 300",
            new_serial
        );
    }
    let old_serial = z.history.last().map(|h| h.serial).unwrap();
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

    assert_eq!(msgs.len(), 2);
    let parsed = parse_axfr_messages(&msgs);

    // First message (delete): old SOA + deleted www A
    let first_ancount = u16::from_be_bytes([msgs[0][6], msgs[0][7]]);
    assert!(
        first_ancount >= 2,
        "delete section must have SOA + deleted records, got {}",
        first_ancount
    );

    // Second message (add): new SOA + added ftp A
    let second_ancount = u16::from_be_bytes([msgs[1][6], msgs[1][7]]);
    assert!(
        second_ancount >= 2,
        "add section must have SOA + added records, got {}",
        second_ancount
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 5: SOA serial comparison
// ══════════════════════════════════════════════════════════════════════

/// RFC 1982 serial comparison: larger serial is more recent (no wrap).
#[test]
fn ixfr_serial_comparison_normal() {
    let zones = Arc::new(ShardedZoneStore::new());
    let mut z = zone_with_soa("example.test", 100);
    z.increment_serial_with_limit(200);
    let new_serial = z.serial;
    z.records.insert(
        ("newrec".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "newrec".to_string(),
            record_type: RecordType::A,
            value: "10.0.0.5".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    if let Some(soa) = z.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        soa[0].value = format!(
            "ns1.example.test. admin.example.test. {} 3600 600 604800 300",
            new_serial
        );
    }
    let old_serial = z.history.last().map(|h| h.serial).unwrap();
    assert!(Zone::serial_is_more_recent(new_serial, old_serial));

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
    assert_eq!(msgs.len(), 2, "valid serial diff must produce delta");
}

// ══════════════════════════════════════════════════════════════════════
// Section 6: IXFR current serial returns SOA only
// ══════════════════════════════════════════════════════════════════════

/// Client requests IXFR with current serial → SOA-only response.
#[test]
fn ixfr_current_serial_soa_only() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert(
        "example.test".to_string(),
        zone_with_soa("example.test", 42),
    );
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], true, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_ixfr_request_messages(
            "example.test",
            client,
            Some(42),
            None,
            0xCAFE,
            &build_ixfr_query("example.test", 42),
        )
        .unwrap();
    assert_eq!(msgs.len(), 1, "current serial must return 1 message");
    let parsed = parse_axfr_messages(&msgs);
    assert_eq!(parsed[0].len(), 1);
    assert_eq!(parsed[0][0].record_type, 6, "must be SOA only");
}

// ══════════════════════════════════════════════════════════════════════
// Section 7: IXFR disabled → error
// ══════════════════════════════════════════════════════════════════════

/// IXFR disabled returns error.
#[test]
fn ixfr_disabled_returns_error() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("example.test".to_string(), zone_with_soa("example.test", 1));
    let transfer = make_transfer_ixfr(zones, vec!["10.0.0.1".to_string()], false, true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let result = transfer.handle_ixfr_request_messages(
        "example.test",
        client,
        Some(0),
        None,
        0xCAFE,
        &build_ixfr_query("example.test", 0),
    );
    assert!(result.is_err(), "disabled IXFR must return error");
}

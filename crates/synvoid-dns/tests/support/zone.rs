//! Common zone construction helpers for integration tests.
//!
//! All functions return owned `Zone` values.  No global state is mutated.
#![allow(dead_code)]
use synvoid_dns::server::{DnsZoneRecord, RecordType, Zone};

/// Build a minimal test zone with SOA, NS, ns1 A, www A, alias CNAME, and _txt TXT records.
///
/// Defaults:
/// - Origin: `"test.local"`
/// - Serial: `2026070601`
/// - NSEC/NSEC3: disabled
/// - TTL: 300 for all records (SOA minimum, NS, A, CNAME, TXT)
///
/// Override the serial or origin after construction if needed:
/// ```ignore
/// let mut zone = build_test_zone();
/// zone.serial = 2026070701;
/// zone.origin = "custom.local".to_string();
/// ```
pub fn build_test_zone() -> Zone {
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
            value: "192.0.2.53".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("www".to_string(), RecordType::A),
        vec![DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("alias".to_string(), RecordType::CNAME),
        vec![DnsZoneRecord {
            name: "alias".to_string(),
            record_type: RecordType::CNAME,
            value: "www.test.local.".to_string(),
            ttl: 300,
            priority: None,
        }],
    );
    zone.records.insert(
        ("_txt".to_string(), RecordType::TXT),
        vec![DnsZoneRecord {
            name: "_txt".to_string(),
            record_type: RecordType::TXT,
            value: "hello".to_string(),
            ttl: 300,
            priority: None,
        }],
    );

    zone
}

/// Build a zone containing only a SOA record.
///
/// Useful for transfer, notify, and update tests that need a minimal
/// valid zone without additional record types.
///
/// Parameters:
/// - `origin`: the zone origin (e.g. `"example.test"`)
/// - `serial`: the SOA serial number
pub fn zone_with_soa(origin: &str, serial: u32) -> Zone {
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

/// Build a zone with SOA + NS + www A records.
///
/// A convenience wrapper around [`zone_with_soa`] that adds commonly
/// needed records for transfer and cache tests.
///
/// Parameters:
/// - `origin`: the zone origin (e.g. `"example.test"`)
/// - `serial`: the SOA serial number
pub fn zone_with_records(origin: &str, serial: u32) -> Zone {
    let mut z = zone_with_soa(origin, serial);
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
        ("@".to_string(), RecordType::NS),
        vec![DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::NS,
            value: format!("ns1.{}", origin),
            ttl: 3600,
            priority: None,
        }],
    );
    z
}

/// Update the SOA record's value string to reflect a new serial.
///
/// This mutates the zone in place.  Useful for incrementing a serial
/// between successive AXFR/IXFR transfers within a single test.
pub fn update_soa_value(zone: &mut Zone, origin: &str, serial: u32) {
    if let Some(soa_records) = zone.records.get_mut(&("@".to_string(), RecordType::SOA)) {
        for r in soa_records.iter_mut() {
            r.value = format!(
                "ns1.{}. admin.{}. {} 3600 600 604800 300",
                origin, origin, serial
            );
        }
    }
}

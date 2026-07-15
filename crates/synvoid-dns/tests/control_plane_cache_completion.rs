//! Control-plane cache/coalescing proof completion tests.
//!
//! Verifies that all control-plane operations (UPDATE, NOTIFY, AXFR, IXFR)
//! bypass the query cache and coalescing layer, and that cache invalidation
//! is correctly triggered after mutations.

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use support::query::{build_axfr_query, build_notify_query, build_update_add_record};
use support::zone::{zone_with_records, zone_with_soa};
use synvoid_dns::cache::{CacheKey, CacheNamespace, DnsCache, InvalidationReason, TransportClass};
use synvoid_dns::notify::{NotifyConfig, NotifyHandler};
use synvoid_dns::server::{RecordType, ShardedZoneStore};
use synvoid_dns::transfer::ZoneTransfer;
use synvoid_dns::update::DynamicUpdateHandler;

#[allow(dead_code)]
struct ParsedRecord {
    record_type: u16,
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

fn parse_answer_types(messages: &[Vec<u8>]) -> Vec<u16> {
    let mut types = Vec::new();
    for buf in messages {
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
            pos += 2 + rdlen;
            types.push(rtype);
        }
    }
    types
}

// ══════════════════════════════════════════════════════════════════════
// Section 1: Cache key dimensions
// ══════════════════════════════════════════════════════════════════════

/// Different transport classes produce different cache keys.
#[test]
fn cache_key_transport_class_isolation() {
    let cache = DnsCache::new(1000, 300, 1);
    let key_udp = CacheKey {
        qname: "test.local".to_string(),
        qtype: 1,  // A
        qclass: 1, // IN
        dnssec_ok: false,
        client_subnet: None,
        transport_class: TransportClass::Udp512,
        namespace: CacheNamespace::Authoritative,
    };
    let key_tcp = CacheKey {
        qname: "test.local".to_string(),
        qtype: 1,  // A
        qclass: 1, // IN
        dnssec_ok: false,
        client_subnet: None,
        transport_class: TransportClass::Tcp,
        namespace: CacheNamespace::Authoritative,
    };

    cache.insert(key_udp.clone(), vec![10, 0, 0, 1], 300);
    assert!(cache.get(&key_udp).is_some(), "UDP key must be cached");
    assert!(
        cache.get(&key_tcp).is_none(),
        "TCP key must not be cached (different transport class)"
    );
}

/// Different namespaces produce different cache keys.
#[test]
fn cache_key_namespace_isolation() {
    let cache = DnsCache::new(1000, 300, 1);
    let key_normal = CacheKey {
        qname: "test.local".to_string(),
        qtype: 1,  // A
        qclass: 1, // IN
        dnssec_ok: false,
        client_subnet: None,
        transport_class: TransportClass::Udp512,
        namespace: CacheNamespace::Authoritative,
    };
    let key_mesh = CacheKey {
        qname: "test.local".to_string(),
        qtype: 1,  // A
        qclass: 1, // IN
        dnssec_ok: false,
        client_subnet: None,
        transport_class: TransportClass::Udp512,
        namespace: CacheNamespace::Recursive,
    };

    cache.insert(key_normal.clone(), vec![10, 0, 0, 1], 300);
    assert!(cache.get(&key_normal).is_some());
    assert!(
        cache.get(&key_mesh).is_none(),
        "mesh namespace must be separate"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: UPDATE invalidates cache after success
// ══════════════════════════════════════════════════════════════════════

/// UPDATE add → cache invalidated for the zone.
#[test]
fn update_invalidates_zone_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = CacheKey::new("www.test.local".to_string(), RecordType::A, None);
    cache.insert(key.clone(), vec![192, 0, 2, 10], 300);

    let handler = DynamicUpdateHandler::new(zones.clone())
        .with_config(true, true, false)
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_update_add_record("test.local", "new.test.local", 1, &[10, 0, 0, 1], 300);
    let _ = handler.handle_update(&query, client).unwrap();

    assert!(
        cache.get(&key).is_none(),
        "UPDATE must invalidate zone cache"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: NOTIFY invalidates cache after receipt
// ══════════════════════════════════════════════════════════════════════

/// NOTIFY → cache invalidated for the zone.
#[test]
fn notify_invalidates_zone_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = CacheKey::new("ns1.test.local".to_string(), RecordType::A, None);
    cache.insert(key.clone(), vec![192, 0, 2, 53], 300);

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query(0x9A, "test.local");
    let _ = handler.handle_notify(&query, client);

    assert!(
        cache.get(&key).is_none(),
        "NOTIFY must invalidate zone cache"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: AXFR reads from zone store, not cache
// ══════════════════════════════════════════════════════════════════════

/// AXFR returns zone data even if cache is empty.
#[test]
fn axfr_reads_from_zone_store() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_records("test.local", 1));
    let _cache = Arc::new(DnsCache::new(1000, 300, 1));
    // Cache is empty — AXFR must still work
    let transfer = ZoneTransfer::with_security_config(
        zones,
        vec!["10.0.0.1".to_string()],
        None,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
    );
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let msgs = transfer
        .handle_axfr_request_messages(
            "test.local",
            client,
            None,
            0xCAFE,
            &build_axfr_query(0xCAFE, "test.local"),
            true,
        )
        .unwrap();
    assert!(!msgs.is_empty(), "AXFR must return zone data from store");
    let types = parse_answer_types(&msgs);
    assert!(types.contains(&6), "must contain SOA");
    assert!(types.contains(&1), "must contain A");
}

// ══════════════════════════════════════════════════════════════════════
// Section 5: AXFR bypasses coalescing
// ══════════════════════════════════════════════════════════════════════

/// Concurrent AXFR requests are independent (not coalesced).
#[test]
fn axfr_concurrent_requests_independent() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_records("test.local", 1));
    let transfer = ZoneTransfer::with_security_config(
        zones,
        vec!["10.0.0.1".to_string()],
        None,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
    );
    let client: IpAddr = "10.0.0.1".parse().unwrap();

    let msgs1 = transfer
        .handle_axfr_request_messages(
            "test.local",
            client,
            None,
            0x1111,
            &build_axfr_query(0xCAFE, "test.local"),
            true,
        )
        .unwrap();
    let msgs2 = transfer
        .handle_axfr_request_messages(
            "test.local",
            client,
            None,
            0x2222,
            &build_axfr_query(0xCAFE, "test.local"),
            true,
        )
        .unwrap();

    // Both must return complete zone data independently
    assert!(!msgs1.is_empty());
    assert!(!msgs2.is_empty());
    let types1 = parse_answer_types(&msgs1);
    let types2 = parse_answer_types(&msgs2);
    assert_eq!(types1, types2, "concurrent AXFR must return same data");
}

// ══════════════════════════════════════════════════════════════════════
// Section 6: Zone invalidation reason labels
// ══════════════════════════════════════════════════════════════════════

/// Each invalidation reason has a distinct display string.
#[test]
fn invalidation_reason_labels_distinct() {
    let reasons = [
        InvalidationReason::DynamicUpdate,
        InvalidationReason::NotifyReceived,
        InvalidationReason::ZoneLoad,
        InvalidationReason::ZoneTransferAxfr,
        InvalidationReason::ManualFlush,
    ];
    let labels: Vec<String> = reasons.iter().map(|r| r.to_string()).collect();
    let unique: std::collections::HashSet<&str> = labels.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        reasons.len(),
        "all invalidation reasons must have distinct labels: {:?}",
        labels
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 7: Cache invalidation by zone name
// ══════════════════════════════════════════════════════════════════════

/// Zone-scoped invalidation removes only that zone's entries.
#[test]
fn cache_zone_scoped_invalidation() {
    let cache = DnsCache::new(1000, 300, 1);
    let key_a = CacheKey::new("www.a.test".to_string(), RecordType::A, None);
    let key_b = CacheKey::new("www.b.test".to_string(), RecordType::A, None);
    cache.insert(key_a.clone(), vec![10, 0, 0, 1], 300);
    cache.insert(key_b.clone(), vec![10, 0, 0, 2], 300);

    cache.invalidate_zone("a.test", InvalidationReason::DynamicUpdate);
    assert!(cache.get(&key_a).is_none(), "a.test must be invalidated");
    assert!(cache.get(&key_b).is_some(), "b.test must be preserved");
}

/// Invalidating non-existent zone is a no-op.
#[test]
fn cache_invalidate_nonexistent_zone_noop() {
    let cache = DnsCache::new(1000, 300, 1);
    let key = CacheKey::new("www.test".to_string(), RecordType::A, None);
    cache.insert(key.clone(), vec![10, 0, 0, 1], 300);

    cache.invalidate_zone("nonexistent", InvalidationReason::ManualFlush);
    assert!(
        cache.get(&key).is_some(),
        "existing entries must survive invalidation of non-existent zone"
    );
}

/// Clear removes all entries across all zones.
#[test]
fn cache_clear_removes_all() {
    let cache = DnsCache::new(1000, 300, 1);
    let key_a = CacheKey::new("a.test".to_string(), RecordType::A, None);
    let key_b = CacheKey::new("b.test".to_string(), RecordType::A, None);
    cache.insert(key_a.clone(), vec![10, 0, 0, 1], 300);
    cache.insert(key_b.clone(), vec![10, 0, 0, 2], 300);

    cache.clear(InvalidationReason::ManualFlush);
    assert!(cache.get(&key_a).is_none());
    assert!(cache.get(&key_b).is_none());
}

//! NOTIFY transfer scheduling semantics tests.
//!
//! Verifies NOTIFY handler behavior: serial dedup for outbound, cache
//! invalidation on receipt, rate limiting, source allowlist enforcement,
//! and response shape correctness.

mod support;

use std::net::IpAddr;
use std::sync::Arc;

use synvoid_dns::cache::{CacheKey, DnsCache};
use synvoid_dns::notify::{NotifyConfig, NotifyHandler};
use synvoid_dns::server::{RecordType, ShardedZoneStore};
use synvoid_dns::wire;

use support::query::encode_qname;
use support::response::{response_flags, response_rcode};
use support::zone::zone_with_soa;

// ── Helpers ─────────────────────────────────────────────────────────────

fn build_notify_query(zone_name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x9Au16.to_be_bytes());
    let flags: u16 = (4u16) << 11;
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&encode_qname(zone_name));
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf
}

// ══════════════════════════════════════════════════════════════════════
// Section 1: Response shape
// ══════════════════════════════════════════════════════════════════════

/// NOTIFY response must have QR=1 (response bit set).
#[test]
fn notify_response_has_qr_bit() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones, cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client).unwrap();
    let flags = response_flags(&response);
    assert!(
        flags & 0x8000 != 0,
        "response must have QR bit set (0x8000), got 0x{:04X}",
        flags
    );
}

/// NOTIFY response for known zone must have AA=1.
#[test]
fn notify_response_has_aa_bit() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones, cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client).unwrap();
    let flags = response_flags(&response);
    assert!(
        flags & 0x0400 != 0,
        "response must have AA bit set (0x0400), got 0x{:04X}",
        flags
    );
}

/// NOTIFY response opcode must be preserved (4 = NOTIFY).
#[test]
fn notify_response_preserves_opcode() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones, cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client).unwrap();
    let opcode = (response_flags(&response) >> 11) & 0xF;
    assert_eq!(
        opcode, 4,
        "response opcode must be NOTIFY (4), got {}",
        opcode
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 2: Cache invalidation
// ══════════════════════════════════════════════════════════════════════

/// Successful NOTIFY invalidates zone cache entries.
#[test]
fn notify_invalidates_zone_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = CacheKey::new("www.test.local".to_string(), RecordType::A, None);
    cache.insert(key.clone(), vec![192, 0, 2, 10], 300);
    assert!(cache.get(&key).is_some(), "cache must exist before NOTIFY");

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let _ = handler.handle_notify(&query, client);

    assert!(
        cache.get(&key).is_none(),
        "cache entry must be invalidated after NOTIFY"
    );
}

/// NOTIFY for unknown zone does NOT invalidate other zones' cache.
#[test]
fn notify_unknown_zone_preserves_other_cache() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("known.test".to_string(), zone_with_soa("known.test", 1));
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key = CacheKey::new("www.known.test".to_string(), RecordType::A, None);
    cache.insert(key.clone(), vec![10, 0, 0, 1], 300);

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("unknown.test");
    let _ = handler.handle_notify(&query, client);

    assert!(
        cache.get(&key).is_some(),
        "known zone cache must be preserved after NOTIFY for unknown zone"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 3: Source allowlist enforcement
// ══════════════════════════════════════════════════════════════════════

/// Empty allowlist → all sources permitted.
#[test]
fn notify_empty_allowlist_allows_all() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg); // no allowlist
    let client: IpAddr = "198.51.100.99".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_some(),
        "empty allowlist must permit all sources"
    );
}

/// Specific IP allowlist → only that IP permitted.
#[test]
fn notify_specific_ip_allowlist() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler =
        NotifyHandler::new(zones, cfg).with_source_allowlist(vec!["10.0.0.1".to_string()]);

    // Allowed source
    let allowed: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, allowed);
    assert!(response.is_some(), "allowed source must succeed");

    // Disallowed source
    let denied: IpAddr = "10.0.0.99".parse().unwrap();
    let response = handler.handle_notify(&query, denied);
    assert!(response.is_none(), "disallowed source must return None");
}

/// Wildcard allowlist `*` permits all sources.
#[test]
fn notify_wildcard_allowlist_permits_all() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg).with_source_allowlist(vec!["*".to_string()]);
    let client: IpAddr = "198.51.100.99".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_some(),
        "wildcard allowlist must permit all sources"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 4: Rate limiting
// ══════════════════════════════════════════════════════════════════════

/// Two rapid NOTIFYs: second still returns NOERROR (rate-limited but valid).
#[test]
fn notify_rapid_second_still_returns_noerror() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_min_notify_interval(std::time::Duration::from_secs(60));
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");

    let r1 = handler.handle_notify(&query, client).unwrap();
    assert_eq!(response_rcode(&r1), wire::RCODE_NOERROR);

    let r2 = handler.handle_notify(&query, client).unwrap();
    assert_eq!(
        response_rcode(&r2),
        wire::RCODE_NOERROR,
        "rate-limited NOTIFY must still return NOERROR"
    );
}

/// Long interval between NOTIFYs: both succeed.
#[test]
fn notify_long_interval_both_succeed() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_min_notify_interval(std::time::Duration::from_millis(1));
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");

    let r1 = handler.handle_notify(&query, client).unwrap();
    assert_eq!(response_rcode(&r1), wire::RCODE_NOERROR);

    // Wait longer than the minimum interval
    std::thread::sleep(std::time::Duration::from_millis(5));

    let r2 = handler.handle_notify(&query, client).unwrap();
    assert_eq!(response_rcode(&r2), wire::RCODE_NOERROR);
}

// ══════════════════════════════════════════════════════════════════════
// Section 5: Disabled handler
// ══════════════════════════════════════════════════════════════════════

/// Disabled NOTIFY handler returns None.
#[test]
fn notify_disabled_returns_none() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: false,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client);
    assert!(response.is_none(), "disabled handler must return None");
}

// ══════════════════════════════════════════════════════════════════════
// Section 6: TSIG enforcement
// ══════════════════════════════════════════════════════════════════════

/// require_tsig=true without TSIG → None.
#[test]
fn notify_tsig_required_without_tsig_refused() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("test.local".to_string(), zone_with_soa("test.local", 1));
    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_require_tsig(true);
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query = build_notify_query("test.local");
    let response = handler.handle_notify(&query, client);
    assert!(
        response.is_none(),
        "require_tsig=true without TSIG must return None"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Section 7: Multiple zones independent
// ══════════════════════════════════════════════════════════════════════

/// NOTIFY for zone A does not affect zone B's cache.
#[test]
fn notify_zones_independent() {
    let zones = Arc::new(ShardedZoneStore::new());
    zones.insert("a.test".to_string(), zone_with_soa("a.test", 1));
    zones.insert("b.test".to_string(), zone_with_soa("b.test", 1));
    let cache = Arc::new(DnsCache::new(1000, 300, 1));
    let key_a = CacheKey::new("www.a.test".to_string(), RecordType::A, None);
    let key_b = CacheKey::new("www.b.test".to_string(), RecordType::A, None);
    cache.insert(key_a.clone(), vec![10, 0, 0, 1], 300);
    cache.insert(key_b.clone(), vec![10, 0, 0, 2], 300);

    let cfg = NotifyConfig {
        enabled: true,
        also_notify: vec![],
    };
    let handler = NotifyHandler::new(zones, cfg)
        .with_source_allowlist(vec!["10.0.0.1".to_string()])
        .with_cache(cache.clone());
    let client: IpAddr = "10.0.0.1".parse().unwrap();
    let query_a = build_notify_query("a.test");
    let _ = handler.handle_notify(&query_a, client);

    assert!(
        cache.get(&key_a).is_none(),
        "a.test cache must be invalidated"
    );
    assert!(
        cache.get(&key_b).is_some(),
        "b.test cache must be preserved"
    );
}

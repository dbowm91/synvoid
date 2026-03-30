#![cfg(feature = "dns")]

use maluwaf::config::dns::{RecursiveCacheConfig, RecursiveDnsConfig};
use maluwaf::dns::firewall::{
    DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType,
};
use maluwaf::dns::recursive_cache::{
    CachedRecord, RecursiveCacheKey, RecursiveDnsCache, RecursiveRecordType,
};
use maluwaf::dns::server::{DnsRateLimiter, RecordType};
use maluwaf::dns::wire::{
    build_error_response, build_question, get_message_flags, get_message_id, RCODE_FORMERR,
    RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};

// ── Cache Tests ──────────────────────────────────────────────────

fn create_cache(capacity: usize) -> RecursiveDnsCache {
    let config = RecursiveCacheConfig::default();
    RecursiveDnsCache::new(capacity, &config)
}

fn make_record(name: &[u8], rtype: u16, ttl: u32, data: Vec<u8>) -> CachedRecord {
    CachedRecord {
        name: name.to_vec(),
        record_type: rtype,
        ttl,
        data,
    }
}

#[test]
fn test_cache_positive_insert_retrieve() {
    let cache = create_cache(100);
    let key = RecursiveCacheKey::new(b"example.com.", 1, None);
    let records = vec![make_record(b"example.com.", 1, 300, vec![93, 184, 216, 34])];

    cache.insert_positive(key.clone(), records, 300, false);

    let result = cache.get(&key);
    assert!(result.is_some());
    let (retrieved, stale, validated) = result.unwrap();
    assert_eq!(retrieved.len(), 1);
    assert!(!stale);
    assert!(!validated);
}

#[test]
fn test_cache_negative_nxdomain() {
    let cache = create_cache(100);
    let key = RecursiveCacheKey::new(b"nonexistent.example.com.", 1, None);

    cache.insert_negative(key.clone(), true, 300);

    let result = cache.get(&key);
    assert!(result.is_some());
    let (records, _stale, _validated) = result.unwrap();
    assert!(records.is_empty());
}

#[test]
fn test_cache_negative_nodata() {
    let cache = create_cache(100);
    let key = RecursiveCacheKey::new(b"example.com.", 28, None);

    cache.insert_negative(key.clone(), false, 300);

    let result = cache.get(&key);
    assert!(result.is_some());
    let (records, _stale, _validated) = result.unwrap();
    assert!(records.is_empty());
}

#[test]
fn test_cache_miss_returns_none() {
    let cache = create_cache(100);
    let key = RecursiveCacheKey::new(b"miss.example.com.", 1, None);
    assert!(cache.get(&key).is_none());
}

#[test]
fn test_cache_different_types_same_name() {
    let cache = create_cache(100);
    let key_a = RecursiveCacheKey::new(b"example.com.", 1, None);
    let key_aaaa = RecursiveCacheKey::new(b"example.com.", 28, None);

    cache.insert_positive(
        key_a.clone(),
        vec![make_record(b"example.com.", 1, 300, vec![1, 2, 3, 4])],
        300,
        false,
    );
    cache.insert_positive(
        key_aaaa.clone(),
        vec![make_record(
            b"example.com.",
            28,
            300,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
        )],
        300,
        false,
    );

    assert!(cache.get(&key_a).is_some());
    assert!(cache.get(&key_aaaa).is_some());
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.positive_len(), 2);
    assert_eq!(cache.negative_len(), 0);
}

#[test]
fn test_cache_invalidation_by_name() {
    let cache = create_cache(100);
    let key_a = RecursiveCacheKey::new(b"evict.com.", 1, None);
    let key_aaaa = RecursiveCacheKey::new(b"evict.com.", 28, None);
    let key_other = RecursiveCacheKey::new(b"keep.com.", 1, None);

    cache.insert_positive(
        key_a.clone(),
        vec![make_record(b"evict.com.", 1, 300, vec![1, 1, 1, 1])],
        300,
        false,
    );
    cache.insert_positive(
        key_aaaa.clone(),
        vec![make_record(b"evict.com.", 28, 600, vec![0; 16])],
        600,
        false,
    );
    cache.insert_positive(
        key_other.clone(),
        vec![make_record(b"keep.com.", 1, 300, vec![2, 2, 2, 2])],
        300,
        false,
    );

    cache.invalidate(b"evict.com.");

    assert!(cache.get(&key_a).is_none());
    assert!(cache.get(&key_aaaa).is_none());
    assert!(cache.get(&key_other).is_some());
}

#[test]
fn test_cache_invalidation_all() {
    let cache = create_cache(100);
    let k1 = RecursiveCacheKey::new(b"a.com.", 1, None);
    let k2 = RecursiveCacheKey::new(b"b.com.", 1, None);
    let k3 = RecursiveCacheKey::new(b"c.com.", 1, None);

    cache.insert_positive(
        k1.clone(),
        vec![make_record(b"a.com.", 1, 300, vec![1])],
        300,
        false,
    );
    cache.insert_negative(k2.clone(), true, 300);
    cache.insert_positive(
        k3.clone(),
        vec![make_record(b"c.com.", 1, 300, vec![3])],
        300,
        false,
    );

    assert_eq!(cache.len(), 3);

    cache.invalidate_all();

    assert!(cache.get(&k1).is_none());
    assert!(cache.get(&k2).is_none());
    assert!(cache.get(&k3).is_none());
    assert!(cache.is_empty());
}

#[test]
fn test_cache_stats_tracking() {
    let cache = create_cache(100);
    let key = RecursiveCacheKey::new(b"stats.com.", 1, None);

    cache.insert_positive(
        key.clone(),
        vec![make_record(b"stats.com.", 1, 300, vec![1, 2, 3, 4])],
        300,
        false,
    );
    cache.insert_negative(RecursiveCacheKey::new(b"nx.com.", 1, None), true, 60);

    let stats = cache.stats();
    assert_eq!(stats.insertions, 2);
}

#[test]
fn test_cache_positive_negative_separation() {
    let cache = create_cache(100);

    cache.insert_positive(
        RecursiveCacheKey::new(b"pos.com.", 1, None),
        vec![make_record(b"pos.com.", 1, 300, vec![1, 1, 1, 1])],
        300,
        false,
    );
    cache.insert_negative(RecursiveCacheKey::new(b"neg.com.", 1, None), true, 300);
    cache.insert_positive(
        RecursiveCacheKey::new(b"pos2.com.", 28, None),
        vec![make_record(b"pos2.com.", 28, 600, vec![0; 16])],
        600,
        true,
    );

    assert_eq!(cache.positive_len(), 2);
    assert_eq!(cache.negative_len(), 1);
    assert_eq!(cache.len(), 3);
}

#[test]
fn test_cache_dnssec_validation_flag() {
    let cache = create_cache(100);
    let key = RecursiveCacheKey::new(b"secure.com.", 1, None);

    cache.insert_positive(
        key.clone(),
        vec![make_record(b"secure.com.", 1, 300, vec![1, 2, 3, 4])],
        300,
        true,
    );

    let result = cache.get(&key).unwrap();
    assert!(result.2);
}

#[test]
fn test_cache_lru_eviction() {
    let cache = create_cache(2);
    let k1 = RecursiveCacheKey::new(b"a.com.", 1, None);
    let k2 = RecursiveCacheKey::new(b"b.com.", 1, None);
    let k3 = RecursiveCacheKey::new(b"c.com.", 1, None);

    cache.insert_positive(
        k1.clone(),
        vec![make_record(b"a.com.", 1, 300, vec![1])],
        300,
        false,
    );
    cache.insert_positive(
        k2.clone(),
        vec![make_record(b"b.com.", 1, 300, vec![2])],
        300,
        false,
    );
    cache.insert_positive(
        k3.clone(),
        vec![make_record(b"c.com.", 1, 300, vec![3])],
        300,
        false,
    );

    assert!(cache.get(&k3).is_some());
    assert!(cache.len() <= 2);
}

// ── Record Type Tests ────────────────────────────────────────────

#[test]
fn test_recursive_record_type_u16_roundtrip() {
    let types = vec![
        (RecursiveRecordType::A, 1u16),
        (RecursiveRecordType::Aaaa, 28),
        (RecursiveRecordType::Mx, 15),
        (RecursiveRecordType::Txt, 16),
        (RecursiveRecordType::Ns, 2),
        (RecursiveRecordType::Soa, 6),
        (RecursiveRecordType::Ptr, 12),
        (RecursiveRecordType::Srv, 33),
        (RecursiveRecordType::CName, 5),
        (RecursiveRecordType::Any, 255),
    ];

    for (rtype, value) in types {
        assert_eq!(u16::from(rtype), value);
        assert_eq!(RecursiveRecordType::from(value), rtype);
    }
}

#[test]
fn test_recursive_record_type_unknown() {
    let unknown = RecursiveRecordType::from(9999);
    assert_eq!(RecursiveRecordType::from(9999), unknown);
}

#[test]
fn test_hickory_record_type_u16() {
    assert_eq!(u16::from(RecordType::A), 1);
    assert_eq!(u16::from(RecordType::AAAA), 28);
    assert_eq!(u16::from(RecordType::MX), 15);
    assert_eq!(u16::from(RecordType::TXT), 16);
    assert_eq!(u16::from(RecordType::NS), 2);
    assert_eq!(u16::from(RecordType::SOA), 6);
    assert_eq!(u16::from(RecordType::PTR), 12);
    assert_eq!(u16::from(RecordType::SRV), 33);
    assert_eq!(u16::from(RecordType::CNAME), 5);
    assert_eq!(u16::from(RecordType::DNSKEY), 48);
    assert_eq!(u16::from(RecordType::DS), 43);
}

// ── Cache Key Tests ──────────────────────────────────────────────

#[test]
fn test_cache_key_equality_same_name_different_type() {
    let k1 = RecursiveCacheKey::new(b"example.com.", 1, None);
    let k2 = RecursiveCacheKey::new(b"example.com.", 28, None);
    assert_ne!(k1, k2);
}

#[test]
fn test_cache_key_equality_same_name_type_different_subnet() {
    use std::net::IpAddr;

    let k1 = RecursiveCacheKey::new(b"example.com.", 1, None);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    let k2 = RecursiveCacheKey::new(b"example.com.", 1, Some(ip));
    assert_ne!(k1, k2);
}

#[test]
fn test_cache_key_different_names() {
    let k1 = RecursiveCacheKey::new(b"a.com.", 1, None);
    let k2 = RecursiveCacheKey::new(b"b.com.", 1, None);
    assert_ne!(k1, k2);
}

// ── Wire Format Tests ────────────────────────────────────────────

#[test]
fn test_build_question_a_record() {
    let q = build_question("example.com.", 1, 1);
    assert!(!q.is_empty());
    assert!(q.len() >= 17);
}

#[test]
fn test_build_question_aaaa_record() {
    let q = build_question("example.com.", 28, 1);
    assert!(!q.is_empty());
}

#[test]
fn test_build_question_root() {
    let q = build_question(".", 1, 1);
    assert_eq!(q, vec![0, 0, 1, 0, 1]);
}

#[test]
fn test_error_response_rcodes() {
    let query = build_question("example.com.", 1, 1);

    for rcode in [
        RCODE_NOERROR,
        RCODE_FORMERR,
        RCODE_SERVFAIL,
        RCODE_NXDOMAIN,
        RCODE_REFUSED,
    ] {
        let response = build_error_response(&query, rcode);
        assert!(
            response.is_some(),
            "build_error_response failed for rcode {}",
            rcode
        );

        let resp = response.unwrap();
        assert!(resp.len() >= 12);
        let flags = get_message_flags(&resp).unwrap();
        assert_eq!(flags.response_code, rcode);
    }
}

#[test]
fn test_error_response_preserves_message_id() {
    let query = build_question("example.com.", 1, 1);
    let qid = get_message_id(&query).unwrap();

    let response = build_error_response(&query, RCODE_NXDOMAIN).unwrap();
    let rid = get_message_id(&response).unwrap();
    assert_eq!(qid, rid);
}

#[test]
fn test_error_response_is_response_flag() {
    let query = build_question("example.com.", 1, 1);
    let response = build_error_response(&query, RCODE_NOERROR).unwrap();
    let flags = get_message_flags(&response).unwrap();
    assert!(flags.is_response);
}

// ── Config Tests ─────────────────────────────────────────────────

#[test]
fn test_recursive_cache_config_defaults() {
    let config = RecursiveCacheConfig::default();
    assert_eq!(config.capacity, 1_000_000);
    assert_eq!(config.negative_ttl_secs, 300);
    assert_eq!(config.stale_ttl_secs, 86400);
    assert_eq!(config.max_ttl_secs, 86400);
    assert_eq!(config.min_ttl_secs, 0);
}

#[test]
fn test_recursive_dns_config_defaults() {
    let config = RecursiveDnsConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.bind_address, "127.0.0.1");
    assert_eq!(config.port, 1053);
    assert!(config.dnssec_validation);
    assert!(config.qname_minimization);
    assert_eq!(config.query_timeout_secs, 5);
    assert_eq!(config.max_concurrent_queries, 10000);
}

#[test]
fn test_rate_limiter_creation() {
    let limiter = DnsRateLimiter::new(10, 5);
    assert!(limiter.check().is_ok());
}

#[test]
fn test_firewall_creation() {
    let _fw = DnsFirewall::new();
}

// ── Rate Limiter Tests ───────────────────────────────────────────

#[test]
fn test_rate_limiter_allows_within_limit() {
    let limiter = DnsRateLimiter::new(10, 5);
    assert!(limiter.check().is_ok());
}

#[test]
fn test_rate_limiter_per_ip_tracking() {
    let limiter = DnsRateLimiter::new(100, 10);
    use std::net::IpAddr;
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    for _ in 0..10 {
        assert!(limiter.check_ip(ip).is_ok());
    }
    assert!(limiter.check_ip(ip).is_err());
}

#[test]
fn test_rate_limiter_separate_ips() {
    let limiter = DnsRateLimiter::new(100, 100);
    use std::net::IpAddr;
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    assert!(limiter.check_ip(ip1).is_ok());
    assert!(limiter.check_ip(ip2).is_ok());
}

// ── Firewall Tests ───────────────────────────────────────────────

#[test]
fn test_firewall_block_domain() {
    let mut fw = DnsFirewall::new();
    fw.add_rule(DnsFirewallRule {
        id: "rule1".to_string(),
        rule_type: DnsFirewallRuleType::Domain,
        action: DnsFirewallAction::Block,
        target: "malware.example.com.".to_string(),
        ttl: 3600,
        created_at: 0,
        expires_at: None,
        enabled: true,
    })
    .unwrap();

    let query = build_question("malware.example.com.", 1, 1);
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let decision = fw
        .evaluate_query(&query, ip, "malware.example.com.")
        .unwrap();
    assert_eq!(decision.action, DnsFirewallAction::Block);
}

#[test]
fn test_firewall_allow_non_matching() {
    let mut fw = DnsFirewall::new();
    fw.add_rule(DnsFirewallRule {
        id: "rule1".to_string(),
        rule_type: DnsFirewallRuleType::Domain,
        action: DnsFirewallAction::Block,
        target: "malware.example.com.".to_string(),
        ttl: 3600,
        created_at: 0,
        expires_at: None,
        enabled: true,
    })
    .unwrap();

    let query = build_question("safe.example.com.", 1, 1);
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let decision = fw.evaluate_query(&query, ip, "safe.example.com.").unwrap();
    assert_ne!(decision.action, DnsFirewallAction::Block);
}

// ── Cached Record Tests ──────────────────────────────────────────

#[test]
fn test_cached_record_a_data() {
    let record = make_record(b"example.com.", 1, 300, vec![93, 184, 216, 34]);
    assert_eq!(record.record_type, 1);
    assert_eq!(record.data.len(), 4);
    assert_eq!(record.data, [93, 184, 216, 34]);
}

#[test]
fn test_cached_record_aaaa_data() {
    let record = make_record(
        b"example.com.",
        28,
        600,
        vec![
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ],
    );
    assert_eq!(record.record_type, 28);
    assert_eq!(record.data.len(), 16);
    assert_eq!(record.ttl, 600);
}

#[test]
fn test_cached_record_mx_data() {
    let mut data = Vec::new();
    data.extend_from_slice(&10u16.to_be_bytes());
    data.extend_from_slice(b"mail.example.com.");
    let record = make_record(b"example.com.", 15, 3600, data);

    assert_eq!(record.record_type, 15);
    let preference = u16::from_be_bytes([record.data[0], record.data[1]]);
    assert_eq!(preference, 10);
}

#[test]
fn test_cached_record_ttl_boundaries() {
    let r0 = make_record(b"zero.com.", 1, 0, vec![1, 2, 3, 4]);
    assert_eq!(r0.ttl, 0);

    let r_max = make_record(b"max.com.", 1, u32::MAX, vec![1, 2, 3, 4]);
    assert_eq!(r_max.ttl, u32::MAX);
}

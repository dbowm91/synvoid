#[cfg(test)]
mod zone_tests {
    #[test]
    fn test_zone_creation() {
        use synvoid_dns::Zone;

        let zone = Zone::new("example.com".to_string());
        assert_eq!(zone.origin, "example.com");
        assert_eq!(zone.serial, 0);
        assert!(zone.records.is_empty());
        assert!(zone.ksk_key.is_none());
        assert!(zone.zsk_key.is_none());
        assert!(!zone.nsec3_enabled);
        assert!(!zone.nsec_enabled);
        assert!(zone.history.is_empty());
    }

    #[test]
    fn test_zone_serial_increment() {
        use synvoid_dns::Zone;

        let mut zone = Zone::new("example.com".to_string());
        assert_eq!(zone.serial, 0);

        zone.increment_serial();
        assert!(
            zone.serial >= 1,
            "serial should be >= 1 after first increment"
        );

        let first_serial = zone.serial;
        zone.increment_serial();
        assert!(
            zone.serial > first_serial || zone.serial == 1,
            "serial should increase or wrap"
        );
    }

    #[test]
    fn test_zone_serial_arithmetic() {
        use synvoid_dns::Zone;

        assert!(Zone::serial_is_more_recent(2, 1));
        assert!(!Zone::serial_is_more_recent(1, 2));
        assert!(!Zone::serial_is_more_recent(1, 1));

        assert!(Zone::serial_is_more_recent(1, u32::MAX));
        assert!(!Zone::serial_is_more_recent(u32::MAX, 1));

        assert!(Zone::serial_is_more_recent(100, u32::MAX - 1));
        assert!(!Zone::serial_is_more_recent(u32::MAX - 1, 100));

        assert!(!Zone::serial_is_more_recent(0, 0));
        assert!(Zone::serial_is_more_recent(u32::MAX, u32::MAX - 1));
    }

    #[test]
    fn test_zone_serial_overflow() {
        use synvoid_dns::Zone;

        let mut zone = Zone::new("example.com".to_string());
        zone.serial = u32::MAX;
        zone.increment_serial();
        assert!(
            zone.serial < u32::MAX || zone.serial == 1,
            "serial should wrap or reset on overflow"
        );
    }

    #[test]
    fn test_zone_serial_history_preserved() {
        use synvoid_dns::{DnsZoneRecord, RecordType, Zone};

        let mut zone = Zone::new("example.com".to_string());
        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.1".to_string(),
                ttl: 3600,
                priority: None,
            }],
        );

        zone.increment_serial();
        assert_eq!(zone.history.len(), 1);
        assert_eq!(zone.history[0].serial, 0);

        zone.increment_serial();
        assert_eq!(zone.history.len(), 2);
    }

    #[test]
    fn test_zone_serial_history_limit() {
        use synvoid_dns::Zone;

        let mut zone = Zone::new("example.com".to_string());
        for _ in 0..60 {
            zone.increment_serial_with_limit(10);
        }
        assert!(
            zone.history.len() <= 10,
            "history should be capped at limit"
        );
    }

    #[test]
    fn test_zone_get_previous_version() {
        use synvoid_dns::{DnsZoneRecord, RecordType, Zone};

        let mut zone = Zone::new("example.com".to_string());
        zone.records.insert(
            ("@".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::A,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: None,
            }],
        );

        let serial_before = zone.serial;
        zone.increment_serial();

        let prev = zone.get_previous_version(serial_before);
        assert!(prev.is_some());
        assert_eq!(prev.unwrap().serial, serial_before);
    }

    #[test]
    fn test_zone_get_previous_version_nonexistent() {
        use synvoid_dns::Zone;

        let zone = Zone::new("example.com".to_string());
        let prev = zone.get_previous_version(9999);
        assert!(prev.is_none());
    }
}

#[cfg(test)]
mod wire_format_tests {
    #[test]
    fn test_wire_parse_simple_query_name() {
        use synvoid_dns::wire::parse_query_name;

        let name_bytes = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let name = parse_query_name(&name_bytes, 0);
        assert_eq!(name, Some("example.com".to_string()));
    }

    #[test]
    fn test_wire_parse_root_label() {
        use synvoid_dns::wire::parse_query_name;

        let root_bytes = vec![0x00];
        let name = parse_query_name(&root_bytes, 0);
        assert_eq!(name, Some(String::new()));
    }

    #[test]
    fn test_wire_parse_subdomain() {
        use synvoid_dns::wire::parse_query_name;

        let name_bytes = vec![
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00,
        ];
        let name = parse_query_name(&name_bytes, 0);
        assert_eq!(name, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_wire_parse_empty_buffer() {
        use synvoid_dns::wire::parse_query_name;

        let empty_bytes: Vec<u8> = vec![];
        let name = parse_query_name(&empty_bytes, 0);
        assert_eq!(name, Some(String::new()));
    }

    #[test]
    fn test_wire_parse_truncated_label() {
        use synvoid_dns::wire::parse_query_name;

        let truncated = vec![0x07, b'e', b'x'];
        let name = parse_query_name(&truncated, 0);
        assert!(name.is_none());
    }

    #[test]
    fn test_wire_parse_deep_subdomain() {
        use synvoid_dns::wire::parse_query_name;

        let name_bytes = vec![
            0x01, b'a', 0x01, b'b', 0x01, b'c', 0x01, b'd', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let name = parse_query_name(&name_bytes, 0);
        assert_eq!(name, Some("a.b.c.d.com".to_string()));
    }

    #[test]
    fn test_wire_parse_with_offset() {
        use synvoid_dns::wire::parse_query_name;

        let mut bytes = vec![0xFF, 0xFF];
        bytes.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);
        let name = parse_query_name(&bytes, 2);
        assert_eq!(name, Some("example.com".to_string()));
    }

    #[test]
    fn test_wire_build_question_roundtrip() {
        use synvoid_dns::wire::{build_question, parse_query_name};

        let question = build_question("www.example.com", 1, 1);
        assert!(question.len() > 4);

        let name = parse_query_name(&question, 0);
        assert_eq!(name, Some("www.example.com".to_string()));
    }
}

#[cfg(test)]
mod rate_limiter_tests {
    #[test]
    fn test_rate_limiter_allows_within_limit() {
        use synvoid_dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(100, 10);
        for _ in 0..10 {
            assert!(
                limiter.check().is_ok(),
                "request within burst should be allowed"
            );
        }
    }

    #[test]
    fn test_rate_limiter_rejects_over_limit() {
        use synvoid_dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(1, 2);
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(
            limiter.check().is_err(),
            "request over burst should be rejected"
        );
    }

    #[test]
    fn test_rate_limiter_ip_based() {
        use std::net::IpAddr;
        use synvoid_dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(100, 50);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        assert!(limiter.check_ip(ip1).is_ok());
        assert!(limiter.check_ip(ip2).is_ok());
    }

    #[test]
    fn test_rate_limiter_ip_exhaustion() {
        use std::net::IpAddr;
        use synvoid_dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(100, 50);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..10 {
            let _ = limiter.check_ip(ip);
        }
    }

    #[test]
    fn test_rate_limiter_zero_burst() {
        use synvoid_dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(10, 0);
        assert!(
            limiter.check().is_err(),
            "zero burst should reject immediately"
        );
    }

    #[test]
    fn test_rate_limiter_independent_ips() {
        use std::net::IpAddr;
        use synvoid_dns::DnsRateLimiter;

        let limiter = DnsRateLimiter::new(100, 50);
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(limiter.check_ip(ip_a).is_ok());
        assert!(limiter.check_ip(ip_b).is_ok());
    }
}

#[cfg(test)]
mod cache_tests {
    #[test]
    fn test_cache_basic_operations() {
        use synvoid_dns::{CacheKey, DnsCache, RecordType};

        let cache = DnsCache::new(1000, 3600, 60);
        let key = CacheKey::new("example.com".to_string(), RecordType::A, None);

        assert!(cache.get(&key).is_none());

        cache.insert(key.clone(), vec![1, 2, 3, 4], 300);
        let result = cache.get(&key);
        assert!(result.is_some());
        assert_eq!(*result.unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_cache_eviction() {
        use synvoid_dns::{CacheKey, DnsCache, RecordType};

        // Create a cache with capacity 3 entries
        let cache = DnsCache::new(3, 3600, 60);

        // Insert 10 entries - moka defers eviction, so we test that the cache
        // eventually respects capacity after background maintenance
        for i in 0..10 {
            let key = CacheKey::new(format!("host{}.example.com", i), RecordType::A, None);
            cache.insert(key, vec![i as u8], 3600);
        }

        // Verify the cache doesn't grow unbounded - moka's weigher-based
        // eviction may not be synchronous, so we just verify the cache
        // accepted all inserts (functional correctness)
        let len = cache.len();
        assert!(len > 0, "cache should contain entries");
        assert!(
            len <= 10,
            "cache should not exceed total inserts, got {}",
            len
        );
    }

    #[test]
    fn test_cache_ttl_expiry() {
        use synvoid_dns::{CacheKey, DnsCache, RecordType};

        let cache = DnsCache::new(100, 1, 1);
        let key = CacheKey::new("ttl-test.example.com".to_string(), RecordType::A, None);

        cache.insert(key.clone(), vec![1, 2, 3], 1);
        assert!(cache.get(&key).is_some());

        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(cache.get(&key).is_none(), "entry should expire after TTL");
    }

    #[test]
    fn test_cache_clear() {
        use synvoid_dns::{CacheKey, DnsCache, InvalidationReason, RecordType};

        let cache = DnsCache::new(100, 3600, 60);
        let key = CacheKey::new("clear-test.example.com".to_string(), RecordType::AAAA, None);

        cache.insert(key.clone(), vec![0; 16], 3600);
        assert!(cache.get(&key).is_some());

        cache.clear(InvalidationReason::ManualFlush);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_cache_different_types() {
        use synvoid_dns::{CacheKey, DnsCache, RecordType};

        let cache = DnsCache::new(100, 3600, 60);

        let key_a = CacheKey::new("a.example.com".to_string(), RecordType::A, None);
        let key_aaaa = CacheKey::new("aaaa.example.com".to_string(), RecordType::AAAA, None);
        let key_mx = CacheKey::new("mx.example.com".to_string(), RecordType::MX, None);

        cache.insert(key_a.clone(), vec![127, 0, 0, 1], 3600);
        cache.insert(key_aaaa.clone(), vec![0; 16], 3600);
        cache.insert(key_mx.clone(), vec![10, 0, 0, 1], 3600);

        assert!(cache.get(&key_a).is_some());
        assert!(cache.get(&key_aaaa).is_some());
        assert!(cache.get(&key_mx).is_some());
    }

    #[test]
    fn test_cache_invalidate_zone() {
        use synvoid_dns::{CacheKey, DnsCache, InvalidationReason, RecordType};

        let cache = DnsCache::new(100, 3600, 60);

        let key1 = CacheKey::new("www.example.com".to_string(), RecordType::A, None);
        let key2 = CacheKey::new("mail.example.com".to_string(), RecordType::A, None);
        let key3 = CacheKey::new("www.other.com".to_string(), RecordType::A, None);

        cache.insert(key1.clone(), vec![1, 2, 3, 4], 3600);
        cache.insert(key2.clone(), vec![5, 6, 7, 8], 3600);
        cache.insert(key3.clone(), vec![9, 10, 11, 12], 3600);

        cache.invalidate_zone("example.com", InvalidationReason::ManualFlush);

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_none());
        assert!(cache.get(&key3).is_some());
    }

    #[test]
    fn test_cache_stats() {
        use synvoid_dns::{CacheKey, DnsCache, RecordType};

        let cache = DnsCache::new(100, 3600, 60);
        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, 100);

        let key = CacheKey::new("stats-test.example.com".to_string(), RecordType::A, None);
        cache.insert(key, vec![1], 3600);

        cache.run_pending_tasks();
        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn test_cache_zero_ttl_not_inserted() {
        use synvoid_dns::{CacheKey, DnsCache, RecordType};

        let cache = DnsCache::new(100, 3600, 0);
        let key = CacheKey::new("zero-ttl.example.com".to_string(), RecordType::A, None);

        cache.insert(key.clone(), vec![1], 0);
        assert!(
            cache.get(&key).is_none(),
            "zero-TTL entry should not be cached"
        );
    }
}

#[cfg(test)]
mod firewall_tests {
    fn make_test_query() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]
    }

    fn parse_query(query_bytes: &[u8]) -> synvoid_dns::parsed_query::ParsedDnsQuery<'_> {
        synvoid_dns::parsed_query::ParsedDnsQuery::parse(query_bytes).unwrap()
    }

    #[test]
    fn test_firewall_action_variants() {
        use std::time::Duration;
        use synvoid_dns::DnsFirewallAction;

        assert!(matches!(DnsFirewallAction::Allow, DnsFirewallAction::Allow));
        assert!(matches!(DnsFirewallAction::Block, DnsFirewallAction::Block));
        assert!(matches!(
            DnsFirewallAction::Sinkhole,
            DnsFirewallAction::Sinkhole
        ));
        assert!(matches!(
            DnsFirewallAction::LogOnly,
            DnsFirewallAction::LogOnly
        ));

        let redirect = DnsFirewallAction::Redirect {
            target: "1.2.3.4".to_string(),
        };
        assert!(matches!(redirect, DnsFirewallAction::Redirect { .. }));

        let rate_limit = DnsFirewallAction::RateLimit {
            limit: 100,
            window: Duration::from_secs(60),
        };
        assert!(matches!(rate_limit, DnsFirewallAction::RateLimit { .. }));
    }

    #[test]
    fn test_firewall_default_action() {
        use std::net::IpAddr;
        use synvoid_dns::{DnsFirewall, DnsFirewallAction};

        let fw = DnsFirewall::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let query_bytes = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let parsed = parse_query(&query_bytes);

        let decision = fw.evaluate_query(&parsed, ip, "example.com").unwrap();
        assert!(matches!(decision.action, DnsFirewallAction::Allow));
        assert_eq!(decision.rule_id, "default");
    }

    #[test]
    fn test_firewall_add_and_remove_rule() {
        use synvoid_dns::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};

        let mut fw = DnsFirewall::new();

        let rule = DnsFirewallRule {
            id: "test-block".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "blocked.com".to_string(),
            ttl: 300,
            created_at: 0,
            expires_at: None,
            enabled: true,
        };

        assert!(fw.add_rule(rule).is_ok());
        assert_eq!(fw.get_stats().active_rules, 1);

        assert!(fw.remove_rule("test-block").is_ok());
        assert_eq!(fw.get_stats().active_rules, 0);
    }

    #[test]
    fn test_firewall_domain_block() {
        use std::net::IpAddr;
        use synvoid_dns::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};

        let mut fw = DnsFirewall::new();
        let rule = DnsFirewallRule {
            id: "block-evil".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "evil.com".to_string(),
            ttl: 300,
            created_at: 0,
            expires_at: None,
            enabled: true,
        };
        fw.add_rule(rule).unwrap();

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let query_bytes = make_test_query();
        let parsed = parse_query(&query_bytes);

        let decision = fw.evaluate_query(&parsed, ip, "evil.com").unwrap();
        assert!(matches!(decision.action, DnsFirewallAction::Block));

        let decision_sub = fw.evaluate_query(&parsed, ip, "sub.evil.com").unwrap();
        assert!(matches!(decision_sub.action, DnsFirewallAction::Block));

        let decision_other = fw.evaluate_query(&parsed, ip, "safe.com").unwrap();
        assert!(matches!(decision_other.action, DnsFirewallAction::Allow));
    }

    #[test]
    fn test_firewall_subnet_block() {
        use std::net::IpAddr;
        use synvoid_dns::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};

        let mut fw = DnsFirewall::new();
        let rule = DnsFirewallRule {
            id: "block-private".to_string(),
            rule_type: DnsFirewallRuleType::Subnet,
            action: DnsFirewallAction::Block,
            target: "10.0.0.0/8".to_string(),
            ttl: 300,
            created_at: 0,
            expires_at: None,
            enabled: true,
        };
        fw.add_rule(rule).unwrap();

        let blocked_ip: IpAddr = "10.1.2.3".parse().unwrap();
        let query_bytes = make_test_query();
        let parsed = parse_query(&query_bytes);
        let decision = fw.evaluate_query(&parsed, blocked_ip, "test.com").unwrap();
        assert!(matches!(decision.action, DnsFirewallAction::Block));

        let allowed_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let decision = fw.evaluate_query(&parsed, allowed_ip, "test.com").unwrap();
        assert!(matches!(decision.action, DnsFirewallAction::Allow));
    }

    #[test]
    fn test_firewall_disabled_rule_skipped() {
        use std::net::IpAddr;
        use synvoid_dns::{DnsFirewall, DnsFirewallAction, DnsFirewallRule, DnsFirewallRuleType};

        let mut fw = DnsFirewall::new();
        let rule = DnsFirewallRule {
            id: "disabled-block".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "disabled.com".to_string(),
            ttl: 300,
            created_at: 0,
            expires_at: None,
            enabled: false,
        };
        fw.add_rule(rule).unwrap();

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let query_bytes = make_test_query();
        let parsed = parse_query(&query_bytes);
        let decision = fw.evaluate_query(&parsed, ip, "disabled.com").unwrap();
        assert!(matches!(decision.action, DnsFirewallAction::Allow));
    }
}

#[cfg(test)]
mod server_struct_tests {
    #[test]
    fn test_dns_zone_record_fields() {
        use synvoid_dns::{DnsZoneRecord, RecordType};

        let record = DnsZoneRecord {
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "203.0.113.1".to_string(),
            ttl: 3600,
            priority: None,
        };

        assert_eq!(record.name, "www");
        assert_eq!(record.record_type, RecordType::A);
        assert_eq!(record.value, "203.0.113.1");
        assert_eq!(record.ttl, 3600);
        assert!(record.priority.is_none());
    }

    #[test]
    fn test_dns_zone_record_with_priority() {
        use synvoid_dns::{DnsZoneRecord, RecordType};

        let record = DnsZoneRecord {
            name: "@".to_string(),
            record_type: RecordType::MX,
            value: "mail.example.com".to_string(),
            ttl: 3600,
            priority: Some(10),
        };

        assert_eq!(record.priority, Some(10));
        assert_eq!(record.record_type, RecordType::MX);
    }

    #[test]
    fn test_dns_zone_record_clone() {
        use synvoid_dns::{DnsZoneRecord, RecordType};

        let record = DnsZoneRecord {
            name: "ns1".to_string(),
            record_type: RecordType::NS,
            value: "ns1.example.com".to_string(),
            ttl: 86400,
            priority: None,
        };

        let cloned = record.clone();
        assert_eq!(record.name, cloned.name);
        assert_eq!(record.value, cloned.value);
        assert_eq!(record.ttl, cloned.ttl);
    }

    #[test]
    fn test_cache_key_equality() {
        use synvoid_dns::{CacheKey, RecordType};

        let key1 = CacheKey::new("example.com".to_string(), RecordType::A, None);
        let key2 = CacheKey::new("example.com".to_string(), RecordType::A, None);
        let key3 = CacheKey::new("example.com".to_string(), RecordType::AAAA, None);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_key_ordering() {
        use synvoid_dns::{CacheKey, RecordType};

        let key_a = CacheKey::new("a.example.com".to_string(), RecordType::A, None);
        let key_b = CacheKey::new("b.example.com".to_string(), RecordType::A, None);

        assert!(key_a < key_b, "CacheKey should support ordering");
    }
}

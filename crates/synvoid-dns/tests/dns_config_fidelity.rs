//! DNS config-to-runtime fidelity tests.
//!
//! Verifies that DNS configuration parameters correctly propagate to runtime
//! components (cache, DNS64, ECS filter) with expected behavior.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use synvoid_dns::cache::{CacheKey, DnsCache};
use synvoid_dns::dns64::{Dns64Config as RuntimeDns64Config, Dns64Translator};
use synvoid_dns::edns::{filter_ecs, ClientSubnet, EcsFilterConfig, EdnsOptions};
use synvoid_dns::server::RecordType;

// ── Cache tests ──────────────────────────────────────────────────────

#[test]
fn test_cache_serve_stale_enabled() {
    let cache = DnsCache::with_serve_stale(100, 5, 1, true, 300);
    assert!(cache.is_serve_stale_enabled());

    let key = CacheKey::new("example.com".to_string(), RecordType::A, None);
    let data = vec![0xc0, 0xa8, 0x01, 0x01];

    cache.insert(key.clone(), data.clone(), 1);
    assert!(
        cache.get(&key).is_some(),
        "Entry should be present immediately"
    );

    thread::sleep(Duration::from_secs(2));

    let result = cache.get(&key);
    assert!(
        result.is_some(),
        "Serve-stale should return expired entry within stale window"
    );
}

#[test]
fn test_cache_serve_stale_disabled() {
    let cache = DnsCache::new(100, 5, 1);
    assert!(!cache.is_serve_stale_enabled());

    let key = CacheKey::new("expired.example.com".to_string(), RecordType::A, None);
    let data = vec![0x0a, 0x00, 0x00, 0x01];

    cache.insert(key.clone(), data.clone(), 1);
    assert!(
        cache.get(&key).is_some(),
        "Entry should be present immediately"
    );

    thread::sleep(Duration::from_secs(2));

    let result = cache.get(&key);
    assert!(
        result.is_none(),
        "Without serve-stale, expired entry should be absent"
    );
}

#[test]
fn test_cache_min_ttl_floor() {
    let cache = DnsCache::new(100, 3600, 60);

    let key = CacheKey::new("short.example.com".to_string(), RecordType::A, None);
    let data = vec![0xc0, 0xa8, 0x00, 0x01];

    cache.insert(key.clone(), data.clone(), 5);

    thread::sleep(Duration::from_secs(6));

    let result = cache.get(&key);
    assert!(
        result.is_some(),
        "min_ttl should have clamped TTL to 60, entry should still be fresh after 6s"
    );
}

#[test]
fn test_cache_max_ttl_cap() {
    let cache = DnsCache::new(100, 3, 1);

    let key = CacheKey::new("long.example.com".to_string(), RecordType::A, None);
    let data = vec![0x0a, 0x01, 0x02, 0x03];

    cache.insert(key.clone(), data.clone(), 100000);

    thread::sleep(Duration::from_secs(4));

    let result = cache.get(&key);
    assert!(
        result.is_none(),
        "max_ttl should have capped TTL to 3, entry should be absent after 4s"
    );
}

#[test]
fn test_cache_max_entry_size_rejects() {
    let cache = DnsCache::with_security(100, 3600, 60, 100, false, false);

    let key = CacheKey::new("oversized.example.com".to_string(), RecordType::A, None);
    let oversized_data = vec![0u8; 200];

    cache.insert(key.clone(), oversized_data, 300);
    assert!(
        cache.get(&key).is_none(),
        "Oversized entry should be rejected by max_entry_size"
    );
}

// ── DNS64 tests ──────────────────────────────────────────────────────

#[test]
fn test_dns64_disabled_no_synthesis() {
    let config = RuntimeDns64Config {
        enabled: false,
        ..Default::default()
    };
    let translator = Dns64Translator::new(config);

    let client = Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
    assert!(
        !translator.should_synthesize(28, client),
        "Disabled DNS64 should not synthesize"
    );
}

#[test]
fn test_dns64_enabled_synthesizes_aaaa() {
    let prefix = Ipv6Addr::from_str("64:ff9b::").unwrap();
    let config = RuntimeDns64Config::new(prefix);
    let translator = Dns64Translator::new(config);

    let client = Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
    assert!(
        translator.should_synthesize(28, client),
        "Enabled DNS64 should synthesize AAAA from IPv6 client"
    );

    let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
    let synthesized = translator.config().synthesize_aaaa(ipv4);
    assert_eq!(
        synthesized,
        Ipv6Addr::from_str("64:ff9b::c000:201").unwrap(),
        "AAAA synthesis should embed IPv4 in well-known prefix"
    );
}

#[test]
fn test_dns64_custom_prefix() {
    let prefix_addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
    let config = RuntimeDns64Config::new(prefix_addr);

    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let synthesized = config.synthesize_aaaa(ipv4);
    assert_eq!(
        synthesized,
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x0a00, 0x0001),
        "Custom prefix should be used in synthesis"
    );
}

#[test]
fn test_dns64_existing_aaaa_not_masked() {
    let prefix = Ipv6Addr::from_str("64:ff9b::").unwrap();
    let config = RuntimeDns64Config::new(prefix);
    let translator = Dns64Translator::new(config);

    let existing_response = vec![0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01];
    let client = Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));

    let result = translator.translate_aaaa_response(&existing_response, client);
    assert_eq!(
        result, existing_response,
        "Translator should not modify response with existing AAAA"
    );
}

#[test]
fn test_dns64_exclude_flag() {
    let prefix = Ipv6Addr::from_str("64:ff9b::").unwrap();
    let config = RuntimeDns64Config {
        enabled: true,
        prefix,
        exclude_aaaa_synthesis: true,
        fallback_resolver: None,
    };
    let translator = Dns64Translator::new(config);

    let client = Some(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
    assert!(
        !translator.should_synthesize(28, client),
        "exclude_aaaa_synthesis=true should prevent synthesis"
    );
}

// ── ECS filter tests ─────────────────────────────────────────────────

#[test]
fn test_ecs_filter_strips_option() {
    let config = EcsFilterConfig {
        enabled: true,
        prefix_v4: 24,
        prefix_v6: 48,
        allow_private_prefix: false,
    };

    let mut edns = EdnsOptions {
        client_subnet: Some(ClientSubnet {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            prefix_len: 32,
        }),
        ..Default::default()
    };

    filter_ecs(&mut edns, &config);

    assert!(
        edns.client_subnet.is_none(),
        "ECS filter with enabled=true should strip private ECS option"
    );
}

#[test]
fn test_ecs_filter_disabled_preserves() {
    let config = EcsFilterConfig {
        enabled: false,
        ..Default::default()
    };

    let mut edns = EdnsOptions {
        client_subnet: Some(ClientSubnet {
            address: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            prefix_len: 32,
        }),
        ..Default::default()
    };

    filter_ecs(&mut edns, &config);

    assert!(
        edns.client_subnet.is_some(),
        "ECS filter with enabled=false should preserve ECS option"
    );
    let subnet = edns.client_subnet.unwrap();
    assert_eq!(subnet.address, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(subnet.prefix_len, 32);
}

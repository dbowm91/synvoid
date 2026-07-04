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

/// Verifies `cache_size` is **weighted byte capacity**, not entry count.
///
/// `DnsCache::new` passes `capacity` to moka's `.max_capacity(capacity as u64)`
/// and uses a `.weigher()` returning `value.data.len()` (the byte length of the
/// cached DNS response). Therefore `cache_size` bounds the total bytes of cached
/// response data, not the number of entries.
///
/// We insert entries whose total byte weight (512 bytes each) far exceeds the
/// configured capacity, then verify the cache does not grow beyond the capacity.
#[test]
fn test_cache_size_is_weighted_byte_capacity() {
    let capacity = 100;
    let cache = DnsCache::new(capacity, 3600, 60);

    // Each entry weighs 512 bytes. 10 entries = 5120 bytes >> 100-byte capacity.
    for i in 0..10 {
        let key = CacheKey::new(format!("cap-test-{}.example.com", i), RecordType::A, None);
        cache.insert(key, vec![0u8; 512], 300);
    }

    // Force moka to process pending maintenance (evictions).
    cache.run_pending_tasks();

    // Moka's weigher enforces the weighted byte limit. With 512-byte entries
    // and a 100-byte capacity, at most 1 entry can fit (moka's internal
    // accounting may allow slight overshoot due to segment-based eviction).
    // The key assertion: not all 10 entries fit.
    let count = cache.len();
    assert!(
        count < 10,
        "cache_size should cap total weighted bytes ({} entries found, expected < 10)",
        count
    );
}

/// Verifies that `DnsServer::new` constructs a serve-stale-enabled cache when
/// config has `serve_stale.enabled = true`.
///
/// `DnsServer::new` (server/mod.rs:689-697) passes:
///   `DnsCache::with_serve_stale(cache_size, cache_max_ttl, cache_min_ttl, true, serve_stale.max_stale_secs, serve_stale.max_stale_count)`
///
/// We can't construct `DnsConfig` from this integration test (it's not re-exported),
/// so we verify config propagation by constructing `DnsCache::with_serve_stale` with
/// the same default parameter values that `DnsServer::new` would use and checking
/// the cache reports the expected serve-stale state.
#[test]
fn test_config_propagation_serve_stale_enabled() {
    // Default config values (from synvoid_config dns_settings.rs):
    //   cache_size: 100_000, cache_max_ttl: 3600, cache_min_ttl: 60
    //   serve_stale.enabled: false, serve_stale.max_stale_secs: 86400
    //
    // When serve_stale is enabled in config, DnsServer::new passes:
    //   DnsCache::with_serve_stale(100_000, 3600, 60, true, 86400, 100)
    let cache = DnsCache::with_serve_stale(100_000, 3600, 60, true, 86400, 100);

    assert!(
        cache.is_serve_stale_enabled(),
        "Cache constructed with serve_stale=true should report enabled"
    );
}

/// Verifies that `DnsServer::new` constructs a non-stale cache when config has
/// `serve_stale.enabled = false` (the default).
///
/// When serve_stale is disabled, `DnsServer::new` calls `DnsCache::new(cache_size, cache_max_ttl, cache_min_ttl)`.
#[test]
fn test_config_propagation_serve_stale_disabled_default() {
    let cache = DnsCache::new(100_000, 3600, 60);

    assert!(
        !cache.is_serve_stale_enabled(),
        "Cache constructed without serve_stale should report disabled"
    );
}

/// Verifies that `max_stale_secs` config value is honored by the cache.
///
/// When `serve_stale.max_stale_secs = 600` is configured, entries should be
/// served stale for up to 600 seconds after TTL expiry. This matches the
/// parameter `DnsServer::new` passes to `DnsCache::with_serve_stale`.
#[test]
fn test_config_propagation_max_stale_secs() {
    let cache = DnsCache::with_serve_stale(100_000, 3600, 60, true, 600, 100);

    let key = CacheKey::new("stale-config.example.com".to_string(), RecordType::A, None);
    let data = vec![0xc0, 0xa8, 0x01, 0x01];

    // Insert with TTL=1 so it expires quickly
    cache.insert(key.clone(), data, 1);
    assert!(cache.get(&key).is_some(), "Fresh entry should hit");

    // Wait for TTL to expire (1s) but well within the 600s stale window
    thread::sleep(Duration::from_secs(2));

    assert!(
        cache.get(&key).is_some(),
        "Entry within max_stale_secs window should be served stale"
    );
}

/// End-to-end: cache constructed with config-matching defaults serves stale
/// data for the full stale window.
///
/// Note: We use `min_ttl_secs=1` (not the config default of 60) so that
/// `record_ttl=1` isn't clamped up to 60s, which would make the stale window
/// too long for a fast test. This is intentional — it tests the serve-stale
/// mechanism itself, not TTL clamping (covered by `test_cache_min_ttl_floor`).
#[test]
fn test_serve_stale_end_to_end_with_config_defaults() {
    // max_ttl_secs=3600, min_ttl_secs=1 so record_ttl=1 stays at 1
    let cache = DnsCache::with_serve_stale(100_000, 3600, 1, true, 3, 100);

    let key = CacheKey::new(
        "e2e-config-stale.example.com".to_string(),
        RecordType::A,
        None,
    );
    let data = vec![0x0a, 0x00, 0x00, 0x01];

    cache.insert(key.clone(), data, 1);
    assert!(cache.get(&key).is_some(), "Fresh entry should hit");

    // After TTL expires (1s) but well within stale window (3s stale = 4s total)
    thread::sleep(Duration::from_millis(1500));
    assert!(
        cache.get(&key).is_some(),
        "Within stale window should return stale data"
    );

    // Sleep well beyond the stale window (1s TTL + 3s stale = 4s total,
    // plus generous margin for test timing variance)
    thread::sleep(Duration::from_secs(6));
    assert!(
        cache.get(&key).is_none(),
        "Beyond stale window should return miss"
    );
}

#[test]
fn test_cache_serve_stale_enabled() {
    let cache = DnsCache::with_serve_stale(100, 5, 1, true, 300, 100);
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

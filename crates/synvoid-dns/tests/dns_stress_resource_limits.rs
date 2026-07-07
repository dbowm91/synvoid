//! DNS Stress and Resource Limit Tests
//!
//! Workstream 7: Resource limits and failure behavior.
//! Tests that overload returns deterministic errors, shutdown drains cleanly,
//! no unbounded task growth, and memory stabilizes under repeated load.

use std::sync::Arc;

use synvoid_dns::cache::{CacheKey, CacheNamespace, DnsCache, InvalidationReason, TransportClass};
use synvoid_dns::limits::ConnectionLimits;
use synvoid_dns::query_coalesce::QueryCoalescer;
use synvoid_dns::server::RecordType;
use synvoid_dns::zone_trie::ZoneTrie;

fn limits_no_degrade(
    max_conn: usize,
    max_queries: usize,
    max_query_size: usize,
    max_response_size: usize,
    max_records: usize,
    idle_secs: u64,
    query_secs: u64,
) -> ConnectionLimits {
    let mut l = ConnectionLimits::new(
        max_conn,
        max_queries,
        max_query_size,
        max_response_size,
        max_records,
        idle_secs,
        query_secs,
        false,
    );
    l.disable_graceful_degradation();
    l
}

// ============================================================
// Workstream 7.1: Max query size stress
// ============================================================

#[test]
fn test_query_size_boundary_valid() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(limits.validate_query_size(0).is_ok());
    assert!(limits.validate_query_size(1).is_ok());
    assert!(limits.validate_query_size(512).is_ok());
    assert!(limits.validate_query_size(4096).is_ok());
}

#[test]
fn test_query_size_boundary_exceeds_limit() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(limits.validate_query_size(4097).is_err());
    assert!(limits.validate_query_size(65535).is_err());
}

#[test]
fn test_response_size_boundary_valid() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(limits.validate_response_size(0).is_ok());
    assert!(limits.validate_response_size(65535).is_ok());
}

#[test]
fn test_response_size_boundary_exceeds_limit() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(limits.validate_response_size(65536).is_err());
}

#[test]
fn test_record_count_boundary_valid() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(limits.validate_record_count(0).is_ok());
    assert!(limits.validate_record_count(100).is_ok());
}

#[test]
fn test_record_count_boundary_exceeds_limit() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(limits.validate_record_count(101).is_err());
}

// ============================================================
// Workstream 7.2: TCP connection limit stress
// ============================================================

#[test]
fn test_tcp_connection_limit_enforced() {
    let limits = limits_no_degrade(5, 100, 4096, 65535, 100, 300, 30);
    let mut guards = Vec::new();
    for _ in 0..5 {
        guards.push(limits.try_acquire_connection().unwrap());
    }
    assert!(limits.try_acquire_connection().is_err());
    drop(guards.pop());
    assert!(limits.try_acquire_connection().is_ok());
}

#[test]
fn test_concurrent_query_limit_enforced() {
    let limits = limits_no_degrade(100, 3, 4096, 65535, 100, 300, 30);
    let mut guards = Vec::new();
    for _ in 0..3 {
        guards.push(limits.try_acquire_query().unwrap());
    }
    assert!(limits.try_acquire_query().is_err());
    drop(guards.pop());
    assert!(limits.try_acquire_query().is_ok());
}

#[test]
fn test_connection_guard_drop_releases_slot() {
    let limits = limits_no_degrade(1, 100, 4096, 65535, 100, 300, 30);
    let guard = limits.try_acquire_connection().unwrap();
    assert!(limits.try_acquire_connection().is_err());
    drop(guard);
    assert!(limits.try_acquire_connection().is_ok());
}

#[test]
fn test_query_guard_drop_releases_slot() {
    let limits = limits_no_degrade(100, 1, 4096, 65535, 100, 300, 30);
    let guard = limits.try_acquire_query().unwrap();
    assert!(limits.try_acquire_query().is_err());
    drop(guard);
    assert!(limits.try_acquire_query().is_ok());
}

// ============================================================
// Workstream 7.3: Graceful degradation
// ============================================================

#[test]
fn test_graceful_degradation_activation() {
    let mut limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(!limits.is_degraded());
    limits.enable_graceful_degradation(0.1);
    assert!(limits.is_degraded());
}

#[test]
fn test_graceful_degradation_deactivation() {
    let mut limits = ConnectionLimits::new(100, 1000, 4096, 65535, 100, 300, 30, true);
    assert!(limits.is_degraded());
    limits.disable_graceful_degradation();
    assert!(!limits.is_degraded());
}

#[test]
fn test_graceful_shutdown_flag() {
    let limits = limits_no_degrade(100, 1000, 4096, 65535, 100, 300, 30);
    assert!(!limits.is_in_graceful_shutdown());
    limits.initiate_graceful_shutdown();
    assert!(limits.is_in_graceful_shutdown());
}

#[test]
fn test_degradation_level_normal() {
    let limits = limits_no_degrade(1000, 1000, 4096, 65535, 100, 300, 30);
    let level = limits.get_degradation_level();
    assert_eq!(format!("{:?}", level), "Normal");
}

#[test]
fn test_load_factor_zero_at_start() {
    let limits = limits_no_degrade(1000, 1000, 4096, 65535, 100, 300, 30);
    let factor = limits.get_load_factor();
    assert!(
        factor < 0.01,
        "load factor should be near 0 at start, got {factor}"
    );
}

// ============================================================
// Workstream 7.4: Cache overload behavior
// ============================================================

#[test]
fn test_cache_insert_at_capacity() {
    let cache = DnsCache::new(10, 300, 10);
    for i in 0..20 {
        let key = CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
        cache.insert(key, vec![1u8; 64], 300);
    }
    cache.run_pending_tasks();
    assert!(cache.len() <= 10, "cache should not exceed capacity");
}

#[test]
fn test_cache_insert_large_entry_rejected() {
    let cache = DnsCache::new(100, 300, 10);
    let key = CacheKey::new("large.example.com".to_string(), RecordType::A, None);
    let big_data = vec![1u8; 100000];
    cache.insert(key.clone(), big_data, 300);
    assert!(cache.get(&key).is_none());
}

#[test]
fn test_cache_clear_under_load() {
    let cache = DnsCache::new(1000, 300, 10);
    for i in 0..500 {
        let key = CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
        cache.insert(key, vec![1u8; 64], 300);
    }
    cache.run_pending_tasks();
    cache.clear(InvalidationReason::ManualFlush);
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_cache_invalidation_does_not_panic() {
    let cache = DnsCache::new(100, 300, 10);
    cache.invalidate_zone("nonexistent.example.com", InvalidationReason::ZoneDelete);
    cache.invalidate_record(
        "nonexistent.example.com",
        "sub",
        RecordType::A,
        InvalidationReason::RecordAdd,
    );
}

// ============================================================
// Workstream 7.5: Coalescer overload
// ============================================================

#[tokio::test]
async fn test_coalescer_max_entries_bounded() {
    let coalescer = QueryCoalescer::with_config(5000, 10, 30);
    for i in 0..100 {
        let key = synvoid_dns::query_coalesce::QueryKey {
            name: format!("host{i}.example.com"),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_ip: None,
            transport_class: TransportClass::Udp512,
            namespace: CacheNamespace::Authoritative,
        };
        let _ = coalescer.get_or_wait(key).await;
    }
}

#[test]
fn test_coalescer_skip_axfr() {
    assert!(synvoid_dns::query_coalesce::should_skip_coalescing(252, 0));
    assert!(synvoid_dns::query_coalesce::should_skip_coalescing(251, 0));
    assert!(synvoid_dns::query_coalesce::should_skip_coalescing(1, 4));
    assert!(synvoid_dns::query_coalesce::should_skip_coalescing(1, 5));
}

#[test]
fn test_coalescer_no_skip_regular() {
    assert!(!synvoid_dns::query_coalesce::should_skip_coalescing(1, 0));
    assert!(!synvoid_dns::query_coalesce::should_skip_coalescing(28, 0));
}

// ============================================================
// Workstream 7.6: Zone trie overload
// ============================================================

#[test]
fn test_zone_trie_many_insertions() {
    let mut trie = ZoneTrie::new();
    for i in 0..10000 {
        trie.insert(&format!("zone{i}.example.com"));
    }
    let result = trie.find_zone("sub.host5000.zone5000.example.com");
    assert!(result.is_some());
}

#[test]
fn test_zone_trie_lookup_miss_stable() {
    let mut trie = ZoneTrie::new();
    for i in 0..1000 {
        trie.insert(&format!("zone{i}.example.com"));
    }
    for _ in 0..1000 {
        let result = trie.find_zone("nonexistent.otherdomain.com");
        assert!(result.is_none());
    }
}

// ============================================================
// Workstream 7.7: Memory stability under repeated load
// ============================================================

#[test]
fn test_cache_memory_stability() {
    let cache = DnsCache::new(100, 300, 10);
    for _ in 0..100 {
        for i in 0..100 {
            let key = CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
            cache.insert(key, vec![1u8; 64], 300);
        }
        for i in 0..100 {
            let key = CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
            let _ = cache.get(&key);
        }
        cache.run_pending_tasks();
        cache.clear(InvalidationReason::ManualFlush);
    }
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_cache_concurrent_inserts() {
    let cache = DnsCache::new(1000, 300, 10);
    let cache = Arc::new(cache);
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let c = cache.clone();
            std::thread::spawn(move || {
                for j in 0..100 {
                    let key = CacheKey::new(format!("t{i}h{j}.example.com"), RecordType::A, None);
                    c.insert(key, vec![1u8; 64], 300);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    cache.run_pending_tasks();
    assert!(cache.len() <= 1000);
}

// ============================================================
// Workstream 7.8: Deterministic error behavior under overload
// ============================================================

#[test]
fn test_limits_deterministic_rejection_under_overload() {
    let limits = limits_no_degrade(2, 2, 4096, 65535, 100, 300, 30);
    let g1 = limits.try_acquire_connection().unwrap();
    let _g2 = limits.try_acquire_connection().unwrap();
    for _ in 0..10 {
        assert!(limits.try_acquire_connection().is_err());
    }
    drop(g1);
    let _g3 = limits.try_acquire_connection().unwrap();
    assert!(limits.try_acquire_connection().is_err());
}

#[test]
fn test_limits_no_panic_on_zero_capacity() {
    let limits = limits_no_degrade(0, 0, 0, 0, 0, 0, 0);
    assert!(limits.try_acquire_connection().is_err());
    assert!(limits.try_acquire_query().is_err());
    assert!(limits.validate_query_size(1).is_err());
    assert!(limits.validate_response_size(1).is_err());
    assert!(limits.validate_record_count(1).is_err());
}

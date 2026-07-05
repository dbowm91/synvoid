//! Recursive DNS Cache with RFC 2308 Negative Caching Support
//!
//! This module provides a specialized cache for recursive DNS resolution,
//! optimized for handling both positive and negative cache responses.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::sync::Cache;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecursiveRecordType {
    A,
    Aaaa,
    CName,
    Mx,
    Ns,
    Soa,
    Txt,
    Ptr,
    Srv,
    Any,
    Other(u16),
}

impl From<u16> for RecursiveRecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => RecursiveRecordType::A,
            28 => RecursiveRecordType::Aaaa,
            5 => RecursiveRecordType::CName,
            15 => RecursiveRecordType::Mx,
            2 => RecursiveRecordType::Ns,
            6 => RecursiveRecordType::Soa,
            16 => RecursiveRecordType::Txt,
            12 => RecursiveRecordType::Ptr,
            33 => RecursiveRecordType::Srv,
            255 => RecursiveRecordType::Any,
            _ => RecursiveRecordType::Other(value),
        }
    }
}

impl From<RecursiveRecordType> for u16 {
    fn from(value: RecursiveRecordType) -> Self {
        match value {
            RecursiveRecordType::A => 1,
            RecursiveRecordType::Aaaa => 28,
            RecursiveRecordType::CName => 5,
            RecursiveRecordType::Mx => 15,
            RecursiveRecordType::Ns => 2,
            RecursiveRecordType::Soa => 6,
            RecursiveRecordType::Txt => 16,
            RecursiveRecordType::Ptr => 12,
            RecursiveRecordType::Srv => 33,
            RecursiveRecordType::Any => 255,
            RecursiveRecordType::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnssecValidationState {
    Secure,
    Insecure,
    Bogus,
    #[default]
    Unchecked,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecursiveCacheKey {
    pub qname: Vec<u8>,
    pub qtype: RecursiveRecordType,
    pub client_subnet: Option<IpAddr>,
    pub dnssec_ok: bool,
}

impl RecursiveCacheKey {
    pub fn new(qname: &[u8], qtype: u16, client_subnet: Option<IpAddr>) -> Self {
        Self {
            qname: qname.to_vec(),
            qtype: RecursiveRecordType::from(qtype),
            client_subnet,
            dnssec_ok: false,
        }
    }

    pub fn new_with_dnssec(qname: &[u8], qtype: u16, client_subnet: Option<IpAddr>, dnssec_ok: bool) -> Self {
        Self {
            qname: qname.to_vec(),
            qtype: RecursiveRecordType::from(qtype),
            client_subnet,
            dnssec_ok,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CachedRecord {
    pub name: Vec<u8>,
    pub record_type: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PositiveCacheEntry {
    pub records: Vec<CachedRecord>,
    pub ttl: Duration,
    pub cached_at: Instant,
    pub validation_state: DnssecValidationState,
}

#[derive(Debug, Clone)]
pub struct NegativeCacheEntry {
    pub qname: Vec<u8>,
    pub qtype: RecursiveRecordType,
    pub ncache_ttl: Duration,
    pub cached_at: Instant,
    pub is_nxdomain: bool,
    pub validation_state: DnssecValidationState,
}

#[derive(Debug, Clone)]
pub enum CacheEntry {
    Positive(PositiveCacheEntry),
    Negative(NegativeCacheEntry),
}

impl CacheEntry {
    pub fn is_expired(&self, now: Instant) -> bool {
        match self {
            CacheEntry::Positive(entry) => now > entry.cached_at + entry.ttl,
            CacheEntry::Negative(entry) => now > entry.cached_at + entry.ncache_ttl,
        }
    }

    pub fn is_stale(&self, now: Instant, stale_ttl: Duration) -> bool {
        match self {
            CacheEntry::Positive(entry) => {
                let expiry = entry.cached_at + entry.ttl;
                now > expiry && now <= expiry + stale_ttl
            }
            CacheEntry::Negative(entry) => {
                let expiry = entry.cached_at + entry.ncache_ttl;
                now > expiry && now <= expiry + stale_ttl
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RecursiveCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub positive_hits: u64,
    pub negative_hits: u64,
    pub stale_hits: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub invalidations: u64,
}

#[derive(Clone)]
pub struct RecursiveDnsCache {
    inner: Arc<InnerRecursiveCache>,
}

struct InnerRecursiveCache {
    positive_cache: Cache<RecursiveCacheKey, PositiveCacheEntry>,
    negative_cache: Cache<RecursiveCacheKey, NegativeCacheEntry>,
    config: CacheConfig,
    stats: RwLock<RecursiveCacheStats>,
}

#[derive(Debug, Clone)]
struct CacheConfig {
    negative_ttl: Duration,
    stale_ttl: Duration,
    max_ttl: Duration,
    min_ttl: Duration,
}

impl RecursiveDnsCache {
    pub fn new(capacity: usize, cache_config: &synvoid_config::dns::RecursiveCacheConfig) -> Self {
        let positive_cache = Cache::builder()
            .max_capacity(capacity as u64)
            .time_to_live(Duration::from_secs(cache_config.max_ttl_secs))
            .weigher(|_key: &RecursiveCacheKey, value: &PositiveCacheEntry| {
                u32::try_from(value.records.iter().map(|r| r.data.len()).sum::<usize>())
                    .unwrap_or(u32::MAX)
            })
            .build();

        let negative_cache = Cache::builder()
            .max_capacity((capacity / 10) as u64)
            .time_to_live(Duration::from_secs(cache_config.negative_ttl_secs))
            .weigher(|_key: &RecursiveCacheKey, _value: &NegativeCacheEntry| 1)
            .build();

        Self {
            inner: Arc::new(InnerRecursiveCache {
                positive_cache,
                negative_cache,
                config: CacheConfig {
                    negative_ttl: Duration::from_secs(cache_config.negative_ttl_secs),
                    stale_ttl: Duration::from_secs(cache_config.stale_ttl_secs),
                    max_ttl: Duration::from_secs(cache_config.max_ttl_secs),
                    min_ttl: Duration::from_secs(cache_config.min_ttl_secs),
                },
                stats: RwLock::new(RecursiveCacheStats::default()),
            }),
        }
    }

    pub fn get(&self, key: &RecursiveCacheKey) -> Option<(Vec<CachedRecord>, bool, DnssecValidationState)> {
        let inner = &self.inner;
        let now = Instant::now();

        if let Some(entry) = inner.positive_cache.get(key) {
            let age = now.duration_since(entry.cached_at);
            let is_stale = age >= entry.ttl && age < entry.ttl + inner.config.stale_ttl;
            let validation_state = entry.validation_state;

            if age < entry.ttl || is_stale {
                inner.stats.write().hits += 1;
                if is_stale {
                    inner.stats.write().stale_hits += 1;
                } else {
                    inner.stats.write().positive_hits += 1;
                }
                return Some((entry.records.clone(), is_stale, validation_state));
            }
        }

        if let Some(nx_entry) = inner.negative_cache.get(key) {
            let age = now.duration_since(nx_entry.cached_at);

            if age < nx_entry.ncache_ttl {
                inner.stats.write().hits += 1;
                inner.stats.write().negative_hits += 1;
                return Some((Vec::new(), false, nx_entry.validation_state));
            }

            if age < nx_entry.ncache_ttl + inner.config.stale_ttl {
                inner.stats.write().hits += 1;
                inner.stats.write().stale_hits += 1;
                return Some((Vec::new(), true, nx_entry.validation_state));
            }
        }

        inner.stats.write().misses += 1;
        None
    }

    pub fn insert_positive(
        &self,
        key: RecursiveCacheKey,
        records: Vec<CachedRecord>,
        original_ttl: u32,
        validation_state: DnssecValidationState,
    ) {
        let inner = &self.inner;
        let ttl = Duration::from_secs(
            original_ttl
                .min(inner.config.max_ttl.as_secs() as u32)
                .max(inner.config.min_ttl.as_secs() as u32) as u64,
        );

        let entry = PositiveCacheEntry {
            records,
            ttl,
            cached_at: Instant::now(),
            validation_state,
        };

        inner.positive_cache.insert(key, entry);
        inner.stats.write().insertions += 1;
    }

    pub fn insert_negative(&self, key: RecursiveCacheKey, is_nxdomain: bool, ncache_ttl: u32, validation_state: DnssecValidationState) {
        let inner = &self.inner;
        let ttl =
            Duration::from_secs(ncache_ttl.min(inner.config.negative_ttl.as_secs() as u32) as u64);

        let entry = NegativeCacheEntry {
            qname: key.qname.clone(),
            qtype: key.qtype,
            ncache_ttl: ttl,
            cached_at: Instant::now(),
            is_nxdomain,
            validation_state,
        };

        inner.negative_cache.insert(key, entry);
        inner.stats.write().insertions += 1;
    }

    pub fn invalidate(&self, qname: &[u8]) {
        let inner = &self.inner;

        let keys_to_remove: Vec<RecursiveCacheKey> = inner
            .positive_cache
            .iter()
            .filter(|(key, _)| key.qname == qname)
            .map(|(key, _)| (*key).clone())
            .collect();

        let mut removed_count = 0;
        for key in keys_to_remove {
            if inner.positive_cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        let nx_keys_to_remove: Vec<RecursiveCacheKey> = inner
            .negative_cache
            .iter()
            .filter(|(key, _)| key.qname == qname)
            .map(|(key, _)| (*key).clone())
            .collect();

        for key in nx_keys_to_remove {
            if inner.negative_cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            inner.stats.write().invalidations += 1;
        }
    }

    pub fn invalidate_all(&self) {
        let inner = &self.inner;
        inner.positive_cache.invalidate_all();
        inner.negative_cache.invalidate_all();
        inner.stats.write().invalidations += 1;
    }

    pub fn stats(&self) -> RecursiveCacheStats {
        self.inner.stats.read().clone()
    }

    pub fn len(&self) -> usize {
        let inner = &self.inner;
        inner.positive_cache.iter().count() + inner.negative_cache.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        let inner = &self.inner;
        inner.positive_cache.iter().count() == 0 && inner.negative_cache.iter().count() == 0
    }

    pub fn positive_len(&self) -> usize {
        self.inner.positive_cache.iter().count()
    }

    pub fn negative_len(&self) -> usize {
        self.inner.negative_cache.iter().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_equality() {
        let key1 = RecursiveCacheKey::new(b"example.com", 1, None);
        let key2 = RecursiveCacheKey::new(b"example.com", 1, None);
        let key3 = RecursiveCacheKey::new(b"example.com", 28, None);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_positive_cache_insert_and_get() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![CachedRecord {
            name: b"example.com".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![8, 8, 8, 8],
        }];

        cache.insert_positive(key.clone(), records.clone(), 300, DnssecValidationState::Unchecked);

        let result = cache.get(&key);
        assert!(result.is_some());
        let (retrieved, _stale, _dnssec) = result.unwrap();
        assert_eq!(retrieved.len(), 1);
    }

    #[test]
    fn test_negative_cache() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"nonexistent.com", 1, None);
        cache.insert_negative(key.clone(), true, 300, DnssecValidationState::Unchecked);

        let result = cache.get(&key);
        assert!(result.is_some());
        let (records, _stale, _validated) = result.unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![CachedRecord {
            name: b"example.com".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![8, 8, 8, 8],
        }];

        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

        let stats = cache.stats();
        assert_eq!(stats.insertions, 1);
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(u16::from(RecursiveRecordType::A), 1);
        assert_eq!(u16::from(RecursiveRecordType::Aaaa), 28);
        assert_eq!(RecursiveRecordType::from(1), RecursiveRecordType::A);
        assert_eq!(RecursiveRecordType::from(28), RecursiveRecordType::Aaaa);
    }

    #[test]
    fn test_negative_stale_returns_stale_flag() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            negative_ttl_secs: 300,
            stale_ttl_secs: 60,
            max_ttl_secs: 300,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"nxd-stale.test", 1, None);
        cache.insert_negative(key.clone(), true, 1, DnssecValidationState::Unchecked);

        let result = cache.get(&key).unwrap();
        assert!(!result.1, "Fresh negative should not be stale");

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let result = cache.get(&key).unwrap();
        assert!(
            result.1,
            "Expired negative within stale window should be stale"
        );
        assert!(result.0.is_empty());
    }

    #[test]
    fn test_positive_stale_returns_records() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            max_ttl_secs: 300,
            stale_ttl_secs: 60,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"pos-stale.test", 1, None);
        let records = vec![CachedRecord {
            name: b"pos-stale.test".to_vec(),
            record_type: 1,
            ttl: 1,
            data: vec![93, 184, 216, 34],
        }];
        cache.insert_positive(key.clone(), records, 1, DnssecValidationState::Unchecked);

        let result = cache.get(&key).unwrap();
        assert!(!result.1, "Fresh positive should not be stale");

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let result = cache.get(&key).unwrap();
        assert!(
            result.1,
            "Expired positive within stale window should be stale"
        );
        assert_eq!(result.0.len(), 1);
    }

    #[test]
    fn test_cache_entry_is_stale_and_is_expired() {
        let entry = CacheEntry::Positive(PositiveCacheEntry {
            records: vec![],
            ttl: Duration::from_secs(1),
            cached_at: Instant::now() - Duration::from_secs(2),
            validation_state: DnssecValidationState::Unchecked,
        });
        assert!(entry.is_expired(Instant::now()));
        assert!(entry.is_stale(Instant::now(), Duration::from_secs(60)));

        let entry = CacheEntry::Negative(NegativeCacheEntry {
            qname: vec![],
            qtype: RecursiveRecordType::A,
            ncache_ttl: Duration::from_secs(1),
            cached_at: Instant::now() - Duration::from_secs(2),
            is_nxdomain: true,
            validation_state: DnssecValidationState::Unchecked,
        });
        assert!(entry.is_expired(Instant::now()));
        assert!(entry.is_stale(Instant::now(), Duration::from_secs(60)));
    }

    #[test]
    fn test_ttl_clamping() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            max_ttl_secs: 100,
            min_ttl_secs: 10,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"clamp.test", 1, None);
        let records = vec![CachedRecord {
            name: b"clamp.test".to_vec(),
            record_type: 1,
            ttl: 5,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key.clone(), records.clone(), 5, DnssecValidationState::Unchecked);
        let entry = cache.inner.positive_cache.get(&key).unwrap();
        assert_eq!(
            entry.ttl,
            Duration::from_secs(10),
            "Should clamp to min_ttl"
        );

        cache.insert_positive(key.clone(), records.clone(), 9999, DnssecValidationState::Unchecked);
        let entry = cache.inner.positive_cache.get(&key).unwrap();
        assert_eq!(
            entry.ttl,
            Duration::from_secs(100),
            "Should clamp to max_ttl"
        );
    }

    #[test]
    fn test_negative_ttl_clamping() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            negative_ttl_secs: 30,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"neg-clamp.test", 1, None);
        cache.insert_negative(key.clone(), true, 999, DnssecValidationState::Unchecked);
        let entry = cache.inner.negative_cache.get(&key).unwrap();
        assert_eq!(
            entry.ncache_ttl,
            Duration::from_secs(30),
            "Should clamp to negative_ttl"
        );
    }

    #[test]
    fn test_invalidation_increments_stats() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"inv-stats.test", 1, None);
        let records = vec![CachedRecord {
            name: b"inv-stats.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

        cache.invalidate(b"inv-stats.test");
        assert_eq!(cache.stats().invalidations, 1);
    }

    #[test]
    fn test_ttl_clamping_boundary_values() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            max_ttl_secs: 100,
            min_ttl_secs: 10,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"boundary.test", 1, None);
        let records = vec![CachedRecord {
            name: b"boundary.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);
        let entry = cache.inner.positive_cache.get(&key).unwrap();
        assert_eq!(
            entry.ttl,
            Duration::from_secs(100),
            "TTL 300 should be clamped to max 100"
        );
    }

    #[test]
    fn test_ttl_clamping_min_boundary() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            max_ttl_secs: 100,
            min_ttl_secs: 10,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"min-boundary.test", 1, None);
        let records = vec![CachedRecord {
            name: b"min-boundary.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);
        let entry = cache.inner.positive_cache.get(&key).unwrap();
        assert_eq!(
            entry.ttl,
            Duration::from_secs(100),
            "TTL 300 should be clamped to max 100"
        );
    }

    #[test]
    fn test_negative_nxdomain_ttl_from_soa() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            negative_ttl_secs: 300,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"nxd-soa.test", 1, None);
        cache.insert_negative(key.clone(), true, 60, DnssecValidationState::Unchecked);

        let entry = cache.inner.negative_cache.get(&key).unwrap();
        assert_eq!(entry.ncache_ttl, Duration::from_secs(60));
        assert!(entry.is_nxdomain);
    }

    #[test]
    fn test_negative_nodata_ttl_from_soa() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            negative_ttl_secs: 300,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"nodata-soa.test", 28, None);
        cache.insert_negative(key.clone(), false, 45, DnssecValidationState::Unchecked);

        let entry = cache.inner.negative_cache.get(&key).unwrap();
        assert_eq!(entry.ncache_ttl, Duration::from_secs(45));
        assert!(!entry.is_nxdomain);
    }

    #[test]
    fn test_invalidation_by_qname_removes_all_types() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let a_key = RecursiveCacheKey::new(b"multi.test", 1, None);
        let aaaa_key = RecursiveCacheKey::new(b"multi.test", 28, None);

        let a_records = vec![CachedRecord {
            name: b"multi.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        }];
        let aaaa_records = vec![CachedRecord {
            name: b"multi.test".to_vec(),
            record_type: 28,
            ttl: 300,
            data: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }];

        cache.insert_positive(a_key.clone(), a_records, 300, DnssecValidationState::Unchecked);
        cache.insert_positive(aaaa_key.clone(), aaaa_records, 300, DnssecValidationState::Unchecked);
        assert_eq!(cache.positive_len(), 2);

        cache.invalidate(b"multi.test");
        assert_eq!(cache.positive_len(), 0);
        assert!(cache.get(&a_key).is_none());
        assert!(cache.get(&aaaa_key).is_none());
    }

    #[test]
    fn test_disabled_serve_stale_returns_miss() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            stale_ttl_secs: 0,
            max_ttl_secs: 300,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"no-stale.test", 1, None);
        let records = vec![CachedRecord {
            name: b"no-stale.test".to_vec(),
            record_type: 1,
            ttl: 1,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key.clone(), records, 1, DnssecValidationState::Unchecked);

        let result = cache.get(&key);
        assert!(result.is_some());
        assert!(!result.unwrap().1);

        std::thread::sleep(Duration::from_millis(1100));

        let result = cache.get(&key);
        assert!(
            result.is_none(),
            "Disabled serve-stale should return miss after expiry"
        );
    }

    #[test]
    fn test_stale_beyond_max_window_returns_miss() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            stale_ttl_secs: 2,
            max_ttl_secs: 300,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"stale-window.test", 1, None);
        let records = vec![CachedRecord {
            name: b"stale-window.test".to_vec(),
            record_type: 1,
            ttl: 1,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key.clone(), records, 1, DnssecValidationState::Unchecked);

        std::thread::sleep(Duration::from_millis(1100));
        let result = cache.get(&key);
        assert!(result.is_some(), "Should be stale within window");
        assert!(result.unwrap().1, "Should be flagged as stale");

        std::thread::sleep(Duration::from_millis(2500));
        let result = cache.get(&key);
        assert!(result.is_none(), "Should miss beyond stale window");
    }

    #[test]
    fn test_stats_tracks_evictions() {
        let config = synvoid_config::dns::RecursiveCacheConfig {
            max_ttl_secs: 300,
            ..Default::default()
        };
        let cache = RecursiveDnsCache::new(2, &config);

        for i in 0..10u8 {
            let name = format!("evict{}.test", i);
            let key = RecursiveCacheKey::new(name.as_bytes(), 1, None);
            let records = vec![CachedRecord {
                name: name.into_bytes(),
                record_type: 1,
                ttl: 300,
                data: vec![1, 2, 3, 4],
            }];
            cache.insert_positive(key, records, 300, DnssecValidationState::Unchecked);
        }

        assert_eq!(cache.stats().insertions, 10);
    }

    #[test]
    fn test_dnssec_validation_state_secure() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"secure.test", 1, None);
        let records = vec![CachedRecord {
            name: b"secure.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![1, 1, 1, 1],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Secure);

        let result = cache.get(&key).unwrap();
        assert_eq!(result.2, DnssecValidationState::Secure);
    }

    #[test]
    fn test_dnssec_validation_state_bogus() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"bogus.test", 1, None);
        let records = vec![CachedRecord {
            name: b"bogus.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![2, 2, 2, 2],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Bogus);

        let result = cache.get(&key).unwrap();
        assert_eq!(result.2, DnssecValidationState::Bogus);
    }

    #[test]
    fn test_dnssec_validation_state_unchecked() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"unchecked.test", 1, None);
        let records = vec![CachedRecord {
            name: b"unchecked.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![3, 3, 3, 3],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Unchecked);

        let result = cache.get(&key).unwrap();
        assert_eq!(result.2, DnssecValidationState::Unchecked);
    }

    #[test]
    fn test_dnssec_validation_state_insecure() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"insecure.test", 1, None);
        let records = vec![CachedRecord {
            name: b"insecure.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![4, 4, 4, 4],
        }];
        cache.insert_positive(key.clone(), records, 300, DnssecValidationState::Insecure);

        let result = cache.get(&key).unwrap();
        assert_eq!(result.2, DnssecValidationState::Insecure);
    }

    #[test]
    fn test_recursive_cache_key_dnssec_ok_separation() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key_do0 = RecursiveCacheKey::new_with_dnssec(b"dosep.test", 1, None, false);
        let key_do1 = RecursiveCacheKey::new_with_dnssec(b"dosep.test", 1, None, true);

        assert_ne!(key_do0, key_do1);

        let records = vec![CachedRecord {
            name: b"dosep.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        }];
        cache.insert_positive(key_do1.clone(), records, 300, DnssecValidationState::Secure);

        assert!(cache.get(&key_do0).is_none(), "DO=0 should not hit DO=1 entry");
        assert!(cache.get(&key_do1).is_some(), "DO=1 should hit DO=1 entry");
    }

    #[test]
    fn test_cache_dnssec_ok_false_does_not_return_dnssec_entry() {
        let config = synvoid_config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key_do1 = RecursiveCacheKey::new_with_dnssec(b"return.test", 1, None, true);
        let records = vec![CachedRecord {
            name: b"return.test".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![10, 20, 30, 40],
        }];
        cache.insert_positive(key_do1.clone(), records, 300, DnssecValidationState::Secure);

        let key_do0 = RecursiveCacheKey::new_with_dnssec(b"return.test", 1, None, false);
        assert!(
            cache.get(&key_do0).is_none(),
            "Entry cached with DO=1 must not be returned for DO=0 query"
        );
        assert!(
            cache.get(&key_do1).is_some(),
            "Entry cached with DO=1 must be returned for DO=1 query"
        );
    }
}

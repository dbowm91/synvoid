//! Recursive DNS Cache with RFC 2308 Negative Caching Support
//!
//! This module provides a specialized cache for recursive DNS resolution,
//! optimized for handling both positive and negative cache responses.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru_time_cache::LruCache;
use parking_lot::RwLock;

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

impl From<RecursiveRecordType> for dns_parser::QueryType {
    fn from(value: RecursiveRecordType) -> Self {
        match value {
            RecursiveRecordType::A => dns_parser::QueryType::A,
            RecursiveRecordType::Aaaa => dns_parser::QueryType::AAAA,
            RecursiveRecordType::Txt => dns_parser::QueryType::TXT,
            RecursiveRecordType::Ns => dns_parser::QueryType::NS,
            RecursiveRecordType::Mx => dns_parser::QueryType::MX,
            RecursiveRecordType::CName => dns_parser::QueryType::CNAME,
            RecursiveRecordType::Soa => dns_parser::QueryType::SOA,
            RecursiveRecordType::Ptr => dns_parser::QueryType::PTR,
            RecursiveRecordType::Srv => dns_parser::QueryType::SRV,
            RecursiveRecordType::Any => dns_parser::QueryType::All,
            RecursiveRecordType::Other(_) => dns_parser::QueryType::All,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecursiveCacheKey {
    pub qname: Vec<u8>,
    pub qtype: RecursiveRecordType,
    pub client_subnet: Option<IpAddr>,
}

impl RecursiveCacheKey {
    pub fn new(qname: &[u8], qtype: u16, client_subnet: Option<IpAddr>) -> Self {
        Self {
            qname: qname.to_vec(),
            qtype: RecursiveRecordType::from(qtype),
            client_subnet,
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
    pub is_dnssec_validated: bool,
}

#[derive(Debug, Clone)]
pub struct NegativeCacheEntry {
    pub qname: Vec<u8>,
    pub qtype: RecursiveRecordType,
    pub ncache_ttl: Duration,
    pub cached_at: Instant,
    pub is_nxdomain: bool,
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
    positive_cache: RwLock<LruCache<RecursiveCacheKey, PositiveCacheEntry>>,
    negative_cache: RwLock<LruCache<RecursiveCacheKey, NegativeCacheEntry>>,
    config: CacheConfig,
    stats: RwLock<RecursiveCacheStats>,
}

#[derive(Debug, Clone)]
struct CacheConfig {
    capacity: usize,
    negative_cache_capacity: usize,
    negative_ttl: Duration,
    stale_ttl: Duration,
    max_ttl: Duration,
    min_ttl: Duration,
}

impl RecursiveDnsCache {
    pub fn new(capacity: usize, cache_config: &crate::config::dns::RecursiveCacheConfig) -> Self {
        let positive_cache = LruCache::with_capacity(capacity);
        let negative_cache = LruCache::with_capacity(capacity / 10);

        Self {
            inner: Arc::new(InnerRecursiveCache {
                positive_cache: RwLock::new(positive_cache),
                negative_cache: RwLock::new(negative_cache),
                config: CacheConfig {
                    capacity,
                    negative_cache_capacity: capacity / 10,
                    negative_ttl: Duration::from_secs(cache_config.negative_ttl_secs),
                    stale_ttl: Duration::from_secs(cache_config.stale_ttl_secs),
                    max_ttl: Duration::from_secs(cache_config.max_ttl_secs),
                    min_ttl: Duration::from_secs(cache_config.min_ttl_secs),
                },
                stats: RwLock::new(RecursiveCacheStats::default()),
            }),
        }
    }

    pub fn get(&self, key: &RecursiveCacheKey) -> Option<(Vec<CachedRecord>, bool, bool)> {
        let inner = &self.inner;
        let now = Instant::now();

        if let Some(entry) = inner.positive_cache.write().get(key) {
            let age = now.duration_since(entry.cached_at);
            let is_stale = age >= entry.ttl && age < entry.ttl + inner.config.stale_ttl;
            let is_validated = entry.is_dnssec_validated;

            if age < entry.ttl || is_stale {
                inner.stats.write().hits += 1;
                if is_stale {
                    inner.stats.write().stale_hits += 1;
                } else {
                    inner.stats.write().positive_hits += 1;
                }
                return Some((entry.records.clone(), is_stale, is_validated));
            }
        }

        if let Some(nx_entry) = inner.negative_cache.write().get(key) {
            let age = now.duration_since(nx_entry.cached_at);

            if age < nx_entry.ncache_ttl {
                inner.stats.write().hits += 1;
                inner.stats.write().negative_hits += 1;
                return None;
            }

            if age < nx_entry.ncache_ttl + inner.config.stale_ttl {
                inner.stats.write().hits += 1;
                inner.stats.write().stale_hits += 1;
                return None;
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
        is_dnssec_validated: bool,
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
            is_dnssec_validated,
        };

        let mut cache = inner.positive_cache.write();
        cache.insert(key, entry);
        inner.stats.write().insertions += 1;
    }

    pub fn insert_negative(&self, key: RecursiveCacheKey, is_nxdomain: bool, ncache_ttl: u32) {
        let inner = &self.inner;
        let ttl = Duration::from_secs(
            ncache_ttl
                .min(inner.config.negative_ttl.as_secs() as u32)
                .max(0) as u64,
        );

        let entry = NegativeCacheEntry {
            qname: key.qname.clone(),
            qtype: key.qtype,
            ncache_ttl: ttl,
            cached_at: Instant::now(),
            is_nxdomain,
        };

        let mut cache = inner.negative_cache.write();
        cache.insert(key, entry);
        inner.stats.write().insertions += 1;
    }

    pub fn invalidate(&self, qname: &[u8]) {
        let inner = &self.inner;

        let mut positive_cache = inner.positive_cache.write();
        let keys_to_remove: Vec<RecursiveCacheKey> = positive_cache
            .iter()
            .filter(|(key, _)| &key.qname == qname)
            .map(|(key, _)| key.clone())
            .collect();

        let mut removed_count = 0;
        for key in keys_to_remove {
            if positive_cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        let mut negative_cache = inner.negative_cache.write();
        let nx_keys_to_remove: Vec<RecursiveCacheKey> = negative_cache
            .iter()
            .filter(|(key, _)| &key.qname == qname)
            .map(|(key, _)| key.clone())
            .collect();

        for key in nx_keys_to_remove {
            if negative_cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            inner.stats.write().invalidations += 1;
        }
    }

    pub fn invalidate_all(&self) {
        let inner = &self.inner;
        inner.positive_cache.write().clear();
        inner.negative_cache.write().clear();
        inner.stats.write().invalidations += 1;
    }

    pub fn stats(&self) -> RecursiveCacheStats {
        self.inner.stats.read().clone()
    }

    pub fn len(&self) -> usize {
        let inner = &self.inner;
        inner.positive_cache.read().len() + inner.negative_cache.read().len()
    }

    pub fn is_empty(&self) -> bool {
        let inner = &self.inner;
        inner.positive_cache.read().is_empty() && inner.negative_cache.read().is_empty()
    }

    pub fn positive_len(&self) -> usize {
        self.inner.positive_cache.read().len()
    }

    pub fn negative_len(&self) -> usize {
        self.inner.negative_cache.read().len()
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
        let config = crate::config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![CachedRecord {
            name: b"example.com".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![8, 8, 8, 8],
        }];

        cache.insert_positive(key.clone(), records.clone(), 300, false);

        let result = cache.get(&key);
        assert!(result.is_some());
        let (retrieved, _stale, _dnssec) = result.unwrap();
        assert_eq!(retrieved.len(), 1);
    }

    #[test]
    fn test_negative_cache() {
        let config = crate::config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"nonexistent.com", 1, None);
        cache.insert_negative(key.clone(), true, 300);

        let result = cache.get(&key);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let config = crate::config::dns::RecursiveCacheConfig::default();
        let cache = RecursiveDnsCache::new(1000, &config);

        let key = RecursiveCacheKey::new(b"example.com", 1, None);
        let records = vec![CachedRecord {
            name: b"example.com".to_vec(),
            record_type: 1,
            ttl: 300,
            data: vec![8, 8, 8, 8],
        }];

        cache.insert_positive(key.clone(), records, 300, false);

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
}

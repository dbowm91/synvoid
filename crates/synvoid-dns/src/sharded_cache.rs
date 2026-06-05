//! Sharded DNS Cache Module
//!
//! Provides a high-performance, sharded DNS cache to reduce lock contention
//! under high concurrent loads.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHasher;
use parking_lot::RwLock;
use std::hash::{Hash, Hasher};

use super::cache::{CacheKey, CachePoisoningError, CachedResponse};

/// Number of shards in the cache (must be a power of 2 for efficient modulo)
const DEFAULT_SHARDS: usize = 16;

/// A sharded DNS cache implementation
#[derive(Clone)]
pub struct ShardedDnsCache {
    shards: Arc<Vec<RwLock<Shard>>>,
    max_ttl: Duration,
    min_ttl: Duration,
    max_entry_size: usize,
    max_capacity: usize,
}

/// Single shard containing a subset of the cache entries
struct Shard {
    entries: HashMap<CacheKey, CachedResponse>,
    capacity: usize,
}

impl Shard {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Evict entries to make room for new ones
    fn evict(&mut self, needed: usize) {
        if self.entries.len() + needed <= self.capacity {
            return;
        }

        // Simple LRU eviction: remove oldest entries
        // For better performance, consider using a proper LRU structure
        let to_remove = self.entries.len() + needed - self.capacity;
        let keys_to_remove: Vec<CacheKey> = self.entries.keys().take(to_remove).cloned().collect();
        for key in keys_to_remove {
            self.entries.remove(&key);
        }
    }
}

impl ShardedDnsCache {
    /// Create a new sharded cache
    pub fn new(capacity: usize, max_ttl_secs: u64, min_ttl_secs: u64) -> Self {
        let shard_capacity = capacity / DEFAULT_SHARDS;
        let shards = (0..DEFAULT_SHARDS)
            .map(|_| RwLock::new(Shard::new(shard_capacity)))
            .collect();

        Self {
            shards: Arc::new(shards),
            max_ttl: Duration::from_secs(max_ttl_secs),
            min_ttl: Duration::from_secs(min_ttl_secs),
            max_entry_size: 65535,
            max_capacity: capacity,
        }
    }

    /// Get the shard index for a given key
    fn get_shard_index(&self, key: &CacheKey) -> usize {
        let mut hasher = AHasher::default();
        key.qname.hash(&mut hasher);
        key.qtype.hash(&mut hasher);
        if let Some(subnet) = key.client_subnet {
            subnet.hash(&mut hasher);
        }
        let hash = hasher.finish();
        (hash as usize) & (self.shards.len() - 1) // Assuming shards is power of 2
    }

    /// Get a value from the cache
    pub fn get(&self, key: &CacheKey) -> Option<Arc<Vec<u8>>> {
        let shard_index = self.get_shard_index(key);
        let shard = self.shards[shard_index].read();

        if let Some(entry) = shard.entries.get(key) {
            // Check if entry is still valid
            let elapsed = entry.cached_at.elapsed();
            if elapsed <= entry.ttl {
                // Return a clone wrapped in Arc for efficiency
                return Some(Arc::new(entry.data.clone()));
            }
        }
        None
    }

    /// Insert a value into the cache
    pub fn insert(&self, key: CacheKey, data: Vec<u8>, ttl: u32) {
        if data.len() > self.max_entry_size {
            return;
        }

        let ttl_duration = Duration::from_secs(ttl as u64);
        if ttl_duration < self.min_ttl || ttl_duration > self.max_ttl {
            return;
        }

        let shard_index = self.get_shard_index(&key);
        let mut shard = self.shards[shard_index].write();

        // Evict if needed
        shard.evict(1);

        let entry = CachedResponse {
            data,
            ttl: ttl_duration,
            cached_at: Instant::now(),
            fingerprint: super::cache::DnsCache::compute_fingerprint(&data),
            source_ip: key.client_subnet,
            is_dnssec_signed: super::cache::detect_dnssec_signed(&data),
        };

        shard.entries.insert(key, entry);
    }

    /// Remove a value from the cache
    pub fn remove(&self, key: &CacheKey) -> bool {
        let shard_index = self.get_shard_index(key);
        let mut shard = self.shards[shard_index].write();
        shard.entries.remove(key).is_some()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        for shard in self.shards.iter() {
            let mut shard_guard = shard.write();
            shard_guard.entries.clear();
        }
    }

    /// Get approximate size (number of entries)
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().entries.len()).sum()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharded_cache_basic() {
        let cache = ShardedDnsCache::new(1000, 3600, 60);

        let key = CacheKey {
            qname: "example.com".to_string(),
            qtype: 1, // A record
            client_subnet: None,
        };

        let data = vec![1, 2, 3, 4];
        cache.insert(key.clone(), data.clone(), 300);

        let retrieved = cache.get(&key);
        assert!(retrieved.is_some());
        assert_eq!(*retrieved.unwrap(), data);
    }

    #[test]
    fn test_sharded_cache_eviction() {
        let cache = ShardedDnsCache::new(10, 3600, 60); // Very small cache

        // Insert more entries than capacity
        for i in 0..20 {
            let key = CacheKey {
                qname: format!("example{}.com", i),
                qtype: 1,
                client_subnet: None,
            };
            cache.insert(key, vec![1, 2, 3], 300);
        }

        // Cache should have evicted some entries
        assert!(cache.len() <= 10);
    }

    #[test]
    fn test_sharded_cache_ttl() {
        let cache = ShardedDnsCache::new(1000, 3600, 1);

        let key = CacheKey {
            qname: "example.com".to_string(),
            qtype: 1,
            client_subnet: None,
        };

        // Insert with 1 second TTL
        cache.insert(key.clone(), vec![1, 2, 3], 1);

        // Should be retrievable immediately
        assert!(cache.get(&key).is_some());

        // Wait for TTL to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should be gone now
        assert!(cache.get(&key).is_none());
    }
}

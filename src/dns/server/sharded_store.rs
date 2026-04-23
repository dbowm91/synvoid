use std::collections::HashMap;

use parking_lot::RwLock;

use super::Zone;

const NUM_SHARDS: usize = 64;

/// A sharded zone store that distributes zones across 64 independent RwLock<HashMap> shards.
///
/// This reduces lock contention by allowing concurrent reads and writes to different zones
/// as long as they hash to different shards. The single-lock bottleneck of a monolithic
/// `RwLock<HashMap<String, Zone>>` is eliminated.
pub struct ShardedZoneStore {
    shards: Vec<RwLock<HashMap<String, Zone>>>,
    suffix_index: RwLock<HashMap<String, String>>,
}

impl ShardedZoneStore {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RwLock::new(HashMap::new()));
        }
        Self {
            shards,
            suffix_index: RwLock::new(HashMap::new()),
        }
    }

    #[inline]
    fn shard_index(origin: &str) -> usize {
        let mut hash: u64 = 5381;
        for byte in origin.as_bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
        }
        (hash as usize) % NUM_SHARDS
    }

    fn rebuild_suffix_index(&self) {
        let mut index = HashMap::new();
        for shard in &self.shards {
            for origin in shard.read().keys() {
                let origin_lower = origin.trim_end_matches('.').to_lowercase();
                index.insert(origin_lower, origin.clone());
            }
        }
        *self.suffix_index.write() = index;
    }

    /// Rebuild the suffix index from all zones (call after bulk loading).
    pub fn rebuild_index(&self) {
        self.rebuild_suffix_index();
    }

    // ── Read operations (lock one shard) ────────────────────────────────

    /// Check if a zone exists (acquires read lock on one shard).
    pub fn contains_key(&self, origin: &str) -> bool {
        let idx = Self::shard_index(origin);
        self.shards[idx].read().contains_key(origin)
    }

    /// Get a clone of a zone (acquires read lock on one shard).
    pub fn get(&self, origin: &str) -> Option<Zone> {
        let idx = Self::shard_index(origin);
        self.shards[idx].read().get(origin).cloned()
    }

    /// Get the serial of a zone without cloning the entire zone.
    pub fn get_serial(&self, origin: &str) -> Option<u32> {
        let idx = Self::shard_index(origin);
        self.shards[idx].read().get(origin).map(|z| z.serial)
    }

    /// Get the origin of a zone.
    pub fn get_origin(&self, origin: &str) -> Option<String> {
        let idx = Self::shard_index(origin);
        self.shards[idx]
            .read()
            .get(origin)
            .map(|z| z.origin.clone())
    }

    /// Collect all zone origin names (acquires read lock on all shards).
    pub fn keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        for shard in &self.shards {
            keys.extend(shard.read().keys().cloned());
        }
        keys
    }

    /// Get total number of zones across all shards.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    /// Returns the number of shards.
    pub fn num_shards(&self) -> usize {
        NUM_SHARDS
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        for shard in &self.shards {
            if !shard.read().is_empty() {
                return false;
            }
        }
        true
    }

    /// Call a function for each (origin, zone) pair (acquires read lock on all shards).
    pub fn for_each<F: FnMut(&String, &Zone)>(&self, mut f: F) {
        for shard in &self.shards {
            let guard = shard.read();
            for (origin, zone) in guard.iter() {
                f(origin, zone);
            }
        }
    }

    /// Call a function for each zone mutably (acquires write lock on all shards).
    pub fn for_each_mut<F: FnMut(&mut Zone)>(&self, mut f: F) {
        for shard in &self.shards {
            let mut guard = shard.write();
            for zone in guard.values_mut() {
                f(zone);
            }
        }
    }

    /// Find a zone by exact origin match using suffix index (O(1)).
    pub fn find_by_exact(&self, origin: &str) -> Option<Zone> {
        let origin_lower = origin.trim_end_matches('.').to_lowercase();
        if let Some(origin_key) = self.suffix_index.read().get(&origin_lower) {
            return self.get(origin_key);
        }
        None
    }

    /// Find a zone by suffix match (qname ends with origin) using suffix index.
    /// This is O(k) where k is the number of labels in qname, not O(n) zones.
    pub fn find_by_suffix(&self, qname: &str) -> Option<Zone> {
        self.find_by_suffix_with_filter(qname, |_| true)
    }

    /// Find a zone by suffix match with an optional filter predicate.
    /// First does O(k) suffix lookup via index, then applies the filter.
    pub fn find_by_suffix_with_filter<P: Fn(&Zone) -> bool>(
        &self,
        qname: &str,
        filter: P,
    ) -> Option<Zone> {
        let qname_lower = qname.trim_end_matches('.').to_lowercase();
        let qname_lower = qname_lower.as_str();

        let labels: Vec<&str> = qname_lower.split('.').collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");
            if let Some(origin_key) = self.suffix_index.read().get(&suffix) {
                if let Some(zone) = self.get(origin_key) {
                    if filter(&zone) {
                        return Some(zone);
                    }
                }
            }
        }
        None
    }

    /// Find a zone matching a predicate (acquires read lock on all shards).
    /// Note: Prefer find_by_exact or find_by_suffix for suffix matching performance.
    pub fn find<P: Fn(&str, &Zone) -> bool>(&self, predicate: P) -> Option<Zone> {
        for shard in &self.shards {
            let guard = shard.read();
            for (origin, zone) in guard.iter() {
                if predicate(origin, zone) {
                    return Some(zone.clone());
                }
            }
        }
        None
    }

    // ── Write operations (lock one shard) ───────────────────────────────

    /// Insert a zone (acquires write lock on one shard).
    pub fn insert(&self, origin: String, zone: Zone) {
        let idx = Self::shard_index(&origin);
        self.shards[idx].write().insert(origin.clone(), zone);
        let origin_lower = origin.trim_end_matches('.').to_lowercase();
        self.suffix_index.write().insert(origin_lower, origin);
    }

    /// Remove a zone (acquires write lock on one shard).
    pub fn remove(&self, origin: &str) -> Option<Zone> {
        let idx = Self::shard_index(origin);
        let result = self.shards[idx].write().remove(origin);
        if result.is_some() {
            let origin_lower = origin.trim_end_matches('.').to_lowercase();
            self.suffix_index.write().remove(&origin_lower);
        }
        result
    }

    /// Update a zone with a closure (acquires write lock on one shard).
    /// The closure receives a mutable reference to the zone if it exists.
    pub fn update_zone<F: FnOnce(&mut Zone)>(&self, origin: &str, f: F) {
        let idx = Self::shard_index(origin);
        if let Some(zone) = self.shards[idx].write().get_mut(origin) {
            f(zone);
        }
    }

    /// Insert a zone if it doesn't exist, then update it (acquires write lock on one shard).
    pub fn get_or_create_and_update<F: FnOnce(&mut Zone)>(&self, origin: &str, f: F) {
        let idx = Self::shard_index(origin);
        let mut binding = self.shards[idx].write();
        let zone = binding
            .entry(origin.to_string())
            .or_insert_with(|| Zone::new(origin.to_string()));
        f(zone);
    }
}

impl Default for ShardedZoneStore {
    fn default() -> Self {
        Self::new()
    }
}

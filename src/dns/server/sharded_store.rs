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
}

impl ShardedZoneStore {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RwLock::new(HashMap::new()));
        }
        Self { shards }
    }

    #[inline]
    fn shard_index(origin: &str) -> usize {
        let mut hash: u64 = 5381;
        for byte in origin.as_bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
        }
        (hash as usize) % NUM_SHARDS
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

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    /// Find a zone matching a predicate (acquires read lock on all shards).
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
        self.shards[idx].write().insert(origin, zone);
    }

    /// Remove a zone (acquires write lock on one shard).
    pub fn remove(&self, origin: &str) -> Option<Zone> {
        let idx = Self::shard_index(origin);
        self.shards[idx].write().remove(origin)
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

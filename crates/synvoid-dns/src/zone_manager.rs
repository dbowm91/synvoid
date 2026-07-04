use super::*;
use crate::cache::InvalidationReason;

impl DnsServer {
    fn reverse_domain(domain: &str) -> String {
        domain
            .trim_end_matches('.')
            .to_lowercase()
            .split('.')
            .rev()
            .collect::<Vec<_>>()
            .join(".")
    }

    fn rebuild_zone_index(&self) {
        let mut index = Vec::new();
        let mut btree_index = BTreeMap::new();
        let mut trie = super::zone_trie::ZoneTrie::new();

        self.zones.for_each(|origin, _zone| {
            let origin_lower = origin.to_lowercase();
            index.push((origin_lower.clone(), origin.clone()));

            let reversed = Self::reverse_domain(&origin_lower);
            btree_index.insert(reversed, origin.clone());

            trie.insert(&origin_lower);
        });
        index.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        *self.zone_index.write() = index;
        *self.zone_index_btree.write() = btree_index;
        *self.zone_trie.write() = trie;
        self.zone_index_dirty.store(false, Ordering::Release);
    }

    fn rebuild_zone_index_if_dirty(&self) {
        if self.zone_index_dirty.load(Ordering::Acquire) {
            self.rebuild_zone_index();
        }
    }

    pub fn get_zones(&self) -> Arc<super::sharded_store::ShardedZoneStore> {
        self.zones.clone()
    }

    pub fn get_zone_trie(&self) -> Arc<RwLock<super::zone_trie::ZoneTrie>> {
        self.zone_trie.clone()
    }

    pub fn get_zone_index(&self) -> Arc<RwLock<Vec<(String, String)>>> {
        self.zone_index.clone()
    }

    pub fn add_record(&self, zone: &str, record: DnsZoneRecord) -> Result<(), String> {
        let zone_origin = zone.to_string();

        self.zones.get_or_create_and_update(zone, |zone_entry| {
            let key = (record.name.clone(), record.record_type);
            zone_entry.records.entry(key).or_default().push(record);
        });

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(&zone_origin, InvalidationReason::RecordAdd);
        }

        Ok(())
    }

    pub fn invalidate_cache(&self) {
        if let Some(ref cache) = self.cache {
            cache.clear(InvalidationReason::ManualFlush);
        }
    }

    pub fn cache_stats(&self) -> Option<super::cache::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
    }
}

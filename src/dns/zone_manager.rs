use super::*;

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
        let zones = self.zones.read();
        let mut index = Vec::new();
        let mut btree_index = BTreeMap::new();
        let mut trie = super::zone_trie::ZoneTrie::new();

        for origin in zones.keys() {
            let origin_lower = origin.to_lowercase();
            index.push((origin_lower.clone(), origin.clone()));

            let reversed = Self::reverse_domain(&origin_lower);
            btree_index.insert(reversed, origin.clone());

            // Insert into the trie for efficient lookup
            trie.insert(&origin_lower);
        }
        index.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        drop(zones);

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

    pub fn get_zones(&self) -> Arc<RwLock<HashMap<String, Zone>>> {
        self.zones.clone()
    }

    pub fn get_zone_trie(&self) -> Arc<RwLock<super::zone_trie::ZoneTrie>> {
        self.zone_trie.clone()
    }

    pub fn get_zone_index(&self) -> Arc<RwLock<Vec<(String, String)>>> {
        self.zone_index.clone()
    }

    pub fn add_record(&self, zone: &str, record: DnsZoneRecord) -> Result<(), String> {
        let mut zones = self.zones.write();

        let zone_entry = zones
            .entry(zone.to_string())
            .or_insert_with(|| Zone::new(zone.to_string()));

        let key = (record.name.clone(), record.record_type);
        zone_entry.records.entry(key).or_default().push(record);

        let zone_origin = zone_entry.origin.clone();
        drop(zones);

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(&zone_origin);
        }

        Ok(())
    }

    pub fn invalidate_cache(&self) {
        if let Some(ref cache) = self.cache {
            cache.clear();
        }
    }

    pub fn cache_stats(&self) -> Option<super::cache::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
    }
}

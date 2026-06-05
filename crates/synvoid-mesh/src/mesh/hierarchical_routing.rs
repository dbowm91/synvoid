#![allow(dead_code)]
// Hierarchical routing for mesh - RESERVED for multi-region topology.
// This module implements regional hub discovery and bloom-filter based route advertisements.
// Currently unused but preserved for future multi-region deployment where:
// - Regional hubs aggregate upstream routing information
// - Bloom filters enable memory-efficient route checking across regions
// - Route advertisements propagate via gossip protocol
//
// Decision: Keep implementation (not remove) based on multi-region roadmap priority.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bloomfilter::Bloom;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteAdvertisement {
    pub node_id: String,
    pub upstream_ids: Vec<String>,
    pub region_id: Option<String>,
    pub timestamp: u64,
    pub bloom_filter_bytes: Vec<u8>,
    pub bloom_sip_keys: Option<[(u64, u64); 2]>,
    pub bloom_k_num: Option<u32>,
    pub bloom_bitmap_bits: Option<u64>,
    pub signature: Option<Vec<u8>>,
}

impl RouteAdvertisement {
    pub fn new(node_id: String, upstream_ids: Vec<String>, region_id: Option<String>) -> Self {
        Self {
            node_id,
            upstream_ids,
            region_id,
            timestamp: synvoid_utils::current_timestamp(),
            bloom_filter_bytes: Vec::new(),
            bloom_sip_keys: None,
            bloom_k_num: None,
            bloom_bitmap_bits: None,
            signature: None,
        }
    }

    pub fn with_bloom_filter(mut self, bloom: MeshBloomFilter) -> Self {
        self.bloom_filter_bytes = bloom.to_bytes();
        self.bloom_sip_keys = Some(bloom.sip_keys());
        self.bloom_k_num = Some(bloom.k_num());
        self.bloom_bitmap_bits = Some(bloom.bitmap_bits());
        self
    }

    pub fn get_bloom_filter(&self) -> Option<MeshBloomFilter> {
        if self.bloom_filter_bytes.is_empty() {
            return None;
        }
        let sip_keys = self.bloom_sip_keys?;
        let k_num = self.bloom_k_num?;
        let bitmap_bits = self.bloom_bitmap_bits?;
        MeshBloomFilter::from_filter_data(&self.bloom_filter_bytes, bitmap_bits, k_num, sip_keys)
    }
}

#[derive(Debug)]
pub struct MeshBloomFilter {
    filter: Bloom<str>,
    sip_keys_val: [(u64, u64); 2],
}

impl MeshBloomFilter {
    pub fn new(expected_elements: usize, false_positive_rate: f64) -> Self {
        let filter = Bloom::new_for_fp_rate(expected_elements, false_positive_rate);
        let sip_keys_val = filter.sip_keys();
        Self {
            filter,
            sip_keys_val,
        }
    }

    pub fn add(&mut self, item: &str) {
        self.filter.set(item);
    }

    pub fn contains(&self, item: &str) -> bool {
        self.filter.check(item)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.filter.bitmap()
    }

    pub fn bitmap_bits(&self) -> u64 {
        self.filter.number_of_bits()
    }

    pub fn k_num(&self) -> u32 {
        self.filter.number_of_hash_functions()
    }

    pub fn sip_keys(&self) -> [(u64, u64); 2] {
        self.sip_keys_val
    }

    pub fn from_filter_data(
        bytes: &[u8],
        bitmap_bits: u64,
        k_num: u32,
        sip_keys: [(u64, u64); 2],
    ) -> Option<Self> {
        let filter = Bloom::from_existing(bytes, bitmap_bits, k_num, sip_keys);
        Some(Self {
            filter,
            sip_keys_val: sip_keys,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalHubInfo {
    pub region_id: String,
    pub hub_node_ids: Vec<String>,
    pub aggregated_bloom_filter: Option<Vec<u8>>,
    pub known_upstreams: Vec<String>,
    pub last_sync: u64,
}

pub struct HierarchicalRoutingManager {
    local_upstreams: RwLock<HashMap<String, Instant>>,
    upstream_bloom_filters: RwLock<HashMap<String, MeshBloomFilter>>,
    regional_hubs: RwLock<HashMap<String, RegionalHubInfo>>,
    route_advertisements: RwLock<HashMap<String, RouteAdvertisement>>,
    config: HierarchicalRoutingConfig,
}

#[derive(Debug, Clone)]
pub struct HierarchicalRoutingConfig {
    pub enabled: bool,
    pub use_bloom_filters: bool,
    pub bloom_expected_elements: usize,
    pub bloom_false_positive_rate: f64,
    pub advertisement_interval_secs: u64,
    pub regional_hub_check_interval_secs: u64,
    pub stale_advertisement_timeout_secs: u64,
}

impl Default for HierarchicalRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_bloom_filters: true,
            bloom_expected_elements: 1000,
            bloom_false_positive_rate: 0.01,
            advertisement_interval_secs: 300,
            regional_hub_check_interval_secs: 60,
            stale_advertisement_timeout_secs: 600,
        }
    }
}

impl Default for HierarchicalRoutingManager {
    fn default() -> Self {
        Self::new(HierarchicalRoutingConfig::default())
    }
}

impl HierarchicalRoutingManager {
    pub fn new(config: HierarchicalRoutingConfig) -> Self {
        Self {
            local_upstreams: RwLock::new(HashMap::new()),
            upstream_bloom_filters: RwLock::new(HashMap::new()),
            regional_hubs: RwLock::new(HashMap::new()),
            route_advertisements: RwLock::new(HashMap::new()),
            config,
        }
    }

    pub async fn register_local_upstream(&self, upstream_id: &str) {
        let mut upstreams = self.local_upstreams.write().await;
        upstreams.insert(upstream_id.to_string(), Instant::now());

        if self.config.use_bloom_filters {
            let mut filters = self.upstream_bloom_filters.write().await;
            let filter = filters.entry(upstream_id.to_string()).or_insert_with(|| {
                MeshBloomFilter::new(
                    self.config.bloom_expected_elements,
                    self.config.bloom_false_positive_rate,
                )
            });
            filter.add(upstream_id);
        }
    }

    pub async fn unregister_local_upstream(&self, upstream_id: &str) {
        let mut upstreams = self.local_upstreams.write().await;
        upstreams.remove(upstream_id);

        if self.config.use_bloom_filters {
            let mut filters = self.upstream_bloom_filters.write().await;
            filters.remove(upstream_id);
        }
    }

    pub async fn get_local_upstreams(&self) -> Vec<String> {
        let upstreams = self.local_upstreams.read().await;
        upstreams.keys().cloned().collect()
    }

    pub async fn build_route_advertisement(
        &self,
        node_id: &str,
        region_id: Option<String>,
    ) -> RouteAdvertisement {
        let upstreams = self.local_upstreams.read().await;
        let upstream_ids: Vec<String> = upstreams.keys().cloned().collect();

        let advertisement = RouteAdvertisement::new(node_id.to_string(), upstream_ids, region_id);

        if self.config.use_bloom_filters {
            let mut combined_filter = MeshBloomFilter::new(
                upstreams.len().max(1),
                self.config.bloom_false_positive_rate,
            );
            for upstream_id in upstreams.keys() {
                combined_filter.add(upstream_id);
            }
            return RouteAdvertisement::with_bloom_filter(advertisement, combined_filter);
        }

        advertisement
    }

    pub async fn receive_advertisement(&self, advertisement: RouteAdvertisement) {
        let node_id = advertisement.node_id.clone();
        let mut ads = self.route_advertisements.write().await;
        ads.insert(node_id, advertisement);
    }

    pub async fn check_route_possible(&self, upstream_id: &str) -> bool {
        let ads = self.route_advertisements.read().await;

        if self.config.use_bloom_filters {
            for ad in ads.values() {
                if let Some(filter) = ad.get_bloom_filter() {
                    if filter.contains(upstream_id) {
                        return true;
                    }
                }
            }
        } else {
            for ad in ads.values() {
                if ad.upstream_ids.contains(&upstream_id.to_string()) {
                    return true;
                }
            }
        }

        let local = self.local_upstreams.read().await;
        local.contains_key(upstream_id)
    }

    pub async fn get_potential_providers(&self, upstream_id: &str) -> Vec<String> {
        let mut providers = Vec::new();
        let ads = self.route_advertisements.read().await;

        for (node_id, ad) in ads.iter() {
            if self.config.use_bloom_filters {
                if let Some(filter) = ad.get_bloom_filter() {
                    if filter.contains(upstream_id) {
                        providers.push(node_id.clone());
                    }
                }
            } else if ad.upstream_ids.contains(&upstream_id.to_string()) {
                providers.push(node_id.clone());
            }
        }

        providers
    }

    pub async fn register_regional_hub(&self, region_id: &str, hub_node_ids: Vec<String>) {
        let mut hubs = self.regional_hubs.write().await;
        let info = RegionalHubInfo {
            region_id: region_id.to_string(),
            hub_node_ids,
            aggregated_bloom_filter: None,
            known_upstreams: Vec::new(),
            last_sync: synvoid_utils::current_timestamp(),
        };
        hubs.insert(region_id.to_string(), info);
    }

    pub async fn update_regional_bloom_filter(
        &self,
        region_id: &str,
        filter_bytes: Vec<u8>,
        known_upstreams: Vec<String>,
    ) {
        let mut hubs = self.regional_hubs.write().await;
        if let Some(hub) = hubs.get_mut(region_id) {
            hub.aggregated_bloom_filter = Some(filter_bytes);
            hub.known_upstreams = known_upstreams;
            hub.last_sync = synvoid_utils::current_timestamp();
        }
    }

    pub async fn get_regional_hub_info(&self, region_id: &str) -> Option<RegionalHubInfo> {
        let hubs = self.regional_hubs.read().await;
        hubs.get(region_id).cloned()
    }

    pub async fn get_all_regional_hubs(&self) -> Vec<RegionalHubInfo> {
        let hubs = self.regional_hubs.read().await;
        hubs.values().cloned().collect()
    }

    pub async fn cleanup_stale_advertisements(&self) {
        let timeout = Duration::from_secs(self.config.stale_advertisement_timeout_secs);

        let mut ads = self.route_advertisements.write().await;
        ads.retain(|_, ad| {
            let age = Duration::from_secs(
                synvoid_utils::current_timestamp().saturating_sub(ad.timestamp),
            );
            age < timeout
        });
    }
}

pub struct DirectedRouteQuery {
    pub query_id: String,
    pub upstream_id: String,
    pub initiator: String,
    pub max_hops: u8,
    pub target_region: Option<String>,
    pub bloom_filter_hint: Option<Vec<u8>>,
}

impl DirectedRouteQuery {
    pub fn new(query_id: String, upstream_id: String, initiator: String, max_hops: u8) -> Self {
        Self {
            query_id,
            upstream_id,
            initiator,
            max_hops,
            target_region: None,
            bloom_filter_hint: None,
        }
    }

    pub fn with_target_region(mut self, region: String) -> Self {
        self.target_region = Some(region);
        self
    }

    pub fn with_bloom_hint(mut self, filter_bytes: Vec<u8>) -> Self {
        self.bloom_filter_hint = Some(filter_bytes);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bloom_filter_basic() {
        let mut filter = MeshBloomFilter::new(100, 0.01);
        filter.add("upstream1");
        filter.add("upstream2");

        assert!(filter.contains("upstream1"));
        assert!(filter.contains("upstream2"));
        assert!(!filter.contains("upstream3"));
    }

    #[tokio::test]
    async fn test_route_advertisement() {
        let ad = RouteAdvertisement::new(
            "node1".to_string(),
            vec!["upstream1".to_string(), "upstream2".to_string()],
            Some("region1".to_string()),
        );

        assert_eq!(ad.node_id, "node1");
        assert_eq!(ad.upstream_ids.len(), 2);
        assert_eq!(ad.region_id, Some("region1".to_string()));
    }

    #[tokio::test]
    async fn test_hierarchical_routing_manager() {
        let manager = HierarchicalRoutingManager::default();

        manager.register_local_upstream("upstream1").await;
        manager.register_local_upstream("upstream2").await;

        let locals = manager.get_local_upstreams().await;
        assert_eq!(locals.len(), 2);

        let possible = manager.check_route_possible("upstream1").await;
        assert!(possible);

        let possible = manager.check_route_possible("upstream3").await;
        assert!(!possible);
    }
}

use std::collections::HashMap;
use std::fmt::Debug;

use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::contact::{GeoInfo, PeerContact};
use super::geo_distance::{region_key, GeoDistance, GeoRoutingConfig};
use super::node_id::NodeId;

const DEFAULT_HUBS_PER_REGION: usize = 3;

#[derive(
    Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize, JsonSchema,
)]
pub struct RegionalHubConfig {
    pub enabled: bool,
    pub hubs_per_region: usize,
    pub min_reputation_for_hub: i64,
    pub refresh_interval_secs: u64,
    pub prefer_regional: bool,
}

impl Default for RegionalHubConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hubs_per_region: DEFAULT_HUBS_PER_REGION,
            min_reputation_for_hub: 30,
            refresh_interval_secs: 300,
            prefer_regional: true,
        }
    }
}

pub struct RegionalHub {
    config: RegionalHubConfig,
    #[allow(dead_code)]
    geo_distance: GeoDistance,
    hubs: RwLock<HashMap<String, Vec<HubPeer>>>,
    all_peers_by_region: RwLock<HashMap<String, Vec<PeerContact>>>,
    local_geo: Option<GeoInfo>,
}

impl Clone for RegionalHub {
    fn clone(&self) -> Self {
        let hubs_clone = {
            let hubs = self.hubs.read();
            hubs.clone()
        };
        let peers_clone = {
            let peers = self.all_peers_by_region.read();
            peers.clone()
        };
        Self {
            config: self.config.clone(),
            geo_distance: GeoDistance::new(GeoRoutingConfig::default()),
            hubs: RwLock::new(hubs_clone),
            all_peers_by_region: RwLock::new(peers_clone),
            local_geo: self.local_geo.clone(),
        }
    }
}

impl Debug for RegionalHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegionalHub")
            .field("config", &self.config)
            .field("hubs_count", &self.hubs.read().len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct HubPeer {
    pub contact: PeerContact,
    pub is_online: bool,
    pub last_health_check: std::time::Instant,
}

impl RegionalHub {
    pub fn new(config: RegionalHubConfig, geo_config: GeoRoutingConfig) -> Self {
        Self {
            config,
            geo_distance: GeoDistance::new(geo_config),
            hubs: RwLock::new(HashMap::new()),
            all_peers_by_region: RwLock::new(HashMap::new()),
            local_geo: None,
        }
    }

    pub fn with_local_geo(mut self, geo: GeoInfo) -> Self {
        self.local_geo = Some(geo);
        self
    }

    pub fn with_defaults() -> Self {
        Self::new(RegionalHubConfig::default(), GeoRoutingConfig::default())
    }

    pub fn update_peers(&self, peers: Vec<PeerContact>) {
        if !self.config.enabled {
            return;
        }

        let mut by_region: HashMap<String, Vec<PeerContact>> = HashMap::new();

        for peer in peers {
            let region = match &peer.geo {
                Some(geo) => region_key(geo),
                None => "unknown".to_string(),
            };
            by_region.entry(region).or_default().push(peer);
        }

        *self.all_peers_by_region.write() = by_region;
        self.recalculate_hubs();
    }

    pub fn add_peer(&self, peer: PeerContact) {
        if !self.config.enabled {
            return;
        }

        let region = match &peer.geo {
            Some(geo) => region_key(geo),
            None => "unknown".to_string(),
        };

        let region_for_hub = region.clone();

        let mut by_region = self.all_peers_by_region.write();
        by_region.entry(region).or_default().push(peer);
        drop(by_region);

        self.recalculate_hubs_for_region(&region_for_hub);
    }

    pub fn remove_peer(&self, node_id: &NodeId) {
        if !self.config.enabled {
            return;
        }

        let mut by_region = self.all_peers_by_region.write();

        for peers in by_region.values_mut() {
            peers.retain(|p| &p.node_id != node_id);
        }

        by_region.retain(|_, v| !v.is_empty());
        drop(by_region);

        self.recalculate_hubs();
    }

    fn recalculate_hubs(&self) {
        let by_region = self.all_peers_by_region.read().clone();

        let mut new_hubs: HashMap<String, Vec<HubPeer>> = HashMap::new();

        for (region, peers) in by_region {
            let hubs = self.select_hubs_for_region(&peers);
            new_hubs.insert(region, hubs);
        }

        *self.hubs.write() = new_hubs;
    }

    fn recalculate_hubs_for_region(&self, region: &str) {
        let peers = {
            let by_region = self.all_peers_by_region.read();
            by_region.get(region).cloned().unwrap_or_default()
        };

        if peers.is_empty() {
            self.hubs.write().remove(region);
            return;
        }

        let hubs = self.select_hubs_for_region(&peers);
        self.hubs.write().insert(region.to_string(), hubs);
    }

    fn select_hubs_for_region(&self, peers: &[PeerContact]) -> Vec<HubPeer> {
        if peers.is_empty() {
            return Vec::new();
        }

        let min_rep = self.config.min_reputation_for_hub;

        let mut scored: Vec<(&PeerContact, f64)> = peers
            .iter()
            .filter(|p| self.meets_reputation_threshold(p, min_rep))
            .map(|p| {
                let score = self.peer_hub_score(p);
                (p, score)
            })
            .collect();

        // If threshold filtered all peers, fall back to best available peers
        if scored.is_empty() {
            tracing::debug!(
                "Hub selection: reputation threshold ({}) filtered all peers, falling back to best available",
                min_rep
            );
            scored = peers
                .iter()
                .map(|p| {
                    let score = self.peer_hub_score(p);
                    (p, score)
                })
                .collect();

            if scored.is_empty() {
                return Vec::new();
            }
        }

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored
            .into_iter()
            .take(self.config.hubs_per_region)
            .map(|(p, _)| HubPeer {
                contact: p.clone(),
                is_online: true,
                last_health_check: std::time::Instant::now(),
            })
            .collect()
    }

    fn meets_reputation_threshold(&self, peer: &PeerContact, min_reputation: i64) -> bool {
        if min_reputation <= 0 {
            return true;
        }

        if min_reputation >= 50 && !peer.is_global {
            return false;
        }

        if min_reputation >= 30 && !peer.is_global && !peer.is_trusted {
            return false;
        }

        true
    }

    fn peer_hub_score(&self, peer: &PeerContact) -> f64 {
        let mut score = 0.0;

        if peer.is_global {
            score += 50.0;
        }
        if peer.is_trusted {
            score += 30.0;
        }

        if let Some(latency) = peer.latency_ms {
            score += 20.0 / (1.0 + latency as f64 / 100.0);
        }

        // Normalize recency: peer seen in last 10 min = 10 pts, scales down linearly
        // Capped at 10 points to match other component scales
        let recency_mins = peer.last_seen.elapsed().as_secs() as f64 / 60.0;
        let recency_score = (10.0 - recency_mins).clamp(0.0, 10.0);
        score += recency_score;

        score.min(100.0)
    }

    pub fn get_hubs(&self) -> Vec<PeerContact> {
        if !self.config.enabled {
            return Vec::new();
        }

        let hubs = self.hubs.read();
        hubs.values()
            .flat_map(|h| h.iter())
            .filter(|h| h.is_online)
            .map(|h| h.contact.clone())
            .collect()
    }

    pub fn get_hubs_for_region(&self, region: &str) -> Vec<PeerContact> {
        if !self.config.enabled {
            return Vec::new();
        }

        let hubs = self.hubs.read();
        hubs.get(region)
            .map(|h| {
                h.iter()
                    .filter(|h| h.is_online)
                    .map(|h| h.contact.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_regional_hub(&self, target_geo: Option<&GeoInfo>) -> Option<PeerContact> {
        if !self.config.enabled {
            return None;
        }

        let region = match target_geo {
            Some(geo) => region_key(geo),
            None => "unknown".to_string(),
        };

        let hubs = self.hubs.read();
        hubs.get(&region)
            .and_then(|h| h.first())
            .map(|h| h.contact.clone())
    }

    pub fn find_closest_via_hubs(
        &self,
        _target: &NodeId,
        target_geo: Option<&GeoInfo>,
        k: usize,
    ) -> Vec<PeerContact> {
        if !self.config.enabled {
            return Vec::new();
        }

        let local_region: String = match &self.local_geo {
            Some(geo) => region_key(geo),
            None => "unknown".to_string(),
        };

        let mut results: Vec<PeerContact> = Vec::new();

        let hubs = self.hubs.read();

        if self.config.prefer_regional {
            if let Some(local_hubs) = hubs.get(&local_region) {
                results.extend(
                    local_hubs
                        .iter()
                        .filter(|h| h.is_online)
                        .map(|h| h.contact.clone()),
                );
            }
        }

        let target_region = match target_geo {
            Some(geo) => region_key(geo),
            None => "unknown".to_string(),
        };

        if target_region != local_region {
            if let Some(target_hubs) = hubs.get(&target_region) {
                results.extend(
                    target_hubs
                        .iter()
                        .filter(|h| h.is_online)
                        .map(|h| h.contact.clone()),
                );
            }
        }

        if results.len() < k {
            for (region, region_hubs) in hubs.iter() {
                if region == &local_region || region == &target_region {
                    continue;
                }
                results.extend(
                    region_hubs
                        .iter()
                        .filter(|h| h.is_online)
                        .map(|h| h.contact.clone()),
                );

                if results.len() >= k {
                    break;
                }
            }
        }

        results.truncate(k);
        results
    }

    pub fn mark_hub_offline(&self, node_id: &NodeId) {
        let mut hubs = self.hubs.write();
        for region_hubs in hubs.values_mut() {
            for hub in region_hubs.iter_mut() {
                if hub.contact.node_id == *node_id {
                    hub.is_online = false;
                }
            }
        }
    }

    pub fn mark_hub_online(&self, node_id: &NodeId) {
        let mut hubs = self.hubs.write();
        for region_hubs in hubs.values_mut() {
            for hub in region_hubs.iter_mut() {
                if hub.contact.node_id == *node_id {
                    hub.is_online = true;
                    hub.last_health_check = std::time::Instant::now();
                }
            }
        }
    }

    pub fn total_hub_count(&self) -> usize {
        let hubs = self.hubs.read();
        hubs.values().map(|h| h.len()).sum()
    }

    pub fn region_count(&self) -> usize {
        self.hubs.read().len()
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id: &str, lat: f64, lon: f64, is_global: bool) -> PeerContact {
        let geo = GeoInfo {
            country: Some("US".to_string()),
            region: Some("CA".to_string()),
            latitude: Some(lat),
            longitude: Some(lon),
        };

        PeerContact::new(
            NodeId::from_node_id_string(id),
            id.to_string(),
            "192.168.1.1".to_string(),
            443,
        )
        .with_geo(geo)
        .with_global(is_global)
    }

    #[test]
    fn test_hub_selection() {
        let hub = RegionalHub::with_defaults();

        let peers = vec![
            make_peer("peer1", 37.7749, -122.4194, true),
            make_peer("peer2", 34.0522, -118.2437, false),
            make_peer("peer3", 40.7128, -74.0060, true),
        ];

        hub.update_peers(peers);

        let hubs = hub.get_hubs();
        assert!(!hubs.is_empty());
    }

    #[test]
    fn test_regional_separation() {
        let hub = RegionalHub::with_defaults();

        let us_west = make_peer("us-west-1", 37.7749, -122.4194, true);
        let us_east = make_peer("us-east-1", 40.7128, -74.0060, true);
        let eu_peer = make_peer("eu-peer-1", 51.5074, -0.1278, false);

        hub.update_peers(vec![us_west, us_east, eu_peer]);

        let us_west_hubs = hub.get_hubs_for_region("US");
        let eu_hubs = hub.get_hubs_for_region("EU");

        assert!(!us_west_hubs.is_empty() || !eu_hubs.is_empty());
    }
}

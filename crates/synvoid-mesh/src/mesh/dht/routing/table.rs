use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::sync::Cache;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use super::bucket::KBucket;
use super::contact::{GeoInfo, PeerContact};
use super::geo_distance::GeoDistance;
use super::node_id::NodeId;
use super::regional_hubs::RegionalHub;

pub const BUCKET_COUNT: usize = 256;
pub const REPLICATION_K: usize = 20;
pub const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub const PING_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_STALE_DURATION: Duration = Duration::from_secs(15 * 60);

const ROUTING_CACHE_SIZE: u64 = 1000;
const ROUTING_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub enum InsertError {
    PeerNotResponsive,
    SameNodeId,
    PowVerificationFailed,
}

/// Error returned by `force_restore_contact` (Iteration 76, Part C).
///
/// Distinct from `InsertError` because the restore path has different
/// failure semantics: it must not silently evict an unrelated contact
/// when the target is absent and the bucket is full. Restoration callers
/// surface this error up to the rollback/recovery path so that residue
/// can be retained and the lifecycle remains `Failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForceRestoreContactError {
    /// The target contact is the local node — rejected.
    SameNodeId,
    /// The target contact is not in the bucket and the bucket is full.
    /// Restoration cannot proceed without evicting an unrelated peer.
    BucketFullTargetAbsent,
}

impl std::fmt::Display for ForceRestoreContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForceRestoreContactError::SameNodeId => {
                write!(f, "DHT force-restore rejected: target is local node")
            }
            ForceRestoreContactError::BucketFullTargetAbsent => {
                write!(
                    f,
                    "DHT force-restore rejected: bucket is full and target is absent"
                )
            }
        }
    }
}

impl std::error::Error for ForceRestoreContactError {}

#[derive(Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
pub struct PersistedRoutingTable {
    pub local_node_id: String,
    pub buckets: Vec<PersistedBucket>,
    pub last_updated: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
pub struct PersistedBucket {
    pub index: usize,
    pub peers: Vec<PersistedContact>,
    pub last_updated: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
pub struct PersistedContact {
    pub node_id: String,
    pub address: String,
    pub port: u16,
    pub geo: Option<GeoInfo>,
    pub latency_ms: Option<u32>,
    pub last_seen: u64,
    pub is_global: bool,
    pub is_trusted: bool,
    pub pow_nonce: Option<u64>,
    pub public_key: Option<Vec<u8>>,
}

impl PersistedRoutingTable {
    pub fn to_bytes(&self) -> Result<Vec<u8>, rkyv::rancor::Error> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self).map(|b| b.into_vec())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, rkyv::rancor::Error> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(data)
    }

    pub fn to_bytes_postcard(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    pub fn from_bytes_postcard(data: &[u8]) -> Option<Self> {
        postcard::from_bytes(data).ok()
    }
}

impl PersistedBucket {
    pub fn to_bytes_rkyv(&self) -> Vec<u8> {
        match rkyv::to_bytes::<rkyv::rancor::Error>(self) {
            Ok(b) => b.into_vec(),
            Err(_) => Vec::new(),
        }
    }

    pub fn from_bytes_rkyv(data: &[u8]) -> Option<Self> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(data).ok()
    }
}

impl PersistedContact {
    pub fn to_bytes_rkyv(&self) -> Vec<u8> {
        match rkyv::to_bytes::<rkyv::rancor::Error>(self) {
            Ok(b) => b.into_vec(),
            Err(_) => Vec::new(),
        }
    }

    pub fn from_bytes_rkyv(data: &[u8]) -> Option<Self> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(data).ok()
    }
}

pub struct RoutingTable {
    local_node_id: NodeId,
    local_node_id_string: String,
    buckets: Vec<KBucket>,
    pending_pings: HashMap<NodeId, Instant>,
    stale_duration: Duration,
    regional_hub: Option<Arc<RegionalHub>>,
    geo_distance: Option<Arc<GeoDistance>>,
    closest_cache: Cache<u64, Vec<PeerContact>>,
}

impl RoutingTable {
    pub fn new(local_node_id: NodeId, local_node_id_string: String) -> Self {
        let mut buckets = Vec::with_capacity(BUCKET_COUNT);
        for i in 0..BUCKET_COUNT {
            buckets.push(KBucket::new(i));
        }

        let closest_cache = Cache::builder()
            .max_capacity(ROUTING_CACHE_SIZE)
            .time_to_live(ROUTING_CACHE_TTL)
            .build();

        Self {
            local_node_id,
            local_node_id_string,
            buckets,
            pending_pings: HashMap::new(),
            stale_duration: DEFAULT_STALE_DURATION,
            regional_hub: None,
            geo_distance: None,
            closest_cache,
        }
    }

    pub fn with_regional_hub(mut self, hub: Arc<RegionalHub>) -> Self {
        self.regional_hub = Some(hub);
        self
    }

    pub fn with_geo_distance(mut self, geo_distance: Arc<GeoDistance>) -> Self {
        self.geo_distance = Some(geo_distance);
        self
    }

    pub fn set_regional_hub(&mut self, hub: Arc<RegionalHub>) {
        self.regional_hub = Some(hub);
    }

    pub fn set_geo_distance(&mut self, geo_distance: Arc<GeoDistance>) {
        self.geo_distance = Some(geo_distance);
    }

    pub fn regional_hub(&self) -> Option<&Arc<RegionalHub>> {
        self.regional_hub.as_ref()
    }

    pub fn geo_distance(&self) -> Option<&Arc<GeoDistance>> {
        self.geo_distance.as_ref()
    }

    pub fn with_stale_duration(mut self, duration: Duration) -> Self {
        self.stale_duration = duration;
        self
    }

    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    pub fn local_node_id_string(&self) -> &str {
        &self.local_node_id_string
    }

    pub fn insert(&mut self, peer: PeerContact) -> Result<Option<PeerContact>, InsertError> {
        if peer.node_id == self.local_node_id {
            return Err(InsertError::SameNodeId);
        }

        if peer.requires_pow() && !peer.verify_pow() {
            tracing::warn!(
                "Rejecting peer {} - failed PoW verification",
                peer.node_id_string
            );
            return Err(InsertError::PowVerificationFailed);
        }

        let bucket_index = peer.node_id.bucket_index(&self.local_node_id);
        let bucket = &mut self.buckets[bucket_index];

        if bucket.contains(&peer.node_id) {
            bucket.mark_seen(&peer.node_id);
            return Ok(None);
        }

        if bucket.is_full() {
            if let Some(oldest) = bucket.get_oldest() {
                if oldest.is_stale(self.stale_duration) {
                    let oldest_id = oldest.node_id;
                    let removed = bucket.remove(&oldest_id);
                    bucket.insert(peer).ok();
                    self.closest_cache.invalidate_all();
                    return Ok(removed);
                } else {
                    self.pending_pings.insert(oldest.node_id, Instant::now());
                    return Err(InsertError::PeerNotResponsive);
                }
            }
        }

        match bucket.insert(peer) {
            Ok(evicted) => {
                self.closest_cache.invalidate_all();
                Ok(evicted)
            }
            Err(_) => Ok(None),
        }
    }

    pub fn try_insert(&mut self, peer: PeerContact) -> Option<PeerContact> {
        if peer.node_id == self.local_node_id {
            return None;
        }

        if peer.requires_pow() && !peer.verify_pow() {
            tracing::debug!("Rejected peer {}: PoW verification failed", peer.node_id);
            return None;
        }

        let bucket_index = peer.node_id.bucket_index(&self.local_node_id);
        let bucket = &mut self.buckets[bucket_index];

        let result = bucket.try_insert(peer);
        if result.is_some() {
            self.closest_cache.invalidate_all();
        }
        result
    }

    pub fn remove(&mut self, node_id: &NodeId) -> Option<PeerContact> {
        let bucket_index = node_id.bucket_index(&self.local_node_id);
        let bucket = &mut self.buckets[bucket_index];
        let removed = bucket.remove(node_id);

        self.pending_pings.remove(node_id);

        if removed.is_some() {
            self.closest_cache.invalidate_all();
        }
        removed
    }

    pub fn find_closest(&self, target: &NodeId, k: usize) -> Vec<PeerContact> {
        let cache_key = Self::cache_key(target);

        if let Some(cached) = self.closest_cache.get(&cache_key) {
            let mut result = cached.clone();
            result.truncate(k);
            return result;
        }

        let target_bucket = target.bucket_index(&self.local_node_id);
        let num_buckets = self.buckets.len();

        let mut candidates: Vec<(PeerContact, NodeId)> = Vec::with_capacity(k * 2);

        for offset in 0..=num_buckets {
            let forward_idx = target_bucket.saturating_add(offset);
            let backward_idx = target_bucket.saturating_sub(offset);

            let buckets_to_search = if offset == 0 {
                vec![forward_idx]
            } else {
                vec![forward_idx, backward_idx]
                    .into_iter()
                    .filter(|&idx| idx < num_buckets)
                    .collect()
            };

            for bucket_idx in buckets_to_search {
                let bucket = &self.buckets[bucket_idx];
                for peer in bucket.get_all() {
                    let dist = target.xor_distance(&peer.node_id);

                    if candidates.len() < k {
                        candidates.push((peer.clone(), dist));
                    } else {
                        let max_dist = candidates
                            .iter()
                            .map(|(_, d)| *d)
                            .max()
                            .unwrap_or(NodeId([0xff; 32]));

                        if dist < max_dist {
                            candidates.retain(|(_, d)| d != &max_dist);
                            candidates.push((peer.clone(), dist));
                        }
                    }
                }
            }
        }

        candidates.sort_by_key(|a| a.1);
        candidates.truncate(k);
        let result: Vec<PeerContact> = candidates.into_iter().map(|(p, _)| p).collect();

        self.closest_cache.insert(cache_key, result.clone());
        result
    }

    fn cache_key(target: &NodeId) -> u64 {
        let bytes = target.as_bytes();
        u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    pub fn find_closest_geo(
        &self,
        target: &NodeId,
        k: usize,
        target_geo: Option<&GeoInfo>,
    ) -> Vec<PeerContact> {
        let mut closest = self.find_closest(target, k * 3);

        if let Some(geo) = target_geo {
            closest.sort_by(|a, b| {
                let dist_a = target.xor_distance(&a.node_id);
                let dist_b = target.xor_distance(&b.node_id);

                let dist_cmp = dist_a.cmp(&dist_b);
                if dist_cmp != std::cmp::Ordering::Equal {
                    return dist_cmp;
                }

                let score_a = a.geo_score(geo);
                let score_b = b.geo_score(geo);
                score_b
                    .partial_cmp(&score_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else {
            closest.sort_by(|a, b| {
                let dist_a = target.xor_distance(&a.node_id);
                let dist_b = target.xor_distance(&b.node_id);

                let dist_cmp = dist_a.cmp(&dist_b);
                if dist_cmp != std::cmp::Ordering::Equal {
                    return dist_cmp;
                }

                let lat_a = a.latency_ms.unwrap_or(u32::MAX);
                let lat_b = b.latency_ms.unwrap_or(u32::MAX);
                lat_a.cmp(&lat_b)
            });
        }

        closest.into_iter().take(k).collect()
    }

    pub fn find_closest_geo_weighted(
        &self,
        target: &NodeId,
        k: usize,
        target_geo: Option<&GeoInfo>,
    ) -> Vec<PeerContact> {
        let geo_dist = match &self.geo_distance {
            Some(g) => g.clone(),
            None => return self.find_closest(target, k),
        };

        let mut closest = self.find_closest(target, k * 3);

        closest.sort_by(|a, b| {
            let xor_a = target.xor_distance(&a.node_id);
            let xor_b = target.xor_distance(&b.node_id);

            let score_a =
                geo_dist.combined_distance(a.geo.as_ref(), target_geo, &xor_a, a.latency_ms);
            let score_b =
                geo_dist.combined_distance(b.geo.as_ref(), target_geo, &xor_b, b.latency_ms);

            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        closest.into_iter().take(k).collect()
    }

    pub fn find_closest_hybrid(
        &self,
        target: &NodeId,
        target_geo: Option<&GeoInfo>,
        k: usize,
    ) -> Vec<PeerContact> {
        if let Some(hub) = &self.regional_hub {
            if hub.is_enabled() {
                let hub_count = (k / 2).max(1);
                let bucket_count = k.saturating_sub(hub_count);

                let hub_peers = hub.find_closest_via_hubs(target, target_geo, hub_count);
                let bucket_peers = self.find_closest(target, bucket_count);

                // Deduplicate by node_id before combining
                let mut seen = HashSet::new();

                let mut combined: Vec<PeerContact> = hub_peers
                    .into_iter()
                    .filter(|p| seen.insert(p.node_id))
                    .collect();

                for peer in bucket_peers {
                    if seen.insert(peer.node_id) {
                        combined.push(peer);
                    }
                }

                combined.sort_by(|a, b| {
                    let dist_a = target.xor_distance(&a.node_id);
                    let dist_b = target.xor_distance(&b.node_id);
                    dist_a.cmp(&dist_b)
                });

                combined.truncate(k);
                return combined;
            }
        }

        self.find_closest(target, k)
    }

    pub fn sync_to_regional_hub(&self) {
        if let Some(hub) = &self.regional_hub {
            let peers = self.get_all_contacts();
            hub.update_peers(peers);
        }
    }

    pub fn get_regional_hubs(&self) -> Vec<PeerContact> {
        match &self.regional_hub {
            Some(hub) => hub.get_hubs(),
            None => Vec::new(),
        }
    }

    pub fn get_bucket_index(&self, node_id: &NodeId) -> usize {
        node_id.bucket_index(&self.local_node_id)
    }

    pub fn mark_responded(&mut self, node_id: &NodeId) {
        self.pending_pings.remove(node_id);

        let bucket_index = node_id.bucket_index(&self.local_node_id);
        self.buckets[bucket_index].mark_seen(node_id);
    }

    pub fn get_stale_peers(&self) -> Vec<NodeId> {
        let now = Instant::now();
        self.pending_pings
            .iter()
            .filter(|(_, ping_time)| now.duration_since(**ping_time) > PING_TIMEOUT)
            .map(|(node_id, _)| *node_id)
            .collect()
    }

    pub fn get_peers_to_ping(&self, bucket_index: usize) -> Vec<PeerContact> {
        if bucket_index >= self.buckets.len() {
            return Vec::new();
        }

        let bucket = &self.buckets[bucket_index];

        if bucket.is_empty() {
            return Vec::new();
        }

        let mut to_ping = Vec::new();

        for peer in bucket.get_all() {
            if peer.is_stale(self.stale_duration) {
                to_ping.push(peer.clone());
            }
        }

        to_ping
    }

    pub fn split_bucket(&mut self, bucket_index: usize) -> bool {
        if bucket_index >= self.buckets.len() - 1 {
            return false;
        }

        let bucket = &mut self.buckets[bucket_index];
        let prefix_len = bucket_index;

        let local_prefix = self.local_node_id.0[prefix_len / 8] & (0x80 >> (prefix_len % 8));
        let split_bit = if local_prefix == 0 { 0x80 } else { 0x00 };

        let (low_peers, high_peers): (Vec<_>, Vec<_>) =
            bucket.get_all_mut().drain(..).partition(|p| {
                let peer_bit = p.node_id.0[prefix_len / 8] & (0x80 >> (prefix_len % 8));
                peer_bit == split_bit
            });

        *bucket.get_all_mut() = low_peers;

        let new_bucket = KBucket::new(bucket_index + 1);
        self.buckets.insert(bucket_index + 1, new_bucket);

        if let Some(new_bucket) = self.buckets.get_mut(bucket_index + 1) {
            for peer in high_peers {
                new_bucket.insert(peer).ok();
            }
        }

        true
    }

    pub fn get_all_contacts(&self) -> Vec<PeerContact> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.get_all().to_vec())
            .collect()
    }

    pub fn import_contacts(&mut self, peers: Vec<PeerContact>) -> usize {
        let mut imported = 0;
        for peer in peers {
            if self.try_insert(peer).is_some() {
                imported += 1;
            }
        }
        imported
    }

    pub fn to_persisted(&self) -> PersistedRoutingTable {
        let buckets = self
            .buckets
            .iter()
            .enumerate()
            .map(|(idx, bucket)| PersistedBucket {
                index: idx,
                peers: bucket
                    .get_all()
                    .iter()
                    .map(|p| PersistedContact {
                        node_id: p.node_id_string.clone(),
                        address: p.address.clone(),
                        port: p.port,
                        geo: p.geo.clone(),
                        latency_ms: p.latency_ms,
                        last_seen: p.last_seen.elapsed().as_secs(),
                        is_global: p.is_global,
                        is_trusted: p.is_trusted,
                        pow_nonce: p.pow_nonce,
                        public_key: p.public_key.clone(),
                    })
                    .collect(),
                last_updated: bucket.last_updated().elapsed().as_secs(),
            })
            .collect();

        PersistedRoutingTable {
            local_node_id: self.local_node_id_string.clone(),
            buckets,
            last_updated: synvoid_utils::safe_unix_timestamp(),
        }
    }

    pub fn to_persisted_bytes(&self) -> Result<Vec<u8>, rkyv::rancor::Error> {
        self.to_persisted().to_bytes()
    }

    pub fn from_persisted_bytes(
        data: Vec<u8>,
        local_node_id: NodeId,
    ) -> Result<Self, rkyv::rancor::Error> {
        PersistedRoutingTable::from_bytes(&data).map(|p| Self::from_persisted(p, local_node_id))
    }

    pub fn from_persisted(data: PersistedRoutingTable, local_node_id: NodeId) -> Self {
        let mut table = Self::new(local_node_id, data.local_node_id.clone());

        for persisted_bucket in data.buckets {
            let idx = persisted_bucket.index;
            if idx < table.buckets.len() {
                for persisted_contact in persisted_bucket.peers {
                    let node_id = NodeId::from_node_id_string(&persisted_contact.node_id);
                    let mut contact = PeerContact::new(
                        node_id,
                        persisted_contact.node_id,
                        persisted_contact.address,
                        persisted_contact.port,
                    )
                    .with_latency(persisted_contact.latency_ms.unwrap_or(0))
                    .with_global(persisted_contact.is_global)
                    .with_trusted(persisted_contact.is_trusted);

                    if let Some(geo) = persisted_contact.geo {
                        contact.geo = Some(geo);
                    }

                    contact.last_seen =
                        Instant::now() - Duration::from_secs(persisted_contact.last_seen);
                    contact.pow_nonce = persisted_contact.pow_nonce;
                    contact.public_key = persisted_contact.public_key;

                    table.buckets[idx].insert(contact).ok();
                }
            }
        }

        table
    }

    pub fn total_peers(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn bucket_stats(&self) -> Vec<(usize, usize)> {
        self.buckets
            .iter()
            .enumerate()
            .map(|(idx, bucket)| (idx, bucket.len()))
            .collect()
    }

    pub fn get_contact(&self, node_id: &NodeId) -> Option<PeerContact> {
        let bucket_index = node_id.bucket_index(&self.local_node_id);
        self.buckets[bucket_index].get(node_id).cloned()
    }

    /// Force-restore a contact during rollback/recovery.
    ///
    /// Unlike `try_insert`, this unconditionally replaces any existing contact
    /// with the same node ID and does not apply PoW admission checks — the
    /// contact was previously accepted state. **Does not** evict an
    /// unrelated contact to make room for an absent target; the underlying
    /// `KBucket::force_replace()` returns `BucketFullTargetAbsent` instead
    /// (Iteration 76, Part C).
    ///
    /// Returns `Ok(())` on success. Errors:
    /// - `InsertError::SameNodeId` if the contact is the local node.
    /// - `ForceRestoreContactError::BucketFullTargetAbsent` if the target
    ///   contact is not in the bucket and the bucket is full.
    pub fn force_restore_contact(
        &mut self,
        contact: PeerContact,
    ) -> Result<(), ForceRestoreContactError> {
        if contact.node_id == self.local_node_id {
            return Err(ForceRestoreContactError::SameNodeId);
        }

        let bucket_index = contact.node_id.bucket_index(&self.local_node_id);
        let node_id = contact.node_id;
        let bucket = &mut self.buckets[bucket_index];

        bucket.force_replace(contact).map_err(|e| match e {
            super::bucket::ForceRestoreError::BucketFullTargetAbsent => {
                ForceRestoreContactError::BucketFullTargetAbsent
            }
        })?;

        self.closest_cache.invalidate_all();
        self.pending_pings.remove(&node_id);

        Ok(())
    }

    pub fn get_sparse_bucket_indices(&self, k: usize) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| bucket.len() < k)
            .map(|(idx, _)| idx)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(prefix: u8) -> PeerContact {
        PeerContact::new(
            NodeId::from_node_id_string(&format!("node-{:02x}00", prefix)),
            format!("node-{:02x}00", prefix),
            "127.0.0.1".to_string(),
            443,
        )
        .with_global(true)
    }

    #[test]
    fn test_insert_single() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        let peer = make_contact(0x01);
        let result = table.insert(peer);
        assert!(result.is_ok());
        assert_eq!(table.total_peers(), 1);
    }

    #[test]
    fn test_insert_duplicate() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        let peer = make_contact(0x01);
        table.insert(peer.clone()).unwrap();
        table.insert(peer).unwrap();

        assert_eq!(table.total_peers(), 1);
    }

    #[test]
    fn test_remove() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        let peer = make_contact(0x01);
        let node_id = peer.node_id;
        table.insert(peer).unwrap();

        let removed = table.remove(&node_id);
        assert!(removed.is_some());
        assert_eq!(table.total_peers(), 0);
    }

    #[test]
    fn test_find_closest() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        for i in 0..10 {
            table.insert(make_contact(i)).unwrap();
        }

        let target = NodeId::from_node_id_string("target-node");
        let closest = table.find_closest(&target, 3);

        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn test_persistence() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        for i in 0..5 {
            table.insert(make_contact(i)).unwrap();
        }

        let persisted = table.to_persisted();
        let restored = RoutingTable::from_persisted(persisted, local);

        assert_eq!(restored.total_peers(), 5);
    }

    #[test]
    fn test_force_restore_existing_contact() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        // Insert contact A
        let mut contact_a = make_contact(0x01);
        contact_a.address = "10.0.0.1".to_string();
        contact_a.port = 8443;
        contact_a.is_global = true;
        contact_a.is_trusted = true;
        contact_a.latency_ms = Some(100);
        table.insert(contact_a.clone()).unwrap();

        // Verify A is present
        let node_id = NodeId::from_node_id_string("node-0100");
        let stored = table.get_contact(&node_id).unwrap();
        assert_eq!(stored.address, "10.0.0.1");

        // Mutate the contact in-place (simulating startup mutation)
        let bucket_idx = node_id.bucket_index(&local);
        let bucket = &mut table.buckets[bucket_idx];
        let existing = bucket.get_mut(&node_id).unwrap();
        existing.address = "10.0.0.2".to_string();
        existing.port = 9443;
        existing.is_global = false;
        existing.latency_ms = Some(200);

        // Verify B is present
        let stored = table.get_contact(&node_id).unwrap();
        assert_eq!(stored.address, "10.0.0.2");

        // Force restore A
        table.force_restore_contact(contact_a.clone()).unwrap();

        // Verify A is restored
        let stored = table.get_contact(&node_id).unwrap();
        assert_eq!(stored.address, "10.0.0.1");
        assert_eq!(stored.port, 8443);
        assert!(stored.is_global);
        assert!(stored.is_trusted);
        assert_eq!(stored.latency_ms, Some(100));
    }

    #[test]
    fn test_force_restore_no_eviction_of_unrelated() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        // Fill a bucket
        for i in 0..20u8 {
            table.insert(make_contact(i)).unwrap();
        }
        assert_eq!(table.total_peers(), 20);

        // Mutate an existing contact in-place
        let node_id = make_contact(0x01).node_id;
        let bucket_idx = node_id.bucket_index(&local);
        let bucket = &mut table.buckets[bucket_idx];
        let existing = bucket.get_mut(&node_id).unwrap();
        existing.address = "mutated".to_string();

        // Force restore original — should replace in-place, not evict
        let original = make_contact(0x01);
        table.force_restore_contact(original).unwrap();

        // All 20 peers still present, no unrelated eviction
        assert_eq!(table.total_peers(), 20);
    }

    #[test]
    fn test_force_restore_invalidation() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        let peer = make_contact(0x01);
        table.insert(peer.clone()).unwrap();

        // Prime the cache
        let target = NodeId::from_node_id_string("target");
        let _ = table.find_closest(&target, 5);

        // Force restore should invalidate cache
        table.force_restore_contact(make_contact(0x01)).unwrap();

        // Subsequent lookup should not use stale cache (just verify no panic)
        let _ = table.find_closest(&target, 5);
    }

    #[test]
    fn test_force_restore_pending_ping_cleanup() {
        let local = NodeId::from_node_id_string("local-node");
        let mut table = RoutingTable::new(local, "local-node".to_string());

        let peer = make_contact(0x01);
        let node_id = peer.node_id;
        table.insert(peer).unwrap();

        // Add a pending ping
        table.pending_pings.insert(node_id, Instant::now());

        // Force restore should clear the pending ping
        table.force_restore_contact(make_contact(0x01)).unwrap();
        assert!(!table.pending_pings.contains_key(&node_id));
    }

    #[test]
    fn test_force_restore_full_bucket_absent_target_returns_conflict() {
        // Iteration 76, Phase 16: A full bucket with the target absent
        // must return `BucketFullTargetAbsent` without evicting any
        // unrelated contact. Residue remains unresolved.
        //
        // We directly fill a single bucket by mutating the routing
        // table's `buckets` field. This bypasses the
        // `insert()` admission checks (PoW, ping responsiveness) and
        // deterministically produces a full bucket. The
        // `force_restore_contact()` path is then exercised against
        // this fixture.
        //
        // `bucket_index(self, local) = 255 - common_prefix_len`. So
        // bucket 255 is for contacts whose high bits differ from the
        // local node (common prefix = 0). With local = [0; 32], any
        // contact whose first byte is non-zero lands in bucket 255.
        let local = NodeId([0u8; 32]);
        let mut table = RoutingTable::new(local, "local-node".to_string());

        // Pick bucket 255 (the "first byte differs" bucket) as our
        // test bucket.
        let bucket_idx = 255usize;

        // Fill the bucket with 20 distinct contacts. We use byte values
        // that flip the **high bit** of the first byte (0x80, 0x81, ...
        // 0x93), since `common_prefix_len` measures the number of leading
        // matching bits and we want the prefix to be 0 bits long for
        // bucket 255. Anything with bit 7 of the first byte set produces
        // a common prefix of 0 against local = [0; 32].
        let mut before: Vec<NodeId> = Vec::new();
        for i in 0u8..20u8 {
            let mut bytes = [0u8; 32];
            // 0x80 | i ensures bit 7 is set; the lower nibble varies so
            // the 20 contacts are all distinct.
            bytes[0] = 0x80 | i;
            let id = NodeId(bytes);
            assert_eq!(
                id.bucket_index(&local),
                bucket_idx,
                "synthesized contact {i} (0x{:02x}) landed in bucket {}",
                bytes[0],
                id.bucket_index(&local)
            );
            table
                .buckets
                .get_mut(bucket_idx)
                .unwrap()
                .insert(PeerContact::new(
                    id,
                    format!("peer-{}", i),
                    "1.1.1.1".into(),
                    443,
                ))
                .expect("insert into empty slot");
            before.push(id);
        }
        assert_eq!(table.buckets[bucket_idx].len(), 20);

        // Synthesize an absent target that ALSO maps to bucket 255
        // (different node_id than any of the existing 20). Pick a
        // node_id whose first byte is 0xFE — that's not in {0..20}.
        let absent_id = NodeId({
            let mut bytes = [0u8; 32];
            bytes[0] = 0xFE;
            bytes
        });
        assert_eq!(absent_id.bucket_index(&local), bucket_idx);
        assert!(!table.buckets[bucket_idx].contains(&absent_id));
        let absent_target =
            PeerContact::new(absent_id, "absent-target".into(), "9.9.9.9".into(), 443);

        // Force-restore the absent target. Bucket is full, target is
        // absent → must return conflict without evicting anyone.
        let result = table.force_restore_contact(absent_target);
        assert_eq!(
            result,
            Err(ForceRestoreContactError::BucketFullTargetAbsent),
            "full bucket with absent target must return conflict"
        );

        // No unrelated contact was evicted
        assert_eq!(table.buckets[bucket_idx].len(), 20);
        for id in &before {
            assert!(
                table.buckets[bucket_idx].contains(id),
                "unrelated contact {id:?} was evicted during force-restore"
            );
        }
    }
}

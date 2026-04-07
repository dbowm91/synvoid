#![allow(
    unused_variables,
    unused_mut,
    clippy::type_complexity,
    clippy::redundant_locals
)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock as ParkingLotRwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

mod serde_secs {
    use serde::{Deserializer, Serializer};
    use std::time::Instant;

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = instant.elapsed().as_secs();
        serializer.serialize_u64(secs)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = serde::Deserialize::deserialize(deserializer)?;
        Ok(Instant::now() - std::time::Duration::from_secs(secs))
    }
}
use moka::future::Cache as MokaCache;

use crate::mesh::config::{MeshConfig, MeshNodeRole};
use crate::mesh::protocol::{MeshPeerInfo, UpstreamInfo, UpstreamOwner};

const NUM_SHARDS: usize = 64;

#[inline]
fn shard_index(key: &str) -> usize {
    let mut hash: u64 = 5381;
    for byte in key.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    (hash as usize) % NUM_SHARDS
}

struct PeerShard {
    peers: HashMap<String, PeerState>,
    peer_scores: HashMap<String, PeerScore>,
    connection_failures: HashMap<String, u32>,
    connection_successes: HashMap<String, u32>,
    latency_history: HashMap<String, Vec<(Instant, u32)>>,
    peer_versions: HashMap<String, u64>,
    route_stability: HashMap<String, RouteStability>,
    bandwidth_trackers: HashMap<String, BandwidthStats>,
}

impl PeerShard {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            peer_scores: HashMap::new(),
            connection_failures: HashMap::new(),
            connection_successes: HashMap::new(),
            latency_history: HashMap::new(),
            peer_versions: HashMap::new(),
            route_stability: HashMap::new(),
            bandwidth_trackers: HashMap::new(),
        }
    }
}

struct ShardedPeerStore {
    shards: Vec<ParkingLotRwLock<PeerShard>>,
}

impl ShardedPeerStore {
    fn new() -> Self {
        let shards = (0..NUM_SHARDS)
            .map(|_| ParkingLotRwLock::new(PeerShard::new()))
            .collect();
        Self { shards }
    }

    #[inline]
    fn shard(&self, key: &str) -> &ParkingLotRwLock<PeerShard> {
        &self.shards[shard_index(key)]
    }

    fn get_peer(&self, node_id: &str) -> Option<PeerState> {
        self.shard(node_id).read().peers.get(node_id).cloned()
    }

    fn get_peer_score(&self, node_id: &str) -> Option<PeerScore> {
        self.shard(node_id).read().peer_scores.get(node_id).cloned()
    }

    fn upsert_peer(&self, peer: PeerState) {
        let node_id = peer.node_id.clone();
        let mut shard = self.shard(&node_id).write();
        shard.peers.insert(node_id.clone(), peer);
        shard.peer_scores.entry(node_id.clone()).or_insert_with(|| {
            let mut s = PeerScore::default();
            s.node_id = node_id.clone();
            s
        });
        shard
            .connection_failures
            .entry(node_id.clone())
            .or_insert(0);
        shard
            .connection_successes
            .entry(node_id.clone())
            .or_insert(0);
        shard
            .latency_history
            .entry(node_id.clone())
            .or_insert_with(Vec::new);
        shard.peer_versions.entry(node_id.clone()).or_insert(0);
    }

    fn update_peer_status(&self, node_id: &str, status: PeerStatus) {
        let mut shard = self.shard(node_id).write();
        if let Some(peer) = shard.peers.get_mut(node_id) {
            peer.status = status;
            peer.last_seen = Instant::now();
        }
    }

    fn update_peer_latency(&self, node_id: &str, latency_ms: u32) {
        let mut shard = self.shard(node_id).write();
        if let Some(peer) = shard.peers.get_mut(node_id) {
            peer.latency_ms = Some(latency_ms);
        }
    }

    fn update_peer<F: FnOnce(&mut PeerState)>(&self, node_id: &str, f: F) {
        let mut shard = self.shard(node_id).write();
        if let Some(peer) = shard.peers.get_mut(node_id) {
            f(peer);
        }
    }

    fn remove_peer(&self, node_id: &str) -> Option<PeerState> {
        let mut shard = self.shard(node_id).write();
        let peer = shard.peers.remove(node_id);
        shard.peer_scores.remove(node_id);
        shard.connection_failures.remove(node_id);
        shard.connection_successes.remove(node_id);
        shard.latency_history.remove(node_id);
        shard.peer_versions.remove(node_id);
        shard.route_stability.remove(node_id);
        shard.bandwidth_trackers.remove(node_id);
        peer
    }

    fn record_latency(&self, node_id: &str, latency_ms: u32) {
        let mut shard = self.shard(node_id).write();
        let entry = shard
            .latency_history
            .entry(node_id.to_string())
            .or_insert_with(Vec::new);
        entry.push((Instant::now(), latency_ms));
        if entry.len() > 20 {
            entry.remove(0);
        }
    }

    fn record_connection_success(&self, node_id: &str) {
        let mut shard = self.shard(node_id).write();
        *shard
            .connection_successes
            .entry(node_id.to_string())
            .or_insert(0) += 1;
    }

    fn record_connection_failure(&self, node_id: &str) {
        let mut shard = self.shard(node_id).write();
        *shard
            .connection_failures
            .entry(node_id.to_string())
            .or_insert(0) += 1;
    }

    fn get_latency_history(&self, node_id: &str) -> Option<Vec<(Instant, u32)>> {
        self.shard(node_id)
            .read()
            .latency_history
            .get(node_id)
            .cloned()
    }

    fn get_connection_failures(&self, node_id: &str) -> u32 {
        self.shard(node_id)
            .read()
            .connection_failures
            .get(node_id)
            .copied()
            .unwrap_or(0)
    }

    fn get_connection_successes(&self, node_id: &str) -> u32 {
        self.shard(node_id)
            .read()
            .connection_successes
            .get(node_id)
            .copied()
            .unwrap_or(0)
    }

    fn get_peer_version(&self, node_id: &str) -> u64 {
        *self
            .shard(node_id)
            .read()
            .peer_versions
            .get(node_id)
            .unwrap_or(&0)
    }

    fn set_peer_version(&self, node_id: &str, version: u64) {
        let mut shard = self.shard(node_id).write();
        shard.peer_versions.insert(node_id.to_string(), version);
    }

    fn get_bandwidth_stats(&self, upstream_id: &str) -> Option<BandwidthStats> {
        self.shard(upstream_id)
            .read()
            .bandwidth_trackers
            .get(upstream_id)
            .cloned()
    }

    fn update_bandwidth<F: FnOnce(&mut BandwidthStats)>(&self, upstream_id: &str, f: F) {
        let mut shard = self.shard(upstream_id).write();
        if let Some(stats) = shard.bandwidth_trackers.get_mut(upstream_id) {
            f(stats);
        }
    }

    fn upsert_bandwidth<F: FnOnce(&mut BandwidthStats)>(&self, upstream_id: &str, f: F) {
        let mut shard = self.shard(upstream_id).write();
        let stats = shard
            .bandwidth_trackers
            .entry(upstream_id.to_string())
            .or_insert_with(BandwidthStats::default);
        f(stats);
    }

    fn get_route_stability(&self, upstream_id: &str) -> Option<RouteStability> {
        self.shard(upstream_id)
            .read()
            .route_stability
            .get(upstream_id)
            .cloned()
    }

    fn update_route_stability<F: FnOnce(&mut RouteStability)>(&self, upstream_id: &str, f: F) {
        let mut shard = self.shard(upstream_id).write();
        if let Some(rs) = shard.route_stability.get_mut(upstream_id) {
            f(rs);
        }
    }

    fn upsert_route_stability<F: FnOnce(&mut RouteStability)>(
        &self,
        upstream_id: &str,
        init: RouteStability,
        f: F,
    ) {
        let mut shard = self.shard(upstream_id).write();
        let rs = shard
            .route_stability
            .entry(upstream_id.to_string())
            .or_insert(init);
        f(rs);
    }

    #[allow(dead_code)]
    fn update_peer_score<F: FnOnce(&mut PeerScore)>(&self, node_id: &str, f: F) {
        let mut shard = self.shard(node_id).write();
        if let Some(score) = shard.peer_scores.get_mut(node_id) {
            f(score);
        }
    }

    fn upsert_peer_score<F: FnOnce(&mut PeerScore)>(&self, node_id: &str, init: PeerScore, f: F) {
        let mut shard = self.shard(node_id).write();
        let score = shard.peer_scores.entry(node_id.to_string()).or_insert(init);
        f(score);
    }

    fn collect_all_peers(&self) -> Vec<PeerState> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.read().peers.values().cloned());
        }
        result
    }

    fn collect_all_peer_scores(&self) -> HashMap<String, PeerScore> {
        let mut result = HashMap::new();
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in &guard.peer_scores {
                result.insert(k.clone(), v.clone());
            }
        }
        result
    }

    fn collect_all_peer_keys(&self) -> Vec<String> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.read().peers.keys().cloned());
        }
        result
    }

    fn for_each_peer<F: FnMut(&String, &PeerState)>(&self, mut f: F) {
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in &guard.peers {
                f(k, v);
            }
        }
    }

    #[allow(dead_code)]
    fn retain_peers<F: FnMut(&String, &PeerState) -> bool>(&self, mut f: F) {
        for shard in &self.shards {
            shard.write().peers.retain(|k, v| f(k, v));
        }
    }

    fn remove_stale(&self, node_id: &str) {
        let mut shard = self.shard(node_id).write();
        shard.peers.remove(node_id);
        shard.peer_scores.remove(node_id);
        shard.route_stability.remove(node_id);
    }

    fn cleanup_inactive(&self, active_ids: &HashSet<String>) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut guard = shard.write();
            let before_failures = guard.connection_failures.len();
            guard
                .connection_failures
                .retain(|id, _| active_ids.contains(id));
            removed += before_failures.saturating_sub(guard.connection_failures.len());

            let before_successes = guard.connection_successes.len();
            guard
                .connection_successes
                .retain(|id, _| active_ids.contains(id));
            removed += before_successes.saturating_sub(guard.connection_successes.len());

            let before_latency = guard.latency_history.len();
            guard
                .latency_history
                .retain(|id, _| active_ids.contains(id));
            removed += before_latency.saturating_sub(guard.latency_history.len());

            let before_versions = guard.peer_versions.len();
            guard.peer_versions.retain(|id, _| active_ids.contains(id));
            removed += before_versions.saturating_sub(guard.peer_versions.len());

            let before_bw = guard.bandwidth_trackers.len();
            guard
                .bandwidth_trackers
                .retain(|id, _| active_ids.contains(id));
            removed += before_bw.saturating_sub(guard.bandwidth_trackers.len());
        }
        removed
    }

    fn clear(&self) {
        for shard in &self.shards {
            let mut guard = shard.write();
            guard.peers.clear();
            guard.peer_scores.clear();
            guard.connection_failures.clear();
            guard.connection_successes.clear();
            guard.latency_history.clear();
            guard.peer_versions.clear();
            guard.route_stability.clear();
            guard.bandwidth_trackers.clear();
        }
    }

    fn set_all_peer_versions(&self, versions: HashMap<String, u64>) {
        for (node_id, version) in versions {
            self.set_peer_version(&node_id, version);
        }
    }

    fn collect_all_peer_versions(&self) -> HashMap<String, u64> {
        let mut result = HashMap::new();
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in &guard.peer_versions {
                result.insert(k.clone(), *v);
            }
        }
        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Connecting,
    Handshake,
    Healthy,
    Unhealthy,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub node_id: String,
    pub address: String,
    pub role: MeshNodeRole,
    pub status: PeerStatus,
    pub capabilities: crate::mesh::protocol::MeshCapabilities,
    pub upstreams: HashSet<String>,
    pub latency_ms: Option<u32>,
    #[serde(with = "serde_secs")]
    pub first_seen: Instant,
    #[serde(with = "serde_secs")]
    pub last_seen: Instant,
    pub is_global: bool,
    pub is_trusted: bool,
    #[serde(skip)]
    pub connection_handle: Option<()>,
    pub geo: Option<String>,
    pub audit_successes: u64,
    pub audit_failures: u64,
    pub quic_port: Option<u32>,
    pub wireguard_port: Option<u32>,
    pub advertised_port: Option<u32>,
    pub previous_reputation: Option<f64>,
}

impl PeerState {
    pub fn is_healthy(&self) -> bool {
        self.status == PeerStatus::Healthy
    }

    pub fn has_upstream(&self, upstream_id: &str) -> bool {
        self.upstreams.contains(upstream_id)
    }

    pub fn audit_reputation(&self) -> f64 {
        let total = self.audit_successes + self.audit_failures;
        if total == 0 {
            if let Some(prev) = self.previous_reputation {
                return prev;
            }
            return 1.0;
        }
        let current = self.audit_successes as f64 / total as f64;

        if let Some(prev) = self.previous_reputation {
            let rebuilding_boost = 0.1;
            return (current * (1.0 - rebuilding_boost)) + (prev * rebuilding_boost);
        }

        current
    }

    pub fn record_audit_success(&mut self) {
        self.audit_successes = self.audit_successes.saturating_add(1);
    }

    pub fn record_audit_failure(&mut self) {
        self.audit_failures = self.audit_failures.saturating_add(1);
    }

    pub fn save_reputation_before_disconnect(&mut self) {
        if self.audit_successes + self.audit_failures > 10 {
            self.previous_reputation = Some(self.audit_reputation());
        }
    }

    pub fn time_away(&self) -> u64 {
        Instant::now().duration_since(self.last_seen).as_secs()
    }
}

#[derive(Debug, Clone)]
pub enum TopologyDelta {
    FullSync(TopologyFullSync),
    Incremental(TopologyIncrementalDelta),
}

#[derive(Debug, Clone)]
pub struct TopologyFullSync {
    pub peers: Vec<PeerState>,
    pub upstreams: HashMap<String, UpstreamOwner>,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub struct TopologyIncrementalDelta {
    pub added_peers: Vec<PeerState>,
    pub updated_peers: Vec<PeerState>,
    pub removed_peers: Vec<String>,
    pub added_upstreams: HashMap<String, UpstreamOwner>,
    pub removed_upstreams: Vec<String>,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub struct UpstreamInfoInternal {
    pub upstream_id: String,
    pub upstream_url: String,
    pub geo: Option<String>,
    pub is_local: bool,
    pub owner_node_id: String,
    pub last_updated: Instant,
    pub peered_wafs: HashSet<String>,
    pub waf_policy: Option<crate::mesh::protocol::WafPolicy>,
    pub protocol: crate::mesh::protocol::UpstreamProtocol,
    pub priority_tier: u32,
}

#[derive(Debug, Clone)]
pub struct PeerSelectionWeights {
    pub random: f64,
    pub latency: f64,
    pub reputation: f64,
    pub role: f64,
}

impl Default for PeerSelectionWeights {
    fn default() -> Self {
        Self {
            random: 0.3,
            latency: 0.3,
            reputation: 0.3,
            role: 0.1,
        }
    }
}

impl PeerSelectionWeights {
    pub fn balanced() -> Self {
        Self {
            random: 0.25,
            latency: 0.25,
            reputation: 0.25,
            role: 0.25,
        }
    }

    pub fn low_latency() -> Self {
        Self {
            random: 0.1,
            latency: 0.6,
            reputation: 0.2,
            role: 0.1,
        }
    }

    pub fn high_reputation() -> Self {
        Self {
            random: 0.1,
            latency: 0.2,
            reputation: 0.6,
            role: 0.1,
        }
    }

    pub fn random_only() -> Self {
        Self {
            random: 1.0,
            latency: 0.0,
            reputation: 0.0,
            role: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockedUpstream {
    pub mesh_identifier: String,
    pub service_id: String,
    pub blocked_until: Instant,
    pub reason: String,
    pub origin_node_id: String,
}

impl UpstreamInfoInternal {
    pub fn can_be_routed_by(&self, node_id: &str) -> bool {
        if self.peered_wafs.is_empty() {
            return true;
        }
        self.peered_wafs.contains(node_id)
    }
}

pub struct MeshTopology {
    config: Arc<MeshConfig>,
    node_id: String,
    router_id: String,
    role: MeshNodeRole,
    peer_store: ShardedPeerStore,
    local_upstreams: RwLock<HashMap<String, UpstreamInfoInternal>>,
    route_cache: MokaCache<String, CachedRoute>,
    global_nodes: RwLock<HashSet<String>>,
    pending_queries: RwLock<HashMap<String, crate::mesh::protocol::PendingQuery>>,
    cache_metrics: RwLock<CacheMetrics>,
    route_usage: RwLock<RouteUsageTracker>,
    topology_version: RwLock<u64>,
    upstream_versions: RwLock<HashMap<String, u64>>,
    blocked_upstreams: RwLock<HashMap<String, BlockedUpstream>>,
    degraded_mode: AtomicBool,
    peer_scores_compat: RwLock<HashMap<String, PeerScore>>,
}

#[derive(Debug, Clone, Default)]
struct CacheMetrics {
    hits: u64,
    misses: u64,
}

#[derive(Debug, Clone)]
struct CachedRoute {
    provider_node_id: String,
    hops: u8,
}

#[derive(Debug, Clone)]
struct RouteStability {
    #[allow(dead_code)]
    upstream_id: String,
    provider_history: Vec<(String, Instant)>,
    stability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    pub node_id: String,
    pub latency_score: f64,
    pub stability_score: f64,
    pub load_score: f64,
    pub traffic_score: f64,
    pub upstream_score: f64,
    pub total_score: f64,
    #[serde(with = "serde_secs")]
    pub last_updated: Instant,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            latency_score: 0.5,
            stability_score: 0.5,
            load_score: 0.5,
            traffic_score: 0.0,
            upstream_score: 0.0,
            total_score: 0.5,
            last_updated: Instant::now(),
        }
    }
}

impl PeerScore {
    pub fn calculate_total(&mut self, weights: &crate::mesh::config::ConnectionScoreWeights) {
        self.total_score = (self.latency_score * weights.latency
            + self.stability_score * weights.stability
            + self.load_score * weights.load
            + self.traffic_score * weights.traffic
            + self.upstream_score * weights.upstream)
            .clamp(0.0, 1.0);
        self.last_updated = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct BandwidthStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub request_count: u64,
    pub last_updated: Instant,
}

impl Default for BandwidthStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            request_count: 0,
            last_updated: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPersistenceData {
    version: u32,
    peers: Vec<PeerState>,
    peer_scores: HashMap<String, PeerScore>,
    saved_at: u64,
}

#[derive(Debug, Clone)]
pub struct RouteUsage {
    pub upstream_id: String,
    pub request_count: u64,
    pub bytes_transferred: u64,
    pub last_used: Instant,
    pub popularity_score: f64,
}

impl RouteUsage {
    pub fn new(upstream_id: String) -> Self {
        Self {
            upstream_id,
            request_count: 0,
            bytes_transferred: 0,
            last_used: Instant::now(),
            popularity_score: 0.0,
        }
    }

    pub fn record_request(&mut self, bytes: u64) {
        self.request_count += 1;
        self.bytes_transferred += bytes;
        self.last_used = Instant::now();
    }

    pub fn calculate_popularity(&mut self, window: Duration) {
        let elapsed = self.last_used.elapsed();
        if elapsed > window {
            self.popularity_score = 0.0;
        } else {
            let recency = 1.0 - (elapsed.as_secs_f64() / window.as_secs_f64());
            let volume = (self.request_count as f64).log10().max(0.0) / 10.0;
            self.popularity_score = (recency * 0.7 + volume * 0.3).min(1.0);
        }
    }
}

pub struct RouteUsageTracker {
    usages: HashMap<String, RouteUsage>,
    #[allow(dead_code)]
    window: Duration,
}

impl Default for RouteUsageTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

impl RouteUsageTracker {
    pub fn new(window: Duration) -> Self {
        Self {
            usages: HashMap::new(),
            window,
        }
    }

    pub fn record_usage(&mut self, upstream_id: String, bytes: u64) {
        let usage = self
            .usages
            .entry(upstream_id.clone())
            .or_insert_with(|| RouteUsage::new(upstream_id));
        usage.record_request(bytes);
    }

    pub fn get_popular_upstreams(&self, limit: usize) -> Vec<String> {
        let mut sorted: Vec<_> = self.usages.values().collect();
        sorted.sort_by(|a, b| {
            b.popularity_score
                .partial_cmp(&a.popularity_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
            .into_iter()
            .take(limit)
            .map(|u| u.upstream_id.clone())
            .collect()
    }

    pub fn get_upstream_score(&self, upstream_id: &str) -> f64 {
        self.usages
            .get(upstream_id)
            .map(|u| u.popularity_score)
            .unwrap_or(0.0)
    }

    pub fn prune_inactive(&mut self, active_ids: &HashSet<String>, max_entries: usize) {
        self.usages.retain(|id, _| active_ids.contains(id));
        if self.usages.len() > max_entries {
            let mut sorted: Vec<_> = self.usages.iter().collect();
            sorted.sort_by(|a, b| {
                b.1.popularity_score
                    .partial_cmp(&a.1.popularity_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let to_remove: Vec<_> = sorted
                .iter()
                .skip(max_entries)
                .map(|(k, _)| (*k).clone())
                .collect();
            for key in to_remove {
                self.usages.remove(&key);
            }
        }
    }
}

impl MeshTopology {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        let node_id = config.node_id();
        let router_id = config.router_id();
        let role = config.role;

        let route_cache = MokaCache::builder()
            .time_to_live(Duration::from_secs(3600))
            .max_capacity(10000)
            .build();

        let local_upstreams: HashMap<String, UpstreamInfoInternal> = config
            .local_upstreams
            .iter()
            .map(|(id, upstream)| {
                let full_upstream_id = config.make_mesh_upstream_id(id);
                let peered_wafs: HashSet<String> = upstream
                    .peered_wafs
                    .iter()
                    .filter(|p| p.allowed)
                    .map(|p| p.node_id.clone())
                    .collect();
                (
                    full_upstream_id.clone(),
                    UpstreamInfoInternal {
                        upstream_id: full_upstream_id,
                        upstream_url: upstream.upstream_url.clone(),
                        geo: upstream.geo.clone(),
                        is_local: true,
                        owner_node_id: node_id.clone(),
                        last_updated: Instant::now(),
                        peered_wafs,
                        waf_policy: upstream.waf_policy.clone(),
                        protocol: upstream.protocol,
                        priority_tier: upstream.priority_tier,
                    },
                )
            })
            .collect();

        let mut global_nodes = HashSet::new();
        if role.is_global() {
            global_nodes.insert(node_id.clone());
        }

        Self {
            config,
            node_id,
            router_id: router_id.clone(),
            role,
            peer_store: ShardedPeerStore::new(),
            local_upstreams: RwLock::new(local_upstreams),
            route_cache,
            global_nodes: RwLock::new(global_nodes),
            pending_queries: RwLock::new(HashMap::new()),
            cache_metrics: RwLock::new(CacheMetrics::default()),
            route_usage: RwLock::new(RouteUsageTracker::default()),
            topology_version: RwLock::new(0),
            upstream_versions: RwLock::new(HashMap::new()),
            blocked_upstreams: RwLock::new(HashMap::new()),
            degraded_mode: AtomicBool::new(false),
            peer_scores_compat: RwLock::new(HashMap::new()),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn router_id(&self) -> &str {
        &self.router_id
    }

    pub fn role(&self) -> MeshNodeRole {
        self.role
    }

    pub fn is_global(&self) -> bool {
        self.role.is_global()
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded_mode.load(Ordering::Relaxed)
    }

    pub fn set_degraded(&self, degraded: bool) {
        self.degraded_mode.store(degraded, Ordering::Relaxed);
        if degraded {
            tracing::warn!("Mesh topology entering degraded mode - global nodes unavailable");
        } else {
            tracing::info!("Mesh topology exiting degraded mode - global nodes available");
        }
    }

    pub async fn record_bandwidth(
        &self,
        upstream_id: &str,
        bytes_sent: u64,
        bytes_received: u64,
        request_count: u64,
    ) {
        self.peer_store.upsert_bandwidth(upstream_id, |stats| {
            stats.bytes_sent += bytes_sent;
            stats.bytes_received += bytes_received;
            stats.request_count += request_count;
            stats.last_updated = Instant::now();
        });
    }

    pub async fn get_bandwidth_stats(&self, upstream_id: &str) -> Option<BandwidthStats> {
        self.peer_store.get_bandwidth_stats(upstream_id)
    }

    pub async fn reset_bandwidth_stats(&self, upstream_id: &str) {
        self.peer_store.update_bandwidth(upstream_id, |stats| {
            *stats = BandwidthStats::default();
            stats.last_updated = Instant::now();
        });
    }

    pub async fn get_all_bandwidth_stats(&self) -> Vec<(String, BandwidthStats)> {
        let mut result = Vec::new();
        for shard in &self.peer_store.shards {
            let guard = shard.read();
            for (k, v) in &guard.bandwidth_trackers {
                result.push((k.clone(), v.clone()));
            }
        }
        result
    }

    pub async fn get_topology_version(&self) -> u64 {
        *self.topology_version.read().await
    }

    async fn increment_version(&self) -> u64 {
        let mut version = self.topology_version.write().await;
        *version += 1;
        *version
    }

    pub async fn get_peer_version(&self, node_id: &str) -> u64 {
        self.peer_store.get_peer_version(node_id)
    }

    pub async fn get_upstream_version(&self, upstream_id: &str) -> u64 {
        *self
            .upstream_versions
            .read()
            .await
            .get(upstream_id)
            .unwrap_or(&0)
    }

    pub async fn get_topology_delta(&self, from_version: u64) -> TopologyDelta {
        let current_version = self.get_topology_version().await;

        if from_version == 0 || current_version - from_version > 100 {
            return TopologyDelta::FullSync(TopologyFullSync {
                peers: self.get_all_peers().await,
                upstreams: self.get_upstream_owners().await,
                version: current_version,
            });
        }

        let local_upstreams = self.local_upstreams.read().await;

        let mut added_peers = Vec::new();
        let mut updated_peers = Vec::new();
        let mut removed_peers = Vec::new();

        let peer_versions = self.peer_store.collect_all_peer_versions();

        for shard in &self.peer_store.shards {
            let guard = shard.read();
            for (node_id, peer) in &guard.peers {
                let peer_ver = peer_versions.get(node_id).copied().unwrap_or(0);
                if peer_ver > from_version {
                    if from_version == 0 {
                        added_peers.push(peer.clone());
                    } else {
                        updated_peers.push(peer.clone());
                    }
                }
            }
        }

        let upstream_versions = self.upstream_versions.read().await;
        let mut added_upstreams = HashMap::new();

        for (upstream_id, info) in local_upstreams.iter() {
            let upstream_ver = upstream_versions.get(upstream_id).copied().unwrap_or(0);
            if upstream_ver > from_version {
                added_upstreams.insert(
                    upstream_id.clone(),
                    UpstreamOwner {
                        owner_node_id: info.owner_node_id.clone(),
                        peered_wafs: info.peered_wafs.iter().cloned().collect(),
                    },
                );
            }
        }

        TopologyDelta::Incremental(TopologyIncrementalDelta {
            added_peers,
            updated_peers,
            removed_peers,
            added_upstreams,
            removed_upstreams: Vec::new(),
            version: current_version,
        })
    }

    pub async fn apply_topology_delta(&self, delta: TopologyDelta) {
        match delta {
            TopologyDelta::FullSync(sync) => {
                self.peer_store.clear();
                let current_version = self.increment_version().await;

                let mut versions = HashMap::new();
                for peer in sync.peers {
                    let node_id = peer.node_id.clone();
                    versions.insert(node_id.clone(), current_version);
                    self.peer_store.upsert_peer(peer);
                }
                self.peer_store.set_all_peer_versions(versions);

                for (upstream_id, _owner) in sync.upstreams {
                    let mut uv = self.upstream_versions.write().await;
                    uv.insert(upstream_id, current_version);
                }
            }
            TopologyDelta::Incremental(delta) => {
                let current_version = self.increment_version().await;

                for peer in delta.added_peers {
                    self.peer_store
                        .set_peer_version(&peer.node_id, current_version);
                }

                for (upstream_id, _owner) in delta.added_upstreams {
                    let mut uv = self.upstream_versions.write().await;
                    uv.insert(upstream_id, current_version);
                }

                for upstream_id in delta.removed_upstreams {
                    let mut uv = self.upstream_versions.write().await;
                    uv.remove(&upstream_id);
                }
            }
        }
    }

    pub async fn get_all_peers(&self) -> Vec<PeerState> {
        self.peer_store.collect_all_peers()
    }

    pub async fn get_all_connected_peers(&self) -> Vec<PeerState> {
        let mut result = Vec::new();
        self.peer_store.for_each_peer(|_, peer| {
            if peer.status == PeerStatus::Healthy {
                result.push(peer.clone());
            }
        });
        result
    }

    pub async fn get_random_peers(&self, count: usize, exclude: Option<&str>) -> Vec<PeerState> {
        let eligible: Vec<PeerState> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|_, peer| {
                if peer.status == PeerStatus::Healthy {
                    if exclude.map(|e| peer.node_id.as_str() != e).unwrap_or(true) {
                        result.push(peer.clone());
                    }
                }
            });
            result
        };

        let count = count.min(eligible.len());
        if count == 0 {
            return vec![];
        }

        use rand::Rng;
        let mut rng = rand::rng();
        let mut reservoir: Vec<PeerState> = Vec::with_capacity(count);
        for (i, peer) in eligible.iter().enumerate() {
            if i < count {
                reservoir.push(peer.clone());
            } else {
                let j = rng.random_range(0..=i);
                if j < count {
                    reservoir[j] = peer.clone();
                }
            }
        }
        reservoir
    }

    pub async fn get_peers_by_latency(
        &self,
        count: usize,
        exclude: Option<&str>,
    ) -> Vec<PeerState> {
        let mut eligible: Vec<PeerState> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|_, peer| {
                if peer.status == PeerStatus::Healthy
                    && peer.latency_ms.is_some()
                    && exclude.map(|e| peer.node_id.as_str() != e).unwrap_or(true)
                {
                    result.push(peer.clone());
                }
            });
            result
        };

        eligible.sort_by(|a, b| {
            let lat_a = a.latency_ms.unwrap_or(u32::MAX);
            let lat_b = b.latency_ms.unwrap_or(u32::MAX);
            lat_a.cmp(&lat_b)
        });

        eligible.into_iter().take(count).collect()
    }

    pub async fn get_peers_by_reputation(
        &self,
        count: usize,
        exclude: Option<&str>,
    ) -> Vec<PeerState> {
        let mut eligible: Vec<PeerState> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|_, peer| {
                if peer.status == PeerStatus::Healthy
                    && exclude.map(|e| peer.node_id.as_str() != e).unwrap_or(true)
                {
                    result.push(peer.clone());
                }
            });
            result
        };

        eligible.sort_by(|a, b| {
            let rep_a = a.audit_reputation();
            let rep_b = b.audit_reputation();
            rep_b
                .partial_cmp(&rep_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        eligible.into_iter().take(count).collect()
    }

    pub async fn get_peers_by_geo(
        &self,
        count: usize,
        target_geo: &str,
        exclude: Option<&str>,
    ) -> Vec<PeerState> {
        let mut eligible: Vec<(PeerState, f64)> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|_, peer| {
                if peer.status == PeerStatus::Healthy
                    && peer.geo.is_some()
                    && exclude.map(|e| peer.node_id.as_str() != e).unwrap_or(true)
                {
                    let score =
                        Self::calculate_geo_score(peer.geo.as_deref().unwrap_or(""), target_geo);
                    result.push((peer.clone(), score));
                }
            });
            result
        };

        eligible.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        eligible.into_iter().take(count).map(|(p, _)| p).collect()
    }

    fn calculate_geo_score(node_geo: &str, target_geo: &str) -> f64 {
        let mut score = 0.0;

        let node_parts: Vec<&str> = node_geo.split(',').collect();
        let target_parts: Vec<&str> = target_geo.split(',').collect();

        if let Some(node_country) = node_parts.first() {
            if let Some(target_country) = target_parts.first() {
                if node_country.eq_ignore_ascii_case(target_country) {
                    score += 100.0;
                }
            }
        }

        if node_parts.len() > 1 && target_parts.len() > 1 {
            if let Some(node_region) = node_parts.get(1) {
                if let Some(target_region) = target_parts.get(1) {
                    if node_region.eq_ignore_ascii_case(target_region) {
                        score += 50.0;
                    }
                }
            }
        }

        if node_geo.eq_ignore_ascii_case(target_geo) {
            score += 25.0;
        }

        score
    }

    pub async fn get_peers_hybrid(
        &self,
        count: usize,
        exclude: Option<&str>,
        weights: &PeerSelectionWeights,
    ) -> Vec<PeerState> {
        let eligible: Vec<PeerState> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|_, peer| {
                if peer.status == PeerStatus::Healthy
                    && exclude.map(|e| peer.node_id.as_str() != e).unwrap_or(true)
                {
                    result.push(peer.clone());
                }
            });
            result
        };

        if eligible.is_empty() {
            return Vec::new();
        }

        let mut scored: Vec<(PeerState, f64)> = eligible
            .into_iter()
            .map(|p| {
                let score = Self::calculate_hybrid_score(&p, weights);
                (p, score)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored.into_iter().take(count).map(|(p, _)| p).collect()
    }

    fn calculate_hybrid_score(peer: &PeerState, weights: &PeerSelectionWeights) -> f64 {
        let mut score = 0.0;

        if weights.random > 0.0 {
            let random_component: f64 = rand::random();
            score += weights.random * random_component * 100.0;
        }

        if weights.latency > 0.0 {
            if let Some(latency_ms) = peer.latency_ms {
                let latency = latency_ms as f64;
                let latency_score = 100.0 / (1.0 + latency / 10.0);
                score += weights.latency * latency_score;
            }
        }

        if weights.reputation > 0.0 {
            let rep = peer.audit_reputation();
            score += weights.reputation * rep * 100.0;
        }

        if weights.role > 0.0 {
            let role_score = if peer.is_global { 50.0 } else { 25.0 };
            score += weights.role * role_score;
        }

        score
    }

    pub async fn add_peer(&self, peer_info: MeshPeerInfo, status: PeerStatus) {
        let existing = self.peer_store.get_peer(&peer_info.node_id);
        let existing_first_seen = existing.as_ref().map(|p| p.first_seen);
        let existing_previous_reputation = existing.as_ref().and_then(|p| p.previous_reputation);
        let existing_geo = existing.as_ref().and_then(|p| p.geo.clone());
        let existing_trusted = existing.as_ref().map(|p| p.is_trusted).unwrap_or(false);
        let existing_audit_successes = existing.as_ref().map(|p| p.audit_successes).unwrap_or(0);
        let existing_audit_failures = existing.as_ref().map(|p| p.audit_failures).unwrap_or(0);

        let node_id = peer_info.node_id.clone();
        let peer_state = PeerState {
            node_id: node_id.clone(),
            address: peer_info.address.clone(),
            role: peer_info.role,
            status,
            capabilities: peer_info.capabilities,
            upstreams: peer_info.upstreams.into_iter().collect(),
            latency_ms: peer_info.latency_ms,
            first_seen: existing_first_seen.unwrap_or_else(Instant::now),
            last_seen: Instant::now(),
            is_global: peer_info.is_global,
            is_trusted: peer_info.is_trusted || existing_trusted,
            connection_handle: None,
            geo: existing_geo,
            audit_successes: existing_audit_successes,
            audit_failures: existing_audit_failures,
            quic_port: peer_info.quic_port,
            wireguard_port: peer_info.wireguard_port,
            advertised_port: peer_info.advertised_port,
            previous_reputation: existing_previous_reputation,
        };

        if peer_state.is_global {
            let mut global = self.global_nodes.write().await;
            global.insert(node_id.clone());
        }

        self.peer_store.upsert_peer(peer_state);

        tracing::debug!("Added peer to topology");
    }

    pub async fn update_peer_status(&self, node_id: &str, status: PeerStatus) {
        self.peer_store.update_peer_status(node_id, status);
    }

    pub async fn update_peer_latency(&self, node_id: &str, latency_ms: u32) {
        self.peer_store.update_peer_latency(node_id, latency_ms);
    }

    pub async fn remove_peer(&self, node_id: &str) {
        if let Some(mut peer) = self.peer_store.remove_peer(node_id) {
            peer.save_reputation_before_disconnect();
            tracing::debug!("Removed peer {} from topology", node_id);
        }
    }

    pub async fn update_peer_audit_stats(&self, node_id: &str, successes: u64, failures: u64) {
        self.peer_store.update_peer(node_id, |peer| {
            peer.audit_successes = peer.audit_successes.saturating_add(successes);
            peer.audit_failures = peer.audit_failures.saturating_add(failures);
        });
    }

    pub async fn get_peer_audit_reputation(&self, node_id: &str) -> Option<f64> {
        self.peer_store
            .get_peer(node_id)
            .map(|p| p.audit_reputation())
    }

    pub async fn get_global_nodes(&self) -> Vec<String> {
        let global = self.global_nodes.read().await;
        global.iter().cloned().collect()
    }

    pub async fn get_global_nodes_as_peer_info(&self) -> Vec<MeshPeerInfo> {
        let global = self.global_nodes.read().await;

        global
            .iter()
            .filter_map(|id| {
                self.peer_store.get_peer(id).map(|p| MeshPeerInfo {
                    node_id: p.node_id.clone(),
                    address: p.address.clone(),
                    role: p.role,
                    capabilities: p.capabilities.clone(),
                    is_global: p.is_global,
                    latency_ms: p.latency_ms,
                    upstreams: p.upstreams.iter().cloned().collect(),
                    is_trusted: p.role.is_global(),
                    quic_port: p.quic_port,
                    wireguard_port: p.wireguard_port,
                    advertised_port: p.advertised_port,
                    dns_serving_healthy: false,
                })
            })
            .collect()
    }

    pub async fn get_closest_global_node(&self) -> Option<String> {
        let mut best: Option<(String, u32)> = None;
        self.peer_store.for_each_peer(|_, peer| {
            if peer.is_global && peer.is_healthy() {
                let latency = peer.latency_ms.unwrap_or(u32::MAX);
                if best.as_ref().map_or(true, |(_, l)| latency < *l) {
                    best = Some((peer.node_id.clone(), latency));
                }
            }
        });
        best.map(|(id, _)| id)
    }

    pub async fn get_peers_by_trust(&self, trusted: bool) -> Vec<PeerState> {
        let mut result = Vec::new();
        self.peer_store.for_each_peer(|_, peer| {
            if peer.is_trusted == trusted {
                result.push(peer.clone());
            }
        });
        result
    }

    pub async fn get_trusted_peers(&self) -> Vec<PeerState> {
        self.get_peers_by_trust(true).await
    }

    pub async fn get_peers_with_upstream(&self, upstream_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        self.peer_store.for_each_peer(|_, peer| {
            if peer.is_healthy() && peer.has_upstream(upstream_id) {
                result.push(peer.node_id.clone());
            }
        });
        result
    }

    pub async fn get_peer(&self, node_id: &str) -> Option<PeerState> {
        self.peer_store.get_peer(node_id)
    }

    pub async fn find_origin_by_mesh_id(&self, _mesh_id: &str) -> Option<String> {
        None
    }

    pub fn find_origin_by_site_sync(&self, site: &str) -> Option<String> {
        let upstreams = self.local_upstreams.blocking_read();

        for (upstream_id, info) in upstreams.iter() {
            if upstream_id == site && info.is_local {
                return Some(info.owner_node_id.clone());
            }
        }

        None
    }

    pub fn find_all_origins_for_site_sync(&self, site: &str) -> Vec<String> {
        let upstreams = self.local_upstreams.blocking_read();
        let mut origins = Vec::new();

        for (upstream_id, info) in upstreams.iter() {
            if upstream_id == site && info.is_local {
                origins.push(info.owner_node_id.clone());
            }
        }

        origins
    }

    pub async fn find_all_origins_for_site(&self, site: &str) -> Vec<String> {
        let upstreams = self.local_upstreams.read().await;
        let mut origins = Vec::new();

        for (upstream_id, info) in upstreams.iter() {
            if upstream_id == site && info.is_local {
                origins.push(info.owner_node_id.clone());
            }
        }

        origins
    }

    pub async fn get_upstream_for_peer(
        &self,
        upstream_id: &str,
        peer_node_id: &str,
    ) -> Option<UpstreamInfoInternal> {
        let upstreams = self.local_upstreams.read().await;
        let upstream = upstreams.get(upstream_id)?;

        if upstream.is_local && upstream.owner_node_id == self.node_id {
            return Some(upstream.clone());
        }

        if upstream.owner_node_id == peer_node_id {
            return Some(upstream.clone());
        }

        if upstream.peered_wafs.is_empty() || upstream.peered_wafs.contains(peer_node_id) {
            return Some(upstream.clone());
        }

        None
    }

    pub async fn get_best_peers_for_query(
        &self,
        upstream_id: &str,
        max_count: usize,
    ) -> Vec<String> {
        let mut candidates: Vec<PeerState> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|_, peer| {
                if peer.is_healthy()
                    && peer.has_upstream(upstream_id)
                    && peer.capabilities.can_route
                {
                    result.push(peer.clone());
                }
            });
            result
        };

        candidates.sort_by(|a, b| {
            let score_a = self
                .peer_store
                .get_peer_score(&a.node_id)
                .map(|s| s.total_score)
                .unwrap_or(0.5);
            let score_b = self
                .peer_store
                .get_peer_score(&b.node_id)
                .map(|s| s.total_score)
                .unwrap_or(0.5);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates
            .into_iter()
            .take(max_count)
            .map(|p| p.node_id.clone())
            .collect()
    }

    pub async fn get_best_peer_for_upstream(&self, upstream_id: &str) -> Option<String> {
        self.get_best_peers_for_query(upstream_id, 1)
            .await
            .into_iter()
            .next()
    }

    pub async fn get_cache_metrics(&self) -> (u64, u64, f64) {
        let metrics = self.cache_metrics.read().await;
        let total = metrics.hits + metrics.misses;
        let hit_rate = if total > 0 {
            metrics.hits as f64 / total as f64
        } else {
            0.0
        };
        (metrics.hits, metrics.misses, hit_rate)
    }

    pub async fn record_cache_hit(&self) {
        let mut metrics = self.cache_metrics.write().await;
        metrics.hits += 1;
    }

    pub async fn record_cache_miss(&self) {
        let mut metrics = self.cache_metrics.write().await;
        metrics.misses += 1;
    }

    pub async fn cache_route(
        &self,
        upstream_id: &str,
        provider_node_id: String,
        hops: u8,
        ttl: Duration,
    ) {
        let stability_score = self
            .calculate_route_stability_internal(upstream_id, &provider_node_id)
            .await;
        let adaptive_ttl = self.calculate_adaptive_ttl(ttl, stability_score);

        self.route_cache
            .insert(
                upstream_id.to_string(),
                CachedRoute {
                    provider_node_id,
                    hops,
                },
            )
            .await;
    }

    async fn calculate_route_stability_internal(&self, upstream_id: &str, provider: &str) -> f64 {
        let provider_str = provider.to_string();
        self.peer_store.update_route_stability(upstream_id, |rs| {
            if rs.provider_history.last().map(|p| &p.0) == Some(&provider_str) {
                rs.stability = (rs.stability + 0.1).min(1.0);
            } else {
                rs.stability = (rs.stability - 0.2).max(0.1);
                rs.provider_history
                    .push((provider_str.clone(), Instant::now()));
                if rs.provider_history.len() > 10 {
                    rs.provider_history.remove(0);
                }
            }
        });

        self.peer_store
            .get_route_stability(upstream_id)
            .map(|rs| rs.stability)
            .unwrap_or_else(|| {
                self.peer_store.upsert_route_stability(
                    upstream_id,
                    RouteStability {
                        upstream_id: upstream_id.to_string(),
                        provider_history: vec![(provider_str, Instant::now())],
                        stability: 0.8,
                    },
                    |_| {},
                );
                0.8
            })
    }

    fn calculate_adaptive_ttl(&self, base_ttl: Duration, stability: f64) -> Duration {
        let ttl_multiplier = 0.5 + (stability * 0.5);
        let adaptive_ttl_secs = (base_ttl.as_secs() as f64 * ttl_multiplier) as u64;
        Duration::from_secs(adaptive_ttl_secs.clamp(60, 7200))
    }

    pub async fn get_cached_route(&self, upstream_id: &str) -> Option<(String, u8)> {
        self.route_cache
            .get(upstream_id)
            .await
            .map(|route| (route.provider_node_id.clone(), route.hops))
    }

    pub async fn invalidate_cache(&self, upstream_id: &str) {
        self.route_cache.remove(upstream_id).await;
    }

    pub async fn cleanup_expired_queries(&self, timeout: Duration) {
        let mut pending = self.pending_queries.write().await;
        let now = Instant::now();
        pending.retain(|_, q| !q.is_expired(timeout));
    }

    pub async fn cleanup_expired_cache(&self) {
        self.route_cache.run_pending_tasks().await;
    }

    pub async fn add_pending_query(&self, query: crate::mesh::protocol::PendingQuery) {
        let mut pending = self.pending_queries.write().await;
        pending.insert(query.query_id.clone(), query);
    }

    pub fn can_forward_service(&self, service_id: &str) -> bool {
        let config = &self.config.routing;
        if config.allow_all_services {
            return true;
        }
        config.allowed_services.iter().any(|s| s == service_id)
    }

    pub async fn add_local_upstream(
        &self,
        upstream_id: String,
        upstream_url: String,
        geo: Option<String>,
    ) {
        let mut upstreams = self.local_upstreams.write().await;

        let existing = upstreams.get(&upstream_id).cloned();

        upstreams.insert(
            upstream_id.clone(),
            UpstreamInfoInternal {
                upstream_id,
                upstream_url,
                geo,
                is_local: true,
                owner_node_id: self.node_id.clone(),
                last_updated: Instant::now(),
                peered_wafs: existing
                    .as_ref()
                    .map(|e| e.peered_wafs.clone())
                    .unwrap_or_default(),
                waf_policy: existing.as_ref().and_then(|e| e.waf_policy.clone()),
                protocol: existing.as_ref().map(|e| e.protocol).unwrap_or_default(),
                priority_tier: existing.as_ref().map(|e| e.priority_tier).unwrap_or(0),
            },
        );
    }

    pub async fn remove_local_upstream(&self, upstream_id: &str) {
        let mut upstreams = self.local_upstreams.write().await;
        upstreams.remove(upstream_id);
    }

    pub async fn get_local_upstreams(&self) -> Vec<UpstreamInfo> {
        let upstreams = self.local_upstreams.read().await;
        upstreams
            .values()
            .map(|u| UpstreamInfo {
                upstream_id: u.upstream_id.clone(),
                upstream_url: None,
                geo: u.geo.clone(),
                is_local: u.is_local,
                owner_node_id: u.owner_node_id.clone(),
                peered_wafs: u.peered_wafs.iter().cloned().collect(),
                url_hash: String::new(),
                waf_policy: u.waf_policy.clone(),
                protocol: u.protocol,
            })
            .collect()
    }

    pub async fn get_upstream_info(&self, upstream_id: &str) -> Option<UpstreamInfoInternal> {
        let upstreams = self.local_upstreams.read().await;
        upstreams.get(upstream_id).cloned()
    }

    pub async fn has_local_upstream(&self, upstream_id: &str) -> bool {
        let upstreams = self.local_upstreams.read().await;
        upstreams.contains_key(upstream_id)
    }

    pub async fn block_upstream(
        &self,
        mesh_identifier: &str,
        service_id: &str,
        blocked_until: Instant,
        reason: &str,
        origin_node_id: &str,
    ) {
        let full_id = format!("{}.{}", mesh_identifier, service_id);
        let mut blocked = self.blocked_upstreams.write().await;
        blocked.insert(
            full_id.clone(),
            BlockedUpstream {
                mesh_identifier: full_id,
                service_id: service_id.to_string(),
                blocked_until,
                reason: reason.to_string(),
                origin_node_id: origin_node_id.to_string(),
            },
        );
    }

    pub async fn is_upstream_blocked(&self, full_upstream_id: &str) -> bool {
        let blocked = self.blocked_upstreams.read().await;
        if let Some(block) = blocked.get(full_upstream_id) {
            if block.blocked_until > Instant::now() {
                return true;
            }
        }
        false
    }

    pub async fn get_blocked_until(&self, full_upstream_id: &str) -> Option<Instant> {
        let blocked = self.blocked_upstreams.read().await;
        blocked
            .get(full_upstream_id)
            .map(|b| b.blocked_until)
            .filter(|&t| t > Instant::now())
    }

    pub async fn cleanup_expired_blocks(&self) {
        let now = Instant::now();
        let mut blocked = self.blocked_upstreams.write().await;
        blocked.retain(|_, v| v.blocked_until > now);
    }

    pub async fn get_upstream_owners(&self) -> HashMap<String, UpstreamOwner> {
        let upstreams = self.local_upstreams.read().await;
        let mut owners = HashMap::new();

        for (id, info) in upstreams.iter() {
            owners.insert(
                id.clone(),
                UpstreamOwner {
                    owner_node_id: info.owner_node_id.clone(),
                    peered_wafs: info.peered_wafs.iter().cloned().collect(),
                },
            );
        }

        owners
    }

    pub async fn update_peer_latency_for_score(&self, node_id: &str, latency_ms: u32) {
        self.peer_store.record_latency(node_id, latency_ms);
    }

    pub async fn calculate_peer_score(&self, node_id: &str) -> PeerScore {
        let mut score = self
            .peer_store
            .get_peer_score(node_id)
            .unwrap_or_else(|| PeerScore {
                node_id: node_id.to_string(),
                ..Default::default()
            });

        if let Some(history) = self.peer_store.get_latency_history(node_id) {
            let recent: Vec<_> = history.iter().rev().take(10).collect();
            if !recent.is_empty() {
                let avg_latency: u64 =
                    recent.iter().map(|(_, l)| *l as u64).sum::<u64>() / recent.len().max(1) as u64;
                score.latency_score = (1.0_f64 - (avg_latency as f64 / 1000.0).min(1.0)).max(0.0);
            }
        }

        let failures = self.peer_store.get_connection_failures(node_id);
        let successes = self.peer_store.get_connection_successes(node_id);
        let total = failures + successes;
        if total > 0 {
            score.stability_score = (successes as f64 / total as f64).max(0.1);
        }

        score.calculate_total(&self.config.connection.connection_score_weights);

        let score_clone = score.clone();
        self.peer_store
            .upsert_peer_score(node_id, score_clone, |s| {
                *s = score.clone();
            });

        score
    }

    pub async fn record_connection_success(&self, node_id: &str) {
        self.peer_store.record_connection_success(node_id);
    }

    pub async fn record_connection_failure(&self, node_id: &str) {
        self.peer_store.record_connection_failure(node_id);
    }

    pub async fn record_route_usage(&self, upstream_id: String, bytes: u64) {
        let mut usage = self.route_usage.write().await;
        usage.record_usage(upstream_id, bytes);
    }

    pub async fn get_scored_peers(&self) -> Vec<(String, PeerScore)> {
        let mut scored = Vec::new();
        let weights = &self.config.connection.connection_score_weights;

        for shard in &self.peer_store.shards {
            let guard = shard.read();
            for (node_id, peer) in &guard.peers {
                let mut score =
                    guard
                        .peer_scores
                        .get(node_id)
                        .cloned()
                        .unwrap_or_else(|| PeerScore {
                            node_id: node_id.clone(),
                            ..Default::default()
                        });

                if let Some(history) = guard.latency_history.get(node_id) {
                    let recent: Vec<_> = history.iter().rev().take(10).collect();
                    if !recent.is_empty() {
                        let avg_latency: u64 = recent.iter().map(|(_, l)| *l as u64).sum::<u64>()
                            / recent.len().max(1) as u64;
                        score.latency_score =
                            (1.0_f64 - (avg_latency as f64 / 1000.0).min(1.0)).max(0.0);
                    }
                }

                let failures = guard.connection_failures.get(node_id).copied().unwrap_or(0);
                let successes = guard
                    .connection_successes
                    .get(node_id)
                    .copied()
                    .unwrap_or(0);
                let total = failures + successes;
                if total > 0 {
                    score.stability_score = (successes as f64 / total as f64).max(0.1);
                }

                score.calculate_total(weights);
                scored.push((node_id.clone(), score));
            }
        }

        scored.sort_by(|a, b| {
            b.1.total_score
                .partial_cmp(&a.1.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored
    }

    pub async fn get_top_peers_by_score(&self, limit: usize) -> Vec<String> {
        let scored = self.get_scored_peers().await;
        scored.into_iter().take(limit).map(|(id, _)| id).collect()
    }

    pub async fn get_frequently_used_upstreams(&self, limit: usize) -> Vec<String> {
        let usage = self.route_usage.read().await;
        usage.get_popular_upstreams(limit)
    }

    pub async fn get_prioritized_connection_targets(&self) -> Vec<(String, Priority)> {
        let mut targets = Vec::new();

        let global_nodes = self.global_nodes.read().await.clone();
        let peer_scores_map = self.peer_store.collect_all_peer_scores();
        let peers = self.peer_store.collect_all_peers();
        let upstreams = {
            let route_usage = self.route_usage.read().await;
            route_usage.get_popular_upstreams(10)
        };

        for node_id in &global_nodes {
            if let Some(score) = peer_scores_map.get(node_id) {
                targets.push((node_id.clone(), Priority::Global(score.total_score)));
            } else {
                targets.push((node_id.clone(), Priority::Global(0.5)));
            }
        }

        for upstream_id in upstreams {
            for peer_state in peers
                .iter()
                .filter(|p| p.is_healthy() && p.has_upstream(&upstream_id))
            {
                let provider = &peer_state.node_id;
                if !global_nodes.contains(provider) && !targets.iter().any(|(id, _)| id == provider)
                {
                    let score = peer_scores_map
                        .get(provider)
                        .map(|s| s.total_score)
                        .unwrap_or(0.5);
                    targets.push((provider.clone(), Priority::UpstreamProvider(score)));
                }
            }
        }

        let edge_peers = {
            let weights = &self.config.connection.connection_score_weights;
            let mut scored: Vec<(String, f64)> = peers
                .iter()
                .map(|peer| {
                    let node_id = &peer.node_id;
                    let mut score =
                        peer_scores_map
                            .get(node_id)
                            .cloned()
                            .unwrap_or_else(|| PeerScore {
                                node_id: node_id.clone(),
                                ..Default::default()
                            });

                    if let Some(history) = self.peer_store.get_latency_history(node_id) {
                        let recent: Vec<_> = history.iter().rev().take(10).collect();
                        if !recent.is_empty() {
                            let avg_latency: u64 =
                                recent.iter().map(|(_, l)| *l as u64).sum::<u64>()
                                    / recent.len().max(1) as u64;
                            score.latency_score =
                                (1.0_f64 - (avg_latency as f64 / 1000.0).min(1.0)).max(0.0);
                        }
                    }

                    let failures = self.peer_store.get_connection_failures(node_id);
                    let successes = self.peer_store.get_connection_successes(node_id);
                    let total = failures + successes;
                    if total > 0 {
                        score.stability_score = (successes as f64 / total as f64).max(0.1);
                    }

                    score.calculate_total(weights);
                    (node_id.clone(), score.total_score)
                })
                .collect();

            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scored
                .into_iter()
                .take(self.config.connection.reconnection_priority.frequent_routes)
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        };

        for node_id in edge_peers {
            if !global_nodes.contains(&node_id) && !targets.iter().any(|(id, _)| id == &node_id) {
                let score = peer_scores_map
                    .get(&node_id)
                    .map(|s| s.total_score)
                    .unwrap_or(0.5);
                targets.push((node_id, Priority::Edge(score)));
            }
        }

        targets.sort_by(|a, b| {
            let a_order = match &a.1 {
                Priority::Global(_) => 0,
                Priority::UpstreamProvider(_) => 1,
                Priority::Edge(_) => 2,
            };
            let b_order = match &b.1 {
                Priority::Global(_) => 0,
                Priority::UpstreamProvider(_) => 1,
                Priority::Edge(_) => 2,
            };
            a_order.cmp(&b_order)
        });

        targets
    }

    pub async fn add_seeded_nodes(&self, nodes: Vec<MeshPeerInfo>) {
        for node in nodes {
            if self.peer_store.get_peer(&node.node_id).is_none() {
                self.add_peer(node, PeerStatus::Connecting).await;
            }
        }
    }

    pub async fn get_seeded_global_nodes(&self) -> Vec<MeshPeerInfo> {
        let global = self.global_nodes.read().await;

        global
            .iter()
            .filter_map(|id| {
                self.peer_store.get_peer(id).map(|p| MeshPeerInfo {
                    node_id: p.node_id.clone(),
                    address: p.address.clone(),
                    role: p.role,
                    capabilities: p.capabilities.clone(),
                    is_global: p.is_global,
                    latency_ms: p.latency_ms,
                    upstreams: p.upstreams.iter().cloned().collect(),
                    is_trusted: p.role.is_global(),
                    quic_port: p.quic_port,
                    wireguard_port: p.wireguard_port,
                    advertised_port: p.advertised_port,
                    dns_serving_healthy: false,
                })
            })
            .collect()
    }

    pub async fn get_seeded_edge_nodes(&self) -> Vec<MeshPeerInfo> {
        let mut result = Vec::new();
        self.peer_store.for_each_peer(|_, peer| {
            if !peer.is_global {
                result.push(MeshPeerInfo {
                    node_id: peer.node_id.clone(),
                    address: peer.address.clone(),
                    role: peer.role,
                    capabilities: peer.capabilities.clone(),
                    is_global: peer.is_global,
                    latency_ms: peer.latency_ms,
                    upstreams: peer.upstreams.iter().cloned().collect(),
                    is_trusted: peer.role.is_global(),
                    quic_port: peer.quic_port,
                    wireguard_port: peer.wireguard_port,
                    advertised_port: peer.advertised_port,
                    dns_serving_healthy: false,
                });
            }
        });
        result
    }

    pub fn peer_scores(&self) -> &RwLock<HashMap<String, PeerScore>> {
        &self.peer_scores_compat
    }

    pub fn route_usage(&self) -> &RwLock<RouteUsageTracker> {
        &self.route_usage
    }

    pub fn config(&self) -> &Arc<MeshConfig> {
        &self.config
    }

    pub async fn save_peers_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let peer_data: Vec<PeerState> = self
            .peer_store
            .collect_all_peers()
            .into_iter()
            .filter(|p| p.status == PeerStatus::Healthy || p.status == PeerStatus::Unhealthy)
            .collect();

        let score_data = self.peer_store.collect_all_peer_scores();

        let persist_data = PeerPersistenceData {
            version: 1,
            peers: peer_data,
            peer_scores: score_data,
            saved_at: crate::mesh::safe_unix_timestamp(),
        };

        let json = serde_json::to_string_pretty(&persist_data)?;
        tokio::fs::write(path, json).await
    }

    pub async fn load_peers_from_file(&self, path: &str) -> Result<usize, std::io::Error> {
        if tokio::fs::metadata(path).await.is_err() {
            tracing::debug!("No peer cache file found at {}", path);
            return Ok(0);
        }

        let content = tokio::fs::read_to_string(path).await?;
        let persist_data: PeerPersistenceData = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let peer_count = persist_data.peers.len();

        for peer in persist_data.peers {
            if peer.status == PeerStatus::Healthy || peer.status == PeerStatus::Unhealthy {
                let mut loaded_peer = peer;
                loaded_peer.status = PeerStatus::Disconnected;
                self.peer_store.upsert_peer(loaded_peer);
            }
        }

        for (node_id, score) in persist_data.peer_scores {
            self.peer_store
                .upsert_peer_score(&node_id, score.clone(), |s| *s = score);
        }

        tracing::info!("Loaded {} peers from cache", peer_count);
        Ok(peer_count)
    }

    pub async fn is_isolated(&self) -> bool {
        self.get_healthy_peer_count().await == 0
    }

    pub async fn get_healthy_peer_count(&self) -> usize {
        let mut count = 0;
        self.peer_store.for_each_peer(|_, peer| {
            if peer.status == PeerStatus::Healthy {
                count += 1;
            }
        });
        count
    }

    pub async fn has_global_connectivity(&self) -> bool {
        let mut found = false;
        self.peer_store.for_each_peer(|_, peer| {
            if peer.status == PeerStatus::Healthy && peer.is_global {
                found = true;
            }
        });
        found
    }

    pub async fn check_network_partition(&self) -> Option<NetworkPartitionState> {
        let healthy_count = self.get_healthy_peer_count().await;
        let has_global = self.has_global_connectivity().await;

        if healthy_count == 0 {
            Some(NetworkPartitionState::Isolated {
                healthy_peers: 0,
                has_global_node: has_global,
            })
        } else if !has_global && !self.role.is_global() {
            Some(NetworkPartitionState::DisconnectedFromGlobal {
                healthy_peers: healthy_count,
            })
        } else if healthy_count < self.config.connection.min_peer_connections {
            Some(NetworkPartitionState::Degraded {
                healthy_peers: healthy_count,
                min_required: self.config.connection.min_peer_connections,
            })
        } else {
            None
        }
    }

    pub async fn prune_stale_peers(&self, stale_threshold_secs: u64) -> usize {
        let now = Instant::now();
        let threshold = Duration::from_secs(stale_threshold_secs);

        let stale_peers: Vec<String> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|id, state| {
                if now.duration_since(state.last_seen) > threshold {
                    result.push(id.clone());
                }
            });
            result
        };

        if stale_peers.is_empty() {
            return 0;
        }

        let mut global_nodes = self.global_nodes.write().await;
        for peer_id in &stale_peers {
            global_nodes.remove(peer_id);
            self.peer_store.remove_stale(peer_id);
        }

        stale_peers.len()
    }

    pub async fn cleanup_stale_metrics(&self, max_entries: usize) -> usize {
        let active_peer_ids: HashSet<String> = self
            .peer_store
            .collect_all_peer_keys()
            .into_iter()
            .collect();

        let removed = self.peer_store.cleanup_inactive(&active_peer_ids);

        {
            let mut route_usage = self.route_usage.write().await;
            route_usage.prune_inactive(&active_peer_ids, max_entries);
        }

        removed
    }
}

#[derive(Debug, Clone)]
pub enum NetworkPartitionState {
    Isolated {
        healthy_peers: usize,
        has_global_node: bool,
    },
    DisconnectedFromGlobal {
        healthy_peers: usize,
    },
    Degraded {
        healthy_peers: usize,
        min_required: usize,
    },
}

impl NetworkPartitionState {
    pub fn severity(&self) -> &str {
        match self {
            NetworkPartitionState::Isolated { .. } => "critical",
            NetworkPartitionState::DisconnectedFromGlobal { .. } => "warning",
            NetworkPartitionState::Degraded { .. } => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum Priority {
    Global(f64),
    UpstreamProvider(f64),
    Edge(f64),
}

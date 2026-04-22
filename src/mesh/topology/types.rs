use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use parking_lot::RwLock as ParkingLotRwLock;
use serde::{Deserialize, Serialize};

pub(crate) mod serde_secs {
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

pub const NUM_SHARDS: usize = 64;

#[inline]
fn shard_index(key: &str) -> usize {
    let mut hash: u64 = 5381;
    for byte in key.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    (hash as usize) % NUM_SHARDS
}

pub struct PeerShard {
    pub peers: HashMap<String, PeerState>,
    pub peer_scores: HashMap<String, PeerScore>,
    pub connection_failures: HashMap<String, u32>,
    pub connection_successes: HashMap<String, u32>,
    pub latency_history: HashMap<String, Vec<(Instant, u32)>>,
    pub peer_versions: HashMap<String, u64>,
    pub route_stability: HashMap<String, RouteStability>,
    pub bandwidth_trackers: HashMap<String, BandwidthStats>,
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

pub struct ShardedPeerStore {
    pub shards: Vec<ParkingLotRwLock<PeerShard>>,
}

impl Default for ShardedPeerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardedPeerStore {
    pub fn new() -> Self {
        let shards = (0..NUM_SHARDS)
            .map(|_| ParkingLotRwLock::new(PeerShard::new()))
            .collect();
        Self { shards }
    }

    #[inline]
    pub fn shard(&self, key: &str) -> &ParkingLotRwLock<PeerShard> {
        &self.shards[shard_index(key)]
    }

    pub fn get_peer(&self, node_id: &str) -> Option<PeerState> {
        self.shard(node_id).read().peers.get(node_id).cloned()
    }

    pub fn get_peer_score(&self, node_id: &str) -> Option<PeerScore> {
        self.shard(node_id).read().peer_scores.get(node_id).cloned()
    }

    pub fn upsert_peer(&self, peer: PeerState) {
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

    pub fn update_peer_status(&self, node_id: &str, status: PeerStatus) {
        let mut shard = self.shard(node_id).write();
        if let Some(peer) = shard.peers.get_mut(node_id) {
            peer.status = status;
            peer.last_seen = Instant::now();
        }
    }

    pub fn update_peer_latency(&self, node_id: &str, latency_ms: u32) {
        let mut shard = self.shard(node_id).write();
        if let Some(peer) = shard.peers.get_mut(node_id) {
            peer.latency_ms = Some(latency_ms);
        }
    }

    pub fn update_peer<F: FnOnce(&mut PeerState)>(&self, node_id: &str, f: F) {
        let mut shard = self.shard(node_id).write();
        if let Some(peer) = shard.peers.get_mut(node_id) {
            f(peer);
        }
    }

    pub fn remove_peer(&self, node_id: &str) -> Option<PeerState> {
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

    pub fn record_latency(&self, node_id: &str, latency_ms: u32) {
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

    pub fn record_connection_success(&self, node_id: &str) {
        let mut shard = self.shard(node_id).write();
        *shard
            .connection_successes
            .entry(node_id.to_string())
            .or_insert(0) += 1;
    }

    pub fn record_connection_failure(&self, node_id: &str) {
        let mut shard = self.shard(node_id).write();
        *shard
            .connection_failures
            .entry(node_id.to_string())
            .or_insert(0) += 1;
    }

    pub fn get_latency_history(&self, node_id: &str) -> Option<Vec<(Instant, u32)>> {
        self.shard(node_id)
            .read()
            .latency_history
            .get(node_id)
            .cloned()
    }

    pub fn get_connection_failures(&self, node_id: &str) -> u32 {
        self.shard(node_id)
            .read()
            .connection_failures
            .get(node_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_connection_successes(&self, node_id: &str) -> u32 {
        self.shard(node_id)
            .read()
            .connection_successes
            .get(node_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_peer_version(&self, node_id: &str) -> u64 {
        *self
            .shard(node_id)
            .read()
            .peer_versions
            .get(node_id)
            .unwrap_or(&0)
    }

    pub fn set_peer_version(&self, node_id: &str, version: u64) {
        let mut shard = self.shard(node_id).write();
        shard.peer_versions.insert(node_id.to_string(), version);
    }

    pub fn get_bandwidth_stats(&self, upstream_id: &str) -> Option<BandwidthStats> {
        self.shard(upstream_id)
            .read()
            .bandwidth_trackers
            .get(upstream_id)
            .cloned()
    }

    pub fn update_bandwidth<F: FnOnce(&mut BandwidthStats)>(&self, upstream_id: &str, f: F) {
        let mut shard = self.shard(upstream_id).write();
        if let Some(stats) = shard.bandwidth_trackers.get_mut(upstream_id) {
            f(stats);
        }
    }

    pub fn upsert_bandwidth<F: FnOnce(&mut BandwidthStats)>(&self, upstream_id: &str, f: F) {
        let mut shard = self.shard(upstream_id).write();
        let stats = shard
            .bandwidth_trackers
            .entry(upstream_id.to_string())
            .or_insert_with(BandwidthStats::default);
        f(stats);
    }

    pub fn get_route_stability(&self, upstream_id: &str) -> Option<RouteStability> {
        self.shard(upstream_id)
            .read()
            .route_stability
            .get(upstream_id)
            .cloned()
    }

    pub fn update_route_stability<F: FnOnce(&mut RouteStability)>(&self, upstream_id: &str, f: F) {
        let mut shard = self.shard(upstream_id).write();
        if let Some(rs) = shard.route_stability.get_mut(upstream_id) {
            f(rs);
        }
    }

    pub fn upsert_route_stability<F: FnOnce(&mut RouteStability)>(
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

    pub fn upsert_peer_score<F: FnOnce(&mut PeerScore)>(
        &self,
        node_id: &str,
        init: PeerScore,
        f: F,
    ) {
        let mut shard = self.shard(node_id).write();
        let score = shard.peer_scores.entry(node_id.to_string()).or_insert(init);
        f(score);
    }

    pub fn collect_all_peers(&self) -> Vec<PeerState> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.read().peers.values().cloned());
        }
        result
    }

    pub fn collect_all_peer_scores(&self) -> HashMap<String, PeerScore> {
        let mut result = HashMap::new();
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in &guard.peer_scores {
                result.insert(k.clone(), v.clone());
            }
        }
        result
    }

    pub fn collect_all_peer_keys(&self) -> Vec<String> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.read().peers.keys().cloned());
        }
        result
    }

    pub fn for_each_peer<F: FnMut(&String, &PeerState)>(&self, mut f: F) {
        for shard in &self.shards {
            let guard = shard.read();
            for (k, v) in &guard.peers {
                f(k, v);
            }
        }
    }

    #[allow(dead_code)]
    pub fn retain_peers<F: FnMut(&String, &PeerState) -> bool>(&self, mut f: F) {
        for shard in &self.shards {
            shard.write().peers.retain(|k, v| f(k, v));
        }
    }

    pub fn remove_stale(&self, node_id: &str) {
        let mut shard = self.shard(node_id).write();
        shard.peers.remove(node_id);
        shard.peer_scores.remove(node_id);
        shard.route_stability.remove(node_id);
    }

    pub fn cleanup_inactive(&self, active_ids: &HashSet<String>) -> usize {
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

    pub fn clear(&self) {
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

    pub fn set_all_peer_versions(&self, versions: HashMap<String, u64>) {
        for (node_id, version) in versions {
            self.set_peer_version(&node_id, version);
        }
    }

    pub fn collect_all_peer_versions(&self) -> HashMap<String, u64> {
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
    pub role: crate::mesh::config::MeshNodeRole,
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
    pub upstreams: HashMap<String, crate::mesh::protocol::UpstreamOwner>,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub struct TopologyIncrementalDelta {
    pub added_peers: Vec<PeerState>,
    pub updated_peers: Vec<PeerState>,
    pub removed_peers: Vec<String>,
    pub added_upstreams: HashMap<String, crate::mesh::protocol::UpstreamOwner>,
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

impl UpstreamInfoInternal {
    pub fn can_be_routed_by(&self, node_id: &str) -> bool {
        if self.peered_wafs.is_empty() {
            return true;
        }
        self.peered_wafs.contains(node_id)
    }
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

#[derive(Debug, Clone, Default)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug, Clone)]
pub struct CachedRoute {
    pub provider_node_id: String,
    pub hops: u8,
}

#[derive(Debug, Clone)]
pub struct RouteStability {
    #[allow(dead_code)]
    pub upstream_id: String,
    pub provider_history: Vec<(String, Instant)>,
    pub stability: f64,
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

impl BandwidthStats {
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    pub fn last_updated(&self) -> Instant {
        self.last_updated
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPersistenceData {
    pub version: u32,
    pub peers: Vec<PeerState>,
    pub peer_scores: HashMap<String, PeerScore>,
    pub saved_at: u64,
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
}

impl Default for RouteUsageTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

impl RouteUsageTracker {
    pub fn new(_window: Duration) -> Self {
        Self {
            usages: HashMap::new(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessRouteInfo {
    pub function_name: String,
    pub routes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub checksum: String,
    pub version: u64,
    pub memory_mb: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub priority: u32,
    pub provider_node_id: String,
    pub registered_at: i64,
}

impl ServerlessRouteInfo {
    pub fn new(
        function_name: String,
        routes: Vec<String>,
        allowed_methods: Vec<String>,
        checksum: String,
        version: u64,
        provider_node_id: String,
    ) -> Self {
        Self {
            function_name,
            routes,
            allowed_methods,
            checksum,
            version,
            memory_mb: None,
            timeout_seconds: None,
            priority: 100,
            provider_node_id,
            registered_at: chrono::Utc::now().timestamp(),
        }
    }

    pub fn matches_path(&self, path: &str) -> bool {
        for route in &self.routes {
            if route == "/" {
                return true;
            }
            if path == route {
                return true;
            }
            if route.ends_with("/*") {
                let prefix = &route[..route.len() - 2];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if route.ends_with('/') {
                if path.starts_with(route) || path == &route[..route.len() - 1] {
                    return true;
                }
            }
        }
        false
    }

    pub fn matches_method(&self, method: &str) -> bool {
        if self.allowed_methods.is_empty() {
            return true;
        }
        self.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }
}

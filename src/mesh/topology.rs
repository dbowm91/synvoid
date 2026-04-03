#![allow(unused_variables, unused_mut)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use lru_time_cache::LruCache;

use crate::mesh::config::{MeshConfig, MeshNodeRole};
use crate::mesh::protocol::{MeshPeerInfo, UpstreamInfo, UpstreamOwner};

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
    peers: RwLock<HashMap<String, PeerState>>,
    local_upstreams: RwLock<HashMap<String, UpstreamInfoInternal>>,
    route_cache: RwLock<LruCache<String, CachedRoute>>,
    global_nodes: RwLock<HashSet<String>>,
    pending_queries: RwLock<HashMap<String, crate::mesh::protocol::PendingQuery>>,
    cache_metrics: RwLock<CacheMetrics>,
    route_stability: RwLock<HashMap<String, RouteStability>>,
    peer_scores: RwLock<HashMap<String, PeerScore>>,
    route_usage: RwLock<RouteUsageTracker>,
    connection_failures: RwLock<HashMap<String, u32>>,
    connection_successes: RwLock<HashMap<String, u32>>,
    latency_history: RwLock<HashMap<String, Vec<(Instant, u32)>>>,
    topology_version: RwLock<u64>,
    peer_versions: RwLock<HashMap<String, u64>>,
    upstream_versions: RwLock<HashMap<String, u64>>,
    blocked_upstreams: RwLock<HashMap<String, BlockedUpstream>>,
    bandwidth_trackers: RwLock<HashMap<String, BandwidthStats>>,
    degraded_mode: AtomicBool,
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
    #[allow(dead_code)] // Reserved for configurable time window
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
}

impl MeshTopology {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        let node_id = config.node_id();
        let router_id = config.router_id();
        let role = config.role;

        let route_cache =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(3600), 10000);

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
            peers: RwLock::new(HashMap::new()),
            local_upstreams: RwLock::new(local_upstreams),
            route_cache: RwLock::new(route_cache),
            global_nodes: RwLock::new(global_nodes),
            pending_queries: RwLock::new(HashMap::new()),
            cache_metrics: RwLock::new(CacheMetrics::default()),
            route_stability: RwLock::new(HashMap::new()),
            peer_scores: RwLock::new(HashMap::new()),
            route_usage: RwLock::new(RouteUsageTracker::default()),
            connection_failures: RwLock::new(HashMap::new()),
            connection_successes: RwLock::new(HashMap::new()),
            latency_history: RwLock::new(HashMap::new()),
            topology_version: RwLock::new(0),
            peer_versions: RwLock::new(HashMap::new()),
            upstream_versions: RwLock::new(HashMap::new()),
            blocked_upstreams: RwLock::new(HashMap::new()),
            bandwidth_trackers: RwLock::new(HashMap::new()),
            degraded_mode: AtomicBool::new(false),
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
        let mut trackers = self.bandwidth_trackers.write().await;
        let stats = trackers
            .entry(upstream_id.to_string())
            .or_insert_with(BandwidthStats::default);
        stats.bytes_sent += bytes_sent;
        stats.bytes_received += bytes_received;
        stats.request_count += request_count;
        stats.last_updated = Instant::now();
    }

    pub async fn get_bandwidth_stats(&self, upstream_id: &str) -> Option<BandwidthStats> {
        let trackers = self.bandwidth_trackers.read().await;
        trackers.get(upstream_id).cloned()
    }

    pub async fn reset_bandwidth_stats(&self, upstream_id: &str) {
        let mut trackers = self.bandwidth_trackers.write().await;
        if let Some(stats) = trackers.get_mut(upstream_id) {
            *stats = BandwidthStats::default();
            stats.last_updated = Instant::now();
        }
    }

    pub async fn get_all_bandwidth_stats(&self) -> Vec<(String, BandwidthStats)> {
        let trackers = self.bandwidth_trackers.read().await;
        trackers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
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
        *self.peer_versions.read().await.get(node_id).unwrap_or(&0)
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

        let peers = self.peers.read().await;
        let local_upstreams = self.local_upstreams.read().await;

        let mut added_peers = Vec::new();
        let mut updated_peers = Vec::new();
        let mut removed_peers = Vec::new();

        let peer_versions = self.peer_versions.read().await;

        for (node_id, peer) in peers.iter() {
            let peer_ver = peer_versions.get(node_id).copied().unwrap_or(0);
            if peer_ver > from_version {
                if from_version == 0 {
                    added_peers.push(peer.clone());
                } else {
                    updated_peers.push(peer.clone());
                }
            }
        }

        drop(peer_versions);
        drop(peers);

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
                let mut peers = self.peers.write().await;
                let mut peer_versions = self.peer_versions.write().await;
                let mut upstream_versions = self.upstream_versions.write().await;

                peers.clear();
                peer_versions.clear();
                upstream_versions.clear();

                let current_version = self.increment_version().await;

                for peer in sync.peers {
                    let node_id = peer.node_id.clone();
                    peer_versions.insert(node_id.clone(), current_version);
                    peers.insert(node_id, peer);
                }

                for (upstream_id, _owner) in sync.upstreams {
                    upstream_versions.insert(upstream_id, current_version);
                }
            }
            TopologyDelta::Incremental(delta) => {
                let current_version = self.increment_version().await;
                let mut peers = self.peers.write().await;
                let mut peer_versions = self.peer_versions.write().await;
                let mut upstream_versions = self.upstream_versions.write().await;

                for peer in delta.added_peers {
                    peer_versions.insert(peer.node_id.clone(), current_version);
                }

                for (upstream_id, _owner) in delta.added_upstreams {
                    upstream_versions.insert(upstream_id, current_version);
                }

                for upstream_id in delta.removed_upstreams {
                    upstream_versions.remove(&upstream_id);
                }
            }
        }
    }

    pub async fn get_all_peers(&self) -> Vec<PeerState> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    pub async fn get_all_connected_peers(&self) -> Vec<PeerState> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .cloned()
            .collect()
    }

    pub async fn get_random_peers(&self, count: usize, exclude: Option<&str>) -> Vec<PeerState> {
        let peers = self.peers.read().await;
        let eligible: Vec<&PeerState> = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .filter(|p| exclude.map(|e| p.node_id.as_str() != e).unwrap_or(true))
            .collect();

        let count = count.min(eligible.len());
        if count == 0 {
            return vec![];
        }

        use rand::Rng;
        let mut rng = rand::rng();
        let mut reservoir: Vec<PeerState> = Vec::with_capacity(count);
        for (i, peer) in eligible.iter().enumerate() {
            if i < count {
                reservoir.push((*peer).clone());
            } else {
                let j = rng.random_range(0..=i);
                if j < count {
                    reservoir[j] = (*peer).clone();
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
        let peers = self.peers.read().await;
        let mut eligible: Vec<PeerState> = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .filter(|p| exclude.map(|e| p.node_id.as_str() != e).unwrap_or(true))
            .filter(|p| p.latency_ms.is_some())
            .cloned()
            .collect();

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
        let peers = self.peers.read().await;
        let mut eligible: Vec<PeerState> = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .filter(|p| exclude.map(|e| p.node_id.as_str() != e).unwrap_or(true))
            .cloned()
            .collect();

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
        let peers = self.peers.read().await;
        let mut eligible: Vec<(PeerState, f64)> = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .filter(|p| exclude.map(|e| p.node_id.as_str() != e).unwrap_or(true))
            .filter(|p| p.geo.is_some())
            .map(|p| {
                let score = Self::calculate_geo_score(p.geo.as_deref().unwrap_or(""), target_geo);
                (p.clone(), score)
            })
            .collect();

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
        let peers = self.peers.read().await;
        let eligible: Vec<PeerState> = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .filter(|p| exclude.map(|e| p.node_id.as_str() != e).unwrap_or(true))
            .cloned()
            .collect();

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
        let mut peers = self.peers.write().await;

        let existing = peers.get(&peer_info.node_id);
        let existing_first_seen = existing.map(|p| p.first_seen);
        let existing_previous_reputation = existing.and_then(|p| p.previous_reputation);
        let existing_geo = existing.and_then(|p| p.geo.clone());
        let existing_trusted = existing.map(|p| p.is_trusted).unwrap_or(false);
        let existing_audit_successes = existing.map(|p| p.audit_successes).unwrap_or(0);
        let existing_audit_failures = existing.map(|p| p.audit_failures).unwrap_or(0);

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

        peers.insert(node_id, peer_state);

        tracing::debug!("Added peer to topology");
    }

    pub async fn update_peer_status(&self, node_id: &str, status: PeerStatus) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.status = status;
            peer.last_seen = Instant::now();
        }
    }

    pub async fn update_peer_latency(&self, node_id: &str, latency_ms: u32) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.latency_ms = Some(latency_ms);
        }
    }

    pub async fn remove_peer(&self, node_id: &str) {
        let mut peers = self.peers.write().await;
        if let Some(mut peer) = peers.remove(node_id) {
            peer.save_reputation_before_disconnect();
            tracing::debug!("Removed peer {} from topology", node_id);
        }
    }

    pub async fn update_peer_audit_stats(&self, node_id: &str, successes: u64, failures: u64) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.audit_successes = peer.audit_successes.saturating_add(successes);
            peer.audit_failures = peer.audit_failures.saturating_add(failures);
        }
    }

    pub async fn get_peer_audit_reputation(&self, node_id: &str) -> Option<f64> {
        let peers = self.peers.read().await;
        peers.get(node_id).map(|p| p.audit_reputation())
    }

    pub async fn get_global_nodes(&self) -> Vec<String> {
        let global = self.global_nodes.read().await;
        global.iter().cloned().collect()
    }

    pub async fn get_global_nodes_as_peer_info(&self) -> Vec<MeshPeerInfo> {
        let peers = self.peers.read().await;
        let global = self.global_nodes.read().await;

        global
            .iter()
            .filter_map(|id| {
                peers.get(id).map(|p| MeshPeerInfo {
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
        let peers = self.peers.read().await;
        let globals: Vec<_> = peers
            .values()
            .filter(|p| p.is_global && p.is_healthy())
            .map(|p| (p.node_id.clone(), p.latency_ms.unwrap_or(u32::MAX)))
            .collect();

        globals
            .into_iter()
            .min_by_key(|(_, latency)| *latency)
            .map(|(id, _)| id)
    }

    pub async fn get_peers_by_trust(&self, trusted: bool) -> Vec<PeerState> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.is_trusted == trusted)
            .cloned()
            .collect()
    }

    pub async fn get_trusted_peers(&self) -> Vec<PeerState> {
        self.get_peers_by_trust(true).await
    }

    pub async fn get_peers_with_upstream(&self, upstream_id: &str) -> Vec<String> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.is_healthy() && p.has_upstream(upstream_id))
            .map(|p| p.node_id.clone())
            .collect()
    }

    pub async fn get_peer(&self, node_id: &str) -> Option<PeerState> {
        let peers = self.peers.read().await;
        peers.get(node_id).cloned()
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
        let peers = self.peers.read().await;
        let scores = self.peer_scores.read().await;

        let mut candidates: Vec<_> = peers
            .values()
            .filter(|p| p.is_healthy() && p.has_upstream(upstream_id))
            .filter(|p| p.capabilities.can_route)
            .collect();

        candidates.sort_by(|a, b| {
            let score_a = scores.get(&a.node_id).map(|s| s.total_score).unwrap_or(0.5);
            let score_b = scores.get(&b.node_id).map(|s| s.total_score).unwrap_or(0.5);
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

        let mut cache = self.route_cache.write().await;
        cache.insert(
            upstream_id.to_string(),
            CachedRoute {
                provider_node_id,
                hops,
            },
        );
    }

    async fn calculate_route_stability_internal(&self, upstream_id: &str, provider: &str) -> f64 {
        let mut route_stability = self.route_stability.write().await;

        if let Some(existing) = route_stability.get_mut(upstream_id) {
            if existing.provider_history.last().map(|p| &p.0) == Some(&provider.to_string()) {
                existing.stability = (existing.stability + 0.1).min(1.0);
            } else {
                existing.stability = (existing.stability - 0.2).max(0.1);
                existing
                    .provider_history
                    .push((provider.to_string(), Instant::now()));
                if existing.provider_history.len() > 10 {
                    existing.provider_history.remove(0);
                }
            }
            existing.stability
        } else {
            route_stability.insert(
                upstream_id.to_string(),
                RouteStability {
                    upstream_id: upstream_id.to_string(),
                    provider_history: vec![(provider.to_string(), Instant::now())],
                    stability: 0.8,
                },
            );
            0.8
        }
    }

    fn calculate_adaptive_ttl(&self, base_ttl: Duration, stability: f64) -> Duration {
        let ttl_multiplier = 0.5 + (stability * 0.5);
        let adaptive_ttl_secs = (base_ttl.as_secs() as f64 * ttl_multiplier) as u64;
        Duration::from_secs(adaptive_ttl_secs.clamp(60, 7200))
    }

    pub async fn get_cached_route(&self, upstream_id: &str) -> Option<(String, u8)> {
        let mut cache = self.route_cache.write().await;
        let result = cache
            .get(upstream_id)
            .map(|route| (route.provider_node_id.clone(), route.hops));

        drop(cache);

        if result.is_some() {
            self.record_cache_hit().await;
        } else {
            self.record_cache_miss().await;
        }

        result
    }

    pub async fn invalidate_cache(&self, upstream_id: &str) {
        let mut cache = self.route_cache.write().await;
        cache.remove(upstream_id);
    }

    pub async fn add_pending_query(&self, query: crate::mesh::protocol::PendingQuery) {
        let mut pending = self.pending_queries.write().await;
        pending.insert(query.query_id.clone(), query);
    }

    pub async fn cleanup_expired_queries(&self, timeout: Duration) {
        let mut pending = self.pending_queries.write().await;
        let now = Instant::now();
        pending.retain(|_, q| !q.is_expired(timeout));
    }

    pub async fn cleanup_expired_cache(&self) {
        let cache = self.route_cache.write().await;
        let _ = cache.len();
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
        let mut history = self.latency_history.write().await;
        let entry = history.entry(node_id.to_string()).or_insert_with(Vec::new);
        entry.push((Instant::now(), latency_ms));
        if entry.len() > 20 {
            entry.remove(0);
        }
    }

    pub async fn calculate_peer_score(&self, node_id: &str) -> PeerScore {
        let mut score = self
            .peer_scores
            .read()
            .await
            .get(node_id)
            .cloned()
            .unwrap_or_else(|| PeerScore {
                node_id: node_id.to_string(),
                ..Default::default()
            });

        if let Some(history) = self.latency_history.read().await.get(node_id) {
            let recent: Vec<_> = history.iter().rev().take(10).collect();
            if !recent.is_empty() {
                let avg_latency: u64 =
                    recent.iter().map(|(_, l)| *l as u64).sum::<u64>() / recent.len().max(1) as u64;
                score.latency_score = (1.0_f64 - (avg_latency as f64 / 1000.0).min(1.0)).max(0.0);
            }
        }

        let failures = self
            .connection_failures
            .read()
            .await
            .get(node_id)
            .copied()
            .unwrap_or(0);
        let successes = self
            .connection_successes
            .read()
            .await
            .get(node_id)
            .copied()
            .unwrap_or(0);
        let total = failures + successes;
        if total > 0 {
            score.stability_score = (successes as f64 / total as f64).max(0.1);
        }

        score.calculate_total(&self.config.connection.connection_score_weights);

        let mut scores = self.peer_scores.write().await;
        scores.insert(node_id.to_string(), score.clone());

        score
    }

    pub async fn record_connection_success(&self, node_id: &str) {
        let mut successes = self.connection_successes.write().await;
        *successes.entry(node_id.to_string()).or_insert(0) += 1;
    }

    pub async fn record_connection_failure(&self, node_id: &str) {
        let mut failures = self.connection_failures.write().await;
        *failures.entry(node_id.to_string()).or_insert(0) += 1;
    }

    pub async fn record_route_usage(&self, upstream_id: String, bytes: u64) {
        let mut usage = self.route_usage.write().await;
        usage.record_usage(upstream_id, bytes);
    }

    pub async fn get_scored_peers(&self) -> Vec<(String, PeerScore)> {
        let peers = self.peers.read().await;
        let mut scored = Vec::new();

        for node_id in peers.keys() {
            let score = self.calculate_peer_score(node_id).await;
            scored.push((node_id.clone(), score));
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

        let global_nodes = self.global_nodes.read().await;
        for node_id in global_nodes.iter() {
            if let Some(score) = self.peer_scores.read().await.get(node_id) {
                targets.push((node_id.clone(), Priority::Global(score.total_score)));
            } else {
                targets.push((node_id.clone(), Priority::Global(0.5)));
            }
        }

        let upstreams = self.route_usage.read().await.get_popular_upstreams(10);
        for upstream_id in upstreams {
            let providers = self.get_peers_with_upstream(&upstream_id).await;
            for provider in providers {
                if !global_nodes.contains(&provider) {
                    let score = self
                        .peer_scores
                        .read()
                        .await
                        .get(&provider)
                        .map(|s| s.total_score)
                        .unwrap_or(0.5);
                    targets.push((provider, Priority::UpstreamProvider(score)));
                }
            }
        }

        let edge_peers = self
            .get_top_peers_by_score(self.config.connection.reconnection_priority.frequent_routes)
            .await;
        for node_id in edge_peers {
            if !global_nodes.contains(&node_id) && !targets.iter().any(|(id, _)| id == &node_id) {
                let score = self
                    .peer_scores
                    .read()
                    .await
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
            if !self.peers.read().await.contains_key(&node.node_id) {
                self.add_peer(node, PeerStatus::Connecting).await;
            }
        }
    }

    pub async fn get_seeded_global_nodes(&self) -> Vec<MeshPeerInfo> {
        let global = self.global_nodes.read().await;
        let peers = self.peers.read().await;

        global
            .iter()
            .filter_map(|id| {
                peers.get(id).map(|p| MeshPeerInfo {
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
        let peers = self.peers.read().await;

        peers
            .values()
            .filter(|p| !p.is_global)
            .map(|p| MeshPeerInfo {
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
            .collect()
    }

    pub fn peer_scores(&self) -> &RwLock<HashMap<String, PeerScore>> {
        &self.peer_scores
    }

    pub fn route_usage(&self) -> &RwLock<RouteUsageTracker> {
        &self.route_usage
    }

    pub fn config(&self) -> &Arc<MeshConfig> {
        &self.config
    }

    pub async fn save_peers_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let peers = self.peers.read().await;

        let peer_data: Vec<PeerState> = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy || p.status == PeerStatus::Unhealthy)
            .cloned()
            .collect();

        let scores = self.peer_scores.read().await;
        let score_data: HashMap<String, PeerScore> = scores.clone();

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

        {
            let mut peers = self.peers.write().await;
            for peer in persist_data.peers {
                if peer.status == PeerStatus::Healthy || peer.status == PeerStatus::Unhealthy {
                    let mut loaded_peer = peer;
                    loaded_peer.status = PeerStatus::Disconnected;
                    peers.insert(loaded_peer.node_id.clone(), loaded_peer);
                }
            }
        }

        {
            let mut scores = self.peer_scores.write().await;
            for (node_id, score) in persist_data.peer_scores {
                scores.insert(node_id, score);
            }
        }

        tracing::info!("Loaded {} peers from cache", peer_count);
        Ok(peer_count)
    }

    pub async fn is_isolated(&self) -> bool {
        let peers = self.peers.read().await;
        let healthy_count = peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .count();

        healthy_count == 0
    }

    pub async fn get_healthy_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.status == PeerStatus::Healthy)
            .count()
    }

    pub async fn has_global_connectivity(&self) -> bool {
        let peers = self.peers.read().await;
        peers
            .values()
            .any(|p| p.status == PeerStatus::Healthy && p.is_global)
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

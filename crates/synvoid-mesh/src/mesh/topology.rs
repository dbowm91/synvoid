#![allow(
    unused_variables,
    unused_mut,
    clippy::type_complexity,
    clippy::redundant_locals
)]

mod types;
pub use types::*;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock as ParkingLotRwLock;
use tokio::sync::RwLock;

use ed25519_dalek::Verifier;

use moka::future::Cache as MokaCache;

use crate::config::{MeshConfig, MeshNodeRole};
use crate::dht::{RecordStoreManager, DEFAULT_GET_BY_PREFIX_LIMIT};
use crate::lifecycle::StagedTopologySnapshot;
use crate::protocol::{MeshPeerInfo, UpstreamInfo, UpstreamOwner};

pub struct MeshTopology {
    config: Arc<MeshConfig>,
    node_id: String,
    router_id: String,
    role: MeshNodeRole,
    peer_store: ShardedPeerStore,
    local_upstreams: RwLock<HashMap<String, UpstreamInfoInternal>>,
    route_cache: MokaCache<String, CachedRoute>,
    verified_upstream_cache: MokaCache<String, Vec<crate::dht::VerifiedUpstream>>,
    global_nodes: RwLock<HashSet<String>>,
    pending_queries: RwLock<HashMap<String, crate::protocol::PendingQuery>>,
    cache_metrics: RwLock<CacheMetrics>,
    route_usage: RwLock<RouteUsageTracker>,
    topology_version: RwLock<u64>,
    upstream_versions: RwLock<HashMap<String, u64>>,
    blocked_upstreams: RwLock<HashMap<String, BlockedUpstream>>,
    degraded_mode: AtomicBool,
    peer_scores_compat: RwLock<HashMap<String, PeerScore>>,
    record_store: ParkingLotRwLock<Option<Arc<RecordStoreManager>>>,
    inflight_dht_queries:
        Arc<DashMap<String, Vec<tokio::sync::oneshot::Sender<Vec<crate::dht::VerifiedUpstream>>>>>,
}

impl MeshTopology {
    pub fn new(config: Arc<MeshConfig>) -> Self {
        let node_id = config.node_id();
        let router_id = config.router_id();
        let role = config.role;

        let route_cache = MokaCache::builder()
            .time_to_live(Duration::from_secs(3600))
            .max_capacity(100000)
            .weigher(|k: &String, v: &CachedRoute| (k.len() + v.provider_node_id.len()) as u32)
            .build();

        let verified_upstream_cache = MokaCache::builder()
            .time_to_live(Duration::from_secs(60))
            .max_capacity(50000)
            .build();

        let local_upstreams: HashMap<String, UpstreamInfoInternal> = config
            .local_upstreams
            .iter()
            .map(|(id, upstream)| {
                let peered_wafs: HashSet<String> = upstream
                    .peered_wafs
                    .iter()
                    .filter(|p| p.allowed)
                    .map(|p| p.node_id.clone())
                    .collect();
                (
                    id.clone(),
                    UpstreamInfoInternal {
                        upstream_id: id.clone(),
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
            verified_upstream_cache,
            global_nodes: RwLock::new(global_nodes),
            pending_queries: RwLock::new(HashMap::new()),
            cache_metrics: RwLock::new(CacheMetrics::default()),
            route_usage: RwLock::new(RouteUsageTracker::default()),
            topology_version: RwLock::new(0),
            upstream_versions: RwLock::new(HashMap::new()),
            blocked_upstreams: RwLock::new(HashMap::new()),
            degraded_mode: AtomicBool::new(false),
            peer_scores_compat: RwLock::new(HashMap::new()),
            record_store: ParkingLotRwLock::new(None),
            inflight_dht_queries: Arc::new(DashMap::new()),
        }
    }

    pub fn set_record_store(&self, record_store: Arc<RecordStoreManager>) {
        *self.record_store.write() = Some(record_store);
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

    pub async fn get_peer_ids(&self) -> Vec<String> {
        let mut peer_ids = Vec::new();
        self.peer_store.for_each_peer(|node_id, _| {
            peer_ids.push(node_id.to_string());
        });
        peer_ids
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
                if peer.status == PeerStatus::Healthy
                    && exclude.map(|e| peer.node_id.as_str() != e).unwrap_or(true)
                {
                    result.push(peer.clone());
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
        let existing_perf_successes = existing
            .as_ref()
            .map(|p| p.performance_audit_successes)
            .unwrap_or(0);
        let existing_perf_failures = existing
            .as_ref()
            .map(|p| p.performance_audit_failures)
            .unwrap_or(0);

        let node_id = peer_info.node_id.clone();
        let peer_state = PeerState {
            node_id: node_id.clone(),
            address: peer_info.address.clone(),
            role: peer_info.role,
            status,
            capabilities: peer_info.capabilities,
            upstreams: peer_info.upstreams.into_iter().collect(),
            latency_ms: peer_info.latency_ms,
            first_seen: existing_first_seen.unwrap_or_else(synvoid_utils::safe_unix_timestamp),
            last_seen: synvoid_utils::safe_unix_timestamp(),
            is_global: peer_info.is_global,
            is_trusted: peer_info.is_trusted || existing_trusted,
            connection_handle: None,
            geo: existing_geo,
            audit_successes: existing_audit_successes,
            audit_failures: existing_audit_failures,
            performance_audit_successes: existing_perf_successes,
            performance_audit_failures: existing_perf_failures,
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

    pub async fn get_average_latency_for_node(&self, node_id: &str) -> Option<u32> {
        self.peer_store.get_average_latency(node_id)
    }

    pub async fn get_global_nodes_with_avg_latency(&self) -> Vec<(String, u32)> {
        let mut result = Vec::new();
        let global = self.global_nodes.read().await;
        for node_id in global.iter() {
            if let Some(avg) = self.peer_store.get_average_latency(node_id) {
                result.push((node_id.clone(), avg));
            } else if let Some(peer) = self.peer_store.get_peer(node_id) {
                if let Some(latency) = peer.latency_ms {
                    result.push((node_id.clone(), latency));
                }
            }
        }
        result
    }

    pub async fn remove_peer(&self, node_id: &str) {
        {
            let mut global = self.global_nodes.write().await;
            global.remove(node_id);
        }
        if let Some(mut peer) = self.peer_store.remove_peer(node_id) {
            peer.save_reputation_before_disconnect();
            tracing::debug!("Removed peer {} from topology", node_id);
        }
    }

    /// Restore an exact `PeerState` (used by startup rollback to preserve
    /// audit counts, timestamps, and reputation).
    ///
    /// Bidirectionally updates `global_nodes`: inserts when `is_global` is
    /// true, removes when false. This ensures rollback corrects both
    /// primary topology state and secondary index membership.
    pub async fn restore_peer_state(&self, peer_state: PeerState) {
        let node_id = peer_state.node_id.clone();
        {
            let mut global = self.global_nodes.write().await;
            if peer_state.is_global {
                global.insert(node_id.clone());
            } else {
                global.remove(&node_id);
            }
        }
        self.peer_store.upsert_peer(peer_state);
        tracing::debug!("Restored peer state for {}", node_id);
    }

    /// Verify that the current topology entry for a peer matches a snapshot
    /// (Iteration 74, Phase 4).
    ///
    /// Used by rollback/recovery verification to prove exact logical restoration.
    /// Compares all primary `PeerState` fields (excluding `connection_handle`,
    /// which is non-restorable) and verifies `global_nodes` index membership
    /// matches the snapshot's `is_global` flag.
    ///
    /// Secondary per-peer metrics (scores, failures, successes, latency history,
    /// versions, route stability, bandwidth) are intentionally excluded — they
    /// are operational metrics that naturally repopulate per the snapshot
    /// boundary decision (Iteration 75, Phase 8).
    pub async fn topology_matches_snapshot(&self, snapshot: &StagedTopologySnapshot) -> bool {
        match self.get_peer(&snapshot.peer_state.node_id).await {
            None => false,
            Some(current) => {
                current.node_id == snapshot.peer_state.node_id
                    && current.address == snapshot.peer_state.address
                    && current.role == snapshot.peer_state.role
                    && current.status == snapshot.peer_state.status
                    && current.capabilities.can_route == snapshot.peer_state.capabilities.can_route
                    && current.capabilities.can_proxy == snapshot.peer_state.capabilities.can_proxy
                    && current.capabilities.can_serve_dns == snapshot.peer_state.capabilities.can_serve_dns
                    && current.capabilities.is_global == snapshot.peer_state.capabilities.is_global
                    && current.capabilities.waf_enabled == snapshot.peer_state.capabilities.waf_enabled
                    && current.capabilities.max_hops == snapshot.peer_state.capabilities.max_hops
                    && current.capabilities.supported_services == snapshot.peer_state.capabilities.supported_services
                    && current.capabilities.preferred_transport == snapshot.peer_state.capabilities.preferred_transport
                    && current.capabilities.supported_protocols == snapshot.peer_state.capabilities.supported_protocols
                    && current.upstreams == snapshot.peer_state.upstreams
                    && current.latency_ms == snapshot.peer_state.latency_ms
                    && current.first_seen == snapshot.peer_state.first_seen
                    && current.last_seen == snapshot.peer_state.last_seen
                    && current.is_global == snapshot.peer_state.is_global
                    && current.is_trusted == snapshot.peer_state.is_trusted
                    && current.geo == snapshot.peer_state.geo
                    && current.audit_successes == snapshot.peer_state.audit_successes
                    && current.audit_failures == snapshot.peer_state.audit_failures
                    && current.performance_audit_successes
                        == snapshot.peer_state.performance_audit_successes
                    && current.performance_audit_failures
                        == snapshot.peer_state.performance_audit_failures
                    && current.quic_port == snapshot.peer_state.quic_port
                    && current.wireguard_port == snapshot.peer_state.wireguard_port
                    && current.advertised_port == snapshot.peer_state.advertised_port
                    && current.previous_reputation == snapshot.peer_state.previous_reputation
                    // Verify global_nodes secondary index matches primary is_global
                    && self.global_nodes.read().await.contains(&snapshot.peer_state.node_id)
                        == snapshot.peer_state.is_global
            }
        }
    }

    /// Check that a peer is absent from the topology (Iteration 74, Phase 4).
    pub async fn peer_absent(&self, node_id: &str) -> bool {
        self.get_peer(node_id).await.is_none()
    }

    pub async fn update_peer_audit_stats(&self, node_id: &str, successes: u64, failures: u64) {
        self.peer_store.update_peer(node_id, |peer| {
            peer.audit_successes = peer.audit_successes.saturating_add(successes);
            peer.audit_failures = peer.audit_failures.saturating_add(failures);
        });
    }

    pub async fn update_peer_audit_stats_weighted(
        &self,
        node_id: &str,
        security_success: u64,
        security_failure: u64,
        performance_success: u64,
        performance_failure: u64,
    ) {
        self.peer_store.update_peer(node_id, |peer| {
            peer.audit_successes = peer.audit_successes.saturating_add(security_success);
            peer.audit_failures = peer.audit_failures.saturating_add(security_failure);
            peer.performance_audit_successes = peer
                .performance_audit_successes
                .saturating_add(performance_success);
            peer.performance_audit_failures = peer
                .performance_audit_failures
                .saturating_add(performance_failure);
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
                if best.as_ref().is_none_or(|(_, l)| latency < *l) {
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
        use std::collections::HashSet;

        let upstreams = self.local_upstreams.read().await;
        let mut origins: HashSet<String> = HashSet::new();

        for (upstream_id, info) in upstreams.iter() {
            if upstream_id == site && info.is_local {
                origins.insert(info.owner_node_id.clone());
            }
        }

        drop(upstreams);

        let verified = self.find_verified_upstreams_for_site(site).await;
        for vu in verified {
            origins.insert(vu.origin_node_id);
        }

        origins.into_iter().collect()
    }

    pub async fn find_verified_upstreams_for_site(
        &self,
        site: &str,
    ) -> Vec<crate::dht::VerifiedUpstream> {
        let site_key = site.to_string();
        let cached = self.verified_upstream_cache.get(&site_key).await;
        if let Some(results) = cached {
            let cache = self.verified_upstream_cache.clone();
            let record_store: Option<Arc<crate::dht::RecordStoreManager>> = {
                let rs = self.record_store.read();
                rs.clone()
            };
            let site_clone = site_key.clone();
            tokio::spawn(async move {
                let Some(rs) = record_store.as_ref() else {
                    return;
                };
                let records = rs.get_all_records();
                let mut new_results: Vec<crate::dht::VerifiedUpstream> = Vec::new();
                for record in records {
                    if record.key.starts_with("verified_upstream:") {
                        if let Ok(verified) =
                            serde_json::from_slice::<crate::dht::VerifiedUpstream>(&record.value)
                        {
                            if verified.upstream_id == site_clone
                                && !verified.global_node_signature.is_empty()
                            {
                                let sign_data = format!(
                                    "{}:{}:{}:{}",
                                    verified.upstream_id,
                                    verified.origin_node_id,
                                    verified.upstream_url,
                                    verified.registered_at
                                );

                                let key = format!("global_node_key:{}", verified.global_node_id);
                                if let Some(key_record) = rs.get_record(&key) {
                                    if let Ok(key_json) = serde_json::from_slice::<serde_json::Value>(
                                        &key_record.value,
                                    ) {
                                        if let Some(pubkey_str) = key_json
                                            .get("public_key")
                                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                                        {
                                            use base64::{
                                                engine::general_purpose::STANDARD, Engine,
                                            };
                                            let sig_bytes = verified.global_node_signature.clone();
                                            if let Ok(pubkey_bytes) = STANDARD.decode(pubkey_str) {
                                                if pubkey_bytes.len() == 32 && sig_bytes.len() == 64
                                                {
                                                    let mut pk_array = [0u8; 32];
                                                    pk_array.copy_from_slice(&pubkey_bytes);
                                                    let mut sig_array = [0u8; 64];
                                                    sig_array.copy_from_slice(&sig_bytes);

                                                    if let Ok(pk) =
                                                        ed25519_dalek::VerifyingKey::from_bytes(
                                                            &pk_array,
                                                        )
                                                    {
                                                        let sig =
                                                            ed25519_dalek::Signature::from_bytes(
                                                                &sig_array,
                                                            );
                                                        if pk
                                                            .verify(sign_data.as_bytes(), &sig)
                                                            .is_ok()
                                                        {
                                                            new_results.push(verified);
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }
                cache.insert(site_clone, new_results).await;
            });
            return results;
        }

        let is_store_available = {
            let guard = self.record_store.read();
            guard.is_some()
        };

        if !is_store_available {
            let site_key = site.to_string();
            self.verified_upstream_cache
                .insert(site_key, Vec::new())
                .await;
            return Vec::new();
        }

        let inflight = self.inflight_dht_queries.clone();
        let site_key = site.to_string();

        if let Some(mut waiters) = inflight.get_mut(&site_key) {
            let (fut_tx, fut_rx) = tokio::sync::oneshot::channel();
            waiters.push(fut_tx);
            return fut_rx.await.unwrap_or_default();
        }

        let (tx, _): (_, tokio::sync::oneshot::Receiver<_>) = tokio::sync::oneshot::channel();
        inflight.insert(site_key.clone(), vec![tx]);

        let records = {
            let guard = self.record_store.read();
            let result = guard.as_ref().unwrap().get_all_records();
            result
        };

        let mut results: Vec<crate::dht::VerifiedUpstream> = Vec::new();

        for record in records {
            if record.key.starts_with("verified_upstream:") {
                if let Ok(verified) =
                    serde_json::from_slice::<crate::dht::VerifiedUpstream>(&record.value)
                {
                    if verified.upstream_id == site {
                        if !verified.global_node_signature.is_empty() {
                            let sign_data = format!(
                                "{}:{}:{}:{}",
                                verified.upstream_id,
                                verified.origin_node_id,
                                verified.upstream_url,
                                verified.registered_at
                            );

                            let key = format!("global_node_key:{}", verified.global_node_id);
                            let guard = self.record_store.read();
                            if let Some(key_record) = guard.as_ref().unwrap().get_record(&key) {
                                if let Ok(key_json) =
                                    serde_json::from_slice::<serde_json::Value>(&key_record.value)
                                {
                                    if let Some(pubkey_str) = key_json
                                        .get("public_key")
                                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                                    {
                                        use base64::{engine::general_purpose::STANDARD, Engine};
                                        let sig_bytes = verified.global_node_signature.clone();
                                        if let Ok(pubkey_bytes) = STANDARD.decode(pubkey_str) {
                                            if pubkey_bytes.len() == 32 && sig_bytes.len() == 64 {
                                                let mut pk_array = [0u8; 32];
                                                pk_array.copy_from_slice(&pubkey_bytes);
                                                let mut sig_array = [0u8; 64];
                                                sig_array.copy_from_slice(&sig_bytes);

                                                if let Ok(pk) =
                                                    ed25519_dalek::VerifyingKey::from_bytes(
                                                        &pk_array,
                                                    )
                                                {
                                                    let sig = ed25519_dalek::Signature::from_bytes(
                                                        &sig_array,
                                                    );
                                                    if pk.verify(sign_data.as_bytes(), &sig).is_ok()
                                                    {
                                                        results.push(verified);
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            tracing::trace!(
                                "VerifiedUpstream signature verification failed for {} from global node {}",
                                site,
                                verified.global_node_id
                            );
                            continue;
                        }
                        results.push(verified);
                    }
                }
            }
        }

        self.verified_upstream_cache
            .insert(site_key.clone(), results.clone())
            .await;

        if let Some((_, waiters)) = inflight.remove(&site_key) {
            for waiter in waiters {
                let _ = waiter.send(results.clone());
            }
        }

        results
    }

    pub async fn invalidate_verified_upstream_cache(&self, site: &str) {
        self.verified_upstream_cache.invalidate(site).await;
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

    pub async fn add_pending_query(&self, query: crate::protocol::PendingQuery) {
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
            saved_at: synvoid_utils::safe_unix_timestamp(),
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
        let now = synvoid_utils::safe_unix_timestamp();

        let stale_peers: Vec<String> = {
            let mut result = Vec::new();
            self.peer_store.for_each_peer(|id, state| {
                if now.saturating_sub(state.last_seen) > stale_threshold_secs {
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

    /// Build descriptors for the topology maintenance background tasks.
    ///
    /// The returned specs do not spawn — the caller registers them with a
    /// `MeshTaskGroup` during transactional startup so they participate in
    /// rollback and unified shutdown.
    pub fn build_background_tasks(
        self: &Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<crate::lifecycle::MeshBackgroundTaskSpec> {
        let mut specs = Vec::new();

        let topology = self.clone();
        let mut shutdown1 = shutdown.clone();
        specs.push(crate::lifecycle::MeshBackgroundTaskSpec {
            name: "topology_stale_metrics",
            class: crate::lifecycle::MeshTaskClass::RestartableBackground,
            future: Box::pin(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                loop {
                    tokio::select! {
                        _ = shutdown1.changed() => {
                            tracing::debug!("Topology stale-metrics loop shutdown");
                            break;
                        }
                        _ = interval.tick() => {
                            topology.cleanup_stale_metrics(10000).await;
                        }
                    }
                }
                Ok(())
            }),
        });

        let topology = self.clone();
        specs.push(crate::lifecycle::MeshBackgroundTaskSpec {
            name: "topology_global_node_liveness",
            class: crate::lifecycle::MeshTaskClass::RestartableBackground,
            future: Box::pin(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            tracing::debug!("Topology global-node-liveness loop shutdown");
                            break;
                        }
                        _ = interval.tick() => {
                            topology.check_global_node_liveness().await;
                        }
                    }
                }
                Ok(())
            }),
        });

        specs
    }

    pub async fn check_global_node_liveness(&self) {
        let record_store = {
            let guard = self.record_store.read();
            guard.clone()
        };

        let Some(rs) = record_store.as_ref() else {
            return;
        };

        let now = synvoid_utils::safe_unix_timestamp();
        let heartbeat_ttl: u64 = 90;
        let mut live_count: u64 = 0;

        let heartbeat_records =
            rs.get_by_prefix("global_node_heartbeat:", DEFAULT_GET_BY_PREFIX_LIMIT);
        for record in heartbeat_records {
            if let Ok(heartbeat) =
                serde_json::from_slice::<crate::dht::GlobalNodeHeartbeat>(&record.value)
            {
                let age = now.saturating_sub(heartbeat.timestamp);
                if age <= heartbeat_ttl {
                    live_count += 1;
                }
            }
        }

        crate::stubs::metrics::record_global_node_liveness_count(live_count);

        let expected_global_nodes = self.config.connection.reconnection_priority.global_nodes;
        if expected_global_nodes > 0 && live_count < expected_global_nodes as u64 {
            let previously_live = crate::stubs::metrics::get_global_node_liveness_count();
            if previously_live > 0
                && previously_live >= expected_global_nodes as u64
                && live_count < previously_live
            {
                tracing::warn!(
                    "Global node quorum potentially lost: expected={} alive={} (previously {})",
                    expected_global_nodes,
                    live_count,
                    previously_live
                );
                crate::stubs::metrics::record_global_node_quorum_lost();
            }
        }
    }
}

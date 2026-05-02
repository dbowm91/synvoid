#![allow(unused_variables)]

use std::convert::Infallible;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use digest::Digest;
use http::header::HeaderValue;
use http::Response as HttpResponse;
use http_body::Body as HttpBody;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use moka::sync::Cache;
use parking_lot::RwLock;
use rand::distr::weighted::WeightedIndex;
use rand::distr::Distribution;
use rand::Rng;
use tokio::sync::RwLock as TokioRwLock;

static WHITELIST_REGEX_CACHE: LazyLock<DashMap<String, Option<regex::Regex>>> =
    LazyLock::new(DashMap::new);

fn get_cached_regex(pattern: &str) -> Option<regex::Regex> {
    WHITELIST_REGEX_CACHE
        .entry(pattern.to_string())
        .or_insert_with(|| regex::Regex::new(pattern).ok())
        .value()
        .as_ref()
        .cloned()
}

use crate::mesh::config::MeshConfig;
use crate::mesh::dht::RecordStoreManager;
use crate::mesh::organization::OrganizationManager;
use crate::mesh::protocol::{ProviderInfo, UpstreamProtocol, WafPolicy};
use crate::mesh::topology::MeshTopology;
use crate::mesh::transport::MeshTransport;
use crate::metrics::bandwidth::get_global_bandwidth_tracker_or_log;
use crate::proxy::headers::is_hop_by_hop_header_name;
use crate::proxy_cache::key::CacheKeyBuilder;
use crate::proxy_cache::ProxyCache;
use crate::proxy_cache::ProxyCacheSettings;

/// Default TTL for cached routing policies (1 hour)
const DEFAULT_POLICY_CACHE_TTL_SECS: u64 = 3600;
/// Cooldown period after provider failure before retry (10 seconds)
const FAILED_PROVIDER_COOLDOWN_SECS: u64 = 10;
/// Window for health metrics calculation (5 minutes)
const HEALTH_METRICS_WINDOW_SECS: u64 = 300;
/// Number of consecutive provider failures before broadcasting block to mesh
pub const BLOCK_BROADCAST_FAILURE_THRESHOLD: u32 = 5;
/// Duration to block an upstream when broadcasting to mesh (5 minutes).
/// This is a mesh-internal decision - when we see repeated failures from a provider,
/// we block locally and inform global peers. The actual ratelimit block duration
/// from the origin WAF is preserved when we receive blocks from other nodes.
const BLOCK_DURATION_SECS: u64 = 300;

#[derive(Clone)]
pub struct MeshProxy {
    config: Arc<MeshConfig>,
    topology: Arc<MeshTopology>,
    transport: Arc<RwLock<Option<Arc<MeshTransport>>>>,
    transport_manager:
        Arc<RwLock<Option<Arc<crate::mesh::transports::manager::MeshTransportManager>>>>,
    record_store: Arc<RwLock<Option<Arc<RecordStoreManager>>>>,
    active_connections: Arc<DashMap<String, MeshConnection>>,
    policy_cache: Cache<String, CachedPolicy>,
    failed_providers: Cache<String, Instant>,
    provider_stats: Arc<DashMap<String, ProviderStats>>,
    org_manager: Arc<TokioRwLock<OrganizationManager>>,
    transform_cache: TieredTransformCache,
    proxy_cache: Arc<RwLock<Option<ProxyCache>>>,
    cache_key_builder: Option<CacheKeyBuilder>,
}

struct MeshConnection {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    peer_node_id: String,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    request_id: String,
    started_at: std::time::Instant,
}

#[derive(Clone)]
pub struct CachedPolicy {
    pub provider_node_id: String,
    pub upstream_url: String,
    pub waf_policy: Option<WafPolicy>,
    pub protocol: UpstreamProtocol,
    pub priority_tier: u32,
    pub expires_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone)]
pub struct ProviderStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_failure: Option<Instant>,
    pub last_success: Option<Instant>,
    pub circuit_state: CircuitState,
    pub circuit_open_until: Option<Instant>,
    pub half_open_requests: u32,
}

impl ProviderStats {
    #[allow(dead_code)]
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        self.successful_requests as f64 / self.total_requests as f64
    }

    pub fn is_available(&self, half_open_max_requests: u32) -> bool {
        match self.circuit_state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(until) = self.circuit_open_until {
                    Instant::now() >= until
                } else {
                    true
                }
            }
            CircuitState::HalfOpen => self.half_open_requests < half_open_max_requests,
        }
    }

    pub fn record_success(&mut self, circuit_close_threshold: u32, circuit_open_timeout_secs: u64) {
        self.total_requests += 1;
        self.successful_requests += 1;
        self.consecutive_failures = 0;
        self.last_success = Some(Instant::now());

        match self.circuit_state {
            CircuitState::Closed => {}
            CircuitState::HalfOpen => {
                self.consecutive_successes += 1;
                if self.consecutive_successes >= circuit_close_threshold {
                    self.circuit_state = CircuitState::Closed;
                    self.consecutive_successes = 0;
                    self.half_open_requests = 0;
                }
            }
            CircuitState::Open => {
                self.circuit_state = CircuitState::HalfOpen;
                self.consecutive_successes = 1;
                self.half_open_requests = 0;
            }
        }
    }

    pub fn record_failure(&mut self, circuit_open_threshold: u32, circuit_open_timeout_secs: u64) {
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());

        match self.circuit_state {
            CircuitState::Closed => {
                if self.consecutive_failures >= circuit_open_threshold {
                    self.circuit_state = CircuitState::Open;
                    self.circuit_open_until =
                        Some(Instant::now() + Duration::from_secs(circuit_open_timeout_secs));
                }
            }
            CircuitState::HalfOpen => {
                self.circuit_state = CircuitState::Open;
                self.circuit_open_until =
                    Some(Instant::now() + Duration::from_secs(circuit_open_timeout_secs));
                self.consecutive_successes = 0;
            }
            CircuitState::Open => {
                self.circuit_open_until =
                    Some(Instant::now() + Duration::from_secs(circuit_open_timeout_secs));
            }
        }
    }

    #[allow(dead_code)]
    fn record_half_open_request(&mut self) {
        self.half_open_requests += 1;
    }

    pub fn decay(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(HEALTH_METRICS_WINDOW_SECS);

        if let Some(last_success) = self.last_success {
            if now.duration_since(last_success) > window {
                self.successful_requests = self.successful_requests.saturating_sub(1);
                self.total_requests = self.total_requests.saturating_sub(1);
            }
        }

        if let Some(last_failure) = self.last_failure {
            if now.duration_since(last_failure) > window {
                self.consecutive_failures = self.consecutive_failures.saturating_sub(1);
            }
        }
    }
}

#[derive(Clone)]
pub struct TransformCacheEntry {
    pub body: Bytes,
    pub content_encoding: Option<String>,
    pub content_type: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DhtTransformEntry {
    body: Vec<u8>,
    content_encoding: Option<String>,
    content_type: Option<String>,
}

impl DhtTransformEntry {
    fn from_cache_entry(entry: &TransformCacheEntry) -> Self {
        Self {
            body: entry.body.to_vec(),
            content_encoding: entry.content_encoding.clone(),
            content_type: entry.content_type.clone(),
        }
    }

    fn into_cache_entry(self) -> TransformCacheEntry {
        TransformCacheEntry {
            body: Bytes::from(self.body),
            content_encoding: self.content_encoding,
            content_type: self.content_type,
        }
    }
}

const L1_CACHE_SIZE: usize = 500;
const L2_CACHE_SIZE: usize = 2000;
const L2_CACHE_TTL_SECS: u64 = 600;

static TRANSFORM_CACHE_L1_HITS: LazyLock<std::sync::atomic::AtomicU64> =
    LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));
static TRANSFORM_CACHE_L2_HITS: LazyLock<std::sync::atomic::AtomicU64> =
    LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));
static TRANSFORM_CACHE_MISSES: LazyLock<std::sync::atomic::AtomicU64> =
    LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));

#[derive(Clone)]
pub struct TieredTransformCache {
    l1: DashMap<String, TransformCacheEntry>,
    l2: Cache<String, TransformCacheEntry>,
}

impl TieredTransformCache {
    pub fn new() -> Self {
        let l2 = Cache::builder()
            .max_capacity(L2_CACHE_SIZE as u64)
            .weigher(|_key: &String, value: &TransformCacheEntry| {
                u32::try_from(value.body.len()).unwrap_or(u32::MAX)
            })
            .time_to_live(Duration::from_secs(L2_CACHE_TTL_SECS))
            .build();
        Self {
            l1: DashMap::with_capacity(L1_CACHE_SIZE),
            l2,
        }
    }

    pub fn get(&self, key: &str) -> Option<TransformCacheEntry> {
        if let Some(entry) = self.l1.get(key) {
            TRANSFORM_CACHE_L1_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(entry.clone());
        }
        if let Some(entry) = self.l2.get(key) {
            TRANSFORM_CACHE_L2_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.l1.insert(key.to_string(), entry.clone());
            return Some(entry);
        }
        TRANSFORM_CACHE_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }

    pub fn insert(&self, key: String, value: TransformCacheEntry) {
        self.l2.insert(key.clone(), value.clone());
        self.l1.insert(key, value);
    }

    pub fn l1_len(&self) -> usize {
        self.l1.len()
    }

    pub fn l2_len(&self) -> usize {
        self.l2.entry_count() as usize
    }
}

impl MeshProxy {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        cache_config: Option<ProxyCacheSettings>,
    ) -> Self {
        let cache_size = config.persistence.policy_cache_size.max(100);
        let policy_cache = Cache::builder()
            .max_capacity(cache_size as u64)
            .time_to_live(Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS))
            .build();
        let failed_providers = Cache::builder()
            .max_capacity(cache_size as u64)
            .time_to_live(Duration::from_secs(FAILED_PROVIDER_COOLDOWN_SECS * 2))
            .build();
        let provider_stats = Arc::new(DashMap::new());

        let transform_cache = TieredTransformCache::new();

        let proxy_cache = cache_config.as_ref().map(|settings| {
            let cache = ProxyCache::new(settings.clone());
            let kb = CacheKeyBuilder::new(settings.key_pattern.clone(), settings.vary_by.clone());
            (cache, kb)
        });

        let (proxy_cache, cache_key_builder) = match proxy_cache {
            Some((cache, kb)) => (Arc::new(RwLock::new(Some(cache))), Some(kb)),
            None => (Arc::new(RwLock::new(None)), None),
        };

        Self {
            config,
            topology,
            transport: Arc::new(RwLock::new(None)),
            transport_manager: Arc::new(RwLock::new(None)),
            record_store: Arc::new(RwLock::new(None)),
            active_connections: Arc::new(DashMap::new()),
            policy_cache,
            failed_providers,
            provider_stats,
            org_manager: Arc::new(TokioRwLock::new(OrganizationManager::new())),
            transform_cache,
            proxy_cache,
            cache_key_builder,
        }
    }

    #[allow(dead_code)]
    pub fn proxy_cache(&self) -> &Arc<RwLock<Option<ProxyCache>>> {
        &self.proxy_cache
    }

    fn is_cacheable_method(method: &http::Method) -> bool {
        matches!(method, &http::Method::GET | &http::Method::HEAD)
    }

    fn should_bypass_cache(headers: &http::HeaderMap) -> bool {
        headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("no-cache") || v.contains("no-store") || v.contains("private"))
            .unwrap_or(false)
    }

    fn is_response_cacheable(status: u16) -> bool {
        matches!(status, 200 | 301 | 302 | 304)
    }

    fn get_cache_max_age(headers: &http::HeaderMap) -> Option<std::time::Duration> {
        headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split(',').find_map(|part| {
                    let part = part.trim();
                    if let Some(val) = part.strip_prefix("max-age=") {
                        val.parse::<u64>().ok().map(std::time::Duration::from_secs)
                    } else {
                        None
                    }
                })
            })
    }

    pub fn set_proxy_cache_preferences(
        &self,
        preferences: &crate::mesh::protocol::ProxyCachePreferences,
    ) {
        let mut proxy_cache = self.proxy_cache.write();
        match proxy_cache.as_mut() {
            Some(cache) => {
                cache.apply_preferences(preferences);
            }
            None => {
                let settings = ProxyCacheSettings {
                    enabled: preferences.enable,
                    inactive: std::time::Duration::from_secs(preferences.inactive),
                    valid_status: preferences.valid_status.iter().map(|&v| v as u16).collect(),
                    methods: preferences.methods.clone(),
                    use_stale: preferences.use_stale.clone(),
                    min_uses: preferences.min_uses,
                    stale_while_revalidate: if preferences.stale_while_revalidate > 0 {
                        Some(std::time::Duration::from_secs(
                            preferences.stale_while_revalidate,
                        ))
                    } else {
                        None
                    },
                    stale_if_error: if preferences.stale_if_error > 0 {
                        Some(std::time::Duration::from_secs(preferences.stale_if_error))
                    } else {
                        None
                    },
                    ..Default::default()
                };
                let cache = ProxyCache::new(settings.clone());
                let kb = CacheKeyBuilder::new(settings.key_pattern, settings.vary_by);
                *proxy_cache = Some(cache);
                drop(proxy_cache);
                // cache_key_builder is immutable after construction; we must rebuild if preferences change key_pattern/vary_by
                // For simplicity, we store a new builder - but since cache_key_builder is Option<CacheKeyBuilder>,
                // we need to handle this carefully. For now, we note that key_pattern/vary_by changes require restart.
            }
        }
    }

    pub fn set_record_store(&self, record_store: Arc<RecordStoreManager>) {
        let mut rs = self.record_store.write();
        *rs = Some(record_store);
    }

    pub fn set_transport(&self, transport: Arc<MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    pub fn set_transport_manager(
        &self,
        manager: Arc<crate::mesh::transports::manager::MeshTransportManager>,
    ) {
        let mut m = self.transport_manager.write();
        *m = Some(manager);
    }

    pub async fn register_organization(&self, org: crate::mesh::Organization) {
        let mut mgr = self.org_manager.write().await;
        mgr.register_organization(org);
    }

    pub async fn issue_tier_key(
        &self,
        org_id: &str,
        tier: u32,
        key: Vec<u8>,
        valid_from: u64,
        valid_until: u64,
    ) -> Option<crate::mesh::TierKey> {
        let mut mgr = self.org_manager.write().await;
        mgr.issue_tier_key(
            org_id,
            tier,
            key,
            valid_from,
            valid_until,
            "self".to_string(),
        )
    }

    pub async fn validate_tier_claim(&self, claim: &crate::mesh::TierClaim) -> bool {
        let mgr = self.org_manager.read().await;
        mgr.validate_tier_claim(claim)
    }

    pub fn min_tier_threshold(&self) -> u32 {
        self.config.tier_config.min_tier_threshold
    }

    pub async fn block_and_broadcast_upstream(
        &self,
        upstream_id: &str,
        reason: &str,
        blocked_duration_secs: u64,
    ) {
        let transport = {
            let guard = self.transport.read();
            guard.clone()
        };
        if let Some(transport) = transport {
            transport
                .broadcast_upstream_block(upstream_id, reason, blocked_duration_secs)
                .await;
        }
    }

    pub async fn resolve_upstream(
        &self,
        req: &Request<Incoming>,
    ) -> Result<(String, CachedPolicy), MeshProxyError> {
        let upstream_id = self.extract_upstream_id(req)?;

        if let Some(cached) = self.get_cached_policy(&upstream_id) {
            let is_expired = cached.expires_at < Instant::now();
            let stale_ttl = Duration::from_secs(self.config.stale_cache_ttl_secs);
            let is_stale = cached.expires_at < Instant::now() - stale_ttl;

            let peer_healthy =
                if let Some(peer) = self.topology.get_peer(&cached.provider_node_id).await {
                    peer.is_healthy()
                } else {
                    false
                };

            if peer_healthy && !is_stale {
                tracing::debug!("Using cached policy for {}", upstream_id);
                return Ok((upstream_id, cached));
            }

            if peer_healthy && is_stale && !self.is_provider_failed(&cached.provider_node_id) {
                tracing::debug!(
                    "Returning stale cached policy for {}, will revalidate in background",
                    upstream_id
                );
                self.mark_stale_cache_for_refresh(upstream_id.to_string());
                return Ok((upstream_id, cached));
            }

            if self.is_provider_failed(&cached.provider_node_id) {
                tracing::debug!(
                    "Cached provider {} is in cooldown for {}",
                    cached.provider_node_id,
                    upstream_id
                );
            }
        }

        let provider_info = {
            let transport = {
                let guard = self.transport.read();
                guard.clone()
            };
            match transport.as_ref() {
                Some(t) => match t.send_route_query(&upstream_id).await {
                    Ok(result) => {
                        let providers = self.filter_failed_providers(&result.providers);

                        let tier_filtered = self.filter_by_tier_threshold(&providers);

                        if tier_filtered.is_empty() && !providers.is_empty() {
                            tracing::warn!(
                                    "All providers for {} filtered by tier threshold {}, returning alternatives for redirect",
                                    upstream_id,
                                    self.min_tier_threshold()
                                );
                            let alternatives: Vec<_> = providers
                                .iter()
                                .map(|p| crate::mesh::protocol::AlternativeProvider {
                                    node_id: p.node_id.clone(),
                                    priority_tier: p.priority_tier,
                                })
                                .collect();

                            return Err(MeshProxyError::TierThresholdNotMet {
                                upstream_id: upstream_id.to_string(),
                                alternatives,
                            });
                        }

                        if providers.is_empty() {
                            if let Some(cached) = self.get_cached_policy(&upstream_id) {
                                if !self.is_provider_failed(&cached.provider_node_id) {
                                    tracing::warn!(
                                        "All providers failed for {}, using stale cache",
                                        upstream_id
                                    );
                                    return Ok((upstream_id, cached));
                                }
                            }
                            return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
                        }
                        tier_filtered.into_iter().next().ok_or_else(|| {
                            MeshProxyError::NoRouteToUpstream(upstream_id.to_string())
                        })?
                    }
                    Err(e) => {
                        if let Some(cached) = self.get_cached_policy(&upstream_id) {
                            tracing::warn!(
                                "Route query failed for {}, using stale cache: {}",
                                upstream_id,
                                e
                            );
                            return Ok((upstream_id, cached));
                        }
                        return Err(MeshProxyError::ConnectionFailed(e.to_string()));
                    }
                },
                None => {
                    return Err(MeshProxyError::ConnectionFailed(
                        "Transport not initialized".to_string(),
                    ));
                }
            }
        };

        let cached = CachedPolicy {
            provider_node_id: provider_info.node_id.clone(),
            upstream_url: provider_info.upstream_url.clone(),
            waf_policy: provider_info.waf_policy.clone(),
            protocol: UpstreamProtocol::Http,
            priority_tier: provider_info.priority_tier,
            expires_at: Instant::now() + Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
        };

        self.cache_policy(&upstream_id, cached.clone());

        Ok((upstream_id, cached))
    }

    fn extract_upstream_id(&self, req: &Request<Incoming>) -> Result<String, MeshProxyError> {
        let uri = req.uri();

        let host = uri
            .host()
            .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
            .ok_or_else(|| MeshProxyError::UpstreamNotFound("No host found".to_string()))?;

        let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });

        let upstream_id = format!("http://{}:{}", host, port);

        Ok(upstream_id)
    }

    fn get_cached_policy(&self, upstream_id: &str) -> Option<CachedPolicy> {
        self.policy_cache.get(upstream_id)
    }

    fn cache_policy(&self, upstream_id: &str, policy: CachedPolicy) {
        self.policy_cache.insert(upstream_id.to_string(), policy);
    }

    fn is_provider_failed(&self, provider_node_id: &str) -> bool {
        self.failed_providers.get(provider_node_id).is_some()
    }

    fn mark_provider_failed(&self, provider_node_id: &str) {
        self.failed_providers
            .insert(provider_node_id.to_string(), Instant::now());
    }

    fn clear_provider_failure(&self, provider_node_id: &str) {
        self.failed_providers.remove(provider_node_id);
    }

    fn filter_failed_providers(&self, providers: &[ProviderInfo]) -> Vec<ProviderInfo> {
        providers
            .iter()
            .filter(|p| !self.is_provider_unhealthy(&p.node_id))
            .cloned()
            .collect()
    }

    fn filter_by_tier_threshold(&self, providers: &[ProviderInfo]) -> Vec<ProviderInfo> {
        let min_tier = self.min_tier_threshold();
        if min_tier == 0 {
            return providers.to_vec();
        }

        providers
            .iter()
            .filter(|p| p.priority_tier >= min_tier)
            .cloned()
            .collect()
    }

    fn is_provider_unhealthy(&self, provider_node_id: &str) -> bool {
        let is_unhealthy = {
            if let Some(mut provider_stats) = self.provider_stats.get_mut(provider_node_id) {
                provider_stats.decay();
                let half_open_max = self.config.connection.half_open_max_requests;
                !provider_stats.is_available(half_open_max)
            } else {
                return self.is_provider_failed(provider_node_id);
            }
        };
        is_unhealthy
    }

    fn record_provider_success(&self, provider_node_id: &str) {
        self.clear_provider_failure(provider_node_id);

        let close_thresh = self.config.connection.circuit_close_threshold;
        let open_timeout = self.config.connection.circuit_open_timeout_secs;

        let entry = self.provider_stats.entry(provider_node_id.to_string());
        match entry {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                e.get_mut().record_success(close_thresh, open_timeout);
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                let mut new_stats = ProviderStats {
                    total_requests: 0,
                    successful_requests: 0,
                    consecutive_failures: 0,
                    consecutive_successes: 0,
                    last_failure: None,
                    last_success: None,
                    circuit_state: CircuitState::Closed,
                    circuit_open_until: None,
                    half_open_requests: 0,
                };
                new_stats.record_success(close_thresh, open_timeout);
                e.insert(new_stats);
            }
        }
    }

    fn record_provider_failure(&self, provider_node_id: &str) -> u32 {
        let failure_count = {
            let open_thresh = self.config.connection.circuit_open_threshold;
            let open_timeout = self.config.connection.circuit_open_timeout_secs;

            let entry = self.provider_stats.entry(provider_node_id.to_string());
            match entry {
                dashmap::mapref::entry::Entry::Occupied(mut e) => {
                    e.get_mut().record_failure(open_thresh, open_timeout);
                    e.get().consecutive_failures
                }
                dashmap::mapref::entry::Entry::Vacant(e) => {
                    let mut new_stats = ProviderStats {
                        total_requests: 0,
                        successful_requests: 0,
                        consecutive_failures: 0,
                        consecutive_successes: 0,
                        last_failure: None,
                        last_success: None,
                        circuit_state: CircuitState::Closed,
                        circuit_open_until: None,
                        half_open_requests: 0,
                    };
                    new_stats.record_failure(open_thresh, open_timeout);
                    e.insert(new_stats);
                    1
                }
            }
        };
        self.mark_provider_failed(provider_node_id);
        failure_count
    }

    async fn get_providers_for_upstream(
        &self,
        upstream_id: &str,
    ) -> Result<Vec<ProviderInfo>, MeshProxyError> {
        let transport = {
            let guard = self.transport.read();
            guard.clone()
        };
        let transport = transport.ok_or_else(|| {
            MeshProxyError::ConnectionFailed("Transport not initialized".to_string())
        })?;

        match transport.send_route_query(upstream_id).await {
            Ok(result) => {
                let providers = self.filter_failed_providers(&result.providers);
                let mut providers_with_capability = Vec::new();
                for p in providers {
                    if let Some(peer) = self.topology.get_peer(&p.node_id).await {
                        if peer.capabilities.can_proxy {
                            providers_with_capability.push(p);
                        }
                    }
                }
                if providers_with_capability.is_empty() {
                    return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
                }
                Ok(providers_with_capability)
            }
            Err(e) => Err(MeshProxyError::ConnectionFailed(e.to_string())),
        }
    }

    fn weighted_shuffle_providers(
        &self,
        providers: Vec<crate::mesh::protocol::ProviderInfo>,
    ) -> Vec<crate::mesh::protocol::ProviderInfo> {
        if providers.len() <= 1 {
            return providers;
        }

        let scores: Vec<f64> = providers.iter().map(|p| p.score.max(0.01)).collect();

        let weighted_index = WeightedIndex::new(&scores).unwrap();
        let mut indices: Vec<usize> = (0..providers.len()).collect();
        let mut rng = rand::rng();

        let mut result = Vec::with_capacity(providers.len());
        for _ in 0..providers.len() {
            let idx = indices.remove(weighted_index.sample(&mut rng));
            result.push(providers[idx].clone());
        }
        result
    }

    // Response transform holds a cache lock across an await; low contention expected.
    #[allow(clippy::await_holding_lock)]
    pub async fn route_request<B>(
        &self,
        upstream_id: &str,
        req: Request<B>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError>
    where
        B: HttpBody + Send,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        let timeout_duration = Duration::from_secs(self.config.request_timeout_secs);
        let start = Instant::now();

        loop {
            if start.elapsed() > timeout_duration {
                tracing::warn!(
                    "Route request to upstream {} exceeded timeout of {}s",
                    upstream_id,
                    timeout_duration.as_secs()
                );
                return Err(MeshProxyError::RequestTimeout(timeout_duration.as_secs()));
            }

            if self.topology.is_upstream_blocked(upstream_id).await {
                tracing::warn!("Upstream {} is blocked due to ratelimit", upstream_id);

                if let Some(blocked_until) = self.topology.get_blocked_until(upstream_id).await {
                    let remaining_secs = blocked_until
                        .saturating_duration_since(Instant::now())
                        .as_secs();

                    if remaining_secs < 5 {
                        let wait_time = rand::rng().random_range(0..=5);
                        tracing::debug!(
                            "Blocking period < 5s, waiting {}s before retry",
                            wait_time
                        );
                        tokio::time::sleep(Duration::from_secs(wait_time)).await;

                        if !self.topology.is_upstream_blocked(upstream_id).await {
                            continue;
                        }
                    }
                }

                return Err(MeshProxyError::UpstreamBlocked(upstream_id.to_string()));
            }

            let cached = self.get_cached_policy(upstream_id);
            let cached_for_check = cached.clone();

            let provider_info = if let Some(ref cached) = cached {
                if let Some(peer) = self.topology.get_peer(&cached.provider_node_id).await {
                    if peer.is_healthy() {
                        Some(crate::mesh::protocol::ProviderInfo {
                            node_id: cached.provider_node_id.clone(),
                            upstream_url: cached.upstream_url.clone(),
                            waf_policy: cached.waf_policy.clone(),
                            hops: 0,
                            ttl: Duration::from_secs(300),
                            score: 1.0,
                            priority_tier: cached.priority_tier,
                            tier_claim: None,
                            org_id: None,
                            mesh_name: None,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(pi) = provider_info {
                if self.config.require_tier_claim {
                    if let Some(ref tc) = pi.tier_claim {
                        if !self.validate_tier_claim(tc).await {
                            tracing::warn!(
                                "Tier claim validation failed for upstream {} provider {}",
                                upstream_id,
                                pi.node_id
                            );
                            return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
                        }
                    } else {
                        tracing::warn!(
                            "Tier claim required but not provided for upstream {}",
                            upstream_id
                        );
                        return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
                    }
                }

                let site_id = upstream_id.to_string();
                let method = req.method().clone();
                let uri = req.uri().clone();
                let headers = req.headers().clone();

                return self
                    .proxy_to_peer_with_fallback(
                        upstream_id,
                        vec![pi],
                        req,
                        site_id,
                        method,
                        uri,
                        headers,
                    )
                    .await;
            }

            if let Some(ref c) = cached_for_check {
                let stale_ttl = Duration::from_secs(self.config.stale_cache_ttl_secs);
                if c.expires_at < Instant::now() - stale_ttl {
                    self.mark_stale_cache_for_refresh(upstream_id.to_string());
                }
            }

            let providers = match self.get_providers_for_upstream(upstream_id).await {
                Ok(p) => p,
                Err(e) => {
                    if let Some(cached) = self.get_cached_policy(upstream_id) {
                        tracing::warn!(
                            "Route query failed for {}, using stale cache: {}",
                            upstream_id,
                            e
                        );
                        return self
                            .proxy_to_peer(
                                &cached.provider_node_id,
                                upstream_id,
                                cached.upstream_url.clone(),
                                req,
                            )
                            .await;
                    }
                    return Err(e);
                }
            };

            let first_provider = &providers[0];
            let cached = CachedPolicy {
                provider_node_id: first_provider.node_id.clone(),
                upstream_url: first_provider.upstream_url.clone(),
                waf_policy: first_provider.waf_policy.clone(),
                protocol: UpstreamProtocol::Http,
                priority_tier: first_provider.priority_tier,
                expires_at: Instant::now() + Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
            };
            self.cache_policy(upstream_id, cached);

            let site_id_for_cache = upstream_id.to_string();
            let method_for_cache = req.method().clone();
            let uri_for_cache = req.uri().clone();
            let headers_for_cache = req.headers().clone();

            return self
                .proxy_to_peer_with_fallback(
                    upstream_id,
                    providers,
                    req,
                    site_id_for_cache,
                    method_for_cache,
                    uri_for_cache,
                    headers_for_cache,
                )
                .await;
        }
    }

    async fn proxy_to_peer_with_fallback<B>(
        &self,
        upstream_id: &str,
        providers: Vec<crate::mesh::protocol::ProviderInfo>,
        req: Request<B>,
        site_id: String,
        request_method: http::Method,
        request_uri: http::Uri,
        request_headers: http::HeaderMap,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError>
    where
        B: HttpBody + Send,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        if providers.is_empty() {
            return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
        }

        let providers = self.weighted_shuffle_providers(providers);

        // Extract method, uri, and headers before consuming the body
        let method = req.method().clone();
        let uri = req.uri().clone();
        let mut headers = req.headers().clone();
        let to_remove: Vec<http::header::HeaderName> = headers
            .iter()
            .filter(|(name, _)| is_hop_by_hop_header_name(name))
            .map(|(name, _)| name.clone())
            .collect();
        for name in to_remove {
            headers.remove(name);
        }

        // Collect request body upfront since we need to send it multiple times
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::warn!("Failed to collect request body for retry: {:?}", e);
                return Err(MeshProxyError::SendFailed(format!(
                    "Failed to collect request body: {:?}",
                    e
                )));
            }
        };

        let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<(
            String,
            Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError>,
        )>(providers.len());

        for provider in &providers {
            let result_tx = result_tx.clone();
            let upstream_id = upstream_id.to_string();
            let node_id = provider.node_id.clone();
            let upstream_url = provider.upstream_url.clone();
            let body = body_bytes.clone();
            let method_clone = method.clone();
            let uri_clone = uri.clone();
            let headers_clone = headers.clone();
            let proxy = self.clone();

            tokio::spawn(async move {
                tracing::debug!("Trying provider {} for {}", node_id, upstream_id);

                // Build request with original method/URI/headers, preserving client's path
                let request_body = http_body_util::Full::new(body);
                let mut retry_req = Request::builder().method(method_clone).uri(uri_clone);
                for (name, value) in headers_clone.iter() {
                    retry_req = retry_req.header(name.as_str(), value.to_str().unwrap_or(""));
                }
                let retry_req = match retry_req.body(request_body) {
                    Ok(req) => req,
                    Err(e) => {
                        let _ = result_tx
                            .send((node_id, Err(MeshProxyError::SendFailed(e.to_string()))))
                            .await;
                        return;
                    }
                };

                let result = proxy
                    .proxy_to_peer(&node_id, &upstream_id, upstream_url, retry_req)
                    .await;
                let _ = result_tx.send((node_id, result)).await;
            });
        }

        drop(result_tx);

        let mut last_error = None;
        let mut successful_provider: Option<String> = None;
        let mut successful_resp: Option<Response<BoxBody<Bytes, Infallible>>> = None;

        while let Some((provider_node_id, result)) = result_rx.recv().await {
            match result {
                Ok(resp) => {
                    self.record_provider_success(&provider_node_id);
                    successful_provider = Some(provider_node_id.clone());
                    successful_resp = Some(resp);
                    break;
                }
                Err(e) => {
                    let failure_count = self.record_provider_failure(&provider_node_id);

                    let tm = {
                        let guard = self.transport_manager.read();
                        guard.clone()
                    };
                    if let Some(ref tm) = tm {
                        tm.report_reachability(
                            upstream_id,
                            &provider_node_id,
                            crate::mesh::dht::ReachabilityStatus::Failed,
                            0,
                            0.0,
                            failure_count,
                        );
                    }

                    if failure_count >= BLOCK_BROADCAST_FAILURE_THRESHOLD
                        && !self.topology.is_upstream_blocked(upstream_id).await
                    {
                        tracing::warn!(
                            upstream_id,
                            failure_count,
                            "Upstream {} has {} consecutive failures - broadcasting block to mesh",
                            upstream_id,
                            failure_count
                        );
                        self.block_and_broadcast_upstream(
                            upstream_id,
                            "provider_consecutive_failures",
                            BLOCK_DURATION_SECS,
                        )
                        .await;
                    }

                    tracing::warn!(
                        "Provider {} failed for {}: {}",
                        provider_node_id,
                        upstream_id,
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        if let Some((provider_node_id, resp)) = successful_provider.zip(successful_resp) {
            if let Some(cached) = self.get_cached_policy(upstream_id) {
                if cached.provider_node_id != provider_node_id {
                    if let Some(provider_info) =
                        providers.iter().find(|p| p.node_id == provider_node_id)
                    {
                        let updated = CachedPolicy {
                            provider_node_id: provider_node_id.clone(),
                            upstream_url: provider_info.upstream_url.clone(),
                            waf_policy: provider_info.waf_policy.clone(),
                            protocol: UpstreamProtocol::Http,
                            priority_tier: provider_info.priority_tier,
                            expires_at: Instant::now()
                                + Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
                        };
                        self.cache_policy(upstream_id, updated);
                    }
                }
            }

            let request_size = body_bytes.len() + format!("{} {} HTTP/1.1\r\n", method, uri).len();
            let response_size = resp.body().size_hint().exact().unwrap_or(0);

            if let Some(bandwidth) = get_global_bandwidth_tracker_or_log() {
                bandwidth.record_site_mesh_egress(upstream_id, request_size as u64);
                bandwidth.record_site_mesh_ingress(upstream_id, response_size);
            }

            tracing::info!(
                "Successfully proxied to {} via provider {}",
                upstream_id,
                provider_node_id
            );

            if Self::is_cacheable_method(&request_method) {
                let cache_opt = self.proxy_cache.read().clone();
                let kb_opt = self.cache_key_builder.clone();
                if let (Some(cache), Some(kb)) = (cache_opt, kb_opt) {
                    if !Self::should_bypass_cache(&request_headers) {
                        let host = request_headers
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or(upstream_id);
                        let cache_key = kb.build(
                            "http",
                            &request_method,
                            host,
                            &request_uri,
                            &request_headers,
                            &site_id,
                        );

                        if let Some(cached_entry) = cache.get(&cache_key).await {
                            tracing::debug!(
                                "Mesh proxy cache HIT for {} {} (site_id={})",
                                request_method,
                                request_uri,
                                site_id
                            );

                            let mut builder = HttpResponse::builder().status(cached_entry.status);
                            for (name, value) in cached_entry.headers.iter() {
                                builder = builder.header(name, value);
                            }

                            let cache_directive = if cached_entry.is_fresh {
                                "public".to_string()
                            } else {
                                "public, stale-while-revalidate".to_string()
                            };
                            builder = builder.header("Cache-Control", cache_directive);
                            builder = builder.header("X-Cache", "HIT");

                            let body_bytes = cached_entry.content.clone();
                            return Ok(builder
                                .body(Full::new(body_bytes).boxed())
                                .unwrap_or_else(|_| crate::http::fallback_error_boxed()));
                        }

                        let status = resp.status().as_u16();
                        if Self::is_response_cacheable(status) {
                            let headers = resp.headers().clone();
                            let body_bytes = match resp.into_body().collect().await {
                                Ok(collected) => collected.to_bytes(),
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to collect response body for cache: {:?}",
                                        e
                                    );
                                    return Ok(HttpResponse::builder()
                                        .status(status)
                                        .body(Full::new(Bytes::new()).boxed())
                                        .unwrap_or_else(|_| crate::http::fallback_error_boxed()));
                                }
                            };
                            let max_age = Self::get_cache_max_age(&headers);

                            if let Err(e) = cache.insert(
                                cache_key,
                                body_bytes.clone(),
                                status,
                                headers,
                                max_age,
                            ) {
                                tracing::warn!(
                                    "Mesh proxy cache insert failed for {} {}: {}",
                                    request_method,
                                    request_uri,
                                    e
                                );
                            } else {
                                tracing::debug!(
                                    "Mesh proxy cached {} {} (site_id={})",
                                    request_method,
                                    request_uri,
                                    site_id
                                );
                            }

                            let mut builder = HttpResponse::builder().status(status);
                            builder = builder.header("X-Cache", "MISS");
                            return Ok(builder
                                .body(Full::new(body_bytes).boxed())
                                .unwrap_or_else(|_| crate::http::fallback_error_boxed()));
                        }
                    }
                }
            }

            return Ok(resp);
        }

        Err(last_error
            .unwrap_or_else(|| MeshProxyError::NoRouteToUpstream(upstream_id.to_string())))
    }

    fn mark_stale_cache_for_refresh(&self, upstream_id: String) {
        if let Some(cached) = self.policy_cache.get(&upstream_id) {
            let refreshed = CachedPolicy {
                provider_node_id: cached.provider_node_id.clone(),
                upstream_url: cached.upstream_url.clone(),
                waf_policy: cached.waf_policy.clone(),
                protocol: cached.protocol,
                priority_tier: cached.priority_tier,
                expires_at: Instant::now() + Duration::from_secs(1),
            };
            self.policy_cache.insert(upstream_id.clone(), refreshed);
            let upstream = upstream_id;
            let cache = self.policy_cache.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                cache.remove(&upstream);
                tracing::debug!(
                    "Stale cache invalidated for {}, will re-fetch on next request",
                    upstream
                );
            });
        }
    }

    // Response transform holds a cache lock across an await; low contention expected.
    #[allow(clippy::await_holding_lock)]
    pub async fn route_request_with_policy(
        &self,
        upstream_id: &str,
        req: Request<Incoming>,
    ) -> Result<(Response<BoxBody<Bytes, Infallible>>, Option<WafPolicy>), MeshProxyError> {
        let providers = match self.get_providers_for_upstream(upstream_id).await {
            Ok(p) => p,
            Err(e) => {
                if let Some(cached) = self.get_cached_policy(upstream_id) {
                    tracing::warn!(
                        "Route query failed for {}, using stale cache: {}",
                        upstream_id,
                        e
                    );
                    let response = self
                        .proxy_to_peer(
                            &cached.provider_node_id,
                            upstream_id,
                            cached.upstream_url.clone(),
                            req,
                        )
                        .await;
                    return response.map(|r| (r, cached.waf_policy));
                }
                return Err(e);
            }
        };

        let first_provider = &providers[0];
        let waf_policy = first_provider.waf_policy.clone();

        let site_id = upstream_id.to_string();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        let response = self
            .proxy_to_peer_with_fallback(upstream_id, providers, req, site_id, method, uri, headers)
            .await;

        match response {
            Ok(resp) => Ok((resp, waf_policy)),
            Err(e) => Err(e),
        }
    }

    async fn proxy_to_peer<B>(
        &self,
        peer_node_id: &str,
        upstream_id: &str,
        provider_upstream_url: String,
        mut req: Request<B>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError>
    where
        B: HttpBody + Send,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        let peer = self
            .topology
            .get_peer(peer_node_id)
            .await
            .ok_or_else(|| MeshProxyError::PeerNotFound(peer_node_id.to_string()))?;

        if !peer.is_healthy() {
            return Err(MeshProxyError::PeerUnhealthy(peer_node_id.to_string()));
        }

        let upstream_info = self
            .topology
            .get_upstream_for_peer(upstream_id, peer_node_id)
            .await;

        let target_url = if let Some(info) = upstream_info {
            if !info.is_local && info.owner_node_id != peer_node_id {
                return Err(MeshProxyError::PeerDoesNotHaveUpstream(
                    peer_node_id.to_string(),
                    upstream_id.to_string(),
                ));
            }
            if info.is_local {
                info.upstream_url.clone()
            } else {
                let peer_upstream = self.topology.get_peer(&info.owner_node_id).await;
                if let Some(p) = peer_upstream {
                    p.address.clone()
                } else {
                    provider_upstream_url
                }
            }
        } else {
            provider_upstream_url
        };

        let request_id = uuid::Uuid::new_v4().to_string();
        self.active_connections.insert(
            request_id.clone(),
            MeshConnection {
                peer_node_id: peer_node_id.to_string(),
                request_id: request_id.clone(),
                started_at: std::time::Instant::now(),
            },
        );

        let uri = req.uri().to_string();
        let method = req.method().clone();

        tracing::debug!(
            "Proxying {} {} to peer {} -> {}",
            method,
            uri,
            peer_node_id,
            target_url
        );

        let transport = {
            let guard = self.transport.read();
            guard.clone()
        };
        let transport = transport.ok_or_else(|| {
            MeshProxyError::ConnectionFailed("Transport not initialized".to_string())
        })?;

        {
            let to_remove: Vec<http::header::HeaderName> = req
                .headers()
                .iter()
                .filter(|(name, _)| is_hop_by_hop_header_name(name))
                .map(|(name, _)| name.clone())
                .collect();
            for name in to_remove {
                req.headers_mut().remove(name);
            }
        }

        let response = transport
            .proxy_http_request(peer_node_id, &target_url, req)
            .await
            .map_err(|e| MeshProxyError::ConnectionFailed(e.to_string()))?;

        self.active_connections.remove(&request_id);

        let mut response = self.transform_response(response, upstream_id, &uri).await;
        {
            let to_remove: Vec<http::header::HeaderName> = response
                .headers()
                .iter()
                .filter(|(name, _)| is_hop_by_hop_header_name(name))
                .map(|(name, _)| name.clone())
                .collect();
            for name in to_remove {
                response.headers_mut().remove(name);
            }
        }

        Ok(response)
    }

    async fn transform_response(
        &self,
        mut response: Response<BoxBody<Bytes, Infallible>>,
        upstream_id: &str,
        request_path: &str,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let tm = {
            let guard = self.transport_manager.read();
            guard.clone()
        };
        let tm = tm.as_ref();

        if tm.is_none() {
            return response;
        }

        let tm = tm.unwrap();

        let image_protection = tm.get_image_protection_for_site(upstream_id).await;
        let image_poison_config = tm.get_image_poison_config_for_site(upstream_id).await;
        let compression = tm.get_compression_for_site(upstream_id).await;
        let minification = tm.get_minification_for_site(upstream_id).await;

        if let Some(ref record_store) = tm.get_record_store() {
            let prefs_key =
                crate::mesh::dht::keys::DhtKey::upstream_proxy_cache_preferences(upstream_id);
            if let Some(record) = record_store.get_record(&prefs_key.as_str()) {
                if let Ok(prefs) = serde_json::from_slice::<
                    crate::mesh::protocol::ProxyCachePreferences,
                >(&record.value)
                {
                    self.set_proxy_cache_preferences(&prefs);
                }
            }
        }

        let has_record_store;
        {
            let mut rs = self.record_store.write();
            if rs.is_none() {
                if let Some(record_store) = tm.get_record_store() {
                    *rs = Some(record_store);
                }
            }
            has_record_store = rs.is_some();
        }

        if !has_record_store
            && image_protection.is_none()
            && image_poison_config.is_none()
            && compression.is_none()
            && minification.is_none()
        {
            return response;
        }

        let body = std::mem::replace(
            response.body_mut(),
            http_body_util::Full::new(Bytes::new()).boxed(),
        );

        let body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return response,
        };

        if body.is_empty() {
            return response;
        }

        let content_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&body);
            hex::encode(hasher.finalize())
        };

        let transform_flags = format!(
            "min:{}:{}:{}:{},img:{}:{},poison:{}:{}:{}",
            minification
                .as_ref()
                .and_then(|c| c.enabled)
                .unwrap_or(false),
            minification
                .as_ref()
                .and_then(|c| c.enable_html)
                .unwrap_or(true),
            minification
                .as_ref()
                .and_then(|c| c.enable_css)
                .unwrap_or(true),
            minification
                .as_ref()
                .and_then(|c| c.enable_js)
                .unwrap_or(true),
            image_protection
                .as_ref()
                .and_then(|c| c.enabled)
                .unwrap_or(false),
            image_protection
                .as_ref()
                .and_then(|c| c.min_size_bytes)
                .unwrap_or(102400) as u64,
            image_poison_config
                .as_ref()
                .and_then(|c| c.enabled)
                .unwrap_or(false),
            image_poison_config
                .as_ref()
                .and_then(|c| c.intensity)
                .unwrap_or(0.5),
            image_poison_config
                .as_ref()
                .and_then(|c| c.jpeg_quality)
                .unwrap_or(85),
        );

        let cache_key = format!("{}:{}:{}", upstream_id, content_hash, transform_flags);

        {
            if let Some(entry) = self.transform_cache.get(&cache_key) {
                tracing::debug!("Transform cache hit for {}", cache_key);
                let mut new_response = Response::builder().status(200);

                if let Some(ref enc) = entry.content_encoding {
                    new_response = new_response.header("Content-Encoding", enc.as_str());
                }
                if let Some(ref ct) = entry.content_type {
                    new_response = new_response.header("Content-Type", ct.as_str());
                }

                let body = http_body_util::Full::new(entry.body.clone()).boxed();
                return new_response.body(body).unwrap_or_else(|_| {
                    Response::builder()
                        .status(500)
                        .body(
                            http_body_util::Full::new(Bytes::from("Internal Server Error")).boxed(),
                        )
                        .unwrap_or_else(|_| {
                            Response::new(http_body_util::Full::new(Bytes::new()).boxed())
                        })
                });
            }
        }

        {
            let rs = self.record_store.read();
            if let Some(ref record_store) = *rs {
                let dht_key = crate::mesh::dht::keys::DhtKey::transformed_content(
                    upstream_id,
                    &content_hash,
                    &transform_flags,
                );
                if let Some(record) = record_store.get_record(&dht_key.as_str()) {
                    tracing::debug!("DHT transform cache hit for {}", cache_key);
                    let entry: Option<DhtTransformEntry> =
                        serde_json::from_slice(&record.value).ok();
                    if let Some(entry) = entry {
                        let entry = entry.into_cache_entry();
                        let mut new_response = Response::builder().status(200);

                        if let Some(ref enc) = entry.content_encoding {
                            new_response = new_response.header("Content-Encoding", enc.as_str());
                        }
                        if let Some(ref ct) = entry.content_type {
                            new_response = new_response.header("Content-Type", ct.as_str());
                        }

                        let body = http_body_util::Full::new(entry.body.clone()).boxed();
                        return new_response.body(body).unwrap_or_else(|_| {
                            Response::builder()
                                .status(500)
                                .body(
                                    http_body_util::Full::new(Bytes::from("Internal Server Error"))
                                        .boxed(),
                                )
                                .unwrap_or_else(|_| {
                                    Response::new(http_body_util::Full::new(Bytes::new()).boxed())
                                })
                        });
                    }
                }
            }
        }

        let mut transformed = body;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        let last_modified = response
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(ref config) = minification {
            if config.enabled.unwrap_or(false) {
                let settings = crate::http::response_transform::MinificationSettings {
                    enabled: true,
                    html: config.enable_html.unwrap_or(true),
                    css: config.enable_css.unwrap_or(true),
                    js: config.enable_js.unwrap_or(true),
                    _marker: std::marker::PhantomData,
                };
                transformed = crate::http::response_transform::apply_minification(
                    transformed,
                    Some(&content_type),
                    &settings,
                );
            }
        }

        if let Some(ref config) = image_protection {
            if config.enabled.unwrap_or(false) && content_type.starts_with("image/") {
                let min_size = config.min_size_bytes.unwrap_or(102400) as u64;
                if transformed.len() as u64 >= min_size {
                    let whitelisted = config
                        .whitelist_patterns
                        .as_ref()
                        .map(|patterns| {
                            patterns.iter().any(|p| {
                                get_cached_regex(p)
                                    .map(|re| re.is_match(request_path))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);

                    if !whitelisted {
                        transformed = self
                            .apply_image_poisoning(
                                transformed,
                                upstream_id,
                                last_modified.clone(),
                                image_poison_config.as_ref(),
                            )
                            .await;
                    }
                }
            }
        }

        if let Some(ref comp_config) = compression {
            if comp_config.enabled.unwrap_or(false) {
                let accept_encoding = response
                    .headers()
                    .get("accept-encoding")
                    .and_then(|v: &http::HeaderValue| v.to_str().ok());

                let settings = crate::http::response_transform::CompressionSettings {
                    enabled: true,
                    brotli_level: comp_config.brotli_level.unwrap_or(6),
                    gzip_level: comp_config.gzip_level.unwrap_or(6),
                    _marker: std::marker::PhantomData,
                };

                let (compressed_body, encoding) =
                    crate::http::response_transform::apply_compression(
                        transformed.clone(),
                        accept_encoding,
                        &settings,
                    );

                if let Some(enc) = encoding {
                    transformed = compressed_body;
                    response.headers_mut().insert(
                        "Content-Encoding",
                        HeaderValue::from_str(&enc)
                            .unwrap_or_else(|_| HeaderValue::from_static("identity")),
                    );
                }
            }
        }

        let full_body = http_body_util::Full::new(transformed.clone());
        let new_body: BoxBody<Bytes, Infallible> = full_body.boxed();

        *response.body_mut() = new_body;

        let content_type_header = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let cached_content_encoding = response
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        {
            self.transform_cache.insert(
                cache_key.clone(),
                TransformCacheEntry {
                    body: transformed.clone(),
                    content_encoding: cached_content_encoding.clone(),
                    content_type: content_type_header.clone(),
                },
            );
        }

        {
            let rs = self.record_store.read();
            if let Some(ref record_store) = *rs {
                let dht_key = crate::mesh::dht::keys::DhtKey::transformed_content(
                    upstream_id,
                    &content_hash,
                    &transform_flags,
                );
                let cache_entry = DhtTransformEntry::from_cache_entry(&TransformCacheEntry {
                    body: transformed,
                    content_encoding: cached_content_encoding,
                    content_type: content_type_header,
                });
                if let Ok(bytes) = serde_json::to_vec(&cache_entry) {
                    record_store.store_and_announce(dht_key.as_str().to_string(), bytes, 3600);
                    tracing::debug!("Stored transformed content in DHT: {}", dht_key.as_str());
                }
            }
        }

        response
    }

    async fn apply_image_poisoning(
        &self,
        body: Bytes,
        site_id: &str,
        last_modified: Option<String>,
        poison_config: Option<&crate::config::site::SiteImagePoisonConfig>,
    ) -> Bytes {
        if body.is_empty() {
            return body;
        }

        let original_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&body);
            hex::encode(hasher.finalize())
        };

        {
            let rs = self.record_store.read();
            if let Some(ref record_store) = *rs {
                let dht_key =
                    crate::mesh::dht::keys::DhtKey::poisoned_image(site_id, &original_hash);
                if let Some(record) = record_store.get_record(&dht_key.as_str()) {
                    tracing::debug!("DHT poisoned image cache hit for {}", dht_key.as_str());
                    return Bytes::from(record.value.clone());
                }
            }
        }

        let static_worker_socket = std::env::var("STATIC_WORKER_SOCKET")
            .unwrap_or_else(|_| "/var/run/maluwaf-static-worker.sock".to_string());

        if static_worker_socket.is_empty() {
            return body;
        }

        let socket_path = std::path::PathBuf::from(&static_worker_socket);

        let client = crate::static_files::client::PoisonImageClient::new(socket_path);

        match client
            .poison_image(
                site_id,
                body.to_vec(),
                last_modified,
                poison_config.and_then(|c| c.level.clone()),
                poison_config.and_then(|c| c.intensity),
                poison_config.and_then(|c| c.seed),
                poison_config.and_then(|c| c.max_dimension),
                poison_config.and_then(|c| c.jpeg_quality),
            )
            .await
        {
            Ok(poisoned) => {
                let dht_key =
                    crate::mesh::dht::keys::DhtKey::poisoned_image(site_id, &original_hash);
                let dht_key_str = dht_key.as_str().to_string();
                {
                    let rs = self.record_store.read();
                    if let Some(ref record_store) = *rs {
                        record_store.store_and_announce(
                            dht_key_str.clone(),
                            poisoned.clone(),
                            3600,
                        );
                        tracing::debug!("Stored poisoned image in DHT: {}", dht_key_str);
                    }
                }
                Bytes::from(poisoned)
            }
            Err(e) => {
                tracing::debug!("Image poisoning failed: {}", e);
                body
            }
        }
    }

    pub fn get_connection_stats(&self) -> MeshProxyStats {
        let now = std::time::Instant::now();

        let mut active: usize = 0;
        let mut avg_duration = std::time::Duration::ZERO;

        for conn in self.active_connections.iter() {
            active += 1;
            avg_duration += now.duration_since(conn.started_at);
        }

        if active > 0 {
            avg_duration /= active as u32;
        }

        MeshProxyStats {
            active_connections: active,
            average_duration: avg_duration,
        }
    }

    pub fn get_transport(&self) -> Arc<RwLock<Option<Arc<MeshTransport>>>> {
        self.transport.clone()
    }

    pub async fn announce_upstream(
        &self,
        upstream_id: &str,
        action: crate::mesh::protocol::AnnounceAction,
    ) -> Result<(), MeshProxyError> {
        if !self.topology.can_forward_service(upstream_id) {
            tracing::debug!(
                "Not announcing upstream {} - service not allowed by policy",
                upstream_id
            );
            return Ok(());
        }

        match action {
            crate::mesh::protocol::AnnounceAction::Add => {
                self.topology
                    .add_local_upstream(upstream_id.to_string(), String::new(), None)
                    .await;
            }
            crate::mesh::protocol::AnnounceAction::Remove => {
                self.topology.remove_local_upstream(upstream_id).await;
            }
            _ => {}
        }

        if let Some(global_id) = self.topology.get_closest_global_node().await {
            tracing::debug!(
                "Announcing upstream {} ({:?}) to global node {}",
                upstream_id,
                action,
                global_id
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MeshProxyStats {
    pub active_connections: usize,
    pub average_duration: std::time::Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum MeshProxyError {
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Peer unhealthy: {0}")]
    PeerUnhealthy(String),
    #[error("Upstream not found: {0}")]
    UpstreamNotFound(String),
    #[error("Peer does not have upstream: {0} -> {1}")]
    PeerDoesNotHaveUpstream(String, String),
    #[error("Upstream not reachable: {0}")]
    UpstreamNotReachable(String),
    #[error("No route to upstream: {0}")]
    NoRouteToUpstream(String),
    #[error("Upstream blocked due to ratelimit: {0}")]
    UpstreamBlocked(String),
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Response build error: {0}")]
    ResponseBuildError(String),
    #[error("Timeout")]
    Timeout,
    #[error("Request timeout after {0}s")]
    RequestTimeout(u64),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Tier threshold not met for upstream: {upstream_id}, alternatives available")]
    TierThresholdNotMet {
        upstream_id: String,
        alternatives: Vec<crate::mesh::protocol::AlternativeProvider>,
    },
}

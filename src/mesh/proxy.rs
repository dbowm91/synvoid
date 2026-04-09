#![allow(unused_variables)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use digest::Digest;
use http::header::HeaderValue;
use http_body::Body as HttpBody;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use moka::sync::Cache;
use parking_lot::RwLock;
use rand::Rng;
use tokio::sync::RwLock as TokioRwLock;

static WHITELIST_REGEX_CACHE: LazyLock<DashMap<String, Option<regex::Regex>>> =
    LazyLock::new(DashMap::new);

fn get_cached_regex(pattern: &str) -> Option<regex::Regex> {
    WHITELIST_REGEX_CACHE
        .entry(pattern.to_string())
        .or_insert_with(|| regex::Regex::new(pattern).ok())
        .value()
        .clone()
}

use crate::mesh::config::MeshConfig;
use crate::mesh::dht::RecordStoreManager;
use crate::mesh::organization::OrganizationManager;
use crate::mesh::protocol::{ProviderInfo, UpstreamProtocol, WafPolicy};
use crate::mesh::topology::MeshTopology;
use crate::mesh::transport::MeshTransport;
use crate::metrics::bandwidth::get_global_bandwidth_tracker_or_log;
use crate::proxy_cache::ProxyCacheSettings;

/// Default TTL for cached routing policies (1 hour)
const DEFAULT_POLICY_CACHE_TTL_SECS: u64 = 3600;
/// Cooldown period after provider failure before retry (10 seconds)
const FAILED_PROVIDER_COOLDOWN_SECS: u64 = 10;
/// TTL for stale cache entries before forcing refresh (60 seconds)
const STALE_CACHE_TTL_SECS: u64 = 60;
/// Maximum exponential backoff delay (120 seconds)
const MAX_EXPONENTIAL_BACKOFF_SECS: u64 = 120;
/// Window for health metrics calculation (5 minutes)
const HEALTH_METRICS_WINDOW_SECS: u64 = 300;
/// Minimum success rate threshold for provider health (50%)
const MIN_SUCCESS_RATE: f64 = 0.5;
/// Number of consecutive provider failures before broadcasting block to mesh
const BLOCK_BROADCAST_FAILURE_THRESHOLD: u32 = 5;
/// Duration to block an upstream when broadcasting to mesh (5 minutes).
/// This is a mesh-internal decision - when we see repeated failures from a provider,
/// we block locally and inform global peers. The actual ratelimit block duration
/// from the origin WAF is preserved when we receive blocks from other nodes.
const BLOCK_DURATION_SECS: u64 = 300;

pub struct MeshProxy {
    config: Arc<MeshConfig>,
    topology: Arc<MeshTopology>,
    transport: Arc<RwLock<Option<Arc<MeshTransport>>>>,
    transport_manager:
        Arc<RwLock<Option<Arc<crate::mesh::transports::manager::MeshTransportManager>>>>,
    record_store: Arc<RwLock<Option<Arc<RecordStoreManager>>>>,
    active_connections: Arc<RwLock<HashMap<String, MeshConnection>>>,
    policy_cache: Cache<String, CachedPolicy>,
    failed_providers: Cache<String, Instant>,
    provider_stats: Cache<String, ProviderStats>,
    org_manager: Arc<TokioRwLock<OrganizationManager>>,
    transform_cache: Arc<Cache<String, TransformCacheEntry>>,
}

struct MeshConnection {
    #[allow(dead_code)]
    peer_node_id: String,
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

#[derive(Clone)]
struct ProviderStats {
    total_requests: u64,
    successful_requests: u64,
    consecutive_failures: u32,
    last_failure: Option<Instant>,
    last_success: Option<Instant>,
    cooldown_until: Option<Instant>,
}

impl ProviderStats {
    fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        self.successful_requests as f64 / self.total_requests as f64
    }

    fn is_healthy(&self) -> bool {
        if let Some(cooldown) = self.cooldown_until {
            if Instant::now() < cooldown {
                return false;
            }
        }
        self.success_rate() >= MIN_SUCCESS_RATE
    }

    fn record_success(&mut self) {
        self.total_requests += 1;
        self.successful_requests += 1;
        self.consecutive_failures = 0;
        self.last_success = Some(Instant::now());
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());

        let backoff_secs = std::cmp::min(
            FAILED_PROVIDER_COOLDOWN_SECS * 2u64.saturating_pow(self.consecutive_failures.min(6)),
            MAX_EXPONENTIAL_BACKOFF_SECS,
        );
        self.cooldown_until = Some(Instant::now() + Duration::from_secs(backoff_secs));
    }

    fn decay(&mut self) {
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
struct TransformCacheEntry {
    body: Bytes,
    content_encoding: Option<String>,
    content_type: Option<String>,
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

const DEFAULT_TRANSFORM_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_TRANSFORM_CACHE_SIZE: usize = 1000;

impl MeshProxy {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        _cache_config: Option<ProxyCacheSettings>,
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
        let provider_stats = Cache::builder()
            .max_capacity(cache_size as u64)
            .time_to_live(Duration::from_secs(HEALTH_METRICS_WINDOW_SECS))
            .build();

        let transform_cache = Cache::builder()
            .max_capacity(DEFAULT_TRANSFORM_CACHE_SIZE as u64)
            .weigher(|_key: &String, value: &TransformCacheEntry| {
                u32::try_from(value.body.len()).unwrap_or(u32::MAX)
            })
            .time_to_live(Duration::from_secs(DEFAULT_TRANSFORM_CACHE_TTL_SECS))
            .build();

        Self {
            config,
            topology,
            transport: Arc::new(RwLock::new(None)),
            transport_manager: Arc::new(RwLock::new(None)),
            record_store: Arc::new(RwLock::new(None)),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            policy_cache,
            failed_providers,
            provider_stats,
            org_manager: Arc::new(TokioRwLock::new(OrganizationManager::new())),
            transform_cache: Arc::new(transform_cache),
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
            let stale_ttl = Duration::from_secs(STALE_CACHE_TTL_SECS);
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
                self.mark_stale_cache_for_refresh(&upstream_id);
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

        let port = uri.port_u16().unwrap_or_else(|| {
            match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            }
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
        if let Some(mut provider_stats) = self.provider_stats.get(provider_node_id) {
            provider_stats.decay();
            self.provider_stats
                .insert(provider_node_id.to_string(), provider_stats.clone());
            return !provider_stats.is_healthy();
        }
        self.is_provider_failed(provider_node_id)
    }

    fn record_provider_success(&self, provider_node_id: &str) {
        self.clear_provider_failure(provider_node_id);

        let mut stats = self
            .provider_stats
            .get(provider_node_id)
            .unwrap_or(ProviderStats {
                total_requests: 0,
                successful_requests: 0,
                consecutive_failures: 0,
                last_failure: None,
                last_success: None,
                cooldown_until: None,
            });
        stats.record_success();
        self.provider_stats
            .insert(provider_node_id.to_string(), stats);
    }

    fn record_provider_failure(&self, provider_node_id: &str) -> u32 {
        let mut stats = self
            .provider_stats
            .get(provider_node_id)
            .unwrap_or(ProviderStats {
                total_requests: 0,
                successful_requests: 0,
                consecutive_failures: 0,
                last_failure: None,
                last_success: None,
                cooldown_until: None,
            });
        stats.record_failure();
        let failure_count = stats.consecutive_failures;
        self.provider_stats
            .insert(provider_node_id.to_string(), stats);
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
                let providers_with_capability: Vec<_> = providers
                    .into_iter()
                    .filter(|p| {
                        if let Some(peer) =
                            futures::executor::block_on(self.topology.get_peer(&p.node_id))
                        {
                            peer.capabilities.can_proxy
                        } else {
                            false
                        }
                    })
                    .collect();
                if providers_with_capability.is_empty() {
                    return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
                }
                Ok(providers_with_capability)
            }
            Err(e) => Err(MeshProxyError::ConnectionFailed(e.to_string())),
        }
    }

    fn weighted_shuffle_providers(&self, providers: Vec<crate::mesh::protocol::ProviderInfo>) -> Vec<crate::mesh::protocol::ProviderInfo> {
        if providers.len() <= 1 {
            return providers;
        }

        let total_score: f64 = providers.iter().map(|p| p.score.max(0.01)).sum();
        let weighted: Vec<(usize, f64)> = providers.iter()
            .enumerate()
            .map(|(i, p)| (i, p.score.max(0.01)))
            .collect();

        let mut result = Vec::with_capacity(providers.len());
        let mut remaining: Vec<usize> = (0..providers.len()).collect();

        while !remaining.is_empty() {
            let r: f64 = rand::rng().random_range(0.0..total_score);
            let mut cumulative = 0.0;
            let mut selected_idx = 0;

            for &idx in &remaining {
                cumulative += weighted[idx].1;
                if cumulative >= r {
                    selected_idx = idx;
                    break;
                }
            }

            result.push(providers[selected_idx].clone());
            remaining.retain(|&x| x != selected_idx);
        }

        result
    }

    // Response transform holds a cache lock across an await; low contention expected.
    #[allow(clippy::await_holding_lock)]
    pub async fn route_request(
        &self,
        upstream_id: &str,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError> {
        loop {
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
                return self
                    .proxy_to_peer_with_fallback(upstream_id, vec![pi], req)
                    .await;
            }

            if let Some(ref c) = cached_for_check {
                let stale_ttl = Duration::from_secs(STALE_CACHE_TTL_SECS);
                if c.expires_at < Instant::now() - stale_ttl {
                    self.mark_stale_cache_for_refresh(upstream_id);
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

            return self
                .proxy_to_peer_with_fallback(upstream_id, providers, req)
                .await;
        }
    }

    async fn proxy_to_peer_with_fallback(
        &self,
        upstream_id: &str,
        providers: Vec<crate::mesh::protocol::ProviderInfo>,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError> {
        if providers.is_empty() {
            return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
        }

        let providers = self.weighted_shuffle_providers(providers);

        // Extract method, uri, and headers before consuming the body
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        // Collect request body upfront since hyper consumes it
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::warn!("Failed to collect request body for retry: {}", e);
                return Err(MeshProxyError::SendFailed(format!(
                    "Failed to collect request body: {}",
                    e
                )));
            }
        };

        let mut last_error = None;

        for (idx, provider) in providers.iter().enumerate() {
            if idx > 0 {
                let wait_time = rand::rng().random_range(10..100);
                tokio::time::sleep(Duration::from_millis(wait_time)).await;
            }

            tracing::debug!(
                "Trying provider {} for {} (attempt {}/{})",
                provider.node_id,
                upstream_id,
                idx + 1,
                providers.len()
            );

            // Build request with original method/URI/headers, preserving client's path
            let request_body = http_body_util::Full::new(body_bytes.clone());
            let mut retry_req = Request::builder().method(method.clone()).uri(uri.clone());
            for (name, value) in headers.iter() {
                retry_req = retry_req.header(name.as_str(), value.to_str().unwrap_or(""));
            }
            let retry_req = retry_req
                .body(request_body)
                .map_err(|e| MeshProxyError::SendFailed(e.to_string()))?;

            match self
                .proxy_to_peer(
                    &provider.node_id,
                    upstream_id,
                    provider.upstream_url.clone(),
                    retry_req,
                )
                .await
            {
                Ok(resp) => {
                    self.record_provider_success(&provider.node_id);

                    if let Some(cached) = self.get_cached_policy(upstream_id) {
                        if cached.provider_node_id != provider.node_id {
                            let updated = CachedPolicy {
                                provider_node_id: provider.node_id.clone(),
                                upstream_url: provider.upstream_url.clone(),
                                waf_policy: provider.waf_policy.clone(),
                                protocol: UpstreamProtocol::Http,
                                priority_tier: provider.priority_tier,
                                expires_at: Instant::now()
                                    + Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
                            };
                            self.cache_policy(upstream_id, updated);
                        }
                    }

                    let request_size =
                        body_bytes.len() + format!("{} {} HTTP/1.1\r\n", method, uri).len();
                    let response_size = resp.body().size_hint().exact().unwrap_or(0);

                    if let Some(bandwidth) = get_global_bandwidth_tracker_or_log() {
                        bandwidth.record_site_mesh_egress(upstream_id, request_size as u64);
                        bandwidth.record_site_mesh_ingress(upstream_id, response_size);
                    }

                    tracing::info!(
                        "Successfully proxied to {} via provider {} (tried {}/{})",
                        upstream_id,
                        provider.node_id,
                        idx + 1,
                        providers.len()
                    );
                    return Ok(resp);
                }
                Err(e) => {
                    let failure_count = self.record_provider_failure(&provider.node_id);

                    let tm = {
                        let guard = self.transport_manager.read();
                        guard.clone()
                    };
                    if let Some(ref tm) = tm {
                        tm.report_reachability(
                            upstream_id,
                            &provider.node_id,
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
                        "Provider {} failed for {} (attempt {}/{}): {}",
                        provider.node_id,
                        upstream_id,
                        idx + 1,
                        providers.len(),
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| MeshProxyError::NoRouteToUpstream(upstream_id.to_string())))
    }

    fn mark_stale_cache_for_refresh(&self, upstream_id: &str) {
        if let Some(cached) = self.policy_cache.get(upstream_id) {
            let refreshed = CachedPolicy {
                provider_node_id: cached.provider_node_id,
                upstream_url: cached.upstream_url,
                waf_policy: cached.waf_policy,
                protocol: cached.protocol,
                priority_tier: cached.priority_tier,
                expires_at: Instant::now() + Duration::from_secs(1),
            };
            self.policy_cache.insert(upstream_id.to_string(), refreshed);
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

        let response = self
            .proxy_to_peer_with_fallback(upstream_id, providers, req)
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
        req: Request<B>,
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
        {
            let mut connections = self.active_connections.write();
            connections.insert(
                request_id.clone(),
                MeshConnection {
                    peer_node_id: peer_node_id.to_string(),
                    request_id: request_id.clone(),
                    started_at: std::time::Instant::now(),
                },
            );
        }

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

        let response = transport
            .proxy_http_request(peer_node_id, &target_url, req)
            .await
            .map_err(|e| MeshProxyError::ConnectionFailed(e.to_string()))?;

        {
            let mut connections = self.active_connections.write();
            connections.remove(&request_id);
        }

        let response = self.transform_response(response, upstream_id, &uri).await;

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

        {
            let mut rs = self.record_store.write();
            if rs.is_none() {
                if let Some(record_store) = tm.get_record_store() {
                    *rs = Some(record_store);
                }
            }
        }

        if image_protection.is_none()
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
            "min:{}:{}:{}:{},img:{}:{}",
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
        let connections = self.active_connections.read();
        let now = std::time::Instant::now();

        let mut active: usize = 0;
        let mut avg_duration = std::time::Duration::ZERO;

        for conn in connections.values() {
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
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Tier threshold not met for upstream: {upstream_id}, alternatives available")]
    TierThresholdNotMet {
        upstream_id: String,
        alternatives: Vec<crate::mesh::protocol::AlternativeProvider>,
    },
}

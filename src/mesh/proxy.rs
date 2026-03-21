#![allow(unused_variables, dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body::Body as HttpBody;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use hyper::body::Incoming;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use rand::Rng;
use tokio::sync::{Mutex, RwLock as TokioRwLock};
use parking_lot::Mutex as PLMutex;

use crate::mesh::config::{MeshConfig, MeshMinificationConfig};
use crate::mesh::organization::OrganizationManager;
use crate::mesh::protocol::{ProviderInfo, UpstreamProtocol, WafPolicy};
use crate::mesh::topology::MeshTopology;
use crate::mesh::transport::MeshTransport;
use crate::proxy_cache::{ProxyCache, ProxyCacheSettings, CacheKeyBuilder};
use crate::metrics::bandwidth::get_global_bandwidth_tracker_or_log;

/// Default TTL for cached routing policies (1 hour)
const DEFAULT_POLICY_CACHE_TTL_SECS: u64 = 3600;
/// Cooldown period after provider failure before retry (10 seconds)
const FAILED_PROVIDER_COOLDOWN_SECS: u64 = 10;
/// TTL for stale cache entries before forcing refresh (60 seconds)
const STALE_CACHE_TTL_SECS: u64 = 60;
/// Maximum number of concurrent route queries
const MAX_IN_FLIGHT_QUERIES: usize = 100;
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
    transport_manager: Arc<RwLock<Option<Arc<crate::mesh::transports::manager::MeshTransportManager>>>>,
    active_connections: Arc<RwLock<HashMap<String, MeshConnection>>>,
    policy_cache: Arc<Mutex<LruCache<String, CachedPolicy>>>,
    failed_providers: Arc<Mutex<LruCache<String, Instant>>>,
    in_flight_queries: Arc<Mutex<LruCache<String, InFlightQuery>>>,
    provider_stats: Arc<Mutex<LruCache<String, ProviderStats>>>,
    org_manager: Arc<TokioRwLock<OrganizationManager>>,
    proxy_cache: Option<Arc<ProxyCache>>,
    cache_key_builder: Option<CacheKeyBuilder>,
    minifier_generator: Arc<crate::static_files::minifier::MinifierGenerator>,
    transform_cache: Arc<PLMutex<LruCache<String, TransformCacheEntry>>>,
}

struct MeshConnection {
    peer_node_id: String,
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

struct InFlightQuery {
    provider: Option<ProviderInfo>,
    completed: bool,
    failed: bool,
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
    created_at: Instant,
}

const DEFAULT_TRANSFORM_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_TRANSFORM_CACHE_SIZE: usize = 1000;

impl MeshProxy {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        cache_config: Option<ProxyCacheSettings>,
    ) -> Self {
        let cache_size = config.persistence.policy_cache_size.max(100);
        let cache = LruCache::with_expiry_duration_and_capacity(
            Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
            cache_size,
        );
        let failed_cache = LruCache::with_expiry_duration_and_capacity(
            Duration::from_secs(FAILED_PROVIDER_COOLDOWN_SECS * 2),
            cache_size,
        );
        let in_flight_cache = LruCache::with_expiry_duration_and_capacity(
            Duration::from_secs(30),
            MAX_IN_FLIGHT_QUERIES,
        );
        let stats_cache = LruCache::with_expiry_duration_and_capacity(
            Duration::from_secs(HEALTH_METRICS_WINDOW_SECS),
            cache_size,
        );

        let (proxy_cache, cache_key_builder) = if let Some(cc) = cache_config {
            if cc.enabled {
                let pc = Arc::new(ProxyCache::new(cc.clone()));
                let kb = CacheKeyBuilder::new(cc.key_pattern.clone(), cc.vary_by.clone());
                (Some(pc), Some(kb))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let transform_cache = LruCache::with_expiry_duration_and_capacity(
            Duration::from_secs(DEFAULT_TRANSFORM_CACHE_TTL_SECS),
            DEFAULT_TRANSFORM_CACHE_SIZE,
        );

        Self {
            config,
            topology,
            transport: Arc::new(RwLock::new(None)),
            transport_manager: Arc::new(RwLock::new(None)),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            policy_cache: Arc::new(Mutex::new(cache)),
            failed_providers: Arc::new(Mutex::new(failed_cache)),
            in_flight_queries: Arc::new(Mutex::new(in_flight_cache)),
            provider_stats: Arc::new(Mutex::new(stats_cache)),
            org_manager: Arc::new(TokioRwLock::new(OrganizationManager::new())),
            proxy_cache,
            cache_key_builder,
            minifier_generator: Arc::new(crate::static_files::minifier::MinifierGenerator::new()),
            transform_cache: Arc::new(PLMutex::new(transform_cache)),
        }
    }

    pub fn set_transport(&self, transport: Arc<MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    pub fn set_transport_manager(&self, manager: Arc<crate::mesh::transports::manager::MeshTransportManager>) {
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
        mgr.issue_tier_key(org_id, tier, key, valid_from, valid_until, "self".to_string())
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
        if let Some(transport) = self.transport.read().as_ref() {
            transport.broadcast_upstream_block(upstream_id, reason, blocked_duration_secs).await;
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
            
            let peer_healthy = if let Some(peer) = self.topology.get_peer(&cached.provider_node_id).await {
                peer.is_healthy()
            } else {
                false
            };
            
            if peer_healthy && !is_stale {
                tracing::debug!("Using cached policy for {}", upstream_id);
                return Ok((upstream_id, cached));
            }
            
            if peer_healthy && is_stale && !self.is_provider_failed(&cached.provider_node_id) {
                tracing::debug!("Returning stale cached policy for {}, will revalidate in background", upstream_id);
                self.mark_stale_cache_for_refresh(&upstream_id);
                return Ok((upstream_id, cached));
            }
            
            if self.is_provider_failed(&cached.provider_node_id) {
                tracing::debug!("Cached provider {} is in cooldown for {}", cached.provider_node_id, upstream_id);
            }
        }

        let provider_info = {
            let transport = self.transport.read();
            match transport.as_ref() {
                Some(t) => {
                    match t.send_route_query(&upstream_id).await {
                        Ok(result) => {
                            let providers = self.filter_failed_providers(&result.providers);
                            
                            let tier_filtered = self.filter_by_tier_threshold(&providers);
                            
                            if tier_filtered.is_empty() && !providers.is_empty() {
                                tracing::warn!(
                                    "All providers for {} filtered by tier threshold {}, returning alternatives for redirect",
                                    upstream_id,
                                    self.min_tier_threshold()
                                );
                                let alternatives: Vec<_> = providers.iter()
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
                                        tracing::warn!("All providers failed for {}, using stale cache", upstream_id);
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
                                tracing::warn!("Route query failed for {}, using stale cache: {}", upstream_id, e);
                                return Ok((upstream_id, cached));
                            }
                            return Err(MeshProxyError::ConnectionFailed(e.to_string()));
                        }
                    }
                }
                None => {
                    return Err(MeshProxyError::ConnectionFailed("Transport not initialized".to_string()));
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
        let host = uri.host()
            .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
            .ok_or_else(|| MeshProxyError::UpstreamNotFound("No host found".to_string()))?;

        let path = uri.path();
        let first_segment = path.split('/')
            .filter(|s| !s.is_empty())
            .next()
            .map(|s| s.to_string());

        let upstream_id = match first_segment {
            Some(seg) => format!("{}:{}", host, seg),
            None => host.to_string(),
        };

        Ok(upstream_id)
    }

    fn detect_protocol(req: &Request<Incoming>) -> UpstreamProtocol {
        let uri = req.uri();
        
        if let Some(upgrade) = req.headers().get("upgrade") {
            if let Ok(upgrade_str) = upgrade.to_str() {
                if upgrade_str.eq_ignore_ascii_case("websocket") {
                    if uri.scheme().map(|s| s == "https").unwrap_or(false) {
                        return UpstreamProtocol::Websockets;
                    }
                    return UpstreamProtocol::Websocket;
                }
            }
        }

        if let Some(content_type) = req.headers().get("content-type") {
            if let Ok(ct) = content_type.to_str() {
                if ct.contains("application/grpc") {
                    return UpstreamProtocol::Grpc;
                }
            }
        }

        if let Some(scheme) = uri.scheme() {
            match scheme.as_str() {
                "https" => return UpstreamProtocol::Https,
                "http" => return UpstreamProtocol::Http,
                "wss" => return UpstreamProtocol::Websockets,
                "ws" => return UpstreamProtocol::Websocket,
                "grpc" => return UpstreamProtocol::Grpc,
                "tcp" => return UpstreamProtocol::Tcp,
                "udp" => return UpstreamProtocol::Udp,
                _ => {}
            }
        }

        let port = uri.port_u16().unwrap_or(80);
        match port {
            443 => UpstreamProtocol::Https,
            8443 => UpstreamProtocol::Https,
            4433 => UpstreamProtocol::Https,
            80 => UpstreamProtocol::Http,
            8080 => UpstreamProtocol::Http,
            _ => UpstreamProtocol::Http,
        }
    }

    fn get_cached_policy(&self, upstream_id: &str) -> Option<CachedPolicy> {
        match self.policy_cache.try_lock() {
            Ok(mut cache) => cache.get(upstream_id).cloned(),
            Err(_) => None,
        }
    }

    fn cache_policy(&self, upstream_id: &str, policy: CachedPolicy) {
        if let Ok(mut cache) = self.policy_cache.try_lock() {
            cache.insert(upstream_id.to_string(), policy);
        }
    }

    fn is_provider_failed(&self, provider_node_id: &str) -> bool {
        match self.failed_providers.try_lock() {
            Ok(mut failed) => failed.get(provider_node_id).is_some(),
            Err(_) => false,
        }
    }

    fn mark_provider_failed(&self, provider_node_id: &str) {
        if let Ok(mut failed) = self.failed_providers.try_lock() {
            failed.insert(provider_node_id.to_string(), Instant::now());
        }
    }

    fn clear_provider_failure(&self, provider_node_id: &str) {
        if let Ok(mut failed) = self.failed_providers.try_lock() {
            failed.remove(provider_node_id);
        }
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

    async fn validate_provider_tier(&self, provider: &ProviderInfo) -> bool {
        if let Some(ref claim) = provider.tier_claim {
            if claim.tier > 0 {
                return self.validate_tier_claim(claim).await;
            }
        }
        true
    }

    fn is_provider_unhealthy(&self, provider_node_id: &str) -> bool {
        if let Ok(mut stats) = self.provider_stats.try_lock() {
            if let Some(provider_stats) = stats.get_mut(provider_node_id) {
                provider_stats.decay();
                return !provider_stats.is_healthy();
            }
        }
        self.is_provider_failed(provider_node_id)
    }

    fn record_provider_success(&self, provider_node_id: &str) {
        self.clear_provider_failure(provider_node_id);
        
        if let Ok(mut stats) = self.provider_stats.try_lock() {
            let stats = stats.entry(provider_node_id.to_string()).or_insert_with(|| ProviderStats {
                total_requests: 0,
                successful_requests: 0,
                consecutive_failures: 0,
                last_failure: None,
                last_success: None,
                cooldown_until: None,
            });
            stats.record_success();
        }
    }

    fn record_provider_failure(&self, provider_node_id: &str) -> u32 {
        let mut failure_count = 0u32;
        if let Ok(mut stats) = self.provider_stats.try_lock() {
            let stats = stats.entry(provider_node_id.to_string()).or_insert_with(|| ProviderStats {
                total_requests: 0,
                successful_requests: 0,
                consecutive_failures: 0,
                last_failure: None,
                last_success: None,
                cooldown_until: None,
            });
            stats.record_failure();
            failure_count = stats.consecutive_failures;
        }
        self.mark_provider_failed(provider_node_id);
        failure_count
    }

    async fn get_or_initiate_route_query(
        &self,
        upstream_id: &str,
    ) -> Result<ProviderInfo, MeshProxyError> {
        let should_initiate = {
            match self.in_flight_queries.try_lock() {
                Ok(mut in_flight) => {
                    if in_flight.get(upstream_id).is_some() {
                        false
                    } else {
                        in_flight.insert(upstream_id.to_string(), InFlightQuery {
                            provider: None,
                            completed: false,
                            failed: false,
                        });
                        true
                    }
                }
                Err(_) => true,
            }
        };

        if !should_initiate {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return self.execute_route_query(upstream_id).await;
        }

        let result = self.execute_route_query(upstream_id).await;

        {
            if let Ok(mut in_flight) = self.in_flight_queries.try_lock() {
                if let Some(query) = in_flight.get_mut(upstream_id) {
                    query.completed = true;
                    if let Ok(ref p) = result {
                        query.provider = Some(p.clone());
                    } else {
                        query.failed = true;
                    }
                }
                in_flight.remove(upstream_id);
            }
        }

        result
    }

    async fn execute_route_query(&self, upstream_id: &str) -> Result<ProviderInfo, MeshProxyError> {
        let transport = self.transport.read();
        let transport = transport.as_ref()
            .ok_or_else(|| MeshProxyError::ConnectionFailed("Transport not initialized".to_string()))?;

        match transport.send_route_query(upstream_id).await {
            Ok(result) => {
                let providers = self.filter_failed_providers(&result.providers);
                if providers.is_empty() {
                    return Err(MeshProxyError::NoRouteToUpstream(upstream_id.to_string()));
                }
                Ok(providers.into_iter().next().unwrap())
            }
            Err(e) => Err(MeshProxyError::ConnectionFailed(e.to_string())),
        }
    }

    pub async fn route_request(
        &self,
        upstream_id: &str,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshProxyError> {
        loop {
            if self.topology.is_upstream_blocked(upstream_id).await {
                tracing::warn!("Upstream {} is blocked due to ratelimit", upstream_id);
                
                if let Some(blocked_until) = self.topology.get_blocked_until(upstream_id).await {
                    let remaining_secs = blocked_until.saturating_duration_since(Instant::now()).as_secs();
                    
                    if remaining_secs < 5 {
                        let wait_time = rand::rng().random_range(0..=5);
                        tracing::debug!("Blocking period < 5s, waiting {}s before retry", wait_time);
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
                return self.proxy_to_peer_with_fallback(upstream_id, vec![pi], req).await;
            }

            if let Some(ref c) = cached_for_check {
                let stale_ttl = Duration::from_secs(STALE_CACHE_TTL_SECS);
                if c.expires_at < Instant::now() - stale_ttl {
                    self.mark_stale_cache_for_refresh(upstream_id);
                }
            }

            let provider = match self.get_or_initiate_route_query(upstream_id).await {
                Ok(p) => p,
                Err(e) => {
                    if let Some(cached) = self.get_cached_policy(upstream_id) {
                        tracing::warn!("Route query failed for {}, using stale cache: {}", upstream_id, e);
                        return self.proxy_to_peer(&cached.provider_node_id, upstream_id, cached.upstream_url.clone(), req).await;
                    }
                    return Err(e);
                }
            };

            let cached = CachedPolicy {
                provider_node_id: provider.node_id.clone(),
                upstream_url: provider.upstream_url.clone(),
                waf_policy: provider.waf_policy.clone(),
                protocol: UpstreamProtocol::Http,
                priority_tier: provider.priority_tier,
                expires_at: Instant::now() + Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
            };
            self.cache_policy(upstream_id, cached);

            return self.proxy_to_peer_with_fallback(upstream_id, vec![provider], req).await;
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

        // Extract method, uri, and headers before consuming the body
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        // Collect request body upfront since hyper consumes it
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::warn!("Failed to collect request body for retry: {}", e);
                return Err(MeshProxyError::SendFailed(format!("Failed to collect request body: {}", e)));
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
                provider.node_id, upstream_id, idx + 1, providers.len()
            );

            // Build request with original method/URI/headers, preserving client's path
            let request_body = http_body_util::Full::new(body_bytes.clone());
            let mut retry_req = Request::builder()
                .method(method.clone())
                .uri(uri.clone());
            for (name, value) in headers.iter() {
                retry_req = retry_req.header(name.as_str(), value.to_str().unwrap_or(""));
            }
            let retry_req = retry_req
                .body(request_body)
                .map_err(|e| MeshProxyError::SendFailed(e.to_string()))?;

            match self.proxy_to_peer(&provider.node_id, upstream_id, provider.upstream_url.clone(), retry_req).await {
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
                                expires_at: Instant::now() + Duration::from_secs(DEFAULT_POLICY_CACHE_TTL_SECS),
                            };
                            self.cache_policy(upstream_id, updated);
                        }
                    }
                    
                    let request_size = body_bytes.len() + format!("{} {} HTTP/1.1\r\n", method, uri).len();
                    let response_size = resp.body().size_hint().exact().unwrap_or(0);
                    
                    if let Some(bandwidth) = get_global_bandwidth_tracker_or_log() {
                        bandwidth.record_site_mesh_egress(upstream_id, request_size as u64);
                        bandwidth.record_site_mesh_ingress(upstream_id, response_size as u64);
                    }
                    
                    tracing::info!(
                        "Successfully proxied to {} via provider {} (tried {}/{})",
                        upstream_id, provider.node_id, idx + 1, providers.len()
                    );
                    return Ok(resp);
                }
                Err(e) => {
                    let failure_count = self.record_provider_failure(&provider.node_id);
                    
                    if failure_count >= BLOCK_BROADCAST_FAILURE_THRESHOLD {
                        if !self.topology.is_upstream_blocked(upstream_id).await {
                            tracing::warn!(
                                upstream_id, failure_count,
                                "Upstream {} has {} consecutive failures - broadcasting block to mesh",
                                upstream_id, failure_count
                            );
                            self.block_and_broadcast_upstream(
                                upstream_id,
                                "provider_consecutive_failures",
                                BLOCK_DURATION_SECS,
                            ).await;
                        }
                    }
                    
                    tracing::warn!(
                        "Provider {} failed for {} (attempt {}/{}): {}",
                        provider.node_id, upstream_id, idx + 1, providers.len(), e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            MeshProxyError::NoRouteToUpstream(upstream_id.to_string())
        }))
    }

    fn mark_stale_cache_for_refresh(&self, upstream_id: &str) {
        let upstream_id_owned = upstream_id.to_string();
        if let Ok(mut cache) = self.policy_cache.try_lock() {
            if let Some(cached) = cache.get(&upstream_id_owned).cloned() {
                let refreshed = CachedPolicy {
                    provider_node_id: cached.provider_node_id,
                    upstream_url: cached.upstream_url,
                    waf_policy: cached.waf_policy,
                    protocol: cached.protocol,
                    priority_tier: cached.priority_tier,
                    expires_at: Instant::now() + Duration::from_secs(1),
                };
                cache.insert(upstream_id_owned, refreshed);
            }
        }
    }

    pub async fn route_request_with_policy(
        &self,
        upstream_id: &str,
        req: Request<Incoming>,
    ) -> Result<(Response<BoxBody<Bytes, Infallible>>, Option<WafPolicy>), MeshProxyError> {
        let provider_info = match self.get_or_initiate_route_query(upstream_id).await {
            Ok(p) => p,
            Err(e) => {
                if let Some(cached) = self.get_cached_policy(upstream_id) {
                    tracing::warn!("Route query failed for {}, using stale cache: {}", upstream_id, e);
                    let response = self.proxy_to_peer(&cached.provider_node_id, upstream_id, cached.upstream_url.clone(), req).await;
                    return response.map(|r| (r, cached.waf_policy));
                }
                return Err(e);
            }
        };

        let response = self.proxy_to_peer(&provider_info.node_id, upstream_id, provider_info.upstream_url.clone(), req).await;

        match response {
            Ok(resp) => {
                self.record_provider_success(&provider_info.node_id);
                Ok((resp, provider_info.waf_policy))
            }
            Err(e) => {
                let _failure_count = self.record_provider_failure(&provider_info.node_id);
                tracing::warn!("Provider {} failed for {}: {}", provider_info.node_id, upstream_id, e);
                Err(e)
            }
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

        let transport = self.transport.read();
        let transport = transport.as_ref()
            .ok_or_else(|| MeshProxyError::ConnectionFailed("Transport not initialized".to_string()))?;

        let response = transport.proxy_http_request(peer_node_id, &target_url, req).await
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
        let tm = self.transport_manager.read();
        let tm = tm.as_ref();

        if tm.is_none() {
            return response;
        }

        let tm = tm.unwrap();

        let image_protection = tm.get_image_protection_for_site(upstream_id).await;
        let compression = tm.get_compression_for_site(upstream_id).await;
        let minification = tm.get_minification_for_site(upstream_id).await;

        if image_protection.is_none() && compression.is_none() && minification.is_none() {
            return response;
        }

        let cache_key = format!(
            "{}:{}:{:?}:{:?}",
            upstream_id,
            request_path,
            minification.as_ref().and_then(|c| c.enabled),
            image_protection.as_ref().and_then(|c| c.enabled),
        );

        {
            let mut cache = self.transform_cache.lock();
            if let Some(entry) = cache.get(&cache_key) {
                tracing::debug!("Transform cache hit for {}", cache_key);
                let mut new_response = Response::builder()
                    .status(200);
                
                if let Some(ref enc) = entry.content_encoding {
                    new_response = new_response.header("Content-Encoding", enc.as_str());
                }
                if let Some(ref ct) = entry.content_type {
                    new_response = new_response.header("Content-Type", ct.as_str());
                }
                
                let body = http_body_util::Full::new(entry.body.clone()).boxed();
                return new_response.body(body).unwrap();
            }
        }

        let content_type = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        let last_modified = response.headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body = std::mem::replace(response.body_mut(), http_body_util::Full::new(Bytes::new()).boxed());

        let body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return response,
        };

        if body.is_empty() {
            return response;
        }

        let mut transformed = body;

        if let Some(ref config) = minification {
            if config.enabled.unwrap_or(false) {
                transformed = self.apply_minification(transformed, &content_type, config);
            }
        }

        if let Some(ref config) = image_protection {
            if config.enabled.unwrap_or(false) && content_type.starts_with("image/") {
                let min_size = config.min_size_bytes.unwrap_or(102400) as u64;
                if transformed.len() as u64 >= min_size {
                    let whitelisted = config.whitelist_patterns.as_ref()
                        .map(|patterns| {
                            patterns.iter().any(|p| {
                                regex::Regex::new(p)
                                    .map(|re| re.is_match(upstream_id))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);

                    if !whitelisted {
                        transformed = self.apply_image_poisoning(transformed, upstream_id, last_modified.clone()).await;
                    }
                }
            }
        }

        if let Some(ref comp_config) = compression {
            if comp_config.enabled.unwrap_or(false) {
                let accept_encoding = response.headers()
                    .get("accept-encoding")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                
                if accept_encoding.contains("br") {
                    if let Ok(compressed) = self.minifier_generator.compress_brotli(&transformed, comp_config.brotli_level.unwrap_or(6) as u32) {
                        transformed = Bytes::from(compressed);
                        response.headers_mut()
                            .insert("Content-Encoding", "br".parse().unwrap());
                    }
                } else if accept_encoding.contains("gzip") {
                    let gzip_level = comp_config.gzip_level.unwrap_or(6) as u32;
                    if let Ok(compressed) = self.minifier_generator.compress_gzip(&transformed, gzip_level) {
                        transformed = Bytes::from(compressed);
                        response.headers_mut()
                            .insert("Content-Encoding", "gzip".parse().unwrap());
                    }
                }
            }
        }

        let full_body = http_body_util::Full::new(transformed.clone());
        let new_body: BoxBody<Bytes, Infallible> = full_body.boxed();

        *response.body_mut() = new_body;

        let content_type_header = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let cached_content_encoding = response.headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        {
            let mut cache = self.transform_cache.lock();
            cache.insert(cache_key, TransformCacheEntry {
                body: transformed,
                content_encoding: cached_content_encoding,
                content_type: content_type_header,
                created_at: Instant::now(),
            });
        }

        response
    }

    fn apply_minification(
        &self,
        body: Bytes,
        content_type: &str,
        config: &MeshMinificationConfig,
    ) -> Bytes {
        let ct = content_type.to_lowercase();
        
        if ct.contains("text/html") || ct.contains("text/css") || ct.contains("javascript") {
            if ct.contains("text/html") {
                if let Ok(text) = String::from_utf8(body.to_vec()) {
                    if let Ok(minified) = self.minifier_generator.minify_html(&text) {
                        return Bytes::from(minified);
                    }
                }
            } else if ct.contains("text/css") {
                if let Ok(text) = String::from_utf8(body.to_vec()) {
                    if let Ok(minified) = self.minifier_generator.minify_css(&text) {
                        return Bytes::from(minified);
                    }
                }
            } else if ct.contains("javascript") {
                if let Ok(text) = String::from_utf8(body.to_vec()) {
                    if let Ok(minified) = self.minifier_generator.minify_js(&text) {
                        return Bytes::from(minified);
                    }
                }
            }
        }

        body
    }

    async fn apply_image_poisoning(
        &self,
        body: Bytes,
        site_id: &str,
        last_modified: Option<String>,
    ) -> Bytes {
        if body.is_empty() {
            return body;
        }

        let static_worker_socket = std::env::var("STATIC_WORKER_SOCKET")
            .unwrap_or_else(|_| "/var/run/maluwaf-static-worker.sock".to_string());

        if static_worker_socket.is_empty() {
            return body;
        }

        let socket_path = std::path::PathBuf::from(&static_worker_socket);

        let client = crate::static_files::client::PoisonImageClient::new(socket_path);

        match client.poison_image(site_id, body.to_vec(), last_modified).await {
            Ok(poisoned) => Bytes::from(poisoned),
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
            tracing::debug!("Not announcing upstream {} - service not allowed by policy", upstream_id);
            return Ok(());
        }

        match action {
            crate::mesh::protocol::AnnounceAction::Add => {
                self.topology.add_local_upstream(
                    upstream_id.to_string(),
                    String::new(),
                    None,
                ).await;
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

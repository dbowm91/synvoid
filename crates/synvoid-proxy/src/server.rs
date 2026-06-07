//! ProxyServer extracted from root `src/proxy/mod.rs`.
//!
//! Contains the core `ProxyServer` struct that orchestrates upstream
//! request forwarding, WAF integration, proxy caching, retry/backoff,
//! and metrics collection.

use ::metrics::{counter, histogram};
use http::Response;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::streaming::TeeBody;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

use subtle::ConstantTimeEq;

use synvoid_config::site::{BufferingConfig, ProxyHeadersConfig, RetryConfig};
use synvoid_http_client::{
    create_http_client_with_config, create_upstream_client, is_quictunnel_url,
    send_request_erased_streaming, send_request_with_body_headers_and_timeout, BoxErasedBody,
    ErasedBodyImpl, ErasedHttpClient, HttpClient, UpstreamTlsConfig,
};

use crate::cache::{
    build_cached_response as build_cached_response_impl,
    filter_cacheable_headers as filter_cacheable_headers_impl,
    get_cache_max_age_static as get_cache_max_age_static_impl, join_upstream_url,
};
use crate::headers::{build_forward_headers, ForwardedProtocol};
use crate::retry::{
    calculate_backoff as calculate_backoff_impl, is_connection_error as is_connection_error_impl,
    is_retryable_status as is_retryable_status_impl, is_timeout_error as is_timeout_error_impl,
    should_retry_request as should_retry_request_impl,
};
use synvoid_core::ids::{RequestId, SiteId};
use synvoid_core::request::RequestContext;
use synvoid_metrics::{record_proxy_cache_hit, record_proxy_cache_miss};
use synvoid_proxy_cache::{CacheHit, CacheKey, CacheKeyBuilder, ProxyCache, ProxyCacheEntry};
use synvoid_upstream::{Backend, UpstreamPool};
use synvoid_waf::traits::{BlockListStore, TarpitService, ThreatLevelProvider, WafProcessor};
use synvoid_waf::ConnectionLimiter;
use synvoid_waf::UpstreamErrorTracker;
pub use synvoid_waf::WafDecision;

pub type ProxyResponse = Response<BoxBody<Bytes, std::io::Error>>;

/// Trait for handling QUIC tunnel requests. Root crate provides the implementation
/// since it depends on tunnel-specific types not available in the proxy crate.
#[async_trait::async_trait]
pub trait QuicTunnelSender: Send + Sync + 'static {
    async fn send_via_quic_tunnel(
        &self,
        method: http::Method,
        url: &str,
        headers: Option<&http::HeaderMap>,
        body: Option<Bytes>,
        timeout: Option<Duration>,
    ) -> Result<(u16, Vec<(String, String)>, Bytes), Box<dyn std::error::Error + Send + Sync>>;
}

pub struct ProxyServer<W: WafProcessor> {
    _client: HttpClient,
    revalidation_client: HttpClient,
    erased_client: ErasedHttpClient,
    upstream_url: String,
    waf: Arc<W>,
    max_response_size: usize,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    site_id: String,
    upstream_pool: Option<Arc<UpstreamPool>>,
    retry_config: Option<RetryConfig>,
    buffering_config: Option<BufferingConfig>,
    cache: Option<Arc<ProxyCache>>,
    cache_key_builder: Option<CacheKeyBuilder>,
    skip_verify: bool,
    cache_purge_token: Option<String>,
    cache_purge_allowed_ips: Arc<HashSet<std::net::IpAddr>>,
    #[allow(dead_code)]
    pool_max_idle_per_host: usize,
    #[allow(dead_code)]
    pool_idle_timeout: Duration,
    is_http2: bool,
    proxy_headers_config: Option<Arc<ProxyHeadersConfig>>,
    drop_blocked_requests: bool,
    connection_limiter: Option<Arc<ConnectionLimiter>>,
    threat_level_provider: Option<Arc<dyn ThreatLevelProvider>>,
    tarpit_service: Option<Arc<dyn TarpitService>>,
    block_store: Option<Arc<dyn BlockListStore>>,
    quic_tunnel_sender: Option<Arc<dyn QuicTunnelSender>>,
}

impl<W: WafProcessor> ProxyServer<W> {
    pub fn new(
        upstream_url: String,
        waf: Arc<W>,
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
        drop_blocked_requests: bool,
        connection_limiter: Option<Arc<ConnectionLimiter>>,
        threat_level_provider: Option<Arc<dyn ThreatLevelProvider>>,
        tarpit_service: Option<Arc<dyn TarpitService>>,
        block_store: Option<Arc<dyn BlockListStore>>,
    ) -> Self {
        Self::new_with_pool_config(
            upstream_url,
            waf,
            max_response_size,
            upstream_error_tracker,
            site_id,
            None,
            100,
            Duration::from_secs(30),
            drop_blocked_requests,
            connection_limiter,
            threat_level_provider,
            tarpit_service,
            block_store,
        )
    }

    pub fn new_with_tls(
        upstream_url: String,
        waf: Arc<W>,
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
        tls_config: Option<&UpstreamTlsConfig>,
        drop_blocked_requests: bool,
        connection_limiter: Option<Arc<ConnectionLimiter>>,
        threat_level_provider: Option<Arc<dyn ThreatLevelProvider>>,
        tarpit_service: Option<Arc<dyn TarpitService>>,
        block_store: Option<Arc<dyn BlockListStore>>,
    ) -> Self {
        Self::new_with_pool_config(
            upstream_url,
            waf,
            max_response_size,
            upstream_error_tracker,
            site_id,
            tls_config,
            100,
            Duration::from_secs(30),
            drop_blocked_requests,
            connection_limiter,
            threat_level_provider,
            tarpit_service,
            block_store,
        )
    }

    pub fn new_with_pool_config(
        upstream_url: String,
        waf: Arc<W>,
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
        tls_config: Option<&UpstreamTlsConfig>,
        pool_max_idle_per_host: usize,
        pool_idle_timeout: Duration,
        drop_blocked_requests: bool,
        connection_limiter: Option<Arc<ConnectionLimiter>>,
        threat_level_provider: Option<Arc<dyn ThreatLevelProvider>>,
        tarpit_service: Option<Arc<dyn TarpitService>>,
        block_store: Option<Arc<dyn BlockListStore>>,
    ) -> Self {
        let (client, revalidation_client) = if let Some(tls) = tls_config {
            (
                create_upstream_client(
                    Duration::from_secs(5),
                    pool_max_idle_per_host,
                    pool_idle_timeout,
                    tls,
                ),
                create_upstream_client(
                    Duration::from_secs(5),
                    pool_max_idle_per_host,
                    pool_idle_timeout,
                    tls,
                ),
            )
        } else {
            (
                create_http_client_with_config(
                    Duration::from_secs(5),
                    pool_max_idle_per_host,
                    pool_idle_timeout,
                ),
                create_http_client_with_config(
                    Duration::from_secs(5),
                    pool_max_idle_per_host,
                    pool_idle_timeout,
                ),
            )
        };

        let skip_verify = tls_config.map(|t| t.skip_verify).unwrap_or(false);

        ProxyServer {
            erased_client: ErasedHttpClient::new(100),
            _client: client,
            revalidation_client,
            upstream_url,
            waf,
            max_response_size,
            upstream_error_tracker,
            site_id,
            upstream_pool: None,
            retry_config: None,
            buffering_config: None,
            cache: None,
            cache_key_builder: None,
            skip_verify,
            cache_purge_token: None,
            cache_purge_allowed_ips: Arc::new(HashSet::new()),
            pool_max_idle_per_host,
            pool_idle_timeout,
            is_http2: false,
            proxy_headers_config: None,
            drop_blocked_requests,
            connection_limiter,
            threat_level_provider,
            tarpit_service,
            block_store,
            quic_tunnel_sender: None,
        }
    }

    pub fn with_upstream_pool(
        mut self,
        pool: Arc<UpstreamPool>,
        retry_config: Option<RetryConfig>,
        buffering_config: Option<BufferingConfig>,
    ) -> Self {
        self.upstream_pool = Some(pool);
        self.retry_config = retry_config;
        self.buffering_config = buffering_config;
        self
    }

    pub fn with_cache(mut self, cache: Arc<ProxyCache>) -> Self {
        let settings = cache.settings();
        let key_pattern = settings.key_pattern.clone();
        let vary_by = settings.vary_by.clone();
        self.cache = Some(cache);
        self.cache_key_builder = Some(CacheKeyBuilder::new(key_pattern, vary_by));
        self
    }

    pub fn with_http2(mut self, is_http2: bool) -> Self {
        self.is_http2 = is_http2;
        self
    }

    pub fn with_proxy_headers_config(mut self, config: Option<Arc<ProxyHeadersConfig>>) -> Self {
        self.proxy_headers_config = config;
        self
    }

    pub fn with_quic_tunnel_sender(mut self, sender: Arc<dyn QuicTunnelSender>) -> Self {
        self.quic_tunnel_sender = Some(sender);
        self
    }

    pub async fn handle_request(
        &self,
        client_ip: std::net::IpAddr,
        method: http::Method,
        path: String,
        user_agent: Option<String>,
        body: Option<BoxErasedBody>,
        skip_waf_check: bool,
        headers: &http::HeaderMap,
    ) -> Result<ProxyResponse, String> {
        let start = Instant::now();

        if let Some(ref conn_limiter) = self.connection_limiter {
            match conn_limiter.try_acquire(&self.site_id, client_ip).await {
                Ok(token) => {
                    drop(token);
                }
                Err(e) => {
                    tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                    counter!("synvoid.traffic.connection_limited").increment(1);
                    return Ok(Response::builder()
                        .status(429)
                        .body(
                            Full::new(Bytes::from("Too Many Connections\n"))
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                .boxed(),
                        )
                        .unwrap());
                }
            }
        }

        let (full_body_bytes, body): (Option<bytes::Bytes>, Option<BoxErasedBody>) =
            if !skip_waf_check {
                const MAX_WAF_BODY_SIZE: usize = 1024 * 1024; // 1MB limit for WAF inspection
                if let Some(b) = body {
                    let collected = b
                        .collect()
                        .await
                        .map_err(|e| format!("Body collection error: {}", e))?;
                    let bytes = collected.to_bytes();
                    let boxed_body: Option<BoxErasedBody> =
                        Some(ErasedBodyImpl::new(Full::new(bytes.clone())));
                    if bytes.len() <= MAX_WAF_BODY_SIZE {
                        (Some(bytes), boxed_body)
                    } else {
                        (None, boxed_body)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, body)
            };

        if !skip_waf_check {
            let drop = self.drop_blocked_requests;

            let (path_for_waf, query_string) = if let Some(q_pos) = path.find('?') {
                (
                    path[..q_pos].to_string(),
                    Some(path[q_pos + 1..].to_string()),
                )
            } else {
                (path.clone(), None)
            };

            let mut ctx = RequestContext::new(RequestId::new(uuid::Uuid::new_v4().to_string()));
            ctx.site_id = Some(SiteId::new(self.site_id.clone()));
            ctx.client_ip = Some(client_ip.to_string());
            ctx.method = Some(method.to_string());
            ctx.path = Some(path_for_waf.clone());
            ctx.query = query_string.clone();
            ctx.user_agent = user_agent.clone();

            let waf_decision = self
                .waf
                .check_request_full(&ctx, headers, full_body_bytes.as_deref())
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("WAF check failed: {}", e);
                    WafDecision::Pass
                });

            match waf_decision {
                WafDecision::Drop => {
                    counter!("synvoid.requests.dropped").increment(1);
                    return Err("blackholed".to_string());
                }
                WafDecision::Stall => {
                    counter!("synvoid.requests.stalled").increment(1);
                    histogram!("synvoid.request.duration").record(start.elapsed());
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    std::future::pending::<()>().await;
                    return Err("stalled".to_string());
                }
                WafDecision::Block(status_code, message) => {
                    counter!("synvoid.requests.blocked").increment(1);
                    histogram!("synvoid.request.duration").record(start.elapsed());
                    if drop {
                        return Err("dropped".to_string());
                    }
                    return Ok(Response::builder()
                        .status(status_code)
                        .body(
                            Full::new(Bytes::from(message))
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                .boxed(),
                        )
                        .unwrap());
                }
                WafDecision::Challenge(_type, html) => {
                    counter!("synvoid.requests.challenged").increment(1);
                    histogram!("synvoid.request.duration").record(start.elapsed());
                    return Ok(Response::builder()
                        .status(200)
                        .header("Content-Type", "text/html")
                        .header("Cache-Control", "no-store, no-cache, must-revalidate")
                        .body(
                            Full::new(bytes::Bytes::from(html))
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                .boxed(),
                        )
                        .unwrap());
                }
                WafDecision::ChallengeWithCookie {
                    challenge_type: _,
                    html,
                    session_cookie_name,
                    session_cookie_value,
                    session_cookie_max_age,
                } => {
                    counter!("synvoid.requests.challenged").increment(1);
                    histogram!("synvoid.request.duration").record(start.elapsed());
                    let cookie = format!(
                        "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                        session_cookie_name, session_cookie_value, session_cookie_max_age
                    );
                    return Ok(Response::builder()
                        .status(200)
                        .header("Content-Type", "text/html")
                        .header("Cache-Control", "no-store, no-cache, must-revalidate")
                        .header("Set-Cookie", cookie)
                        .body(
                            Full::new(bytes::Bytes::from(html))
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                .boxed(),
                        )
                        .unwrap());
                }
                WafDecision::Tarpit(tar_path) => {
                    counter!("synvoid.requests.tarpitted").increment(1);
                    histogram!("synvoid.request.duration").record(start.elapsed());
                    if let Some(ref tarpit) = self.tarpit_service {
                        let stream = tarpit.stream_tarpit(&tar_path, user_agent.as_deref());
                        return Ok(Response::builder()
                            .status(200)
                            .header("Content-Type", "text/html")
                            .header("Cache-Control", "no-store, no-cache, must-revalidate")
                            .body(BodyExt::boxed(http_body_util::StreamBody::new(
                                futures::StreamExt::map(stream, |res| {
                                    res.map(http_body::Frame::data)
                                }),
                            )))
                            .unwrap());
                    }
                    return Ok(Response::builder()
                        .status(200)
                        .body(
                            Full::new(Bytes::from("Tarpit active"))
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                .boxed(),
                        )
                        .unwrap());
                }
                WafDecision::Pass => {}
            }
        }

        let forward_result = self.forward_request(method, &path, body).await;

        match forward_result {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();

                if let Some(ref tracker) = self.upstream_error_tracker {
                    if status_code >= 400 {
                        let result = tracker.record_error(client_ip, &path, status_code);

                        if let synvoid_waf::UpstreamErrorResult::ProbingDetected {
                            unique_endpoints,
                            error_count,
                        } = result
                        {
                            tracing::warn!(
                                ip = %client_ip,
                                endpoints = ?unique_endpoints,
                                error_count = error_count,
                                status_code = status_code,
                                "Potential upstream vulnerability probe detected - healthy upstream returning errors"
                            );

                            let config = tracker.get_config();
                            if config.auto_ban_elevated_threat {
                                let threat_level = self
                                    .threat_level_provider
                                    .as_ref()
                                    .map(|tl| tl.get_threat_level())
                                    .unwrap_or(1);
                                if threat_level >= config.elevated_threat_threshold {
                                    let ban_duration = config.elevated_ban_duration;
                                    tracing::warn!(
                                        ip = %client_ip,
                                        threat_level = threat_level,
                                        ban_duration_secs = ban_duration,
                                        "Auto-banning source of upstream error probing"
                                    );
                                    if let Some(ref store) = self.block_store {
                                        store.block_ip(
                                            client_ip,
                                            "upstream_error_probe",
                                            ban_duration,
                                            "global",
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                counter!("synvoid.requests.proxied").increment(1);
                histogram!("synvoid.request.duration").record(start.elapsed());
                Ok(response)
            }
            Err(e) => {
                counter!("synvoid.requests.upstream_error").increment(1);
                tracing::error!("Upstream error: {}", e);
                histogram!("synvoid.request.duration").record(start.elapsed());
                Ok(Response::builder()
                    .status(502)
                    .body(
                        Full::new(Bytes::from_static(b"Bad Gateway"))
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                            .boxed(),
                    )
                    .unwrap_or_else(|_| {
                        Response::builder()
                            .status(502)
                            .body(
                                Full::new(Bytes::from_static(b"Bad Gateway"))
                                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                    .boxed(),
                            )
                            .unwrap_or_else(|_| unreachable!())
                    }))
            }
        }
    }

    async fn forward_request(
        &self,
        method: http::Method,
        path: &str,
        body: Option<BoxErasedBody>,
    ) -> Result<ProxyResponse, Box<dyn std::error::Error + Send + Sync>> {
        if self.skip_verify {
            tracing::warn!(
                site_id = %self.site_id,
                upstream = %self.upstream_url,
                path,
                "Forwarding request over connection with TLS verification DISABLED"
            );
        }
        if let Some(ref pool) = self.upstream_pool {
            return self.forward_with_pool(method, path, pool, body).await;
        }

        let url = join_upstream_url(&self.upstream_url, path);
        self.send_single_request(method, &url, None, body).await
    }

    pub async fn forward_request_via_tunnel(
        &self,
        method: http::Method,
        tunnel_url: &str,
        path: &str,
        headers: Option<&http::HeaderMap>,
        body: Option<BoxErasedBody>,
    ) -> Result<ProxyResponse, Box<dyn std::error::Error + Send + Sync>> {
        let full_url = join_upstream_url(tunnel_url, path);
        self.send_single_request(method, &full_url, headers, body)
            .await
    }

    pub async fn handle_request_with_cache(
        &self,
        method: http::Method,
        path: &str,
        host: &str,
        headers: &http::HeaderMap,
        scheme: &str,
        body: Option<BoxErasedBody>,
        client_ip: std::net::IpAddr,
    ) -> Result<ProxyResponse, String> {
        let purge_token = headers
            .get("x-cache-purge-token")
            .and_then(|v| v.to_str().ok());
        if method.as_str() == "PURGE" {
            return self
                .handle_cache_purge(path, host, purge_token, client_ip)
                .await
                .map(|r| {
                    r.map(|b| {
                        Full::new(b)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                            .boxed()
                    })
                });
        }

        if !self.is_cacheable_method(&method) {
            return self
                .forward_request(method, path, body)
                .await
                .map_err(|e| e.to_string());
        }

        if let Some(cache) = &self.cache {
            if let Some(key_builder) = &self.cache_key_builder {
                if cache.is_enabled() {
                    if self.should_bypass_cache(headers) {
                        tracing::debug!("Cache bypass requested for {}", path);
                    } else {
                        let uri = http::Uri::try_from(path)
                            .unwrap_or_else(|_| http::Uri::from_static("/"));
                        let cache_key =
                            key_builder.build(scheme, &method, host, &uri, headers, &self.site_id);

                        let hit_status = cache.get_hit_status(&cache_key);

                        if let Some(cached) = cache.get(&cache_key).await {
                            tracing::debug!("Cache HIT for {}", path);
                            counter!("synvoid.proxy.cache.hit").increment(1);
                            cache.record_cache_hit();
                            record_proxy_cache_hit();

                            let is_swr = matches!(hit_status, Some(CacheHit::StaleWhileRevalidate));

                            if is_swr {
                                let cache_clone = cache.clone();
                                let key_clone = cache_key.clone();
                                let path_owned = path.to_string();
                                let method_clone = method.clone();
                                let upstream_url_clone = self.upstream_url.clone();
                                let reval_client = self.revalidation_client.clone();

                                // Build headers for revalidation (standard forward headers)
                                let reval_headers = build_forward_headers(
                                    client_ip,
                                    headers,
                                    &ProxyHeadersConfig::default(),
                                    ForwardedProtocol::Https,
                                );

                                if cache_clone.try_acquire_revalidation(&key_clone) {
                                    tokio::spawn(async move {
                                        cache_clone.record_revalidation_queued();
                                        let semaphore = cache_clone.revalidation_semaphore();
                                        let permit = match semaphore.acquire().await {
                                            Ok(p) => p,
                                            Err(_) => {
                                                cache_clone.record_revalidation_end();
                                                cache_clone.release_revalidation(&key_clone);
                                                tracing::warn!("Revalidation semaphore closed");
                                                return;
                                            }
                                        };
                                        cache_clone.record_revalidation_start();
                                        tracing::debug!(
                                            "Triggering background revalidation for {}",
                                            path_owned
                                        );
                                        let _ = Self::revalidate_cache_entry(
                                            &reval_client,
                                            cache_clone.clone(),
                                            key_clone.clone(),
                                            method_clone,
                                            path_owned,
                                            upstream_url_clone,
                                            reval_headers,
                                        )
                                        .await;
                                        drop(permit);
                                        cache_clone.record_revalidation_end();
                                        cache_clone.release_revalidation(&key_clone);
                                    });
                                }

                                counter!("synvoid.proxy.cache.stale_while_revalidate").increment(1);
                            }

                            let response = self.build_cached_response(&cached);
                            return Ok(response.map(|b| {
                                Full::new(b)
                                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                                    .boxed()
                            }));
                        }

                        tracing::debug!("Cache MISS for {}", path);
                        counter!("synvoid.proxy.cache.miss").increment(1);
                        cache.record_cache_miss();
                        record_proxy_cache_miss();

                        let result = self.forward_request(method.clone(), path, body).await;

                        match result {
                            Ok(response) => {
                                self.process_cache_invalidate_header(response.headers());

                                if self.is_response_cacheable_headers(
                                    response.status(),
                                    response.headers(),
                                ) {
                                    let status = response.status().as_u16();
                                    let allowed_headers = cache.settings().allowed_headers.clone();
                                    let headers_to_cache = filter_cacheable_headers_impl(
                                        response.headers(),
                                        &allowed_headers,
                                    );
                                    let max_age = self.get_cache_max_age(&headers_to_cache);

                                    let (parts, body) = response.into_parts();
                                    let teed_body = TeeBody::new(
                                        body,
                                        Some(cache.clone()),
                                        Some(cache_key),
                                        status,
                                        headers_to_cache,
                                        max_age,
                                        self.max_response_size,
                                    );
                                    return Ok(Response::from_parts(parts, teed_body.boxed()));
                                }
                                return Ok(response);
                            }
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                }
            }
        }

        self.forward_request(method, path, body)
            .await
            .map_err(|e| e.to_string())
    }

    pub fn invalidate_cache(&self, path: &str) -> usize {
        if let Some(ref cache) = self.cache {
            cache.invalidate_by_pattern(path)
        } else {
            0
        }
    }

    pub fn invalidate_cache_by_host(&self, host: &str) -> usize {
        if let Some(ref cache) = self.cache {
            cache.invalidate_by_host(host)
        } else {
            0
        }
    }

    async fn handle_cache_purge(
        &self,
        path: &str,
        host: &str,
        purge_token: Option<&str>,
        client_ip: std::net::IpAddr,
    ) -> Result<Response<bytes::Bytes>, String> {
        if let Some(ref required_token) = self.cache_purge_token {
            match purge_token {
                Some(token) if required_token.as_bytes().ct_eq(token.as_bytes()).into() => {}
                _ => {
                    tracing::warn!(
                        "Unauthorized cache purge attempt from {} to {}",
                        client_ip,
                        host
                    );
                    return Ok(Response::builder()
                        .status(403)
                        .body(bytes::Bytes::from("Forbidden: authentication required\n"))
                        .unwrap_or_else(|_| Response::new(bytes::Bytes::new())));
                }
            }
        } else if !self.cache_purge_allowed_ips.is_empty()
            && !self.cache_purge_allowed_ips.contains(&client_ip)
        {
            tracing::warn!(
                "Unauthorized cache purge from {} (IP not in allowlist) to {}",
                client_ip,
                host
            );
            return Ok(Response::builder()
                .status(403)
                .body(bytes::Bytes::from("Forbidden: IP not allowed\n"))
                .unwrap_or_else(|_| Response::new(bytes::Bytes::new())));
        } else if self.cache_purge_token.is_none() && self.cache_purge_allowed_ips.is_empty() {
            tracing::warn!(
                "Unauthorized cache purge from {} to {} - no token configured and allowlist empty",
                client_ip,
                host
            );
            return Ok(Response::builder()
                .status(403)
                .body(bytes::Bytes::from("Forbidden: purge not configured\n"))
                .unwrap_or_else(|_| Response::new(bytes::Bytes::new())));
        }

        let count = if path == "*" {
            if let Some(ref cache) = self.cache {
                cache.clear();
                tracing::info!("Purged all cache entries for host {}", host);
                1
            } else {
                0
            }
        } else if let Some(pattern) = path.strip_prefix("*/") {
            if let Some(ref cache) = self.cache {
                let count = cache.invalidate_by_pattern(pattern);
                tracing::info!(
                    "Purged {} cache entries matching pattern {}",
                    count,
                    pattern
                );
                count
            } else {
                0
            }
        } else if let Some(ref cache) = self.cache {
            cache.invalidate_by_pattern(&format!("GET:{}:{}:*", host, path))
        } else {
            0
        };

        Ok(Response::builder()
            .status(200)
            .body(bytes::Bytes::from(format!("Purged {} entries\n", count)))
            .unwrap_or_else(|_| Response::new(bytes::Bytes::new())))
    }

    fn process_cache_invalidate_header(&self, headers: &http::HeaderMap) {
        if let Some(invalidate) = headers.get("x-cache-invalidate") {
            if let Ok(invalidate_str) = invalidate.to_str() {
                if let Some(ref cache) = self.cache {
                    for pattern in invalidate_str.split(',') {
                        let pattern = pattern.trim();
                        let count = cache.invalidate_by_pattern(pattern);
                        if count > 0 {
                            tracing::debug!(
                                "X-Cache-Invalidate: purged {} entries matching '{}'",
                                count,
                                pattern
                            );
                        }
                    }
                }
            }
        }
    }

    fn is_cacheable_method(&self, method: &http::Method) -> bool {
        if let Some(ref cache) = self.cache {
            cache
                .settings()
                .methods
                .iter()
                .any(|m| m.as_str().eq_ignore_ascii_case(method.as_str()))
        } else {
            false
        }
    }

    fn should_bypass_cache(&self, headers: &http::HeaderMap) -> bool {
        if let Some(cc) = headers.get("cache-control") {
            if let Ok(cc_str) = cc.to_str() {
                return cc_str.contains("no-cache")
                    || cc_str.contains("no-store")
                    || cc_str.contains("private");
            }
        }
        false
    }

    fn get_cache_max_age(&self, headers: &http::HeaderMap) -> Option<std::time::Duration> {
        get_cache_max_age_static_impl(headers)
    }

    fn build_cached_response(&self, entry: &ProxyCacheEntry) -> Response<bytes::Bytes> {
        build_cached_response_impl(entry)
    }

    async fn revalidate_cache_entry(
        client: &HttpClient,
        cache: Arc<ProxyCache>,
        key: CacheKey,
        method: http::Method,
        path: String,
        upstream_url: String,
        headers: http::HeaderMap,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let url = join_upstream_url(&upstream_url, &path);

        match send_request_with_body_headers_and_timeout(
            client,
            method,
            &url,
            None,
            headers,
            Some(Duration::from_secs(5)),
        )
        .await
        {
            Ok(response) => {
                let status = response.status_code();
                let headers = response.headers.clone();
                let body = response.body.clone();

                if cache.is_status_cacheable(status) {
                    let allowed_headers = cache.settings().allowed_headers.clone();
                    let filtered_headers =
                        filter_cacheable_headers_impl(&headers, &allowed_headers);
                    let max_age = get_cache_max_age_static_impl(&filtered_headers);
                    if let Err(e) = cache.insert(key, body, status, filtered_headers, max_age) {
                        tracing::warn!("Failed to update cached response: {}", e);
                    } else {
                        tracing::debug!("Successfully revalidated cache for {}", path);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Background revalidation failed for {}: {}", path, e);
                cache.record_revalidation_failure();
            }
        }

        Ok(())
    }

    async fn forward_with_pool(
        &self,
        method: http::Method,
        path: &str,
        pool: &UpstreamPool,
        mut body: Option<BoxErasedBody>,
    ) -> Result<ProxyResponse, Box<dyn std::error::Error + Send + Sync>> {
        let retry_config = self.retry_config.as_ref();
        let retry_enabled = retry_config.map(|c| c.enabled).unwrap_or(false);
        let max_retries = retry_config.map(|c| c.max_retries).unwrap_or(3);
        let should_retry_method = retry_config
            .map(|c| should_retry_request_impl(&method, c))
            .unwrap_or(true);

        let mut current_backend: Option<Backend> = None;
        let mut last_error: Option<String> = None;
        let mut attempt = 0;
        let mut tried_backends: HashSet<std::sync::Arc<String>> = HashSet::new();

        loop {
            let backend = if let Some(ref be) = current_backend {
                match pool.select_next_backend(be) {
                    Some(next) => next,
                    None => break,
                }
            } else {
                match pool.select_backend() {
                    Some(b) => b,
                    None => break,
                }
            };

            if tried_backends.contains(&backend.url) {
                tracing::debug!("All backends exhausted, breaking retry loop");
                break;
            }
            tried_backends.insert(backend.url.clone());

            current_backend = Some(backend.clone());
            attempt += 1;

            backend.increment_connections();

            let url = join_upstream_url(backend.url.as_str(), path);

            tracing::debug!(
                "Attempting request to upstream: {} (attempt {}/{})",
                url,
                attempt,
                max_retries + 1
            );

            let start_time = std::time::Instant::now();
            let result = self
                .send_single_request(method.clone(), &url, None, body.take())
                .await;

            backend.record_latency(start_time.elapsed());
            backend.decrement_connections();

            match result {
                Ok(response) => {
                    let status = response.status().as_u16();

                    if retry_enabled
                        && should_retry_method
                        && is_retryable_status_impl(status, retry_config.unwrap())
                        && attempt < max_retries
                    {
                        if let Some(ref be) = current_backend {
                            pool.mark_failed(&be.url);
                        }

                        if let Some(timeout) = retry_config.unwrap().timeout_ms {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                calculate_backoff_impl(attempt, timeout),
                            ))
                            .await;
                        }

                        continue;
                    }

                    return Ok(response);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    last_error = Some(error_str.clone());

                    if retry_enabled && should_retry_method {
                        let should_retry = (retry_config.unwrap().retry_on_error
                            && is_connection_error_impl(&*e))
                            || (retry_config.unwrap().retry_on_timeout
                                && is_timeout_error_impl(&*e));

                        if should_retry && attempt <= max_retries {
                            if let Some(ref be) = current_backend {
                                pool.mark_failed(&be.url);
                            }

                            if let Some(timeout) = retry_config.unwrap().timeout_ms {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    calculate_backoff_impl(attempt, timeout),
                                ))
                                .await;
                            }

                            continue;
                        }
                    }

                    if let Some(ref be) = current_backend {
                        pool.mark_failed(&be.url);
                    }

                    if retry_enabled && should_retry_method && attempt < max_retries {
                        continue;
                    }

                    break;
                }
            }
        }

        Err(format!(
            "All upstream servers failed after {} attempts: {}",
            attempt,
            last_error.unwrap_or_default()
        )
        .into())
    }

    fn is_response_cacheable_headers(
        &self,
        status: http::StatusCode,
        headers: &http::HeaderMap,
    ) -> bool {
        if let Some(ref cache) = self.cache {
            let status_u16 = status.as_u16();
            if !cache.settings().valid_status.contains(&status_u16) {
                return false;
            }

            if let Some(cc) = headers.get("cache-control") {
                if let Ok(cc_str) = cc.to_str() {
                    if cc_str.contains("no-store") || cc_str.contains("private") {
                        return false;
                    }
                }
            }

            return true;
        }
        false
    }

    async fn send_single_request(
        &self,
        method: http::Method,
        url: &str,
        headers: Option<&http::HeaderMap>,
        body: Option<BoxErasedBody>,
    ) -> Result<ProxyResponse, Box<dyn std::error::Error + Send + Sync>> {
        use crate::headers::HOP_BY_HOP_HEADERS;

        let hop_by_hop_headers = HOP_BY_HOP_HEADERS;

        if is_quictunnel_url(url) {
            if let Some(ref sender) = self.quic_tunnel_sender {
                let bytes_body = if let Some(mut b) = body {
                    let mut collected = bytes::BytesMut::new();
                    let waker = futures::task::noop_waker();
                    let mut cx = std::task::Context::from_waker(&waker);
                    while let std::task::Poll::Ready(Some(Ok(frame))) = b.poll_frame(&mut cx) {
                        if frame.is_data() {
                            if let Ok(data) = frame.into_data().map(|b| b) {
                                collected.extend_from_slice(&data);
                            }
                        }
                    }
                    Some(collected.freeze())
                } else {
                    None
                };

                let (status, resp_headers, response_body) = sender
                    .send_via_quic_tunnel(
                        method,
                        url,
                        headers,
                        bytes_body,
                        Some(std::time::Duration::from_secs(30)),
                    )
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;

                let mut builder = Response::builder().status(status);
                for (k, v) in &resp_headers {
                    builder = builder.header(k.as_str(), v.as_str());
                }

                if response_body.len() > self.max_response_size {
                    return Err("Response too large".into());
                }

                return Ok(builder.body(
                    Full::new(response_body)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                        .boxed(),
                )?);
            } else {
                return Err("QUIC tunnel support not configured".into());
            }
        }

        let forward_headers = if let Some(ref config) = self.proxy_headers_config {
            crate::headers::build_forward_headers(
                std::net::IpAddr::from([127, 0, 0, 1]),
                headers.as_deref().unwrap_or(&http::HeaderMap::new()),
                config,
                crate::headers::ForwardedProtocol::Https,
            )
        } else {
            headers.cloned().unwrap_or_default()
        };

        let response = send_request_erased_streaming(
            &self.erased_client,
            method,
            url,
            body.unwrap_or_else(|| {
                ErasedBodyImpl::from_full(http_body_util::Full::new(bytes::Bytes::new()))
            }),
            forward_headers,
            Some(std::time::Duration::from_secs(30)),
            self.is_http2,
        )
        .await?;

        let (parts, incoming_body) = response.into_parts();

        let mut builder = Response::builder().status(parts.status);
        for (k, v) in parts.headers.iter() {
            if !hop_by_hop_headers.contains(&k.as_str()) {
                builder = builder.header(k, v);
            }
        }

        let streamed_body = incoming_body
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)));

        Ok(builder.body(streamed_body.boxed())?)
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::join_upstream_url;

    #[test]
    fn test_join_upstream_url_no_trailing_slash() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", "/path"),
            "http://backend.example.com/path"
        );
        assert_eq!(
            join_upstream_url("http://backend.example.com", "/path/to/page"),
            "http://backend.example.com/path/to/page"
        );
    }

    #[test]
    fn test_join_upstream_url_with_trailing_slash() {
        assert_eq!(
            join_upstream_url("http://backend.example.com/", "/path"),
            "http://backend.example.com/path"
        );
        assert_eq!(
            join_upstream_url("http://backend.example.com///", "/path"),
            "http://backend.example.com/path"
        );
    }

    #[test]
    fn test_join_upstream_url_path_without_leading_slash() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", "path"),
            "http://backend.example.com/path"
        );
        assert_eq!(
            join_upstream_url("http://backend.example.com", "path/to/page"),
            "http://backend.example.com/path/to/page"
        );
    }

    #[test]
    fn test_join_upstream_url_empty_path() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", ""),
            "http://backend.example.com/"
        );
    }

    #[test]
    fn test_join_upstream_url_preserves_query() {
        assert_eq!(
            join_upstream_url("http://backend.example.com", "/path?query=1"),
            "http://backend.example.com/path?query=1"
        );
    }

    #[test]
    fn test_join_upstream_url_with_port() {
        assert_eq!(
            join_upstream_url("http://backend.example.com:8080", "/path"),
            "http://backend.example.com:8080/path"
        );
        assert_eq!(
            join_upstream_url("http://backend.example.com:8080/", "/path"),
            "http://backend.example.com:8080/path"
        );
    }

    #[test]
    fn test_proxy_path_query_split_sqli() {
        let path = "/search?id=1' OR '1'='1";
        let (path_for_waf, query_string) = if let Some(q_pos) = path.find('?') {
            (
                path[..q_pos].to_string(),
                Some(path[q_pos + 1..].to_string()),
            )
        } else {
            (path.to_string(), None)
        };

        assert_eq!(path_for_waf, "/search");
        assert_eq!(query_string, Some("id=1' OR '1'='1".to_string()));
    }

    #[test]
    fn test_proxy_path_query_split_xss() {
        let path = "/comment?q=<script>alert(1)</script>";
        let (path_for_waf, query_string) = if let Some(q_pos) = path.find('?') {
            (
                path[..q_pos].to_string(),
                Some(path[q_pos + 1..].to_string()),
            )
        } else {
            (path.to_string(), None)
        };

        assert_eq!(path_for_waf, "/comment");
        assert_eq!(
            query_string,
            Some("q=<script>alert(1)</script>".to_string())
        );
    }

    #[test]
    fn test_proxy_path_no_query() {
        let path = "/api/users";
        let (path_for_waf, query_string) = if let Some(q_pos) = path.find('?') {
            (
                path[..q_pos].to_string(),
                Some(path[q_pos + 1..].to_string()),
            )
        } else {
            (path.to_string(), None)
        };

        assert_eq!(path_for_waf, "/api/users");
        assert_eq!(query_string, None);
    }

    #[test]
    fn test_proxy_path_query_only() {
        let path = "/search?query=test";
        let (path_for_waf, query_string) = if let Some(q_pos) = path.find('?') {
            (
                path[..q_pos].to_string(),
                Some(path[q_pos + 1..].to_string()),
            )
        } else {
            (path.to_string(), None)
        };

        assert_eq!(path_for_waf, "/search");
        assert_eq!(query_string, Some("query=test".to_string()));
    }

    #[test]
    fn test_proxy_path_multiple_question_marks() {
        let path = "/search?redirect=https://evil.com?bad=true";
        let (path_for_waf, query_string) = if let Some(q_pos) = path.find('?') {
            (
                path[..q_pos].to_string(),
                Some(path[q_pos + 1..].to_string()),
            )
        } else {
            (path.to_string(), None)
        };

        assert_eq!(path_for_waf, "/search");
        assert_eq!(
            query_string,
            Some("redirect=https://evil.com?bad=true".to_string())
        );
    }
}

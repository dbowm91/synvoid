//! Reverse proxy and request forwarding.
//!
//! Handles proxied HTTP/HTTPS requests end-to-end: upstream selection
//! with load balancing, header filtering (stripping hop-by-hop and
//! information-leaking headers), proxy caching, retry with backoff,
//! request buffering, and metrics collection. Integrates with the WAF
//! for attack detection before forwarding.

pub mod cache;
pub mod headers;
pub mod retry;

pub use headers::{
    apply_response_header_transforms, build_forward_headers, build_headers_to_filter,
    filter_response_headers, filter_response_headers_buf, is_hop_by_hop_header,
    is_hop_by_hop_header_name, sanitize_request_path, validate_and_truncate_xff, HEADERS_TO_STRIP,
    HOP_BY_HOP_HEADERS, MAX_XFF_CHAIN_LENGTH,
};

use ::metrics::{counter, histogram};
use http::Response;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::site::{BufferingConfig, ProxyCacheConfig, RetryConfig};
use crate::http_client::{
    create_http_client_with_config, create_upstream_client,
    send_request_with_body_and_timeout_with_limit, send_request_with_timeout, HttpClient,
    UpstreamTlsConfig,
};
use crate::metrics::{record_proxy_cache_hit, record_proxy_cache_miss};
use crate::proxy::cache::{
    build_cached_response as build_cached_response_impl,
    filter_sensitive_headers as filter_sensitive_headers_impl,
    get_cache_max_age_static as get_cache_max_age_static_impl,
};
use crate::proxy::retry::{
    calculate_backoff as calculate_backoff_impl, is_connection_error as is_connection_error_impl,
    is_retryable_status as is_retryable_status_impl, is_timeout_error as is_timeout_error_impl,
};
use crate::proxy_cache::{
    CacheHit, CacheKey, CacheKeyBuilder, ProxyCache, ProxyCacheEntry, ProxyCacheSettings,
};
use crate::upstream::{Backend, LoadBalanceAlgorithm, UpstreamPool};
pub use crate::waf::WafDecision;
use crate::waf::{UpstreamErrorTracker, WafCore};

pub struct ProxyServer {
    client: HttpClient,
    revalidation_client: HttpClient,
    upstream_url: String,
    waf: Arc<WafCore>,
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
}

impl ProxyServer {
    pub fn new(
        upstream_url: String,
        waf: Arc<WafCore>,
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
    ) -> Self {
        Self::new_with_tls(
            upstream_url,
            waf,
            max_response_size,
            upstream_error_tracker,
            site_id,
            None,
        )
    }

    pub fn new_with_tls(
        upstream_url: String,
        waf: Arc<WafCore>,
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
        tls_config: Option<&UpstreamTlsConfig>,
    ) -> Self {
        let (client, revalidation_client) = if let Some(tls) = tls_config {
            (
                create_upstream_client(
                    std::time::Duration::from_secs(5),
                    100,
                    std::time::Duration::from_secs(30),
                    tls,
                ),
                create_upstream_client(
                    std::time::Duration::from_secs(5),
                    50,
                    std::time::Duration::from_secs(15),
                    tls,
                ),
            )
        } else {
            (
                create_http_client_with_config(
                    std::time::Duration::from_secs(5),
                    100,
                    std::time::Duration::from_secs(30),
                ),
                create_http_client_with_config(
                    std::time::Duration::from_secs(5),
                    50,
                    std::time::Duration::from_secs(15),
                ),
            )
        };

        let skip_verify = tls_config.map(|t| t.skip_verify).unwrap_or(false);

        ProxyServer {
            client,
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
        let settings = cache.settings().clone();
        self.cache = Some(cache);
        self.cache_key_builder = Some(CacheKeyBuilder::new(settings.key_pattern, settings.vary_by));
        self
    }

    pub fn from_config(
        servers: Vec<String>,
        backup_servers: Vec<String>,
        retry_config: Option<RetryConfig>,
        buffering_config: Option<BufferingConfig>,
        cache_config: Option<ProxyCacheConfig>,
        waf: Arc<WafCore>,
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
        tls_config: Option<&UpstreamTlsConfig>,
    ) -> Self {
        let (client, revalidation_client, skip_verify) = if let Some(tls) = tls_config {
            (
                create_upstream_client(
                    std::time::Duration::from_secs(5),
                    100,
                    std::time::Duration::from_secs(30),
                    tls,
                ),
                create_upstream_client(
                    std::time::Duration::from_secs(5),
                    50,
                    std::time::Duration::from_secs(15),
                    tls,
                ),
                tls.skip_verify,
            )
        } else {
            (
                create_http_client_with_config(
                    std::time::Duration::from_secs(5),
                    100,
                    std::time::Duration::from_secs(30),
                ),
                create_http_client_with_config(
                    std::time::Duration::from_secs(5),
                    50,
                    std::time::Duration::from_secs(15),
                ),
                false,
            )
        };

        let upstream_pool = if !servers.is_empty() || !backup_servers.is_empty() {
            Some(Arc::new(UpstreamPool::new_with_backup(
                servers,
                backup_servers,
                LoadBalanceAlgorithm::default(),
            )))
        } else {
            None
        };

        let (cache, cache_key_builder) = if let Some(ref cc) = cache_config {
            let settings = ProxyCacheSettings::from_config(
                cc.enable,
                cc.path.clone(),
                cc.max_size.clone(),
                cc.inactive,
                cc.use_temp_file,
                cc.valid_status.clone(),
                cc.methods.clone(),
                cc.use_stale.clone(),
                cc.min_uses,
                cc.key.clone(),
                cc.vary_by.clone(),
                cc.memory_max.clone(),
                cc.disk_max.clone(),
                cc.stale_while_revalidate,
                cc.stale_if_error,
            );

            let cache = Arc::new(ProxyCache::new(settings));
            let kb = CacheKeyBuilder::new(
                cache.settings().key_pattern.clone(),
                cache.settings().vary_by.clone(),
            );
            (Some(cache), Some(kb))
        } else {
            (None, None)
        };

        ProxyServer {
            client,
            revalidation_client,
            upstream_url: String::new(),
            waf,
            max_response_size,
            upstream_error_tracker,
            site_id,
            upstream_pool,
            retry_config,
            buffering_config,
            cache,
            cache_key_builder,
            skip_verify,
            cache_purge_token: None,
            cache_purge_allowed_ips: Arc::new(HashSet::new()),
        }
    }

    pub async fn handle_request(
        &self,
        client_ip: std::net::IpAddr,
        method: http::Method,
        path: String,
        user_agent: Option<String>,
        body: Option<bytes::Bytes>,
        skip_waf_check: bool,
        headers: &http::HeaderMap,
    ) -> Result<Response<bytes::Bytes>, String> {
        let start = Instant::now();

        if let Some(ref conn_limiter) = self.waf.connection_limiter {
            match conn_limiter.try_acquire(&self.site_id, client_ip).await {
                Ok(token) => {
                    drop(token);
                }
                Err(e) => {
                    tracing::warn!("Connection limit exceeded for {}: {}", client_ip, e);
                    counter!("maluwaf.traffic.connection_limited").increment(1);
                    return Err("connection_limit_exceeded".to_string());
                }
            }
        }

        if !skip_waf_check {
            let drop = self.waf.config.drop_blocked_requests;

            let body_slice: Option<&[u8]> = body.as_deref();
            let query_string = None;

            let waf_decision = self
                .waf
                .check_request_full(
                    client_ip,
                    method.as_str(),
                    &path,
                    query_string,
                    headers,
                    body_slice,
                    user_agent.as_deref(),
                    None,
                )
                .await;

            match waf_decision {
                WafDecision::Drop => {
                    counter!("maluwaf.requests.dropped").increment(1);
                    return Err("blackholed".to_string());
                }
                WafDecision::Stall => {
                    counter!("maluwaf.requests.stalled").increment(1);
                    histogram!("maluwaf.request.duration").record(start.elapsed());
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    std::future::pending::<()>().await;
                    return Err("stalled".to_string());
                }
                WafDecision::Block(_status_code, _message) => {
                    counter!("maluwaf.requests.blocked").increment(1);
                    histogram!("maluwaf.request.duration").record(start.elapsed());
                    if drop {
                        return Err("dropped".to_string());
                    }
                    return Err("blocked".to_string());
                }
                WafDecision::Challenge(html) => {
                    counter!("maluwaf.requests.challenged").increment(1);
                    histogram!("maluwaf.request.duration").record(start.elapsed());
                    return Ok(Response::builder()
                        .status(200)
                        .header("Content-Type", "text/html")
                        .header("Cache-Control", "no-store, no-cache, must-revalidate")
                        .body(bytes::Bytes::from(html))
                        .unwrap_or_else(|_| crate::http::fallback_error_bytes()));
                }
                WafDecision::ChallengeWithCookie {
                    html,
                    session_cookie_name,
                    session_cookie_value,
                    session_cookie_max_age,
                } => {
                    counter!("maluwaf.requests.challenged").increment(1);
                    histogram!("maluwaf.request.duration").record(start.elapsed());
                    let cookie = format!(
                        "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                        session_cookie_name, session_cookie_value, session_cookie_max_age
                    );
                    return Ok(Response::builder()
                        .status(200)
                        .header("Content-Type", "text/html")
                        .header("Cache-Control", "no-store, no-cache, must-revalidate")
                        .header("Set-Cookie", cookie)
                        .body(bytes::Bytes::from(html))
                        .unwrap_or_else(|_| crate::http::fallback_error_bytes()));
                }
                WafDecision::Tarpit(_) => {
                    counter!("maluwaf.requests.tarpitted").increment(1);
                    histogram!("maluwaf.request.duration").record(start.elapsed());
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

                        if let crate::waf::UpstreamErrorResult::ProbingDetected {
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
                                    .waf
                                    .threat_level
                                    .as_ref()
                                    .map(|tl| tl.get_level().as_u8())
                                    .unwrap_or(1);
                                if threat_level >= config.elevated_threat_threshold {
                                    let ban_duration = config.elevated_ban_duration;
                                    tracing::warn!(
                                        ip = %client_ip,
                                        threat_level = threat_level,
                                        ban_duration_secs = ban_duration,
                                        "Auto-banning source of upstream error probing"
                                    );
                                    if let Some(ref store) = self.waf.block_store {
                                        store.block_ip(
                                            client_ip,
                                            "upstream_error_probe",
                                            ban_duration,
                                            "global",
                                        );
                                    }
                                    if let Some(ref threat_intel) = crate::waf::get_threat_intel() {
                                        threat_intel.announce_local_block(
                                            client_ip,
                                            "upstream_error_probe".to_string(),
                                            ban_duration,
                                            "global".to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                counter!("maluwaf.requests.proxied").increment(1);
                histogram!("maluwaf.request.duration").record(start.elapsed());
                Ok(response)
            }
            Err(e) => {
                counter!("maluwaf.requests.upstream_error").increment(1);
                tracing::error!("Upstream error: {}", e);
                histogram!("maluwaf.request.duration").record(start.elapsed());
                Ok(Response::builder()
                    .status(502)
                    .body(bytes::Bytes::from_static(b"Bad Gateway"))
                    .unwrap_or_else(|_| crate::http::fallback_error_bytes()))
            }
        }
    }

    async fn forward_request(
        &self,
        method: http::Method,
        path: &str,
        body: Option<bytes::Bytes>,
    ) -> Result<Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
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

        let url = format!("{}{}", self.upstream_url, path);
        self.send_single_request(method, &url, None, body).await
    }

    pub async fn forward_request_via_tunnel(
        &self,
        method: http::Method,
        tunnel_url: &str,
        path: &str,
        headers: Option<&http::HeaderMap>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        let full_url = format!("{}{}", tunnel_url, path);
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
        body: Option<bytes::Bytes>,
        client_ip: std::net::IpAddr,
    ) -> Result<Response<bytes::Bytes>, String> {
        let purge_token = headers
            .get("x-cache-purge-token")
            .and_then(|v| v.to_str().ok());
        if method.as_str() == "PURGE" {
            return self
                .handle_cache_purge(path, host, purge_token, client_ip)
                .await;
        }

        if !self.is_cacheable_method(&method) {
            return self
                .forward_request(method, path, body)
                .await
                .map_err(|e| e.to_string());
        }

        if let (Some(cache), Some(key_builder)) = (&self.cache, &self.cache_key_builder) {
            if cache.is_enabled() {
                if self.should_bypass_cache(headers) {
                    tracing::debug!("Cache bypass requested for {}", path);
                } else {
                    let uri =
                        http::Uri::try_from(path).unwrap_or_else(|_| http::Uri::from_static("/"));
                    let cache_key =
                        key_builder.build(scheme, &method, host, &uri, headers, &self.site_id);

                    let hit_status = cache.get_hit_status(&cache_key);

                    if let Some(cached) = cache.get(&cache_key).await {
                        tracing::debug!("Cache HIT for {}", path);
                        counter!("maluwaf.proxy.cache.hit").increment(1);
                        cache.record_cache_hit();
                        record_proxy_cache_hit();

                        let is_swr = matches!(hit_status, Some(CacheHit::StaleWhileRevalidate));

                        if is_swr {
                            let cache_clone = cache.clone();
                            let key_clone = cache_key.clone();
                            let path_owned = path.to_string();
                            let method_clone = method.clone();
                            let scheme_owned = scheme.to_string();
                            let host_owned = host.to_string();
                            let reval_client = self.revalidation_client.clone();

                            tokio::spawn(async move {
                                tracing::debug!(
                                    "Triggering background revalidation for {}",
                                    path_owned
                                );
                                let _ = Self::revalidate_cache_entry(
                                    &reval_client,
                                    cache_clone,
                                    key_clone,
                                    method_clone,
                                    path_owned,
                                    scheme_owned,
                                    host_owned,
                                )
                                .await;
                            });

                            counter!("maluwaf.proxy.cache.stale_while_revalidate").increment(1);
                        }

                        let response = self.build_cached_response(&cached);
                        return Ok(response);
                    }

                    tracing::debug!("Cache MISS for {}", path);
                    counter!("maluwaf.proxy.cache.miss").increment(1);
                    cache.record_cache_miss();
                    record_proxy_cache_miss();

                    let result = self
                        .forward_request(method.clone(), path, body.clone())
                        .await;

                    match result {
                        Ok(response) => {
                            self.process_cache_invalidate_header(response.headers());

                            if self.is_response_cacheable(&response, headers) {
                                let status = response.status().as_u16();
                                let body = response.body().clone();
                                let headers = filter_sensitive_headers_impl(response.headers());
                                let max_age = self.get_cache_max_age(&headers);

                                if let Err(e) =
                                    cache.insert(cache_key, body, status, headers, max_age)
                                {
                                    tracing::warn!("Failed to cache response: {}", e);
                                }
                            }
                            return Ok(response);
                        }
                        Err(e) => return Err(e.to_string()),
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
                Some(token) if token == required_token.as_str() => {}
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
            if let Some(cache_key) = CacheKey::from_cache_string(&format!("GET:{}:{}", host, path))
            {
                cache.invalidate(&cache_key);
                tracing::info!("Purged cache entry for {}", path);
            }
            1
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
                .any(|m| m.eq_ignore_ascii_case(method.as_str()))
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

    fn is_response_cacheable(
        &self,
        response: &Response<bytes::Bytes>,
        _request_headers: &http::HeaderMap,
    ) -> bool {
        if let Some(ref cache) = self.cache {
            let status = response.status().as_u16();
            if !cache.settings().valid_status.contains(&status) {
                return false;
            }

            if let Some(cc) = response.headers().get("cache-control") {
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
        scheme: String,
        host: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let url = format!("{}://{}{}", scheme, host, path);

        match send_request_with_timeout(client, method, &url, Some(Duration::from_secs(5))).await {
            Ok(response) => {
                let status = response.status_code();
                let headers = response.headers.clone();
                let body = response.body.clone();

                if cache.is_status_cacheable(status) {
                    let max_age = get_cache_max_age_static_impl(&headers);
                    if let Err(e) = cache.insert(key, body, status, headers, max_age) {
                        tracing::warn!("Failed to update cached response: {}", e);
                    } else {
                        tracing::debug!("Successfully revalidated cache for {}", path);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Background revalidation failed for {}: {}", path, e);
            }
        }

        Ok(())
    }

    async fn forward_with_pool(
        &self,
        method: http::Method,
        path: &str,
        pool: &UpstreamPool,
        body: Option<bytes::Bytes>,
    ) -> Result<Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        let retry_config = self.retry_config.as_ref();
        let max_retries = retry_config.map(|c| c.max_retries).unwrap_or(3);

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

            let url = format!("{}{}", backend.url.trim_end_matches('/'), path);

            tracing::debug!(
                "Attempting request to upstream: {} (attempt {}/{})",
                url,
                attempt,
                max_retries + 1
            );

            let result = self
                .send_single_request(method.clone(), &url, None, body.clone())
                .await;

            backend.decrement_connections();

            match result {
                Ok(response) => {
                    let status = response.status().as_u16();

                    if let Some(config) = retry_config {
                        if is_retryable_status_impl(status, config) && attempt <= max_retries {
                            if let Some(ref be) = current_backend {
                                pool.mark_failed(&be.url);
                            }

                            if let Some(timeout) = config.timeout_ms {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    calculate_backoff_impl(attempt, timeout),
                                ))
                                .await;
                            }

                            continue;
                        }
                    }

                    return Ok(response);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    last_error = Some(error_str.clone());

                    if let Some(config) = retry_config {
                        let should_retry = (config.retry_on_error && is_connection_error_impl(&*e))
                            || (config.retry_on_timeout && is_timeout_error_impl(&*e));

                        if should_retry && attempt <= max_retries {
                            if let Some(ref be) = current_backend {
                                pool.mark_failed(&be.url);
                            }

                            if let Some(timeout) = config.timeout_ms {
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

                    if attempt <= max_retries {
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

    #[allow(dead_code)]
    fn is_retryable_status(&self, status: u16, config: &RetryConfig) -> bool {
        is_retryable_status_impl(status, config)
    }

    #[allow(dead_code)]
    fn is_connection_error(&self, error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
        is_connection_error_impl(error)
    }

    #[allow(dead_code)]
    fn is_timeout_error(&self, error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
        is_timeout_error_impl(error)
    }

    #[allow(dead_code)]
    fn calculate_backoff(&self, attempt: u32, base_timeout_ms: u64) -> u64 {
        calculate_backoff_impl(attempt, base_timeout_ms)
    }

    async fn send_single_request(
        &self,
        method: http::Method,
        url: &str,
        headers: Option<&http::HeaderMap>,
        body: Option<bytes::Bytes>,
    ) -> Result<Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        use crate::proxy::headers::HOP_BY_HOP_HEADERS;

        let hop_by_hop_headers = HOP_BY_HOP_HEADERS;

        if crate::http_client::is_quictunnel_url(url) {
            let response = crate::http_client::send_request_via_quic_tunnel(
                method,
                url,
                headers,
                body,
                Some(std::time::Duration::from_secs(30)),
            )
            .await?;

            let status = response.status_code();
            let headers_vec: Vec<(String, String)> = response
                .headers_iter()
                .filter(|(k, _)| !hop_by_hop_headers.contains(&k.as_str()))
                .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
                .collect();
            let body = response.body;

            if body.len() > self.max_response_size {
                tracing::warn!(
                    "Upstream response body too large: {} bytes (limit: {})",
                    body.len(),
                    self.max_response_size
                );
                return Err("Response too large".into());
            }

            let mut builder = Response::builder().status(status);

            for (key, value) in headers_vec {
                builder = builder.header(&key, &value);
            }

            return Ok(builder.body(body)?);
        }

        let response = send_request_with_body_and_timeout_with_limit(
            &self.client,
            method,
            url,
            body,
            Some(std::time::Duration::from_secs(30)),
            Some(self.max_response_size),
        )
        .await?;

        let status = response.status_code();

        let headers: Vec<(String, String)> = response
            .headers_iter()
            .filter(|(k, _)| !hop_by_hop_headers.contains(&k.as_str()))
            .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
            .collect();

        let body = response.body;

        let mut builder = Response::builder().status(status);

        for (key, value) in headers {
            builder = builder.header(&key, &value);
        }

        Ok(builder.body(body)?)
    }
}

use http::{header::HeaderName, Method, Response};
use ::metrics::{counter, histogram};
use std::sync::Arc;
use std::time::{Instant, Duration};

use crate::challenge::ChallengeResult;
use crate::config::site::{ProxyHeadersConfig, RetryConfig, BufferingConfig, ProxyCacheConfig};
use crate::waf::{
    BotDetectionResult, EndpointCheckResult, RateLimitResult, UpstreamErrorTracker, WafCore,
};
use crate::http_client::{create_http_client_with_config, send_request_with_timeout, HttpClient};
use crate::metrics::{record_proxy_cache_hit, record_proxy_cache_miss};
use crate::upstream::{UpstreamPool, Backend, LoadBalanceAlgorithm};
use crate::proxy_cache::{ProxyCache, ProxyCacheSettings, CacheKey, CacheKeyBuilder, ProxyCacheEntry, CacheHit};
use ahash::AHashSet;
use once_cell::sync::Lazy;

pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "close",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

pub const HEADERS_TO_STRIP: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "via",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
    "x-backend",
    "x-server",
];

static HOP_BY_HOP_HEADERS_SET: Lazy<AHashSet<&'static str>> = Lazy::new(|| {
    HOP_BY_HOP_HEADERS.iter().copied().collect()
});

static HEADERS_TO_STRIP_SET: Lazy<AHashSet<&'static str>> = Lazy::new(|| {
    HEADERS_TO_STRIP.iter().copied().collect()
});

static HOP_BY_HOP_HEADER_NAMES: Lazy<AHashSet<http::header::HeaderName>> = Lazy::new(|| {
    HOP_BY_HOP_HEADERS.iter().filter_map(|s| s.parse().ok()).collect()
});

#[inline]
pub fn is_hop_by_hop_header(name: &str) -> bool {
    HOP_BY_HOP_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
}

#[inline]
pub fn is_hop_by_hop_header_name(name: &http::header::HeaderName) -> bool {
    HOP_BY_HOP_HEADER_NAMES.contains(name)
}

pub fn build_headers_to_filter(global_headers: &[String], site_headers: &[String]) -> AHashSet<String> {
    let mut to_filter = AHashSet::with_capacity(
        HOP_BY_HOP_HEADERS.len() + 
        HEADERS_TO_STRIP.len() + 
        global_headers.len() + 
        site_headers.len()
    );
    
    to_filter.extend(HOP_BY_HOP_HEADERS_SET.iter().copied().map(String::from));
    to_filter.extend(HEADERS_TO_STRIP_SET.iter().copied().map(String::from));
    
    for header in global_headers {
        let lower = header.to_lowercase();
        to_filter.insert(lower);
    }
    
    for header in site_headers {
        let lower = header.to_lowercase();
        to_filter.insert(lower);
    }
    
    to_filter
}

pub fn sanitize_request_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut prev_was_percent = false;
    let mut decode_buffer = String::new();
    
    for c in path.chars() {
        if c == '%' && !prev_was_percent {
            prev_was_percent = true;
            decode_buffer.clear();
            continue;
        }
        
        if prev_was_percent {
            decode_buffer.push(c);
            if decode_buffer.len() == 2 {
                if let (Ok(h), Ok(l)) = (
                    u8::from_str_radix(&decode_buffer[0..1], 16),
                    u8::from_str_radix(&decode_buffer[1..2], 16),
                ) {
                    let decoded_byte = (h << 4) | l;
                    if decoded_byte == 0 {
                        continue;
                    }
                    if let Some(decoded_char) = char::from_u32(decoded_byte as u32) {
                        result.push(decoded_char);
                    } else {
                        result.push_str(&decode_buffer);
                    }
                } else {
                    result.push('%');
                    result.push_str(&decode_buffer);
                }
                decode_buffer.clear();
            }
            prev_was_percent = false;
        } else if c == '.' && result.ends_with('/') {
            continue;
        } else if c == '/' && result.ends_with('/') {
            continue;
        } else if c.is_control() {
            continue;
        } else {
            result.push(c);
        }
    }
    
    if prev_was_percent {
        result.push('%');
    }
    
    result
}

#[inline]
pub fn filter_response_headers(
    headers: &http::HeaderMap,
    headers_to_filter: &AHashSet<String>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| {
            let name_str = k.as_str();
            !HOP_BY_HOP_HEADERS_SET.contains(name_str) && !headers_to_filter.contains(name_str)
        })
        .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
        .collect()
}

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
}

impl ProxyServer {
    pub fn new(
        upstream_url: String, 
        waf: Arc<WafCore>, 
        max_response_size: usize,
        upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
        site_id: String,
    ) -> Self {
        let client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            100,
            std::time::Duration::from_secs(30),
        );

        let revalidation_client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            50,
            std::time::Duration::from_secs(15),
        );

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
        self.cache_key_builder = Some(CacheKeyBuilder::new(
            settings.key_pattern,
            settings.vary_by,
        ));
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
    ) -> Self {
        let client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            100,
            std::time::Duration::from_secs(30),
        );

        let revalidation_client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            50,
            std::time::Duration::from_secs(15),
        );

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
        }
    }

    pub async fn handle_request(
        &self,
        client_ip: std::net::IpAddr,
        method: http::Method,
        path: String,
        user_agent: Option<String>,
    ) -> Result<Response<String>, String> {
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

        let drop = self.waf.config.drop_blocked_requests;

        match self.check_waf(&client_ip, &path, &method, user_agent.as_deref()).await {
            WafDecision::Drop => {
                counter!("maluwaf.requests.dropped").increment(1);
                return Err("blackholed".to_string());
            }
            WafDecision::Stall => {
                counter!("maluwaf.requests.stalled").increment(1);
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
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
                    .body(html)
                    .unwrap_or_else(|_| Response::builder()
                        .status(500)
                        .body("Internal Server Error".to_string())
                        .unwrap()));
            }
            WafDecision::ChallengeWithCookie { html, session_cookie_name, session_cookie_value, session_cookie_max_age } => {
                counter!("maluwaf.requests.challenged").increment(1);
                histogram!("maluwaf.request.duration").record(start.elapsed());
                let cookie = format!("{}={}; path=/; max-age={}; Secure; SameSite=Strict", session_cookie_name, session_cookie_value, session_cookie_max_age);
                return Ok(Response::builder()
                    .status(200)
                    .header("Content-Type", "text/html")
                    .header("Cache-Control", "no-store, no-cache, must-revalidate")
                    .header("Set-Cookie", cookie)
                    .body(html)
                    .unwrap_or_else(|_| Response::builder()
                        .status(500)
                        .body("Internal Server Error".to_string())
                        .unwrap()));
            }
            WafDecision::Tarpit(_) => {
                counter!("maluwaf.requests.tarpitted").increment(1);
                histogram!("maluwaf.request.duration").record(start.elapsed());
            }
            WafDecision::Pass => {}
        }

        let forward_result = self.forward_request(method, &path).await;

        match forward_result {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();
                
                if let Some(ref tracker) = self.upstream_error_tracker {
                    if status_code >= 400 {
                        let result = tracker.record_error(client_ip, &path, status_code);
                        
                        match result {
                            crate::waf::UpstreamErrorResult::ProbingDetected { unique_endpoints, error_count } => {
                                tracing::warn!(
                                    ip = %client_ip,
                                    endpoints = ?unique_endpoints,
                                    error_count = error_count,
                                    status_code = status_code,
                                    "Potential upstream vulnerability probe detected - healthy upstream returning errors"
                                );
                                
                                let config = tracker.get_config();
                                if config.auto_ban_elevated_threat {
                                    let threat_level = self.waf.threat_level.as_ref()
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
                                            store.block_ip(client_ip, "upstream_error_probe", ban_duration, "global");
                                        }
                                        if let Some(ref threat_intel) = crate::waf::get_threat_intel() {
                                            let _ = threat_intel.announce_local_block(
                                                client_ip,
                                                "upstream_error_probe".to_string(),
                                                ban_duration,
                                                "global".to_string(),
                                            );
                                        }
                                    }
                                }
                            }
                            _ => {}
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
                    .body("Bad Gateway".to_string())
                    .unwrap_or_else(|_| Response::builder()
                        .status(500)
                        .body("Internal Server Error".to_string())
                        .unwrap()))
            }
        }
    }

    async fn check_waf(
        &self,
        client_ip: &std::net::IpAddr,
        path: &str,
        method: &Method,
        user_agent: Option<&str>,
    ) -> WafDecision {
        if self.waf.whitelist.contains(client_ip) {
            return WafDecision::Pass;
        }

        if self.waf.rate_limiter.is_in_blackhole() {
            counter!("maluwaf.ratelimit.blackhole_drop").increment(1);
            return WafDecision::Drop;
        }

        match self.waf.rate_limiter.check_global() {
            RateLimitResult::Blackholed => {
                counter!("maluwaf.ratelimit.blackhole_drop").increment(1);
                return WafDecision::Drop;
            }
            RateLimitResult::Limited { limit_type, retry_after_millis } => {
                tracing::debug!("Global rate limited: {} ({})", limit_type, retry_after_millis);
                return WafDecision::Block(429, format!("Global rate limit exceeded ({})", limit_type));
            }
            RateLimitResult::Allowed => {}
        }

        match self.waf.rate_limiter.acquire_global_connection().await {
            Ok(_permit) => {}
            Err(_) => {
                tracing::warn!("Global connection limit exceeded");
                return WafDecision::Block(503, "Service Unavailable - Server overloaded".to_string());
            }
        }

        match self.waf.rate_limiter.check_rate_limit(*client_ip).await {
            RateLimitResult::Limited { limit_type, retry_after_millis } => {
                tracing::debug!("Rate limited: {} for {} ({})", limit_type, client_ip, retry_after_millis);
                let body = format!("Rate limit exceeded ({})", limit_type);
                return WafDecision::Block(429, body);
            }
            RateLimitResult::Blackholed => {
                return WafDecision::Drop;
            }
            RateLimitResult::Allowed => {}
        }

        if let EndpointCheckResult::Blocked { response_code: _, html: _, .. } =
            self.waf.endpoint_blocker.check(path, method.as_str())
        {
            tracing::info!("Blocked endpoint accessed: {} - method: {}", path, method);
            return WafDecision::Stall;
        }

        let bot_result = self.waf.bot_detector.check(user_agent);
        match bot_result {
            BotDetectionResult::Blocked { reason, .. } => {
                tracing::info!("Blocking bot: {} - UA: {:?}", reason, user_agent);
                return WafDecision::Stall;
            }
            BotDetectionResult::Tarpit { reason, .. } => {
                tracing::info!("Tarpitting scraper: {} - UA: {:?}", reason, user_agent);
                return WafDecision::Tarpit(path.to_string());
            }
            BotDetectionResult::Allowed { .. } => {}
        }

        if let Some(matched) = self.waf.sensitive_endpoint_manager.check(path) {
            tracing::info!("Honeypot endpoint accessed: {} - matched: {}", path, matched);
            if let Some(ref store) = self.waf.block_store {
                let ban_duration = 24 * 60 * 60;
                store.block_ip(*client_ip, "honeypot", ban_duration, "global");
            }
            if let Some(ref threat_intel) = crate::waf::get_threat_intel() {
                let _ = threat_intel.announce_local_block(
                    *client_ip,
                    "honeypot".to_string(),
                    24 * 60 * 60,
                    "global".to_string(),
                );
            }
            return WafDecision::Stall;
        }

        if self.waf.challenge_manager.is_honeypot_hit(client_ip, path) {
            tracing::info!("IP-bound honeypot accessed: {} by {}", path, client_ip);
            if let Some(ref store) = self.waf.block_store {
                let ban_duration = 24 * 60 * 60;
                store.block_ip(*client_ip, "honeypot", ban_duration, "global");
            }
            if let Some(ref threat_intel) = crate::waf::get_threat_intel() {
                let _ = threat_intel.announce_local_block(
                    *client_ip,
                    "honeypot".to_string(),
                    24 * 60 * 60,
                    "global".to_string(),
                );
            }
            return WafDecision::Stall;
        }

        if self.waf.config.enable_pow_challenge || self.waf.config.enable_css_honeypot {
            let challenge_result = self.waf.challenge_manager.check_cookie(None);
            match challenge_result {
                ChallengeResult::NotSet | ChallengeResult::Failed => {
                    let (html, session_id) = self.waf.challenge_manager.generate_challenge_page(client_ip);
                    if let Some(sid) = session_id {
                        let session_cookie_name = self.waf.challenge_manager.css_session_cookie_name();
                        let window_secs = self.waf.challenge_manager.css_window_secs();
                        return WafDecision::ChallengeWithCookie {
                            html,
                            session_cookie_name,
                            session_cookie_value: sid,
                            session_cookie_max_age: window_secs,
                        };
                    } else {
                        return WafDecision::Challenge(html);
                    }
                }
                ChallengeResult::Passed => {}
                ChallengeResult::RateLimited => {
                    return WafDecision::Pass;
                }
            }
        }

        WafDecision::Pass
    }

    async fn forward_request(
        &self,
        method: http::Method,
        path: &str,
    ) -> Result<Response<String>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref pool) = self.upstream_pool {
            return self.forward_with_pool(method, path, pool).await;
        }

        let url = format!("{}{}", self.upstream_url, path);
        self.send_single_request(method, &url, None).await
    }

    pub async fn forward_request_via_tunnel(
        &self,
        method: http::Method,
        tunnel_url: &str,
        path: &str,
        headers: Option<&http::HeaderMap>,
        _body: Option<bytes::Bytes>,
    ) -> Result<Response<String>, Box<dyn std::error::Error + Send + Sync>> {
        let full_url = format!("{}{}", tunnel_url, path);
        self.send_single_request(method, &full_url, headers).await
    }

    pub async fn handle_request_with_cache(
        &self,
        method: http::Method,
        path: &str,
        host: &str,
        headers: &http::HeaderMap,
        scheme: &str,
    ) -> Result<Response<String>, String> {
        if method.as_str() == "PURGE" {
            return self.handle_cache_purge(path, host).await;
        }

        if !self.is_cacheable_method(&method) {
            return self.forward_request(method, path).await.map_err(|e| e.to_string());
        }

        if let (Some(cache), Some(key_builder)) = (&self.cache, &self.cache_key_builder) {
            if cache.is_enabled() {
                if self.should_bypass_cache(headers) {
                    tracing::debug!("Cache bypass requested for {}", path);
                } else {
                    let uri = http::Uri::try_from(path).unwrap_or_else(|_| http::Uri::from_static("/"));
                    let cache_key = key_builder.build(scheme, &method, host, &uri, headers, &self.site_id);
                    
                    let hit_status = cache.get_hit_status(&cache_key);
                    
                    if let Some(cached) = cache.get(&cache_key) {
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
                                tracing::debug!("Triggering background revalidation for {}", path_owned);
                                let _ = Self::revalidate_cache_entry(
                                    &reval_client,
                                    cache_clone,
                                    key_clone,
                                    method_clone,
                                    path_owned,
                                    scheme_owned,
                                    host_owned,
                                ).await;
                            });
                            
                            counter!("maluwaf.proxy.cache.stale_while_revalidate").increment(1);
                        }
                        
                        let response = self.build_cached_response(cached);
                        return Ok(response);
                    }
                    
                    tracing::debug!("Cache MISS for {}", path);
                    counter!("maluwaf.proxy.cache.miss").increment(1);
                    cache.record_cache_miss();
                    record_proxy_cache_miss();
                    
                    let result = self.forward_request(method.clone(), path).await;
                    
                    match result {
                        Ok(response) => {
                            self.process_cache_invalidate_header(response.headers());
                            
                            if self.is_response_cacheable(&response, headers) {
                                let status = response.status().as_u16();
                                let body = bytes::Bytes::from(response.body().clone());
                                let headers = self.filter_sensitive_headers(response.headers());
                                let max_age = self.get_cache_max_age(&headers);
                                
                                if let Err(e) = cache.insert(cache_key, body, status, headers, max_age) {
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
        
        self.forward_request(method, path).await.map_err(|e| e.to_string())
    }

    fn filter_sensitive_headers(&self, headers: &http::HeaderMap) -> http::HeaderMap {
        const SENSITIVE_HEADERS: &[&str] = &[
            "set-cookie",
            "authorization",
            "www-authenticate",
            "proxy-authenticate",
            "proxy-authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
        ];
        
        let mut filtered = http::HeaderMap::new();
        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            if !SENSITIVE_HEADERS.contains(&name_str) {
                filtered.insert(name, value.clone());
            }
        }
        filtered
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

    async fn handle_cache_purge(&self, path: &str, host: &str) -> Result<Response<String>, String> {
        let count = if path == "*" {
            if let Some(ref cache) = self.cache {
                cache.clear();
                tracing::info!("Purged all cache entries for host {}", host);
                1
            } else {
                0
            }
        } else if path.starts_with("*/") {
            let pattern = &path[2..];
            if let Some(ref cache) = self.cache {
                let count = cache.invalidate_by_pattern(pattern);
                tracing::info!("Purged {} cache entries matching pattern {}", count, pattern);
                count
            } else {
                0
            }
        } else {
            if let Some(ref cache) = self.cache {
                if let Some(cache_key) = CacheKey::from_cache_string(
                    &format!("GET:{}:{}", host, path)
                ) {
                    cache.invalidate(&cache_key);
                    tracing::info!("Purged cache entry for {}", path);
                }
                1
            } else {
                0
            }
        };

        Ok(Response::builder()
            .status(200)
            .body(format!("Purged {} entries\n", count))
            .unwrap())
    }

    fn process_cache_invalidate_header(&self, headers: &http::HeaderMap) {
        if let Some(invalidate) = headers.get("x-cache-invalidate") {
            if let Ok(invalidate_str) = invalidate.to_str() {
                if let Some(ref cache) = self.cache {
                    for pattern in invalidate_str.split(',') {
                        let pattern = pattern.trim();
                        let count = cache.invalidate_by_pattern(pattern);
                        if count > 0 {
                            tracing::debug!("X-Cache-Invalidate: purged {} entries matching '{}'", count, pattern);
                        }
                    }
                }
            }
        }
    }

    fn is_cacheable_method(&self, method: &http::Method) -> bool {
        if let Some(ref cache) = self.cache {
            cache.settings().methods.iter().any(|m| m.eq_ignore_ascii_case(method.as_str()))
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

    fn is_response_cacheable(&self, response: &Response<String>, _request_headers: &http::HeaderMap) -> bool {
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
        if let Some(cc) = headers.get("cache-control") {
            if let Ok(cc_str) = cc.to_str() {
                for part in cc_str.split(',') {
                    let part = part.trim();
                    if part.starts_with("max-age=") {
                        if let Ok(age) = part[8..].parse::<u64>() {
                            return Some(std::time::Duration::from_secs(age));
                        }
                    }
                }
            }
        }
        None
    }

    fn build_cached_response(&self, entry: ProxyCacheEntry) -> Response<String> {
        let mut builder = Response::builder().status(entry.status);
        
        for (name, value) in entry.headers.iter() {
            builder = builder.header(name, value);
        }
        
        let mut cache_directive = if entry.is_fresh {
            "public".to_string()
        } else {
            "public, stale-while-revalidate".to_string()
        };
        
        if let Some(expires_at) = entry.expires_at {
            let max_age = expires_at.saturating_duration_since(std::time::Instant::now());
            if max_age.as_secs() > 0 {
                cache_directive.push_str(&format!(", max-age={}", max_age.as_secs()));
            }
        }
        
        if let Some(swr) = entry.stale_while_revalidate {
            let swr_age = swr.saturating_duration_since(std::time::Instant::now());
            if swr_age.as_secs() > 0 {
                cache_directive.push_str(&format!(", stale-while-revalidate={}", swr_age.as_secs()));
            }
        }
        
        if let Some(sie) = entry.stale_if_error {
            let sie_age = sie.saturating_duration_since(std::time::Instant::now());
            if sie_age.as_secs() > 0 {
                cache_directive.push_str(&format!(", stale-if-error={}", sie_age.as_secs()));
            }
        }
        
        builder = builder.header("Cache-Control", cache_directive);
        
        if entry.is_fresh {
            builder = builder.header("X-Cache", "HIT");
        } else {
            builder = builder.header("X-Cache", "STALE");
        }
        
        builder.body(String::from_utf8_lossy(&entry.content).to_string()).unwrap_or_else(|_| {
            Response::builder()
                .status(500)
                .body("Internal Server Error".to_string())
                .unwrap()
        })
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
                let body = bytes::Bytes::from(response.body.clone());
                
                if cache.is_status_cacheable(status) {
                    let max_age = Self::get_cache_max_age_static(&headers);
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
    
    fn get_cache_max_age_static(headers: &http::HeaderMap) -> Option<Duration> {
        if let Some(cc) = headers.get("cache-control") {
            if let Ok(cc_str) = cc.to_str() {
                for part in cc_str.split(',') {
                    let part = part.trim();
                    if part.starts_with("max-age=") {
                        if let Ok(age) = part[8..].parse::<u64>() {
                            return Some(Duration::from_secs(age));
                        }
                    }
                }
            }
        }
        None
    }

    async fn forward_with_pool(
        &self,
        method: http::Method,
        path: &str,
        pool: &UpstreamPool,
    ) -> Result<Response<String>, Box<dyn std::error::Error + Send + Sync>> {
        let retry_config = self.retry_config.as_ref();
        let max_retries = retry_config.map(|c| c.max_retries).unwrap_or(3);
        
        let mut current_backend: Option<Backend> = None;
        let mut last_error: Option<String> = None;
        let mut attempt = 0;
        let mut tried_backends: std::collections::HashSet<std::sync::Arc<String>> = std::collections::HashSet::new();

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
            
            tracing::debug!("Attempting request to upstream: {} (attempt {}/{})", url, attempt, max_retries + 1);

            let result = self.send_single_request(method.clone(), &url, None).await;

            backend.decrement_connections();

            match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    
                    if let Some(ref config) = retry_config {
                        if self.is_retryable_status(status, config) && attempt <= max_retries {
                            if let Some(ref be) = current_backend {
                                pool.mark_failed(&be.url);
                            }
                            
                            if let Some(timeout) = config.timeout_ms {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    self.calculate_backoff(attempt, timeout)
                                )).await;
                            }
                            
                            continue;
                        }
                    }
                    
                    return Ok(response);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    last_error = Some(error_str.clone());
                    
                    if let Some(ref config) = retry_config {
                        let should_retry = (config.retry_on_error && self.is_connection_error(&error_str))
                            || (config.retry_on_timeout && self.is_timeout_error(&error_str));
                        
                        if should_retry && attempt <= max_retries {
                            if let Some(ref be) = current_backend {
                                pool.mark_failed(&be.url);
                            }
                            
                            if let Some(timeout) = config.timeout_ms {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    self.calculate_backoff(attempt, timeout)
                                )).await;
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

        Err(format!("All upstream servers failed after {} attempts: {}", attempt, last_error.unwrap_or_default()).into())
    }

    fn is_retryable_status(&self, status: u16, config: &RetryConfig) -> bool {
        if !config.retry_on_status.is_empty() {
            return config.retry_on_status.contains(&status);
        }
        false
    }

    fn is_connection_error(&self, error: &str) -> bool {
        let error_lower = error.to_lowercase();
        error_lower.contains("connection")
            || error_lower.contains("refused")
            || error_lower.contains("reset")
            || error_lower.contains("broken pipe")
            || error_lower.contains("network")
    }

    fn is_timeout_error(&self, error: &str) -> bool {
        let error_lower = error.to_lowercase();
        error_lower.contains("timeout") || error_lower.contains("timed out")
    }

    fn calculate_backoff(&self, attempt: u32, base_timeout_ms: u64) -> u64 {
        let delay = base_timeout_ms * 2u64.saturating_pow(attempt.min(5));
        delay.min(30000)
    }

    async fn send_single_request(
        &self,
        method: http::Method,
        url: &str,
        headers: Option<&http::HeaderMap>,
    ) -> Result<Response<String>, Box<dyn std::error::Error + Send + Sync>> {
        let hop_by_hop_headers = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ];

        if crate::http_client::is_quictunnel_url(url) {
            let response = crate::http_client::send_request_via_quic_tunnel(
                method,
                url,
                headers,
                None,
                Some(std::time::Duration::from_secs(30)),
            ).await?;
            
            let status = response.status_code();
            let headers_vec: Vec<(String, String)> = response
                .headers_iter()
                .filter(|(k, _)| !hop_by_hop_headers.contains(&k.as_str()))
                .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
                .collect();
            let body = response.body;
            
            if body.len() > self.max_response_size {
                tracing::warn!("Upstream response body too large: {} bytes (limit: {})", body.len(), self.max_response_size);
                return Err("Response too large".into());
            }
            
            let mut builder = Response::builder().status(status);
            
            for (key, value) in headers_vec {
                builder = builder.header(&key, &value);
            }
            
            return Ok(builder.body(body)?);
        }
        
        let response = send_request_with_timeout(
            &self.client,
            method,
            url,
            Some(std::time::Duration::from_secs(30)),
        ).await?;
        
        let status = response.status_code();
        
        let content_length = response.header("content-length")
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(size) = content_length {
            if size > self.max_response_size {
                tracing::warn!("Upstream response too large: {} bytes (limit: {})", size, self.max_response_size);
                return Err("Response too large".into());
            }
        }
        
        let headers: Vec<(String, String)> = response
            .headers_iter()
            .filter(|(k, _)| !hop_by_hop_headers.contains(&k.as_str()))
            .filter_map(|(k, v)| v.to_str().ok().map(|vv| (k.to_string(), vv.to_string())))
            .collect();
        
        let body = response.body;
        
        if body.len() > self.max_response_size {
            tracing::warn!("Upstream response body too large: {} bytes (limit: {})", body.len(), self.max_response_size);
            return Err("Response too large".into());
        }
        
        let mut builder = Response::builder().status(status);
        
        for (key, value) in headers {
            builder = builder.header(&key, &value);
        }
        
        Ok(builder.body(body)?)
    }
}

/// WAF decision for a request.
///
/// This enum represents the result of WAF inspection, indicating how the
/// request should be handled.
pub enum WafDecision {
    /// Block the request with the given HTTP status code and message.
    Block(u16, String),
    /// Challenge the client with the given HTML challenge page.
    Challenge(String),
    /// Challenge with Set-Cookie headers (for CSS challenges).
    ChallengeWithCookie {
        html: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
    /// Feed the client tarpit content (markov chain generated).
    Tarpit(String),
    /// Allow the request to pass through to the backend.
    Pass,
    /// Silently drop the connection without response.
    Drop,
    /// Stall the connection (for honeypot endpoints).
    Stall,
}

pub fn apply_response_header_transforms(
    headers: &mut http::HeaderMap,
    config: &ProxyHeadersConfig,
) {
    if config.clear.is_empty() && config.set.is_empty() && config.hide.is_empty() {
        return;
    }
    
    let clear_patterns: Vec<String> = config.clear.iter().cloned().collect();
    let hide_patterns: Vec<String> = config.hide.iter().cloned().collect();
    
    let should_remove = |name: &http::header::HeaderName| -> bool {
        let name_str = name.as_str();
        
        for pattern in &clear_patterns {
            if pattern.contains('*') {
                let prefix = pattern.trim_end_matches('*');
                if name_str.starts_with(prefix) {
                    return true;
                }
            } else if name_str == pattern.to_lowercase() {
                return true;
            }
        }
        
        for pattern in &hide_patterns {
            if pattern.contains('*') {
                let prefix = pattern.trim_end_matches('*');
                if name_str.starts_with(prefix) {
                    return true;
                }
            } else if name_str == pattern.to_lowercase() {
                return true;
            }
        }
        
        false
    };
    
    let mut new_headers = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        if !should_remove(name) {
            new_headers.insert(name, value.clone());
        }
    }
    
    for override_hdr in &config.set {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(override_hdr.name.as_bytes()),
            override_hdr.value.parse(),
        ) {
            new_headers.insert(name, value);
        }
    }
    
    *headers = new_headers;
}

pub fn build_forward_headers(
    client_ip: std::net::IpAddr,
    original_headers: &http::HeaderMap,
    config: &ProxyHeadersConfig,
    is_tls: bool,
) -> Vec<(String, String)> {
    let mut forward_headers = Vec::new();
    
    let headers_to_forward: Vec<&str> = if config.forward.is_empty() {
        vec!["X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto", "Host"]
    } else {
        config.forward.iter().map(|s| s.as_str()).collect()
    };
    
    for header_name in headers_to_forward {
        match header_name {
            "X-Real-IP" => {
                forward_headers.push(("X-Real-IP".to_string(), client_ip.to_string()));
            }
            "X-Forwarded-For" => {
                let existing = original_headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let new_value = if existing.is_empty() {
                    client_ip.to_string()
                } else {
                    format!("{}, {}", existing, client_ip)
                };
                forward_headers.push(("X-Forwarded-For".to_string(), new_value));
            }
            "X-Forwarded-Proto" => {
                let proto = if is_tls { "https" } else { "http" };
                forward_headers.push(("X-Forwarded-Proto".to_string(), proto.to_string()));
            }
            "X-Forwarded-Host" => {
                if let Some(host) = original_headers.get("host") {
                    if let Ok(host_str) = host.to_str() {
                        forward_headers.push(("X-Forwarded-Host".to_string(), host_str.to_string()));
                    }
                }
            }
            "Host" | "host" => {
                if let Some(host) = original_headers.get("host") {
                    if let Ok(host_str) = host.to_str() {
                        forward_headers.push(("Host".to_string(), host_str.to_string()));
                    }
                }
            }
            _ => {
                if let Some(value) = original_headers.get(header_name) {
                    if let Ok(value_str) = value.to_str() {
                        forward_headers.push((header_name.to_string(), value_str.to_string()));
                    }
                }
            }
        }
    }
    
    forward_headers
}

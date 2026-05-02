use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::HeaderName;
use http::{HeaderMap, Method, Request, Response};

use crate::config::site::SiteProxyConfig;
use crate::config::SiteSecurityHeadersConfig;
use crate::http_client::{HttpClient, HttpResponse};
use crate::proxy_cache::{CacheHit, CacheKey, CacheKeyBuilder, ProxyCache, ProxyCacheEntry};
use crate::utils;

use super::cache::{
    build_cached_response, filter_sensitive_headers, get_cache_max_age_static,
};
use super::headers::build_forward_headers;
use super::join_upstream_url;

#[derive(Debug)]
pub struct ResponseSizeError;

impl std::fmt::Display for ResponseSizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "response body exceeds size limit")
    }
}

impl std::error::Error for ResponseSizeError {}

pub struct PreparedUpstreamTarget {
    pub url: String,
    pub timeout: Duration,
    pub max_response_size: Option<usize>,
}

impl PreparedUpstreamTarget {
    pub fn new(upstream: &str, path: &str, config: Option<&SiteProxyConfig>) -> Self {
        let url = join_upstream_url(upstream, path);
        let timeout = config
            .and_then(|c| c.upstream.as_ref())
            .and_then(|u| u.read_timeout.as_deref())
            .and_then(utils::parse_duration)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        let max_response_size = config.and_then(|c| c.max_response_size);
        Self {
            url,
            timeout,
            max_response_size,
        }
    }
}

pub struct UpstreamResponsePolicy {
    pub headers_to_filter: HashSet<HeaderName>,
    pub security_headers: Option<SiteSecurityHeadersConfig>,
    pub max_response_size: Option<usize>,
}

/// Check if a buffered response body exceeds the configured size limit.
///
/// For **buffered responses**: hard limit check. Returns `Err(ResponseSizeError)`
/// if the body exceeds `max_size`, and the caller should respond with 502 Bad Gateway.
///
/// For **streaming responses**: this function cannot be used directly since the body
/// is not fully buffered. Use a content-length header pre-check instead — compare the
/// advertised content-length against `max_size` before streaming. Note that chunked
/// or unknown-length responses may still exceed the limit since the actual body size
/// is not known until fully received.
pub fn apply_response_size_limit(
    body: &[u8],
    max_size: Option<usize>,
) -> Result<(), ResponseSizeError> {
    if let Some(max) = max_size {
        if body.len() > max {
            return Err(ResponseSizeError);
        }
    }
    Ok(())
}

pub fn build_upstream_request(
    method: &Method,
    target: &PreparedUpstreamTarget,
    headers: HeaderMap,
) -> Request<Bytes> {
    let mut req = Request::builder()
        .method(method.clone())
        .uri(&target.url)
        .body(Bytes::new())
        .unwrap_or_else(|e| panic!("failed to build upstream request: {}", e));
    *req.headers_mut() = headers;
    req
}

pub struct ProxyExecutor {
    pub cache: Option<Arc<ProxyCache>>,
    pub cache_key_builder: Option<CacheKeyBuilder>,
    pub site_id: String,
    pub upstream_url: String,
    pub client: HttpClient,
    pub revalidation_client: HttpClient,
}

impl ProxyExecutor {
    pub async fn execute_with_cache(
        &self,
        method: Method,
        path: &str,
        host: &str,
        headers: &HeaderMap,
        scheme: &str,
        body: Option<Bytes>,
        client_ip: std::net::IpAddr,
    ) -> Result<Response<Bytes>, String> {
        if !self.is_cacheable_method(&method) {
            return self.forward_request(method, path, body, headers, client_ip).await;
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
                            let is_swr = matches!(hit_status, Some(CacheHit::StaleWhileRevalidate));

                            if is_swr {
                                self.trigger_revalidation(
                                    cache.clone(),
                                    cache_key,
                                    method.clone(),
                                    path.to_string(),
                                    client_ip,
                                    headers,
                                );
                            }

                            return Ok(build_cached_response(&cached));
                        }

                        tracing::debug!("Cache MISS for {}", path);
                        let result = self.forward_request(method, path, body, headers, client_ip).await;

                        match result {
                            Ok(response) => {
                                if self.is_response_cacheable(&response) {
                                    let status = response.status().as_u16();
                                    let body = response.body().clone();
                                    let filtered_headers = filter_sensitive_headers(response.headers());
                                    let max_age = get_cache_max_age_static(&filtered_headers);

                                    if let Err(e) =
                                        cache.insert(cache_key, body, status, filtered_headers, max_age)
                                    {
                                        tracing::warn!("Failed to cache response: {}", e);
                                    }
                                }
                                return Ok(response);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }

        self.forward_request(method, path, body, headers, client_ip).await
    }

    async fn forward_request(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        headers: &HeaderMap,
        client_ip: std::net::IpAddr,
    ) -> Result<Response<Bytes>, String> {
        let url = join_upstream_url(&self.upstream_url, path);
        let forward_headers = build_forward_headers(
            client_ip,
            headers,
            &crate::config::site::ProxyHeadersConfig::default(),
            true,
        );

        match crate::http_client::send_request_with_body_headers_and_timeout(
            &self.client,
            method,
            &url,
            body,
            forward_headers,
            Some(Duration::from_secs(30)),
        )
        .await
        {
            Ok(resp) => {
                let mut builder = Response::builder().status(resp.status);
                for (k, v) in resp.headers.iter() {
                    builder = builder.header(k, v);
                }
                Ok(builder.body(resp.body).unwrap_or_else(|_| crate::http::fallback_error_bytes()))
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn is_cacheable_method(&self, method: &Method) -> bool {
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

    fn should_bypass_cache(&self, headers: &HeaderMap) -> bool {
        if let Some(cc) = headers.get("cache-control") {
            if let Ok(cc_str) = cc.to_str() {
                let cc_lower = cc_str.to_ascii_lowercase();
                return cc_lower.contains("no-cache")
                    || cc_lower.contains("no-store")
                    || cc_lower.contains("private");
            }
        }
        false
    }

    fn is_response_cacheable(&self, response: &Response<Bytes>) -> bool {
        if let Some(ref cache) = self.cache {
            let status = response.status().as_u16();
            if !cache.settings().valid_status.contains(&status) {
                return false;
            }

            if let Some(cc) = response.headers().get("cache-control") {
                if let Ok(cc_str) = cc.to_str() {
                    let cc_lower = cc_str.to_ascii_lowercase();
                    if cc_lower.contains("no-store") || cc_lower.contains("private") {
                        return false;
                    }
                }
            }

            return true;
        }
        false
    }

    fn trigger_revalidation(
        &self,
        cache: Arc<ProxyCache>,
        key: CacheKey,
        method: Method,
        path: String,
        client_ip: std::net::IpAddr,
        original_headers: &HeaderMap,
    ) {
        let reval_client = self.revalidation_client.clone();
        let upstream_url = self.upstream_url.clone();
        let reval_headers = build_forward_headers(
            client_ip,
            original_headers,
            &crate::config::site::ProxyHeadersConfig::default(),
            true,
        );

        tokio::spawn(async move {
            tracing::debug!("Triggering background revalidation for {}", path);
            let url = join_upstream_url(&upstream_url, &path);
            
            match crate::http_client::send_request_with_body_headers_and_timeout(
                &reval_client,
                method,
                &url,
                None,
                reval_headers,
                Some(Duration::from_secs(5)),
            )
            .await
            {
                Ok(resp) => {
                    if cache.is_status_cacheable(resp.status.as_u16()) {
                        let filtered_headers = filter_sensitive_headers(&resp.headers);
                        let max_age = get_cache_max_age_static(&filtered_headers);
                        if let Err(e) = cache.insert(key, resp.body, resp.status.as_u16(), filtered_headers, max_age) {
                            tracing::warn!("Failed to update cached response: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Background revalidation failed for {}: {}", path, e);
                }
            }
        });
    }
}

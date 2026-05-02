use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use http::header::HeaderName;
use http::{HeaderMap, Method, Request};

use crate::config::site::SiteProxyConfig;
use crate::config::SiteSecurityHeadersConfig;
use crate::utils;

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

use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body_util::Full;
use std::sync::Arc;
use std::time::Duration;

use crate::{build_forward_headers, ForwardedProtocol};
use synvoid_config::site::ProxyHeadersConfig;
use synvoid_http_client::eggfetch_transport::{EggfetchResponseBody, EggfetchUpstreamClient};

pub struct DispatchParams {
    pub lane_client: EggfetchUpstreamClient,
    pub method: Method,
    pub upstream_url: String,
    pub body: Bytes,
    pub headers: HeaderMap,
    pub timeout: Duration,
    pub forwarded_protocol: ForwardedProtocol,
    pub proxy_config: Arc<ProxyHeadersConfig>,
    pub client_ip: std::net::IpAddr,
    /// Retained for API compatibility. The legacy transport used this only
    /// as a pool-lookup hint (never for protocol switching); the eggfetch
    /// lane negotiates HTTP/1 vs HTTP/2 via ALPN instead, so this is ignored.
    pub is_http2: bool,
}

#[derive(Debug)]
pub struct UpstreamDispatchError {
    pub message: String,
    pub status: Option<u16>,
}

impl std::fmt::Display for UpstreamDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UpstreamDispatchError {}

pub async fn dispatch_to_upstream(
    params: DispatchParams,
) -> Result<Response<EggfetchResponseBody>, UpstreamDispatchError> {
    let forward_headers = build_forward_headers(
        params.client_ip,
        &params.headers,
        &params.proxy_config,
        params.forwarded_protocol,
    );

    // Phase 60: eggfetch lane. `execute` streams the response like the
    // legacy erased path did; ALPN negotiates the protocol (`is_http2`
    // was pool-hint-only upstream).
    let uri: http::Uri = params
        .upstream_url
        .parse()
        .map_err(|e| UpstreamDispatchError {
            message: format!(
                "Upstream request failed: invalid URL {}: {}",
                params.upstream_url, e
            ),
            status: None,
        })?;
    let mut req = http::Request::builder()
        .method(params.method)
        .uri(uri)
        .body(Full::new(params.body))
        .map_err(|e| UpstreamDispatchError {
            message: format!("Upstream request failed: cannot build request: {}", e),
            status: None,
        })?;
    // Mirror the legacy helpers: caller headers replace, not append.
    *req.headers_mut() = forward_headers;
    let response = params
        .lane_client
        .execute(req, Some(params.timeout), None)
        .await
        .map_err(|e| UpstreamDispatchError {
            message: format!("Upstream request failed: {}", e),
            status: None,
        })?;

    Ok(response)
}

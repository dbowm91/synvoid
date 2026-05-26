use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use std::sync::Arc;
use std::time::Duration;

use crate::config::site::ProxyHeadersConfig;
use crate::http_client::{send_request_streaming, HttpClient};
use crate::proxy::{build_forward_headers, ForwardedProtocol};

pub struct DispatchParams {
    pub client: HttpClient,
    pub method: Method,
    pub upstream_url: String,
    pub body: Bytes,
    pub headers: HeaderMap,
    pub timeout: Duration,
    pub forwarded_protocol: ForwardedProtocol,
    pub proxy_config: Arc<ProxyHeadersConfig>,
    pub client_ip: std::net::IpAddr,
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
) -> Result<Response<Incoming>, UpstreamDispatchError> {
    let forward_headers = build_forward_headers(
        params.client_ip,
        &params.headers,
        &params.proxy_config,
        params.forwarded_protocol,
    );

    let body = Full::new(params.body);
    let response = send_request_streaming(
        &params.client,
        params.method,
        &params.upstream_url,
        body,
        forward_headers,
        Some(params.timeout),
    )
    .await
    .map_err(|e| UpstreamDispatchError {
        message: format!("Upstream request failed: {}", e),
        status: None,
    })?;

    Ok(response)
}

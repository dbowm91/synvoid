use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use std::sync::Arc;
use std::time::Duration;

use crate::{build_forward_headers, ForwardedProtocol};
use synvoid_config::site::ProxyHeadersConfig;
use synvoid_http_client::{
    send_request_erased_streaming, ErasedBodyImpl, ErasedHttpClient, HttpClient,
};

pub struct DispatchParams {
    pub client: HttpClient,
    pub erased_client: ErasedHttpClient,
    pub method: Method,
    pub upstream_url: String,
    pub body: Bytes,
    pub headers: HeaderMap,
    pub timeout: Duration,
    pub forwarded_protocol: ForwardedProtocol,
    pub proxy_config: Arc<ProxyHeadersConfig>,
    pub client_ip: std::net::IpAddr,
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
) -> Result<Response<Incoming>, UpstreamDispatchError> {
    let forward_headers = build_forward_headers(
        params.client_ip,
        &params.headers,
        &params.proxy_config,
        params.forwarded_protocol,
    );

    let body = ErasedBodyImpl::from_full(Full::new(params.body));
    let response = send_request_erased_streaming(
        &params.erased_client,
        params.method,
        &params.upstream_url,
        body,
        forward_headers,
        Some(params.timeout),
        params.is_http2,
    )
    .await
    .map_err(|e| UpstreamDispatchError {
        message: format!("Upstream request failed: {}", e),
        status: None,
    })?;

    Ok(response)
}

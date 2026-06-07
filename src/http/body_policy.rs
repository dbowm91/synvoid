use bytes::Bytes;
use std::net::IpAddr;
use std::sync::Arc;

use crate::waf::WafCore;

use synvoid_http::collect_and_scan_request_body as collect_and_scan_request_body_impl;
pub use synvoid_http::BodyPolicyError;

pub async fn collect_and_scan_request_body(
    body: hyper::body::Incoming,
    waf: &Arc<WafCore>,
    client_ip: IpAddr,
    content_length: Option<usize>,
    max_streaming_body_size: usize,
) -> Result<(Bytes, u64), BodyPolicyError> {
    collect_and_scan_request_body_impl(
        body,
        waf.as_ref(),
        client_ip,
        content_length,
        max_streaming_body_size,
    )
    .await
}

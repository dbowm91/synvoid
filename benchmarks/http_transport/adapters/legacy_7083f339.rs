//! Legacy Hyper-lane adapter, pinned to immutable revision `7083f339`.
//!
//! Uses the exact legacy production-equivalent client construction and call
//! path from the pre-migration tree:
//!
//! - small requests: `create_upstream_client` + `send_request_with_body_and_timeout`
//!   (buffered GET, the legacy small-request production path);
//! - streaming: `create_upstream_streaming_client` + `send_request_streaming_generic`
//!   (the same generic entry point production used in
//!   `upstream_proxy_dispatch.rs` / `streaming_waf_upstream_dispatch.rs`).
//!
//! Compatibility shim (documented per the Phase 63 plan): production wrapped
//! its streaming bodies in `StreamingWafBody`/erased adapters; here the
//! common multi-frame [`crate::common::FixtureBody`] is wrapped in
//! `ErasedBodyImpl::new`, which preserves the exact frame sequence (no
//! buffering, no re-chunking) while satisfying the legacy `BoxErasedBody`
//! client type. The frame geometry timed on this lane is therefore identical
//! to the eggfetch lane's.
//!
//! This file uses only API present at `7083f339` AND on the current tree
//! (the frozen compatibility surface), so the committed harness compiles
//! unmodified in both worktrees.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use synvoid_http_client::{
    create_upstream_client, create_upstream_streaming_client, send_request_streaming_generic,
    send_request_with_body_and_timeout, ErasedBodyImpl, HttpClient, StreamingHttpClient,
    UpstreamTlsConfig,
};

use crate::common::{drain_body, FixtureBody};

pub const LANE: &str = "legacy";
pub const ADAPTER_FILE: &str = "adapters/legacy_7083f339.rs";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn plaintext_tls() -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        allow_plaintext: true,
        ..UpstreamTlsConfig::default()
    }
}

pub fn ca_tls(ca_path: &str) -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        ca_cert_path: Some(ca_path.to_string()),
        ..UpstreamTlsConfig::default()
    }
}

pub fn small_client() -> HttpClient {
    create_upstream_client(
        CONNECT_TIMEOUT,
        100,
        Duration::from_secs(30),
        &plaintext_tls(),
    )
}

pub fn h2_client(ca_path: &str) -> HttpClient {
    create_upstream_client(
        CONNECT_TIMEOUT,
        100,
        Duration::from_secs(30),
        &ca_tls(ca_path),
    )
}

pub fn stream_client() -> StreamingHttpClient {
    create_upstream_streaming_client(
        CONNECT_TIMEOUT,
        100,
        Duration::from_secs(30),
        &plaintext_tls(),
    )
}

/// Buffered small GET; returns response body bytes on 200.
pub async fn small_get(client: &HttpClient, url: &str, timeout: Duration) -> Result<u64> {
    let resp =
        send_request_with_body_and_timeout(client, http::Method::GET, url, None, Some(timeout))
            .await?;
    if resp.status != http::StatusCode::OK {
        anyhow::bail!("unexpected status {}", resp.status);
    }
    Ok(resp.body.len() as u64)
}

/// True streaming POST with the common multi-frame body; drains the full
/// response body (same measurement boundary as the eggfetch lane).
pub async fn stream_post(
    client: &StreamingHttpClient,
    url: String,
    body: FixtureBody,
    timeout: Duration,
) -> Result<u64> {
    let erased = ErasedBodyImpl::new(body);
    let resp = send_request_streaming_generic(
        client.clone(),
        http::Method::POST,
        url,
        erased,
        http::HeaderMap::new(),
        Some(timeout),
    )
    .await
    .context("legacy streaming request")?;
    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("unexpected status {}", resp.status());
    }
    drain_body(resp.into_body()).await
}

/// Streaming request stopped at response headers; the caller drops the body
/// (early-drop workload). Returns time-to-headers; the response body is
/// returned unconsumed for the caller to drop.
pub async fn stream_headers(
    client: &StreamingHttpClient,
    url: String,
    body: FixtureBody,
    timeout: Duration,
) -> Result<hyper::Response<hyper::body::Incoming>> {
    let erased = ErasedBodyImpl::new(body);
    let resp = send_request_streaming_generic(
        client.clone(),
        http::Method::POST,
        url,
        erased,
        http::HeaderMap::new(),
        Some(timeout),
    )
    .await
    .context("legacy streaming request (headers)")?;
    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("unexpected status {}", resp.status());
    }
    Ok(resp)
}

/// Cold construction probe (informational, non-hot-path): unique SNI per
/// iteration forces a real build behind the policy-keyed client cache
/// instead of a cache hit. Performs no I/O.
pub fn cold_construct(iters: usize, salt: usize) -> Duration {
    let start = Instant::now();
    for i in 0..iters {
        let tls = UpstreamTlsConfig {
            server_name: Some(format!("cold-{salt}-{i}.bench.invalid")),
            ..UpstreamTlsConfig::default()
        };
        let _client =
            create_upstream_streaming_client(CONNECT_TIMEOUT, 100, Duration::from_secs(30), &tls);
    }
    start.elapsed()
}

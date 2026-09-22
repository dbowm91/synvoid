//! Eggfetch-lane adapter for the current (post-migration) tree.
//!
//! Uses the qualified production lane exactly as production does:
//!
//! - small requests: `EggfetchUpstreamClient::cached` + `send_buffered`
//!   (buffered GET, mirroring the legacy small-request contract);
//! - streaming: `EggfetchUpstreamClient::cached` + `execute` with the common
//!   multi-frame [`crate::common::FixtureBody`] (native generic-body path,
//!   no bytes-stream conversion, no forced buffering);
//! - H2: same buffered call against the TLS/ALPN loopback server.
//!
//! The response-drain boundary (full body consumed) matches the legacy
//! adapter. This file is compiled only with the harness `eggfetch` feature;
//! legacy-revision overlay builds pass `--no-default-features`.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use synvoid_http_client::eggfetch_transport::EggfetchUpstreamClient;
use synvoid_http_client::UpstreamTlsConfig;

use crate::common::{drain_body, FixtureBody};

pub const LANE: &str = "eggfetch";
pub const ADAPTER_FILE: &str = "adapters/eggfetch_current.rs";

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

pub fn small_client() -> Result<EggfetchUpstreamClient> {
    EggfetchUpstreamClient::cached(
        CONNECT_TIMEOUT,
        100,
        Duration::from_secs(30),
        &plaintext_tls(),
    )
    .context("eggfetch small client build")
}

pub fn h2_client(ca_path: &str) -> Result<EggfetchUpstreamClient> {
    EggfetchUpstreamClient::cached(
        CONNECT_TIMEOUT,
        100,
        Duration::from_secs(30),
        &ca_tls(ca_path),
    )
    .context("eggfetch h2 client build")
}

pub fn stream_client() -> Result<EggfetchUpstreamClient> {
    EggfetchUpstreamClient::cached(
        CONNECT_TIMEOUT,
        100,
        Duration::from_secs(30),
        &plaintext_tls(),
    )
    .context("eggfetch stream client build")
}

/// Buffered small GET; returns response body bytes on 200.
pub async fn small_get(
    client: &EggfetchUpstreamClient,
    url: &str,
    timeout: Duration,
) -> Result<u64> {
    let resp = client
        .send_buffered(
            http::Method::GET,
            url,
            None,
            http::HeaderMap::new(),
            Some(timeout),
            None,
        )
        .await?;
    if resp.status != http::StatusCode::OK {
        anyhow::bail!("unexpected status {}", resp.status);
    }
    Ok(resp.body.len() as u64)
}

/// True streaming POST with the common multi-frame body; drains the full
/// response body (same measurement boundary as the legacy lane).
pub async fn stream_post(
    client: &EggfetchUpstreamClient,
    url: &str,
    body: FixtureBody,
    timeout: Duration,
) -> Result<u64> {
    let uri: http::Uri = url.parse().context("stream url")?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .body(body)
        .context("stream request build")?;
    let resp = client
        .execute(req, Some(timeout), None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("unexpected status {}", resp.status());
    }
    drain_body(resp.into_body()).await
}

/// Streaming request stopped at response headers; the caller drops the body
/// (early-drop workload). The concrete response-body type stays inside this
/// adapter; the caller only needs it to be droppable, so it is boxed.
pub async fn stream_headers(
    client: &EggfetchUpstreamClient,
    url: &str,
    body: FixtureBody,
    timeout: Duration,
) -> Result<Box<dyn Send>> {
    let uri: http::Uri = url.parse().context("stream url")?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .body(body)
        .context("stream request build")?;
    let resp = client
        .execute(req, Some(timeout), None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("unexpected status {}", resp.status());
    }
    Ok(Box::new(resp.into_body()))
}

/// Cold construction probe (informational, non-hot-path): unique SNI per
/// iteration forces a real build behind the policy-keyed client cache
/// instead of a cache hit. Performs no I/O.
pub fn cold_construct(iters: usize, salt: usize) -> Result<Duration> {
    let start = Instant::now();
    for i in 0..iters {
        let tls = UpstreamTlsConfig {
            server_name: Some(format!("cold-{salt}-{i}.bench.invalid")),
            ..UpstreamTlsConfig::default()
        };
        let _client =
            EggfetchUpstreamClient::cached(CONNECT_TIMEOUT, 100, Duration::from_secs(30), &tls)?;
    }
    Ok(start.elapsed())
}

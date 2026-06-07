use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use http::{HeaderMap, Method};
use metrics::counter;

use synvoid_config::MainConfig;
use synvoid_http_client::HttpClient;
use synvoid_metrics::bandwidth::BandwidthTracker;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::RouteTarget;
use synvoid_waf::ConnectionLimiter;

use crate::http3_body::Http3RequestStream;
use crate::http3_buffered_upstream_dispatch::handle_http3_buffered_upstream_pass;
use crate::http3_streaming_upstream_dispatch::handle_http3_streaming_upstream_pass;
use crate::traffic_control::{maybe_enforce_http3_site_connection_limits, ConnectionTokenGuard};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[allow(clippy::too_many_arguments)]
pub async fn handle_http3_found_route<S, W>(
    start: Instant,
    route_target: &RouteTarget,
    stream_scanned_upstream_mode: bool,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    client_ip: IpAddr,
    request_stream: &mut W,
    max_request_size: usize,
    body_bytes: Vec<u8>,
    streaming_waf: Option<S>,
    connection_guard: Option<&ConnectionTokenGuard>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,
    main_config: &Arc<MainConfig>,
    client: &HttpClient,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
    bandwidth: Option<&Arc<BandwidthTracker>>,
    metrics: Option<&Arc<WorkerMetrics>>,
) -> Result<(), BoxError>
where
    S: synvoid_http_client::StreamingWafScanner + Send + Sync + Unpin + 'static,
    W: Http3RequestStream,
{
    if let Err(e) = maybe_enforce_http3_site_connection_limits(
        connection_guard,
        connection_limiter,
        route_target,
        client_ip,
    )
    .await
    {
        tracing::warn!(
            "HTTP/3 per-site connection limit exceeded for site {}: {}",
            route_target.site_id,
            e
        );
        counter!("synvoid.http3.connection_limited").increment(1);
        crate::http3_terminal::finalize_http3_request(request_stream, start).await?;
        return Ok(());
    }

    if stream_scanned_upstream_mode {
        counter!("synvoid.http3.request.streaming_path").increment(1);
        handle_http3_streaming_upstream_pass(
            start,
            route_target,
            path,
            method,
            headers,
            host,
            client_ip,
            request_stream,
            max_request_size,
            streaming_waf,
            main_config,
            upstream_client_registry,
            bandwidth,
            metrics,
        )
        .await?;
    } else {
        handle_http3_buffered_upstream_pass(
            start,
            route_target,
            path,
            method,
            headers,
            host,
            client_ip,
            request_stream,
            body_bytes,
            main_config,
            client,
            bandwidth,
            metrics,
        )
        .await?;
    }

    Ok(())
}

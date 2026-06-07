use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::{HeaderMap, Method};
use metrics::counter;

use synvoid_config::{site::SiteBotConfig, MainConfig};
use synvoid_http_client::HttpClient;
use synvoid_metrics::bandwidth::{BandwidthProtocol, BandwidthTracker};
use synvoid_metrics::{record_stall_end, record_stall_start, WorkerMetrics};
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::{RouteResult, RouteTarget};
use synvoid_waf::{ConnectionLimiter, WafDecision};

use crate::http3_body::{
    collect_http3_request_body, Http3BodyCollectionOutcome, Http3RequestStream,
};
use crate::http3_route_dispatch::handle_http3_found_route;
use crate::http3_terminal::maybe_handle_http3_terminal_route_result;
use crate::http3_waf_dispatch::{maybe_handle_http3_waf_decision, Http3WafDecisionOutcome};
use crate::traffic_control::ConnectionTokenGuard;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait]
pub trait Http3RequestWaf: Send + Sync {
    async fn check_request_full(
        &self,
        site_id: Option<&str>,
        ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        user_agent: Option<&str>,
        ja4_hash: Option<&str>,
        site_bot_config: Option<&SiteBotConfig>,
    ) -> WafDecision;

    fn generate_tarpit_response(&self, path: &str) -> String;
}

fn should_stream_http3_upstream(route_target: &RouteTarget, headers: &HeaderMap) -> bool {
    let needs_body_transform = route_target
        .site_config
        .r#static
        .enable_minification
        .unwrap_or(false)
        || route_target
            .site_config
            .image_poison
            .enabled
            .unwrap_or(false)
        || route_target
            .site_config
            .r#static
            .enable_compression
            .unwrap_or(false);

    let content_length_u64: Option<u64> = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    matches!(
        route_target.backend_type,
        synvoid_proxy::router::BackendType::Upstream
    ) && route_target.site_config.proxy.should_stream(
        content_length_u64,
        route_target.site_config.proxy.streaming_threshold_bytes,
    ) && !needs_body_transform
        && !synvoid_http_client::is_quictunnel_url(&route_target.upstream)
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_http3_request_dispatch<Waf, S, W>(
    start: Instant,
    route_result: &RouteResult,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    query_string: Option<&str>,
    user_agent: Option<&str>,
    client_ip: IpAddr,
    request_stream: &mut W,
    max_request_size: usize,
    streaming_waf_for_body: Option<S>,
    streaming_waf_for_upstream: Option<S>,
    connection_guard: Option<&ConnectionTokenGuard>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,
    main_config: &Arc<MainConfig>,
    client: &HttpClient,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
    bandwidth: Option<&Arc<BandwidthTracker>>,
    metrics: Option<&Arc<WorkerMetrics>>,
    waf: &Waf,
) -> Result<(), BoxError>
where
    Waf: Http3RequestWaf + ?Sized,
    S: crate::shared_handler::StreamingWafScanner
        + synvoid_http_client::StreamingWafScanner
        + Send
        + Sync
        + Unpin
        + 'static,
    W: Http3RequestStream,
{
    let stream_scanned_upstream_mode = match route_result {
        RouteResult::Found(route_target) => should_stream_http3_upstream(route_target, headers),
        _ => false,
    };

    let body_collection = collect_http3_request_body(
        stream_scanned_upstream_mode,
        max_request_size,
        client_ip,
        streaming_waf_for_body,
        request_stream,
    )
    .await?;

    let (body_bytes, request_body_size) = match body_collection {
        Http3BodyCollectionOutcome::Continue(collected) => {
            (collected.body_bytes, collected.request_body_size)
        }
        Http3BodyCollectionOutcome::Responded => {
            return Ok(());
        }
    };

    let body_slice: Option<&[u8]> = if body_bytes.is_empty() {
        None
    } else {
        Some(&body_bytes)
    };
    let waf_body_slice: Option<&[u8]> = if stream_scanned_upstream_mode {
        None
    } else {
        body_slice
    };

    if request_body_size > 0 {
        if let Some(ref bw) = bandwidth {
            bw.record_ingress(request_body_size, BandwidthProtocol::Http3);
            bw.record_site_ingress(host, request_body_size);
        }
    }

    tracing::trace!(
        client = %client_ip,
        method = %method,
        path = %path,
        body_size = body_bytes.len(),
        "HTTP/3 request body read"
    );

    let (waf_site_id, waf_bot_config) = match route_result {
        RouteResult::Found(route_target) => (
            Some(route_target.site_id.as_ref()),
            Some(&route_target.site_config.bot),
        ),
        _ => (Some(host), None),
    };

    let waf_decision = waf
        .check_request_full(
            waf_site_id,
            client_ip,
            method.as_str(),
            path,
            query_string,
            headers,
            waf_body_slice,
            user_agent,
            None,
            waf_bot_config,
        )
        .await;

    let waf_dispatch_outcome = maybe_handle_http3_waf_decision(
        waf_decision,
        host,
        request_stream,
        bandwidth,
        Duration::from_secs(10),
        || record_stall_start(),
        || record_stall_end(),
        |tar_path| waf.generate_tarpit_response(tar_path),
    )
    .await?;

    if let Http3WafDecisionOutcome::EarlyReturn = waf_dispatch_outcome {
        return Ok(());
    }

    if maybe_handle_http3_terminal_route_result(route_result, host, request_stream, start).await? {
        return Ok(());
    }

    if let RouteResult::Found(route_target) = route_result {
        if stream_scanned_upstream_mode {
            counter!("synvoid.http3.request.streaming_path").increment(1);
        }

        handle_http3_found_route(
            start,
            route_target,
            stream_scanned_upstream_mode,
            path,
            method,
            headers,
            host,
            client_ip,
            request_stream,
            max_request_size,
            body_bytes,
            streaming_waf_for_upstream,
            connection_guard,
            connection_limiter,
            main_config,
            client,
            upstream_client_registry,
            bandwidth,
            metrics,
        )
        .await?;
    } else {
        unreachable!("terminal HTTP/3 route results should already be handled");
    }

    Ok(())
}

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::{header, HeaderMap, Method, Response, StatusCode};
use http_body_util::BodyExt;
use http_body_util::Full;

use synvoid_config::site::ProxyHeadersConfig;
use synvoid_config::MainConfig;
use synvoid_http_client::HttpClient;
use synvoid_metrics::{
    bandwidth::{BandwidthProtocol, BandwidthTracker, EgressDirection},
    WorkerMetrics,
};
use synvoid_proxy::{
    build_forward_headers, filter_response_headers_buf, ForwardedProtocol, PreparedUpstreamTarget,
    RouteTarget,
};

use crate::http3_body::{send_response_with_body, Http3RequestStream};
use crate::http3_terminal::finalize_http3_request;
use crate::response_helpers::apply_security_headers;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn build_plain_error_response(status: StatusCode, content_type: &'static str) -> Response<()> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(())
        .unwrap_or_else(|_| {
            tracing::error!("Failed to build HTTP/3 error response body");
            Response::new(())
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_http3_buffered_upstream_pass<W>(
    start: Instant,
    route_target: &RouteTarget,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    client_ip: IpAddr,
    request_stream: &mut W,
    body_bytes: Vec<u8>,
    main_config: &Arc<MainConfig>,
    client: &HttpClient,
    bandwidth: Option<&Arc<BandwidthTracker>>,
    metrics: Option<&Arc<WorkerMetrics>>,
) -> Result<(), BoxError>
where
    W: Http3RequestStream,
{
    let upstream_target = PreparedUpstreamTarget::new(
        &route_target.upstream,
        path,
        Some(&route_target.site_config.proxy),
    );

    static DEFAULT_HEADERS_CONFIG: ProxyHeadersConfig = ProxyHeadersConfig {
        clear: Vec::new(),
        set: Vec::new(),
        forward: Vec::new(),
        hide: Vec::new(),
    };

    let forward_headers = build_forward_headers(
        client_ip,
        headers,
        route_target
            .site_config
            .proxy
            .headers
            .as_ref()
            .unwrap_or(&DEFAULT_HEADERS_CONFIG),
        ForwardedProtocol::Https,
    );

    let upstream_result = synvoid_http_client::send_request_streaming(
        client,
        method.clone(),
        &upstream_target.url,
        Full::new(Bytes::from(body_bytes)),
        forward_headers,
        Some(upstream_target.timeout),
    )
    .await
    .map_err(|e| Box::new(std::io::Error::other(e.to_string())) as BoxError);

    match upstream_result {
        Ok(upstream_resp) => {
            let (parts, mut upstream_body) = upstream_resp.into_parts();
            let body_len = parts
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            let size_exceeded = upstream_target
                .max_response_size
                .map(|max| body_len > 0 && body_len as usize > max)
                .unwrap_or(false);

            if size_exceeded {
                let response = build_plain_error_response(StatusCode::BAD_GATEWAY, "text/plain");
                send_response_with_body(request_stream, response, Bytes::from("Bad Gateway"))
                    .await
                    .map_err(|e| Box::new(e) as BoxError)?;
                if let Some(metrics) = metrics {
                    metrics.record_site_upstream_failure(&route_target.site_id);
                }
                finalize_http3_request(request_stream, start).await?;
                return Ok(());
            }

            let headers_to_filter = synvoid_proxy::build_headers_to_filter_for_site(
                &main_config.security.more_clear_headers,
                &route_target.site_config.security.more_clear_headers,
                &route_target.site_config.security_headers.more_clear_headers,
            );
            let filtered_headers = filter_response_headers_buf(&parts.headers, &headers_to_filter);
            let mut resp_builder = Response::builder().status(parts.status);

            for (name, value) in filtered_headers.iter() {
                if let Ok(v) = value.to_str() {
                    resp_builder = resp_builder.header(name.as_str(), v);
                }
            }

            resp_builder = apply_security_headers(
                resp_builder,
                &route_target.site_config.security_headers,
                main_config.security.global_security_headers,
            );

            let response = resp_builder.body(()).map_err(|e| Box::new(e) as BoxError)?;
            request_stream
                .send_response(response)
                .await
                .map_err(|e| Box::new(e) as BoxError)?;

            while let Some(chunk) = upstream_body.frame().await {
                match chunk {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            request_stream
                                .send_data(data.clone())
                                .await
                                .map_err(|e| Box::new(e) as BoxError)?;

                            let data_len = data.len() as u64;
                            if let Some(bw) = bandwidth {
                                bw.record_egress(
                                    data_len,
                                    BandwidthProtocol::Http3,
                                    EgressDirection::Proxied,
                                );
                                bw.record_site_egress(host, data_len);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading upstream body: {}", e);
                        break;
                    }
                }
            }

            if let Some(metrics) = metrics {
                metrics.record_site_upstream_success(&route_target.site_id);
            }
            finalize_http3_request(request_stream, start).await?;
        }
        Err(e) => {
            tracing::error!("Upstream error over HTTP/3: {}", e);
            if let Some(metrics) = metrics {
                metrics.record_site_upstream_failure(&route_target.site_id);
            }

            let body = Bytes::from("Bad Gateway");
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(body)
                .unwrap();

            let (parts, body) = response.into_parts();
            request_stream
                .send_response(Response::from_parts(parts, ()))
                .await
                .map_err(|e| Box::new(e) as BoxError)?;
            request_stream
                .send_data(body)
                .await
                .map_err(|e| Box::new(e) as BoxError)?;
            finalize_http3_request(request_stream, start).await?;
        }
    }

    Ok(())
}

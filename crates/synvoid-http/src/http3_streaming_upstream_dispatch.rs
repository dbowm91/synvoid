use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::{header, HeaderMap, Method, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Frame;
use metrics::{counter, histogram};
use tokio::sync::mpsc;

use synvoid_config::site::ProxyHeadersConfig;
use synvoid_config::MainConfig;
use synvoid_http_client::{
    send_request_streaming_generic, upstream_tls_from_site_config, ErasedBodyImpl,
    StreamingWafBody, StreamingWafScanner,
};
use synvoid_metrics::{
    bandwidth::{BandwidthProtocol, BandwidthTracker, EgressDirection},
    WorkerMetrics,
};
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::{
    build_forward_headers, build_headers_to_filter_for_site, filter_response_headers_buf,
    ForwardedProtocol, PreparedUpstreamTarget, RouteTarget,
};

use crate::headers::generate_stealth_timestamp;
use crate::http3_body::Http3RequestStream;
use crate::response_helpers::apply_security_headers;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
struct H3ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl H3ChannelBody {
    fn new(rx: mpsc::Receiver<Result<Bytes, std::io::Error>>) -> Self {
        Self { rx }
    }
}

impl hyper::body::Body for H3ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn build_json_error_response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::DATE, generate_stealth_timestamp(5))
        .body(())
        .unwrap_or_else(|_| {
            tracing::error!("Failed to build HTTP/3 error response body");
            Response::new(())
        })
}

async fn send_response_with_body<W: Http3RequestStream>(
    request_stream: &mut W,
    response: Response<()>,
    body: Bytes,
) -> Result<(), BoxError> {
    let (parts, _) = response.into_parts();
    request_stream
        .send_response(Response::from_parts(parts, ()))
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
    request_stream
        .send_data(body)
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
    Ok(())
}

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
pub async fn handle_http3_streaming_upstream_pass<W>(
    start: Instant,
    route_target: &RouteTarget,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    client_ip: IpAddr,
    request_stream: &mut W,
    max_request_size: usize,
    streaming_waf: Option<Box<dyn StreamingWafScanner>>,
    main_config: &Arc<MainConfig>,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
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
    let headers_to_filter = build_headers_to_filter_for_site(
        &main_config.security.more_clear_headers,
        &route_target.site_config.security.more_clear_headers,
        &route_target.site_config.security_headers.more_clear_headers,
    );
    static DEFAULT_HEADERS_CONFIG: ProxyHeadersConfig = ProxyHeadersConfig {
        clear: Vec::new(),
        set: Vec::new(),
        forward: Vec::new(),
        hide: Vec::new(),
    };
    let forward_header_map = build_forward_headers(
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
    let tls_config = route_target
        .site_config
        .proxy
        .upstream
        .as_ref()
        .and_then(|u| u.tls.as_ref())
        .and_then(upstream_tls_from_site_config);
    let streaming_client = upstream_client_registry
        .get_or_create_streaming(&route_target.site_id, tls_config.as_ref());

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    let streaming_body = H3ChannelBody::new(rx);
    let waf_body = StreamingWafBody::new(streaming_body, streaming_waf, client_ip);
    let erased_body = ErasedBodyImpl::new(waf_body);

    let upstream_url = upstream_target.url.clone();
    let upstream_timeout = Some(upstream_target.timeout);
    let max_response_size = upstream_target.max_response_size;

    let upstream_task = tokio::spawn({
        let streaming_client = streaming_client.clone();
        let method = method.clone();
        async move {
            send_request_streaming_generic(
                streaming_client.as_ref().clone(),
                method,
                upstream_url,
                erased_body,
                forward_header_map,
                upstream_timeout,
            )
            .await
        }
    });

    let mut streamed_body_len: usize = 0;
    while let Some(chunk_bytes) = request_stream.recv_data().await? {
        let chunk_len = chunk_bytes.len();
        if streamed_body_len + chunk_len > max_request_size {
            let response = build_json_error_response(StatusCode::PAYLOAD_TOO_LARGE);
            send_response_with_body(
                request_stream,
                response,
                Bytes::from_static(b"{\"error\":\"Request body too large\"}"),
            )
            .await?;
            request_stream.finish().await?;
            upstream_task.abort();
            return Ok(());
        }

        streamed_body_len += chunk_len;
        if tx.send(Ok(chunk_bytes)).await.is_err() {
            break;
        }
    }
    drop(tx);

    if streamed_body_len > 0 {
        if let Some(bw) = bandwidth {
            bw.record_ingress(streamed_body_len as u64, BandwidthProtocol::Http3);
            bw.record_site_ingress(host, streamed_body_len as u64);
        }
    }

    let upstream_result = match upstream_task.await {
        Ok(result) => result,
        Err(e) => Err(anyhow::anyhow!("upstream task join error: {}", e)),
    };

    match upstream_result {
        Ok(upstream_resp) => {
            let (parts, mut upstream_body) = upstream_resp.into_parts();
            let body_len = parts
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            if max_response_size
                .map(|max| body_len > 0 && body_len as usize > max)
                .unwrap_or(false)
            {
                let response = build_plain_error_response(StatusCode::BAD_GATEWAY, "text/plain");
                send_response_with_body(request_stream, response, Bytes::from("Bad Gateway"))
                    .await?;
                if let Some(metrics) = metrics {
                    metrics.record_site_upstream_failure(&route_target.site_id);
                }
            } else {
                let filtered_headers =
                    filter_response_headers_buf(&parts.headers, &headers_to_filter);
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
            }
        }
        Err(e) => {
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                    counter!("synvoid.http3.requests.blocked").increment(1);
                    let response = build_json_error_response(StatusCode::FORBIDDEN);
                    send_response_with_body(
                        request_stream,
                        response,
                        Bytes::from("{\"error\":\"Request blocked by WAF during streaming\"}"),
                    )
                    .await?;
                    request_stream.finish().await?;
                    return Ok(());
                }
            }
            tracing::error!("Upstream error over HTTP/3 streaming: {}", e);
            if let Some(metrics) = metrics {
                metrics.record_site_upstream_failure(&route_target.site_id);
            }
            let response = build_plain_error_response(StatusCode::BAD_GATEWAY, "text/plain");
            send_response_with_body(request_stream, response, Bytes::from("Bad Gateway")).await?;
        }
    }

    request_stream.finish().await?;
    histogram!("synvoid.http3.request.duration").record(start.elapsed());
    counter!("synvoid.http3.responses").increment(1);
    Ok(())
}

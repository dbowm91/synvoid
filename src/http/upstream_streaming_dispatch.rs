use ahash::AHashSet;
use anyhow::Result as AnyhowResult;
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::metrics::bandwidth::{BandwidthProtocol, EgressDirection};
use crate::metrics::WorkerMetrics;
use crate::proxy::{apply_response_size_limit, filter_response_headers_buf};
use crate::router::RouteTarget;

const ZERO_COPY_THRESHOLD: u64 = 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn handle_streaming_upstream_response(
    request_result: AnyhowResult<Response<Incoming>>,
    target: &RouteTarget,
    site_id: &str,
    request_body_size: u64,
    headers_to_filter: &AHashSet<http::header::HeaderName>,
    max_response_size: Option<usize>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    metrics: &Option<Arc<WorkerMetrics>>,
    on_upstream_success: impl Fn(),
    on_upstream_failure: impl Fn(),
    on_error_egress: impl Fn(u64),
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    match request_result {
        Ok(upstream_resp) => {
            on_upstream_success();

            let (resp_parts, upstream_body) = upstream_resp.into_parts();
            let body_len = resp_parts
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let is_chunked = resp_parts
                .headers
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("chunked"))
                .unwrap_or(false);

            if let Some(m) = metrics {
                m.bandwidth
                    .record_proxied(request_body_size, body_len, &target.upstream);
                m.bandwidth
                    .record_site_proxied(site_id, request_body_size, body_len);
                m.bandwidth.record_egress(
                    body_len,
                    BandwidthProtocol::Http,
                    EgressDirection::Proxied,
                );
                m.bandwidth.record_site_egress(site_id, body_len);
            }

            let status = resp_parts.status.as_u16();
            let filtered_headers =
                filter_response_headers_buf(&resp_parts.headers, headers_to_filter);
            let mut builder = Response::builder().status(status);
            for (key, value) in filtered_headers.iter() {
                if let Ok(v) = value.to_str() {
                    builder = builder.header(key.as_str(), v);
                }
            }
            if let Some(alt_svc) = alt_svc {
                builder = builder.header("Alt-Svc", alt_svc.as_str());
            }
            let builder =
                crate::http::response_helpers::apply_security_headers(builder, target, main_config);

            let should_zero_copy = body_len > ZERO_COPY_THRESHOLD || (body_len == 0 && is_chunked);
            if should_zero_copy {
                if body_len > 0
                    && max_response_size
                        .map(|max_size| body_len as usize > max_size)
                        .unwrap_or(false)
                {
                    return Ok(crate::http::response_builder::build_response_with_alt_svc(
                        502,
                        "Bad Gateway".to_string(),
                        "text/plain",
                        alt_svc,
                        main_config,
                    ));
                }

                return Ok(builder
                    .body(
                        upstream_body
                            .map_err(|e| {
                                tracing::warn!("Upstream body stream error: {}", e);
                                unreachable!()
                            })
                            .boxed(),
                    )
                    .unwrap_or_else(|_| {
                        crate::http::response_builder::build_response_with_alt_svc(
                            500,
                            crate::http::reason_phrase(500).to_string(),
                            "text/plain",
                            alt_svc,
                            main_config,
                        )
                    }));
            }

            match upstream_body.collect().await {
                Ok(collected) => {
                    let body_bytes = collected.to_bytes();
                    if apply_response_size_limit(&body_bytes, max_response_size).is_err() {
                        return Ok(crate::http::response_builder::build_response_with_alt_svc(
                            502,
                            "Bad Gateway".to_string(),
                            "text/plain",
                            alt_svc,
                            main_config,
                        ));
                    }

                    let body_len = body_bytes.len() as u64;
                    if let Some(m) = metrics {
                        m.bandwidth.record_egress(
                            body_len,
                            BandwidthProtocol::Http,
                            EgressDirection::Proxied,
                        );
                        m.bandwidth.record_site_egress(site_id, body_len);
                    }

                    Ok(builder
                        .body(http_body_util::Full::new(body_bytes).boxed())
                        .unwrap_or_else(|_| {
                            crate::http::response_builder::build_response_with_alt_svc(
                                500,
                                crate::http::reason_phrase(500).to_string(),
                                "text/plain",
                                alt_svc,
                                main_config,
                            )
                        }))
                }
                Err(e) => {
                    tracing::warn!("Failed to collect upstream body: {}", e);
                    Ok(builder
                        .body(http_body_util::Full::new(Bytes::new()).boxed())
                        .unwrap_or_else(|_| {
                            crate::http::response_builder::build_response_with_alt_svc(
                                500,
                                crate::http::reason_phrase(500).to_string(),
                                "text/plain",
                                alt_svc,
                                main_config,
                            )
                        }))
                }
            }
        }
        Err(e) => {
            on_upstream_failure();
            tracing::error!("Upstream streaming error: {}", e);
            let error_body = "Bad Gateway".to_string();
            on_error_egress(error_body.len() as u64);
            Ok(crate::http::response_builder::build_response_with_alt_svc(
                502,
                error_body,
                "text/plain",
                alt_svc,
                main_config,
            ))
        }
    }
}

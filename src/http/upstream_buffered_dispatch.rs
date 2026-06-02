use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use crate::config::MainConfig;
#[cfg(feature = "mesh")]
use crate::mesh::transport::MeshTransportManager;
use crate::metrics::bandwidth::{BandwidthProtocol, EgressDirection};
use crate::metrics::WorkerMetrics;
use crate::proxy::executor::PreparedUpstreamTarget;
use crate::proxy::{apply_response_size_limit, filter_response_headers_buf};
use crate::router::{RouteTarget, Router};

use super::upstream_response_transform::transform_upstream_response;

#[allow(clippy::too_many_arguments)]
pub async fn handle_buffered_upstream_request<PoisonFn, PoisonFut>(
    target: &RouteTarget,
    router: &Arc<Router>,
    path: &str,
    site_id: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    forwarding_client: &crate::http_client::HttpClient,
    upstream_target: &PreparedUpstreamTarget,
    headers_to_filter: &ahash::AHashSet<http::header::HeaderName>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    metrics: &Option<Arc<WorkerMetrics>>,
    request_body_size: u64,
    #[cfg(feature = "mesh")] mesh_transport: &Option<Arc<MeshTransportManager>>,
    on_upstream_success: impl Fn(),
    on_upstream_failure: impl Fn(),
    on_error_egress: impl Fn(u64),
    poison_image: PoisonFn,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>
where
    PoisonFn: Fn(
        Bytes,
        String,
        Option<String>,
        Option<crate::config::site::SiteImagePoisonConfig>,
    ) -> PoisonFut,
    PoisonFut: Future<Output = Bytes>,
{
    let resp = if crate::http_client::is_quictunnel_url(&target.upstream) {
        crate::http_client::send_request_via_quic_tunnel(
            method.clone(),
            &upstream_target.url,
            Some(&parts.headers),
            Some(full_body_arc.as_ref().clone()),
            Some(upstream_target.timeout),
        )
        .await
    } else {
        crate::http_client::send_request_with_body_and_timeout(
            forwarding_client,
            method.clone(),
            &upstream_target.url,
            Some(full_body_arc.as_ref().clone()),
            Some(upstream_target.timeout),
        )
        .await
    };

    match resp {
        Ok(resp) => {
            on_upstream_success();

            let status = resp.status_code();
            let content_type = resp
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let last_modified = resp
                .headers
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let headers: http::HeaderMap =
                filter_response_headers_buf(&resp.headers, headers_to_filter);
            let body = resp.body;
            if apply_response_size_limit(&body, upstream_target.max_response_size).is_err() {
                return Ok(crate::http::response_builder::build_response_with_alt_svc(
                    502,
                    "Bad Gateway".to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                ));
            }

            let accept_encoding = parts
                .headers
                .get("accept-encoding")
                .and_then(|v: &http::HeaderValue| v.to_str().ok());
            let transformed = transform_upstream_response(
                target,
                router,
                path,
                site_id,
                headers,
                body,
                status,
                content_type,
                last_modified,
                accept_encoding,
                #[cfg(feature = "mesh")]
                mesh_transport,
                poison_image,
            )
            .await;
            let body = transformed.body;
            let body_len = transformed.body_len;
            let headers = transformed.headers;

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

            let mut builder = Response::builder().status(status);
            for (key, value) in headers.iter() {
                if let (Ok(k), Ok(v)) = (
                    http::header::HeaderName::from_bytes(key.as_str().as_bytes()),
                    http::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    builder = builder.header(k, v);
                }
            }

            if let Some(alt_svc) = alt_svc {
                builder = builder.header("Alt-Svc", alt_svc.as_str());
            }

            builder =
                crate::http::response_helpers::apply_security_headers(builder, target, main_config);

            Ok(builder.body(Full::new(body).boxed()).unwrap_or_else(|_| {
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
            on_upstream_failure();
            tracing::error!("Upstream error: {}", e);
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

#[cfg(feature = "mesh")]
use bytes::Bytes;
#[cfg(feature = "mesh")]
use http::Response;
#[cfg(feature = "mesh")]
use http_body_util::combinators::BoxBody;
#[cfg(feature = "mesh")]
use http_body_util::BodyExt;
#[cfg(feature = "mesh")]
use std::convert::Infallible;
#[cfg(feature = "mesh")]
use std::sync::Arc;

#[cfg(feature = "mesh")]
use synvoid_config::MainConfig;
#[cfg(feature = "mesh")]
use synvoid_mesh::MeshProxy;
#[cfg(feature = "mesh")]
use synvoid_metrics::bandwidth::{BandwidthProtocol, EgressDirection};
#[cfg(feature = "mesh")]
use synvoid_metrics::WorkerMetrics;
#[cfg(feature = "mesh")]
use synvoid_proxy::{
    build_headers_to_filter, filter_response_headers_buf, BackendType, RouteTarget,
};

/// Dispatch a `BackendType::Mesh` request through the mesh data path.
///
/// The site's `upstream` string is the mesh service ID. It is sent to the
/// selected origin as the typed service-target preface; the origin resolves it
/// against its own `local_upstreams`. No backend pool is involved: the pool was
/// never populated in production and its HTTP role is retired.
#[cfg(feature = "mesh")]
#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_mesh_backend(
    mesh_proxy: Option<&Arc<MeshProxy>>,
    target: &RouteTarget,
    site_id: &str,
    path: &str,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    main_config: &Arc<MainConfig>,
    alt_svc: &Option<String>,
    metrics: &Option<Arc<WorkerMetrics>>,
    request_body_size: u64,
    on_upstream_success: impl Fn(),
    on_upstream_failure: impl Fn(),
) -> Option<Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>> {
    if !matches!(target.backend_type, BackendType::Mesh) {
        return None;
    }

    let Some(proxy) = mesh_proxy else {
        tracing::warn!(
            "Mesh backend configured for site {} but no mesh forwarder is available",
            site_id
        );
        return Some(Ok(crate::response_builder::build_response_with_alt_svc(
            502,
            "Backend misconfigured: mesh forwarder not available".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        )));
    };

    let service_id = target.upstream.as_ref();
    if service_id.is_empty() {
        tracing::warn!(
            "Mesh backend configured for site {} without a service ID",
            site_id
        );
        return Some(Ok(crate::response_builder::build_response_with_alt_svc(
            502,
            "Backend misconfigured: mesh service ID is empty".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        )));
    }

    let body_bytes_for_mesh: Bytes = full_body_arc.as_ref().clone();
    let body_len = body_bytes_for_mesh.len();
    let mut proxy_req = http::Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone());
    for (name, value) in parts.headers.iter() {
        // The client's chunked framing was decoded by the HTTP pipeline; the
        // mesh hop always sends this fixed-length buffered body.
        if name == http::header::TRANSFER_ENCODING {
            continue;
        }
        proxy_req = proxy_req.header(name.as_str(), value.to_str().unwrap_or(""));
    }
    proxy_req = proxy_req.header(http::header::CONTENT_LENGTH, body_len);
    let proxy_req = proxy_req
        .body(http_body_util::Full::new(body_bytes_for_mesh))
        .unwrap_or_else(|_| http::Request::new(http_body_util::Full::new(Bytes::new())));

    Some(match proxy.route_request(service_id, proxy_req).await {
        Ok(resp) => {
            on_upstream_success();
            let (resp_parts, body) = resp.into_parts();
            let status = resp_parts.status.as_u16();
            let body_len = resp_parts
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            if let Some(m) = metrics {
                m.bandwidth
                    .record_proxied(request_body_size, body_len, service_id);
                m.bandwidth
                    .record_site_proxied(site_id, request_body_size, body_len);
                m.bandwidth.record_egress(
                    body_len,
                    BandwidthProtocol::Http,
                    EgressDirection::Proxied,
                );
                m.bandwidth.record_site_egress(site_id, body_len);
            }

            let headers_to_filter = build_headers_to_filter(
                &main_config.security.more_clear_headers,
                &target
                    .site_config
                    .security
                    .more_clear_headers
                    .iter()
                    .chain(
                        target
                            .site_config
                            .security_headers
                            .more_clear_headers
                            .iter(),
                    )
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let filtered_headers =
                filter_response_headers_buf(&resp_parts.headers, &headers_to_filter);

            let mut builder = Response::builder().status(status);
            for (key, value) in filtered_headers.iter() {
                if let Ok(v) = value.to_str() {
                    builder = builder.header(key.as_str(), v);
                }
            }

            if let Some(alt_svc) = alt_svc {
                builder = builder.header("Alt-Svc", alt_svc.as_str());
            }

            builder = crate::response_helpers::apply_security_headers(
                builder,
                &target.site_config.security_headers,
                main_config.security.global_security_headers,
            );

            Ok(builder.body(body.boxed()).unwrap_or_else(|_| {
                crate::response_builder::build_response_with_alt_svc(
                    500,
                    crate::reason_phrase(500).to_string(),
                    "text/plain",
                    alt_svc,
                    main_config,
                )
            }))
        }
        Err(e) => {
            on_upstream_failure();
            tracing::warn!(
                service_id = %service_id,
                site = %site_id,
                path = %path,
                "Mesh proxy error: {}",
                e
            );
            Ok(crate::response_builder::build_response_with_alt_svc(
                502,
                format!("Mesh Proxy Error: {}", e),
                "text/plain",
                alt_svc,
                main_config,
            ))
        }
    })
}

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
use crate::config::MainConfig;
#[cfg(feature = "mesh")]
use crate::mesh::MeshBackendPool;
#[cfg(feature = "mesh")]
use crate::metrics::bandwidth::{BandwidthProtocol, EgressDirection};
#[cfg(feature = "mesh")]
use crate::metrics::WorkerMetrics;
#[cfg(feature = "mesh")]
use crate::proxy::{build_headers_to_filter, filter_response_headers_buf};
#[cfg(feature = "mesh")]
use crate::router::{BackendType, RouteTarget};

#[cfg(feature = "mesh")]
pub async fn maybe_handle_mesh_backend(
    mesh_backend_pool: &Option<Arc<MeshBackendPool>>,
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

    if let Some(pool) = mesh_backend_pool {
        let upstream_id = target.upstream.as_ref();
        if let Some(backend) = pool.select_backend(upstream_id).await {
            let body_bytes_for_mesh: Bytes = full_body_arc.as_ref().clone();
            let mut proxy_req = http::Request::builder()
                .method(parts.method.clone())
                .uri(parts.uri.clone());
            for (name, value) in parts.headers.iter() {
                proxy_req = proxy_req.header(name.as_str(), value.to_str().unwrap_or(""));
            }
            let proxy_req = proxy_req
                .body(http_body_util::Full::new(body_bytes_for_mesh))
                .unwrap_or_else(|_| http::Request::new(http_body_util::Full::new(Bytes::new())));

            return Some(match backend.proxy_request(proxy_req).await {
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
                            .record_proxied(request_body_size, body_len, upstream_id);
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

                    builder = crate::http::response_helpers::apply_security_headers(
                        builder,
                        target,
                        main_config,
                    );

                    Ok(builder
                        .body(
                            body.map_err(|e| {
                                tracing::warn!("Mesh proxy body error: {}", e);
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
                        }))
                }
                Err(e) => {
                    on_upstream_failure();
                    tracing::warn!("Mesh proxy error for site {} path {}: {}", site_id, path, e);
                    backend.record_failure();
                    Ok(crate::http::response_builder::build_response_with_alt_svc(
                        502,
                        format!("Mesh Proxy Error: {}", e),
                        "text/plain",
                        alt_svc,
                        main_config,
                    ))
                }
            });
        }

        tracing::warn!(
            "Mesh backend selected no available backend for upstream: {}",
            upstream_id
        );
        return Some(Ok(
            crate::http::response_builder::build_response_with_alt_svc(
                503,
                "Mesh backend temporarily unavailable".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            ),
        ));
    }

    tracing::warn!(
        "Mesh backend but no mesh_backend_pool configured for site {}",
        site_id
    );
    Some(Ok(
        crate::http::response_builder::build_response_with_alt_svc(
            502,
            "Backend misconfigured: mesh backend pool not available".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        ),
    ))
}

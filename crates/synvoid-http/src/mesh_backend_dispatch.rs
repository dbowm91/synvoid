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
use std::net::IpAddr;
#[cfg(feature = "mesh")]
use std::sync::Arc;

#[cfg(feature = "mesh")]
use synvoid_config::MainConfig;
#[cfg(feature = "mesh")]
use synvoid_mesh::service_target::{ClientMetadata, ClientProtocol};
#[cfg(feature = "mesh")]
use synvoid_mesh::MeshProxy;
#[cfg(feature = "mesh")]
use synvoid_metrics::bandwidth::{BandwidthProtocol, EgressDirection};
#[cfg(feature = "mesh")]
use synvoid_metrics::WorkerMetrics;
#[cfg(feature = "mesh")]
use synvoid_proxy::headers::is_hop_by_hop_header_name;
#[cfg(feature = "mesh")]
use synvoid_proxy::{
    build_headers_to_filter, filter_response_headers_buf, BackendType, ForwardedProtocol,
    RouteTarget,
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
    client_ip: IpAddr,
    forwarded_protocol: ForwardedProtocol,
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
    let proxy_req = build_mesh_proxy_request(parts, body_bytes_for_mesh);

    // The client address is authored here, from the socket peer the HTTP
    // pipeline already carries. It never comes from a client header.
    let meta = ClientMetadata {
        client_ip,
        proto: match forwarded_protocol {
            ForwardedProtocol::Http => ClientProtocol::Http,
            ForwardedProtocol::Https => ClientProtocol::Https,
        },
    };

    Some(
        match proxy
            .route_request_with_meta(service_id, proxy_req, Some(&meta))
            .await
        {
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
        },
    )
}

/// Build the mesh request from the buffered client request.
///
/// The HTTP pipeline already decoded the client's chunked framing, so the mesh
/// hop always carries this buffered body with exactly one authoritative
/// `Content-Length`. The client's own `Content-Length` and
/// `Transfer-Encoding` are skipped, as are hop-by-hop and client-supplied
/// forwarding headers: the origin rebuilds those from the authenticated
/// preface metadata.
#[cfg(feature = "mesh")]
fn build_mesh_proxy_request(
    parts: &http::request::Parts,
    body: Bytes,
) -> http::Request<http_body_util::Full<Bytes>> {
    let body_len = body.len();
    let mut builder = http::Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone());
    for (name, value) in parts.headers.iter() {
        if name == http::header::CONTENT_LENGTH
            || name == http::header::TRANSFER_ENCODING
            || is_hop_by_hop_header_name(name)
            || is_client_forwarding_header(name)
        {
            continue;
        }
        builder = builder.header(name.as_str(), value.to_str().unwrap_or(""));
    }
    builder = builder.header(http::header::CONTENT_LENGTH, body_len);
    builder
        .body(http_body_util::Full::new(body))
        .unwrap_or_else(|_| http::Request::new(http_body_util::Full::new(Bytes::new())))
}

/// A forwarding header is a client claim; only the preface metadata is
/// authoritative.
#[cfg(feature = "mesh")]
fn is_client_forwarding_header(name: &http::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "x-forwarded-for" | "x-real-ip" | "forwarded" | "x-forwarded-proto" | "x-forwarded-host"
    )
}

#[cfg(all(test, feature = "mesh"))]
mod tests {
    use super::*;

    fn request_parts(headers: &[(&'static str, &'static str)]) -> http::request::Parts {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri("http://blog.example/api");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(())
            .expect("valid fixture request")
            .into_parts()
            .0
    }

    #[test]
    fn client_content_length_is_replaced_not_duplicated() {
        let parts = request_parts(&[
            ("host", "blog.example"),
            ("content-length", "3"),
            ("content-type", "text/plain"),
        ]);

        let request = build_mesh_proxy_request(&parts, Bytes::from_static(b"abc"));

        let lengths: Vec<_> = request.headers().get_all("content-length").iter().collect();
        assert_eq!(
            lengths.len(),
            1,
            "the mesh request must carry exactly one Content-Length"
        );
        assert_eq!(lengths[0], "3");
        assert!(
            request.headers().get("content-type").is_some(),
            "end-to-end headers must survive"
        );
        assert!(
            request.headers().get("transfer-encoding").is_none(),
            "client chunked framing must not leak onto the mesh hop"
        );
    }

    #[test]
    fn hop_by_hop_and_forwarding_headers_are_not_copied() {
        let parts = request_parts(&[
            ("host", "blog.example"),
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-real-ip", "203.0.113.9"),
            ("forwarded", "for=203.0.113.9"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
        ]);

        let request = build_mesh_proxy_request(&parts, Bytes::new());

        for name in [
            "connection",
            "keep-alive",
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "x-forwarded-proto",
            "x-forwarded-host",
        ] {
            assert!(
                request.headers().get(name).is_none(),
                "{name} must not be copied onto the mesh hop"
            );
        }
        assert_eq!(
            request.headers().get("host").and_then(|v| v.to_str().ok()),
            Some("blog.example"),
            "Host is preserved"
        );
    }
}

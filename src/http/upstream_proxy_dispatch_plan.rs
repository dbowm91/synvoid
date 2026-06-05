use std::sync::Arc;

use ahash::AHashSet;
use http::HeaderMap;

use crate::config::site::ProxyHeadersConfig;
use crate::config::MainConfig;
use crate::http_client::{HttpClient, StreamingHttpClient};
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::{
    build_forward_headers, build_headers_to_filter, ForwardedProtocol, PreparedUpstreamTarget,
};
use crate::router::RouteTarget;

pub struct UpstreamProxyDispatchPlan {
    pub upstream_target: PreparedUpstreamTarget,
    pub headers_to_filter: AHashSet<http::header::HeaderName>,
    pub forwarding_client: Arc<HttpClient>,
    pub streaming: Option<StreamingUpstreamDispatchPlan>,
}

pub struct StreamingUpstreamDispatchPlan {
    pub forward_headers: HeaderMap,
    pub client: Arc<StreamingHttpClient>,
}

pub fn prepare_upstream_proxy_dispatch_plan(
    target: &RouteTarget,
    path: &str,
    main_config: &Arc<MainConfig>,
    full_body_len: u64,
    client_ip: std::net::IpAddr,
    parts: &http::request::Parts,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
    client: &HttpClient,
) -> UpstreamProxyDispatchPlan {
    let upstream_target =
        PreparedUpstreamTarget::new(&target.upstream, path, Some(&target.site_config.proxy));

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

    let site_tls_config = target
        .site_config
        .proxy
        .upstream
        .as_ref()
        .and_then(|u| u.tls.as_ref())
        .and_then(crate::http_client::upstream_tls_from_site_config);

    let forwarding_client = if site_tls_config.is_some() {
        upstream_client_registry.get_or_create(&target.site_id, site_tls_config.as_ref())
    } else {
        Arc::new(client.clone())
    };

    let streaming_threshold = target.site_config.proxy.streaming_threshold_bytes;
    let use_streaming = target
        .site_config
        .proxy
        .body_buffering_policy
        .map(|policy| policy.should_stream(full_body_len, streaming_threshold))
        .unwrap_or(false);

    let streaming = if use_streaming {
        Some(StreamingUpstreamDispatchPlan {
            forward_headers: build_forward_headers(
                client_ip,
                &parts.headers,
                target
                    .site_config
                    .proxy
                    .headers
                    .as_ref()
                    .unwrap_or(&ProxyHeadersConfig::default()),
                ForwardedProtocol::Http,
            ),
            client: upstream_client_registry
                .get_or_create_streaming(&target.site_id, site_tls_config.as_ref()),
        })
    } else {
        None
    };

    UpstreamProxyDispatchPlan {
        upstream_target,
        headers_to_filter,
        forwarding_client,
        streaming,
    }
}

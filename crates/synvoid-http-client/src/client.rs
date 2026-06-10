//! Public client type aliases and high-level construction entry points.

use std::time::Duration;

use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyperlocal::UnixConnector;

use crate::erased_pool::BoxErasedBody;
use crate::pool::{
    build_https_client, build_upstream_client, UPSTREAM_CLIENT_CACHE,
    UPSTREAM_STREAMING_CLIENT_CACHE,
};
use crate::tls::UpstreamTlsConfig;

pub type HttpClient = Client<HttpsConnector<HttpConnector>, http_body_util::Full<bytes::Bytes>>;
pub type StreamingHttpClient = Client<HttpsConnector<HttpConnector>, BoxErasedBody>;
pub type UnixHttpClient = Client<UnixConnector, http_body_util::Full<bytes::Bytes>>;

// Re-export create_unix from unix module (unix owns the impl; this keeps client.rs as the
// documented owner of the public creation entrypoint per split plan, while avoiding fn duplication).
pub use crate::unix::create_unix_http_client;

/// Empty body type for HEAD/empty requests (re-exported for API compat).
#[derive(Clone, Default)]
pub struct EmptyBody;

impl hyper::body::Body for EmptyBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(None)
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(0)
    }
}

pub fn create_http_client() -> HttpClient {
    create_http_client_with_config(Duration::from_secs(5), 1000, Duration::from_secs(30))
}

pub fn create_http_client_with_config(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
) -> HttpClient {
    build_https_client(
        connect_timeout,
        pool_max_idle_per_host,
        pool_idle_timeout,
        None,
    )
}

pub fn create_upstream_client(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    tls_config: &UpstreamTlsConfig,
) -> HttpClient {
    use crate::pool::UpstreamClientKey;
    use crate::tls::UpstreamTlsConfigHashable;

    let key = UpstreamClientKey {
        tls_config: UpstreamTlsConfigHashable::from(tls_config),
        pool_max_idle: pool_max_idle_per_host,
        pool_idle_secs: pool_idle_timeout.as_secs(),
    };

    if let Some(client) = UPSTREAM_CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let client = build_upstream_client::<http_body_util::Full<bytes::Bytes>>(
        connect_timeout,
        pool_max_idle_per_host,
        pool_idle_timeout,
        tls_config,
    );

    UPSTREAM_CLIENT_CACHE.insert(key, client.clone());
    client
}

pub fn create_upstream_streaming_client(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    tls_config: &UpstreamTlsConfig,
) -> StreamingHttpClient {
    use crate::pool::UpstreamClientKey;
    use crate::tls::UpstreamTlsConfigHashable;

    let key = UpstreamClientKey {
        tls_config: UpstreamTlsConfigHashable::from(tls_config),
        pool_max_idle: pool_max_idle_per_host,
        pool_idle_secs: pool_idle_timeout.as_secs(),
    };

    if let Some(client) = UPSTREAM_STREAMING_CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let client = build_upstream_client::<BoxErasedBody>(
        connect_timeout,
        pool_max_idle_per_host,
        pool_idle_timeout,
        tls_config,
    );

    UPSTREAM_STREAMING_CLIENT_CACHE.insert(key, client.clone());
    client
}

pub fn create_simple_http_client(timeout: Duration) -> HttpClient {
    create_http_client_with_config(Duration::from_secs(5), 100, timeout)
}

/// Compatibility re-export of is_quictunnel_url (logic duplicated in root quic for phase4).
pub fn is_quictunnel_url(url: &str) -> bool {
    url.starts_with("quictunnel://") || url.starts_with("quictunnel:")
}

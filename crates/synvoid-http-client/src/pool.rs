//! Connection pooling, client keying, and upstream client construction/caching.
//!
//! Owns UpstreamClientKey, the moka caches (with 100/300s TTL), and the build_* helpers.
//! create_upstream_* live in client.rs but use these.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use moka::sync::Cache;

use crate::erased_pool::BoxErasedBody;
use crate::tls::{build_tls_config, UpstreamTlsConfig, UpstreamTlsConfigHashable};

#[derive(Hash, PartialEq, Eq)]
pub(crate) struct UpstreamClientKey {
    pub(crate) tls_config: UpstreamTlsConfigHashable,
    pub(crate) pool_max_idle: usize,
    pub(crate) pool_idle_secs: u64,
}

const MAX_UPSTREAM_CLIENT_CACHE_SIZE: u64 = 100;
const UPSTREAM_CLIENT_CACHE_TTL_SECS: u64 = 300;

fn upstream_client_cache() -> Cache<UpstreamClientKey, HttpClient> {
    Cache::builder()
        .max_capacity(MAX_UPSTREAM_CLIENT_CACHE_SIZE)
        .time_to_live(Duration::from_secs(UPSTREAM_CLIENT_CACHE_TTL_SECS))
        .build()
}

pub(crate) static UPSTREAM_CLIENT_CACHE: std::sync::LazyLock<Cache<UpstreamClientKey, HttpClient>> =
    std::sync::LazyLock::new(upstream_client_cache);

fn upstream_streaming_client_cache() -> Cache<UpstreamClientKey, StreamingHttpClient> {
    Cache::builder()
        .max_capacity(MAX_UPSTREAM_CLIENT_CACHE_SIZE)
        .time_to_live(Duration::from_secs(UPSTREAM_CLIENT_CACHE_TTL_SECS))
        .build()
}

pub(crate) static UPSTREAM_STREAMING_CLIENT_CACHE: std::sync::LazyLock<
    Cache<UpstreamClientKey, StreamingHttpClient>,
> = std::sync::LazyLock::new(upstream_streaming_client_cache);

pub(crate) fn build_https_client<B>(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    tls_config: Option<rustls::ClientConfig>,
) -> Client<HttpsConnector<HttpConnector>, B>
where
    B: http_body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: std::fmt::Debug + Send + Sync + std::error::Error,
{
    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(connect_timeout));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(60)));

    let tls_config = tls_config.unwrap_or_else(|| build_tls_config(None, false, None));

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http2()
        .wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .pool_idle_timeout(pool_idle_timeout)
        .http2_only(false)
        .build(https_connector)
}

pub(crate) fn build_upstream_client<B>(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    tls_config: &UpstreamTlsConfig,
) -> Client<HttpsConnector<HttpConnector>, B>
where
    B: http_body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: std::fmt::Debug + Send + Sync + std::error::Error,
{
    let rustls_config = build_tls_config(
        tls_config.ca_cert_path.as_deref(),
        tls_config.skip_verify,
        tls_config.skip_verify_reason.as_deref(),
    );

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(connect_timeout));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(60)));

    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(rustls_config);

    let builder = if tls_config.allow_plaintext {
        static WARNED_PLAINTEXT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        WARNED_PLAINTEXT.get_or_init(|| {
            tracing::warn!(
                "HTTP upstream allow_plaintext is enabled - HTTP connections will be allowed. \
                 This is insecure for production deployments."
            );
        });
        builder.https_or_http()
    } else {
        builder.https_only()
    };

    let https_connector = builder.enable_http2().wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .pool_idle_timeout(pool_idle_timeout)
        .http2_only(false)
        .build(https_connector)
}

// Type aliases for the cache value types (to avoid repeating in static decls above)
type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
type StreamingHttpClient = Client<HttpsConnector<HttpConnector>, BoxErasedBody>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_client_key_equal_for_identical_settings() {
        let tls = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            allow_plaintext: false,
        };
        let key1 = UpstreamClientKey {
            tls_config: tls.clone(),
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        let key2 = UpstreamClientKey {
            tls_config: tls,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        assert!(key1 == key2);
    }

    #[test]
    fn upstream_client_key_different_for_different_ca_path() {
        let tls1 = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            allow_plaintext: false,
        };
        let tls2 = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: Some("/ca.pem".to_string()),
            server_name: None,
            skip_verify: false,
            allow_plaintext: false,
        };
        let key1 = UpstreamClientKey {
            tls_config: tls1,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        let key2 = UpstreamClientKey {
            tls_config: tls2,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        assert!(key1 != key2);
    }

    #[test]
    fn upstream_client_key_different_for_skip_verify() {
        let tls1 = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            allow_plaintext: false,
        };
        let tls2 = UpstreamTlsConfigHashable {
            verify: false,
            ca_cert_path: None,
            server_name: None,
            skip_verify: true,
            allow_plaintext: false,
        };
        let key1 = UpstreamClientKey {
            tls_config: tls1,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        let key2 = UpstreamClientKey {
            tls_config: tls2,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        assert!(key1 != key2);
    }

    #[test]
    fn upstream_client_key_different_for_allow_plaintext() {
        let tls1 = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            allow_plaintext: false,
        };
        let tls2 = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            allow_plaintext: true,
        };
        let key1 = UpstreamClientKey {
            tls_config: tls1,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        let key2 = UpstreamClientKey {
            tls_config: tls2,
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        assert!(key1 != key2);
    }

    #[test]
    fn upstream_client_key_different_for_pool_idle_settings() {
        let tls = UpstreamTlsConfigHashable {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            allow_plaintext: false,
        };
        let key1 = UpstreamClientKey {
            tls_config: tls.clone(),
            pool_max_idle: 10,
            pool_idle_secs: 30,
        };
        let key2 = UpstreamClientKey {
            tls_config: tls,
            pool_max_idle: 10,
            pool_idle_secs: 60,
        };
        assert!(key1 != key2);
    }
}

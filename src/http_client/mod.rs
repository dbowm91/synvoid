//! HTTP client abstraction for upstream proxy connections.
//!
//! Provides TLS-configurable HTTP/1.1 and HTTP/2 clients using hyper,
//! with support for connection pooling, timeouts, and per-site TLS settings.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{header, Method, Request, Response, Uri};
use http_body_util::BodyExt;
use http_body_util::Full;
use http_body_util::Limited;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use hyperlocal::{UnixConnector, Uri as HyperlocalUri};
use moka::sync::Cache;
use serde::{de::DeserializeOwned, Serialize};

mod erased_pool;
mod typed_pool;

pub use erased_pool::{
    ErasedBody, ErasedBodyImpl, ErasedConnectionPool, ErasedHttpClient, PoolKey,
};
pub use typed_pool::{TypedConnectionPool, TypedHttpClient, TypedPoolKey};

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
pub type StreamingHttpClient = Client<HttpsConnector<HttpConnector>, BoxErasedBody>;
pub type UnixHttpClient = Client<UnixConnector, Full<Bytes>>;
pub use erased_pool::BoxErasedBody;

#[derive(Hash, PartialEq, Eq)]
struct UpstreamClientKey {
    tls_config: UpstreamTlsConfigHashable,
    pool_max_idle: usize,
    pool_idle_secs: u64,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct UpstreamTlsConfigHashable {
    verify: bool,
    ca_cert_path: Option<String>,
    server_name: Option<String>,
    skip_verify: bool,
    allow_plaintext: bool,
}

impl From<&UpstreamTlsConfig> for UpstreamTlsConfigHashable {
    fn from(cfg: &UpstreamTlsConfig) -> Self {
        Self {
            verify: cfg.verify,
            ca_cert_path: cfg.ca_cert_path.clone(),
            server_name: cfg.server_name.clone(),
            skip_verify: cfg.skip_verify,
            allow_plaintext: cfg.allow_plaintext,
        }
    }
}

const MAX_UPSTREAM_CLIENT_CACHE_SIZE: u64 = 100;
const UPSTREAM_CLIENT_CACHE_TTL_SECS: u64 = 300;

fn upstream_client_cache() -> Cache<UpstreamClientKey, HttpClient> {
    Cache::builder()
        .max_capacity(MAX_UPSTREAM_CLIENT_CACHE_SIZE)
        .time_to_live(Duration::from_secs(UPSTREAM_CLIENT_CACHE_TTL_SECS))
        .build()
}

static UPSTREAM_CLIENT_CACHE: LazyLock<Cache<UpstreamClientKey, HttpClient>> =
    LazyLock::new(upstream_client_cache);

fn upstream_streaming_client_cache() -> Cache<UpstreamClientKey, StreamingHttpClient> {
    Cache::builder()
        .max_capacity(MAX_UPSTREAM_CLIENT_CACHE_SIZE)
        .time_to_live(Duration::from_secs(UPSTREAM_CLIENT_CACHE_TTL_SECS))
        .build()
}

static UPSTREAM_STREAMING_CLIENT_CACHE: LazyLock<Cache<UpstreamClientKey, StreamingHttpClient>> =
    LazyLock::new(upstream_streaming_client_cache);

pub fn is_unix_socket_url(url: &str) -> Option<PathBuf> {
    let trimmed = url.trim();

    if trimmed.starts_with("http+unix://") || trimmed.starts_with("http+unix:") {
        let path = trimmed
            .trim_start_matches("http+unix://")
            .trim_start_matches("http+unix:");
        return Some(PathBuf::from(path));
    }

    if trimmed.starts_with("unix://") || trimmed.starts_with("unix:") {
        let path = trimmed
            .trim_start_matches("unix://")
            .trim_start_matches("unix:");
        return Some(PathBuf::from(path));
    }

    if trimmed.starts_with('/') || trimmed.starts_with("./") {
        return Some(PathBuf::from(trimmed));
    }

    None
}

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

/// A streaming body wrapper that performs WAF scanning on chunks as they pass through.
/// This enables true streaming: body is scanned and forwarded without full buffering.
pub struct StreamingWafBody<B> {
    inner: B,
    streaming_waf: Option<crate::waf::attack_detection::StreamingWafCore>,
    client_ip: IpAddr,
    blocked: bool,
    error_sent: bool,
}

impl<B> StreamingWafBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    pub fn new(
        inner: B,
        streaming_waf: Option<crate::waf::attack_detection::StreamingWafCore>,
        client_ip: IpAddr,
    ) -> Self {
        Self {
            inner,
            streaming_waf,
            client_ip,
            blocked: false,
            error_sent: false,
        }
    }
}

impl<B> hyper::body::Body for StreamingWafBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug + Send,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if self.blocked {
            if !self.error_sent {
                self.error_sent = true;
                let msg = "Request blocked by WAF during streaming body scan";
                return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    msg,
                ))));
            }
            return std::task::Poll::Ready(None);
        }

        let this = &mut *self;
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(ref mut sw) = this.streaming_waf {
                        match sw.scan_chunk(&data) {
                            crate::waf::attack_detection::StreamingWafDecision::Block(_, _) => {
                                tracing::warn!(
                                    client_ip = %this.client_ip,
                                    "Request blocked by streaming WAF mid-body"
                                );
                                metrics::counter!("synvoid.http.streaming_body_blocked")
                                    .increment(1);
                                this.blocked = true;
                                return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "Request blocked by WAF",
                                ))));
                            }
                            crate::waf::attack_detection::StreamingWafDecision::Continue => {}
                        }
                    }
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(
                std::io::Error::new(std::io::ErrorKind::Other, format!("body error: {:?}", e)),
            ))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct UpstreamTlsConfig {
    pub verify: bool,
    pub ca_cert_path: Option<String>,
    pub server_name: Option<String>,
    pub skip_verify: bool,
    pub skip_verify_reason: Option<String>,
    pub allow_plaintext: bool,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            skip_verify_reason: None,
            allow_plaintext: false,
        }
    }
}

impl UpstreamTlsConfig {
    pub fn from_site_config(config: &crate::config::site::UpstreamTlsConfig) -> Option<Self> {
        let enabled = config.enabled.unwrap_or(true);
        if !enabled {
            return None;
        }
        let skip_verify = config.skip_verify.unwrap_or(false);
        if skip_verify {
            let reason = config
                .skip_verify_reason
                .as_deref()
                .unwrap_or("none provided");
            tracing::warn!(
                reason,
                "Upstream TLS: skip_verify is ENABLED \u{2014} hostname verification is BYPASSED but chain validation still occurs. Configure skip_verify_reason to document why this is needed."
            );
        }
        Some(Self {
            verify: !skip_verify,
            ca_cert_path: config.ca_cert.clone(),
            server_name: None,
            skip_verify,
            skip_verify_reason: config.skip_verify_reason.clone(),
            allow_plaintext: false,
        })
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
    let key = UpstreamClientKey {
        tls_config: UpstreamTlsConfigHashable::from(tls_config),
        pool_max_idle: pool_max_idle_per_host,
        pool_idle_secs: pool_idle_timeout.as_secs(),
    };

    if let Some(client) = UPSTREAM_CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let client = build_upstream_client::<Full<Bytes>>(
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

fn build_https_client<B>(
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

fn build_upstream_client<B>(
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

fn load_ca_certs_from_path(path: &str) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;
    let pem_data = std::fs::read(path)
        .with_context(|| format!("Failed to read CA certificate file: {}", path))?;
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(&pem_data)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path);
    }
    Ok(certs)
}

fn build_tls_config(
    ca_cert_path: Option<&str>,
    skip_verify: bool,
    skip_verify_reason: Option<&str>,
) -> rustls::ClientConfig {
    use rustls::crypto::aws_lc_rs;
    use std::sync::Arc;

    let provider = Arc::new(aws_lc_rs::default_provider());

    // Log crypto provider capabilities at first build
    static PROVIDER_LOGGED: std::sync::Once = std::sync::Once::new();
    PROVIDER_LOGGED.call_once(|| {
        tracing::info!(
            "HTTP client TLS initialized with aws-lc-rs provider (TLS 1.3, \
             PQ support: {})",
            if cfg!(feature = "post-quantum") {
                "enabled"
            } else {
                "not available"
            }
        );
    });

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("failed to set TLS protocol versions");

    if skip_verify {
        let reason = skip_verify_reason.unwrap_or("not specified");
        tracing::warn!(
            reason,
            "TLS hostname verification BYPASSED for upstream — chain validation still occurs. Connection is secure against eavesdropping but NOT against impersonation."
        );

        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            let _ = root_store.add(cert);
        }
        if root_store.is_empty() {
            tracing::warn!("No native root certificates available, falling back to webpki roots");
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        if !native_certs.errors.is_empty() {
            tracing::warn!(
                "Some native root certificates failed to load: {} errors",
                native_certs.errors.len()
            );
        }

        if let Some(ca_path) = ca_cert_path {
            match load_ca_certs_from_path(ca_path) {
                Ok(certs) => {
                    let added = certs.len();
                    for cert in certs {
                        let _ = root_store.add(cert);
                    }
                    tracing::info!("Loaded {} custom CA certificate(s) from {}", added, ca_path);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load custom CA certificates from {}: {}",
                        ca_path,
                        e
                    );
                }
            }
        }

        let inner = WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .expect("failed to build WebPkiServerVerifier");
        let verifier_reason = skip_verify_reason.unwrap_or("not specified");
        let verifier = HostnameSkippingVerifier::new(inner, verifier_reason.to_string());

        let mut config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        return config;
    }

    // Try native roots, fall back to webpki
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }
    if root_store.is_empty() {
        tracing::warn!("No native root certificates available, falling back to webpki roots");
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if !native_certs.errors.is_empty() {
        tracing::warn!(
            "Some native root certificates failed to load: {} errors",
            native_certs.errors.len()
        );
    }

    // Load custom CA certificates from file
    if let Some(ca_path) = ca_cert_path {
        match load_ca_certs_from_path(ca_path) {
            Ok(certs) => {
                let added = certs.len();
                for cert in certs {
                    let _ = root_store.add(cert);
                }
                tracing::info!("Loaded {} custom CA certificate(s) from {}", added, ca_path);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load custom CA certificates from {}: {}",
                    ca_path,
                    e
                );
            }
        }
    }

    let mut config = builder
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;

#[derive(Debug)]
struct HostnameSkippingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    skip_reason: String,
}

impl HostnameSkippingVerifier {
    fn new(inner: Arc<WebPkiServerVerifier>, reason: String) -> Self {
        Self {
            inner,
            skip_reason: reason,
        }
    }
}

impl ServerCertVerifier for HostnameSkippingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(scv) => Ok(scv),
            Err(rustls::Error::InvalidCertificate(cert_error)) => {
                if let rustls::CertificateError::NotValidForName = cert_error {
                    tracing::warn!(
                        reason = %self.skip_reason,
                        "Skipping hostname verification for upstream connection"
                    );
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(cert_error))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn create_unix_http_client() -> UnixHttpClient {
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(30))
        .http2_only(false)
        .build(UnixConnector)
}

pub async fn send_unix_request_with_timeout(
    client: &UnixHttpClient,
    socket_path: &str,
    path: &str,
    method: Method,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    send_unix_request_with_body(client, socket_path, path, method, None, timeout).await
}

pub async fn send_unix_request_with_body(
    client: &UnixHttpClient,
    socket_path: &str,
    path: &str,
    method: Method,
    body: Option<bytes::Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    let uri = HyperlocalUri::new(socket_path, path);

    let full_body = if let Some(b) = body {
        let _len = b.len();
        http_body_util::Full::new(b)
    } else {
        http_body_util::Full::new(Bytes::new())
    };

    let req = Request::builder()
        .method(method.clone())
        .uri(uri)
        .body(full_body)?;

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.request(req).await?
    };

    Ok(HttpResponse::from_hyper(response, None).await)
}

pub async fn send_request(client: &HttpClient, method: Method, url: &str) -> Result<HttpResponse> {
    send_request_with_timeout(client, method, url, None).await
}

pub async fn send_request_with_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    send_request_with_body_and_timeout(client, method, url, None, timeout).await
}

pub async fn send_request_with_timeout_and_headers(
    client: &HttpClient,
    method: Method,
    url: &str,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    let uri: Uri = url.parse()?;
    let body = Full::new(Bytes::new());
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;
    *req_builder.headers_mut() = headers;
    let req = req_builder;

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.request(req).await?
    };

    Ok(HttpResponse::from_hyper(response, None).await)
}

pub async fn send_request_with_body_and_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    send_request_with_body_and_timeout_with_limit(client, method, url, body, timeout, None).await
}

pub async fn send_request_with_body_and_timeout_with_limit(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    timeout: Option<Duration>,
    max_response_size: Option<usize>,
) -> Result<HttpResponse> {
    let uri: Uri = url.parse()?;
    let body = Full::new(body.unwrap_or_default());
    let req = Request::builder().method(method).uri(uri).body(body)?;

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.request(req).await?
    };

    Ok(HttpResponse::from_hyper(response, max_response_size).await)
}

pub async fn send_request_with_body_headers_and_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    let uri: Uri = url.parse()?;
    let body = Full::new(body.unwrap_or_default());
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;
    *req_builder.headers_mut() = headers;
    let req = req_builder;

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.request(req).await?
    };

    Ok(HttpResponse::from_hyper(response, None).await)
}

/// Send a request and return the raw hyper Response with streaming body intact.
/// The caller is responsible for consuming the body stream.
///
/// Body must be `Full<Bytes>`. For streaming with WAF scanning, wrap the body
/// in `StreamingWafBody` which implements `http_body::Body`.
pub async fn send_request_streaming(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Full<Bytes>,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
) -> Result<Response<Incoming>> {
    let uri: Uri = url.parse()?;
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;
    *req_builder.headers_mut() = headers;
    let req = req_builder;

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.request(req).await?
    };

    Ok(response)
}

pub async fn send_request_streaming_generic<B>(
    client: &Client<HttpsConnector<HttpConnector>, B>,
    method: Method,
    url: &str,
    body: B,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
) -> Result<Response<Incoming>>
where
    B: http_body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: std::fmt::Debug + Send + Sync + std::error::Error,
{
    let uri: Uri = url.parse()?;
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;
    *req_builder.headers_mut() = headers;
    let req = req_builder;

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.request(req).await?
    };

    Ok(response)
}

pub async fn send_request_erased_streaming(
    client: &ErasedHttpClient,
    method: Method,
    url: &str,
    body: BoxErasedBody,
    headers: http::HeaderMap,
    timeout: Option<Duration>,
    is_http2: bool,
) -> Result<Response<Incoming>> {
    let uri: Uri = url.parse()?;
    let mut req_builder = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;
    *req_builder.headers_mut() = headers;
    let req = req_builder;

    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.send_request(req, authority, is_http2, Some(t))).await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("request timed out")),
        }
    } else {
        client.send_request(req, authority, is_http2, None).await?
    };

    Ok(response)
}

pub struct HttpResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    pub async fn from_hyper(response: Response<Incoming>, max_size: Option<usize>) -> Self {
        let status = response.status();
        let headers = response.headers().clone();

        let body = if let Some(limit) = max_size {
            let limited_body = Limited::new(response.into_body(), limit);
            match limited_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Self {
                        status,
                        headers,
                        body: Bytes::new(),
                    }
                }
            }
        } else {
            response
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .unwrap_or_default()
        };

        Self {
            status,
            headers,
            body,
        }
    }

    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn headers_iter(
        &self,
    ) -> impl Iterator<Item = (&http::header::HeaderName, &http::HeaderValue)> {
        self.headers.iter()
    }
}

pub fn is_quictunnel_url(url: &str) -> bool {
    url.starts_with("quictunnel://") || url.starts_with("quictunnel:")
}

pub async fn send_request_via_quic_tunnel(
    method: Method,
    url: &str,
    headers: Option<&http::HeaderMap>,
    body: Option<bytes::Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    use crate::tunnel::quic::framing::{read_message, write_message};
    use crate::tunnel::quic::messages::TunnelMessage;
    use crate::tunnel::QUIC_TUNNEL_REGISTRY;

    let trimmed = url
        .trim_start_matches("quictunnel://")
        .trim_start_matches("quictunnel:");

    let (peer, port_str) = if let Some(colon_pos) = trimmed.rfind(':') {
        let peer = &trimmed[..colon_pos];
        let path_start = trimmed[colon_pos + 1..].find('/');
        let (port_str, _path) = if let Some(idx) = path_start {
            let remaining = &trimmed[colon_pos + 1..];
            (&remaining[..idx], Some(&remaining[idx..]))
        } else {
            (&trimmed[colon_pos + 1..], None)
        };
        (peer, port_str)
    } else {
        return Err(anyhow::anyhow!(
            "Invalid quictunnel URL format: expected quictunnel://peer:port"
        ));
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port in quictunnel URL: {}", port_str))?;

    let runtime = QUIC_TUNNEL_REGISTRY
        .get_runtime()
        .await
        .ok_or_else(|| anyhow::anyhow!("QUIC tunnel runtime not available"))?;

    let identifier = format!("http-port-{}", port);

    let (mut send_stream, mut recv_stream) = runtime
        .open_tunnel_stream_to_peer(peer, &identifier)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open QUIC tunnel stream: {}", e))?;

    let stream_open = TunnelMessage::StreamOpen {
        identifier: identifier.clone(),
        port,
        protocol: "http".to_string(),
        tls_passthrough: false,
    };
    write_message(&mut send_stream, &stream_open).await?;

    let response = read_message(&mut recv_stream, 65536).await?;
    match response {
        TunnelMessage::StreamOpenAck {
            success, message, ..
        } => {
            if !success {
                return Err(anyhow::anyhow!(
                    "Stream open failed: {}",
                    message.unwrap_or_default()
                ));
            }
        }
        _ => return Err(anyhow::anyhow!("Unexpected response to StreamOpen")),
    }

    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, "/", peer
    );

    if let Some(h) = headers {
        for (name, value) in h.iter() {
            if name != http::header::HOST && name != http::header::CONNECTION {
                http_request.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
            }
        }
    }

    if let Some(ref b) = body {
        http_request.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }

    http_request.push_str("\r\n");

    send_stream.write_all(http_request.as_bytes()).await?;

    if let Some(b) = body {
        send_stream.write_all(&b).await?;
    }

    send_stream
        .finish()
        .map_err(|e| anyhow::anyhow!("Failed to finish send stream: {}", e))?;

    let result = if let Some(t) = timeout {
        match tokio::time::timeout(t, async {
            let mut response_data = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match recv_stream.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => response_data.extend_from_slice(&buf[..n]),
                    Ok(None) => break,
                    Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
                }
            }
            Ok::<_, anyhow::Error>(response_data)
        })
        .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow::anyhow!("Request timed out")),
        }
    } else {
        let mut response_data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match recv_stream.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => response_data.extend_from_slice(&buf[..n]),
                Ok(None) => break,
                Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
            }
        }
        response_data
    };

    let response_str = String::from_utf8_lossy(&result);
    let mut header_lines = response_str.split("\r\n");

    let status_line = header_lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("No status line in response"))?;

    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status_code: u16 = status_parts
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("No status code in response"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid status code"))?;

    let mut response_headers = http::HeaderMap::new();
    loop {
        match header_lines.next() {
            Some("") => break,
            Some(line) => {
                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].trim();
                    let value = line[colon_pos + 1..].trim();
                    if let Ok(header_name) = http::header::HeaderName::try_from(name) {
                        if let Ok(header_value) = http::header::HeaderValue::from_str(value) {
                            response_headers.append(header_name, header_value);
                        }
                    }
                }
            }
            None => break,
        }
    }

    let response_headers = {
        use crate::proxy::headers::filter_response_headers_buf_with_str_set;
        let hop_by_hop: std::collections::HashSet<&str> = crate::proxy::headers::HOP_BY_HOP_HEADERS
            .iter()
            .copied()
            .collect();
        filter_response_headers_buf_with_str_set(&response_headers, &hop_by_hop)
    };

    let body_start = response_str
        .find("\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(0);
    let response_body = Bytes::from(result[body_start..].to_vec());

    Ok(HttpResponse {
        status: http::StatusCode::from_u16(status_code)
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
        headers: response_headers,
        body: response_body,
    })
}

pub async fn get(client: &HttpClient, url: &str) -> Result<HttpResponse, String> {
    send_request(client, Method::GET, url)
        .await
        .map_err(|e| e.to_string())
}

pub async fn get_with_timeout(
    client: &HttpClient,
    url: &str,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    send_request_with_timeout(client, Method::GET, url, Some(timeout))
        .await
        .map_err(|e| e.to_string())
}

pub async fn post_json<T: Serialize>(
    client: &HttpClient,
    url: &str,
    body: &T,
) -> Result<HttpResponse, String> {
    let json = serde_json::to_string(body).map_err(|e| e.to_string())?;

    let uri: Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(json)))
        .map_err(|e| e.to_string())?;

    let response = client.request(req).await.map_err(|e| e.to_string())?;

    Ok(HttpResponse::from_hyper(response, None).await)
}

pub async fn post_json_with_timeout<T: Serialize>(
    client: &HttpClient,
    url: &str,
    body: &T,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    let json = serde_json::to_string(body).map_err(|e| e.to_string())?;

    let uri: Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(json)))
        .map_err(|e| e.to_string())?;

    let response = match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("request timed out".to_string()),
    };

    Ok(HttpResponse::from_hyper(response, None).await)
}

pub async fn post_json_response<T: Serialize, R: DeserializeOwned>(
    client: &HttpClient,
    url: &str,
    body: &T,
) -> Result<R, String> {
    let response = post_json(client, url, body).await?;
    let s = String::from_utf8(response.body.to_vec()).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

pub async fn post_json_response_with_timeout<T: Serialize, R: DeserializeOwned>(
    client: &HttpClient,
    url: &str,
    body: &T,
    timeout: Duration,
) -> Result<R, String> {
    let response = post_json_with_timeout(client, url, body, timeout).await?;
    let s = String::from_utf8(response.body.to_vec()).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

pub fn create_simple_http_client(timeout: Duration) -> HttpClient {
    create_http_client_with_config(Duration::from_secs(5), 100, timeout)
}

pub async fn get_with_auth(
    client: &HttpClient,
    url: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    use base64::Engine;
    use http::header::AUTHORIZATION;

    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));

    let uri: Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(AUTHORIZATION, format!("Basic {}", credentials))
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;

    let response = match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("request timed out".to_string()),
    };

    Ok(HttpResponse::from_hyper(response, None).await)
}

pub async fn head_with_auth(
    client: &HttpClient,
    url: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    use base64::Engine;
    use http::header::AUTHORIZATION;

    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));

    let uri: Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let req = Request::builder()
        .method(Method::HEAD)
        .uri(uri)
        .header(AUTHORIZATION, format!("Basic {}", credentials))
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;

    let response = match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("request timed out".to_string()),
    };

    Ok(HttpResponse::from_hyper(response, None).await)
}

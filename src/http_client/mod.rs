//! HTTP client abstraction for upstream proxy connections.
//!
//! Provides TLS-configurable HTTP/1.1 and HTTP/2 clients using hyper,
//! with support for connection pooling, timeouts, and per-site TLS settings.

use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use http::{header, Method, Request, Response, Uri};
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use hyperlocal::{UnixConnector, Uri as HyperlocalUri};
use serde::{de::DeserializeOwned, Serialize};

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
pub type UnixHttpClient = Client<UnixConnector, Full<Bytes>>;

#[derive(Hash, PartialEq, Eq)]
struct UpstreamClientKey {
    tls_config: UpstreamTlsConfig,
    pool_max_idle: usize,
    pool_idle_secs: u64,
}

static UPSTREAM_CLIENT_CACHE: LazyLock<DashMap<UpstreamClientKey, HttpClient>> =
    LazyLock::new(DashMap::new);

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
            tracing::warn!(
                reason = config.skip_verify_reason.as_deref().unwrap_or("none provided"),
                "Upstream TLS: skip_verify is ENABLED \u{2014} certificate verification is disabled"
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
    create_http_client_with_config(Duration::from_secs(5), 100, Duration::from_secs(30))
}

pub fn create_http_client_with_config(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
) -> HttpClient {
    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(connect_timeout));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(60)));

    let tls_config = build_tls_config(None, false, None);

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http2()
        .wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .pool_idle_timeout(pool_idle_timeout)
        .http2_only(false)
        .build(https_connector)
}

pub fn create_upstream_client(
    connect_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_idle_timeout: Duration,
    tls_config: &UpstreamTlsConfig,
) -> HttpClient {
    let key = UpstreamClientKey {
        tls_config: tls_config.clone(),
        pool_max_idle: pool_max_idle_per_host,
        pool_idle_secs: pool_idle_timeout.as_secs(),
    };

    if let Some(client) = UPSTREAM_CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(connect_timeout));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(60)));

    let rustls_config = build_tls_config(
        tls_config.ca_cert_path.as_deref(),
        tls_config.skip_verify,
        tls_config.skip_verify_reason.as_deref(),
    );

    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(rustls_config);

    let builder = if tls_config.allow_plaintext {
        builder.https_or_http()
    } else {
        builder.https_only()
    };

    let https_connector = builder.enable_http2().wrap_connector(http_connector);

    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .pool_idle_timeout(pool_idle_timeout)
        .http2_only(false)
        .build(https_connector);

    UPSTREAM_CLIENT_CACHE.insert(key, client.clone());
    client
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

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("failed to set TLS protocol versions");

    if skip_verify {
        let reason = skip_verify_reason.unwrap_or("not specified");
        tracing::warn!(
            reason,
            "TLS certificate verification is DISABLED for upstream connections — \
             this is insecure and should only be used in development"
        );
        let mut config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier::new(reason.to_string())))
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

#[derive(Debug)]
struct NoVerifier {
    skip_reason: String,
}

impl NoVerifier {
    fn new(reason: String) -> Self {
        Self {
            skip_reason: reason,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        tracing::warn!(
            reason = %self.skip_reason,
            "TLS certificate verification DISABLED - accepting certificate without validation"
        );
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
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

    Ok(HttpResponse::from_hyper(response).await)
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

    Ok(HttpResponse::from_hyper(response).await)
}

pub async fn send_request_with_body_and_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    timeout: Option<Duration>,
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

    Ok(HttpResponse::from_hyper(response).await)
}

pub struct HttpResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    pub async fn from_hyper(response: Response<Incoming>) -> Self {
        let status = response.status();
        let headers = response.headers().clone();

        let body = response
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();

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

    Ok(HttpResponse::from_hyper(response).await)
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

    Ok(HttpResponse::from_hyper(response).await)
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

    Ok(HttpResponse::from_hyper(response).await)
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

    Ok(HttpResponse::from_hyper(response).await)
}

use std::time::Duration;
use std::path::PathBuf;

use http::{Request, Response, Method, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_rustls::HttpsConnector;
use hyperlocal::{UnixConnector, Uri as HyperlocalUri};

pub type HttpClient = Client<HttpsConnector<HttpConnector>, EmptyBody>;
pub type UnixHttpClient = Client<UnixConnector, EmptyBody>;

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

#[derive(Debug, Clone)]
pub struct UpstreamTlsConfig {
    pub verify: bool,
    pub ca_cert_path: Option<String>,
    pub server_name: Option<String>,
    pub skip_verify: bool,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
        }
    }
}

pub fn create_http_client() -> HttpClient {
    create_http_client_with_config(
        Duration::from_secs(5),
        100,
        Duration::from_secs(30),
    )
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
    
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .unwrap()
        .https_or_http()
        .enable_http2()
        .wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .pool_idle_timeout(pool_idle_timeout)
        .http2_only(false)
        .build(https_connector)
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
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let uri = HyperlocalUri::new(socket_path, path);
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(EmptyBody)?;
    
    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err("request timed out".into()),
        }
    } else {
        client.request(req).await?
    };
    
    Ok(HttpResponse::from_hyper(response).await)
}

pub async fn send_request(
    client: &HttpClient,
    method: Method,
    url: &str,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    send_request_with_timeout(client, method, url, None).await
}

pub async fn send_request_with_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    timeout: Option<Duration>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let uri: Uri = url.parse()?;
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(EmptyBody)?;
    
    let response = if let Some(t) = timeout {
        match tokio::time::timeout(t, client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err("request timed out".into()),
        }
    } else {
        client.request(req).await?
    };
    
    Ok(HttpResponse::from_hyper(response).await)
}

pub struct HttpResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: String,
}

impl HttpResponse {
    pub async fn from_hyper(response: Response<Incoming>) -> Self {
        let status = response.status();
        let headers = response.headers().clone();
        
        let body_bytes = response
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();
        
        let body = String::from_utf8_lossy(&body_bytes).to_string();
        
        Self { status, headers, body }
    }
    
    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }
    
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
    
    pub fn headers_iter(&self) -> impl Iterator<Item = (&http::header::HeaderName, &http::HeaderValue)> {
        self.headers.iter()
    }
}

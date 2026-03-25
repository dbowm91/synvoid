use std::time::Duration;
use std::path::PathBuf;

use bytes::Bytes;
use http::{Request, Response, Method, Uri, header};
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_rustls::HttpsConnector;
use hyperlocal::{UnixConnector, Uri as HyperlocalUri};
use serde::{Serialize, de::DeserializeOwned};

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
pub type UnixHttpClient = Client<UnixConnector, Full<Bytes>>;

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
    send_unix_request_with_body(client, socket_path, path, method, None, timeout).await
}

pub async fn send_unix_request_with_body(
    client: &UnixHttpClient,
    socket_path: &str,
    path: &str,
    method: Method,
    body: Option<bytes::Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
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
    send_request_with_body_and_timeout(client, method, url, None, timeout).await
}

pub async fn send_request_with_body_and_timeout(
    client: &HttpClient,
    method: Method,
    url: &str,
    body: Option<Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    let uri: Uri = url.parse()?;
    let body = Full::new(body.unwrap_or_else(Bytes::new));
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)?;

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

pub fn is_quictunnel_url(url: &str) -> bool {
    url.starts_with("quictunnel://") || url.starts_with("quictunnel:")
}

pub async fn send_request_via_quic_tunnel(
    method: Method,
    url: &str,
    headers: Option<&http::HeaderMap>,
    body: Option<bytes::Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
    use crate::tunnel::QUIC_TUNNEL_REGISTRY;
    use crate::tunnel::quic::messages::TunnelMessage;
    use crate::tunnel::quic::framing::{read_message, write_message};

    
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
        return Err("Invalid quictunnel URL format: expected quictunnel://peer:port".into());
    };
    
    let port: u16 = port_str.parse()
        .map_err(|_| format!("Invalid port in quictunnel URL: {}", port_str))?;
    
    let runtime = QUIC_TUNNEL_REGISTRY.get_runtime().await
        .ok_or_else(|| "QUIC tunnel runtime not available".to_string())?;
    
    let identifier = format!("http-port-{}", port);
    
    let (mut send_stream, mut recv_stream) = runtime.open_tunnel_stream_to_peer(peer, &identifier).await
        .map_err(|e| format!("Failed to open QUIC tunnel stream: {}", e))?;
    
    let stream_open = TunnelMessage::StreamOpen {
        identifier: identifier.clone(),
        port,
        protocol: "http".to_string(),
        tls_passthrough: false,
    };
    write_message(&mut send_stream, &stream_open).await?;
    
    let response = read_message(&mut recv_stream, 65536).await?;
    match response {
        TunnelMessage::StreamOpenAck { success, message, .. } => {
            if !success {
                return Err(format!("Stream open failed: {}", message.unwrap_or_default()).into());
            }
        }
        _ => return Err("Unexpected response to StreamOpen".into()),
    }
    
    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method,
        "/",
        peer
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
    
    send_stream.finish()
        .map_err(|e| format!("Failed to finish send stream: {}", e))?;
    
    let result = if let Some(t) = timeout {
        match tokio::time::timeout(t, async {
            let mut response_data = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match recv_stream.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => response_data.extend_from_slice(&buf[..n]),
                    Ok(None) => break,
                    Err(e) => return Err(format!("Read error: {}", e).into()),
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response_data)
        }).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err("Request timed out".into()),
        }
    } else {
        let mut response_data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match recv_stream.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => response_data.extend_from_slice(&buf[..n]),
                Ok(None) => break,
                Err(e) => return Err(format!("Read error: {}", e).into()),
            }
        }
        response_data
    };
    
    let response_str = String::from_utf8_lossy(&result);
    let mut header_lines = response_str.split("\r\n");
    
    let status_line = header_lines.next()
        .ok_or("No status line in response")?;
    
    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status_code: u16 = status_parts.get(1)
        .ok_or("No status code in response")?
        .parse()
        .map_err(|_| "Invalid status code")?;
    
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
    
    let body_start = response_str.find("\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(0);
    let response_body = response_str[body_start..].to_string();
    
    Ok(HttpResponse {
        status: http::StatusCode::from_u16(status_code).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
        headers: response_headers,
        body: response_body,
    })
}

pub async fn get(client: &HttpClient, url: &str) -> Result<HttpResponse, String> {
    send_request(client, Method::GET, url)
        .await
        .map_err(|e| e.to_string())
}

pub async fn get_with_timeout(client: &HttpClient, url: &str, timeout: Duration) -> Result<HttpResponse, String> {
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
    
    let uri: Uri = url.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(json)))
        .map_err(|e| e.to_string())?;

    let response = client.request(req).await
        .map_err(|e| e.to_string())?;
    
    Ok(HttpResponse::from_hyper(response).await)
}

pub async fn post_json_with_timeout<T: Serialize>(
    client: &HttpClient,
    url: &str,
    body: &T,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    let json = serde_json::to_string(body).map_err(|e| e.to_string())?;
    
    let uri: Uri = url.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
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
    serde_json::from_str(&response.body).map_err(|e| e.to_string())
}

pub async fn post_json_response_with_timeout<T: Serialize, R: DeserializeOwned>(
    client: &HttpClient,
    url: &str,
    body: &T,
    timeout: Duration,
) -> Result<R, String> {
    let response = post_json_with_timeout(client, url, body, timeout).await?;
    serde_json::from_str(&response.body).map_err(|e| e.to_string())
}

pub fn create_simple_http_client(timeout: Duration) -> HttpClient {
    create_http_client_with_config(
        Duration::from_secs(5),
        100,
        timeout,
    )
}

//! Unix socket URL parsing and Unix HTTP client/request helpers.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use http::{Method, Request};
use hyper_util::rt::TokioExecutor;
use hyperlocal::{UnixConnector, Uri as HyperlocalUri};

use crate::response::HttpResponse;

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

pub fn create_unix_http_client() -> crate::client::UnixHttpClient {
    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(30))
        .http2_only(false)
        .build(UnixConnector)
}

pub async fn send_unix_request_with_timeout(
    client: &crate::client::UnixHttpClient,
    socket_path: &str,
    path: &str,
    method: Method,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    send_unix_request_with_body(client, socket_path, path, method, None, timeout).await
}

pub async fn send_unix_request_with_body(
    client: &crate::client::UnixHttpClient,
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
        http_body_util::Full::new(bytes::Bytes::new())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_unix_socket_url_recognizes_http_unix_schemes() {
        assert!(is_unix_socket_url("http+unix:///var/run/app.sock").is_some());
        assert!(is_unix_socket_url("http+unix:/var/run/app.sock").is_some());
    }

    #[test]
    fn is_unix_socket_url_recognizes_unix_schemes() {
        assert!(is_unix_socket_url("unix:///var/run/app.sock").is_some());
        assert!(is_unix_socket_url("unix:/var/run/app.sock").is_some());
    }

    #[test]
    fn is_unix_socket_url_recognizes_absolute_paths() {
        assert!(is_unix_socket_url("/var/run/app.sock").is_some());
    }

    #[test]
    fn is_unix_socket_url_recognizes_relative_dot_slash_paths() {
        assert!(is_unix_socket_url("./app.sock").is_some());
    }

    #[test]
    fn is_unix_socket_url_rejects_normal_http_https() {
        assert!(is_unix_socket_url("http://example.com").is_none());
        assert!(is_unix_socket_url("https://example.com").is_none());
    }

    #[test]
    fn is_unix_socket_url_rejects_bare_relative_without_dot_slash() {
        assert!(is_unix_socket_url("relative.sock").is_none());
    }
}

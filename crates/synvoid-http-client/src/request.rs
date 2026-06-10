//! Generic HTTP request helpers, streaming variants, and convenience get/post/auth wrappers.

use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http::{header, Method, Request, Response, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use serde::{de::DeserializeOwned, Serialize};

use crate::client::HttpClient;
use crate::erased_pool::{BoxErasedBody, ErasedHttpClient};
use crate::response::HttpResponse;

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
    client: Client<HttpsConnector<HttpConnector>, B>,
    method: Method,
    url: String,
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

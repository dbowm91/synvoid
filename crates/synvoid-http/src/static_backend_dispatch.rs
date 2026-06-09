use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;

use synvoid_proxy::{BackendType, RouteTarget};

pub async fn maybe_handle_static_backend(
    target: RouteTarget,
    path: String,
    method: http::Method,
    headers: http::HeaderMap,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if !matches!(target.backend_type, BackendType::Static) {
        return None;
    }

    let static_handler = target.static_handler.as_ref()?;
    let accept_encoding = headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let if_none_match = headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let if_modified_since = headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let range_header = headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match static_handler
        .serve(
            &path,
            &method,
            accept_encoding.as_deref(),
            if_none_match.as_deref(),
            if_modified_since.as_deref(),
            range_header.as_deref(),
        )
        .await
    {
        Ok(response) => {
            let mut builder = http::Response::builder().status(response.status);
            for (name, value) in response.headers {
                builder = builder.header(&name, &value);
            }
            let resp = match response.body {
                synvoid_static_files::StaticResponseBody::InMemory(body) => builder
                    .body(Full::new(body).boxed())
                    .unwrap_or_else(|_| crate::fallback_error_boxed()),
                synvoid_static_files::StaticResponseBody::Buffered(body) => {
                    tracing::debug!("Zero-copy streaming for buffered static content");
                    builder
                        .body(Full::new(body).boxed())
                        .unwrap_or_else(|_| crate::fallback_error_boxed())
                }
            };
            Some(resp)
        }
        Err(e) => {
            tracing::warn!("Static file error for {}: {}", path, e);
            None
        }
    }
}

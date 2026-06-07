use std::time::Instant;

use bytes::Bytes;
use http::{header, Response, StatusCode};
use metrics::{counter, histogram};

use synvoid_proxy::RouteResult;

use crate::headers::generate_stealth_timestamp;
use crate::http3_body::{send_response_with_body, Http3RequestStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn build_not_found_response() -> Response<()> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::DATE, generate_stealth_timestamp(5))
        .body(())
        .unwrap_or_else(|_| {
            tracing::error!("Failed to build HTTP/3 not-found response");
            Response::new(())
        })
}

pub async fn finalize_http3_request<W: Http3RequestStream>(
    request_stream: &mut W,
    start: Instant,
) -> Result<(), BoxError> {
    request_stream
        .finish()
        .await
        .map_err(|e| Box::new(e) as BoxError)?;
    histogram!("synvoid.http3.request.duration").record(start.elapsed());
    counter!("synvoid.http3.responses").increment(1);
    Ok(())
}

pub async fn maybe_handle_http3_terminal_route_result<W: Http3RequestStream>(
    route_result: &RouteResult,
    host: &str,
    request_stream: &mut W,
    start: Instant,
) -> Result<bool, BoxError> {
    match route_result {
        RouteResult::Found(_) => Ok(false),
        RouteResult::NotFound(msg) | RouteResult::Error(msg) => {
            tracing::debug!("Route not found: {} for host: {}", msg, host);
            counter!("synvoid.http3.requests.not_found").increment(1);
            let body = format!("Not Found: {}", msg);
            let response = build_not_found_response();
            send_response_with_body(request_stream, response, Bytes::from(body)).await?;
            finalize_http3_request(request_stream, start).await?;
            Ok(true)
        }
    }
}

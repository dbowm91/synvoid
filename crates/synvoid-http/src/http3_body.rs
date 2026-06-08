use std::net::IpAddr;

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use metrics::counter;

use crate::headers::generate_stealth_timestamp;
use crate::shared_handler::StreamingWafScanner;
use synvoid_http_client::StreamingWafDecision;

#[async_trait]
pub trait Http3RequestStream {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn recv_data(&mut self) -> Result<Option<Bytes>, Self::Error>;
    async fn send_response(&mut self, response: Response<()>) -> Result<(), Self::Error>;
    async fn send_data(&mut self, body: Bytes) -> Result<(), Self::Error>;
    async fn finish(&mut self) -> Result<(), Self::Error>;
}

pub struct Http3CollectedBody {
    pub body_bytes: Vec<u8>,
    pub request_body_size: u64,
}

pub enum Http3BodyCollectionOutcome {
    Continue(Http3CollectedBody),
    Responded,
}

pub(crate) fn build_json_error_response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::DATE, generate_stealth_timestamp(5))
        .body(())
        .unwrap_or_else(|_| {
            tracing::error!("Failed to build HTTP/3 error response body");
            Response::new(())
        })
}

pub(crate) async fn send_response_with_body<W>(
    request_stream: &mut W,
    response: Response<()>,
    body: Bytes,
) -> Result<(), W::Error>
where
    W: Http3RequestStream,
{
    let (parts, _) = response.into_parts();
    request_stream
        .send_response(Response::from_parts(parts, ()))
        .await?;
    request_stream.send_data(body).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn collect_http3_request_body<W>(
    stream_scanned_upstream_mode: bool,
    max_request_size: usize,
    client_ip: IpAddr,
    mut streaming_waf: Option<Box<dyn StreamingWafScanner>>,
    request_stream: &mut W,
) -> Result<Http3BodyCollectionOutcome, W::Error>
where
    W: Http3RequestStream,
{
    if stream_scanned_upstream_mode {
        return Ok(Http3BodyCollectionOutcome::Continue(Http3CollectedBody {
            body_bytes: Vec::new(),
            request_body_size: 0,
        }));
    }

    let mut body_bytes = Vec::new();
    while let Some(chunk_bytes) = request_stream.recv_data().await? {
        let chunk_len = chunk_bytes.len();
        if body_bytes.len() + chunk_len > max_request_size {
            tracing::warn!(
                client = %client_ip,
                size = body_bytes.len(),
                "HTTP/3 request body exceeds max size"
            );
            counter!("synvoid.http3.request.body_too_large").increment(1);
            let response = build_json_error_response(StatusCode::PAYLOAD_TOO_LARGE);
            request_stream.send_response(response).await?;
            request_stream
                .send_data(Bytes::from_static(
                    b"{\"error\":\"Request body too large\"}",
                ))
                .await?;
            request_stream.finish().await?;
            return Ok(Http3BodyCollectionOutcome::Responded);
        }

        if let Some(sw) = streaming_waf.as_mut() {
            if let StreamingWafDecision::Block(status, message) = sw.scan_chunk(&chunk_bytes) {
                counter!("synvoid.http3.requests.blocked").increment(1);
                let response = build_json_error_response(
                    StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                );
                request_stream.send_response(response).await?;
                request_stream
                    .send_data(Bytes::from(format!("{{\"error\":\"{}\"}}", message)))
                    .await?;
                request_stream.finish().await?;
                return Ok(Http3BodyCollectionOutcome::Responded);
            }
        }

        body_bytes.extend_from_slice(&chunk_bytes);
    }

    let request_body_size = body_bytes.len() as u64;
    Ok(Http3BodyCollectionOutcome::Continue(Http3CollectedBody {
        body_bytes,
        request_body_size,
    }))
}

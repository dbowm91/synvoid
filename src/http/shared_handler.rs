use bytes::Bytes;
use http::{Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use metrics;
use std::convert::Infallible;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::config::MainConfig;
use crate::http::response_builder::{
    build_json_response, build_response_with_alt_svc, build_response_with_cookie,
};
use crate::waf::attack_detection::{StreamingWafCore, StreamingWafDecision};

pub struct SharedRequestHandler;

impl SharedRequestHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle_health_request(
        &self,
        alt_svc: &Option<String>,
        main_config: &MainConfig,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let body = serde_json::json!({
            "status": "healthy",
        })
        .to_string();

        self.build_response_with_alt_svc(200, body, "application/json", alt_svc, main_config)
    }

    pub fn handle_ready_request(
        &self,
        is_ready: bool,
        alt_svc: &Option<String>,
        main_config: &MainConfig,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let (status_code, body) = if is_ready {
            let body = serde_json::json!({
                "ready": true,
            })
            .to_string();
            (200, body)
        } else {
            let body = serde_json::json!({
                "ready": false,
                "reason": "not_ready",
            })
            .to_string();
            (503, body)
        };

        self.build_response_with_alt_svc(
            status_code,
            body,
            "application/json",
            alt_svc,
            main_config,
        )
    }

    pub fn build_response_with_alt_svc(
        &self,
        status: u16,
        body: String,
        content_type: &str,
        alt_svc: &Option<String>,
        main_config: &MainConfig,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        build_response_with_alt_svc(status, body, content_type, alt_svc, main_config)
    }

    pub fn build_response_with_cookie(
        &self,
        status: u16,
        body: String,
        content_type: &str,
        cookie: &str,
        alt_svc: &Option<String>,
        main_config: &MainConfig,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        build_response_with_cookie(status, body, content_type, cookie, alt_svc, main_config)
    }

    pub fn build_json_response(
        &self,
        status: u16,
        body: String,
        alt_svc: &Option<String>,
        main_config: &MainConfig,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        build_json_response(status, body, alt_svc, main_config)
    }

    pub fn build_error_response(
        &self,
        status: u16,
        message: &str,
        alt_svc: &Option<String>,
        main_config: &MainConfig,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let body = serde_json::json!({
            "error": message
        })
        .to_string();

        self.build_response_with_alt_svc(status, body, "application/json", alt_svc, main_config)
    }

    pub fn handle_waf_decision_drop() -> Response<BoxBody<Bytes, Infallible>> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()).boxed())
            .unwrap_or_else(|_| crate::http::fallback_error_boxed())
    }
}

impl Default for SharedRequestHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_json_response() {
        let handler = SharedRequestHandler::new();
        let main_config = MainConfig::default();

        let resp =
            handler.build_json_response(200, r#"{"status":"ok"}"#.to_string(), &None, &main_config);

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_build_response_with_alt_svc() {
        let handler = SharedRequestHandler::new();
        let main_config = MainConfig::default();
        let alt_svc = Some("h3=\":443\"".to_string());

        let resp = handler.build_response_with_alt_svc(
            200,
            "OK".to_string(),
            "text/plain",
            &alt_svc,
            &main_config,
        );

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().contains_key("alt-svc"));
    }

    #[test]
    fn test_build_error_response() {
        let handler = SharedRequestHandler::new();
        let main_config = MainConfig::default();

        let resp = handler.build_error_response(500, "Internal Server Error", &None, &main_config);

        assert_eq!(resp.status(), 500);
    }
}



#[derive(Clone, Copy)]
pub enum BodyCollectionProtocol {
    Http,
    Https,
}

impl BodyCollectionProtocol {
    fn counter_blocked(&self) -> &'static str {
        match self {
            BodyCollectionProtocol::Http => "synvoid.http.streaming_body_blocked",
            BodyCollectionProtocol::Https => "synvoid.https.streaming_body_blocked",
        }
    }

    fn counter_too_large(&self) -> &'static str {
        match self {
            BodyCollectionProtocol::Http => "synvoid.http.streaming_body_too_large",
            BodyCollectionProtocol::Https => "synvoid.https.streaming_body_too_large",
        }
    }
}

pub struct WafStreamedBody<B> {
    inner: B,
    streaming_waf: Option<StreamingWafCore>,
    client_ip: IpAddr,
    protocol: BodyCollectionProtocol,
    max_body_size: usize,
    accumulated_len: usize,
}

impl<B> WafStreamedBody<B> {
    pub fn new(
        inner: B,
        streaming_waf: Option<StreamingWafCore>,
        client_ip: IpAddr,
        protocol: BodyCollectionProtocol,
        max_body_size: usize,
    ) -> Self {
        Self {
            inner,
            streaming_waf,
            client_ip,
            protocol,
            max_body_size,
            accumulated_len: 0,
        }
    }
}

impl<B> Body for WafStreamedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_data() {
                    let chunk = frame.into_data().unwrap_or_default();
                    this.accumulated_len += chunk.len();

                    if this.accumulated_len > this.max_body_size {
                        tracing::warn!(
                            client_ip = %this.client_ip,
                            size = this.accumulated_len,
                            limit = this.max_body_size,
                            "Request body exceeded max streaming body size limit"
                        );
                        metrics::counter!(this.protocol.counter_too_large()).increment(1);
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Body too large",
                        ))));
                    }

                    if let Some(sw) = &mut this.streaming_waf {
                        if let StreamingWafDecision::Block(_, _) = sw.scan_chunk(&chunk) {
                            tracing::warn!(
                                client_ip = %this.client_ip,
                                "Request blocked during streaming body WAF check"
                            );
                            metrics::counter!(this.protocol.counter_blocked()).increment(1);
                            return Poll::Ready(Some(Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "Blocked by WAF",
                            ))));
                        }
                    }

                    Poll::Ready(Some(Ok(Frame::data(chunk))))
                } else {
                    Poll::Ready(Some(Ok(frame)))
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub fn stream_body_with_waf<B>(
    body: B,
    waf: &Arc<crate::waf::WafCore>,
    client_ip: IpAddr,
    protocol: BodyCollectionProtocol,
    max_body_size: usize,
) -> WafStreamedBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    let streaming_waf = waf.streaming();
    WafStreamedBody::new(body, streaming_waf, client_ip, protocol, max_body_size)
}

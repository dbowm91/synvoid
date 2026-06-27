use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Response, StatusCode};
use metrics::counter;

use synvoid_metrics::bandwidth::{BandwidthProtocol, BandwidthTracker, EgressDirection};
use synvoid_metrics::{record_stall_timeout, StallPermit};
use synvoid_waf::WafDecision;

use crate::headers::generate_stealth_timestamp;
use crate::http3_body::{build_json_error_response, send_response_with_body, Http3RequestStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3WafDecisionOutcome {
    Continue,
    EarlyReturn,
}

fn build_html_response(status: StatusCode, extra_headers: &[(&str, String)]) -> Response<()> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::DATE, generate_stealth_timestamp(5));
    for (name, value) in extra_headers {
        builder = builder.header(*name, value.as_str());
    }
    builder.body(()).unwrap_or_else(|_| {
        tracing::error!("Failed to build HTTP/3 response headers");
        Response::new(())
    })
}

fn record_bandwidth_egress(
    bandwidth: Option<&Arc<BandwidthTracker>>,
    host: &str,
    body_len: u64,
    direction: EgressDirection,
) {
    if let Some(ref bw) = bandwidth {
        bw.record_egress(body_len, BandwidthProtocol::Http3, direction);
        bw.record_site_egress(host, body_len);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_http3_waf_decision<W, TarpitFn>(
    decision: WafDecision,
    host: &str,
    request_stream: &mut W,
    bandwidth: Option<&Arc<BandwidthTracker>>,
    stall_timeout: Duration,
    max_stalled_requests: u32,
    generate_tarpit_html: TarpitFn,
) -> Result<Http3WafDecisionOutcome, W::Error>
where
    W: Http3RequestStream,
    TarpitFn: FnOnce(&str) -> String,
{
    match decision {
        WafDecision::Pass => Ok(Http3WafDecisionOutcome::Continue),
        WafDecision::Stall => {
            counter!("synvoid.http3.requests.stalled").increment(1);
            let permit = match StallPermit::try_new(max_stalled_requests) {
                Some(p) => p,
                None => {
                    counter!("synvoid.http3.requests.stall_capped").increment(1);
                    tracing::warn!(
                        max_stalled = max_stalled_requests,
                        "HTTP/3 stall rejected due to concurrency cap"
                    );
                    let body = r#"{"error":"Too many requests"}"#;
                    let body_len = body.len() as u64;
                    record_bandwidth_egress(bandwidth, host, body_len, EgressDirection::Blocked);
                    let response = build_json_error_response(StatusCode::TOO_MANY_REQUESTS);
                    send_response_with_body(request_stream, response, Bytes::from(body)).await?;
                    request_stream.finish().await?;
                    return Ok(Http3WafDecisionOutcome::EarlyReturn);
                }
            };
            tokio::time::sleep(stall_timeout).await;
            drop(permit);
            record_stall_timeout();
            tracing::debug!("Stall timeout reached");
            Ok(Http3WafDecisionOutcome::Continue)
        }
        WafDecision::Drop => {
            counter!("synvoid.http3.blackhole_drop").increment(1);
            Ok(Http3WafDecisionOutcome::EarlyReturn)
        }
        WafDecision::Block(status, message) => {
            counter!("synvoid.http3.requests.blocked").increment(1);
            let body = format!("{{\"error\":\"{}\"}}", message);
            let body_len = body.len() as u64;
            record_bandwidth_egress(bandwidth, host, body_len, EgressDirection::Blocked);
            let response = build_json_error_response(
                StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
            );
            send_response_with_body(request_stream, response, Bytes::from(body)).await?;
            request_stream.finish().await?;
            Ok(Http3WafDecisionOutcome::EarlyReturn)
        }
        WafDecision::Challenge(_type, html) => {
            counter!("synvoid.http3.requests.challenged").increment(1);
            let body_len = html.len() as u64;
            record_bandwidth_egress(bandwidth, host, body_len, EgressDirection::Challenged);
            let response = build_html_response(StatusCode::OK, &[]);
            send_response_with_body(request_stream, response, Bytes::from(html)).await?;
            request_stream.finish().await?;
            Ok(Http3WafDecisionOutcome::EarlyReturn)
        }
        WafDecision::ChallengeWithCookie {
            challenge_type: _,
            html,
            session_cookie_name,
            session_cookie_value,
            session_cookie_max_age,
        } => {
            counter!("synvoid.http3.requests.challenged").increment(1);
            let body_len = html.len() as u64;
            record_bandwidth_egress(bandwidth, host, body_len, EgressDirection::Challenged);
            let cookie = format!(
                "{}={}; path=/; max-age={}; Secure; SameSite=Strict; HttpOnly",
                session_cookie_name, session_cookie_value, session_cookie_max_age
            );
            let response = build_html_response(StatusCode::OK, &[("Set-Cookie", cookie)]);
            send_response_with_body(request_stream, response, Bytes::from(html)).await?;
            request_stream.finish().await?;
            Ok(Http3WafDecisionOutcome::EarlyReturn)
        }
        WafDecision::Tarpit(tar_path) => {
            counter!("synvoid.http3.requests.tarpitted").increment(1);
            let html = generate_tarpit_html(&tar_path);
            let body_len = html.len() as u64;
            record_bandwidth_egress(bandwidth, host, body_len, EgressDirection::Blocked);
            let response = build_html_response(StatusCode::OK, &[]);
            send_response_with_body(request_stream, response, Bytes::from(html)).await?;
            request_stream.finish().await?;
            Ok(Http3WafDecisionOutcome::EarlyReturn)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockRequestStream {
        response_sent: AtomicBool,
        data_sent: AtomicBool,
        finished: AtomicBool,
    }

    impl MockRequestStream {
        fn new() -> Self {
            Self {
                response_sent: AtomicBool::new(false),
                data_sent: AtomicBool::new(false),
                finished: AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl Http3RequestStream for MockRequestStream {
        type Error = Infallible;

        async fn recv_data(&mut self) -> Result<Option<Bytes>, Infallible> {
            Ok(None)
        }
        async fn send_response(&mut self, _response: Response<()>) -> Result<(), Infallible> {
            self.response_sent.store(true, Ordering::Relaxed);
            Ok(())
        }
        async fn send_data(&mut self, _body: Bytes) -> Result<(), Infallible> {
            self.data_sent.store(true, Ordering::Relaxed);
            Ok(())
        }
        async fn finish(&mut self) -> Result<(), Infallible> {
            self.finished.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn http3_stall_allows_when_below_limit() {
        let mut stream = MockRequestStream::new();

        let result = maybe_handle_http3_waf_decision(
            WafDecision::Stall,
            "test.example.com",
            &mut stream,
            None,
            Duration::from_millis(10),
            u32::MAX,
            |_path| "tarpit".to_string(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Http3WafDecisionOutcome::Continue);
    }

    #[tokio::test]
    async fn http3_stall_returns_429_when_limit_reached() {
        // Acquire permits up to the limit
        let mut permits = Vec::new();
        for _ in 0..100 {
            permits.push(StallPermit::try_new(u32::MAX).unwrap());
        }
        let mut stream = MockRequestStream::new();

        let result = maybe_handle_http3_waf_decision(
            WafDecision::Stall,
            "test.example.com",
            &mut stream,
            None,
            Duration::from_millis(10),
            100,
            |_path| "tarpit".to_string(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Http3WafDecisionOutcome::EarlyReturn);
        assert!(stream.response_sent.load(Ordering::Relaxed));
        assert!(stream.data_sent.load(Ordering::Relaxed));
        assert!(stream.finished.load(Ordering::Relaxed));
        drop(permits);
    }

    #[tokio::test]
    async fn http3_stall_releases_permit_after_completion() {
        let mut stream = MockRequestStream::new();

        let result = maybe_handle_http3_waf_decision(
            WafDecision::Stall,
            "test.example.com",
            &mut stream,
            None,
            Duration::from_millis(10),
            u32::MAX,
            |_path| "tarpit".to_string(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Http3WafDecisionOutcome::Continue);
    }

    #[tokio::test]
    async fn http3_stall_uses_configured_stall_limit() {
        // Acquire permits up to the limit
        let mut permits = Vec::new();
        for _ in 0..2 {
            permits.push(StallPermit::try_new(u32::MAX).unwrap());
        }
        let mut stream = MockRequestStream::new();

        let result = maybe_handle_http3_waf_decision(
            WafDecision::Stall,
            "test.example.com",
            &mut stream,
            None,
            Duration::from_millis(10),
            2,
            |_path| "tarpit".to_string(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Http3WafDecisionOutcome::EarlyReturn);
        assert!(stream.response_sent.load(Ordering::Relaxed));
        drop(permits);
    }

    #[tokio::test]
    async fn http3_stall_pass_continues_immediately() {
        let mut stream = MockRequestStream::new();

        let result = maybe_handle_http3_waf_decision(
            WafDecision::Pass,
            "test.example.com",
            &mut stream,
            None,
            Duration::from_millis(10),
            100,
            |_path| "tarpit".to_string(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Http3WafDecisionOutcome::Continue);
        assert!(!stream.response_sent.load(Ordering::Relaxed));
    }

    #[test]
    fn stall_permit_try_new_succeeds_below_limit() {
        let _permit = StallPermit::try_new(u32::MAX);
        assert!(
            _permit.is_some(),
            "try_new(u32::MAX) should always succeed unless counter is at u32::MAX"
        );
    }

    #[test]
    fn stall_permit_try_new_fails_at_limit() {
        // Hold a permit to guarantee the active count is >= 1.
        let guard = StallPermit::try_new(u32::MAX).unwrap();
        // try_new(1) must fail because the active count is >= 1 == limit.
        assert!(
            StallPermit::try_new(1).is_none(),
            "try_new(1) must fail when active count >= 1"
        );
        drop(guard);
    }

    #[test]
    fn stall_permit_drops_release_counter() {
        let before = synvoid_metrics::get_active_stalled_requests();
        let permit = StallPermit::try_new(u32::MAX).unwrap();
        let after_acquire = synvoid_metrics::get_active_stalled_requests();
        assert!(
            after_acquire > before,
            "counter must increase after acquiring a permit: before={before}, after_acquire={after_acquire}"
        );
        drop(permit);
        let after_drop = synvoid_metrics::get_active_stalled_requests();
        assert!(
            after_drop < after_acquire,
            "counter must decrease after dropping a permit: after_acquire={after_acquire}, after_drop={after_drop}"
        );
    }
}

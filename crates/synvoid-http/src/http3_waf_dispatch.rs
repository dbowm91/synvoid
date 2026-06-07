use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Response, StatusCode};
use metrics::counter;

use synvoid_metrics::bandwidth::{BandwidthProtocol, BandwidthTracker, EgressDirection};
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
pub async fn maybe_handle_http3_waf_decision<W, TarpitFn, StallStartFn, StallEndFn>(
    decision: WafDecision,
    host: &str,
    request_stream: &mut W,
    bandwidth: Option<&Arc<BandwidthTracker>>,
    stall_timeout: Duration,
    mut on_stall_start: StallStartFn,
    mut on_stall_end: StallEndFn,
    generate_tarpit_html: TarpitFn,
) -> Result<Http3WafDecisionOutcome, W::Error>
where
    W: Http3RequestStream,
    TarpitFn: FnOnce(&str) -> String,
    StallStartFn: FnMut(),
    StallEndFn: FnMut(),
{
    match decision {
        WafDecision::Pass => Ok(Http3WafDecisionOutcome::Continue),
        WafDecision::Stall => {
            counter!("synvoid.http3.requests.stalled").increment(1);
            on_stall_start();
            tokio::time::sleep(stall_timeout).await;
            on_stall_end();
            tracing::debug!("Stall timeout reached, dropping connection");
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

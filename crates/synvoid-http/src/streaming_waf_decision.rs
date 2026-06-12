use std::convert::Infallible;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use http::Response;
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use metrics::counter;

use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::{record_stall_timeout, StallPermit};
use synvoid_waf::WafDecision;

use crate::response_builder::{build_response_with_alt_svc, build_response_with_cookie};
use crate::response_helpers::format_secure_http_only_cookie;

pub type TarpitStream =
    Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + Sync + 'static>>;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_streaming_waf_decision<DropFn, RenderBlockFn, TarpitFn>(
    decision: WafDecision,
    on_drop: DropFn,
    render_block_body: RenderBlockFn,
    stream_tarpit: TarpitFn,
    http_config: &HttpConfig,
    user_agent: Option<&str>,
    alt_svc: &Option<String>,
    main_config: &MainConfig,
) -> Option<Response<BoxBody<Bytes, Infallible>>>
where
    DropFn: FnOnce(),
    RenderBlockFn: FnOnce(u16, &str) -> String,
    TarpitFn: FnOnce(&str, Option<&str>) -> TarpitStream,
{
    match decision {
        WafDecision::Pass => None,
        WafDecision::Drop => {
            counter!("synvoid.http.blackhole_drop").increment(1);
            on_drop();
            Some(
                Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| crate::fallback_error_boxed()),
            )
        }
        WafDecision::Stall => {
            counter!("synvoid.http.stalled").increment(1);
            let permit = match StallPermit::try_new(http_config.max_stalled_requests) {
                Some(p) => p,
                None => {
                    return Some(build_response_with_alt_svc(
                        429,
                        "Too many requests".to_string(),
                        "text/plain",
                        alt_svc,
                        main_config,
                    ));
                }
            };
            let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
            tokio::time::sleep(stall_timeout).await;
            record_stall_timeout();
            drop(permit);
            Some(build_response_with_alt_svc(
                408,
                "Request timeout".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            ))
        }
        WafDecision::Block(status, message) => {
            let body = render_block_body(status, &message);
            Some(build_response_with_alt_svc(
                status,
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
        WafDecision::Challenge(_type, html) => Some(build_response_with_alt_svc(
            200,
            html,
            "text/html",
            alt_svc,
            main_config,
        )),
        WafDecision::ChallengeWithCookie {
            challenge_type: _,
            html,
            session_cookie_name,
            session_cookie_value,
            session_cookie_max_age,
        } => {
            let cookie = format_secure_http_only_cookie(
                &session_cookie_name,
                &session_cookie_value,
                session_cookie_max_age as u64,
            );
            Some(build_response_with_cookie(
                200,
                html,
                "text/html",
                &cookie,
                alt_svc,
                main_config,
            ))
        }
        WafDecision::Tarpit(tar_path) => {
            let stream = stream_tarpit(&tar_path, user_agent);
            let mut builder = Response::builder()
                .status(200)
                .header("Content-Type", "text/html");
            if let Some(alt_svc_value) = alt_svc {
                builder = builder.header("Alt-Svc", alt_svc_value.as_str());
            }
            Some(
                builder
                    .body(BodyExt::boxed(StreamBody::new(stream.map(|res| {
                        Ok::<_, Infallible>(Frame::data(res.unwrap_or_default()))
                    }))))
                    .unwrap(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::HttpConfig;

    fn test_http_config(max_stalled: u32) -> HttpConfig {
        let mut config = HttpConfig::default();
        config.max_stalled_requests = max_stalled;
        config.waf_stall_timeout_secs = 0;
        config
    }

    fn noop_drop() {}
    fn noop_render(_: u16, _: &str) -> String {
        String::new()
    }
    fn noop_tarpit(_: &str, _: Option<&str>) -> TarpitStream {
        Box::pin(futures::stream::empty())
    }

    #[tokio::test]
    async fn streaming_stall_below_cap_returns_408() {
        let config = test_http_config(u32::MAX);
        let resp = maybe_handle_streaming_waf_decision(
            WafDecision::Stall,
            noop_drop,
            noop_render,
            noop_tarpit,
            &config,
            None,
            &None,
            &MainConfig::default(),
        )
        .await;

        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), 408);
    }

    #[tokio::test]
    async fn streaming_stall_at_cap_returns_429() {
        let config = test_http_config(2);
        let _permits: Vec<_> = (0..2)
            .filter_map(|_| StallPermit::try_new(2))
            .collect();

        let before = std::time::Instant::now();
        let resp = maybe_handle_streaming_waf_decision(
            WafDecision::Stall,
            noop_drop,
            noop_render,
            noop_tarpit,
            &config,
            None,
            &None,
            &MainConfig::default(),
        )
        .await;
        let elapsed = before.elapsed();

        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), 429);
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "should not sleep when cap is reached"
        );
    }

    #[tokio::test]
    async fn streaming_stall_permit_releases_after_sleep() {
        let config = test_http_config(u32::MAX);

        let resp = maybe_handle_streaming_waf_decision(
            WafDecision::Stall,
            noop_drop,
            noop_render,
            noop_tarpit,
            &config,
            None,
            &None,
            &MainConfig::default(),
        )
        .await;

        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), 408);
    }
}

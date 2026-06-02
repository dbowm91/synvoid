use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use http::Response;
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use metrics::counter;

use crate::config::{HttpConfig, MainConfig};
use crate::http::response_builder::build_response_with_alt_svc;
use crate::http::response_helpers::format_secure_http_only_cookie;
use crate::router::RouteTarget;
use crate::waf::WafCore;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_streaming_waf_decision<DropFn>(
    decision: crate::proxy::WafDecision,
    waf: &Arc<WafCore>,
    on_drop: DropFn,
    http_config: &HttpConfig,
    target: &RouteTarget,
    user_agent: Option<&str>,
    alt_svc: &Option<String>,
    main_config: &MainConfig,
) -> Option<Response<BoxBody<Bytes, Infallible>>>
where
    DropFn: FnOnce(),
{
    match decision {
        crate::proxy::WafDecision::Pass => None,
        crate::proxy::WafDecision::Drop => {
            counter!("synvoid.http.blackhole_drop").increment(1);
            on_drop();
            Some(
                Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed()),
            )
        }
        crate::proxy::WafDecision::Stall => {
            counter!("synvoid.http.stalled").increment(1);
            let stall_timeout = Duration::from_secs(http_config.waf_stall_timeout_secs);
            tokio::time::sleep(stall_timeout).await;
            Some(build_response_with_alt_svc(
                408,
                "Request timeout".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            ))
        }
        crate::proxy::WafDecision::Block(status, message) => {
            let body = waf.error_page_manager.render_page_with_theme(
                status,
                Some(&message),
                target
                    .site_config
                    .error_pages
                    .theme
                    .as_ref()
                    .map(|theme_config| {
                        theme_config.to_theme_config(waf.error_page_manager.theme())
                    })
                    .as_ref(),
            );
            Some(build_response_with_alt_svc(
                status,
                body,
                "text/html",
                alt_svc,
                main_config,
            ))
        }
        crate::proxy::WafDecision::Challenge(_type, html) => Some(build_response_with_alt_svc(
            200,
            html,
            "text/html",
            alt_svc,
            main_config,
        )),
        crate::proxy::WafDecision::ChallengeWithCookie {
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
            Some(crate::http::response_builder::build_response_with_cookie(
                200,
                html,
                "text/html",
                &cookie,
                alt_svc,
                main_config,
            ))
        }
        crate::proxy::WafDecision::Tarpit(tar_path) => {
            let stream = waf.stream_tarpit(&tar_path, user_agent);
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

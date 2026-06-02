use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use metrics::counter;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use crate::challenge::HONEYPOT_PREFIX;
use crate::config::MainConfig;
use crate::http::response_helpers::format_secure_http_only_cookie;
use crate::waf::WafCore;

pub fn maybe_handle_challenge_paths(
    path: &str,
    client_ip: IpAddr,
    waf: &Arc<WafCore>,
    parts: &http::request::Parts,
    main_config: &Arc<MainConfig>,
    alt_svc: &Option<String>,
    mut on_log: impl FnMut(u16, bool),
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if path.starts_with(HONEYPOT_PREFIX) {
        counter!("synvoid.honeypot.hit").increment(1);
        tracing::info!("HTTP honeypot accessed: {} by {}", path, client_ip);
        waf.block_ip_for_honeypot(
            client_ip,
            "honeypot",
            waf.config.honeypot_ban_duration_secs,
            "global",
        );
        on_log(408, true);
        return Some(crate::http::response_builder::build_response_with_alt_svc(
            408,
            "Request timeout".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        ));
    }

    if path.starts_with("/_waf_css_challenge") {
        let (html, _) = waf
            .challenge_manager
            .generate_challenge_page(&client_ip, Some(path));
        on_log(200, true);
        return Some(crate::http::response_builder::build_response_with_alt_svc(
            200,
            html,
            "text/html",
            alt_svc,
            main_config,
        ));
    }

    if path.starts_with("/_waf_assets") {
        let asset_name = match path.strip_prefix("/_waf_assets/rnd-") {
            Some(name) => name.strip_suffix(".png").unwrap_or(name),
            None => {
                on_log(204, true);
                let mut resp = Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                resp.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                return Some(resp);
            }
        };

        if !waf.challenge_manager.css_enabled() {
            on_log(404, true);
            return Some(crate::http::response_builder::build_response_with_alt_svc(
                404,
                "Not Found".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            ));
        }

        let cookie_name = waf.challenge_manager.css_session_cookie_name();
        let session_id = parts
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookie_str| {
                cookie_str
                    .split(';')
                    .find(|c| c.trim().starts_with(&format!("{}=", cookie_name)))
                    .map(|c| c.trim()[cookie_name.len() + 1..].to_string())
            });

        let session_id = match session_id {
            Some(sid) => sid,
            None => {
                on_log(204, true);
                let mut resp = Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                resp.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                return Some(resp);
            }
        };

        let (res, action) = waf
            .challenge_manager
            .record_css_asset_request(&session_id, asset_name);

        if res == crate::challenge::AssetRequestResult::InvalidAsset {
            tracing::warn!("Bot detected via CSS aspect-ratio trap: IP {}", client_ip);
            waf.block_ip_for_honeypot(
                client_ip,
                "css_trap_hit",
                waf.config.honeypot_ban_duration_secs,
                "global",
            );
        }

        match action {
            crate::challenge::CssAssetAction::RedirectWithCookie => {
                let verified_cookie_name = waf.challenge_manager.css_verified_cookie_name();
                let window_secs = waf.challenge_manager.css_window_secs();
                let cookie = format_secure_http_only_cookie(
                    &verified_cookie_name,
                    "verified",
                    window_secs as u64,
                );
                let response = Response::builder()
                    .status(http::StatusCode::FOUND)
                    .header(http::header::LOCATION, "/")
                    .header(http::header::SET_COOKIE, cookie)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                return Some(response);
            }
            crate::challenge::CssAssetAction::DropConnection => {
                let mut resp = Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| crate::http::fallback_error_boxed());
                resp.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                return Some(resp);
            }
        }
    }

    None
}

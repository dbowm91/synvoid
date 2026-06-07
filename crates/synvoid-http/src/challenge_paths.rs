use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use metrics::counter;
use std::convert::Infallible;
use std::net::IpAddr;

use synvoid_challenge::css::{AssetRequestResult, CssAssetAction};
use synvoid_challenge::honeypot::HONEYPOT_PREFIX;
use synvoid_config::MainConfig;

use crate::response_builder::{build_response_with_alt_svc, fallback_error_boxed};
use crate::response_helpers::format_secure_http_only_cookie;

pub trait ChallengePathWaf {
    fn block_ip_for_honeypot(&self, ip: IpAddr, reason: &str, duration_secs: u64, scope: &str);

    fn generate_challenge_page(
        &self,
        ip: &IpAddr,
        app_path: Option<&str>,
    ) -> (String, Option<String>);

    fn css_enabled(&self) -> bool;

    fn css_session_cookie_name(&self) -> String;

    fn record_css_asset_request(
        &self,
        session_id: &str,
        asset_name: &str,
    ) -> (AssetRequestResult, CssAssetAction);

    fn css_verified_cookie_name(&self) -> String;

    fn css_window_secs(&self) -> u64;
}

pub fn maybe_handle_challenge_paths<W>(
    path: &str,
    client_ip: IpAddr,
    waf: &W,
    honeypot_ban_duration_secs: u64,
    parts: &http::request::Parts,
    main_config: &MainConfig,
    alt_svc: &Option<String>,
    mut on_log: impl FnMut(u16, bool),
) -> Option<Response<BoxBody<Bytes, Infallible>>>
where
    W: ChallengePathWaf + ?Sized,
{
    if path.starts_with(HONEYPOT_PREFIX) {
        counter!("synvoid.honeypot.hit").increment(1);
        tracing::info!("HTTP honeypot accessed: {} by {}", path, client_ip);
        waf.block_ip_for_honeypot(client_ip, "honeypot", honeypot_ban_duration_secs, "global");
        on_log(408, true);
        return Some(build_response_with_alt_svc(
            408,
            "Request timeout".to_string(),
            "text/plain",
            alt_svc,
            main_config,
        ));
    }

    if path.starts_with("/_waf_css_challenge") {
        let (html, _) = waf.generate_challenge_page(&client_ip, Some(path));
        on_log(200, true);
        return Some(build_response_with_alt_svc(
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
                    .unwrap_or_else(|_| fallback_error_boxed());
                resp.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                return Some(resp);
            }
        };

        if !waf.css_enabled() {
            on_log(404, true);
            return Some(build_response_with_alt_svc(
                404,
                "Not Found".to_string(),
                "text/plain",
                alt_svc,
                main_config,
            ));
        }

        let cookie_name = waf.css_session_cookie_name();
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
                    .unwrap_or_else(|_| fallback_error_boxed());
                resp.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                return Some(resp);
            }
        };

        let (res, action) = waf.record_css_asset_request(&session_id, asset_name);

        if res == AssetRequestResult::InvalidAsset {
            tracing::warn!("Bot detected via CSS aspect-ratio trap: IP {}", client_ip);
            waf.block_ip_for_honeypot(
                client_ip,
                "css_trap_hit",
                honeypot_ban_duration_secs,
                "global",
            );
        }

        match action {
            CssAssetAction::RedirectWithCookie => {
                let verified_cookie_name = waf.css_verified_cookie_name();
                let window_secs = waf.css_window_secs();
                let cookie =
                    format_secure_http_only_cookie(&verified_cookie_name, "verified", window_secs);
                let response = Response::builder()
                    .status(http::StatusCode::FOUND)
                    .header(http::header::LOCATION, "/")
                    .header(http::header::SET_COOKIE, cookie)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| fallback_error_boxed());
                return Some(response);
            }
            CssAssetAction::DropConnection => {
                let mut resp = Response::builder()
                    .status(http::StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::from_static(&[])).boxed())
                    .unwrap_or_else(|_| fallback_error_boxed());
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

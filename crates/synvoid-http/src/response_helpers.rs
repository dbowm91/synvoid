use bytes::Bytes;
use futures::StreamExt;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;

use synvoid_config::site::SiteSecurityHeadersConfig;

use crate::headers::{
    compute_websocket_accept_key, generate_stealth_timestamp, inject_security_headers,
};

pub type BoxBodyResponse = Response<BoxBody<Bytes, Infallible>>;

/// Enforce the single-value invariant for `date`/`server` on Canonical H1
/// responses (Phase 75): a relayed upstream value plus a site-generated one
/// must not both reach the wire (duplicate `Date` is a spec violation and
/// the direct-H1 final boundary fail-closes it to 500). The LAST occurrence
/// wins so explicit site policy stays authoritative over relayed values.
/// Single values pass through untouched.
pub fn dedupe_single_value_response_headers(resp: BoxBodyResponse) -> BoxBodyResponse {
    let (mut parts, body) = resp.into_parts();
    for name in ["date", "server"] {
        if let Some(last) = parts.headers.get_all(name).iter().next_back().cloned() {
            parts.headers.remove(name);
            parts.headers.insert(name, last);
        }
    }
    Response::from_parts(parts, body)
}

/// Convert a body to an infallible body without panicking when the upstream
/// connection fails after the response has started.
pub fn swallow_body_errors<B>(body: B) -> BoxBody<Bytes, Infallible>
where
    B: http_body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
    B::Error: std::fmt::Debug + Send + Sync + 'static,
{
    let stream = futures::stream::unfold(body.into_data_stream(), |mut body| async move {
        match body.next().await {
            Some(Ok(bytes)) => Some((Ok(http_body::Frame::data(bytes)), body)),
            Some(Err(error)) => {
                tracing::warn!("Upstream body stream error: {:?}", error);
                None
            }
            None => None,
        }
    });
    http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(stream))
}

pub fn apply_security_headers(
    builder: http::response::Builder,
    security_headers: &SiteSecurityHeadersConfig,
    global_security_headers: bool,
) -> http::response::Builder {
    let mut builder = builder;
    if security_headers.enabled.unwrap_or(false) || global_security_headers {
        builder = inject_security_headers(builder, security_headers);
    }
    if security_headers.date_header.unwrap_or(true) {
        let jitter = security_headers.date_jitter_seconds.unwrap_or(5);
        builder = builder.header("Date", generate_stealth_timestamp(jitter));
    }
    if let Some(ref token) = security_headers.server_token {
        builder = builder.header("Server", token.as_str());
    }
    builder
}

pub fn build_websocket_response(headers: &http::HeaderMap) -> BoxBodyResponse {
    let ws_key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let ws_protocols = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok());

    let accept_key = compute_websocket_accept_key(ws_key);

    let mut builder = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key);

    if let Some(protocols) = ws_protocols {
        builder = builder.header("Sec-WebSocket-Protocol", protocols);
    }

    let boxed: BoxBody<Bytes, Infallible> = Full::new(Bytes::new()).boxed();
    builder
        .body(boxed)
        .unwrap_or_else(|_| crate::fallback_error_boxed())
}

pub fn format_secure_http_only_cookie(name: &str, value: &str, max_age_secs: u64) -> String {
    format!(
        "{}={}; path=/; max-age={}; Secure; SameSite=Strict; HttpOnly",
        name, value, max_age_secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::site::{SiteCookieConfig, SiteCorsConfig, SiteSecurityHeadersConfig};

    fn default_security_config() -> SiteSecurityHeadersConfig {
        SiteSecurityHeadersConfig {
            enabled: None,
            strict_transport_security: None,
            content_security_policy: None,
            x_frame_options: None,
            x_content_type_options: None,
            x_xss_protection: None,
            referrer_policy: None,
            permissions_policy: None,
            cache_control: None,
            expect_ct: None,
            x_permitted_cross_domain_policies: None,
            x_download_options: None,
            content_type: None,
            more_clear_headers: vec![],
            cors: SiteCorsConfig::default(),
            cookie: SiteCookieConfig::default(),
            date_header: None,
            date_jitter_seconds: None,
            server_token: None,
        }
    }

    #[test]
    fn test_apply_security_headers_hsts() {
        let config = SiteSecurityHeadersConfig {
            enabled: Some(true),
            strict_transport_security: Some("max-age=31536000".to_string()),
            ..default_security_config()
        };
        let builder = http::Response::builder();
        let resp = apply_security_headers(builder, &config, false)
            .body(())
            .unwrap();
        assert_eq!(
            resp.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000"
        );
    }

    #[test]
    fn test_build_websocket_response() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        let resp = build_websocket_response(&headers);
        assert_eq!(resp.status(), 101);
        assert_eq!(resp.headers().get("upgrade").unwrap(), "websocket");
    }

    #[test]
    fn test_format_secure_http_only_cookie() {
        let cookie = format_secure_http_only_cookie("sid", "abc", 60);
        assert!(cookie.contains("sid=abc"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
    }

    #[test]
    fn test_dedupe_keeps_last_date_and_server() {
        use http_body_util::BodyExt as _;
        let resp = http::Response::builder()
            .status(200)
            .header("date", "Sun, 06 Nov 1994 08:49:37 GMT")
            .header("server", "upstream")
            .body(http_body_util::Empty::<Bytes>::new().boxed())
            .unwrap();
        let mut resp = resp;
        resp.headers_mut()
            .append("date", "Mon, 07 Nov 1994 08:49:37 GMT".parse().unwrap());
        resp.headers_mut().append("server", "site".parse().unwrap());
        resp.headers_mut().append("x-keep", "1".parse().unwrap());
        resp.headers_mut().append("x-keep", "2".parse().unwrap());
        let deduped = dedupe_single_value_response_headers(resp);
        let date: Vec<_> = deduped.headers().get_all("date").iter().collect();
        assert_eq!(date.len(), 1);
        assert_eq!(date[0], "Mon, 07 Nov 1994 08:49:37 GMT");
        let server: Vec<_> = deduped.headers().get_all("server").iter().collect();
        assert_eq!(server.len(), 1);
        assert_eq!(server[0], "site");
        // Unrelated duplicates are untouched.
        assert_eq!(deduped.headers().get_all("x-keep").iter().count(), 2);
    }

    #[test]
    fn test_dedupe_leaves_single_values_alone() {
        use http_body_util::BodyExt as _;
        let resp = http::Response::builder()
            .status(200)
            .header("date", "Sun, 06 Nov 1994 08:49:37 GMT")
            .header("x-keep", "1")
            .body(http_body_util::Empty::<Bytes>::new().boxed())
            .unwrap();
        let deduped = dedupe_single_value_response_headers(resp);
        assert_eq!(deduped.status(), 200);
        assert_eq!(deduped.headers().get_all("date").iter().count(), 1);
        assert_eq!(deduped.headers().get("x-keep").unwrap(), "1");
    }
}

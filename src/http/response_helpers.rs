use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::Full;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::http::headers::{compute_websocket_accept_key, generate_stealth_timestamp, inject_security_headers};
use crate::router::RouteTarget;

pub type BoxBodyResponse = Response<BoxBody<Bytes, Infallible>>;

pub fn apply_security_headers(
    builder: http::response::Builder,
    target: &RouteTarget,
    main_config: &Arc<MainConfig>,
) -> http::response::Builder {
    let mut builder = builder;
    if target.site_config.security_headers.enabled.unwrap_or(false)
        || main_config.security.global_security_headers
    {
        builder = inject_security_headers(builder, &target.site_config.security_headers);
    }
    if target
        .site_config
        .security_headers
        .date_header
        .unwrap_or(true)
    {
        let jitter = target
            .site_config
            .security_headers
            .date_jitter_seconds
            .unwrap_or(5);
        builder = builder.header("Date", generate_stealth_timestamp(jitter));
    }
    if let Some(ref token) = target.site_config.security_headers.server_token {
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
        .unwrap_or_else(|_| crate::http::fallback_error_boxed())
}
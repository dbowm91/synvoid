// Root compatibility shim — canonical implementation is in synvoid-http.
use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::sync::Arc;

use crate::config::MainConfig;
use crate::waf::WafCore;

pub fn maybe_handle_challenge_paths(
    path: &str,
    client_ip: std::net::IpAddr,
    waf: &Arc<WafCore>,
    parts: &http::request::Parts,
    main_config: &Arc<MainConfig>,
    alt_svc: &Option<String>,
    on_log: impl FnMut(u16, bool),
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    synvoid_http::maybe_handle_challenge_paths(
        path,
        client_ip,
        waf.as_ref(),
        waf.config.honeypot_ban_duration_secs,
        parts,
        main_config.as_ref(),
        alt_svc,
        on_log,
    )
}

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use http::HeaderMap;
use metrics::counter;

use synvoid_proxy::{RouteResult, Router};

use crate::request_parse::resolve_client_ip;

pub struct Http3RequestPrelude {
    pub parts: http::request::Parts,
    pub route_result: RouteResult,
    pub client_ip: IpAddr,
    pub path: String,
    pub host: String,
    pub query_string: Option<String>,
    pub user_agent: Option<String>,
}

pub enum Http3RequestPreludeOutcome {
    Continue(Box<Http3RequestPrelude>),
    Respond,
}

fn extract_host(headers: &HeaderMap) -> String {
    headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

pub fn prepare_http3_request_prelude<B>(
    request: http::Request<B>,
    remote_addr: SocketAddr,
    trusted_proxies: &[String],
    router: &Arc<Router>,
    over_bandwidth_limit: bool,
) -> Http3RequestPreludeOutcome {
    let client_ip = resolve_client_ip(request.headers(), trusted_proxies, remote_addr.ip());

    if over_bandwidth_limit {
        tracing::warn!("Monthly bandwidth limit exceeded - returning 503");
        counter!("synvoid.bandwidth.limit_exceeded").increment(1);
        return Http3RequestPreludeOutcome::Respond;
    }

    let (parts, _body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let query_string = parts.uri.query().map(String::from);
    let host = extract_host(&parts.headers);
    let user_agent = extract_user_agent(&parts.headers);
    let route_result = router.route(&host, &path);

    Http3RequestPreludeOutcome::Continue(Box::new(Http3RequestPrelude {
        parts,
        route_result,
        client_ip,
        path,
        host,
        query_string,
        user_agent,
    }))
}

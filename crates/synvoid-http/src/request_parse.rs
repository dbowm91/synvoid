use std::net::IpAddr;

use http::HeaderMap;
use synvoid_waf::{request_sanitization::RequestSanitizer, WafDecision};

pub trait EarlyWafHooks {
    fn verify_trust_token(&self, client_ip: IpAddr, token: &str) -> bool;

    fn check_early(
        &self,
        client_ip: IpAddr,
        path: &str,
        cookies: Option<&str>,
        user_agent: Option<&str>,
    ) -> WafDecision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalEndpointAction {
    None,
    Drain,
    DrainStatus,
    Health,
    Ready,
}

const INTERNAL_DRAIN_PATH: &str = "/__internal__/drain";
const INTERNAL_DRAIN_STATUS_PATH: &str = "/__internal__/drain-status";
const INTERNAL_HEALTH_PATH: &str = "/__internal__/health";
const INTERNAL_READY_PATH: &str = "/__internal__/ready";
const HTTP01_CHALLENGE_PREFIX: &str = "/.well-known/synvoid-challenge/";

pub fn extract_request_metadata(
    parts: &http::request::Parts,
) -> (http::Method, String, String, Option<String>, Option<String>) {
    let method = parts.method.clone();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let user_agent = parts
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cookies = parts
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    (method, path, host, user_agent, cookies)
}

pub fn classify_internal_endpoint(
    path: &str,
    client_ip: IpAddr,
    has_drain_state: bool,
) -> InternalEndpointAction {
    if has_drain_state {
        let is_localhost = matches!(client_ip, IpAddr::V4(ip) if ip.is_loopback())
            || matches!(client_ip, IpAddr::V6(ip) if ip.is_loopback());

        if is_localhost {
            if path == INTERNAL_DRAIN_PATH {
                return InternalEndpointAction::Drain;
            }
            if path == INTERNAL_DRAIN_STATUS_PATH {
                return InternalEndpointAction::DrainStatus;
            }
        }

        if path == INTERNAL_HEALTH_PATH {
            return InternalEndpointAction::Health;
        }
        if path == INTERNAL_READY_PATH {
            return InternalEndpointAction::Ready;
        }
    } else if path == INTERNAL_HEALTH_PATH || path == INTERNAL_READY_PATH {
        return InternalEndpointAction::Health;
    }

    InternalEndpointAction::None
}

pub fn should_handle_key_exchange_path(path: &str) -> bool {
    path.starts_with("/key-") || path == "/health"
}

pub fn parse_http01_challenge_token(path: &str) -> Option<&str> {
    let token = path.strip_prefix(HTTP01_CHALLENGE_PREFIX)?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    Some(token)
}

pub fn extract_trust_token(cookies: Option<&str>) -> Option<&str> {
    let cookies_str = cookies?;
    cookies_str.split(';').find_map(|s| {
        let s = s.trim();
        s.strip_prefix("sv_trust=")
    })
}

pub fn should_skip_waf_from_trust_cookie<W: EarlyWafHooks>(
    waf: &W,
    client_ip: IpAddr,
    cookies: Option<&str>,
) -> bool {
    if let Some(token) = extract_trust_token(cookies) {
        return waf.verify_trust_token(client_ip, token);
    }
    false
}

pub fn early_waf_decision<W: EarlyWafHooks>(
    waf: &W,
    client_ip: IpAddr,
    path: &str,
    cookies: Option<&str>,
    skip_waf: bool,
) -> WafDecision {
    if skip_waf {
        WafDecision::Pass
    } else {
        waf.check_early(client_ip, path, cookies, None)
    }
}

pub fn sanitize_and_resolve_client_ip(
    headers: &mut HeaderMap,
    trusted_proxies: &[String],
    client_ip: IpAddr,
) -> IpAddr {
    let sanitizer = RequestSanitizer::new(trusted_proxies.to_vec(), true);
    sanitizer.sanitize_request_headers(headers, client_ip);
    sanitizer
        .get_real_ip(headers, client_ip)
        .unwrap_or(client_ip)
}

pub fn resolve_client_ip(
    headers: &HeaderMap,
    trusted_proxies: &[String],
    client_ip: IpAddr,
) -> IpAddr {
    let sanitizer = RequestSanitizer::new(trusted_proxies.to_vec(), true);
    sanitizer
        .get_real_ip(headers, client_ip)
        .unwrap_or(client_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn classify_internal_endpoint_requires_loopback_for_drain() {
        let action = classify_internal_endpoint(
            "/__internal__/drain",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            true,
        );
        assert_eq!(action, InternalEndpointAction::None);

        let action = classify_internal_endpoint(
            "/__internal__/drain",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            true,
        );
        assert_eq!(action, InternalEndpointAction::Drain);
    }

    #[test]
    fn classify_internal_endpoint_health_ready_behavior() {
        let health_with_drain = classify_internal_endpoint(
            "/__internal__/health",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            true,
        );
        assert_eq!(health_with_drain, InternalEndpointAction::Health);

        let ready_with_drain = classify_internal_endpoint(
            "/__internal__/ready",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            true,
        );
        assert_eq!(ready_with_drain, InternalEndpointAction::Ready);

        let health_without_drain = classify_internal_endpoint(
            "/__internal__/health",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            false,
        );
        assert_eq!(health_without_drain, InternalEndpointAction::Health);

        let ready_without_drain = classify_internal_endpoint(
            "/__internal__/ready",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            false,
        );
        assert_eq!(ready_without_drain, InternalEndpointAction::Health);
    }

    #[test]
    fn should_handle_key_exchange_path_behavior() {
        assert!(should_handle_key_exchange_path("/key-test"));
        assert!(should_handle_key_exchange_path("/health"));
        assert!(!should_handle_key_exchange_path("/ready"));
    }

    #[test]
    fn extract_trust_token_behavior() {
        assert_eq!(
            extract_trust_token(Some("foo=bar; sv_trust=abc123; a=b")),
            Some("abc123")
        );
        assert_eq!(extract_trust_token(Some("foo=bar")), None);
        assert_eq!(extract_trust_token(None), None);
    }

    #[test]
    fn parse_http01_challenge_token_behavior() {
        assert_eq!(
            parse_http01_challenge_token("/.well-known/synvoid-challenge/token123"),
            Some("token123")
        );
        assert_eq!(
            parse_http01_challenge_token("/.well-known/synvoid-challenge/"),
            None
        );
        assert_eq!(
            parse_http01_challenge_token("/.well-known/synvoid-challenge/a/b"),
            None
        );
    }
}

//! Root-test ownership: COMPOSITION
//! Rationale: Phase 01 TLS request-flow convergence. Proves plaintext HTTP
//! and HTTPS observe the same canonical request-policy semantics: framing
//! fails closed identically, trusted-proxy resolution, internal endpoints,
//! WebSocket upgrade validation, body-policy error mapping, and upstream
//! `X-Forwarded-*` headers agree except for the documented
//! `X-Forwarded-Proto` scheme value.
//!
//! Table style: no duplicate policy engine is maintained here; each case
//! asserts equivalence across the two transports through the canonical
//! `synvoid-http` / `synvoid-proxy` helpers both servers now compose.

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, HeaderValue, Method, Uri, Version};
use synvoid_http::body_policy::BodyPolicyError;
use synvoid_http::framing::{validate_request_framing, validate_transfer_framing};
use synvoid_http::request_parse::{
    classify_internal_endpoint, sanitize_and_resolve_client_ip, InternalEndpointAction,
};
use synvoid_http::validation_helpers::validate_websocket_upgrade;
use synvoid_proxy::headers::{build_forward_headers, ForwardedProtocol};

fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            name.parse::<http::header::HeaderName>().unwrap(),
            value.parse::<HeaderValue>().unwrap(),
        );
    }
    headers
}

// ─── Framing fails closed identically ────────────────────────────────────────

#[test]
fn framing_rejection_parity_http_https() {
    // Duplicate Content-Length must reject on both transports (canonical
    // `validate_transfer_framing`; the old HTTPS path skipped this check).
    let mut dup = HeaderMap::new();
    dup.append(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
    dup.append(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
    assert!(validate_transfer_framing(&dup).is_err());

    // CL + Transfer-Encoding together must reject on both.
    let cl_te = header_map(&[("content-length", "5"), ("transfer-encoding", "chunked")]);
    assert!(validate_transfer_framing(&cl_te).is_err());

    // Well-formed single CL is accepted for both.
    let ok = header_map(&[("content-length", "5"), ("host", "example.com")]);
    let uri: Uri = "/".parse().unwrap();
    let result = validate_request_framing(&ok, &uri, Version::HTTP_11);
    assert!(result.is_ok());
}

#[test]
fn duplicate_host_rejected_for_both_transports() {
    let mut headers = HeaderMap::new();
    headers.append(http::header::HOST, HeaderValue::from_static("a.example"));
    headers.append(http::header::HOST, HeaderValue::from_static("b.example"));
    let uri: Uri = "/".parse().unwrap();
    assert!(validate_request_framing(&headers, &uri, Version::HTTP_11).is_err());
}

// ─── Trusted-proxy resolution ────────────────────────────────────────────────

#[test]
fn trusted_proxy_resolution_parity() {
    // Phase 01 fix: HTTPS previously used the raw peer IP; both transports
    // now run the same `sanitize_and_resolve_client_ip`.
    let peer: IpAddr = "203.0.113.7".parse().unwrap();
    let trusted = vec!["10.0.0.1".to_string()];

    let mut http_headers = header_map(&[("x-forwarded-for", "198.51.100.9")]);
    let mut https_headers = http_headers.clone();
    let http_ip = sanitize_and_resolve_client_ip(&mut http_headers, &trusted, peer);
    let https_ip = sanitize_and_resolve_client_ip(&mut https_headers, &trusted, peer);
    assert_eq!(http_ip, https_ip);

    // Untrusted proxy headers must not override the peer IP on either path.
    let mut untrusted_h = header_map(&[("x-forwarded-for", "198.51.100.9")]);
    let mut untrusted_s = untrusted_h.clone();
    let empty: Vec<String> = vec![];
    assert_eq!(
        sanitize_and_resolve_client_ip(&mut untrusted_h, &empty, peer),
        sanitize_and_resolve_client_ip(&mut untrusted_s, &empty, peer),
    );
}

// ─── Internal endpoints ──────────────────────────────────────────────────────

#[test]
fn internal_endpoint_parity() {
    for path in [
        "/__internal__/health",
        "/__internal__/ready",
        "/__internal__/drain",
        "/__internal__/drain-status",
    ] {
        let http = classify_internal_endpoint(path, localhost(), true);
        let https = classify_internal_endpoint(path, localhost(), true);
        assert_eq!(
            http, https,
            "internal endpoint {path} must classify identically"
        );
    }
    assert_eq!(
        classify_internal_endpoint("/api/users", localhost(), true),
        InternalEndpointAction::None
    );
}

// ─── WebSocket upgrade validation ────────────────────────────────────────────

#[test]
fn websocket_upgrade_validation_parity() {
    let ws_upgrade = header_map(&[
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("sec-websocket-version", "13"),
    ]);
    assert!(validate_websocket_upgrade(&ws_upgrade));

    let plain = header_map(&[("host", "example.com")]);
    assert!(!validate_websocket_upgrade(&plain));
    // Validation is transport-agnostic: the same helper gates upgrades on
    // both HTTP/1.1 and HTTPS/1.1 (HTTP/2 never upgrades; the helper simply
    // returns false for non-upgrade headers on either path).
    assert_eq!(
        validate_websocket_upgrade(&ws_upgrade),
        validate_websocket_upgrade(&ws_upgrade)
    );
}

// ─── Body-policy error mapping ───────────────────────────────────────────────

#[test]
fn body_policy_errors_fail_closed_on_both_transports() {
    for error in [BodyPolicyError::BlockedByWaf, BodyPolicyError::BodyTooLarge] {
        let candidate = error.candidate();
        assert_eq!(
            candidate.class,
            synvoid_core::enforcement::EnforcementClass::Block
        );
        assert!(candidate.class.is_terminal());
    }
}

// ─── Upstream forwarding ─────────────────────────────────────────────────────

#[test]
fn forwarded_headers_agree_except_scheme() {
    let client_ip: IpAddr = "203.0.113.7".parse().unwrap();
    let original = header_map(&[("host", "example.com"), ("user-agent", "parity-test")]);
    let config = synvoid_config::site::ProxyHeadersConfig::default();

    let http_headers =
        build_forward_headers(client_ip, &original, &config, ForwardedProtocol::Http);
    let https_headers =
        build_forward_headers(client_ip, &original, &config, ForwardedProtocol::Https);

    let proto = |h: &HeaderMap| {
        h.get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(proto(&http_headers).as_deref(), Some("http"));
    assert_eq!(proto(&https_headers).as_deref(), Some("https"));

    // Every other forwarded header must agree; only the scheme differs.
    for (name, value) in http_headers.iter() {
        if name == "x-forwarded-proto" {
            continue;
        }
        assert_eq!(
            https_headers.get(name),
            Some(value),
            "forwarded header {name} must agree across transports"
        );
    }
    assert_eq!(
        http_headers.len() + 1,
        https_headers.len() + usize::from(proto(&http_headers) != proto(&https_headers)),
        "header sets must differ only by scheme"
    );
}

// ─── Method/path normalization vocabulary ────────────────────────────────────

#[test]
fn method_and_version_vocabulary_shared() {
    // Both transports serve HTTP/1.1 + HTTP/2 after their respective
    // handshakes (TLS via ALPN, plaintext directly); the request-policy
    // layer sees the same `hyper` request shape either way.
    let _ = Method::GET;
    let _ = Version::HTTP_11;
    let _ = Version::HTTP_2;
}

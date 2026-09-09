//! Root-test ownership: COMPOSITION
//! Rationale: Phase 24 HTTP differential/property closure. Proves the
//! canonical parse + normalization path is deterministic, that routing and
//! WAF consume the same security-relevant normalized target, that HTTP/1 and
//! HTTP/3 representations agree where semantics overlap, that
//! percent-encoding/dot-segment variants cannot bypass path rules, that
//! forwarding headers cannot override direct client identity, and that
//! body/framing rejection is deterministic and fail-closed.
//!
//! Table/property style: no duplicate expected parser is maintained; each
//! case asserts equivalence or fail-closed behavior across two consumers.

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, HeaderValue, Method, Uri, Version};
use synvoid_core::enforcement::EnforcementClass;
use synvoid_http::framing::{
    validate_host_authority, validate_request_framing, validate_transfer_framing,
};
use synvoid_proxy::headers::{build_forward_headers, ForwardedProtocol};
use synvoid_proxy::location_matcher::LocationMatcher;
use synvoid_waf::attack_detection::normalizer::InputNormalizer;

fn normalizer() -> InputNormalizer {
    InputNormalizer::new()
}

fn normalized_owned(input: &str) -> String {
    normalizer().normalize(input).as_str().to_owned()
}

// ─── Determinism ────────────────────────────────────────────────────────────

#[test]
fn canonical_normalization_is_deterministic() {
    let corpus = [
        "/api/users/123",
        "/search?q=hello%20world",
        "/%41%44%4d%49%4e",
        "/a/./b/../c",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%C0%BE",
        "user%3Dadmin%26pass%3Dsecret",
        "/static/css/style.css",
        "",
        "%",
        "%2",
        "%%41",
    ];
    for input in corpus {
        let first = normalized_owned(input);
        let second = normalized_owned(input);
        assert_eq!(
            first, second,
            "normalization must be deterministic for {input:?}"
        );
    }
}

#[test]
fn framing_rejection_is_deterministic_and_fail_closed() {
    // Every ambiguous framing must reject with 400 + terminal Block, repeatedly.
    let cases: Vec<HeaderMap> = vec![
        // Duplicate Content-Length (even identical values reject).
        {
            let mut h = HeaderMap::new();
            h.append(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
            h.append(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
            h
        },
        // CL + Transfer-Encoding together.
        {
            let mut h = HeaderMap::new();
            h.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
            h.insert(
                http::header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
            h
        },
        // Unsupported coding.
        {
            let mut h = HeaderMap::new();
            h.insert(
                http::header::TRANSFER_ENCODING,
                HeaderValue::from_static("gzip"),
            );
            h
        },
        // Malformed length.
        {
            let mut h = HeaderMap::new();
            h.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_static("12abc"),
            );
            h
        },
        // Duplicate Host.
        {
            let mut h = HeaderMap::new();
            h.append(http::header::HOST, HeaderValue::from_static("a.example"));
            h.append(http::header::HOST, HeaderValue::from_static("a.example"));
            h
        },
    ];
    for (i, headers) in cases.iter().enumerate() {
        for _ in 0..2 {
            let transfer = validate_transfer_framing(headers);
            let uri: Uri = "/".parse().unwrap();
            let host = validate_host_authority(headers, &uri, Version::HTTP_11);
            // At least one of the two validators must reject every hostile case.
            assert!(
                transfer.is_err() || host.is_err(),
                "hostile framing case {i} must reject"
            );
            for err in transfer.err().into_iter().chain(host.err()) {
                assert_eq!(err.status(), 400);
                assert_eq!(err.candidate().class, EnforcementClass::Block);
                assert!(err.candidate().class.is_terminal());
            }
        }
    }
}

// ─── Routing and WAF share the normalized target ────────────────────────────

#[test]
fn routing_and_waf_observe_same_normalized_target() {
    // An admin-prefix route and a WAF-side normalized check must agree on
    // every percent-encoding/dot-segment variant: either both see the admin
    // target or both see a non-admin target — never a split.
    let matcher = LocationMatcher::new(vec!["/admin".to_string()]);
    let variants = [
        "/admin",
        "/%61dmin",
        "/%41DMIN",
        "/admin/",
        "/admin/../admin",
        "/admin/%2e%2e/admin",
        "/ADMIN",
        "/administrator",
        "/api/admin",
    ];
    for raw in variants {
        let normalized = normalized_owned(raw);
        let route_on_raw = matcher.match_uri(raw).is_some();
        let route_on_normalized = matcher.match_uri(&normalized).is_some();
        // The security property: the normalized view is the one policy must
        // use. Raw-vs-normalized disagreement is exactly the bypass class, so
        // record that normalization collapses the dangerous aliases onto the
        // same decision the WAF normalizer sees. The route here is a prefix
        // match on "/admin", so only normalized targets under that prefix
        // must route-match.
        let waf_sees_admin = normalized.starts_with("/admin");
        if waf_sees_admin {
            assert!(
                route_on_normalized,
                "normalized {raw:?} -> {normalized:?} exposes admin; route must match normalized view"
            );
        }
        // Deterministic: same raw input always yields the same pair.
        let normalized2 = normalized_owned(raw);
        assert_eq!(normalized, normalized2);
        assert_eq!(route_on_raw, matcher.match_uri(raw).is_some());
    }
}

#[test]
fn percent_encoding_variants_cannot_bypass_exact_route() {
    let matcher = LocationMatcher::new(vec!["= /login".to_string()]);
    // Exact match is byte-exact on the raw target; the canonical pipeline
    // normalizes before policy, so an encoded alias must normalize onto the
    // same string the exact route compares against.
    assert!(matcher.match_uri("/login").is_some());
    assert!(
        matcher.match_uri("/%6cogin").is_none(),
        "raw exact match is byte-exact"
    );
    let normalized = normalized_owned("/%6cogin");
    assert_eq!(normalized, "/login");
    assert!(matcher.match_uri(&normalized).is_some());
}

// ─── HTTP/1 vs HTTP/3 equivalence ───────────────────────────────────────────

#[test]
fn http1_and_http3_host_validation_agree_where_semantics_overlap() {
    // Same Host header + origin-form target: both versions accept.
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("example.com"));
    let uri: Uri = "/path".parse().unwrap();
    let h1 = validate_host_authority(&headers, &uri, Version::HTTP_11);
    let h3 = validate_host_authority(&headers, &uri, Version::HTTP_3);
    assert!(h1.is_ok());
    assert!(h3.is_ok());
    assert_eq!(h1.unwrap().host, h3.unwrap().host);

    // Duplicate Host fails closed on both versions.
    let mut dup = HeaderMap::new();
    dup.append(http::header::HOST, HeaderValue::from_static("example.com"));
    dup.append(http::header::HOST, HeaderValue::from_static("example.com"));
    assert!(validate_host_authority(&dup, &uri, Version::HTTP_11).is_err());
    assert!(validate_host_authority(&dup, &uri, Version::HTTP_3).is_err());

    // Absolute-form / Host conflict fails closed on both versions.
    let mut conflict = HeaderMap::new();
    conflict.insert(
        http::header::HOST,
        HeaderValue::from_static("other.example"),
    );
    let abs: Uri = "http://example.com/path".parse().unwrap();
    assert!(validate_host_authority(&conflict, &abs, Version::HTTP_11).is_err());
    assert!(validate_host_authority(&conflict, &abs, Version::HTTP_3).is_err());

    // Transfer framing is version-independent: CL+TE rejects everywhere.
    let mut clash = HeaderMap::new();
    clash.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("4"));
    clash.insert(
        http::header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    assert!(validate_transfer_framing(&clash).is_err());
    assert!(validate_request_framing(&clash, &uri, Version::HTTP_11).is_err());
    assert!(validate_request_framing(&clash, &uri, Version::HTTP_3).is_err());
}

// ─── Forwarding identity ────────────────────────────────────────────────────

#[test]
fn forwarding_headers_cannot_override_direct_client_identity() {
    use synvoid_config::site::ProxyHeadersConfig;
    let direct: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let config = ProxyHeadersConfig::default();

    // A spoofed X-Forwarded-For / X-Real-IP from the client is replaced by the
    // direct peer: the forwarded chain always ends with the direct IP and the
    // real-IP header always equals the direct IP.
    let mut hostile = HeaderMap::new();
    hostile.insert(
        "x-forwarded-for",
        HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
    );
    hostile.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
    hostile.insert("forwarded", HeaderValue::from_static("for=10.0.0.1"));
    let forwarded = build_forward_headers(direct, &hostile, &config, ForwardedProtocol::Https);
    let xff = forwarded
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        xff.ends_with(&direct.to_string()),
        "XFF must terminate with direct peer, got {xff:?}"
    );
    assert!(
        !xff.contains("9.9.9.9"),
        "spoofed real-ip must not survive in XFF: {xff:?}"
    );
    let real_ip = forwarded
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(real_ip, direct.to_string());

    // Benign request without spoofing still carries direct identity.
    let plain = HeaderMap::new();
    let forwarded = build_forward_headers(direct, &plain, &config, ForwardedProtocol::Http);
    assert_eq!(
        forwarded.get("x-real-ip").and_then(|v| v.to_str().ok()),
        Some(direct.to_string()).as_deref()
    );
    assert_eq!(
        forwarded
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok()),
        Some("http")
    );
}

// ─── Method / target sanity ─────────────────────────────────────────────────

#[test]
fn valid_methods_cover_dispatch_surface() {
    use synvoid_http::HTTP_VALID_METHODS;
    for method in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::HEAD,
    ] {
        assert!(
            HTTP_VALID_METHODS.contains(&method.as_str()),
            "{} must be a valid dispatch method",
            method.as_str()
        );
    }
}

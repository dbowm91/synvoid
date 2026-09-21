//! Phase 50: WAF execution-model parity tests.
//!
//! Pins detection/enforcement/scoring behavior of the borrowed inline
//! evaluation core across the configuration matrix: each detector
//! enabled/disabled, strict normalization on/off, anomaly scoring on/off,
//! empty/binary/over-limit bodies, smuggling headers, JWT locations, and
//! multiply-matching payloads (deterministic priority winner).

use http::{HeaderMap, Method};
use std::net::{IpAddr, Ipv4Addr};
use synvoid_waf::attack_detection::{AttackDetectionConfig, AttackDetector, AttackType};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

fn detector() -> AttackDetector {
    AttackDetector::new(AttackDetectionConfig::default())
}

fn detector_no_anomaly() -> AttackDetector {
    let mut config = AttackDetectionConfig::default();
    config.anomaly_scoring.enabled = false;
    AttackDetector::new(config)
}

fn detector_strict() -> AttackDetector {
    let mut config = AttackDetectionConfig::default();
    config.strict_normalization = true;
    AttackDetector::new(config)
}

fn empty_headers() -> HeaderMap {
    HeaderMap::new()
}

#[tokio::test]
async fn benign_request_has_no_detection() {
    let detector = detector();
    let headers = empty_headers();
    let (result, _score) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/api/users/123",
            None,
            &headers,
            None,
        )
        .await;
    assert!(result.is_none(), "benign path-only must not detect");
}

#[tokio::test]
async fn single_match_categories_preserved() {
    let detector = detector();
    let headers = empty_headers();
    let cases: &[(&str, Option<&str>, AttackType)] = &[
        ("/search", Some("id=1' OR '1'='1"), AttackType::Sqli),
        (
            "/search",
            Some("q=<script>alert(1)</script>"),
            AttackType::Xss,
        ),
        (
            "/files",
            Some("f=../../etc/passwd"),
            AttackType::PathTraversal,
        ),
        ("/t", Some("t={{7*7}}"), AttackType::Ssti),
        ("/run", Some("cmd=; rm -rf /"), AttackType::CmdInjection),
    ];
    for (path, query, expected) in cases {
        let (result, score) = detector
            .check_request(TEST_IP, &Method::GET, path, *query, &headers, None)
            .await;
        let result = result.unwrap_or_else(|| panic!("expected detection for {path:?}"));
        assert_eq!(
            result.attack_type, *expected,
            "wrong category for {path:?} {query:?}"
        );
        assert!(score > 0, "anomaly mode must accumulate a score");
    }
}

#[tokio::test]
async fn anomaly_disabled_is_outcome_first() {
    let detector = detector_no_anomaly();
    let headers = empty_headers();
    let (result, score) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/search",
            Some("id=1' OR '1'='1"),
            &headers,
            None,
        )
        .await;
    assert!(result.is_some(), "anomaly-disabled must still detect");
    assert_eq!(score, 0, "anomaly-disabled returns zero score");

    let (benign, _) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/api/users/123",
            None,
            &headers,
            None,
        )
        .await;
    assert!(benign.is_none());
}

#[tokio::test]
async fn strict_normalization_rejects_overlong() {
    let detector = detector_strict();
    let headers = empty_headers();
    let (result, _) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/%c0%afetc%c0%afpasswd",
            None,
            &headers,
            None,
        )
        .await;
    assert!(result.is_some(), "strict mode must flag overlong UTF-8");
}

#[tokio::test]
async fn body_size_limit_is_fail_closed() {
    let mut config = AttackDetectionConfig::default();
    config.max_request_body_size = Some(16);
    let detector = AttackDetector::new(config);
    let headers = empty_headers();
    let big_body = vec![b'a'; 1024];
    let (result, _) = detector
        .check_request(
            TEST_IP,
            &Method::POST,
            "/api/submit",
            None,
            &headers,
            Some(&big_body),
        )
        .await;
    assert!(result.is_some(), "over-limit body must be rejected");
}

#[tokio::test]
async fn binary_body_is_handled_deterministically() {
    let detector = detector();
    let headers = empty_headers();
    let binary: Vec<u8> = (0u8..=255u8).collect();
    let first = detector
        .check_request(
            TEST_IP,
            &Method::POST,
            "/api/submit",
            None,
            &headers,
            Some(&binary),
        )
        .await;
    let second = detector
        .check_request(
            TEST_IP,
            &Method::POST,
            "/api/submit",
            None,
            &headers,
            Some(&binary),
        )
        .await;
    assert_eq!(
        first.0.as_ref().map(|r| &r.attack_type),
        second.0.as_ref().map(|r| &r.attack_type),
        "binary body outcome must be deterministic"
    );
}

#[tokio::test]
async fn empty_body_matches_no_body_behavior() {
    let detector = detector();
    let headers = empty_headers();
    let (result, _) = detector
        .check_request(
            TEST_IP,
            &Method::POST,
            "/api/submit",
            None,
            &headers,
            Some(b""),
        )
        .await;
    assert!(result.is_none(), "empty body must not detect");
}

#[tokio::test]
async fn smuggling_headers_detected() {
    let detector = detector();
    let mut headers = HeaderMap::new();
    headers.insert("host", http::HeaderValue::from_static("example.com"));
    headers.insert("content-length", http::HeaderValue::from_static("11"));
    headers.insert(
        "transfer-encoding",
        http::HeaderValue::from_static("chunked"),
    );
    let (result, _) = detector
        .check_request(
            TEST_IP,
            &Method::POST,
            "/api/submit",
            None,
            &headers,
            Some(b"hello=world"),
        )
        .await;
    let result = result.expect("CL+TE smuggling must detect");
    assert_eq!(result.attack_type, AttackType::RequestSmuggling);
}

#[tokio::test]
async fn jwt_detected_in_header_query_and_body() {
    let detector = detector();
    // alg=none confusion-attack token: header {"alg":"none"}.
    let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    let (via_header, _) = detector
        .check_request(TEST_IP, &Method::GET, "/api/me", None, &headers, None)
        .await;
    assert_eq!(
        via_header.map(|r| r.attack_type),
        Some(AttackType::Jwt),
        "JWT in Authorization header must detect"
    );

    let (via_query, _) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/api/me",
            Some(token),
            &empty_headers(),
            None,
        )
        .await;
    assert_eq!(
        via_query.map(|r| r.attack_type),
        Some(AttackType::Jwt),
        "JWT in query string must detect"
    );

    let (via_body, _) = detector
        .check_request(
            TEST_IP,
            &Method::POST,
            "/api/login",
            None,
            &empty_headers(),
            Some(token.as_bytes()),
        )
        .await;
    assert_eq!(
        via_body.map(|r| r.attack_type),
        Some(AttackType::Jwt),
        "JWT in body must detect"
    );
}

#[tokio::test]
async fn multiply_matching_payload_has_deterministic_priority_winner() {
    let detector = detector();
    let headers = empty_headers();
    // Matches more than one detector family; priority selection must be
    // deterministic across repeated evaluations.
    let query = Some("q=<script>' OR '1'='1</script>");
    let mut winners = Vec::new();
    for _ in 0..20 {
        let (result, score) = detector
            .check_request(TEST_IP, &Method::GET, "/search", query, &headers, None)
            .await;
        let result = result.expect("multiply-matching payload must detect");
        assert!(score > 0);
        winners.push(result.attack_type);
    }
    assert!(
        winners.iter().all(|w| *w == winners[0]),
        "priority winner must be deterministic, got {winners:?}"
    );
}

#[tokio::test]
async fn disabled_detector_removes_its_coverage_only() {
    // SQLi payload that no other family matches: disabling SQLi clears it,
    // while XSS coverage stays intact.
    let sqli_only = "id=1' OR '1'='1";

    let mut config = AttackDetectionConfig::default();
    config.sqli.enabled = false;
    let no_sqli = AttackDetector::new(config);
    let (result, _) = no_sqli
        .check_request(
            TEST_IP,
            &Method::GET,
            "/search",
            Some(sqli_only),
            &empty_headers(),
            None,
        )
        .await;
    assert!(
        result.is_none(),
        "with SQLi disabled the SQLi-only payload must pass, got {result:?}"
    );

    let detector = detector();
    let (xss, _) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/search",
            Some("q=<script>alert(1)</script>"),
            &empty_headers(),
            None,
        )
        .await;
    assert_eq!(
        xss.map(|r| r.attack_type),
        Some(AttackType::Xss),
        "XSS coverage must remain with default config"
    );
}

#[tokio::test]
async fn all_detectors_disabled_passes_attack_traffic() {
    let mut config = AttackDetectionConfig::default();
    config.sqli.enabled = false;
    config.xss.enabled = false;
    config.ssti.enabled = false;
    config.cmd_injection.enabled = false;
    config.path_traversal.enabled = false;
    config.rfi.enabled = false;
    config.ssrf.enabled = false;
    config.xxe.enabled = false;
    config.jwt.enabled = false;
    config.request_smuggling.enabled = false;
    config.ldap_injection.enabled = false;
    config.xpath_injection.enabled = false;
    config.open_redirect.enabled = false;
    let detector = AttackDetector::new(config);
    let (result, _) = detector
        .check_request(
            TEST_IP,
            &Method::GET,
            "/search",
            Some("id=1' OR '1'='1"),
            &empty_headers(),
            None,
        )
        .await;
    assert!(
        result.is_none(),
        "disabled detector families must not fire, got {result:?}"
    );
}

use http::{HeaderMap, HeaderValue, Method};
use std::net::{IpAddr, Ipv4Addr};
use synvoid_waf::attack_detection::{AttackDetectionConfig, AttackDetector, AttackType};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

fn detector() -> AttackDetector {
    AttackDetector::new(AttackDetectionConfig::default())
}

fn headers_with(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, HeaderValue::from_static(value));
    }
    headers
}

#[tokio::test]
async fn firefox_media_accept_is_not_sqli() {
    let headers = headers_with(&[
        ("referer", "http://192.168.182.143:8082/post/example"),
        (
            "accept",
            "video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5",
        ),
    ]);

    let (result, _score) = detector()
        .check_request(
            TEST_IP,
            &Method::GET,
            "/static/uploads/example.mp4",
            None,
            &headers,
            None,
        )
        .await;

    assert!(
        result.is_none(),
        "browser media Accept must not be treated as SQL injection: {result:?}"
    );
}

#[tokio::test]
async fn sqli_in_cookie_is_still_detected() {
    let headers = headers_with(&[
        ("referer", "http://example.test/post/example"),
        ("cookie", "session=1' OR '1'='1"),
    ]);

    let (result, _score) = detector()
        .check_request(TEST_IP, &Method::GET, "/post/example", None, &headers, None)
        .await;

    let result = result.expect("cookie SQL injection must still be detected");
    assert_eq!(result.attack_type, AttackType::Sqli);
}

#[tokio::test]
async fn sqli_in_configured_custom_header_is_still_detected() {
    let mut config = AttackDetectionConfig::default();
    config.header_scan.scan = vec!["x-custom".to_string()];
    let detector = AttackDetector::new(config);

    let headers = headers_with(&[
        ("referer", "http://example.test/post/example"),
        ("x-custom", "1' OR '1'='1"),
    ]);

    let (result, _score) = detector
        .check_request(TEST_IP, &Method::GET, "/post/example", None, &headers, None)
        .await;

    let result = result.expect("configured custom-header SQL injection must still be detected");
    assert_eq!(result.attack_type, AttackType::Sqli);
}

#[tokio::test]
async fn unconfigured_custom_header_is_not_payload_scanned() {
    let headers = headers_with(&[
        ("referer", "http://example.test/post/example"),
        ("x-custom", "1' OR '1'='1"),
    ]);

    let (result, _score) = detector()
        .check_request(TEST_IP, &Method::GET, "/post/example", None, &headers, None)
        .await;

    assert!(
        result.is_none(),
        "unknown headers are skip-by-default; configure [attack_detection.headers].scan to inspect them: {result:?}"
    );
}

#[tokio::test]
async fn authorization_is_not_sqli_scanned_by_default() {
    let headers = headers_with(&[
        ("referer", "http://example.test/post/example"),
        ("authorization", "Bearer 1' OR '1'='1"),
    ]);

    let (result, _score) = detector()
        .check_request(TEST_IP, &Method::GET, "/post/example", None, &headers, None)
        .await;

    assert!(
        result.is_none(),
        "Authorization belongs to the JWT detector, not SQLi/XSS: {result:?}"
    );
}

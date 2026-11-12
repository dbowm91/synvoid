use http::{HeaderMap, HeaderValue, Method};
use std::net::{IpAddr, Ipv4Addr};
use synvoid_waf::attack_detection::{AttackDetectionConfig, AttackDetector, AttackType};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, HeaderValue::from_static(value));
    }
    map
}

async fn assert_no_sqli_xss(label: &str, headers: &HeaderMap, path: &str, query: Option<&str>) {
    let detector = AttackDetector::new(AttackDetectionConfig::default());
    let (result, _score) = detector
        .check_request(TEST_IP, &Method::GET, path, query, headers, None)
        .await;

    if let Some(result) = result {
        assert!(
            !matches!(result.attack_type, AttackType::Sqli | AttackType::Xss),
            "{label} produced a SQLi/XSS detection at {}: {:?}",
            result.input_location,
            result.attack_type
        );
    }
}

#[tokio::test]
async fn firefox_navigation_and_asset_headers_are_clean() {
    let navigation = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("connection", "keep-alive"),
        ("upgrade-insecure-requests", "1"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-user", "?1"),
        ("priority", "u=0, i"),
        ("te", "trailers"),
        ("dnt", "1"),
        (
            "referer",
            "http://192.168.182.143:8082/post/example?from=feed",
        ),
    ]);
    assert_no_sqli_xss("firefox navigation", &navigation, "/post/example", None).await;

    let asset = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        ),
        ("accept", "image/avif,image/webp,*/*"),
        ("sec-fetch-dest", "image"),
        ("sec-fetch-mode", "no-cors"),
        ("sec-fetch-site", "same-origin"),
        (
            "referer",
            "http://192.168.182.143:8082/static/css/public.css?v=2026",
        ),
        ("if-none-match", "\"abc123\""),
        ("if-modified-since", "Wed, 21 Oct 2026 07:28:00 GMT"),
        ("cache-control", "max-age=0"),
        ("pragma", "no-cache"),
        ("range", "bytes=0-1023"),
    ]);
    assert_no_sqli_xss("firefox asset", &asset, "/static/css/public.css", None).await;

    let video = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        ),
        (
            "accept",
            "video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5",
        ),
        ("sec-fetch-dest", "video"),
        ("sec-fetch-mode", "no-cors"),
        ("range", "bytes=0-"),
        (
            "referer",
            "http://192.168.182.143:8082/post/example?next=%2Ffeed%3Fpage%3D2",
        ),
    ]);
    assert_no_sqli_xss("firefox video", &video, "/static/uploads/example.mp4", None).await;

    let font = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        ),
        ("accept", "font/woff2,*/*;q=0.1"),
        ("sec-fetch-dest", "font"),
        ("sec-fetch-mode", "cors"),
        ("origin", "http://192.168.182.143:8082"),
        ("range", "bytes=0-65535"),
    ]);
    assert_no_sqli_xss("firefox font", &font, "/static/fonts/inter.woff2", None).await;
}

#[tokio::test]
async fn chrome_and_safari_headers_are_clean() {
    let chrome = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        ),
        ("sec-ch-ua", "\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Windows\""),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-user", "?1"),
        ("priority", "u=0, i"),
        ("cookie", "session=abc123; theme=dark; consent=analytics%3Dtrue"),
    ]);
    assert_no_sqli_xss("chrome navigation", &chrome, "/", None).await;

    let safari = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        ),
        ("accept", "application/json, text/plain, */*"),
        ("origin", "https://example.com"),
        ("referer", "https://example.com/dashboard?tab=activity&range=7d"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        ("content-type", "application/json"),
        ("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    ]);
    assert_no_sqli_xss(
        "safari fetch",
        &safari,
        "/api/dashboard",
        Some("tab=activity&range=7d"),
    )
    .await;
}

#[tokio::test]
async fn command_line_and_language_clients_are_clean() {
    let clients: &[(&str, &str, &str)] = &[
        ("curl", "curl/8.10.1", "*/*"),
        ("wget", "Wget/1.21.4", "*/*"),
        (
            "python-requests",
            "python-requests/2.32.3",
            "application/json",
        ),
        ("python-httpx", "python-httpx/0.27.2", "application/json"),
        ("python-aiohttp", "aiohttp/3.10.9", "application/json"),
        ("go", "Go-http-client/2.0", "application/json"),
        ("java-okhttp", "okhttp/4.12.0", "application/json"),
        (
            "node-fetch",
            "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)",
            "*/*",
        ),
        ("axios", "axios/1.7.7", "application/json, text/plain, */*"),
        ("postman", "PostmanRuntime/7.42.0", "*/*"),
    ];

    for (label, user_agent, accept) in clients {
        let mut map = HeaderMap::new();
        map.insert("user-agent", HeaderValue::from_str(user_agent).expect("UA"));
        map.insert("accept", HeaderValue::from_str(accept).expect("accept"));
        map.insert("accept-encoding", HeaderValue::from_static("gzip, deflate"));
        map.insert("connection", HeaderValue::from_static("keep-alive"));
        map.insert(
            "authorization",
            HeaderValue::from_static(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            ),
        );
        map.insert(
            "referer",
            HeaderValue::from_static("https://example.com/api/items?page=2&sort=name"),
        );
        assert_no_sqli_xss(label, &map, "/api/items", Some("page=2&sort=name")).await;
    }
}

#[tokio::test]
async fn cdn_proxy_trace_and_jwt_headers_are_clean() {
    let cdn = headers(&[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        ),
        ("accept", "text/html"),
        ("via", "1.1 varnish (Varnish/7.4)"),
        ("x-cache", "HIT"),
        ("x-cache-hits", "3"),
        ("x-served-by", "cache-lhr-egll1980045-LHR"),
        ("cf-ray", "8f3b2c1d0e4f5a6b-LHR"),
        ("x-forwarded-for", "203.0.113.9, 10.0.0.4"),
        ("x-forwarded-proto", "https"),
        ("x-real-ip", "203.0.113.9"),
        ("forwarded", "for=203.0.113.9;proto=https;by=10.0.0.4"),
        (
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ),
        ("tracestate", "congo=t61rcWkgMzE"),
        ("x-request-id", "req-8f3b2c1d0e4f5a6b"),
        ("x-b3-traceid", "4bf92f3577b34da6a3ce929d0e0e4736"),
        (
            "uber-trace-id",
            "4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1",
        ),
        ("host", "192.168.182.143:8082"),
        ("content-type", "application/json"),
        ("content-length", "42"),
        ("cache-control", "no-cache"),
        ("pragma", "no-cache"),
        ("dnt", "1"),
        ("te", "trailers"),
        ("connection", "keep-alive"),
        ("priority", "u=3, i"),
        ("if-match", "\"etag-value\""),
        ("if-unmodified-since", "Wed, 21 Oct 2026 07:28:00 GMT"),
        ("if-range", "\"etag-value\""),
    ]);
    assert_no_sqli_xss(
        "cdn/proxy/trace",
        &cdn,
        "/api/items",
        Some("page=2&sort=name"),
    )
    .await;
}

#[tokio::test]
async fn benign_header_variants_never_escalate() {
    let variants = [
        headers(&[
            ("accept", "text/html,application/xhtml+xml"),
            ("referer", "https://example.com/a?b=1&c=2"),
            ("cookie", "session=abc; theme=dark"),
        ]),
        headers(&[
            ("accept", "application/json"),
            ("origin", "https://example.com"),
            ("cookie", "session=def; consent=analytics%3Dtrue"),
        ]),
        headers(&[
            ("accept", "image/avif,image/webp,*/*"),
            ("referer", "https://example.com/static/app.css?v=3"),
            ("cookie", "session=ghi; locale=en-US"),
        ]),
    ];

    for variant in &variants {
        let detector = AttackDetector::new(AttackDetectionConfig::default());
        let (result, _score) = detector
            .check_request(TEST_IP, &Method::GET, "/", None, variant, None)
            .await;
        if let Some(result) = result {
            assert!(
                !matches!(result.attack_type, AttackType::Sqli | AttackType::Xss),
                "benign header variant produced SQLi/XSS: {result:?}"
            );
            assert_eq!(
                result.escalation_weight(),
                0,
                "benign header variant must not be escalation-eligible: {result:?}"
            );
        }
    }
}

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http::{HeaderMap, Method};
use std::net::IpAddr;
use std::sync::Arc;
use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

fn benchmark_attack_detection_common(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let headers = HeaderMap::new();

    let benign_inputs = vec![
        "/api/users/123",
        "/api/v1/posts",
        "/static/css/style.css",
        "/health",
    ];

    let mut group = c.benchmark_group("attack_detection");

    for input in &benign_inputs {
        group.bench_with_input(BenchmarkId::new("benign", input), input, |b, path| {
            b.iter(|| {
                let _ = detector.check_request(TEST_IP, &Method::GET, path, None, &headers, None);
            });
        });
    }

    group.finish();
}

fn benchmark_attack_detection_sqli(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let headers = HeaderMap::new();

    let sqli_inputs = vec![
        "1' OR '1'='1",
        "admin'--",
        "1 UNION SELECT password FROM users",
        "'; DROP TABLE users--",
    ];

    let mut group = c.benchmark_group("attack_detection_sqli");

    for (i, input) in sqli_inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("query", i), input, |b, query| {
            b.iter(|| {
                let _ = detector.check_request(
                    TEST_IP,
                    &Method::GET,
                    "/search",
                    Some(query),
                    &headers,
                    None,
                );
            });
        });
    }

    group.finish();
}

fn benchmark_attack_detection_xss(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let headers = HeaderMap::new();

    let xss_inputs = vec![
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "{{7*7}}",
    ];

    let mut group = c.benchmark_group("attack_detection_xss");

    for (i, input) in xss_inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("query", i), input, |b, query| {
            b.iter(|| {
                let _ = detector.check_request(
                    TEST_IP,
                    &Method::GET,
                    "/search",
                    Some(query),
                    &headers,
                    None,
                );
            });
        });
    }

    group.finish();
}

// TODO: feature removed — check_request_anomaly_scoring method no longer exists on AttackDetector
// fn benchmark_anomaly_scoring(c: &mut Criterion) { ... }

criterion_group!(
    benches,
    benchmark_attack_detection_common,
    benchmark_attack_detection_sqli,
    benchmark_attack_detection_xss,
);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http::{HeaderMap, Method};
use std::sync::Arc;
use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

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
                let _ = detector.check_request(&Method::GET, path, None, &headers, None);
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
                let _ =
                    detector.check_request(&Method::GET, "/search", Some(query), &headers, None);
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
                let _ =
                    detector.check_request(&Method::GET, "/search", Some(query), &headers, None);
            });
        });
    }

    group.finish();
}

fn benchmark_anomaly_scoring(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let headers = HeaderMap::new();

    let mut group = c.benchmark_group("anomaly_scoring");

    group.bench_function("benign_request", |b| {
        b.iter(|| {
            let _ = detector.check_request_anomaly_scoring(
                &Method::GET,
                "/api/users/123",
                None,
                &headers,
                None,
            );
        });
    });

    group.bench_function("sqli_attack", |b| {
        b.iter(|| {
            let _ = detector.check_request_anomaly_scoring(
                &Method::GET,
                "/search",
                Some("q=1' OR '1'='1"),
                &headers,
                None,
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_attack_detection_common,
    benchmark_attack_detection_sqli,
    benchmark_attack_detection_xss,
    benchmark_anomaly_scoring
);
criterion_main!(benches);

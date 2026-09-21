//! Phase 49: wave-10 attack-detection benchmark truth.
//!
//! The detector under test may spawn Tokio tasks, so every async case runs
//! under a real multi-thread Tokio runtime constructed ONCE outside the timed
//! loop. `futures::executor::block_on` cannot reproduce Tokio scheduling and
//! is not used here.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http::{HeaderMap, Method};
use std::net::IpAddr;
use std::sync::Arc;
use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

/// Shared Tokio runtime built once per benchmark case, outside the timed loop.
fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("bench-wave10")
        .enable_all()
        .build()
        .expect("bench Tokio runtime")
}

fn detector_with(anomaly: bool, strict: bool) -> Arc<AttackDetector> {
    let mut anomaly_scoring = AttackDetectionConfig::default().anomaly_scoring;
    anomaly_scoring.enabled = anomaly;
    let config = AttackDetectionConfig {
        anomaly_scoring,
        strict_normalization: strict,
        ..AttackDetectionConfig::default()
    };
    Arc::new(AttackDetector::new(config))
}

fn benchmark_attack_detection_common(c: &mut Criterion) {
    let detector = detector_with(true, false);
    let rt = bench_runtime();
    let headers = HeaderMap::new();

    let benign_inputs = [
        "/api/users/123",
        "/api/v1/posts",
        "/static/css/style.css",
        "/health",
    ];

    let mut group = c.benchmark_group("attack_detection");

    for input in &benign_inputs {
        group.bench_with_input(BenchmarkId::new("benign", input), input, |b, path| {
            b.iter(|| {
                rt.block_on(detector.check_request(
                    TEST_IP,
                    &Method::GET,
                    path,
                    None,
                    &headers,
                    None,
                ));
            });
        });
    }

    group.finish();
}

fn benchmark_attack_detection_sqli(c: &mut Criterion) {
    let detector = detector_with(true, false);
    let rt = bench_runtime();
    let headers = HeaderMap::new();

    let sqli_inputs = [
        "1' OR '1'='1",
        "admin'--",
        "1 UNION SELECT password FROM users",
        "'; DROP TABLE users--",
    ];

    let mut group = c.benchmark_group("attack_detection_sqli");

    for (i, input) in sqli_inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("query", i), input, |b, query| {
            b.iter(|| {
                rt.block_on(detector.check_request(
                    TEST_IP,
                    &Method::GET,
                    "/search",
                    Some(query),
                    &headers,
                    None,
                ));
            });
        });
    }

    group.finish();
}

fn benchmark_attack_detection_xss(c: &mut Criterion) {
    let detector = detector_with(true, false);
    let rt = bench_runtime();
    let headers = HeaderMap::new();

    let xss_inputs = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "{{7*7}}",
    ];

    let mut group = c.benchmark_group("attack_detection_xss");

    for (i, input) in xss_inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("query", i), input, |b, query| {
            b.iter(|| {
                rt.block_on(detector.check_request(
                    TEST_IP,
                    &Method::GET,
                    "/search",
                    Some(query),
                    &headers,
                    None,
                ));
            });
        });
    }

    group.finish();
}

/// Benign query/header matrix plus 1 KiB / 10 KiB POST bodies.
fn benchmark_benign_matrix(c: &mut Criterion) {
    let detector = detector_with(true, false);
    let rt = bench_runtime();

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("Mozilla/5.0"),
    );
    headers.insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("application/json"),
    );

    let body_1kib = "field=".to_string() + &"b".repeat(1018);
    let body_10kib = "field=".to_string() + &"b".repeat(10_234);

    let mut group = c.benchmark_group("attack_detection_benign_matrix");
    group.bench_function("query_headers", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/api/search",
                Some("q=hello+world&sort=desc&page=2"),
                &headers,
                None,
            ));
        });
    });
    group.bench_function("post_1kib_body", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::POST,
                "/api/submit",
                None,
                &headers,
                Some(body_1kib.as_bytes()),
            ));
        });
    });
    group.bench_function("post_10kib_body", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::POST,
                "/api/submit",
                None,
                &headers,
                Some(body_10kib.as_bytes()),
            ));
        });
    });
    group.finish();
}

/// Path traversal / request-smuggling / JWT representative inputs.
fn benchmark_other_attack_classes(c: &mut Criterion) {
    let detector = detector_with(true, false);
    let rt = bench_runtime();

    let mut jwt_headers = HeaderMap::new();
    jwt_headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"),
    );
    let mut smuggle_headers = HeaderMap::new();
    smuggle_headers.insert("host", http::HeaderValue::from_static("example.com"));
    smuggle_headers.insert("content-length", http::HeaderValue::from_static("11"));
    smuggle_headers.insert(
        "transfer-encoding",
        http::HeaderValue::from_static("chunked"),
    );
    let plain = HeaderMap::new();

    let mut group = c.benchmark_group("attack_detection_other_classes");
    group.bench_function("path_traversal", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/files/%2e%2e/%2e%2e/etc/passwd",
                None,
                &plain,
                None,
            ));
        });
    });
    group.bench_function("request_smuggling", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::POST,
                "/api/submit",
                None,
                &smuggle_headers,
                Some(b"hello=world" as &[u8]),
            ));
        });
    });
    group.bench_function("jwt_bearer", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/api/me",
                None,
                &jwt_headers,
                None,
            ));
        });
    });
    group.finish();
}

/// Early-terminal anomaly-disabled path.
fn benchmark_anomaly_disabled(c: &mut Criterion) {
    let detector = detector_with(false, false);
    let rt = bench_runtime();
    let headers = HeaderMap::new();

    let mut group = c.benchmark_group("attack_detection_anomaly_disabled");
    group.bench_function("benign", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/api/users/123",
                None,
                &headers,
                None,
            ));
        });
    });
    group.bench_function("sqli_first_hit", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/search",
                Some("1' OR '1'='1"),
                &headers,
                None,
            ));
        });
    });
    group.finish();
}

/// Strict-normalization path.
fn benchmark_strict(c: &mut Criterion) {
    let detector = detector_with(true, true);
    let rt = bench_runtime();
    let headers = HeaderMap::new();

    let mut group = c.benchmark_group("attack_detection_strict");
    group.bench_function("benign", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/api/users/123",
                None,
                &headers,
                None,
            ));
        });
    });
    group.bench_function("overlong", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                TEST_IP,
                &Method::GET,
                "/%c0%afetc%c0%afpasswd",
                None,
                &headers,
                None,
            ));
        });
    });
    group.finish();
}

/// Concurrent batch harness (1/8/32/128 in flight).
fn benchmark_concurrency(c: &mut Criterion) {
    let detector = detector_with(true, false);
    let rt = bench_runtime();

    let mut group = c.benchmark_group("attack_detection_concurrency");
    for batch in [1usize, 8, 32, 128] {
        group.bench_with_input(BenchmarkId::new("batch", batch), &batch, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let mut join_set = tokio::task::JoinSet::new();
                    for i in 0..n {
                        let detector = Arc::clone(&detector);
                        join_set.spawn(async move {
                            let headers = HeaderMap::new();
                            let (path, query) = if i % 4 == 0 {
                                ("/search", Some("id=1' OR '1'='1"))
                            } else {
                                ("/api/users/123", None)
                            };
                            detector
                                .check_request(TEST_IP, &Method::GET, path, query, &headers, None)
                                .await
                        });
                    }
                    while join_set.join_next().await.is_some() {}
                });
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_attack_detection_common,
    benchmark_attack_detection_sqli,
    benchmark_attack_detection_xss,
    benchmark_benign_matrix,
    benchmark_other_attack_classes,
    benchmark_anomaly_disabled,
    benchmark_strict,
    benchmark_concurrency,
);
criterion_main!(benches);

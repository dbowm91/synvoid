//! Phase 49: WAF normalization + request benchmark truth.
//!
//! Methodology corrections (performance campaign Phase 49):
//! - The Tokio runtime is constructed ONCE per benchmark case, outside the
//!   Criterion timed loop. Previously `Runtime::new()` ran inside `b.iter`,
//!   timing runtime construction/teardown as though it were detector latency.
//! - All async `AttackDetector::check_request` benches execute under a real
//!   multi-thread Tokio runtime, matching production scheduling (the detector
//!   spawns Tokio tasks). A futures single-thread executor is not used.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http::HeaderMap;
use std::sync::Arc;
use synvoid::waf::attack_detection::normalizer::InputNormalizer;
use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

/// Shared multi-thread Tokio runtime built once per benchmark case (outside
/// the timed loop) so setup cost never contaminates detector latency.
fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("bench-waf")
        .enable_all()
        .build()
        .expect("bench Tokio runtime")
}

fn benign_headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (k, v) in pairs {
        headers.insert(
            http::header::HeaderName::from_lowercase(k.as_bytes()).unwrap(),
            http::HeaderValue::from_str(v).unwrap(),
        );
    }
    headers
}

fn benchmark_normalize_benign(c: &mut Criterion) {
    let normalizer = InputNormalizer::new();

    let benign_inputs = vec![
        ("static_path", "/api/users/123"),
        ("static_query", "page=1&size=20"),
        ("normal_header", "Mozilla/5.0"),
        ("simple_body", "username=testuser"),
    ];

    let mut group = c.benchmark_group("normalize/benign");

    for (name, input) in benign_inputs {
        group.bench_with_input(BenchmarkId::new("normalize", name), &input, |b, i| {
            b.iter(|| {
                criterion::black_box(normalizer.normalize(i));
            });
        });
    }

    group.finish();
}

fn benchmark_normalize_encoded(c: &mut Criterion) {
    let normalizer = InputNormalizer::new();

    let encoded_inputs = vec![
        ("url_encoded_space", "hello%20world"),
        ("url_encoded_slash", "test%2Fpath"),
        ("url_encoded_unicode", "%3Cscript%3E"),
        ("html_entities", "&lt;script&gt;"),
        ("mixed_encoding", "user%3Dadmin%26pass%3D<PASSWORD>"),
    ];

    let mut group = c.benchmark_group("normalize/encoded");

    for (name, input) in encoded_inputs {
        group.bench_with_input(BenchmarkId::new("normalize", name), &input, |b, i| {
            b.iter(|| {
                criterion::black_box(normalizer.normalize(i));
            });
        });
    }

    group.finish();
}

fn benchmark_normalize_all_small(c: &mut Criterion) {
    let normalizer = Arc::new(InputNormalizer::new());
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let rt = bench_runtime();

    let path = "/api/users/123";
    let query = Some("page=1&size=20");
    let headers = benign_headers(&[
        ("host", "example.com"),
        ("user-agent", "Mozilla/5.0"),
        ("accept", "application/json"),
    ]);

    let mut group = c.benchmark_group("normalize/small_request");

    group.bench_function("normalize_all_path_only", |b| {
        b.iter(|| {
            let _ = normalizer.normalize(path);
        });
    });

    group.bench_function("check_request_benign", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                &http::Method::GET,
                path,
                query,
                &headers,
                None,
            ));
        });
    });

    group.bench_function("check_request_benign_query_headers", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                &http::Method::GET,
                "/api/search",
                Some("q=hello+world&sort=desc&page=2"),
                &headers,
                None,
            ));
        });
    });

    group.finish();
}

fn benchmark_normalize_all_with_body(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let rt = bench_runtime();

    let body_1kib = "data=".to_string() + &"a".repeat(1019);
    let headers = benign_headers(&[
        ("host", "example.com"),
        ("content-type", "application/x-www-form-urlencoded"),
    ]);

    let mut group = c.benchmark_group("normalize/with_body");

    group.bench_function("check_request_form_body", |b| {
        let body = "username=testuser&password=<PASSWORD>";
        b.iter(|| {
            rt.block_on(detector.check_request(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                &http::Method::POST,
                "/api/users",
                None,
                &headers,
                Some(body.as_bytes()),
            ));
        });
    });

    group.bench_function("check_request_1kib_body", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                &http::Method::POST,
                "/api/submit",
                None,
                &headers,
                Some(body_1kib.as_bytes()),
            ));
        });
    });

    group.finish();
}

fn benchmark_normalize_large_body(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));
    let rt = bench_runtime();

    let large_body = "data=".to_string() + &"x".repeat(10_000);
    let headers = benign_headers(&[("content-type", "application/x-www-form-urlencoded")]);

    let mut group = c.benchmark_group("normalize/large_body");

    group.bench_function("check_request_10kb_body", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                &http::Method::POST,
                "/api/submit",
                None,
                &headers,
                Some(large_body.as_bytes()),
            ));
        });
    });

    group.finish();
}

/// Representative suspicious inputs through the full default detector set
/// (anomaly scoring enabled, the default).
fn benchmark_suspicious_inputs(c: &mut Criterion) {
    let detector = Arc::new(AttackDetector::new(AttackDetectionConfig::default()));
    let rt = bench_runtime();
    let headers = HeaderMap::new();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    let cases: &[(&str, &str, Option<&str>)] = &[
        ("sqli", "/search", Some("id=1' OR '1'='1")),
        (
            "xss",
            "/search",
            Some("q=%3Cscript%3Ealert(1)%3C/script%3E"),
        ),
        ("path_traversal", "/files", Some("f=../../etc/passwd")),
        ("smuggling_headers", "/api/submit", Some("x=1")),
        ("jwt_header", "/api/me", None),
    ];

    let mut group = c.benchmark_group("normalize/suspicious");
    for (name, path, query) in cases {
        group.bench_with_input(
            BenchmarkId::new("check_request", name),
            &(*path, *query),
            |b, (p, q)| {
                b.iter(|| {
                    rt.block_on(detector.check_request(
                        ip,
                        &http::Method::GET,
                        p,
                        *q,
                        &headers,
                        None,
                    ));
                });
            },
        );
    }

    // JWT bearer token in Authorization header (exercises the JWT detector).
    let jwt_headers = benign_headers(&[(
        "authorization",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.AF6F9Owud8BGT9Rfpv8TzQv2Zv6J1Z6v6J1Z6v6J1Z6v",
    )]);
    group.bench_function("check_request_jwt_bearer", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                ip,
                &http::Method::GET,
                "/api/me",
                None,
                &jwt_headers,
                None,
            ));
        });
    });

    // Request-smuggling hostile header set.
    let smuggle_headers = benign_headers(&[
        ("host", "example.com"),
        ("content-length", "11"),
        ("transfer-encoding", "chunked"),
    ]);
    group.bench_function("check_request_smuggling_headers", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                ip,
                &http::Method::POST,
                "/api/submit",
                None,
                &smuggle_headers,
                Some(b"hello=world"),
            ));
        });
    });

    group.finish();
}

/// Anomaly-scoring-disabled early-terminal path (must stay short-circuiting).
fn benchmark_anomaly_disabled(c: &mut Criterion) {
    let mut anomaly_scoring = AttackDetectionConfig::default().anomaly_scoring;
    anomaly_scoring.enabled = false;
    let config = AttackDetectionConfig {
        anomaly_scoring,
        ..AttackDetectionConfig::default()
    };
    let detector = Arc::new(AttackDetector::new(config));
    let rt = bench_runtime();
    let headers = HeaderMap::new();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    let mut group = c.benchmark_group("normalize/anomaly_disabled");
    group.bench_function("check_request_benign", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                ip,
                &http::Method::GET,
                "/api/users/123",
                None,
                &headers,
                None,
            ));
        });
    });
    group.bench_function("check_request_sqli", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                ip,
                &http::Method::GET,
                "/search",
                Some("id=1' OR '1'='1"),
                &headers,
                None,
            ));
        });
    });
    group.finish();
}

/// Strict-normalization-enabled path.
fn benchmark_strict_normalization(c: &mut Criterion) {
    let config = AttackDetectionConfig {
        strict_normalization: true,
        ..AttackDetectionConfig::default()
    };
    let detector = Arc::new(AttackDetector::new(config));
    let rt = bench_runtime();
    let headers = HeaderMap::new();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    let mut group = c.benchmark_group("normalize/strict");
    group.bench_function("check_request_benign", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                ip,
                &http::Method::GET,
                "/api/users/123",
                None,
                &headers,
                None,
            ));
        });
    });
    group.bench_function("check_request_overlong", |b| {
        b.iter(|| {
            rt.block_on(detector.check_request(
                ip,
                &http::Method::GET,
                "/%c0%afetc%c0%afpasswd",
                None,
                &headers,
                None,
            ));
        });
    });
    group.finish();
}

/// Concurrent batch harness: N requests in flight on the shared runtime.
/// Reports batch completion (throughput + total latency), not per-request
/// Criterion samples.
fn benchmark_concurrency(c: &mut Criterion) {
    let detector = Arc::new(AttackDetector::new(AttackDetectionConfig::default()));
    let rt = bench_runtime();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    let mut group = c.benchmark_group("normalize/concurrency");
    for batch in [1usize, 8, 32, 128] {
        group.bench_with_input(BenchmarkId::new("batch_benign", batch), &batch, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let mut join_set = tokio::task::JoinSet::new();
                    for i in 0..n {
                        let detector = Arc::clone(&detector);
                        join_set.spawn(async move {
                            let headers = HeaderMap::new();
                            let path = if i % 8 == 0 {
                                "/search?q=hello"
                            } else {
                                "/api/users/123"
                            };
                            detector
                                .check_request(ip, &http::Method::GET, path, None, &headers, None)
                                .await
                        });
                    }
                    while join_set.join_next().await.is_some() {}
                });
            });
        });
        group.bench_with_input(
            BenchmarkId::new("batch_suspicious", batch),
            &batch,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut join_set = tokio::task::JoinSet::new();
                        for _ in 0..n {
                            let detector = Arc::clone(&detector);
                            join_set.spawn(async move {
                                let headers = HeaderMap::new();
                                detector
                                    .check_request(
                                        ip,
                                        &http::Method::GET,
                                        "/search",
                                        Some("id=1' OR '1'='1"),
                                        &headers,
                                        None,
                                    )
                                    .await
                            });
                        }
                        while join_set.join_next().await.is_some() {}
                    });
                });
            },
        );
    }
    group.finish();
}

/// Framing/body-policy common path (Phase 24 hot path).
///
/// Measures the canonical fail-closed validators on benign vs adversarial
/// header sets: the per-request cost paid before routing/WAF evaluation.
fn benchmark_framing_policy(c: &mut Criterion) {
    use synvoid_http::framing::{validate_request_framing, validate_transfer_framing};

    let benign: HeaderMap = [
        ("host", "example.com"),
        ("content-length", "11"),
        ("content-type", "application/x-www-form-urlencoded"),
    ]
    .into_iter()
    .map(|(k, v)| {
        (
            http::header::HeaderName::from_lowercase(k.as_bytes()).unwrap(),
            http::HeaderValue::from_str(v).unwrap(),
        )
    })
    .collect();
    let hostile_cl_te: HeaderMap = [
        ("host", "example.com"),
        ("content-length", "11"),
        ("transfer-encoding", "chunked"),
    ]
    .into_iter()
    .map(|(k, v)| {
        (
            http::header::HeaderName::from_lowercase(k.as_bytes()).unwrap(),
            http::HeaderValue::from_str(v).unwrap(),
        )
    })
    .collect();
    let uri: http::Uri = "/bench".parse().unwrap();

    let mut group = c.benchmark_group("framing_policy");
    group.bench_function("transfer_benign", |b| {
        b.iter(|| criterion::black_box(validate_transfer_framing(&benign)));
    });
    group.bench_function("transfer_hostile_cl_te", |b| {
        b.iter(|| criterion::black_box(validate_transfer_framing(&hostile_cl_te)));
    });
    group.bench_function("request_framing_benign", |b| {
        b.iter(|| {
            criterion::black_box(validate_request_framing(
                &benign,
                &uri,
                http::Version::HTTP_11,
            ))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_normalize_benign,
    benchmark_normalize_encoded,
    benchmark_normalize_all_small,
    benchmark_normalize_all_with_body,
    benchmark_normalize_large_body,
    benchmark_suspicious_inputs,
    benchmark_anomaly_disabled,
    benchmark_strict_normalization,
    benchmark_concurrency,
    benchmark_framing_policy
);
criterion_main!(benches);

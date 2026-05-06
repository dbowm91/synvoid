use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use http::HeaderMap;
use std::sync::Arc;
use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector, InputNormalizer};

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
        group.bench_with_input(BenchmarkId::new("normalize", name), input, |b, i| {
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
        group.bench_with_input(BenchmarkId::new("normalize", name), input, |b, i| {
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

    let request = TestRequest {
        path: "/api/users/123",
        query: Some("page=1&size=20"),
        headers: vec![
            ("host", "example.com"),
            ("user-agent", "Mozilla/5.0"),
            ("accept", "application/json"),
        ],
        body: None,
    };

    let mut group = c.benchmark_group("normalize/small_request");

    group.bench_function("normalize_all_path_only", |b| {
        b.iter(|| {
            let _ = normalizer.normalize(request.path);
        });
    });

    group.bench_function("check_request_benign", |b| {
        let mut headers = HeaderMap::new();
        for (k, v) in &request.headers {
            headers.insert(
                http::header::HeaderName::from_lowercase(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        b.iter(|| {
            let _ = detector.check_request(
                &http::Method::GET,
                request.path,
                request.query,
                &headers,
                None,
            );
        });
    });

    group.finish();
}

fn benchmark_normalize_all_with_body(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));

    let request = TestRequest {
        path: "/api/users",
        query: None,
        headers: vec![
            ("host", "example.com"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        body: Some("username=testuser&password=<PASSWORD>"),
    };

    let mut group = c.benchmark_group("normalize/with_body");

    group.bench_function("check_request_form_body", |b| {
        let mut headers = HeaderMap::new();
        for (k, v) in &request.headers {
            headers.insert(
                http::header::HeaderName::from_lowercase(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        b.iter(|| {
            let _ = detector.check_request(
                &http::Method::POST,
                request.path,
                request.query,
                &headers,
                request.body.map(|b| b.as_bytes()),
            );
        });
    });

    group.finish();
}

fn benchmark_normalize_large_body(c: &mut Criterion) {
    let config = AttackDetectionConfig::default();
    let detector = Arc::new(AttackDetector::new(config));

    let large_body = "data=".to_string() + &"x".repeat(10_000);

    let mut group = c.benchmark_group("normalize/large_body");

    group.bench_function("check_request_10kb_body", |b| {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        b.iter(|| {
            let _ = detector.check_request(
                &http::Method::POST,
                "/api/submit",
                None,
                &headers,
                Some(large_body.as_bytes()),
            );
        });
    });

    group.finish();
}

struct TestRequest<'a> {
    path: &'a str,
    query: Option<&'a str>,
    headers: Vec<(&'a str, &'a str)>,
    body: Option<&'a str>,
}

criterion_group!(
    benches,
    benchmark_normalize_benign,
    benchmark_normalize_encoded,
    benchmark_normalize_all_small,
    benchmark_normalize_all_with_body,
    benchmark_normalize_large_body
);
criterion_main!(benches);

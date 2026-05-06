use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;

fn clean_domain(host: &str) -> String {
    let host = host.trim();
    let host = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if let Some(stripped) = host.strip_prefix("www.") {
        stripped.to_lowercase()
    } else {
        host.to_lowercase()
    }
}

fn bench_clean_domain(c: &mut Criterion) {
    let mut group = c.benchmark_group("router/clean_domain");

    group.bench_function("simple_domain", |b| {
        b.iter(|| {
            criterion::black_box(clean_domain("example.com"));
        });
    });

    group.bench_function("with_www", |b| {
        b.iter(|| {
            criterion::black_box(clean_domain("www.example.com"));
        });
    });

    group.bench_function("with_port", |b| {
        b.iter(|| {
            criterion::black_box(clean_domain("example.com:8080"));
        });
    });

    group.bench_function("with_https_prefix", |b| {
        b.iter(|| {
            criterion::black_box(clean_domain("https://example.com"));
        });
    });

    group.bench_function("with_path", |b| {
        b.iter(|| {
            criterion::black_box(clean_domain("example.com/api/v1/users"));
        });
    });

    group.finish();
}

fn bench_suffix_matching(c: &mut Criterion) {
    let suffixes: Vec<Arc<str>> = (0..10000)
        .map(|i| Arc::from(format!("{}.example.com", i)))
        .collect();

    let mut group = c.benchmark_group("router/suffix_match");

    group.bench_function("hit_first", |b| {
        let host = "0.example.com";
        b.iter(|| {
            let clean = clean_domain(host);
            for suffix in suffixes.iter() {
                if clean.ends_with(suffix.as_ref()) {
                    break;
                }
            }
        });
    });

    group.bench_function("hit_last", |b| {
        let host = "9999.example.com";
        b.iter(|| {
            let clean = clean_domain(host);
            for suffix in suffixes.iter() {
                if clean.ends_with(suffix.as_ref()) {
                    break;
                }
            }
        });
    });

    group.bench_function("miss", |b| {
        let host = "notfound.example.com";
        b.iter(|| {
            let clean = clean_domain(host);
            for suffix in suffixes.iter() {
                if clean.ends_with(suffix.as_ref()) {
                    break;
                }
            }
        });
    });

    group.finish();
}

fn bench_exact_matching(c: &mut Criterion) {
    use std::collections::HashMap;

    let domains: HashMap<Arc<str>, usize> = (0..10000)
        .map(|i| (Arc::from(format!("example{}.com", i)), i))
        .collect();

    let mut group = c.benchmark_group("router/exact_match");

    group.bench_function("hit", |b| {
        let host = "example500.com";
        b.iter(|| {
            let clean = clean_domain(host);
            criterion::black_box(domains.get(clean.as_str()));
        });
    });

    group.bench_function("miss", |b| {
        let host = "notfound.com";
        b.iter(|| {
            let clean = clean_domain(host);
            criterion::black_box(domains.get(clean.as_str()));
        });
    });

    group.finish();
}

fn bench_location_matching(c: &mut Criterion) {
    let locations = vec![
        "/",
        "/api",
        "/api/v1",
        "/api/v1/users",
        "/api/v1/users/{id}",
        "/admin",
        "/admin/users",
        "/static",
        "/static/css",
        "/static/js",
    ];

    let mut group = c.benchmark_group("router/location_match");

    group.bench_function("exact_hit", |b| {
        let path = "/api/v1/users";
        b.iter(|| {
            for loc in &locations {
                if loc == &path {
                    break;
                }
            }
        });
    });

    group.bench_function("prefix_match", |b| {
        let path = "/api/v1/users/123";
        b.iter(|| {
            for loc in &locations {
                if path.starts_with(*loc) {
                    break;
                }
            }
        });
    });

    group.bench_function("no_match", |b| {
        let path = "/unknown/path";
        b.iter(|| {
            for loc in &locations {
                if path.starts_with(&**loc) {
                    break;
                }
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_clean_domain,
    bench_suffix_matching,
    bench_exact_matching,
    bench_location_matching
);
criterion_main!(benches);

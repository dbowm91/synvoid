use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

fn build_cache_key(method: &str, scheme: &str, host: &str, uri: &str) -> String {
    format!("{}:{}:{}:{}", scheme, method, host, uri)
}

fn benchmark_proxy_cache_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy_cache_key");

    group.bench_function("build_key_simple", |b| {
        b.iter(|| {
            let _ = build_cache_key("GET", "https", "example.com", "/api/users");
        });
    });

    group.bench_function("build_key_complex_uri", |b| {
        b.iter(|| {
            let _ = build_cache_key(
                "POST",
                "https",
                "api.example.com",
                "/api/v1/users?page=1&limit=100&sort=name",
            );
        });
    });

    let keys: Vec<_> = (0..1000)
        .map(|i| {
            build_cache_key(
                "GET",
                "https",
                &format!("example{}.com", i % 100),
                "/api/path",
            )
        })
        .collect();

    group.bench_function("hash_key_lookup", |b| {
        let mut map: HashMap<String, usize> = HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            map.insert(key.clone(), i);
        }
        b.iter(|| {
            for key in &keys {
                let _ = map.get(key);
            }
        });
    });

    group.finish();
}

fn benchmark_cache_key_hash(c: &mut Criterion) {
    #[derive(Clone, PartialEq, Eq)]
    struct CacheKey {
        scheme: String,
        method: String,
        host: String,
        uri: String,
    }

    impl Hash for CacheKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.scheme.hash(state);
            self.method.hash(state);
            self.host.hash(state);
            self.uri.hash(state);
        }
    }

    let cache_keys: Vec<_> = (0..1000)
        .map(|i| CacheKey {
            scheme: "https".to_string(),
            method: "GET".to_string(),
            host: format!("example{}.com", i % 100),
            uri: "/api/path".to_string(),
        })
        .collect();

    let mut group = c.benchmark_group("cache_key_hash");

    group.bench_function("hash_single_key", |b| {
        let key = &cache_keys[0];
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            hasher.finish()
        });
    });

    group.bench_function("hash_many_keys", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(cache_keys.len());
            for key in &cache_keys {
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                results.push(hasher.finish());
            }
        });
    });

    group.finish();
}

fn benchmark_entropy_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_calculation");

    let low_entropy = "/api/users/users/users/users/users";
    let high_entropy = "/api/users/123/profile?token=abc123xyz&sig=AAAAAAA";
    let base64_encoded =
        "dHJ1c3RlZF9jbGllbnRfaWQ9MTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=";
    let normal_text = "The quick brown fox jumps over the lazy dog";

    group.bench_with_input(
        BenchmarkId::new("low_entropy", "path"),
        low_entropy,
        |b, s| {
            b.iter(|| calculate_entropy(s));
        },
    );

    group.bench_with_input(
        BenchmarkId::new("high_entropy", "url"),
        high_entropy,
        |b, s| {
            b.iter(|| calculate_entropy(s));
        },
    );

    group.bench_with_input(
        BenchmarkId::new("base64", "encoded"),
        base64_encoded,
        |b, s| {
            b.iter(|| calculate_entropy(s));
        },
    );

    group.bench_with_input(
        BenchmarkId::new("normal_text", "english"),
        normal_text,
        |b, s| {
            b.iter(|| calculate_entropy(s));
        },
    );

    group.finish();
}

fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f32;
    let entropy: f32 = char_counts
        .values()
        .map(|&count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum();

    entropy
}

criterion_group!(
    benches,
    benchmark_proxy_cache_key,
    benchmark_cache_key_hash,
    benchmark_entropy_calculation
);
criterion_main!(benches);

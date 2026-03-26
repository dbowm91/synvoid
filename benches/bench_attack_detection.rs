use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

fn benchmark_normalizer(c: &mut Criterion) {
    let inputs = vec![
        ("hello_world", "Hello World"),
        ("xss_attempt", "<script>alert('XSS')</script>"),
        ("sql_injection", "1' OR '1'='1"),
        ("path_traversal", "../../../etc/passwd"),
        ("ssti", "{{7*7}}"),
        ("http_request", "GET /admin HTTP/1.1\r\nHost: example.com\r\n"),
        ("long_text", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
    ];

    let mut group = c.benchmark_group("normalizer");
    for (name, input) in &inputs {
        group.bench_with_input(BenchmarkId::new("normalize", name), input, |b, i| {
            b.iter(|| {
                let _ = i.to_lowercase();
                let _ = urlencoding_decode(i);
            });
        });
    }
    group.finish();
}

fn benchmark_string_allocation(c: &mut Criterion) {
    let large_input = "x".repeat(10_000);

    let mut group = c.benchmark_group("string_allocation");
    group.bench_function("to_lowercase_10kb", |b| {
        b.iter(|| large_input.to_lowercase());
    });
    group.bench_function("to_vec_10kb", |b| {
        b.iter(|| large_input.as_bytes().to_vec());
    });
    group.finish();
}

fn benchmark_url_decode(c: &mut Criterion) {
    let encoded = "%3Cscript%3Ealert('xss')%3C/script%3E";
    c.bench_function("url_decode", |b| {
        b.iter(|| urlencoding_decode(encoded));
    });
}

criterion_group!(
    benches,
    benchmark_normalizer,
    benchmark_string_allocation,
    benchmark_url_decode
);
criterion_main!(benches);

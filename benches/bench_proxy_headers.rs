use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use std::str::FromStr;

fn build_forward_headers(
    client_ip: std::net::IpAddr,
    original_headers: &http::HeaderMap,
    config: &ProxyHeadersConfig,
    protocol: ForwardedProtocol,
) -> http::HeaderMap {
    let mut forward_headers = http::HeaderMap::new();

    let headers_to_forward: Vec<&str> = if config.forward.is_empty() {
        vec!["*"]
    } else {
        config.forward.iter().map(|s| s.as_str()).collect()
    };

    let forward_all = headers_to_forward.contains(&"*");

    for (name, value) in original_headers.iter() {
        let name_str = name.as_str();

        if is_hop_by_hop_header(name_str) {
            continue;
        }

        if name_str.eq_ignore_ascii_case("x-forwarded-for")
            || name_str.eq_ignore_ascii_case("x-real-ip")
            || name_str.eq_ignore_ascii_case("forwarded")
            || name_str.eq_ignore_ascii_case("x-forwarded-proto")
        {
            continue;
        }

        if config.hide.iter().any(|h| h.eq_ignore_ascii_case(name_str)) {
            continue;
        }

        if config.clear.iter().any(|h| h.eq_ignore_ascii_case(name_str)) {
            continue;
        }

        let should_forward = forward_all
            || headers_to_forward
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name_str));
        if should_forward {
            forward_headers.insert(name, value.clone());
        }
    }

    let xff_value = {
        let existing = original_headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        validate_and_truncate_xff(existing, &client_ip.to_string())
    };
    if let Ok(value) = xff_value.parse::<http::HeaderValue>() {
        forward_headers.insert(
            http::header::HeaderName::from_static("x-forwarded-for"),
            value,
        );
    }

    if let Ok(value) = client_ip.to_string().parse::<http::HeaderValue>() {
        forward_headers.insert(http::header::HeaderName::from_static("x-real-ip"), value);
    }

    let proto = protocol.as_str();
    if let Ok(value) = proto.parse::<http::HeaderValue>() {
        forward_headers.insert(
            http::header::HeaderName::from_static("x-forwarded-proto"),
            value,
        );
    }

    forward_headers
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn validate_and_truncate_xff(existing: &str, new_ip: &str) -> String {
    let mut result = String::new();
    let parts: Vec<&str> = existing.split(',').collect();
    let count = parts.len().min(5);
    for i in 0..count {
        let ip = parts[parts.len() - 1 - i].trim();
        if !ip.is_empty() {
            if !result.is_empty() {
                result.push_str(", ");
            }
            result.push_str(ip);
        }
    }
    if !result.is_empty() {
        result.push_str(", ");
    }
    result.push_str(new_ip);
    if result.len() > 4096 {
        result.truncate(4096);
        if let Some(comma) = result.rfind(',') {
            result.truncate(comma);
        }
    }
    result
}

#[derive(Clone)]
pub struct ProxyHeadersConfig {
    pub forward: Vec<String>,
    pub hide: Vec<String>,
    pub clear: Vec<String>,
}

impl Default for ProxyHeadersConfig {
    fn default() -> Self {
        Self {
            forward: vec!["*".to_string()],
            hide: vec!["authorization".to_string()],
            clear: vec!["proxy-authorization".to_string()],
        }
    }
}

#[derive(Clone, Copy)]
pub enum ForwardedProtocol {
    Http,
    Https,
}

impl ForwardedProtocol {
    fn as_str(&self) -> &str {
        match self {
            ForwardedProtocol::Http => "http",
            ForwardedProtocol::Https => "https",
        }
    }
}

fn create_test_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HOST,
        http::HeaderValue::from_static("example.com"),
    );
    headers.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static("Mozilla/5.0"),
    );
    headers.insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("text/html"),
    );
    headers.insert(
        http::header::ACCEPT_LANGUAGE,
        http::HeaderValue::from_static("en-US,en;q=0.9"),
    );
    headers.insert(
        http::header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("gzip, deflate"),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        http::header::REFERER,
        http::HeaderValue::from_static("https://google.com"),
    );
    headers.insert(
        "X-Custom-Header".parse::<http::header::HeaderName>().unwrap(),
        http::HeaderValue::from_static("custom-value"),
    );
    headers.insert(
        "X-Request-Id".parse::<http::header::HeaderName>().unwrap(),
        http::HeaderValue::from_static("12345"),
    );
    headers
}

fn benchmark_build_forward_headers(c: &mut Criterion) {
    let client_ip = IpAddr::from_str("192.168.1.100").unwrap();
    let headers = create_test_headers();
    let config = ProxyHeadersConfig::default();

    c.benchmark_group("proxy/build_forward_headers")
        .bench_function("small_headers", |b| {
            b.iter(|| {
                criterion::black_box(build_forward_headers(
                    client_ip,
                    &headers,
                    &config,
                    ForwardedProtocol::Https,
                ));
            });
        });

    let mut large_headers = create_test_headers();
    for i in 0..50 {
        let name = format!("X-Header-{}", i);
        let value = format!("value-{}", i);
        large_headers.insert(
            name.parse::<http::header::HeaderName>().unwrap(),
            http::HeaderValue::from_str(&value).unwrap(),
        );
    }

    c.benchmark_group("proxy/build_forward_headers/large")
        .bench_function("50_headers", |b| {
            b.iter(|| {
                criterion::black_box(build_forward_headers(
                    client_ip,
                    &large_headers,
                    &config,
                    ForwardedProtocol::Https,
                ));
            });
        });
}

fn benchmark_ip_to_string(c: &mut Criterion) {
    let client_ip = IpAddr::from_str("192.168.1.100").unwrap();

    c.bench_function("ip_to_string", |b| {
        b.iter(|| {
            criterion::black_box(client_ip.to_string());
        });
    });

    let ipv6_ip = IpAddr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap();
    c.bench_function("ipv6_to_string", |b| {
        b.iter(|| {
            criterion::black_box(ipv6_ip.to_string());
        });
    });
}

fn benchmark_header_cloning(c: &mut Criterion) {
    let mut headers = create_test_headers();
    headers.insert(
        "X-Large-Header".parse::<http::header::HeaderName>().unwrap(),
        http::HeaderValue::from_str(&"x".repeat(1000)).unwrap(),
    );

    c.bench_function("header_clone", |b| {
        b.iter(|| {
            let mut new_headers = http::HeaderMap::new();
            for (name, value) in headers.iter() {
                new_headers.insert(name.clone(), value.clone());
            }
        });
    });
}

fn benchmark_xff_processing(c: &mut Criterion) {
    c.bench_function("xff_empty", |b| {
        b.iter(|| {
            criterion::black_box(validate_and_truncate_xff("", "192.168.1.100"));
        });
    });

    c.bench_function("xff_single", |b| {
        b.iter(|| {
            criterion::black_box(validate_and_truncate_xff("10.0.0.1", "192.168.1.100"));
        });
    });

    c.bench_function("xff_multiple", |b| {
        b.iter(|| {
            criterion::black_box(validate_and_truncate_xff(
                "10.0.0.1, 10.0.0.2, 10.0.0.3",
                "192.168.1.100",
            ));
        });
    });

    c.bench_function("xff_many", |b| {
        let xff = (0..20).map(|i| format!("10.0.0.{}", i)).collect::<Vec<_>>().join(", ");
        b.iter(|| {
            criterion::black_box(validate_and_truncate_xff(&xff, "192.168.1.100"));
        });
    });
}

criterion_group!(
    benches,
    benchmark_build_forward_headers,
    benchmark_ip_to_string,
    benchmark_header_cloning,
    benchmark_xff_processing
);
criterion_main!(benches);

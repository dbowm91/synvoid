use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_dns::cache::{CacheNamespace, TransportClass};
use synvoid_dns::query_coalesce::{QueryCoalescer, QueryKey};

fn build_query_key(name: &str, qtype: u16) -> QueryKey {
    QueryKey {
        name: name.to_string(),
        qtype,
        qclass: 1,
        dnssec_ok: false,
        client_ip: Some("192.168.1.1".to_string()),
        transport_class: TransportClass::Udp512,
        namespace: CacheNamespace::Authoritative,
    }
}

fn bench_coalescer_new(c: &mut Criterion) {
    c.bench_function("coalescer_new", |b| {
        b.iter(|| {
            QueryCoalescer::new();
        });
    });
}

fn bench_coalescer_with_config(c: &mut Criterion) {
    c.bench_function("coalescer_with_config", |b| {
        b.iter(|| {
            QueryCoalescer::with_config(black_box(500), black_box(10000), black_box(30));
        });
    });
}

fn bench_coalescer_key_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("coalescer_key_creation");
    let names = [
        ("short", "a.b"),
        ("medium", "www.example.com"),
        ("long", "sub.domain.long.hostname.example.com"),
    ];
    for (label, name) in &names {
        group.bench_with_input(BenchmarkId::from_parameter(label), name, |b, &name| {
            b.iter(|| {
                build_query_key(black_box(name), 1);
            });
        });
    }
    group.finish();
}

fn bench_should_skip_coalescing(c: &mut Criterion) {
    let mut group = c.benchmark_group("should_skip_coalescing");
    let cases: &[(&str, u16, u8)] = &[
        ("regular_a", 1, 0),
        ("regular_aaaa", 28, 0),
        ("axfr", 252, 0),
        ("ixfr", 251, 0),
        ("notify_opcode", 1, 4),
        ("update_opcode", 1, 5),
    ];
    for (label, qtype, opcode) in cases {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(*qtype, *opcode),
            |b, &(qt, op)| {
                b.iter(|| {
                    synvoid_dns::query_coalesce::should_skip_coalescing(
                        black_box(qt),
                        black_box(op),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_coalescer_new,
    bench_coalescer_with_config,
    bench_coalescer_key_creation,
    bench_should_skip_coalescing,
);
criterion_main!(benches);

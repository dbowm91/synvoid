use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_dns::parsed_query::ParsedDnsQuery;
use synvoid_dns::wire;

fn build_test_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(512);
    // Header
    query.extend_from_slice(&[0x12, 0x34]); // ID
    query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
                                            // Question
    for label in name.trim_end_matches('.').split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // root
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    query
}

fn bench_parse_query_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_query_name");
    let names = [
        ("short", "a.b"),
        ("medium", "www.example.com"),
        ("long", "sub.domain.long.hostname.example.com"),
    ];
    for (label, name) in &names {
        let query = build_test_query(name, 1);
        // Find the offset where qname starts (after 12-byte header)
        group.bench_with_input(BenchmarkId::from_parameter(label), name, |b, _| {
            b.iter(|| {
                wire::parse_query_name(black_box(&query), 12);
            });
        });
    }
    group.finish();
}

fn bench_parse_dns_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_dns_message");
    let names = [
        ("short", "a.b"),
        ("medium", "www.example.com"),
        ("long", "sub.domain.long.hostname.example.com"),
    ];
    for (label, name) in &names {
        let query = build_test_query(name, 1);
        group.bench_with_input(BenchmarkId::from_parameter(label), name, |b, _| {
            b.iter(|| {
                let _ = wire::parse_dns_message(black_box(&query));
            });
        });
    }
    group.finish();
}

fn bench_parsed_dns_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsed_dns_query");
    let names = [
        ("short", "a.b"),
        ("medium", "www.example.com"),
        ("long", "sub.domain.long.hostname.example.com"),
    ];
    for (label, name) in &names {
        let query = build_test_query(name, 1);
        group.bench_with_input(BenchmarkId::from_parameter(label), name, |b, _| {
            b.iter(|| {
                let _ = ParsedDnsQuery::parse(black_box(&query));
            });
        });
    }
    group.finish();
}

fn bench_get_message_id(c: &mut Criterion) {
    let query = build_test_query("example.com", 1);
    c.bench_function("get_message_id", |b| {
        b.iter(|| {
            wire::get_message_id(black_box(&query));
        });
    });
}

fn bench_get_message_flags(c: &mut Criterion) {
    let query = build_test_query("example.com", 1);
    c.bench_function("get_message_flags", |b| {
        b.iter(|| {
            wire::get_message_flags(black_box(&query));
        });
    });
}

criterion_group!(
    benches,
    bench_parse_query_name,
    bench_parse_dns_message,
    bench_parsed_dns_query,
    bench_get_message_id,
    bench_get_message_flags,
);
criterion_main!(benches);

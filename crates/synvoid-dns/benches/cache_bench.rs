use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_dns::cache::{CacheKey, CacheNamespace, DnsCache, TransportClass};
use synvoid_dns::server::RecordType;

fn bench_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert");
    for capacity in [1000, 10000, 100000] {
        let cache = DnsCache::new(capacity, 300, 10);
        let key = CacheKey::new("example.com".to_string(), RecordType::A, None);
        let data = vec![0u8; 64];
        group.bench_with_input(BenchmarkId::from_parameter(capacity), &capacity, |b, _| {
            b.iter(|| {
                cache.insert(black_box(key.clone()), black_box(data.clone()), 300);
            });
        });
    }
    group.finish();
}

fn bench_cache_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup");
    for capacity in [1000, 10000] {
        let cache = DnsCache::new(capacity, 300, 10);
        // Pre-populate
        for i in 0..capacity {
            let key = CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
            cache.insert(key, vec![1u8; 64], 300);
        }
        group.bench_with_input(
            BenchmarkId::from_parameter(capacity),
            &capacity,
            |b, &cap| {
                b.iter(|| {
                    let key =
                        CacheKey::new(format!("host{}.example.com", cap / 2), RecordType::A, None);
                    cache.get(black_box(&key));
                });
            },
        );
    }
    group.finish();
}

fn bench_cache_lookup_miss(c: &mut Criterion) {
    let cache = DnsCache::new(10000, 300, 10);
    c.bench_function("cache_lookup_miss", |b| {
        b.iter(|| {
            let key = CacheKey::new("nonexistent.example.com".to_string(), RecordType::A, None);
            cache.get(black_box(&key));
        });
    });
}

fn bench_cache_transport_classes(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_transport_classes");
    let classes = [
        ("udp512", TransportClass::Udp512),
        ("udp_edns_1232", TransportClass::UdpEdns(1232)),
        ("udp_edns_4096", TransportClass::UdpEdns(4096)),
        ("tcp", TransportClass::Tcp),
        ("https", TransportClass::Http),
        ("quic", TransportClass::Quic),
    ];
    let cache = DnsCache::new(10000, 300, 10);
    for (_name, tc) in &classes {
        let key = CacheKey {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            client_subnet: None,
            transport_class: *tc,
            namespace: CacheNamespace::Authoritative,
        };
        cache.insert(key, vec![1u8; 64], 300);
    }
    group.bench_function("lookup_by_transport_class", |b| {
        b.iter(|| {
            for (_, tc) in &classes {
                let key = CacheKey {
                    qname: "example.com".to_string(),
                    qtype: 1,
                    qclass: 1,
                    dnssec_ok: false,
                    client_subnet: None,
                    transport_class: *tc,
                    namespace: CacheNamespace::Authoritative,
                };
                cache.get(black_box(&key));
            }
        });
    });
    group.finish();
}

fn bench_cache_invalidation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_invalidation");
    for record_count in [100, 1000] {
        let cache = DnsCache::new(10000, 300, 10);
        for i in 0..record_count {
            let key = CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
            cache.insert(key, vec![1u8; 64], 300);
        }
        group.bench_with_input(
            BenchmarkId::from_parameter(record_count),
            &record_count,
            |b, &count| {
                b.iter(|| {
                    for i in 0..count {
                        let key =
                            CacheKey::new(format!("host{i}.example.com"), RecordType::A, None);
                        cache.get(black_box(&key));
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_cache_insert,
    bench_cache_lookup,
    bench_cache_lookup_miss,
    bench_cache_transport_classes,
    bench_cache_invalidation,
);
criterion_main!(benches);

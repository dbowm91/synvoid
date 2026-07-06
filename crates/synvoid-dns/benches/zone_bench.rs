use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_dns::server::{DnsZoneRecord, RecordType, Zone};

fn bench_zone_new(c: &mut Criterion) {
    c.bench_function("zone_new", |b| {
        b.iter(|| {
            Zone::new(black_box("example.com".to_string()));
        });
    });
}

fn bench_zone_insert_records(c: &mut Criterion) {
    let mut group = c.benchmark_group("zone_insert_records");
    for count in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_batched(
                || Zone::new("example.com".to_string()),
                |mut zone| {
                    for i in 0..count {
                        let record = DnsZoneRecord {
                            name: format!("host{i}.example.com"),
                            record_type: RecordType::A,
                            value: "192.168.1.1".to_string(),
                            ttl: 300,
                            priority: None,
                        };
                        zone.records
                            .entry((record.name.clone(), RecordType::A))
                            .or_default()
                            .push(record);
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_zone_lookup_authoritative(c: &mut Criterion) {
    let mut group = c.benchmark_group("zone_lookup_authoritative");
    for count in [100, 1000] {
        let mut zone = Zone::new("example.com".to_string());
        for i in 0..count {
            let record = DnsZoneRecord {
                name: format!("host{i}.example.com"),
                record_type: RecordType::A,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: None,
            };
            zone.records
                .entry((record.name.clone(), RecordType::A))
                .or_default()
                .push(record);
        }
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let name = format!("host{}.example.com", count / 2);
                zone.lookup_authoritative(black_box(&name), 1);
            });
        });
    }
    group.finish();
}

fn bench_zone_nxdomain(c: &mut Criterion) {
    let mut zone = Zone::new("example.com".to_string());
    for i in 0..100 {
        let record = DnsZoneRecord {
            name: format!("host{i}.example.com"),
            record_type: RecordType::A,
            value: "192.168.1.1".to_string(),
            ttl: 300,
            priority: None,
        };
        zone.records
            .entry((record.name.clone(), RecordType::A))
            .or_default()
            .push(record);
    }
    c.bench_function("zone_lookup_nxdomain", |b| {
        b.iter(|| {
            zone.lookup_authoritative(black_box("nonexistent.example.com"), 1);
        });
    });
}

fn bench_zone_increment_serial(c: &mut Criterion) {
    c.bench_function("zone_increment_serial", |b| {
        b.iter(|| {
            let mut zone = Zone::new("example.com".to_string());
            for _ in 0..100 {
                zone.increment_serial();
            }
        });
    });
}

fn bench_zone_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("zone_trie");
    let mut trie = synvoid_dns::zone_trie::ZoneTrie::new();
    let origins: Vec<String> = (0..1000).map(|i| format!("zone{i}.example.com")).collect();
    for origin in &origins {
        trie.insert(origin);
    }
    group.bench_function("longest_match_hit", |b| {
        b.iter(|| {
            trie.find_zone(black_box("sub.host500.zone500.example.com"));
        });
    });
    group.bench_function("longest_match_miss", |b| {
        b.iter(|| {
            trie.find_zone(black_box("nonexistent.otherdomain.com"));
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_zone_new,
    bench_zone_insert_records,
    bench_zone_lookup_authoritative,
    bench_zone_nxdomain,
    bench_zone_increment_serial,
    bench_zone_trie,
);
criterion_main!(benches);

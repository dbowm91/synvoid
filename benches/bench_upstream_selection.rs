//! Phase 49: upstream-selection benchmarks.
//!
//! Covers every `LoadBalanceAlgorithm` at 1/4/16/64 backends plus
//! unhealthy mixes, backup fallback, protocol filtering, `select_next_backend`
//! and IP-hash selection. Fixture construction and backend mutation happen
//! outside the timed loop; only selection is timed.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_upstream::{BackendProtocol, LoadBalanceAlgorithm, UpstreamPool};

fn urls(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("http://127.0.0.1:{}/", 9000 + i))
        .collect()
}

fn make_pool(algorithm: LoadBalanceAlgorithm, n: usize) -> UpstreamPool {
    UpstreamPool::new(urls(n), algorithm)
}

fn benchmark_algorithms_by_size(c: &mut Criterion) {
    let algorithms = [
        ("round_robin", LoadBalanceAlgorithm::RoundRobin),
        ("random", LoadBalanceAlgorithm::Random),
        ("least_connections", LoadBalanceAlgorithm::LeastConnections),
        ("peak_ewma", LoadBalanceAlgorithm::PeakEwma),
        ("weighted_rr", LoadBalanceAlgorithm::WeightedRoundRobin),
        ("ip_hash", LoadBalanceAlgorithm::IpHash),
    ];

    let mut group = c.benchmark_group("upstream/select_by_size");
    for (name, algorithm) in algorithms {
        for n in [1usize, 4, 16, 64] {
            let pool = make_pool(algorithm.clone(), n);
            group.bench_with_input(BenchmarkId::new(name, n), &n, |b, _| {
                b.iter(|| criterion::black_box(pool.select_backend()));
            });
        }
    }
    group.finish();
}

fn benchmark_weighted_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("upstream/weighted");

    for n in [4usize, 16] {
        let pool = UpstreamPool::new(urls(n), LoadBalanceAlgorithm::WeightedRoundRobin);
        group.bench_with_input(BenchmarkId::new("select", n), &n, |b, _| {
            b.iter(|| criterion::black_box(pool.select_backend()));
        });
    }

    // Zero-total-weight pool (all weights forced to zero via fresh pool with
    // zero-weight backends is not directly expressible; exercise the uniform
    // path through single-backend weight-zero setup instead).
    let single = UpstreamPool::new(urls(1), LoadBalanceAlgorithm::WeightedRoundRobin);
    group.bench_function("select_zero_weight_single", |b| {
        b.iter(|| criterion::black_box(single.select_backend()));
    });
    group.finish();
}

fn benchmark_unhealthy_and_backup(c: &mut Criterion) {
    let mut group = c.benchmark_group("upstream/failover");

    // Half the primaries unhealthy.
    let pool = make_pool(LoadBalanceAlgorithm::RoundRobin, 16);
    for (i, backend) in pool.get_backends().iter().enumerate() {
        if i % 2 == 0 {
            pool.mark_unhealthy(&backend.url);
        }
    }
    group.bench_function("round_robin_half_unhealthy", |b| {
        b.iter(|| criterion::black_box(pool.select_backend()));
    });

    // All primaries down with backup fallback.
    let with_backup = UpstreamPool::new_with_backup(
        urls(4),
        vec!["http://127.0.0.1:9999/".to_string()],
        LoadBalanceAlgorithm::RoundRobin,
    );
    for backend in with_backup.get_backends().iter() {
        if !backend.is_backup {
            with_backup.mark_unhealthy(&backend.url);
        }
    }
    group.bench_function("backup_fallback", |b| {
        b.iter(|| criterion::black_box(with_backup.select_backend()));
    });

    // Least-connections with skewed connection counts.
    let loaded = make_pool(LoadBalanceAlgorithm::LeastConnections, 16);
    {
        let backends = loaded.get_backends();
        for (i, backend) in backends.iter().enumerate() {
            for _ in 0..(i % 5) {
                backend.increment_connections();
            }
        }
    }
    group.bench_function("least_connections_skewed", |b| {
        b.iter(|| criterion::black_box(loaded.select_backend()));
    });

    group.finish();
}

fn benchmark_protocol_and_next(c: &mut Criterion) {
    let mut group = c.benchmark_group("upstream/filtered");

    let pool = UpstreamPool::new(urls(16), LoadBalanceAlgorithm::RoundRobin);
    pool.add_backend_with_protocol("http://127.0.0.1:9100/".to_string(), BackendProtocol::Grpc);
    group.bench_function("select_for_protocol", |b| {
        b.iter(|| {
            criterion::black_box(pool.select_backend_for_protocol(BackendProtocol::Http));
        });
    });

    let current = pool.select_backend().expect("bench pool has backends");
    group.bench_function("select_next_backend", |b| {
        b.iter(|| criterion::black_box(pool.select_next_backend(&current)));
    });

    group.bench_function("try_select_backend", |b| {
        b.iter(|| criterion::black_box(pool.try_select_backend()));
    });

    group.finish();
}

fn benchmark_ip_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("upstream/ip_hash");
    let pool = make_pool(LoadBalanceAlgorithm::IpHash, 16);
    let clients = ["10.0.0.1", "10.0.0.2", "192.168.1.100", "2001:db8::1"];
    for (i, client) in clients.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("client", i), client, |b, ip| {
            b.iter(|| criterion::black_box(pool.select_backend_for_ip(ip)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_algorithms_by_size,
    benchmark_weighted_distribution,
    benchmark_unhealthy_and_backup,
    benchmark_protocol_and_next,
    benchmark_ip_hash,
);
criterion_main!(benches);

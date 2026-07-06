use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_dns::limits::ConnectionLimits;

fn bench_limits_new(c: &mut Criterion) {
    c.bench_function("limits_new", |b| {
        b.iter(|| {
            ConnectionLimits::new(
                black_box(1000),
                black_box(5000),
                black_box(4096),
                black_box(65535),
                black_box(100),
                black_box(300),
                black_box(30),
                black_box(false),
            );
        });
    });
}

fn bench_limits_try_acquire_connection(c: &mut Criterion) {
    let mut group = c.benchmark_group("limits_try_acquire_connection");
    for max in [100, 1000, 10000] {
        let limits = ConnectionLimits::new(max, 5000, 4096, 65535, 100, 300, 30, false);
        group.bench_with_input(BenchmarkId::from_parameter(max), &max, |b, _| {
            b.iter(|| {
                let _ = limits.try_acquire_connection();
            });
        });
    }
    group.finish();
}

fn bench_limits_try_acquire_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("limits_try_acquire_query");
    for max in [1000, 5000, 10000] {
        let limits = ConnectionLimits::new(1000, max, 4096, 65535, 100, 300, 30, false);
        group.bench_with_input(BenchmarkId::from_parameter(max), &max, |b, _| {
            b.iter(|| {
                let _ = limits.try_acquire_query();
            });
        });
    }
    group.finish();
}

fn bench_limits_validate_query_size(c: &mut Criterion) {
    let limits = ConnectionLimits::new(1000, 5000, 4096, 65535, 100, 300, 30, false);
    let mut group = c.benchmark_group("limits_validate_query_size");
    for size in [64, 512, 1024, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let _ = limits.validate_query_size(black_box(size));
            });
        });
    }
    group.finish();
}

fn bench_limits_degradation_level(c: &mut Criterion) {
    let limits = ConnectionLimits::new(1000, 5000, 4096, 65535, 100, 300, 30, false);
    c.bench_function("limits_get_degradation_level", |b| {
        b.iter(|| {
            limits.get_degradation_level();
        });
    });
}

criterion_group!(
    benches,
    bench_limits_new,
    bench_limits_try_acquire_connection,
    bench_limits_try_acquire_query,
    bench_limits_validate_query_size,
    bench_limits_degradation_level,
);
criterion_main!(benches);

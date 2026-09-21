//! Phase 49: buffer-pool benchmarks.
//!
//! Covers TLS-cache hits per tier, local spill, global acquire/release,
//! same-thread and cross-thread reuse, growth within/across tiers, jumbo
//! allocation, and zero-length acquire followed by incremental growth.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_utils::buffer::pool::BufferPool;

fn benchmark_tier_acquire_release(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool/tier_reuse");
    let cases: &[(&str, usize)] = &[
        ("small_512", 512),
        ("small_4k", 4096),
        ("medium_16k", 16 * 1024),
        ("medium_64k", 64 * 1024),
        ("large_128k", 128 * 1024),
        ("large_256k", 256 * 1024),
    ];
    for (name, size) in cases {
        group.bench_with_input(BenchmarkId::new("acquire_release", name), size, |b, &n| {
            b.iter(|| {
                let buf = BufferPool::acquire(n);
                criterion::black_box(buf.len());
            });
        });
    }
    group.finish();
}

fn benchmark_tls_cache_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool/tls_cache");
    // Prime the TLS cache outside the timed loop, then measure hit reuse.
    for (name, size) in [
        ("small", 1024usize),
        ("medium", 32 * 1024),
        ("large", 200 * 1024),
    ] {
        {
            let buf = BufferPool::acquire(size);
            drop(buf);
        }
        group.bench_with_input(BenchmarkId::new("tls_hit", name), &size, |b, &n| {
            b.iter(|| {
                let buf = BufferPool::acquire(n);
                criterion::black_box(buf.len());
            });
        });
    }
    group.finish();
}

fn benchmark_global_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool/global");
    for (name, size) in [("small", 1024usize), ("medium", 32 * 1024)] {
        group.bench_with_input(BenchmarkId::new("global", name), &size, |b, &n| {
            b.iter(|| {
                let buf = BufferPool::acquire_global(n);
                criterion::black_box(buf.len());
            });
        });
    }
    group.finish();
}

fn benchmark_cross_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool/cross_thread");
    // Acquire on this thread, move to a worker thread, drop there, then
    // reacquire here: exercises cross-thread return accounting.
    group.bench_function("acquire_drop_reacquire", |b| {
        b.iter(|| {
            let buf = BufferPool::acquire_global(4096);
            std::thread::scope(|s| {
                s.spawn(move || {
                    drop(buf);
                });
            });
            let buf2 = BufferPool::acquire_global(4096);
            criterion::black_box(buf2.len());
        });
    });
    group.finish();
}

fn benchmark_growth(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool/growth");
    group.bench_function("grow_within_tier", |b| {
        b.iter(|| {
            let mut buf = BufferPool::acquire(512);
            buf.resize(3000);
            criterion::black_box(buf.len());
        });
    });
    group.bench_function("grow_across_tiers", |b| {
        b.iter(|| {
            let mut buf = BufferPool::acquire(1024);
            buf.resize(100 * 1024);
            criterion::black_box(buf.len());
        });
    });
    group.bench_function("jumbo_allocate", |b| {
        b.iter(|| {
            let buf = BufferPool::acquire(512 * 1024);
            criterion::black_box(buf.len());
        });
    });
    group.bench_function("zero_then_incremental_growth", |b| {
        b.iter(|| {
            let mut buf = BufferPool::acquire(0);
            buf.resize(0);
            for _ in 0..8 {
                let next = buf.len() + 1024;
                buf.resize(next);
            }
            criterion::black_box(buf.len());
        });
    });
    group.bench_function("extend_from_slice_1kib", |b| {
        let chunk = vec![0xABu8; 1024];
        b.iter(|| {
            let mut buf = BufferPool::acquire(0);
            buf.resize(0);
            buf.extend_from_slice(&chunk);
            criterion::black_box(buf.len());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_tier_acquire_release,
    benchmark_tls_cache_hit,
    benchmark_global_pool,
    benchmark_cross_thread,
    benchmark_growth,
);
criterion_main!(benches);

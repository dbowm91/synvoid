use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct AtomicBucketWindow {
    buckets: Vec<AtomicU32>,
    bucket_count: usize,
    bucket_duration_ms: u64,
    current_bucket: AtomicU64,
    start_ms: u64,
}

impl AtomicBucketWindow {
    pub fn new(window_secs: u32, bucket_count: u32) -> Self {
        let bucket_count = bucket_count.max(1) as usize;
        let buckets: Vec<AtomicU32> = (0..bucket_count).map(|_| AtomicU32::new(0)).collect();
        let bucket_duration_ms = (window_secs as u64 * 1000) / bucket_count as u64;

        Self {
            buckets,
            bucket_count,
            bucket_duration_ms,
            current_bucket: AtomicU64::new(0),
            start_ms: Instant::now().elapsed().as_millis() as u64,
        }
    }

    #[inline]
    pub fn increment(&self) -> u32 {
        let now_ms = Instant::now().elapsed().as_millis() as u64 - self.start_ms;
        let bucket_idx = ((now_ms / self.bucket_duration_ms) % self.bucket_count as u64) as usize;
        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed) + 1
    }

    #[inline]
    pub fn get_count(&self) -> u32 {
        let now_ms = Instant::now().elapsed().as_millis() as u64 - self.start_ms;
        let bucket_idx = ((now_ms / self.bucket_duration_ms) % self.bucket_count as u64) as usize;
        self.buckets[bucket_idx].load(Ordering::Relaxed)
    }

    #[inline]
    pub fn sum_all_buckets(&self) -> u32 {
        let mut total = 0u32;
        for bucket in &self.buckets {
            total += bucket.load(Ordering::Relaxed);
        }
        total
    }
}

fn benchmark_atomic_bucket(c: &mut Criterion) {
    let window = Arc::new(AtomicBucketWindow::new(60, 60));

    let mut group = c.benchmark_group("atomic_bucket_window");
    group.bench_function("increment", |b| {
        b.iter(|| window.increment());
    });
    group.bench_function("get_count", |b| {
        b.iter(|| window.get_count());
    });
    group.bench_function("sum_all_buckets", |b| {
        b.iter(|| window.sum_all_buckets());
    });
    group.finish();
}

fn benchmark_ring_buffer(c: &mut Criterion) {
    let mut buffer = Vec::with_capacity(100);

    c.bench_function("ring_buffer_push", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            buffer.push(counter);
            counter += 1;
        });
    });
}

fn benchmark_collections(c: &mut Criterion) {
    let map: HashMap<String, u32> = (0..1000).map(|i| (format!("key_{}", i), i)).collect();
    let set: HashSet<String> = (0..1000).map(|i| format!("key_{}", i)).collect();

    let mut group = c.benchmark_group("collections");
    group.bench_function("hashmap_get", |b| {
        b.iter(|| map.get("key_500"));
    });
    group.bench_function("hashset_contains", |b| {
        b.iter(|| set.contains("key_500"));
    });
    group.finish();
}

fn benchmark_vec_contains(c: &mut Criterion) {
    let vec: Vec<String> = (0..1000).map(|i| format!("key_{}", i)).collect();

    c.bench_function("vec_contains", |b| {
        b.iter(|| vec.contains(&"key_500".to_string()));
    });
}

criterion_group!(
    benches,
    benchmark_atomic_bucket,
    benchmark_ring_buffer,
    benchmark_collections,
    benchmark_vec_contains
);
criterion_main!(benches);

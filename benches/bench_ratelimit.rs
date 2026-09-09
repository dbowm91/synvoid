use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct AtomicBucketWindow {
    buckets: Vec<AtomicU32>,
    bucket_count: usize,
    bucket_duration_ms: u64,
    #[allow(dead_code)]
    current_bucket: AtomicU64,
    start: Instant,
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
            start: Instant::now(),
        }
    }

    #[inline]
    pub fn increment(&self) -> u32 {
        let now_ms = self.start.elapsed().as_millis() as u64;
        let bucket_idx = ((now_ms / self.bucket_duration_ms) % self.bucket_count as u64) as usize;
        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed) + 1
    }

    #[inline]
    pub fn get_count(&self) -> u32 {
        let now_ms = self.start.elapsed().as_millis() as u64;
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

/// Canonical sliding-window limiter lookup/update (Phase 24 hot path).
///
/// Exercises the real `synvoid_waf` limiter (contended single key + sharded
/// key set) rather than the local toy window above.
fn benchmark_sliding_limiter(c: &mut Criterion) {
    use synvoid_waf::ratelimit::sliding::{SlidingWindowConfig, SlidingWindowLimiter};

    let limiter = SlidingWindowLimiter::new(
        vec![SlidingWindowConfig::with_buckets(60, 4, u32::MAX)],
        1024,
    );
    let hot = "hot-key".to_string();
    let sharded: Vec<String> = (0..64).map(|i| format!("key-{i}")).collect();
    let mut group = c.benchmark_group("sliding_limiter");
    group.bench_function("check_and_increment_hot_key", |b| {
        b.iter(|| criterion::black_box(limiter.check_and_increment(&hot)));
    });
    group.bench_function("check_and_increment_sharded", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i += 1;
            criterion::black_box(limiter.check_and_increment(&sharded[i % 64]));
        });
    });
    group.finish();
}

/// Block-store lookup/admission (Phase 24 hot path).
///
/// Pre-populated store; measures admission-path `is_blocked` hits, misses,
/// and steady-state re-block admission. Persistence is disabled
/// (`data_dir: None`, `persist_interval_secs: 0`).
fn benchmark_blockstore_lookup(c: &mut Criterion) {
    use std::net::{IpAddr, Ipv4Addr};
    use synvoid_block_store::BlockStore;
    use synvoid_core::block_store::{BlockProvenance, BlockProvenanceKind};

    let config = synvoid_config::DenyListLimitsConfig {
        max_entries: 2048,
        persist_interval_secs: 0,
        target_state_persist: false,
        target_state_max_records: 10_000,
        target_state_ttl_secs: 604_800,
    };
    let store = BlockStore::new(true, None, config);
    let provenance = BlockProvenance {
        kind: BlockProvenanceKind::Test,
        source: Some("bench".to_string()),
    };
    for i in 0..512u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i));
        let _ = store.block_ip_with_provenance(ip, "bench", 3600, "global", provenance.clone());
    }
    let hit = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + 7));
    let miss = IpAddr::V4(Ipv4Addr::from(0x0C00_0000));

    let mut group = c.benchmark_group("blockstore_lookup");
    group.bench_function("is_blocked_hit", |b| {
        b.iter(|| criterion::black_box(store.is_blocked(&hit, "global")));
    });
    group.bench_function("is_blocked_miss", |b| {
        b.iter(|| criterion::black_box(store.is_blocked(&miss, "global")));
    });
    group.bench_function("block_admission_steady_state", |b| {
        let mut i = 0u32;
        b.iter(|| {
            i += 1;
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + (i % 512)));
            criterion::black_box(store.block_ip_with_provenance(
                ip,
                "bench",
                3600,
                "global",
                provenance.clone(),
            ));
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_atomic_bucket,
    benchmark_ring_buffer,
    benchmark_collections,
    benchmark_vec_contains,
    benchmark_sliding_limiter,
    benchmark_blockstore_lookup
);
criterion_main!(benches);

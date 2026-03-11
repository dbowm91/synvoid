use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlidingDecision {
    Allowed,
    Limited,
}

pub struct AtomicBucketWindow {
    buckets: Vec<AtomicU32>,
    bucket_count: usize,
    bucket_duration_ms: u64,
    current_bucket: std::sync::atomic::AtomicU64,
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
            current_bucket: std::sync::atomic::AtomicU64::new(0),
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

pub struct RingBuffer {
    data: Vec<u64>,
}

impl RingBuffer {
    pub fn with_capacity(_capacity: usize) -> Self {
        Self { data: Vec::new() }
    }

    pub fn push(&mut self, value: u64) {
        self.data.push(value);
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

fn main() {
    println!("Running rate limiting benchmarks...\n");

    println!("=== AtomicBucketWindow Benchmark ===");
    let window = Arc::new(AtomicBucketWindow::new(60, 60));

    let start = Instant::now();
    for _ in 0..100_000 {
        window.increment();
    }
    let elapsed = start.elapsed();
    println!(
        "  increment(): {:.3}ns/op (100K ops)",
        elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
    );

    let start = Instant::now();
    for _ in 0..100_000 {
        window.get_count();
    }
    let elapsed = start.elapsed();
    println!(
        "  get_count(): {:.3}ns/op (100K ops)",
        elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
    );

    let start = Instant::now();
    for _ in 0..10_000 {
        window.sum_all_buckets();
    }
    let elapsed = start.elapsed();
    println!(
        "  sum_all_buckets(): {:.3}µs/op (10K ops)",
        elapsed.as_secs_f64() * 1_000_000.0 / 10_000.0
    );

    println!("\n=== RingBuffer Benchmark ===");
    let mut buffer = RingBuffer::with_capacity(100);

    let start = Instant::now();
    for i in 0..100_000 {
        buffer.push(i);
    }
    let elapsed = start.elapsed();
    println!(
        "  push(): {:.3}ns/op (100K ops)",
        elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
    );

    println!("\n=== HashMap Lookup Benchmark ===");
    use std::collections::{HashMap, HashSet};
    let mut map: HashMap<String, u32> = HashMap::new();
    for i in 0..1000 {
        map.insert(format!("key_{}", i), i);
    }

    let start = Instant::now();
    for _ in 0..100_000 {
        let _ = map.get("key_500");
    }
    let elapsed = start.elapsed();
    println!(
        "  HashMap get (1000 entries): {:.3}ns/op (100K ops)",
        elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
    );

    let mut set: HashSet<String> = (0..1000).map(|i| format!("key_{}", i)).collect();

    let start = Instant::now();
    for _ in 0..100_000 {
        let _ = set.contains("key_500");
    }
    let elapsed = start.elapsed();
    println!(
        "  HashSet contains (1000 entries): {:.3}ns/op (100K ops)",
        elapsed.as_secs_f64() * 1_000_000_000.0 / 100_000.0
    );

    println!("\n=== Vec::contains Benchmark (INEFFICIENT) ===");
    let vec: Vec<String> = (0..1000).map(|i| format!("key_{}", i)).collect();

    let start = Instant::now();
    for _ in 0..10_000 {
        let _ = vec.contains(&"key_500".to_string());
    }
    let elapsed = start.elapsed();
    println!(
        "  Vec::contains (1000 entries): {:.3}µs/op (10K ops)",
        elapsed.as_secs_f64() * 1_000_000.0 / 10_000.0
    );

    println!("\nDone!");
}

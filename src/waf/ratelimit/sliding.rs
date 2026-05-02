use std::hash::Hash;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

const DEFAULT_BUCKET_COUNT: u32 = 60;

#[derive(Debug, Clone)]
pub struct SlidingWindowConfig {
    pub window_secs: u32,
    pub bucket_count: u32,
    pub limit: u32,
}

impl SlidingWindowConfig {
    pub fn new(window_secs: u32, limit: u32) -> Self {
        let bucket_count = std::cmp::min(window_secs, DEFAULT_BUCKET_COUNT);
        Self {
            window_secs,
            bucket_count,
            limit,
        }
    }

    pub fn with_buckets(window_secs: u32, bucket_count: u32, limit: u32) -> Self {
        Self {
            window_secs,
            bucket_count: bucket_count.max(1),
            limit,
        }
    }
}

impl Default for SlidingWindowConfig {
    fn default() -> Self {
        Self::new(60, 100)
    }
}

pub struct AtomicBucketWindow {
    buckets: Box<[AtomicU32]>,
    bucket_count: u32,
    bucket_duration_ms: u64,
    current_bucket: AtomicU64,
    start_ms: u64,
}

impl AtomicBucketWindow {
    pub fn new(window_secs: u32, bucket_count: u32) -> Self {
        let bucket_count = bucket_count.max(1);
        let buckets: Vec<AtomicU32> = (0..bucket_count).map(|_| AtomicU32::new(0)).collect();
        let bucket_duration_ms = (window_secs as u64 * 1000) / bucket_count as u64;

        Self {
            buckets: buckets.into_boxed_slice(),
            bucket_count,
            bucket_duration_ms,
            current_bucket: AtomicU64::new(0),
            start_ms: Instant::now().elapsed().as_millis() as u64,
        }
    }

    #[inline]
    pub fn increment(&self) -> u32 {
        let now_ms = Instant::now().elapsed().as_millis() as u64 - self.start_ms;
        let bucket_idx = self.rotate_and_get_bucket(now_ms);

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed) + 1
    }

    #[inline]
    pub fn get_count(&self) -> u32 {
        let now_ms = Instant::now().elapsed().as_millis() as u64 - self.start_ms;
        self.rotate_and_get_bucket(now_ms);

        self.sum_buckets()
    }

    #[inline]
    fn rotate_and_get_bucket(&self, now_ms: u64) -> usize {
        let new_bucket = now_ms / self.bucket_duration_ms;

        loop {
            let last_bucket = self.current_bucket.load(Ordering::Acquire);

            if new_bucket <= last_bucket {
                break;
            }

            let successful = self
                .current_bucket
                .compare_exchange(last_bucket, new_bucket, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok();

            if successful {
                let buckets_to_clear =
                    std::cmp::min((new_bucket - last_bucket) as u32, self.bucket_count);

                for i in 0..buckets_to_clear {
                    let idx = ((last_bucket + i as u64) % self.bucket_count as u64) as usize;
                    self.buckets[idx].store(0, Ordering::Release);
                }
                break;
            }
        }

        ((now_ms / self.bucket_duration_ms) % self.bucket_count as u64) as usize
    }

    #[inline]
    fn sum_buckets(&self) -> u32 {
        let mut total = 0u32;
        for bucket in self.buckets.iter() {
            total += bucket.load(Ordering::Relaxed);
        }
        total
    }

    pub fn reset(&self) {
        for bucket in self.buckets.iter() {
            bucket.store(0, Ordering::Relaxed);
        }
    }
}

pub struct SlidingWindowEntry {
    windows: Vec<AtomicBucketWindow>,
}

impl SlidingWindowEntry {
    fn new(configs: &[SlidingWindowConfig]) -> Self {
        let windows = configs
            .iter()
            .map(|cfg| AtomicBucketWindow::new(cfg.window_secs, cfg.bucket_count))
            .collect();

        Self { windows }
    }

    #[inline]
    pub fn check_and_increment(
        &self,
        configs: &[SlidingWindowConfig],
    ) -> Option<(&'static str, u32)> {
        for (i, window) in self.windows.iter().enumerate() {
            let count = window.increment();
            if count > configs[i].limit {
                return Some((Self::limit_type(i), configs[i].limit));
            }
        }
        None
    }

    #[inline]
    pub fn get_counts(&self) -> Vec<u32> {
        self.windows.iter().map(|w| w.get_count()).collect()
    }

    #[inline]
    fn limit_type(idx: usize) -> &'static str {
        match idx {
            0 => "sliding_per_second",
            1 => "sliding_per_minute",
            2 => "sliding_per_hour",
            _ => "sliding_unknown",
        }
    }
}

pub struct SlidingWindowLimiter<K: Hash + Eq> {
    entries: parking_lot::RwLock<std::collections::HashMap<K, SlidingWindowEntry>>,
    configs: Vec<SlidingWindowConfig>,
    max_entries: usize,
    cleanup_threshold: f64,
}

impl<K: Hash + Eq + Clone> SlidingWindowLimiter<K> {
    pub fn new(configs: Vec<SlidingWindowConfig>, max_entries: usize) -> Self {
        Self {
            entries: parking_lot::RwLock::new(std::collections::HashMap::with_capacity_and_hasher(
                max_entries.next_power_of_two().max(64) as usize,
                std::hash::RandomState::default(),
            )),
            configs,
            max_entries,
            cleanup_threshold: 0.9,
        }
    }

    pub fn check_and_increment(&self, key: &K) -> SlidingDecision {
        let is_limited = {
            let mut entries = self.entries.write();
            let entry = entries
                .entry(key.clone())
                .or_insert_with(|| SlidingWindowEntry::new(&self.configs));

            if let Some((limit_type, limit)) = entry.check_and_increment(&self.configs) {
                return SlidingDecision::Limited {
                    limit_type,
                    current: limit,
                };
            }
            false
        };

        if is_limited {
            return SlidingDecision::Allowed;
        }

        if self.entries.read().len() > self.max_entries {
            self.maybe_cleanup();
        }

        SlidingDecision::Allowed
    }

    pub fn get_count(&self, key: &K) -> Option<Vec<u32>> {
        self.entries.read().get(key).map(|e| e.get_counts())
    }

    pub fn get_entry_count(&self) -> usize {
        self.entries.read().len()
    }

    fn maybe_cleanup(&self) {
        let mut entries = self.entries.write();
        if entries.len() > (self.max_entries as f64 * self.cleanup_threshold) as usize {
            entries.retain(|_, entry| {
                let counts = entry.get_counts();
                counts.iter().any(|&c| c > 0)
            });
        }
    }

    pub fn remove(&self, key: &K) {
        self.entries.write().remove(key);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlidingDecision {
    Allowed,
    Limited {
        limit_type: &'static str,
        current: u32,
    },
}

impl SlidingDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, SlidingDecision::Allowed)
    }

    pub fn is_limited(&self) -> bool {
        !self.is_allowed()
    }
}

pub struct MultiWindowSlidingLimiter {
    second_window: AtomicBucketWindow,
    minute_window: AtomicBucketWindow,
    hour_window: AtomicBucketWindow,
    per_second_limit: u32,
    per_minute_limit: u32,
    per_hour_limit: u32,
}

impl MultiWindowSlidingLimiter {
    pub fn new(per_second: u32, per_minute: u32, per_hour: u32) -> Self {
        Self {
            second_window: AtomicBucketWindow::new(1, 10),
            minute_window: AtomicBucketWindow::new(60, 60),
            hour_window: AtomicBucketWindow::new(3600, 60),
            per_second_limit: per_second,
            per_minute_limit: per_minute,
            per_hour_limit: per_hour,
        }
    }

    pub fn check(&self) -> SlidingGlobalDecision {
        let second_count = self.second_window.increment();
        if second_count > self.per_second_limit {
            return SlidingGlobalDecision::Limited {
                limit_type: "global_sliding_per_second",
                retry_after_ms: 1000,
            };
        }

        let minute_count = self.minute_window.get_count();
        if minute_count > self.per_minute_limit {
            return SlidingGlobalDecision::Limited {
                limit_type: "global_sliding_per_minute",
                retry_after_ms: 60000,
            };
        }

        let hour_count = self.hour_window.get_count();
        if hour_count > self.per_hour_limit {
            return SlidingGlobalDecision::Limited {
                limit_type: "global_sliding_per_hour",
                retry_after_ms: 3600000,
            };
        }

        SlidingGlobalDecision::Allowed
    }

    pub fn get_stats(&self) -> GlobalSlidingStats {
        GlobalSlidingStats {
            per_second: self.second_window.get_count(),
            per_minute: self.minute_window.get_count(),
            per_hour: self.hour_window.get_count(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlidingGlobalDecision {
    Allowed,
    Limited {
        limit_type: &'static str,
        retry_after_ms: u64,
    },
}

impl SlidingGlobalDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, SlidingGlobalDecision::Allowed)
    }
}

#[derive(Debug, Clone)]
pub struct GlobalSlidingStats {
    pub per_second: u32,
    pub per_minute: u32,
    pub per_hour: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::thread;

    #[test]
    fn test_atomic_bucket_window_basic() {
        let window = AtomicBucketWindow::new(1, 10);

        let count = window.increment();
        assert_eq!(count, 1);

        let count = window.increment();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_atomic_bucket_window_rotation() {
        let window = AtomicBucketWindow::new(1, 10);

        for _ in 0..5 {
            window.increment();
        }

        assert_eq!(window.get_count(), 5);
    }

    #[test]
    fn test_sliding_window_limiter_ip() {
        let configs = vec![
            SlidingWindowConfig::new(1, 10),
            SlidingWindowConfig::new(60, 100),
        ];
        let limiter: SlidingWindowLimiter<IpAddr> = SlidingWindowLimiter::new(configs, 1000);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            assert_eq!(limiter.check_and_increment(&ip), SlidingDecision::Allowed);
        }
    }

    #[test]
    fn test_sliding_window_limiter_limit() {
        let configs = vec![SlidingWindowConfig::new(1, 3)];
        let limiter: SlidingWindowLimiter<IpAddr> = SlidingWindowLimiter::new(configs, 1000);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert_eq!(limiter.check_and_increment(&ip), SlidingDecision::Allowed);
        assert_eq!(limiter.check_and_increment(&ip), SlidingDecision::Allowed);
        assert_eq!(limiter.check_and_increment(&ip), SlidingDecision::Allowed);

        let decision = limiter.check_and_increment(&ip);
        assert!(matches!(decision, SlidingDecision::Limited { .. }));
    }

    #[test]
    fn test_sliding_window_different_keys() {
        let configs = vec![SlidingWindowConfig::new(1, 5)];
        let limiter: SlidingWindowLimiter<IpAddr> = SlidingWindowLimiter::new(configs, 1000);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        for _ in 0..5 {
            assert_eq!(limiter.check_and_increment(&ip1), SlidingDecision::Allowed);
        }

        assert_eq!(limiter.check_and_increment(&ip2), SlidingDecision::Allowed);
    }

    #[test]
    fn test_multi_window_sliding_limiter() {
        let limiter = MultiWindowSlidingLimiter::new(10, 100, 1000);

        for _ in 0..5 {
            assert_eq!(limiter.check(), SlidingGlobalDecision::Allowed);
        }
    }

    #[test]
    fn test_multi_window_concurrent() {
        use std::sync::Arc;

        let limiter = Arc::new(MultiWindowSlidingLimiter::new(1000, 10000, 100000));
        let limiter_clone = limiter.clone();

        let handle = thread::spawn(move || {
            for _ in 0..1000 {
                limiter_clone.check();
            }
        });

        for _ in 0..1000 {
            limiter.check();
        }

        handle.join().unwrap();

        let stats = limiter.get_stats();
        assert!(stats.per_second >= 1000);
    }

    #[test]
    fn test_sliding_window_config_defaults() {
        let config = SlidingWindowConfig::default();
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.bucket_count, 60);
    }

    #[test]
    fn test_sliding_window_with_custom_buckets() {
        let config = SlidingWindowConfig::with_buckets(60, 120, 200);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.bucket_count, 120);
        assert_eq!(config.limit, 200);
    }
}

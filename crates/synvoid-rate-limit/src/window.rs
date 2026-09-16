//! Monotonic sliding-window counter primitive.
//!
//! [`AtomicSlidingWindow`] is a lock-free bucketed event counter. Callers pass
//! an explicit millisecond tick, so window behavior is fully deterministic in
//! tests. Production callers derive the tick from [`WindowClock`] (monotonic)
//! or from their own monotonic baseline.
//!
//! Rotation contract:
//!
//! - exactly one concurrent caller wins rotation per bucket advance
//!   (compare-exchange on the last-rotated marker);
//! - the winner clears at most `bucket_count` stale buckets, addressed as
//!   `(last_rotate + 1 + i) % bucket_count` with wrapping arithmetic;
//! - the running sum is decremented with saturating subtraction, so
//!   concurrent rotation can never underflow it;
//! - a time jump larger than the whole window clears every bucket;
//! - degenerate configuration is clamped (`bucket_count >= 1`,
//!   `bucket_duration_ms >= 1`, saturating duration multiplication) instead of
//!   panicking on the request path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Monotonic millisecond tick source for [`AtomicSlidingWindow`].
///
/// Owning one clock per limiter (or sharing one explicitly) keeps every
/// window on the same baseline. Never substitute wall-clock milliseconds:
/// NTP steps or timezone-agnostic epoch math would corrupt rotation.
#[derive(Debug)]
pub struct WindowClock {
    start: Instant,
}

impl WindowClock {
    /// Starts a clock anchored at the current monotonic instant.
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Milliseconds elapsed since this clock was created (saturating).
    #[inline]
    pub fn now_ms(&self) -> u64 {
        self.start
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

impl Default for WindowClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy-neutral snapshot of one window against a caller-supplied limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowStats {
    /// Events currently inside the window.
    pub count: u64,
    /// The limit the caller is enforcing.
    pub limit: u64,
    /// `limit.saturating_sub(count)`.
    pub remaining: u64,
}

impl WindowStats {
    /// Builds a snapshot; `remaining` saturates at zero past the limit.
    pub fn new(count: u64, limit: u64) -> Self {
        Self {
            count,
            limit,
            remaining: limit.saturating_sub(count),
        }
    }

    /// Whether `count` is at or below the limit (exactly N is allowed).
    pub fn is_within_limit(&self) -> bool {
        self.count <= self.limit
    }
}

/// Lock-free sliding-window event counter over an explicit millisecond tick.
///
/// `bucket_count` buckets cover `window_duration_secs` seconds; each
/// increment lands in the bucket for its tick and the running sum tracks the
/// window total in O(1). All methods are wait-free except rotation, which is
/// resolved by a single compare-exchange winner.
pub struct AtomicSlidingWindow {
    buckets: Box<[AtomicU64]>,
    bucket_count: u64,
    bucket_duration_ms: u64,
    last_rotate_ms: AtomicU64,
    running_sum: AtomicU64,
}

impl AtomicSlidingWindow {
    /// Creates a window covering `window_duration_secs` seconds.
    ///
    /// Degenerate inputs are clamped, never panicking: `bucket_count` floors
    /// at 1, the duration multiplication saturates, and each bucket spans at
    /// least 1ms.
    pub fn new(window_duration_secs: u64, bucket_count: u64) -> Self {
        // Clamp degenerate inputs instead of panicking on the request path.
        let bucket_count = bucket_count.max(1);
        let buckets: Vec<AtomicU64> = (0..bucket_count).map(|_| AtomicU64::new(0)).collect();
        let bucket_duration_ms = (window_duration_secs.saturating_mul(1000) / bucket_count).max(1);

        Self {
            buckets: buckets.into_boxed_slice(),
            bucket_count,
            bucket_duration_ms,
            last_rotate_ms: AtomicU64::new(0),
            running_sum: AtomicU64::new(0),
        }
    }

    /// Number of buckets in the window.
    pub fn bucket_count(&self) -> u64 {
        self.bucket_count
    }

    /// Milliseconds covered by a single bucket.
    pub fn bucket_duration_ms(&self) -> u64 {
        self.bucket_duration_ms
    }

    /// Records one event at tick `now_ms`, returning the window total after it.
    pub fn increment_at(&self, now_ms: u64) -> u64 {
        self.rotate_buckets(now_ms);

        let bucket_idx = ((now_ms / self.bucket_duration_ms) % self.bucket_count) as usize;
        let _count = self.buckets[bucket_idx].fetch_add(1, Ordering::AcqRel) + 1;
        self.running_sum.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Returns the window total at tick `now_ms` after expiring stale buckets.
    pub fn count_at(&self, now_ms: u64) -> u64 {
        self.rotate_buckets(now_ms);
        self.running_sum.load(Ordering::Acquire)
    }

    /// Records one event at this clock's current tick.
    #[inline]
    pub fn increment_now(&self, clock: &WindowClock) -> u64 {
        self.increment_at(clock.now_ms())
    }

    /// Returns the window total at this clock's current tick.
    #[inline]
    pub fn count_now(&self, clock: &WindowClock) -> u64 {
        self.count_at(clock.now_ms())
    }

    /// Snapshots this window against a caller-supplied `limit` at `now_ms`.
    pub fn stats_at(&self, now_ms: u64, limit: u64) -> WindowStats {
        WindowStats::new(self.count_at(now_ms), limit)
    }

    /// Clears every bucket and the running sum.
    pub fn reset(&self) {
        for bucket in self.buckets.iter() {
            bucket.store(0, Ordering::Relaxed);
        }
        self.running_sum.store(0, Ordering::Relaxed);
    }

    fn rotate_buckets(&self, now_ms: u64) {
        let current_bucket = now_ms / self.bucket_duration_ms;
        let last_rotate = self.last_rotate_ms.load(Ordering::Acquire);

        if current_bucket > last_rotate
            && self
                .last_rotate_ms
                .compare_exchange(
                    last_rotate,
                    current_bucket,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            let buckets_to_clear = std::cmp::min(current_bucket - last_rotate, self.bucket_count);

            for i in 0..buckets_to_clear {
                let idx =
                    (last_rotate.wrapping_add(1).wrapping_add(i) % self.bucket_count) as usize;
                let cleared = self.buckets[idx].swap(0, Ordering::AcqRel);
                let _ = self
                    .running_sum
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                        v.saturating_sub(cleared).into()
                    });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_events_at_same_tick() {
        let window = AtomicSlidingWindow::new(1, 10);

        assert_eq!(window.increment_at(100), 1);
        assert_eq!(window.increment_at(150), 2);
        assert_eq!(window.count_at(150), 2);
    }

    #[test]
    fn boundary_at_exactly_limit_and_limit_plus_one() {
        let window = AtomicSlidingWindow::new(60, 60);
        let limit = 5u64;

        for expected in 1..=limit {
            let count = window.increment_at(1_000);
            assert_eq!(count, expected);
            assert!(window.stats_at(1_000, limit).is_within_limit());
        }
        let over = window.increment_at(1_000);
        assert_eq!(over, limit + 1);
        let stats = window.stats_at(1_000, limit);
        assert!(!stats.is_within_limit());
        assert_eq!(stats.remaining, 0);
    }

    #[test]
    fn window_expires_after_full_duration() {
        // 1s window / 10 buckets = 100ms per bucket.
        let window = AtomicSlidingWindow::new(1, 10);
        for _ in 0..3 {
            window.increment_at(100);
        }
        assert_eq!(window.count_at(100), 3);
        // Just inside the window the events survive.
        assert_eq!(window.count_at(1_099), 3);
        // Exactly one full window later every bucket is stale.
        assert_eq!(window.count_at(1_100), 0);
    }

    #[test]
    fn large_time_jump_clears_stale_buckets() {
        let window = AtomicSlidingWindow::new(60, 60);
        for _ in 0..7 {
            window.increment_at(5_000);
        }
        assert_eq!(window.count_at(5_000), 7);
        // A jump far beyond the window must clear everything, not wrap
        // stale counts back into view.
        assert_eq!(window.count_at(u64::MAX - 1), 0);
        // The window stays usable afterwards.
        assert_eq!(window.increment_at(u64::MAX - 1), 1);
    }

    #[test]
    fn rotation_clears_only_advancing_buckets_small_current() {
        // Regression: with current_bucket < bucket_count the cleared set is
        // (last_rotate+1..=current) mod bucket_count.
        let window = AtomicSlidingWindow::new(60, 60);
        window.buckets[2].store(10, Ordering::Relaxed);
        window.buckets[22].store(7, Ordering::Relaxed);
        window.running_sum.store(17, Ordering::Relaxed);

        window.rotate_buckets(5000);

        assert_eq!(window.buckets[2].load(Ordering::Relaxed), 0);
        assert_eq!(window.buckets[22].load(Ordering::Relaxed), 7);
        assert_eq!(window.running_sum.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn rotation_clears_only_advancing_buckets_partial() {
        // Regression: with current=100, last=95, bc=60 the advancing set is
        // 96..=100 mod 60 = 36..=40; bucket 44 must survive.
        let window = AtomicSlidingWindow::new(60, 60);
        window.last_rotate_ms.store(95, Ordering::Relaxed);
        window.buckets[36].store(5, Ordering::Relaxed);
        window.buckets[44].store(9, Ordering::Relaxed);
        window.running_sum.store(14, Ordering::Relaxed);

        window.rotate_buckets(100_000);

        assert_eq!(window.buckets[36].load(Ordering::Relaxed), 0);
        assert_eq!(window.buckets[44].load(Ordering::Relaxed), 9);
        assert_eq!(window.running_sum.load(Ordering::Relaxed), 9);
    }

    #[test]
    fn degenerate_configuration_is_clamped() {
        let window = AtomicSlidingWindow::new(0, 0);
        assert_eq!(window.bucket_count(), 1);
        assert_eq!(window.bucket_duration_ms(), 1);
        assert_eq!(window.increment_at(0), 1);
        assert_eq!(window.count_at(0), 1);

        let zero_window = AtomicSlidingWindow::new(0, 4);
        assert_eq!(zero_window.bucket_duration_ms(), 1);
        assert_eq!(zero_window.increment_at(10), 1);
    }

    #[test]
    fn saturating_duration_math_never_overflows() {
        // Extreme durations saturate instead of overflowing; the bucket count
        // stays caller-sized so no absurd allocation is attempted.
        let window = AtomicSlidingWindow::new(u64::MAX, 60);
        assert_eq!(window.bucket_count(), 60);
        assert!(window.bucket_duration_ms() >= 1);
        // Tick math divides before indexing, so extreme ticks stay in range.
        window.increment_at(u64::MAX);
        let _ = window.count_at(u64::MAX);
    }

    #[test]
    fn reset_clears_counts_and_stays_usable() {
        let window = AtomicSlidingWindow::new(1, 10);
        let _ = window.increment_at(100);
        let _ = window.increment_at(100);
        assert_eq!(window.count_at(100), 2);

        window.reset();
        assert_eq!(window.count_at(100), 0);
        assert_eq!(window.increment_at(100), 1);
    }

    #[test]
    fn stats_report_remaining_with_saturation() {
        let stats = WindowStats::new(3, 10);
        assert_eq!(stats.remaining, 7);
        assert!(stats.is_within_limit());

        let over = WindowStats::new(12, 10);
        assert_eq!(over.remaining, 0);
        assert!(!over.is_within_limit());
    }

    #[test]
    fn window_clock_is_monotonic_and_shared() {
        let clock = WindowClock::new();
        let first = clock.now_ms();
        let window = AtomicSlidingWindow::new(60, 60);
        assert_eq!(window.increment_now(&clock), 1);
        assert_eq!(window.count_now(&clock), 1);
        assert!(clock.now_ms() >= first);
    }

    #[test]
    fn concurrent_increments_at_same_tick_sum_exactly() {
        use std::sync::Arc;
        use std::thread;

        let window = Arc::new(AtomicSlidingWindow::new(60, 60));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let window = Arc::clone(&window);
            handles.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    window.increment_at(1_000);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker panicked");
        }
        assert_eq!(window.count_at(1_000), 8_000);
    }

    #[test]
    fn concurrent_increments_during_rotation_never_underflow() {
        use std::sync::Arc;
        use std::thread;

        // 10 buckets of 100ms: racing threads force rotation while others
        // increment, exercising the CAS-winner path and the saturating sum.
        let window = Arc::new(AtomicSlidingWindow::new(1, 10));
        let mut handles = Vec::new();
        for t in 0..8u64 {
            let window = Arc::clone(&window);
            handles.push(thread::spawn(move || {
                for i in 0..2_000u64 {
                    window.increment_at(t * 150 + (i % 25) * 100);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker panicked");
        }
        // Every recorded event is either still counted or was legitimately
        // expired by rotation; the sum can never wrap or exceed the total.
        let total = 8 * 2_000;
        let counted = window.count_at(200_000);
        assert!(counted <= total, "counted {counted} of {total}");
        let bucket_sum: u64 = window
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum();
        assert_eq!(
            bucket_sum,
            window.running_sum.load(Ordering::Relaxed),
            "bucket sum must track the running sum after racing rotation"
        );
    }

    #[test]
    fn deterministic_retry_timing_from_stats() {
        // A full 1s window frees exactly one window duration later; no sleep.
        let window = AtomicSlidingWindow::new(1, 10);
        let limit = 2u64;
        assert_eq!(window.increment_at(0), 1);
        assert_eq!(window.increment_at(0), 2);
        assert_eq!(window.increment_at(0), 3);
        assert!(!window.stats_at(0, limit).is_within_limit());
        assert!(window.stats_at(1_000, limit).is_within_limit());
    }
}

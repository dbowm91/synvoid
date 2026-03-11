use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::waf::ratelimit::sliding::AtomicBucketWindow;

#[derive(Debug, Clone, Copy, Default)]
pub struct ThreatMetrics {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub attacks_per_minute: u32,
    pub rate_limit_hits_per_minute: u32,
    pub blocked_per_minute: u32,
}

pub struct ThreatMetricsCollector {
    requests_per_second: AtomicBucketWindow,
    requests_per_minute: AtomicBucketWindow,
    attacks_per_minute: AtomicBucketWindow,
    rate_limit_hits: AtomicBucketWindow,
    blocked_requests: AtomicBucketWindow,
    total_requests: AtomicU64,
    total_attacks: AtomicU64,
    total_rate_limit_hits: AtomicU64,
    total_blocked: AtomicU64,
    start_time: Instant,
}

impl ThreatMetricsCollector {
    pub fn new() -> Self {
        Self {
            requests_per_second: AtomicBucketWindow::new(1, 10),
            requests_per_minute: AtomicBucketWindow::new(60, 60),
            attacks_per_minute: AtomicBucketWindow::new(60, 60),
            rate_limit_hits: AtomicBucketWindow::new(60, 60),
            blocked_requests: AtomicBucketWindow::new(60, 60),
            total_requests: AtomicU64::new(0),
            total_attacks: AtomicU64::new(0),
            total_rate_limit_hits: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    #[inline]
    pub fn record_request(&self) {
        self.requests_per_second.increment();
        self.requests_per_minute.increment();
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_attack(&self) {
        self.attacks_per_minute.increment();
        self.total_attacks.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_rate_limit_hit(&self) {
        self.rate_limit_hits.increment();
        self.total_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_blocked(&self) {
        self.blocked_requests.increment();
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_current_metrics(&self) -> ThreatMetrics {
        ThreatMetrics {
            requests_per_second: self.requests_per_second.get_count(),
            requests_per_minute: self.requests_per_minute.get_count(),
            attacks_per_minute: self.attacks_per_minute.get_count(),
            rate_limit_hits_per_minute: self.rate_limit_hits.get_count(),
            blocked_per_minute: self.blocked_requests.get_count(),
        }
    }

    pub fn get_total_counts(&self) -> (u64, u64, u64, u64) {
        (
            self.total_requests.load(Ordering::Relaxed),
            self.total_attacks.load(Ordering::Relaxed),
            self.total_rate_limit_hits.load(Ordering::Relaxed),
            self.total_blocked.load(Ordering::Relaxed),
        )
    }

    pub fn get_uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn reset(&self) {
        self.requests_per_second.reset();
        self.requests_per_minute.reset();
        self.attacks_per_minute.reset();
        self.rate_limit_hits.reset();
        self.blocked_requests.reset();
        self.total_requests.store(0, Ordering::Relaxed);
        self.total_attacks.store(0, Ordering::Relaxed);
        self.total_rate_limit_hits.store(0, Ordering::Relaxed);
        self.total_blocked.store(0, Ordering::Relaxed);
    }
}

impl Default for ThreatMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_request() {
        let collector = ThreatMetricsCollector::new();

        collector.record_request();
        collector.record_request();

        let metrics = collector.get_current_metrics();
        assert_eq!(metrics.requests_per_minute, 2);
    }

    #[test]
    fn test_record_attack() {
        let collector = ThreatMetricsCollector::new();

        collector.record_attack();
        collector.record_attack();
        collector.record_attack();

        let metrics = collector.get_current_metrics();
        assert_eq!(metrics.attacks_per_minute, 3);
    }

    #[test]
    fn test_combined_metrics() {
        let collector = ThreatMetricsCollector::new();

        collector.record_request();
        collector.record_request();
        collector.record_attack();
        collector.record_rate_limit_hit();

        let metrics = collector.get_current_metrics();
        assert_eq!(metrics.requests_per_minute, 2);
        assert_eq!(metrics.attacks_per_minute, 1);
        assert_eq!(metrics.rate_limit_hits_per_minute, 1);
    }

    #[test]
    fn test_total_counts() {
        let collector = ThreatMetricsCollector::new();

        for _ in 0..100 {
            collector.record_request();
        }
        for _ in 0..5 {
            collector.record_attack();
        }

        let totals = collector.get_total_counts();
        assert_eq!(totals.0, 100);
        assert_eq!(totals.1, 5);
    }
}

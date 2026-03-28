use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::waf::ratelimit::core::AtomicSlidingWindow;

pub struct MeshPeerRateLimiter {
    per_second: AtomicSlidingWindow,
    per_minute: AtomicSlidingWindow,
    per_hour: AtomicSlidingWindow,
}

impl MeshPeerRateLimiter {
    pub fn new(
        messages_per_second: usize,
        messages_per_minute: usize,
        messages_per_hour: usize,
    ) -> Self {
        Self {
            per_second: AtomicSlidingWindow::new(1, 10),
            per_minute: AtomicSlidingWindow::new(60, 60),
            per_hour: AtomicSlidingWindow::new(3600, 60),
        }
    }

    pub fn check(&self) -> RateLimitCheck {
        let now_ms = crate::utils::safe_unix_duration().as_millis() as u64;

        let second_count = self.per_second.get_count(now_ms);
        let minute_count = self.per_minute.get_count(now_ms);
        let hour_count = self.per_hour.get_count(now_ms);

        RateLimitCheck {
            allowed: true,
            current_second: second_count,
            current_minute: minute_count,
            current_hour: hour_count,
        }
    }

    pub fn record(&self) {
        let now_ms = crate::utils::safe_unix_duration().as_millis() as u64;

        self.per_second.increment(now_ms);
        self.per_minute.increment(now_ms);
        self.per_hour.increment(now_ms);
    }
}

pub struct RateLimitCheck {
    pub allowed: bool,
    pub current_second: u64,
    pub current_minute: u64,
    pub current_hour: u64,
}

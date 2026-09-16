use synvoid_rate_limit::{AtomicSlidingWindow, WindowClock};

/// Per-peer mesh admission policy over the shared sliding-window mechanism.
///
/// Windows and bucket counts are unchanged from the pre-extraction shape;
/// only the counter implementation moved (previously a no-op stub) and the
/// tick source is now monotonic instead of wall-clock. Mesh trust/reputation
/// decisions stay here; the window only reports counts.
pub struct MeshPeerRateLimiter {
    per_second: AtomicSlidingWindow,
    per_minute: AtomicSlidingWindow,
    per_hour: AtomicSlidingWindow,
    clock: WindowClock,
    max_per_second: u64,
    max_per_minute: u64,
    max_per_hour: u64,
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
            clock: WindowClock::new(),
            max_per_second: messages_per_second as u64,
            max_per_minute: messages_per_minute as u64,
            max_per_hour: messages_per_hour as u64,
        }
    }

    pub fn check(&self) -> RateLimitCheck {
        let second_count = self.per_second.count_now(&self.clock);
        let minute_count = self.per_minute.count_now(&self.clock);
        let hour_count = self.per_hour.count_now(&self.clock);

        RateLimitCheck {
            allowed: second_count < self.max_per_second
                && minute_count < self.max_per_minute
                && hour_count < self.max_per_hour,
            current_second: second_count,
            current_minute: minute_count,
            current_hour: hour_count,
        }
    }

    pub fn record(&self) {
        self.per_second.increment_now(&self.clock);
        self.per_minute.increment_now(&self.clock);
        self.per_hour.increment_now(&self.clock);
    }
}

pub struct RateLimitCheck {
    pub allowed: bool,
    pub current_second: u64,
    pub current_minute: u64,
    pub current_hour: u64,
}

#[cfg(test)]
mod tests {
    use super::MeshPeerRateLimiter;

    #[test]
    fn configured_limits_are_enforced() {
        let limiter = MeshPeerRateLimiter::new(2, 10, 10);
        assert!(limiter.check().allowed);
        limiter.record();
        assert!(limiter.check().allowed);
        limiter.record();
        assert!(!limiter.check().allowed);
    }
}

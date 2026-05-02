use crate::utils::now_ms;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

pub struct TokenBucket {
    capacity: u64,
    available: AtomicU64,
    refill_rate: AtomicU64,
    refill_interval_ms: u64,
    last_refill: AtomicU64,
    #[cfg(test)]
    time_offset_ms: AtomicI64,
}

impl TokenBucket {
    pub fn new(
        capacity_bytes: u64,
        refill_rate_bytes_per_sec: u64,
        refill_interval_ms: u64,
    ) -> Self {
        Self {
            capacity: capacity_bytes,
            available: AtomicU64::new(capacity_bytes),
            refill_rate: AtomicU64::new(refill_rate_bytes_per_sec),
            refill_interval_ms,
            last_refill: AtomicU64::new(now_ms()),
            #[cfg(test)]
            time_offset_ms: AtomicI64::new(0),
        }
    }

    #[cfg(test)]
    pub fn advance_time(&self, ms: u64) {
        self.time_offset_ms.fetch_add(ms as i64, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn now_ms_with_offset(&self) -> u64 {
        let base = now_ms() as i64;
        (base + self.time_offset_ms.load(Ordering::Relaxed)) as u64
    }

    pub fn try_consume(&self, bytes: u64) -> bool {
        self.refill();

        let current = self.available.load(Ordering::Acquire);
        if current >= bytes {
            let new = current - bytes;
            self.available.store(new, Ordering::Release);
            true
        } else {
            false
        }
    }

    pub fn consume(&self, bytes: u64) -> Duration {
        loop {
            self.refill();

            let current = self.available.load(Ordering::Acquire);
            if current >= bytes {
                let new = current - bytes;
                if self
                    .available
                    .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Duration::ZERO;
                }
            } else {
                let deficit = bytes - current;
                let refill_rate = self.refill_rate.load(Ordering::Acquire);
                let wait_ms = (deficit * 1000) / refill_rate.max(1);
                std::thread::sleep(Duration::from_millis(wait_ms.min(1000)));
            }
        }
    }

    pub fn available_tokens(&self) -> u64 {
        self.refill();
        self.available.load(Ordering::Acquire)
    }

    pub fn set_rate(&self, refill_rate_bytes_per_sec: u64) {
        self.refill();
        self.refill_rate
            .store(refill_rate_bytes_per_sec, Ordering::Release);
    }

    fn refill(&self) {
        #[cfg(test)]
        let now = self.now_ms_with_offset();
        #[cfg(not(test))]
        let now = now_ms();
        let last = self.last_refill.load(Ordering::Acquire);

        if now >= last + self.refill_interval_ms
            && self
                .last_refill
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let elapsed_ms = now - last;
            let refill_rate = self.refill_rate.load(Ordering::Acquire);
            let tokens_to_add = (elapsed_ms * refill_rate) / 1000;
            let current = self.available.load(Ordering::Acquire);
            let new = (current + tokens_to_add).min(self.capacity);
            self.available.store(new, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(100, 50, 100);

        assert!(bucket.try_consume(50));
        assert!(bucket.try_consume(30));
        assert!(!bucket.try_consume(30));

        bucket.advance_time(600);

        assert!(bucket.try_consume(50));
    }

    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(100, 1000, 50);

        bucket.try_consume(50);
        assert_eq!(bucket.available_tokens(), 50);

        bucket.advance_time(100);

        let available = bucket.available_tokens();
        assert!(available >= 50);
    }
}

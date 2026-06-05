use synvoid_utils::now_ms;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct AsyncTokenBucket {
    capacity: u64,
    available: AtomicU64,
    refill_rate: AtomicU64,
    refill_interval_ms: u64,
    last_refill: AtomicU64,
}

impl AsyncTokenBucket {
    pub fn new(
        capacity_bytes: u64,
        refill_rate_bytes_per_sec: u64,
        refill_interval_ms: u64,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            capacity: capacity_bytes,
            available: AtomicU64::new(capacity_bytes),
            refill_rate: AtomicU64::new(refill_rate_bytes_per_sec),
            refill_interval_ms,
            last_refill: AtomicU64::new(now_ms()),
        })
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

    pub async fn consume(&self, bytes: u64) {
        loop {
            if self.try_consume(bytes) {
                return;
            }

            let current = self.available.load(Ordering::Acquire);
            let deficit = bytes.saturating_sub(current);
            let refill_rate = self.refill_rate.load(Ordering::Acquire);
            let wait_ms = (deficit * 1000) / refill_rate.max(1);
            tokio::time::sleep(tokio::time::Duration::from_millis(wait_ms.min(1000))).await;
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

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    fn refill(&self) {
        let now = now_ms();
        let last = self.last_refill.load(Ordering::Acquire);

        if now >= last + self.refill_interval_ms
            && self
                .last_refill
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let elapsed_ms = now.saturating_sub(last);
            let refill_rate = self.refill_rate.load(Ordering::Acquire);
            let tokens_to_add = (elapsed_ms * refill_rate) / 1000;
            let current = self.available.load(Ordering::Acquire);
            let new = (current + tokens_to_add).min(self.capacity);
            self.available.store(new, Ordering::Release);
        }
    }
}

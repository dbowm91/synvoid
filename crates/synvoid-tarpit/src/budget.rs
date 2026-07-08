use crate::config::BudgetConfig;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Snapshot of current budget consumption.
#[derive(Debug, Clone)]
pub struct BudgetState {
    pub chunks_sent: u64,
    pub bytes_sent: u64,
    pub elapsed_secs: u64,
    pub idle_secs: u64,
}

/// Tracks budget consumption for a single tarpit session.
pub struct SessionBudget {
    config: BudgetConfig,
    start: Instant,
    last_activity: Mutex<Instant>,
    chunks_sent: AtomicU64,
    bytes_sent: AtomicU64,
}

impl SessionBudget {
    pub fn new(config: BudgetConfig) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            config,
            start: now,
            last_activity: Mutex::new(now),
            chunks_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        })
    }

    /// Record that a chunk of `len` bytes was sent.
    ///
    /// Returns `false` if any budget limit has been exceeded (duration, chunks, or bytes),
    /// indicating the session should be terminated.
    pub fn record_chunk(&self, len: usize) -> bool {
        let chunks = self.chunks_sent.fetch_add(1, Ordering::Relaxed) + 1;
        let bytes = self.bytes_sent.fetch_add(len as u64, Ordering::Relaxed) + len as u64;

        *self.last_activity.lock() = Instant::now();

        if chunks >= self.config.max_chunks {
            return false;
        }
        if bytes >= self.config.max_bytes {
            return false;
        }
        if self.start.elapsed().as_secs() >= self.config.max_duration_secs {
            return false;
        }

        true
    }

    /// Check if the session has exceeded its duration budget.
    pub fn is_expired(&self) -> bool {
        self.start.elapsed().as_secs() >= self.config.max_duration_secs
    }

    /// Check if the session has been idle for longer than `max_idle_secs`.
    pub fn is_idle(&self) -> bool {
        let last = *self.last_activity.lock();
        last.elapsed().as_secs() >= self.config.max_idle_secs
    }

    /// Number of chunks sent so far.
    pub fn chunks_sent(&self) -> u64 {
        self.chunks_sent.load(Ordering::Relaxed)
    }

    /// Total bytes sent so far.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Seconds since the session started.
    pub fn elapsed_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    /// Take a snapshot of current consumption.
    pub fn state(&self) -> BudgetState {
        BudgetState {
            chunks_sent: self.chunks_sent(),
            bytes_sent: self.bytes_sent(),
            elapsed_secs: self.elapsed_secs(),
            idle_secs: self.last_activity.lock().elapsed().as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_budget(max_chunks: u64, max_bytes: u64, max_duration_secs: u64) -> BudgetConfig {
        BudgetConfig {
            max_chunks,
            max_bytes,
            max_duration_secs,
            max_idle_secs: 60,
            write_timeout_ms: 5000,
        }
    }

    #[test]
    fn record_chunk_within_budget() {
        let budget = SessionBudget::new(test_budget(10, 1024, 600));
        assert!(budget.record_chunk(100));
        assert_eq!(budget.chunks_sent(), 1);
        assert_eq!(budget.bytes_sent(), 100);
    }

    #[test]
    fn reject_after_max_chunks() {
        let budget = SessionBudget::new(test_budget(2, 1024, 600));
        assert!(budget.record_chunk(10)); // chunks=1, < 2
        assert!(!budget.record_chunk(10)); // chunks=2, >= 2
    }

    #[test]
    fn reject_after_max_bytes() {
        let budget = SessionBudget::new(test_budget(100, 50, 600));
        assert!(budget.record_chunk(30));
        assert!(!budget.record_chunk(30));
    }

    #[test]
    fn reject_after_duration() {
        let budget = SessionBudget::new(test_budget(1000, 1024 * 1024, 0));
        // max_duration_secs=0 means immediately expired
        assert!(!budget.record_chunk(10));
    }

    #[test]
    fn is_expired_zero_duration() {
        let budget = SessionBudget::new(test_budget(100, 1024, 0));
        assert!(budget.is_expired());
    }

    #[test]
    fn state_snapshot() {
        let budget = SessionBudget::new(test_budget(10, 1024, 600));
        budget.record_chunk(42);
        let state = budget.state();
        assert_eq!(state.chunks_sent, 1);
        assert_eq!(state.bytes_sent, 42);
    }
}

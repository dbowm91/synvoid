use std::sync::atomic::{AtomicUsize, Ordering};
#[allow(unused_imports)]
use std::sync::LazyLock;

/// Global governor for memory-intensive proxy operations.
///
/// Specifically used to limit the amount of memory consumed by concurrent
/// response buffering (TEE) for the cache.
pub struct GlobalCacheGovernor;

// Default to 512MB for concurrent cache buffering
const DEFAULT_MAX_BUFFERED_BYTES: usize = 512 * 1024 * 1024;

static CURRENT_BUFFERED_BYTES: AtomicUsize = AtomicUsize::new(0);
static MAX_BUFFERED_BYTES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_BUFFERED_BYTES);

impl GlobalCacheGovernor {
    /// Attempt to reserve space for buffering.
    /// Returns true if the reservation was successful.
    pub fn try_reserve(bytes: usize) -> bool {
        let max = MAX_BUFFERED_BYTES.load(Ordering::Relaxed);
        let mut current = CURRENT_BUFFERED_BYTES.load(Ordering::Relaxed);

        loop {
            if current + bytes > max {
                return false;
            }

            match CURRENT_BUFFERED_BYTES.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Release previously reserved space.
    pub fn release(bytes: usize) {
        CURRENT_BUFFERED_BYTES.fetch_sub(bytes, Ordering::SeqCst);
    }

    /// Update the maximum allowed buffered bytes.
    pub fn set_max_buffered_bytes(bytes: usize) {
        MAX_BUFFERED_BYTES.store(bytes, Ordering::SeqCst);
    }

    /// Get current memory usage for cache buffering.
    pub fn current_usage() -> usize {
        CURRENT_BUFFERED_BYTES.load(Ordering::Relaxed)
    }
}

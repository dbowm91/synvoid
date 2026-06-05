pub mod bandwidth;
pub mod health;
pub mod payloads;
pub mod types;

pub use bandwidth::{
    get_global_bandwidth_tracker, BandwidthPayload, BandwidthProtocol, BandwidthTracker,
    EgressDirection,
};
pub use payloads::*;
pub use types::*;

// Cache support items extracted from root's collection.rs to avoid circular dependencies
pub const LATENCY_SAMPLE_SIZE: usize = 1000;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

pub static STATIC_CACHE_HITS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
pub static STATIC_CACHE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub fn record_static_cache_hit() {
    STATIC_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_static_cache_miss() {
    STATIC_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}

pub fn get_static_cache_hits() -> u64 {
    STATIC_CACHE_HITS.load(Ordering::Relaxed)
}

pub fn get_static_cache_misses() -> u64 {
    STATIC_CACHE_MISSES.load(Ordering::Relaxed)
}

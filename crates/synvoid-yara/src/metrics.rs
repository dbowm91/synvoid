//! Engine-local observability counters.
//!
//! These counters live in the canonical YARA crate so the engine does not
//! depend back on upload/mesh metrics. Upload keeps its own upload-level
//! counters and may re-export these getters for dashboard continuity.

use std::sync::atomic::{AtomicU64, Ordering};

static SCAN_QUEUE_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static SCAN_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
static SCAN_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static RELOAD_SUCCESS: AtomicU64 = AtomicU64::new(0);
static RELOAD_FAILURE: AtomicU64 = AtomicU64::new(0);

pub fn increment_scan_queue_timeout() {
    SCAN_QUEUE_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_queue_full() {
    SCAN_QUEUE_FULL.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_timeout() {
    SCAN_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_yara_reload_success() {
    RELOAD_SUCCESS.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_yara_reload_failure() {
    RELOAD_FAILURE.fetch_add(1, Ordering::Relaxed);
}

pub fn get_scan_queue_timeout() -> u64 {
    SCAN_QUEUE_TIMEOUT.load(Ordering::Relaxed)
}

pub fn get_scan_queue_full() -> u64 {
    SCAN_QUEUE_FULL.load(Ordering::Relaxed)
}

pub fn get_scan_timeout() -> u64 {
    SCAN_TIMEOUT.load(Ordering::Relaxed)
}

pub fn get_yara_reload_success() -> u64 {
    RELOAD_SUCCESS.load(Ordering::Relaxed)
}

pub fn get_yara_reload_failure() -> u64 {
    RELOAD_FAILURE.load(Ordering::Relaxed)
}

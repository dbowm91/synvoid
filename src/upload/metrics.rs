use std::sync::atomic::{AtomicU64, Ordering};

pub static UPLOAD_RATE_LIMIT_EXCEEDED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SIGNATURE_MISMATCH: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_MALWARE_DETECTED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SIZE_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_TYPE_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn increment_rate_limit_exceeded() {
    UPLOAD_RATE_LIMIT_EXCEEDED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_signature_mismatch() {
    UPLOAD_SIGNATURE_MISMATCH.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_malware_detected() {
    UPLOAD_MALWARE_DETECTED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_size_rejected() {
    UPLOAD_SIZE_REJECTED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_type_rejected() {
    UPLOAD_TYPE_REJECTED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_upload_total() {
    UPLOAD_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn add_upload_bytes(bytes: u64) {
    UPLOAD_TOTAL_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn get_rate_limit_exceeded() -> u64 {
    UPLOAD_RATE_LIMIT_EXCEEDED.load(Ordering::Relaxed)
}

pub fn get_signature_mismatch() -> u64 {
    UPLOAD_SIGNATURE_MISMATCH.load(Ordering::Relaxed)
}

pub fn get_malware_detected() -> u64 {
    UPLOAD_MALWARE_DETECTED.load(Ordering::Relaxed)
}

pub fn get_size_rejected() -> u64 {
    UPLOAD_SIZE_REJECTED.load(Ordering::Relaxed)
}

pub fn get_type_rejected() -> u64 {
    UPLOAD_TYPE_REJECTED.load(Ordering::Relaxed)
}

pub fn get_upload_total() -> u64 {
    UPLOAD_TOTAL.load(Ordering::Relaxed)
}

pub fn get_upload_total_bytes() -> u64 {
    UPLOAD_TOTAL_BYTES.load(Ordering::Relaxed)
}

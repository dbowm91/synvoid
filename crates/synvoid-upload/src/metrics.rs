use std::sync::atomic::{AtomicU64, Ordering};

pub static UPLOAD_RATE_LIMIT_EXCEEDED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SIGNATURE_MISMATCH: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_MALWARE_DETECTED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SIZE_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_TYPE_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_CLEAN: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_MALICIOUS: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_DISABLED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_INDETERMINATE: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_FAIL_OPEN_ALLOWED: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_SCAN_QUARANTINE_ON_ERROR: AtomicU64 = AtomicU64::new(0);

pub static YARA_SCAN_QUEUE_TIMEOUT: AtomicU64 = AtomicU64::new(0);
pub static YARA_SCAN_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
pub static YARA_SCAN_TIMEOUT: AtomicU64 = AtomicU64::new(0);
pub static YARA_RELOAD_SUCCESS: AtomicU64 = AtomicU64::new(0);
pub static YARA_RELOAD_FAILURE: AtomicU64 = AtomicU64::new(0);

pub static ARCHIVE_INSPECTIONS: AtomicU64 = AtomicU64::new(0);
pub static ARCHIVE_ENTRIES_SCANNED: AtomicU64 = AtomicU64::new(0);
pub static ARCHIVE_MALWARE_DETECTED: AtomicU64 = AtomicU64::new(0);
pub static ARCHIVE_LIMIT_VIOLATIONS: AtomicU64 = AtomicU64::new(0);
pub static ARCHIVE_MALFORMED: AtomicU64 = AtomicU64::new(0);

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

pub fn increment_scan_clean() {
    UPLOAD_SCAN_CLEAN.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_malicious() {
    UPLOAD_SCAN_MALICIOUS.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_disabled() {
    UPLOAD_SCAN_DISABLED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_unavailable() {
    UPLOAD_SCAN_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_indeterminate() {
    UPLOAD_SCAN_INDETERMINATE.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_fail_open_allowed() {
    UPLOAD_SCAN_FAIL_OPEN_ALLOWED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_quarantine_on_error() {
    UPLOAD_SCAN_QUARANTINE_ON_ERROR.fetch_add(1, Ordering::Relaxed);
}

pub fn get_scan_clean() -> u64 {
    UPLOAD_SCAN_CLEAN.load(Ordering::Relaxed)
}

pub fn get_scan_malicious() -> u64 {
    UPLOAD_SCAN_MALICIOUS.load(Ordering::Relaxed)
}

pub fn get_scan_disabled() -> u64 {
    UPLOAD_SCAN_DISABLED.load(Ordering::Relaxed)
}

pub fn get_scan_unavailable() -> u64 {
    UPLOAD_SCAN_UNAVAILABLE.load(Ordering::Relaxed)
}

pub fn get_scan_indeterminate() -> u64 {
    UPLOAD_SCAN_INDETERMINATE.load(Ordering::Relaxed)
}

pub fn get_scan_fail_open_allowed() -> u64 {
    UPLOAD_SCAN_FAIL_OPEN_ALLOWED.load(Ordering::Relaxed)
}

pub fn get_scan_quarantine_on_error() -> u64 {
    UPLOAD_SCAN_QUARANTINE_ON_ERROR.load(Ordering::Relaxed)
}

pub fn increment_scan_queue_timeout() {
    YARA_SCAN_QUEUE_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_queue_full() {
    YARA_SCAN_QUEUE_FULL.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_scan_timeout() {
    YARA_SCAN_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_yara_reload_success() {
    YARA_RELOAD_SUCCESS.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_yara_reload_failure() {
    YARA_RELOAD_FAILURE.fetch_add(1, Ordering::Relaxed);
}

pub fn get_scan_queue_timeout() -> u64 {
    YARA_SCAN_QUEUE_TIMEOUT.load(Ordering::Relaxed)
}

pub fn get_scan_queue_full() -> u64 {
    YARA_SCAN_QUEUE_FULL.load(Ordering::Relaxed)
}

pub fn get_scan_timeout() -> u64 {
    YARA_SCAN_TIMEOUT.load(Ordering::Relaxed)
}

pub fn get_yara_reload_success() -> u64 {
    YARA_RELOAD_SUCCESS.load(Ordering::Relaxed)
}

pub fn get_yara_reload_failure() -> u64 {
    YARA_RELOAD_FAILURE.load(Ordering::Relaxed)
}

pub fn increment_archive_inspection() {
    ARCHIVE_INSPECTIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn add_archive_entries_scanned(count: u32) {
    ARCHIVE_ENTRIES_SCANNED.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn increment_archive_malware_detected() {
    ARCHIVE_MALWARE_DETECTED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_archive_limit_violation() {
    ARCHIVE_LIMIT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_archive_malformed() {
    ARCHIVE_MALFORMED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_archive_inspections() -> u64 {
    ARCHIVE_INSPECTIONS.load(Ordering::Relaxed)
}

pub fn get_archive_entries_scanned() -> u64 {
    ARCHIVE_ENTRIES_SCANNED.load(Ordering::Relaxed)
}

pub fn get_archive_malware_detected() -> u64 {
    ARCHIVE_MALWARE_DETECTED.load(Ordering::Relaxed)
}

pub fn get_archive_limit_violations() -> u64 {
    ARCHIVE_LIMIT_VIOLATIONS.load(Ordering::Relaxed)
}

pub fn get_archive_malformed() -> u64 {
    ARCHIVE_MALFORMED.load(Ordering::Relaxed)
}

//! Truthful ICMP observability (Phase 87, Workstream G).
//!
//! The pre-Phase-87 packet allow/block/rate-limit counter helpers were not
//! evidence of kernel packet outcomes — no backend called them, and only
//! the eBPF lane has real per-packet counters (exposed via
//! `EbpfFilter::get_stats`, a backend-specific API, not a core metric).
//! They are removed. What remains is lifecycle truth the manager can prove:
//! apply outcomes, drift detections, and verification observations.
//!
//! This module stays optional/caller-owned: the core enforcement contract
//! (`enforce::{ApplyReceipt, EnforcementReport}`) returns structured data
//! and never requires the `metrics` crate.

use metrics::{counter, gauge};

/// Filter lifecycle gauge, set by the admin enable/disable path.
pub fn icmp_filter_enabled(enabled: bool) {
    gauge!("synvoid.icmp.filter_enabled").set(if enabled { 1.0 } else { 0.0 });
}

/// Coarse lifecycle status gauge (`enabled`/`disabled`/`error`).
pub fn icmp_filter_status(status: &str) {
    gauge!("synvoid.icmp.filter_status").set(match status {
        "enabled" => 1.0,
        "disabled" => 0.0,
        "error" => -1.0,
        _ => 0.0,
    });
}

/// One apply attempt finished. `result` is one of `applied`,
/// `compile_rejected`, `install_failed`, `drifted`, `unknown`.
pub fn icmp_apply_finished(backend: &str, result: &str) {
    counter!("synvoid.icmp.apply_finished_total",
        "backend" => backend.to_string(), "result" => result.to_string())
    .increment(1);
}

/// Live state failed to match the applied generation.
pub fn icmp_drift_detected(backend: &str) {
    counter!("synvoid.icmp.drift_detected_total", "backend" => backend.to_string()).increment(1);
}

/// One verification observation. `state` is one of `applied`, `absent`,
/// `drifted`, `unknown`.
pub fn icmp_verification_observed(backend: &str, state: &str) {
    counter!("synvoid.icmp.verification_observed_total",
        "backend" => backend.to_string(), "state" => state.to_string())
    .increment(1);
}

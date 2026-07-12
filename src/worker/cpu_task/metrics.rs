// Submodule: CPU task metrics (static atomics + helpers).
//
// All `static` atomic globals live in this single file to avoid duplicate
// definitions across the cpu_task module tree.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use synvoid_ipc::{CpuOffloadStats, CpuTaskKind};
use synvoid_metrics::TimingStatsPayload;

pub static CPU_TASK_ACTIVE_MINIFY: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_ACTIVE_GET_COMPRESSED: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_ACTIVE_IMAGE_RIGHTS: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_ACTIVE_YARA_SCAN: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_ACTIVE_WASM_EXECUTE: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_ACTIVE_SERVERLESS_INVOKE: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_QUEUED_MINIFY: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_QUEUED_GET_COMPRESSED: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_QUEUED_IMAGE_RIGHTS: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_QUEUED_YARA_SCAN: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_QUEUED_WASM_EXECUTE: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_QUEUED_SERVERLESS_INVOKE: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_COMPLETED_MINIFY: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_COMPLETED_GET_COMPRESSED: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_COMPLETED_IMAGE_RIGHTS: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_COMPLETED_YARA_SCAN: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_COMPLETED_WASM_EXECUTE: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_COMPLETED_SERVERLESS_INVOKE: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_PAYLOAD_BYTES_IN_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_TIMEOUT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_SUBMITTED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static STATIC_CPU_OFFLOAD_EVENT_LOOP_LAG_MS: AtomicU64 = AtomicU64::new(0);
pub static CPU_TASK_DURATION_SAMPLES: LazyLock<Mutex<HashMap<&'static str, VecDeque<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub const CPU_TASK_DURATION_SAMPLE_SIZE: usize = 1000;

pub fn snapshot_static_cpu_offload_stats(worker_rss_bytes: u64) -> CpuOffloadStats {
    CpuOffloadStats {
        queued_minify: CPU_TASK_QUEUED_MINIFY.load(Ordering::Relaxed),
        queued_get_compressed: CPU_TASK_QUEUED_GET_COMPRESSED.load(Ordering::Relaxed),
        queued_poison_image: CPU_TASK_QUEUED_IMAGE_RIGHTS.load(Ordering::Relaxed),
        queued_yara_scan: CPU_TASK_QUEUED_YARA_SCAN.load(Ordering::Relaxed),
        queued_wasm_execute: CPU_TASK_QUEUED_WASM_EXECUTE.load(Ordering::Relaxed),
        queued_serverless_invoke: CPU_TASK_QUEUED_SERVERLESS_INVOKE.load(Ordering::Relaxed),
        active_minify: CPU_TASK_ACTIVE_MINIFY.load(Ordering::Relaxed),
        active_get_compressed: CPU_TASK_ACTIVE_GET_COMPRESSED.load(Ordering::Relaxed),
        active_poison_image: CPU_TASK_ACTIVE_IMAGE_RIGHTS.load(Ordering::Relaxed),
        active_yara_scan: CPU_TASK_ACTIVE_YARA_SCAN.load(Ordering::Relaxed),
        active_wasm_execute: CPU_TASK_ACTIVE_WASM_EXECUTE.load(Ordering::Relaxed),
        active_serverless_invoke: CPU_TASK_ACTIVE_SERVERLESS_INVOKE.load(Ordering::Relaxed),
        completed_minify: CPU_TASK_COMPLETED_MINIFY.load(Ordering::Relaxed),
        completed_get_compressed: CPU_TASK_COMPLETED_GET_COMPRESSED.load(Ordering::Relaxed),
        completed_poison_image: CPU_TASK_COMPLETED_IMAGE_RIGHTS.load(Ordering::Relaxed),
        completed_yara_scan: CPU_TASK_COMPLETED_YARA_SCAN.load(Ordering::Relaxed),
        completed_wasm_execute: CPU_TASK_COMPLETED_WASM_EXECUTE.load(Ordering::Relaxed),
        completed_serverless_invoke: CPU_TASK_COMPLETED_SERVERLESS_INVOKE.load(Ordering::Relaxed),
        payload_bytes_in_total: CPU_TASK_PAYLOAD_BYTES_IN_TOTAL.load(Ordering::Relaxed),
        payload_bytes_out_total: CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL.load(Ordering::Relaxed),
        rejected_total: CPU_TASK_REJECTED_TOTAL.load(Ordering::Relaxed),
        timeout_total: CPU_TASK_TIMEOUT_TOTAL.load(Ordering::Relaxed),
        failed_total: CPU_TASK_FAILED_TOTAL.load(Ordering::Relaxed),
        submitted_total: CPU_TASK_SUBMITTED_TOTAL.load(Ordering::Relaxed),
        fallback_inline_small_total: CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL.load(Ordering::Relaxed),
        task_duration_ms: summarize_cpu_task_durations(),
        event_loop_lag_ms: STATIC_CPU_OFFLOAD_EVENT_LOOP_LAG_MS.load(Ordering::Relaxed),
        worker_rss_bytes,
    }
}

pub fn increment_task_kind_queued(task_kind: CpuTaskKind) {
    match task_kind {
        CpuTaskKind::Minify => {
            CPU_TASK_QUEUED_MINIFY.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::GetCompressed => {
            CPU_TASK_QUEUED_GET_COMPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::PoisonImage => {
            CPU_TASK_QUEUED_IMAGE_RIGHTS.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::YaraScan => {
            CPU_TASK_QUEUED_YARA_SCAN.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::WasmExecute => {
            CPU_TASK_QUEUED_WASM_EXECUTE.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::ServerlessInvoke => {
            CPU_TASK_QUEUED_SERVERLESS_INVOKE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn decrement_task_kind_queued(task_kind: CpuTaskKind) {
    match task_kind {
        CpuTaskKind::Minify => {
            let _ =
                CPU_TASK_QUEUED_MINIFY
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        CpuTaskKind::GetCompressed => {
            let _ = CPU_TASK_QUEUED_GET_COMPRESSED.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        CpuTaskKind::PoisonImage => {
            let _ = CPU_TASK_QUEUED_IMAGE_RIGHTS.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        CpuTaskKind::YaraScan => {
            let _ =
                CPU_TASK_QUEUED_YARA_SCAN
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        CpuTaskKind::WasmExecute => {
            let _ = CPU_TASK_QUEUED_WASM_EXECUTE.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        CpuTaskKind::ServerlessInvoke => {
            let _ = CPU_TASK_QUEUED_SERVERLESS_INVOKE.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
    }
}

pub fn increment_task_kind_active(task_kind: CpuTaskKind) {
    match task_kind {
        CpuTaskKind::Minify => {
            CPU_TASK_ACTIVE_MINIFY.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::GetCompressed => {
            CPU_TASK_ACTIVE_GET_COMPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::PoisonImage => {
            CPU_TASK_ACTIVE_IMAGE_RIGHTS.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::YaraScan => {
            CPU_TASK_ACTIVE_YARA_SCAN.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::WasmExecute => {
            CPU_TASK_ACTIVE_WASM_EXECUTE.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::ServerlessInvoke => {
            CPU_TASK_ACTIVE_SERVERLESS_INVOKE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn decrement_task_kind_active(task_kind: CpuTaskKind) {
    match task_kind {
        CpuTaskKind::Minify => {
            let _ =
                CPU_TASK_ACTIVE_MINIFY
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        CpuTaskKind::GetCompressed => {
            let _ = CPU_TASK_ACTIVE_GET_COMPRESSED.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        CpuTaskKind::PoisonImage => {
            let _ = CPU_TASK_ACTIVE_IMAGE_RIGHTS.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        CpuTaskKind::YaraScan => {
            let _ =
                CPU_TASK_ACTIVE_YARA_SCAN
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        CpuTaskKind::WasmExecute => {
            let _ = CPU_TASK_ACTIVE_WASM_EXECUTE.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
        CpuTaskKind::ServerlessInvoke => {
            let _ = CPU_TASK_ACTIVE_SERVERLESS_INVOKE.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| v.checked_sub(1),
            );
        }
    }
}

pub fn increment_task_kind_completed(task_kind: CpuTaskKind) {
    match task_kind {
        CpuTaskKind::Minify => {
            CPU_TASK_COMPLETED_MINIFY.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::GetCompressed => {
            CPU_TASK_COMPLETED_GET_COMPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::PoisonImage => {
            CPU_TASK_COMPLETED_IMAGE_RIGHTS.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::YaraScan => {
            CPU_TASK_COMPLETED_YARA_SCAN.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::WasmExecute => {
            CPU_TASK_COMPLETED_WASM_EXECUTE.fetch_add(1, Ordering::Relaxed);
        }
        CpuTaskKind::ServerlessInvoke => {
            CPU_TASK_COMPLETED_SERVERLESS_INVOKE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn cpu_task_kind_label(task_kind: CpuTaskKind) -> &'static str {
    match task_kind {
        CpuTaskKind::Minify => "minify",
        CpuTaskKind::GetCompressed => "get_compressed",
        CpuTaskKind::PoisonImage => "image_rights",
        CpuTaskKind::YaraScan => "yara_scan",
        CpuTaskKind::WasmExecute => "wasm_execute",
        CpuTaskKind::ServerlessInvoke => "serverless_invoke",
    }
}

pub fn record_cpu_task_duration(task_kind: CpuTaskKind, duration_ms: u64) {
    let task_kind_label = cpu_task_kind_label(task_kind);
    let mut samples = CPU_TASK_DURATION_SAMPLES
        .lock()
        .expect("cpu task duration samples lock");
    let phase_samples = samples
        .entry(task_kind_label)
        .or_insert_with(|| VecDeque::with_capacity(CPU_TASK_DURATION_SAMPLE_SIZE));
    if phase_samples.len() >= CPU_TASK_DURATION_SAMPLE_SIZE {
        phase_samples.pop_front();
    }
    phase_samples.push_back(duration_ms);
}

pub fn summarize_timing_samples(samples: &[u64]) -> TimingStatsPayload {
    if samples.is_empty() {
        return TimingStatsPayload::default();
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let sum: u64 = sorted.iter().sum();
    let avg = sum as f64 / sorted.len() as f64;
    let p50 = sorted[sorted.len() / 2] as f64;
    let p95 = sorted[(sorted.len() as f64 * 0.95) as usize] as f64;
    let p99 = sorted[((sorted.len() as f64 * 0.99) as usize).min(sorted.len() - 1)] as f64;

    TimingStatsPayload {
        avg_ms: avg,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
    }
}

pub fn summarize_cpu_task_durations() -> HashMap<String, TimingStatsPayload> {
    let samples = CPU_TASK_DURATION_SAMPLES
        .lock()
        .expect("cpu task duration samples lock");
    let mut summary = HashMap::new();

    for (task_kind, durations) in samples.iter() {
        let durations: Vec<u64> = durations.iter().copied().collect();
        summary.insert(
            (*task_kind).to_string(),
            summarize_timing_samples(&durations),
        );
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_cpu_task_kind_label_mappings() {
        assert_eq!(cpu_task_kind_label(CpuTaskKind::Minify), "minify");
        assert_eq!(
            cpu_task_kind_label(CpuTaskKind::GetCompressed),
            "get_compressed"
        );
        assert_eq!(
            cpu_task_kind_label(CpuTaskKind::PoisonImage),
            "image_rights"
        );
        assert_eq!(cpu_task_kind_label(CpuTaskKind::YaraScan), "yara_scan");
        assert_eq!(
            cpu_task_kind_label(CpuTaskKind::WasmExecute),
            "wasm_execute"
        );
        assert_eq!(
            cpu_task_kind_label(CpuTaskKind::ServerlessInvoke),
            "serverless_invoke"
        );
    }

    #[test]
    fn test_increment_decrement_task_kind_active_for_new_variants() {
        let initial_wasm = CPU_TASK_ACTIVE_WASM_EXECUTE.load(Ordering::Relaxed);
        increment_task_kind_active(CpuTaskKind::WasmExecute);
        assert_eq!(
            CPU_TASK_ACTIVE_WASM_EXECUTE.load(Ordering::Relaxed),
            initial_wasm + 1
        );
        decrement_task_kind_active(CpuTaskKind::WasmExecute);
        assert_eq!(
            CPU_TASK_ACTIVE_WASM_EXECUTE.load(Ordering::Relaxed),
            initial_wasm
        );

        let initial_serverless = CPU_TASK_ACTIVE_SERVERLESS_INVOKE.load(Ordering::Relaxed);
        increment_task_kind_active(CpuTaskKind::ServerlessInvoke);
        assert_eq!(
            CPU_TASK_ACTIVE_SERVERLESS_INVOKE.load(Ordering::Relaxed),
            initial_serverless + 1
        );
        decrement_task_kind_active(CpuTaskKind::ServerlessInvoke);
        assert_eq!(
            CPU_TASK_ACTIVE_SERVERLESS_INVOKE.load(Ordering::Relaxed),
            initial_serverless
        );
    }

    #[test]
    fn test_increment_decrement_task_kind_queued_for_new_variants() {
        let initial_wasm = CPU_TASK_QUEUED_WASM_EXECUTE.load(Ordering::Relaxed);
        increment_task_kind_queued(CpuTaskKind::WasmExecute);
        assert_eq!(
            CPU_TASK_QUEUED_WASM_EXECUTE.load(Ordering::Relaxed),
            initial_wasm + 1
        );
        decrement_task_kind_queued(CpuTaskKind::WasmExecute);
        assert_eq!(
            CPU_TASK_QUEUED_WASM_EXECUTE.load(Ordering::Relaxed),
            initial_wasm
        );

        let initial_serverless = CPU_TASK_QUEUED_SERVERLESS_INVOKE.load(Ordering::Relaxed);
        increment_task_kind_queued(CpuTaskKind::ServerlessInvoke);
        assert_eq!(
            CPU_TASK_QUEUED_SERVERLESS_INVOKE.load(Ordering::Relaxed),
            initial_serverless + 1
        );
        decrement_task_kind_queued(CpuTaskKind::ServerlessInvoke);
        assert_eq!(
            CPU_TASK_QUEUED_SERVERLESS_INVOKE.load(Ordering::Relaxed),
            initial_serverless
        );
    }

    #[test]
    fn test_increment_task_kind_completed_for_new_variants() {
        let initial_wasm = CPU_TASK_COMPLETED_WASM_EXECUTE.load(Ordering::Relaxed);
        increment_task_kind_completed(CpuTaskKind::WasmExecute);
        assert_eq!(
            CPU_TASK_COMPLETED_WASM_EXECUTE.load(Ordering::Relaxed),
            initial_wasm + 1
        );
        CPU_TASK_COMPLETED_WASM_EXECUTE.store(initial_wasm, Ordering::Relaxed);

        let initial_serverless = CPU_TASK_COMPLETED_SERVERLESS_INVOKE.load(Ordering::Relaxed);
        increment_task_kind_completed(CpuTaskKind::ServerlessInvoke);
        assert_eq!(
            CPU_TASK_COMPLETED_SERVERLESS_INVOKE.load(Ordering::Relaxed),
            initial_serverless + 1
        );
        CPU_TASK_COMPLETED_SERVERLESS_INVOKE.store(initial_serverless, Ordering::Relaxed);
    }

    #[test]
    fn test_snapshot_static_cpu_offload_stats_includes_new_fields() {
        let stats = snapshot_static_cpu_offload_stats(2048);
        // These fields are u64 and can't be negative, just verify they exist
        let _ = stats.queued_wasm_execute;
        let _ = stats.active_wasm_execute;
        let _ = stats.queued_serverless_invoke;
        let _ = stats.active_serverless_invoke;
        assert_eq!(stats.worker_rss_bytes, 2048);
    }

    #[test]
    fn test_static_cpu_offload_task_duration_summary() {
        record_cpu_task_duration(CpuTaskKind::ServerlessInvoke, 10);
        record_cpu_task_duration(CpuTaskKind::ServerlessInvoke, 20);
        record_cpu_task_duration(CpuTaskKind::ServerlessInvoke, 30);

        let stats = snapshot_static_cpu_offload_stats(4096);
        let summary = stats
            .task_duration_ms
            .get("serverless_invoke")
            .expect("serverless_invoke summary should be present");

        assert_eq!(summary.avg_ms, 20.0);
        assert_eq!(summary.p50_ms, 20.0);
        assert_eq!(summary.p95_ms, 30.0);
        assert_eq!(summary.p99_ms, 30.0);
    }
}

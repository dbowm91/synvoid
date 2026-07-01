use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use parking_lot::Mutex;

static WASM_PLUGIN_INVOCATIONS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_DECISIONS_PASS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_DECISIONS_BLOCK: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_DECISIONS_CHALLENGE: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_ERRORS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_FUEL_CONSUMED: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_DURATIONS_MS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_POOL_HITS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_POOL_MISSES: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_POOL_DROPPED: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_FUEL_EXHAUSTED: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_EPOCH_TIMEOUTS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_HOST_CALL_TIMEOUTS: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static WASM_PLUGIN_FRESH_INSTANCES: LazyLock<Mutex<HashMap<String, AtomicU64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Default)]
pub struct WasmPluginMetrics {
    pub invocations: u64,
    pub decisions_pass: u64,
    pub decisions_block: u64,
    pub decisions_challenge: u64,
    pub errors: u64,
    pub fuel_consumed: u64,
    pub total_duration_ms: u64,
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub pool_dropped: u64,
    pub fuel_exhausted_count: u64,
    pub epoch_timeout_count: u64,
    pub host_call_timeout_count: u64,
    pub fresh_instance_count: u64,
}

impl WasmPluginMetrics {
    pub fn get(plugin_name: &str) -> Self {
        let invocations = WASM_PLUGIN_INVOCATIONS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let decisions_pass = WASM_PLUGIN_DECISIONS_PASS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let decisions_block = WASM_PLUGIN_DECISIONS_BLOCK
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let decisions_challenge = WASM_PLUGIN_DECISIONS_CHALLENGE
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let errors = WASM_PLUGIN_ERRORS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let fuel_consumed = WASM_PLUGIN_FUEL_CONSUMED
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let total_duration_ms = WASM_PLUGIN_DURATIONS_MS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let pool_hits = WASM_PLUGIN_POOL_HITS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let pool_misses = WASM_PLUGIN_POOL_MISSES
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let pool_dropped = WASM_PLUGIN_POOL_DROPPED
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let fuel_exhausted_count = WASM_PLUGIN_FUEL_EXHAUSTED
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let epoch_timeout_count = WASM_PLUGIN_EPOCH_TIMEOUTS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let host_call_timeout_count = WASM_PLUGIN_HOST_CALL_TIMEOUTS
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let fresh_instance_count = WASM_PLUGIN_FRESH_INSTANCES
            .lock()
            .get(plugin_name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);

        Self {
            invocations,
            decisions_pass,
            decisions_block,
            decisions_challenge,
            errors,
            fuel_consumed,
            total_duration_ms,
            pool_hits,
            pool_misses,
            pool_dropped,
            fuel_exhausted_count,
            epoch_timeout_count,
            host_call_timeout_count,
            fresh_instance_count,
        }
    }

    pub fn avg_duration_ms(&self) -> f64 {
        if self.invocations > 0 {
            self.total_duration_ms as f64 / self.invocations as f64
        } else {
            0.0
        }
    }

    pub fn pass_rate(&self) -> f64 {
        let total = self.decisions_pass + self.decisions_block + self.decisions_challenge;
        if total > 0 {
            (self.decisions_pass as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
}

pub fn record_wasm_invocation(plugin_name: &str) {
    WASM_PLUGIN_INVOCATIONS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_decision_pass(plugin_name: &str) {
    WASM_PLUGIN_DECISIONS_PASS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_decision_block(plugin_name: &str) {
    WASM_PLUGIN_DECISIONS_BLOCK
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_decision_challenge(plugin_name: &str) {
    WASM_PLUGIN_DECISIONS_CHALLENGE
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_error(plugin_name: &str) {
    WASM_PLUGIN_ERRORS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_fuel_consumed(plugin_name: &str, fuel: u64) {
    WASM_PLUGIN_FUEL_CONSUMED
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(fuel, Ordering::Relaxed);
}

pub fn record_wasm_duration(plugin_name: &str, duration_ms: u64) {
    WASM_PLUGIN_DURATIONS_MS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(duration_ms, Ordering::Relaxed);
}

pub fn record_pool_hit(plugin_name: &str) {
    WASM_PLUGIN_POOL_HITS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_pool_miss(plugin_name: &str) {
    WASM_PLUGIN_POOL_MISSES
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_pool_drop(plugin_name: &str) {
    WASM_PLUGIN_POOL_DROPPED
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_fresh_instance(plugin_name: &str) {
    WASM_PLUGIN_FRESH_INSTANCES
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_fuel_exhausted(plugin_name: &str) {
    WASM_PLUGIN_FUEL_EXHAUSTED
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_epoch_timeout(plugin_name: &str) {
    WASM_PLUGIN_EPOCH_TIMEOUTS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_host_call_timeout(plugin_name: &str) {
    WASM_PLUGIN_HOST_CALL_TIMEOUTS
        .lock()
        .entry(plugin_name.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_plugin_pool_stats(plugin_name: &str, hits: u64, misses: u64, dropped: u64) {
    metrics::counter!(
        "synvoid_plugin_pool_hit_total",
        "plugin" => plugin_name.to_string()
    )
    .increment(hits);
    metrics::counter!(
        "synvoid_plugin_pool_miss_total",
        "plugin" => plugin_name.to_string()
    )
    .increment(misses);
    metrics::counter!(
        "synvoid_plugin_pool_dropped_total",
        "plugin" => plugin_name.to_string()
    )
    .increment(dropped);
}

/// Record a concurrency-limit exceeded event.
///
/// This metric is reserved for actual concurrency gating (semaphore exhaustion
/// in `PluginInvocationGuard`), NOT for pool misses. A pool miss means no warm
/// instance was available — the request is served by instantiating a fresh one.
pub fn record_concurrency_limit_exceeded(plugin_name: &str) {
    metrics::counter!(
        "synvoid_plugin_concurrency_limit_exceeded_total",
        "plugin" => plugin_name.to_string()
    )
    .increment(1);
}

pub fn get_wasm_metrics(plugin_name: &str) -> WasmPluginMetrics {
    WasmPluginMetrics::get(plugin_name)
}

pub fn get_all_wasm_metrics() -> HashMap<String, WasmPluginMetrics> {
    let mut result = HashMap::new();
    for name in WASM_PLUGIN_INVOCATIONS.lock().keys() {
        result.insert(name.clone(), WasmPluginMetrics::get(name));
    }
    result
}

pub fn record_plugin_state_transition(from: &str, to: &str, reason: &str) {
    tracing::info!(
        from = from,
        to = to,
        reason = reason,
        "Plugin state transition"
    );
    metrics::counter!(
        "synvoid_plugin_state_transition_total",
        "from" => from.to_string(),
        "to" => to.to_string(),
        "reason" => reason.to_string()
    )
    .increment(1);
}

pub fn record_plugin_load(tier: &str, status: &str) {
    metrics::counter!(
        "synvoid_plugin_load_total",
        "tier" => tier.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

pub fn record_plugin_hot_reload(status: &str) {
    metrics::counter!(
        "synvoid_plugin_hot_reload_total",
        "status" => status.to_string()
    )
    .increment(1);
}

pub fn record_plugin_capability_violation(capability: &str) {
    metrics::counter!(
        "synvoid_plugin_capability_violation_total",
        "capability" => capability.to_string()
    )
    .increment(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostCallFailureClass {
    EnvLookupTimeout,
    BodyChunkTimeout,
    MeshQueryTimeout,
    MeshThreatTimeout,
    MeshEmitTimeout,
    CapabilityDenied,
    InvalidPointer,
    InputTooLarge,
    Unavailable,
    InternalError,
}

pub fn record_host_call_failure(plugin_name: &str, host_function: &str, failure_class: &str) {
    metrics::counter!(
        "synvoid_plugin_host_call_failure_total",
        "plugin" => plugin_name.to_string(),
        "host_function" => host_function.to_string(),
        "failure_class" => failure_class.to_string()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_plugin_metrics_new_fields_default() {
        let metrics = WasmPluginMetrics::default();
        assert_eq!(metrics.pool_hits, 0);
        assert_eq!(metrics.pool_misses, 0);
        assert_eq!(metrics.pool_dropped, 0);
        assert_eq!(metrics.fuel_exhausted_count, 0);
        assert_eq!(metrics.epoch_timeout_count, 0);
        assert_eq!(metrics.host_call_timeout_count, 0);
        assert_eq!(metrics.fresh_instance_count, 0);
    }

    #[test]
    fn test_record_pool_hit_miss_drop() {
        let name = "test_pool_plugin";
        record_pool_hit(name);
        record_pool_miss(name);
        record_pool_drop(name);
        let m = WasmPluginMetrics::get(name);
        assert!(m.pool_hits > 0);
        assert!(m.pool_misses > 0);
        assert!(m.pool_dropped > 0);
    }

    #[test]
    fn test_record_fuel_exhausted() {
        let name = "test_fuel_plugin";
        record_fuel_exhausted(name);
        let m = WasmPluginMetrics::get(name);
        assert_eq!(m.fuel_exhausted_count, 1);
    }

    #[test]
    fn test_record_epoch_timeout() {
        let name = "test_epoch_plugin";
        record_epoch_timeout(name);
        let m = WasmPluginMetrics::get(name);
        assert_eq!(m.epoch_timeout_count, 1);
    }

    #[test]
    fn test_record_host_call_timeout() {
        let name = "test_host_timeout_plugin";
        record_host_call_timeout(name);
        let m = WasmPluginMetrics::get(name);
        assert_eq!(m.host_call_timeout_count, 1);
    }

    #[test]
    fn test_record_fresh_instance() {
        let name = "test_fresh_instance_plugin";
        record_fresh_instance(name);
        let m = WasmPluginMetrics::get(name);
        assert_eq!(m.fresh_instance_count, 1);
    }

    #[test]
    fn test_record_plugin_state_transition_emits_log() {
        record_plugin_state_transition("test_from", "test_to", "test_reason");
    }
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;

// Phase 52: single consolidated per-plugin counter set. Steady-state recording
// for a known plugin performs one borrowed map lookup and no `String`
// allocation; an owned key is allocated only on first-use insertion.
#[derive(Debug, Default)]
struct WasmMetricCounters {
    invocations: AtomicU64,
    decisions_pass: AtomicU64,
    decisions_block: AtomicU64,
    decisions_challenge: AtomicU64,
    errors: AtomicU64,
    fuel_consumed: AtomicU64,
    total_duration_ms: AtomicU64,
    pool_hits: AtomicU64,
    pool_misses: AtomicU64,
    pool_dropped: AtomicU64,
    fuel_exhausted_count: AtomicU64,
    epoch_timeout_count: AtomicU64,
    host_call_timeout_count: AtomicU64,
    fresh_instance_count: AtomicU64,
}

static WASM_METRICS_REGISTRY: LazyLock<Mutex<HashMap<String, Arc<WasmMetricCounters>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Borrowed fast path: no allocation when the plugin is already registered.
fn counters_for(plugin_name: &str) -> Arc<WasmMetricCounters> {
    if let Some(counters) = WASM_METRICS_REGISTRY.lock().get(plugin_name) {
        return Arc::clone(counters);
    }
    let mut registry = WASM_METRICS_REGISTRY.lock();
    // Recheck under the lock; another thread may have inserted meanwhile.
    if let Some(counters) = registry.get(plugin_name) {
        return Arc::clone(counters);
    }
    let counters = Arc::new(WasmMetricCounters::default());
    registry.insert(plugin_name.to_string(), Arc::clone(&counters));
    counters
}

/// Snapshot helper: clone the handle under the lock, load atomics after
/// release so readers never hold the registry lock during atomic loads.
fn snapshot_for(plugin_name: &str) -> Option<WasmMetricCountersSnapshot> {
    let counters = WASM_METRICS_REGISTRY
        .lock()
        .get(plugin_name)
        .map(Arc::clone)?;
    Some(counters.snapshot())
}

#[derive(Debug, Default)]
struct WasmMetricCountersSnapshot {
    invocations: u64,
    decisions_pass: u64,
    decisions_block: u64,
    decisions_challenge: u64,
    errors: u64,
    fuel_consumed: u64,
    total_duration_ms: u64,
    pool_hits: u64,
    pool_misses: u64,
    pool_dropped: u64,
    fuel_exhausted_count: u64,
    epoch_timeout_count: u64,
    host_call_timeout_count: u64,
    fresh_instance_count: u64,
}

impl WasmMetricCounters {
    fn snapshot(&self) -> WasmMetricCountersSnapshot {
        WasmMetricCountersSnapshot {
            invocations: self.invocations.load(Ordering::Relaxed),
            decisions_pass: self.decisions_pass.load(Ordering::Relaxed),
            decisions_block: self.decisions_block.load(Ordering::Relaxed),
            decisions_challenge: self.decisions_challenge.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            fuel_consumed: self.fuel_consumed.load(Ordering::Relaxed),
            total_duration_ms: self.total_duration_ms.load(Ordering::Relaxed),
            pool_hits: self.pool_hits.load(Ordering::Relaxed),
            pool_misses: self.pool_misses.load(Ordering::Relaxed),
            pool_dropped: self.pool_dropped.load(Ordering::Relaxed),
            fuel_exhausted_count: self.fuel_exhausted_count.load(Ordering::Relaxed),
            epoch_timeout_count: self.epoch_timeout_count.load(Ordering::Relaxed),
            host_call_timeout_count: self.host_call_timeout_count.load(Ordering::Relaxed),
            fresh_instance_count: self.fresh_instance_count.load(Ordering::Relaxed),
        }
    }
}

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
        let snapshot = snapshot_for(plugin_name).unwrap_or_default();

        Self {
            invocations: snapshot.invocations,
            decisions_pass: snapshot.decisions_pass,
            decisions_block: snapshot.decisions_block,
            decisions_challenge: snapshot.decisions_challenge,
            errors: snapshot.errors,
            fuel_consumed: snapshot.fuel_consumed,
            total_duration_ms: snapshot.total_duration_ms,
            pool_hits: snapshot.pool_hits,
            pool_misses: snapshot.pool_misses,
            pool_dropped: snapshot.pool_dropped,
            fuel_exhausted_count: snapshot.fuel_exhausted_count,
            epoch_timeout_count: snapshot.epoch_timeout_count,
            host_call_timeout_count: snapshot.host_call_timeout_count,
            fresh_instance_count: snapshot.fresh_instance_count,
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
    counters_for(plugin_name)
        .invocations
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_decision_pass(plugin_name: &str) {
    counters_for(plugin_name)
        .decisions_pass
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_decision_block(plugin_name: &str) {
    counters_for(plugin_name)
        .decisions_block
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_decision_challenge(plugin_name: &str) {
    counters_for(plugin_name)
        .decisions_challenge
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_error(plugin_name: &str) {
    counters_for(plugin_name)
        .errors
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_wasm_fuel_consumed(plugin_name: &str, fuel: u64) {
    counters_for(plugin_name)
        .fuel_consumed
        .fetch_add(fuel, Ordering::Relaxed);
}

pub fn record_wasm_duration(plugin_name: &str, duration_ms: u64) {
    counters_for(plugin_name)
        .total_duration_ms
        .fetch_add(duration_ms, Ordering::Relaxed);
}

pub fn record_pool_hit(plugin_name: &str) {
    counters_for(plugin_name)
        .pool_hits
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_pool_miss(plugin_name: &str) {
    counters_for(plugin_name)
        .pool_misses
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_pool_drop(plugin_name: &str) {
    counters_for(plugin_name)
        .pool_dropped
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_fresh_instance(plugin_name: &str) {
    counters_for(plugin_name)
        .fresh_instance_count
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_fuel_exhausted(plugin_name: &str) {
    counters_for(plugin_name)
        .fuel_exhausted_count
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_epoch_timeout(plugin_name: &str) {
    counters_for(plugin_name)
        .epoch_timeout_count
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_host_call_timeout(plugin_name: &str) {
    counters_for(plugin_name)
        .host_call_timeout_count
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
    // Phase 52: snapshot (name, handle) pairs under the lock, release it,
    // then load atomics outside the lock. The previous implementation called
    // `WasmPluginMetrics::get` while holding the invocations lock, which
    // self-deadlocks on the non-reentrant mutex.
    let handles: Vec<(String, Arc<WasmMetricCounters>)> = {
        let registry = WASM_METRICS_REGISTRY.lock();
        registry
            .iter()
            .map(|(name, counters)| (name.clone(), Arc::clone(counters)))
            .collect()
    };
    let mut result = HashMap::with_capacity(handles.len());
    for (name, counters) in handles {
        let snapshot = counters.snapshot();
        result.insert(
            name,
            WasmPluginMetrics {
                invocations: snapshot.invocations,
                decisions_pass: snapshot.decisions_pass,
                decisions_block: snapshot.decisions_block,
                decisions_challenge: snapshot.decisions_challenge,
                errors: snapshot.errors,
                fuel_consumed: snapshot.fuel_consumed,
                total_duration_ms: snapshot.total_duration_ms,
                pool_hits: snapshot.pool_hits,
                pool_misses: snapshot.pool_misses,
                pool_dropped: snapshot.pool_dropped,
                fuel_exhausted_count: snapshot.fuel_exhausted_count,
                epoch_timeout_count: snapshot.epoch_timeout_count,
                host_call_timeout_count: snapshot.host_call_timeout_count,
                fresh_instance_count: snapshot.fresh_instance_count,
            },
        );
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

pub fn record_unsafe_native_extension_loaded(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_loaded_total",
        "name" => name.to_string()
    )
    .increment(1);
}

pub fn record_unsafe_native_extension_load_failed(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_load_failed_total",
        "name" => name.to_string()
    )
    .increment(1);
}

pub fn record_unsafe_native_extension_reloaded(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_reloaded_total",
        "name" => name.to_string()
    )
    .increment(1);
}

pub fn record_unsafe_native_extension_request(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_request_total",
        "name" => name.to_string()
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

    /// Phase 52: `get_all_wasm_metrics` must not self-deadlock when at least
    /// one plugin is registered. Bounded timeout fails closed on regression.
    #[test]
    fn test_get_all_wasm_metrics_completes_with_registered_plugin() {
        use std::time::Duration;
        record_wasm_invocation("test_get_all_deadlock_plugin");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(get_all_wasm_metrics()).expect("send snapshot");
        });
        let snapshot = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("get_all_wasm_metrics completed within 10s");
        assert!(
            snapshot.contains_key("test_get_all_deadlock_plugin"),
            "snapshot contains the registered plugin"
        );
    }

    /// Phase 52: repeated hot-key recording updates one coherent counter set.
    #[test]
    fn test_hot_key_recording_is_coherent() {
        let name = "test_hot_key_coherent_plugin";
        record_wasm_invocation(name);
        record_wasm_decision_pass(name);
        record_wasm_duration(name, 7);
        let m = WasmPluginMetrics::get(name);
        assert_eq!(m.invocations, 1);
        assert_eq!(m.decisions_pass, 1);
        assert_eq!(m.total_duration_ms, 7);
        let all = get_all_wasm_metrics();
        let m_all = all.get(name).expect("present in full snapshot");
        assert_eq!(m_all.invocations, 1);
        assert_eq!(m_all.decisions_pass, 1);
    }
}

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

#[derive(Debug, Clone, Default)]
pub struct WasmPluginMetrics {
    pub invocations: u64,
    pub decisions_pass: u64,
    pub decisions_block: u64,
    pub decisions_challenge: u64,
    pub errors: u64,
    pub fuel_consumed: u64,
    pub total_duration_ms: u64,
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

        Self {
            invocations,
            decisions_pass,
            decisions_block,
            decisions_challenge,
            errors,
            fuel_consumed,
            total_duration_ms,
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

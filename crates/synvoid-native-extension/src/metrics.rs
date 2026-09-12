//! Native-extension-specific metrics helpers.
//!
//! Phase 28: these counters live in `synvoid-native-extension` (the explicit
//! unsafe capability owner), not in the sandboxed WASM `wasm_metrics` module.
//! Metric names are unchanged so existing dashboards keep working:
//! `synvoid_unsafe_native_extension_{loaded,load_failed,reloaded,request}_total`.
//!
//! `synvoid-plugin-runtime` keeps thin same-named helpers for compatibility,
//! but the loader in this crate emits via the functions below.

/// Record a successful native extension load.
pub fn record_unsafe_native_extension_loaded(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_loaded_total",
        "name" => name.to_string()
    )
    .increment(1);
}

/// Record a failed native extension load attempt.
pub fn record_unsafe_native_extension_load_failed(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_load_failed_total",
        "name" => name.to_string()
    )
    .increment(1);
}

/// Record a successful native extension hot-reload.
pub fn record_unsafe_native_extension_reloaded(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_reloaded_total",
        "name" => name.to_string()
    )
    .increment(1);
}

/// Record a request routed through a native extension.
pub fn record_unsafe_native_extension_request(name: &str) {
    metrics::counter!(
        "synvoid_unsafe_native_extension_request_total",
        "name" => name.to_string()
    )
    .increment(1);
}

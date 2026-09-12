//! Plugin application lifecycle composition (root-owned).
//!
//! Phase 21: the unified [`PluginManager`] and [`PluginManagerLifecycle`]
//! are canonical in `synvoid_plugin_runtime::plugin_manager`. This module is
//! a compatibility facade re-exporting them together with the shared WASM
//! plugin types. Reusable runtime behavior — manifest/capability validation,
//! trust-tier and signature decisions, WASM execution policy,
//! timeout/resource-limit policy, quarantine and failure accounting — lives
//! only in `synvoid-plugin-runtime` and must not gain a second copy here.
//!
//! Root retains application composition only: loading plugins from
//! application configuration, mesh-aware module resolution (below),
//! attaching the runtime to worker state, and supervisor task ownership via
//! `crate::server::plugin_runtime::PluginRuntimeOwner` (which owns the
//! hot-reload watcher; never `std::mem::forget`).

pub mod unsafe_native_loader;

/// Narrow native-extension backend wiring (Phase 28).
///
/// Available only with the `unsafe-native-extensions` feature. The root
/// composition may inject a backend via `PluginManager::with_native_backend`;
/// request-path code stays on the narrow trait and never sees loader handles.
/// Re-exported from the canonical `synvoid-native-extension` crate directly
/// so the capability owner is explicit at the composition root.
#[cfg(feature = "unsafe-native-extensions")]
pub use synvoid_native_extension::{
    InProcessNativeBackend, NativeExtensionBackend, NativeExtensionHandle,
};
pub use synvoid_plugin_runtime::plugin_manager::{
    AxumPluginError, PluginManager, PluginManagerLifecycle, UnsafeNativePluginError,
};
pub use synvoid_plugin_runtime::unsafe_native_loader::{
    current_generation, get_global_unsafe_native_config, is_production_env,
    set_global_unsafe_native_config, UnsafeNativeExtension, UnsafeNativeExtensionConfig,
    UnsafeNativeExtensionStatus, UnsafeNativeGlobalStatus,
};
pub use synvoid_plugin_runtime::{
    get_all_wasm_metrics, get_global_plugin_manager, get_wasm_metrics, GlobalPluginManager,
    GlobalWasmMemoryBudget, MemoryBudgetError, PluginInfo, PluginLoadConfig, PooledInstance,
    WasmFilterResult, WasmInstancePool, WasmPluginError, WasmPluginManager, WasmPluginMetrics,
    WasmPool, WasmResourceLimits, WasmRuntime,
};
pub use synvoid_plugin_runtime::{
    limits_from_manifest, EffectivePluginPolicy, PluginSourceIdentity, PreparedPluginLoad,
};

/// Resolve mesh-distributed WASM bytes for a plugin file stem.
///
/// Returns the stored `Plugin` module bytes when the mesh WASM store holds
/// them under `name`. This is application composition (mesh + plugin); the
/// runtime crate stays free of root mesh types by taking resolved bytes
/// (`load_wasm_plugin_from_bytes`) or the resolver hook on
/// `PluginManagerLifecycle::load_plugins_from_dir_with_resolver`.
#[cfg(feature = "mesh")]
pub fn resolve_mesh_plugin_bytes(name: &str) -> Option<Vec<u8>> {
    let wasm_dist = crate::mesh::get_global_wasm_dist_manager()?;
    wasm_dist.get_module_data(name, crate::mesh::protocol::WasmModuleType::Plugin)
}

/// Load a WASM plugin, preferring mesh-distributed bytes when available.
///
/// This replaces the former mesh-gated `PluginManager::load_wasm_plugin`
/// inherent method that was removed with the root duplicate manager. The
/// no-mesh build uses `PluginManager::load_wasm_plugin` directly.
#[cfg(feature = "mesh")]
pub fn load_wasm_plugin_with_mesh_fallback(
    manager: &PluginManager,
    path: &std::path::Path,
) -> Result<(), WasmPluginError> {
    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
        if let Some(data) = resolve_mesh_plugin_bytes(name) {
            tracing::debug!("Loading plugin '{}' from mesh WASM store", name);
            return manager.load_wasm_plugin_from_bytes(name, data);
        }
    }
    manager.load_wasm_plugin(path)
}

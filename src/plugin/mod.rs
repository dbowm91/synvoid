use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use bytes::Bytes;
use http::{Request, Response};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;

pub mod unsafe_native_loader;

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

/// Backward-compatible alias — prefer `UnsafeNativePluginError` for new code.
pub use synvoid_plugin_runtime::plugin_manager::AxumPluginError;
pub use synvoid_plugin_runtime::plugin_manager::UnsafeNativePluginError;

// ─── PluginManager (public API) ──────────────────────────────────────────────

pub struct PluginManager {
    wasm_manager: Arc<WasmPluginManager>,
    unsafe_native_extensions: RwLock<Vec<Arc<UnsafeNativeExtensionWrapper>>>,
    last_native_load_error: RwLock<Option<String>>,
}

struct UnsafeNativeExtensionWrapper {
    extension: Arc<UnsafeNativeExtension>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new()),
            unsafe_native_extensions: RwLock::new(Vec::new()),
            last_native_load_error: RwLock::new(None),
        }
    }

    pub fn with_wasm_limits(limits: WasmResourceLimits) -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new().with_limits(limits)),
            unsafe_native_extensions: RwLock::new(Vec::new()),
            last_native_load_error: RwLock::new(None),
        }
    }

    pub fn with_load_config(config: PluginLoadConfig) -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new().with_load_config(config)),
            unsafe_native_extensions: RwLock::new(Vec::new()),
            last_native_load_error: RwLock::new(None),
        }
    }

    pub fn set_load_config(&self, config: PluginLoadConfig) {
        self.wasm_manager.set_load_config(config);
    }

    #[cfg(feature = "mesh")]
    pub fn load_wasm_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        if let Some(name) = path.file_stem() {
            if let Some(name_str) = name.to_str() {
                if let Some(wasm_dist) = crate::mesh::get_global_wasm_dist_manager() {
                    if let Some(data) = wasm_dist
                        .get_module_data(name_str, crate::mesh::protocol::WasmModuleType::Plugin)
                    {
                        tracing::debug!("Loading plugin '{}' from mesh WASM store", name_str);
                        self.wasm_manager.load_plugin_from_memory(
                            name_str,
                            &data,
                            self.wasm_manager.get_default_limits(),
                        )?;
                        return Ok(());
                    }
                }
            }
        }
        self.wasm_manager.load_plugin(path)?;
        Ok(())
    }

    #[cfg(not(feature = "mesh"))]
    pub fn load_wasm_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        self.wasm_manager.load_plugin(path)?;
        Ok(())
    }

    pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, UnsafeNativePluginError> {
        self.load_unsafe_native_extension(path, &[], None)
    }

    pub fn load_unsafe_native_extension(
        &self,
        path: &Path,
        allowed_dirs: &[String],
        expected_hash: Option<&str>,
    ) -> Result<Arc<Router>, UnsafeNativePluginError> {
        match unsafe_native_loader::load_plugin_full(path, allowed_dirs, expected_hash) {
            Ok(ext) => {
                *self.last_native_load_error.write() = None;
                let router = ext.router.clone();
                let wrapper = UnsafeNativeExtensionWrapper {
                    extension: Arc::new(ext),
                };
                self.unsafe_native_extensions
                    .write()
                    .push(Arc::new(wrapper));
                Ok(router)
            }
            Err(e) => {
                *self.last_native_load_error.write() = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Get the first loaded unsafe native extension router, if any
    pub fn get_axum_router(&self) -> Option<Arc<Router>> {
        self.unsafe_native_extensions
            .read()
            .first()
            .map(|w| w.extension.router.clone())
    }

    /// Get an unsafe native extension router by name
    pub fn get_axum_router_by_name(&self, name: &str) -> Option<Arc<Router>> {
        self.unsafe_native_extensions
            .read()
            .iter()
            .find(|w| w.extension.name == name)
            .map(|w| w.extension.router.clone())
    }

    /// Get all loaded unsafe native extension routers
    pub fn get_axum_routers(&self) -> Vec<Arc<Router>> {
        self.unsafe_native_extensions
            .read()
            .iter()
            .map(|w| w.extension.router.clone())
            .collect()
    }

    /// Remove an unsafe native extension by name. Returns true if found and removed.
    /// The old router stays in memory until all references are dropped.
    pub fn unload_axum_plugin(&self, name: &str) -> bool {
        let mut plugins = self.unsafe_native_extensions.write();
        let before = plugins.len();
        plugins.retain(|w| w.extension.name != name);
        plugins.len() < before
    }

    /// Returns status information for all loaded unsafe native extensions.
    pub fn unsafe_native_status(&self) -> Vec<UnsafeNativeExtensionStatus> {
        self.unsafe_native_extensions
            .read()
            .iter()
            .map(|w| w.extension.status())
            .collect()
    }

    /// Returns global status of the unsafe native extension subsystem,
    /// combining configuration state with per-extension status.
    pub fn unsafe_native_global_status(&self) -> UnsafeNativeGlobalStatus {
        let config = get_global_unsafe_native_config();
        let extensions: Vec<UnsafeNativeExtensionStatus> = self
            .unsafe_native_extensions
            .read()
            .iter()
            .map(|w| w.extension.status())
            .collect();
        let last_load_error = self.last_native_load_error.read().clone();
        UnsafeNativeGlobalStatus {
            enabled: config.enabled,
            production_mode: config.is_production(),
            allow_in_production: config.allow_in_production,
            hot_reload_enabled: config.hot_reload_enabled,
            loaded_count: extensions.len(),
            last_load_error,
            extensions,
        }
    }

    /// Returns the last error from a failed native extension load attempt.
    pub fn last_native_load_error(&self) -> Option<String> {
        self.last_native_load_error.read().clone()
    }

    pub fn apply_wasm_filters(
        &self,
        request: Request<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        self.wasm_manager.filter_request(request, env)
    }

    pub fn apply_wasm_filters_with_plugins(
        &self,
        request: Request<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        self.wasm_manager
            .filter_request_with_plugins(request, plugin_names, env)
    }

    pub fn apply_wasm_response_transforms(
        &self,
        response: Response<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        self.wasm_manager.transform_response(response, env)
    }

    pub fn apply_wasm_response_transforms_with_plugins(
        &self,
        response: Response<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        self.wasm_manager
            .transform_response_with_plugins(response, plugin_names, env)
    }

    /// Get the underlying WASM plugin manager
    pub fn wasm_manager(&self) -> &Arc<WasmPluginManager> {
        &self.wasm_manager
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl synvoid_http::AxumDynamicRouterLookup for PluginManager {
    fn get_axum_router(&self) -> Option<Arc<Router>> {
        PluginManager::get_axum_router(self)
    }

    fn get_axum_router_by_name(&self, name: &str) -> Option<Arc<Router>> {
        PluginManager::get_axum_router_by_name(self, name)
    }
}

impl synvoid_http::WasmFilterBackend for PluginManager {
    fn apply_wasm_filters(
        &self,
        request: Request<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        PluginManager::apply_wasm_filters(self, request, env)
    }

    fn apply_wasm_filters_with_plugins(
        &self,
        request: Request<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        PluginManager::apply_wasm_filters_with_plugins(self, request, plugin_names, env)
    }
}

// ─── PluginAppManager (lifecycle management) ─────────────────────────────────

/// Manages plugin lifecycle: load, unload, reload, and hot-reload via file watching.
pub struct PluginManagerLifecycle {
    plugin_manager: Arc<PluginManager>,
    watch_dir: Option<PathBuf>,
    _watcher: Option<RecommendedWatcher>,
    plugin_dir: Option<PathBuf>,
}

impl PluginManagerLifecycle {
    pub fn new(plugin_manager: Arc<PluginManager>) -> Self {
        Self {
            plugin_manager,
            watch_dir: None,
            _watcher: None,
            plugin_dir: None,
        }
    }

    /// Load all WASM plugins from a directory
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, WasmPluginError> {
        if !dir.is_dir() {
            return Err(WasmPluginError::LoadFailed(format!(
                "plugin directory does not exist: {}",
                dir.display()
            )));
        }

        self.plugin_dir = Some(dir.to_path_buf());

        let mut loaded = 0;
        let entries = std::fs::read_dir(dir)
            .map_err(|e| WasmPluginError::LoadFailed(format!("failed to read dir: {}", e)))?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Failed to read plugin directory entry: {}", e);
                    continue;
                }
            };
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "wasm" || ext == "wat" {
                    match self.plugin_manager.load_wasm_plugin(&path) {
                        Ok(()) => {
                            loaded += 1;
                            tracing::info!("Loaded plugin: {}", path.display());
                        }
                        Err(e) => {
                            tracing::error!("Failed to load plugin {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Load all unsafe native extensions (.so/.dylib/.dll) from a directory
    pub fn load_axum_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, AxumPluginError> {
        if !dir.is_dir() {
            return Err(AxumPluginError::LoadFailed(format!(
                "plugin directory does not exist: {}",
                dir.display()
            )));
        }

        let mut loaded = 0;
        let entries = std::fs::read_dir(dir)
            .map_err(|e| AxumPluginError::LoadFailed(format!("failed to read dir: {}", e)))?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Failed to read plugin directory entry: {}", e);
                    continue;
                }
            };
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "so" || ext == "dylib" || ext == "dll" {
                    match self.plugin_manager.load_axum_plugin(&path) {
                        Ok(_) => {
                            loaded += 1;
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to load unsafe native extension {}: {}",
                                path.display(),
                                e
                            );
                        }
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Enable hot-reload watching on a directory.
    /// When `.wasm`, `.wat`, `.so`, `.dylib`, or `.dll` files change, plugins are reloaded.
    pub fn enable_hot_reload(&mut self, dir: &Path) -> Result<(), String> {
        let dir = dir.to_path_buf();
        if !dir.is_dir() {
            return Err(format!(
                "hot-reload directory does not exist: {}",
                dir.display()
            ));
        }

        let plugin_manager = self.plugin_manager.clone();
        let _watch_dir = dir.clone();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) => {
                    if !matches!(event.kind, notify::EventKind::Modify(_)) {
                        return;
                    }
                    for path in &event.paths {
                        if let Some(ext) = path.extension() {
                            match ext.to_str() {
                                Some("wasm") | Some("wat") => {
                                    tracing::info!("Hot-reloading WASM plugin: {}", path.display());
                                    match plugin_manager.wasm_manager().reload_plugin(path) {
                                        Ok(_) => {
                                            tracing::info!(
                                                "Successfully hot-reloaded: {}",
                                                path.display()
                                            );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Hot-reload failed for {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                                Some("so") | Some("dylib") | Some("dll") => {
                                    let native_config =
                                        synvoid_plugin_runtime::get_global_unsafe_native_config();
                                    if !native_config.hot_reload_enabled {
                                        tracing::debug!(
                                            "Skipping native hot-reload (hot_reload_enabled=false): {}",
                                            path.display()
                                        );
                                        return;
                                    }
                                    tracing::info!(
                                        "Hot-reloading unsafe native extension: {}",
                                        path.display()
                                    );
                                    // Remove old extension entry by name (library stays loaded
                                    // until all in-flight request references are dropped)
                                    let name = path
                                        .file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    plugin_manager.unload_axum_plugin(&name);
                                    match plugin_manager.load_axum_plugin(path) {
                                        Ok(_) => {
                                            tracing::info!(
                                                "Successfully hot-reloaded: {}",
                                                path.display()
                                            );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Hot-reload failed for {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Hot-reload watch error: {}", e);
                }
            }
        })
        .map_err(|e| format!("failed to create file watcher: {}", e))?;

        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| format!("failed to watch directory {}: {}", dir.display(), e))?;

        // Keep watcher alive by storing it
        self._watcher = Some(watcher);
        self.watch_dir = Some(dir.clone());

        tracing::info!("Hot-reload enabled for plugin directory: {}", dir.display());
        Ok(())
    }

    /// Reload a specific plugin by path
    pub fn reload_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        if let Some(ext) = path.extension() {
            match ext.to_str() {
                Some("wasm") | Some("wat") => {
                    self.plugin_manager.wasm_manager().reload_plugin(path)?;
                }
                Some("so") | Some("dylib") | Some("dll") => {
                    self.plugin_manager
                        .load_axum_plugin(path)
                        .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;
                }
                _ => {
                    return Err(WasmPluginError::LoadFailed(format!(
                        "unsupported plugin extension: {}",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Unload all plugins and clean up
    pub fn shutdown(&self) {
        // The watcher is dropped when self._watcher is dropped,
        // which stops the file watching thread.
        tracing::info!("Plugin lifecycle manager shutting down");
    }

    pub fn plugin_manager(&self) -> &Arc<PluginManager> {
        &self.plugin_manager
    }
}
